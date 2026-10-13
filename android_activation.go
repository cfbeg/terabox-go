package terabox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AndroidActivationState contains the APK's account-scoped ReportUser consumer
// state. It is private session data, including returned media URLs. A new
// installation must not inherit another account's state.
type AndroidActivationState struct {
	AccountUID                   string                             `json:"account_uid"`
	OldUser                      *bool                              `json:"old_user,omitempty"`
	UseTimestamp                 bool                               `json:"use_timestamp"`
	TimeZone                     string                             `json:"time_zone,omitempty"`
	Actions                      map[string]AndroidActivationRecord `json:"actions,omitempty"`
	MediaInfo                    *AndroidActivationMediaInfo        `json:"media_info,omitempty"`
	PendingPushMessageTimeMillis *int64                             `json:"pending_push_message_time_ms,omitempty"`
}

// AndroidActivationRecord retains the native value for one successful action.
// The date representation is the APK's yyMMdd, not an elapsed-time interval.
type AndroidActivationRecord struct {
	TimestampMillis int64  `json:"timestamp_ms,omitempty"`
	Date            string `json:"date,omitempty"`
}

// AndroidActivationMediaInfo mirrors ReportUserResponse.NewUserMediaInfo. The
// APK saves these values only when videourl is nonempty; Go retains the data
// without emitting Android UI broadcasts.
type AndroidActivationMediaInfo struct {
	PictureURL string `json:"picurl"`
	VideoURL   string `json:"videourl"`
	VideoName  string `json:"videoname"`
}

// AndroidActivationPolicy selects the APK's scheduled activation guard. The
// observed wh.d() selects timestamp storage when its config value is >= 5;
// both modes suppress the same local calendar day, never an arbitrary interval.
// A nil ConfigValue keeps the restored mode, or the APK's start_config/c
// fallback of 6 (timestamp mode) for a session without state. TimeZone is the
// device's IANA zone, or "Local".
// Action defaults to the profile's captured action; no lifecycle suffix is
// generated. RefreshAndroidAppConfig bypasses this guard for explicit SK refresh.
type AndroidActivationPolicy struct {
	ConfigValue *int64
	TimeZone    string
	Action      string
}

// AndroidActivationResult reports whether the activation was sent or already
// completed for this account/action/day. It contains no credentials or URLs.
type AndroidActivationResult struct {
	Attempted bool `json:"attempted"`
	Skipped   bool `json:"skipped"`
}

func cloneAndroidActivation(state *AndroidActivationState) *AndroidActivationState {
	if state == nil {
		return nil
	}
	clone := *state
	if state.OldUser != nil {
		value := *state.OldUser
		clone.OldUser = &value
	}
	if state.PendingPushMessageTimeMillis != nil {
		value := *state.PendingPushMessageTimeMillis
		clone.PendingPushMessageTimeMillis = &value
	}
	if state.MediaInfo != nil {
		value := *state.MediaInfo
		clone.MediaInfo = &value
	}
	if state.Actions != nil {
		clone.Actions = make(map[string]AndroidActivationRecord, len(state.Actions))
		for action, record := range state.Actions {
			clone.Actions[action] = record
		}
	}
	return &clone
}

func androidActivationActionValid(action string) bool {
	base := action
	if strings.HasSuffix(base, "_QIAN") {
		base = strings.TrimSuffix(base, "_QIAN")
	} else if strings.HasSuffix(base, "_HOU") {
		base = strings.TrimSuffix(base, "_HOU")
	}
	switch base {
	case "ANDROID_ACTIVE_FRONTDESK", "ANDROID_ACTIVE_BACKGROUND_ALBUMBACKUP",
		"ANDROID_ACTIVE_BACKGROUND_DOWNLOAD", "ANDROID_ACTIVE_BACKGROUND_UPLOAD",
		"ANDROID_ACTIVE_BACKGROUND_UPLOAD_AND_DOWNLOAD", "ANDROID_ACTIVE_LOGOUT":
		return true
	}
	return false
}

func androidActivationLocation(zone string) (*time.Location, error) {
	if zone == "" || zone == "Local" {
		return time.Local, nil
	}
	location, err := time.LoadLocation(zone)
	if err != nil {
		return nil, errors.New("Android activation requires a valid device time zone")
	}
	return location, nil
}

func validateAndroidActivation(state *AndroidActivationState, uid string) error {
	if state == nil {
		return nil
	}
	if uid == "" || state.AccountUID != uid {
		return errors.New("Android activation state belongs to a different native account")
	}
	if _, err := androidActivationLocation(state.TimeZone); err != nil {
		return err
	}
	if state.PendingPushMessageTimeMillis != nil && *state.PendingPushMessageTimeMillis < 0 {
		return errors.New("Android activation contains an invalid push-message timestamp")
	}
	for action, record := range state.Actions {
		if !androidActivationActionValid(action) || action == "ANDROID_ACTIVE_LOGOUT" ||
			record.TimestampMillis < 0 || (record.TimestampMillis == 0 && record.Date == "") ||
			(record.TimestampMillis != 0 && record.Date != "") {
			return errors.New("Android activation contains an invalid action record")
		}
		if record.Date != "" {
			if _, err := time.Parse("060102", record.Date); err != nil || len(record.Date) != 6 {
				return errors.New("Android activation contains an invalid date record")
			}
		}
	}
	if state.MediaInfo != nil {
		for _, value := range []string{state.MediaInfo.PictureURL, state.MediaInfo.VideoURL, state.MediaInfo.VideoName} {
			if !attributionStringValid(value) || strings.ContainsAny(value, "\r\n\x00") {
				return errors.New("Android activation contains invalid media data")
			}
		}
	}
	return nil
}

func androidActivationSameDay(record AndroidActivationRecord, now time.Time, location *time.Location) bool {
	if record.TimestampMillis > 0 {
		previous := time.UnixMilli(record.TimestampMillis).In(location)
		current := now.In(location)
		return previous.Year() == current.Year() && previous.YearDay() == current.YearDay()
	}
	return record.Date != "" && record.Date == now.In(location).Format("060102")
}

// SendAndroidAppActivation performs the APK's scheduled ReportUser request,
// preserving account/action calendar-day suppression across session restore.
// Use RefreshAndroidAppConfig to force retrieval of a missing or stale SK.
func (c *Client) SendAndroidAppActivation(ctx context.Context, policy *AndroidActivationPolicy) (*AndroidActivationResult, error) {
	return c.sendAndroidAppActivation(ctx, policy, false)
}

func (c *Client) sendAndroidAppActivation(ctx context.Context, policy *AndroidActivationPolicy, force bool) (*AndroidActivationResult, error) {
	op := "sendAndroidAppActivation"
	if force {
		op = "refreshAndroidAppConfig"
	}
	c.mu.RLock()
	app := c.androidApp
	c.mu.RUnlock()
	if app == nil {
		return nil, wrapErr(op, errors.New("own authenticated Android UID and ndus are required"))
	}
	app.activationMu.Lock()
	defer app.activationMu.Unlock()
	profile := c.AndroidAppProfile()
	ndus, _ := c.CookieValue("ndus")
	if profile.UID == "" || ndus == "" {
		return nil, wrapErr(op, errors.New("own authenticated Android UID and ndus are required"))
	}
	if err := validateAndroidActivation(profile.Activation, profile.UID); err != nil {
		return nil, wrapErr(op, err)
	}
	if len(profile.ReportParams) == 0 || profile.ReportParams["start_source"] == "" ||
		profile.ReportParams["push_on"] == "" || profile.ReportParams["backup_on "] == "" {
		return nil, wrapErr(op, errors.New("captured ReportParams are required for Android activation"))
	}
	action := profile.ReportParams["action"]
	useTimestamp, zone := true, "Local"
	if profile.Activation != nil {
		useTimestamp = profile.Activation.UseTimestamp
		if profile.Activation.TimeZone != "" {
			zone = profile.Activation.TimeZone
		}
	}
	if policy != nil {
		if policy.ConfigValue != nil {
			useTimestamp = *policy.ConfigValue >= 5
		}
		if policy.TimeZone != "" {
			zone = policy.TimeZone
		}
		if policy.Action != "" {
			action = policy.Action
		}
	}
	if !androidActivationActionValid(action) || (force && action != "ANDROID_ACTIVE_FRONTDESK") {
		return nil, wrapErr(op, errors.New("captured Android activation action is required"))
	}
	location, err := androidActivationLocation(zone)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	requestTime := time.UnixMilli(c.androidAppTime())
	if !force && profile.Activation != nil && action != "ANDROID_ACTIVE_LOGOUT" &&
		androidActivationSameDay(profile.Activation.Actions[action], requestTime, location) {
		return &AndroidActivationResult{Skipped: true}, nil
	}
	query := url.Values{}
	for key, value := range profile.ReportParams {
		query.Set(key, value)
	}
	query.Set("action", action)
	query.Set("timestamp", strconv.FormatInt(requestTime.UnixMilli(), 10))
	if profile.Activation != nil && profile.Activation.OldUser != nil {
		if *profile.Activation.OldUser {
			query.Del("needrookie")
		} else {
			query.Set("needrookie", "1")
		}
	}
	var response struct {
		Errno     *int                        `json:"errno"`
		Code      *int                        `json:"code"`
		Msg       string                      `json:"errmsg"`
		Alias     string                      `json:"error_msg"`
		UInfo     string                      `json:"uinfo"`
		IsNew     *int                        `json:"isnew"`
		MediaInfo *AndroidActivationMediaInfo `json:"mediainfo"`
	}
	result := &AndroidActivationResult{Attempted: true}
	if err := c.doJSON(ctx, op, &requestOpts{method: http.MethodGet,
		path: "/api/report/user", query: query}, &response); err != nil {
		return result, err
	}
	if response.Errno == nil {
		return result, wrapErr(op, errors.New("Android configuration response is missing errno"))
	}
	code := *response.Errno
	if response.Code != nil && *response.Code != 0 {
		code = *response.Code
	}
	if code != 0 {
		message := response.Msg
		if message == "" {
			message = response.Alias
		}
		return result, wrapErr(op, &APIError{Code: code, Message: message})
	}
	if response.UInfo == "" {
		return result, wrapErr(op, errors.New("Android configuration response is missing uinfo"))
	}
	if _, err := DecodeAndroidSK(profile.UID, response.UInfo); err != nil {
		return result, wrapErr(op, err)
	}
	state := cloneAndroidActivation(profile.Activation)
	if state == nil {
		state = &AndroidActivationState{AccountUID: profile.UID}
	}
	state.UseTimestamp, state.TimeZone = useTimestamp, zone
	if response.IsNew != nil && (*response.IsNew == 0 || *response.IsNew == 1) {
		oldUser := *response.IsNew == 0
		state.OldUser = &oldUser
	}
	responseTime := time.UnixMilli(c.androidAppTime())
	if action != "ANDROID_ACTIVE_LOGOUT" && androidActivationSameDay(
		AndroidActivationRecord{TimestampMillis: requestTime.UnixMilli()}, responseTime, location) {
		if state.Actions == nil {
			state.Actions = make(map[string]AndroidActivationRecord)
		}
		if useTimestamp {
			stamp := responseTime.UnixMilli()
			// A clock adjustment within the same day must not regress a saved
			// timestamp. Native suppression still uses calendar dates.
			if previous := state.Actions[action].TimestampMillis; previous > stamp &&
				androidActivationSameDay(state.Actions[action], responseTime, location) {
				stamp = previous
			}
			state.Actions[action] = AndroidActivationRecord{TimestampMillis: stamp}
		} else {
			state.Actions[action] = AndroidActivationRecord{Date: responseTime.In(location).Format("060102")}
		}
	}
	if response.MediaInfo != nil && response.MediaInfo.VideoURL != "" {
		state.MediaInfo = response.MediaInfo
	}
	state.PendingPushMessageTimeMillis = nil
	if err := validateAndroidActivation(state, profile.UID); err != nil {
		return result, wrapErr(op, fmt.Errorf("invalid Android activation response state: %w", err))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cookies["ndus"] != ndus || c.androidApp.profile.UID != profile.UID {
		return result, wrapErr(op, errors.New("Android account changed during configuration refresh"))
	}
	current := &c.androidApp.profile
	current.EncodedSK, current.Activation = response.UInfo, cloneAndroidActivation(state)
	delete(current.ReportParams, "source")
	delete(current.ReportParams, "msg_id")
	if state.OldUser != nil {
		if *state.OldUser {
			delete(current.ReportParams, "needrookie")
		} else {
			current.ReportParams["needrookie"] = "1"
		}
	}
	return result, nil
}
