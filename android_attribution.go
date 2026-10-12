package terabox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// AndroidClickAttribution preserves the public share page's actual app-open
// event. UserAgent is the browser UA, not the native dubox UA. Nothing here is
// generated from a shared owner ID or from an Android profile template.
type AndroidClickAttribution struct {
	PageURL        string            `json:"page_url"`
	UserAgent      string            `json:"user_agent"`
	DeepLink       string            `json:"deep_link"`
	TeraLinkID     string            `json:"tera_link_id"`
	TeraLinkType   int               `json:"tera_link_type"`
	Language       string            `json:"language"`
	OSVersion      string            `json:"os_version"`
	Device         string            `json:"device"`
	Referrer       string            `json:"referrer"`
	Agency         *string           `json:"agency,omitempty"`
	OpSource       *string           `json:"op_source,omitempty"`
	CommonParams   map[string]string `json:"common_params"`
	BrowserCookies string            `json:"browser_cookies,omitempty"`
	BridgeBody     map[string]string `json:"bridge_body,omitempty"`
}

// AndroidInstallAttribution contains OS/application installation observations.
// InstallTime is PackageInfo.firstInstallTime in milliseconds; FirstLaunchTime
// is the saved first_launch_time Unix seconds multiplied by 1000. The APK sends
// an empty Clipboard, independently of its separate clipboard deeplink parser.
// IsFirstLaunch is local state and is never sent as an invented query field.
type AndroidInstallAttribution struct {
	Clipboard       string `json:"clipboard"`
	DeviceCountry   string `json:"device_country"`
	DeviceLanguage  string `json:"device_lang"`
	OSVersion       string `json:"os_version"`
	Device          string `json:"device"`
	InstallTime     *int64 `json:"install_time,omitempty"`
	FirstLaunchTime int64  `json:"first_launch_time"`
	IsFirstLaunch   bool   `json:"is_first_launch"`
}

// AndroidAttributionCapture binds observed browser/install provenance to the
// actual installation's CUID. A nil InstallReferrer means it was unavailable;
// a pointer to "" means Play returned an actual empty string. Neither value is
// replaced with a guessed campaign, shared URL or Webmaster owner identifier.
type AndroidAttributionCapture struct {
	DeviceID        string                     `json:"device_id"`
	Click           *AndroidClickAttribution   `json:"click,omitempty"`
	Install         *AndroidInstallAttribution `json:"install,omitempty"`
	InstallReferrer *string                    `json:"install_referrer,omitempty"`
	// NativeMediaCache is the observed RequestCommonParams static cache, not
	// the similarly named MMKV installation value. Nil means unobserved.
	NativeMediaCache  *AndroidNativeMediaCache `json:"native_media_cache,omitempty"`
	StoredMediaSource *string                  `json:"stored_media_source,omitempty"`
	// MaterialSourceScene is the actual AfSpreadHelperKt.c() result. It is
	// never inferred from a share owner, campaign or arbitrary deeplink.
	MaterialSourceScene *string `json:"material_source_scene,omitempty"`
}

// AndroidNativeMediaCache models RequestCommonParams.c(): only an uninitialized
// static cache reads MMKV. Changing stored attribution does not clear it.
type AndroidNativeMediaCache struct {
	Initialized bool    `json:"initialized"`
	Value       *string `json:"value,omitempty"`
}

// AndroidReferrerData contains the nullable server DTO fields unchanged. The
// server's status is attribution metadata, not the request's errno and not a
// receipt proving Webmaster acquisition or rewards.
type AndroidReferrerData struct {
	MediaSource   *string `json:"mediaSource"`
	Status        *string `json:"status"`
	Agency        *string `json:"agency"`
	Campaign      *string `json:"campaign"`
	Code          *string `json:"code"`
	AdSet         *string `json:"adSet"`
	OpSource      *string `json:"opSource"`
	DeepLinkValue *string `json:"deepLinkValue"`
	DeepLink      *string `json:"deeplink"`
}

// AndroidAttributionReport records one report without treating uncertain HTTP
// outcomes as successful. Attempted without Succeeded prevents implicit replay
// after restore; callers can inspect the preserved response before recovery.
type AndroidAttributionReport struct {
	Attempted   bool            `json:"attempted"`
	Succeeded   bool            `json:"succeeded"`
	HTTPStatus  int             `json:"http_status,omitempty"`
	Errno       *int            `json:"errno,omitempty"`
	RequestID   string          `json:"request_id,omitempty"`
	RawResponse json.RawMessage `json:"raw_response,omitempty"`
	// RawBody retains a bounded byte prefix even for interrupted/non-JSON
	// replies. It is private evidence, never a success or replay indication.
	RawBody []byte `json:"raw_body,omitempty"`
}

const androidAttributionResponseLimit = 1 << 20

// AndroidAttributionState is installation state, distinct from account and
// Webmaster credit state. It is included in WebmasterRegistrationSession.
type AndroidAttributionState struct {
	Capture               AndroidAttributionCapture         `json:"capture"`
	ClickReport           AndroidAttributionReport          `json:"click_report"`
	InstallReport         AndroidAttributionReport          `json:"install_report"`
	ReferrerReport        AndroidAttributionReport          `json:"referrer_report"`
	Referrer              *AndroidReferrerData              `json:"referrer,omitempty"`
	AppInstallMediaSource *string                           `json:"app_install_media_source,omitempty"`
	WebmasterUK           *int64                            `json:"tera_link_webmaster_uk,omitempty"`
	NativeMediaCache      *AndroidNativeMediaCache          `json:"native_media_cache,omitempty"`
	AfCampaign            *string                           `json:"af_campaign,omitempty"`
	DeepLinkValue         *string                           `json:"deep_link_value,omitempty"`
	PostLogin             *AndroidPostLoginAttributionState `json:"post_login,omitempty"`
}

func cloneAndroidAttribution(state *AndroidAttributionState) *AndroidAttributionState {
	if state == nil {
		return nil
	}
	// The model contains only JSON-safe scalar values. A JSON copy also copies
	// all nullable strings and raw responses, preventing shared mutable state.
	body, _ := json.Marshal(state)
	var copy AndroidAttributionState
	_ = json.Unmarshal(body, &copy)
	return &copy
}

func attributionStringValid(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func validateAndroidAttributionCapture(capture AndroidAttributionCapture, deviceID string) error {
	if capture.DeviceID == "" || capture.DeviceID != deviceID {
		return errors.New("attribution capture must belong to this Android installation's device ID")
	}
	if capture.Click == nil && capture.Install == nil {
		return errors.New("attribution capture requires observed click or installation inputs")
	}
	if capture.InstallReferrer != nil && capture.Install == nil {
		return errors.New("Play install referrer requires its observed installation inputs")
	}
	if capture.InstallReferrer != nil && !attributionStringValid(*capture.InstallReferrer) {
		return errors.New("Play install referrer must be valid UTF-8 without control characters")
	}
	if capture.NativeMediaCache != nil {
		if capture.NativeMediaCache.Initialized != (capture.NativeMediaCache.Value != nil) ||
			(capture.NativeMediaCache.Value != nil && !attributionStringValid(*capture.NativeMediaCache.Value)) {
			return errors.New("observed native media cache has inconsistent initialization/value")
		}
	}
	for _, value := range []*string{capture.StoredMediaSource, capture.MaterialSourceScene} {
		if value != nil && !attributionStringValid(*value) {
			return errors.New("observed installation cache contains an invalid string")
		}
	}
	if click := capture.Click; click != nil {
		page, err := url.Parse(click.PageURL)
		if err != nil || page.Scheme != "https" || page.User != nil ||
			(page.Hostname() != TeraBoxDomain && !strings.HasSuffix(page.Hostname(), "."+TeraBoxDomain)) {
			return errors.New("click page URL must be its observed HTTPS TeraBox URL")
		}
		deepLink, err := url.Parse(click.DeepLink)
		if err != nil || (deepLink.Scheme != "dubox" && deepLink.Scheme != "terabox") || deepLink.Host == "" {
			return errors.New("click requires the observed dubox or terabox app-open deeplink")
		}
		if strings.TrimSpace(click.UserAgent) == "" || strings.TrimSpace(click.TeraLinkID) == "" || click.TeraLinkType <= 0 {
			return errors.New("click requires its observed browser UA, tera_link_id and tera_link_type")
		}
		for _, value := range []string{click.PageURL, click.UserAgent, click.DeepLink, click.TeraLinkID,
			click.Language, click.OSVersion, click.Device, click.Referrer} {
			if !attributionStringValid(value) {
				return errors.New("click capture contains an invalid string")
			}
		}
		for _, value := range []*string{click.Agency, click.OpSource} {
			if value != nil && !attributionStringValid(*value) {
				return errors.New("click capture contains an invalid optional string")
			}
		}
		if err := validateAndroidClickCommonParams(click, deviceID); err != nil {
			return err
		}
	}
	if install := capture.Install; install != nil {
		if install.Clipboard != "" {
			return errors.New("APK install/referrer reporters send an empty clipboard")
		}
		if (install.InstallTime != nil && *install.InstallTime < 0) || install.FirstLaunchTime < 0 || install.FirstLaunchTime%1000 != 0 {
			return errors.New("installation times must be actual nonnegative milliseconds; first launch uses saved seconds multiplied by 1000")
		}
		for _, value := range []string{install.DeviceCountry, install.DeviceLanguage, install.OSVersion, install.Device} {
			if !attributionStringValid(value) {
				return errors.New("installation capture contains an invalid string")
			}
		}
	}
	return nil
}

func validateAndroidClickCommonParams(click *AndroidClickAttribution, deviceID string) error {
	required := []string{"app_id", "web", "channel", "clienttype", "jsToken", "dp-logid", "version", "devuid", "cuid", "lang"}
	allowed := map[string]bool{"app_id": true, "web": true, "channel": true, "clienttype": true, "jsToken": true,
		"dp-logid": true, "version": true, "devuid": true, "cuid": true, "lang": true,
		"rand": true, "time": true, "zid": true, "ck_st": true, "ck_val": true, "ck_own": true, "ck_tk": true}
	for _, key := range required {
		if _, exists := click.CommonParams[key]; !exists {
			return errors.New("click requires its captured interceptor common query, including browser jsToken and dp-logid")
		}
	}
	for key, value := range click.CommonParams {
		if !allowed[key] || !attributionStringValid(value) {
			return errors.New("click common query contains an unsupported or invalid captured field")
		}
	}
	if click.CommonParams["app_id"] != "250528" || click.CommonParams["web"] != "1" {
		return errors.New("click common query requires the captured share-page app_id and web values")
	}
	switch click.CommonParams["clienttype"] {
	case "5":
		if click.CommonParams["channel"] != "dubox" || click.CommonParams["version"] != "0" ||
			click.CommonParams["devuid"] != "0" || click.CommonParams["cuid"] != "0" || len(click.BridgeBody) != 0 {
			return errors.New("browser click query must retain the public page's browser common values")
		}
		for _, key := range []string{"rand", "time", "zid", "ck_st", "ck_val", "ck_own", "ck_tk"} {
			if _, exists := click.CommonParams[key]; exists {
				return errors.New("browser click cannot contain Android WebView signing fields")
			}
		}
	case "1":
		if click.CommonParams["devuid"] != deviceID || click.CommonParams["cuid"] != deviceID {
			return errors.New("WebView click query must belong to the captured Android installation")
		}
		for _, key := range []string{"version", "devuid", "cuid"} {
			if value, exists := click.BridgeBody[key]; !exists || value != click.CommonParams[key] {
				return errors.New("WebView click requires captured bridge body fields matching its common query")
			}
		}
		if value, exists := click.BridgeBody["lang"]; exists && value != click.Language {
			return errors.New("captured final WebView body language must preserve the endpoint browser language")
		}
	default:
		return errors.New("click common query requires a captured browser or Android WebView client type")
	}
	for key, value := range click.BridgeBody {
		if (key != "version" && key != "devuid" && key != "cuid" && key != "lang") || !attributionStringValid(value) {
			return errors.New("click bridge body contains an unsupported or invalid captured field")
		}
	}
	if !attributionStringValid(click.BrowserCookies) {
		return errors.New("captured browser cookies contain invalid characters")
	}
	return nil
}

func validateAndroidAttributionState(state *AndroidAttributionState, profile AndroidAppProfile) error {
	if state == nil {
		return nil
	}
	if err := validateAndroidAttributionCapture(state.Capture, profile.DeviceID); err != nil {
		return err
	}
	reports := []AndroidAttributionReport{state.ClickReport, state.InstallReport, state.ReferrerReport}
	if state.PostLogin != nil {
		reports = append(reports, state.PostLogin.InviteReport, state.PostLogin.MaterialReport)
	}
	for _, report := range reports {
		if (report.Succeeded && (!report.Attempted || report.Errno == nil || *report.Errno != 0)) ||
			(!report.Attempted && (report.HTTPStatus != 0 || report.Errno != nil || report.RequestID != "" || len(report.RawResponse) != 0 || len(report.RawBody) != 0)) {
			return errors.New("saved attribution report has inconsistent attempt/result state")
		}
		if report.HTTPStatus < 0 || report.HTTPStatus > 599 || (report.HTTPStatus > 0 && report.HTTPStatus < 100) {
			return errors.New("saved attribution report has an invalid HTTP status")
		}
		if len(report.RawResponse) != 0 && !json.Valid(report.RawResponse) {
			return errors.New("saved attribution response must be valid JSON")
		}
		if len(report.RawBody) > androidAttributionResponseLimit {
			return errors.New("saved attribution wire bytes exceed the read limit")
		}
		if len(report.RawBody) != 0 && len(report.RawResponse) != 0 {
			var bodyValue, responseValue any
			decode := func(body []byte, target *any) error {
				decoder := json.NewDecoder(bytes.NewReader(body))
				decoder.UseNumber()
				return decoder.Decode(target)
			}
			if !json.Valid(report.RawBody) || decode(report.RawBody, &bodyValue) != nil || decode(report.RawResponse, &responseValue) != nil || !reflect.DeepEqual(bodyValue, responseValue) {
				return errors.New("saved attribution JSON does not match its original wire bytes")
			}
		}
		if len(report.RawBody) != 0 && !json.Valid(report.RawBody) && (report.Succeeded || report.Errno != nil || report.RequestID != "") {
			return errors.New("non-JSON attribution wire bytes cannot have confirmed envelope metadata")
		}
		if report.Succeeded && (report.HTTPStatus != http.StatusOK || len(report.RawResponse) == 0) {
			return errors.New("confirmed attribution report requires its actual successful HTTP response")
		}
		if len(report.RawResponse) != 0 {
			var envelope androidAttributionEnvelope
			decodeErr := json.Unmarshal(report.RawResponse, &envelope)
			if decodeErr != nil {
				if report.Succeeded || report.Errno != nil || report.RequestID != "" {
					return errors.New("invalid observed attribution envelope cannot have confirmed metadata")
				}
			} else if !reflect.DeepEqual(envelope.Errno, report.Errno) || attributionRequestID(envelope.RequestID) != report.RequestID {
				return errors.New("saved attribution metadata does not match its actual response")
			}
		}
	}
	if (state.ClickReport.Attempted && state.Capture.Click == nil) ||
		((state.InstallReport.Attempted || state.ReferrerReport.Attempted) && state.Capture.Install == nil) {
		return errors.New("saved attribution report is missing its captured inputs")
	}
	if state.ReferrerReport.Succeeded != (state.Referrer != nil) {
		return errors.New("saved attribution result must match its confirmed referrer report")
	}
	if state.ReferrerReport.Succeeded {
		referrer, err := attributionReferrerFromRaw(state.ReferrerReport.RawResponse)
		if err != nil || !reflect.DeepEqual(referrer, state.Referrer) {
			return errors.New("saved referrer data does not match its actual confirmed response")
		}
	}
	if state.Referrer != nil && (state.Capture.Install.IsFirstLaunch || state.NativeMediaCache != nil) && state.AppInstallMediaSource == nil {
		return errors.New("saved first-launch result is missing its derived installation media source")
	}
	if state.AppInstallMediaSource != nil {
		if state.Referrer == nil || state.Capture.Install == nil || (!state.Capture.Install.IsFirstLaunch && state.NativeMediaCache == nil) {
			return errors.New("saved installation media source requires a confirmed first-launch result")
		}
		if (state.NativeMediaCache == nil && (*state.AppInstallMediaSource != androidReferrerMediaSource(state.Referrer) ||
			profile.NativeParams["af_media_source"] != *state.AppInstallMediaSource ||
			profile.LegacyNativeParams["af_media_source"] != *state.AppInstallMediaSource)) ||
			(state.NativeMediaCache != nil && *state.AppInstallMediaSource != androidReferrerMediaSource(state.Referrer)) {
			return errors.New("saved installation media source does not match its result/profile")
		}
	}
	if state.NativeMediaCache != nil {
		cache := state.NativeMediaCache
		if cache.Initialized != (cache.Value != nil) || (cache.Value != nil && !attributionStringValid(*cache.Value)) {
			return errors.New("saved native media cache has inconsistent initialization/value")
		}
		// A durable pre-request checkpoint marks an uncertain attempt before
		// native common construction has initialized its static cache. That
		// snapshot must remain restorable while retaining the replay guard.
		for _, report := range []AndroidAttributionReport{state.InstallReport, state.ReferrerReport} {
			observed := report.Succeeded || report.HTTPStatus != 0 || report.Errno != nil || report.RequestID != "" || len(report.RawResponse) != 0 || len(report.RawBody) != 0
			if observed && !cache.Initialized {
				return errors.New("observed native report response requires its initialized process media cache")
			}
		}
		if cache.Initialized && (profile.NativeParams["af_media_source"] != *cache.Value || profile.LegacyNativeParams["af_media_source"] != *cache.Value) {
			return errors.New("saved native media cache does not match effective profile values")
		}
		if captured := state.Capture.NativeMediaCache; captured != nil && captured.Initialized && !reflect.DeepEqual(captured, cache) {
			return errors.New("saved native media cache changed its actually observed initialized value")
		}
		if state.Referrer != nil &&
			(state.AppInstallMediaSource == nil || *state.AppInstallMediaSource != androidReferrerMediaSource(state.Referrer) ||
				!reflect.DeepEqual(state.AfCampaign, state.Referrer.Campaign) || !reflect.DeepEqual(state.DeepLinkValue, state.Referrer.DeepLinkValue)) {
			return errors.New("saved first-launch MMKV attribution does not match actual response")
		}
	}
	if state.AfCampaign != nil || state.DeepLinkValue != nil {
		if state.Referrer == nil || state.Capture.Install == nil ||
			!reflect.DeepEqual(state.AfCampaign, state.Referrer.Campaign) || !reflect.DeepEqual(state.DeepLinkValue, state.Referrer.DeepLinkValue) {
			return errors.New("saved campaign/material cache requires its actual first-launch referrer response")
		}
	}
	if err := validateAndroidPostLoginAttribution(state, profile); err != nil {
		return err
	}
	if state.WebmasterUK != nil {
		if state.Referrer == nil || state.Capture.Install == nil || !state.Capture.Install.IsFirstLaunch || state.Referrer.DeepLink == nil {
			return errors.New("saved Webmaster UK requires a returned first-launch deeplink")
		}
		deepLink, err := url.Parse(*state.Referrer.DeepLink)
		if err != nil {
			return errors.New("saved Webmaster UK has invalid returned deeplink")
		}
		owner, err := strconv.ParseInt(deepLink.Query().Get("uk"), 10, 64)
		if err != nil || owner == -1 || owner != *state.WebmasterUK {
			return errors.New("saved Webmaster UK does not match the returned deeplink")
		}
	}
	return nil
}

func attributionRequestID(raw json.RawMessage) string {
	var value string
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

func attributionReferrerFromRaw(raw json.RawMessage) (*AndroidReferrerData, error) {
	var envelope androidAttributionEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Errno == nil || *envelope.Errno != 0 {
		return nil, errors.New("attribution response is missing a successful envelope")
	}
	data := strings.TrimSpace(string(envelope.Data))
	if len(data) == 0 || data[0] != '{' {
		return nil, errors.New("successful attribution response is missing nonnull object referrer data")
	}
	var referrer AndroidReferrerData
	if err := json.Unmarshal(envelope.Data, &referrer); err != nil {
		return nil, errors.New("attribution response contains invalid referrer data")
	}
	return &referrer, nil
}

func attributionWebmasterUK(referrer *AndroidReferrerData) *int64 {
	if referrer.DeepLink != nil {
		if deepLink, err := url.Parse(*referrer.DeepLink); err == nil {
			if owner, err := strconv.ParseInt(deepLink.Query().Get("uk"), 10, 64); err == nil && owner != -1 {
				return &owner
			}
		}
	}
	return nil
}

func applyAttributionMedia(profile *AndroidAppProfile, value string) {
	for _, values := range []*map[string]string{&profile.NativeParams, &profile.LegacyNativeParams} {
		if *values == nil {
			*values = make(map[string]string)
		}
		(*values)["af_media_source"] = value
	}
}

func androidReferrerMediaSource(referrer *AndroidReferrerData) string {
	if referrer.MediaSource == nil || strings.TrimSpace(*referrer.MediaSource) == "" {
		return "null"
	}
	return *referrer.MediaSource
}

// SetAndroidAttributionCapture validates and saves provenance before any HTTP
// operation. It cannot replace an existing capture or attach it to a different
// CUID. Restoring an installation uses RestoreWebmasterRegistrationSession.
func (c *Client) SetAndroidAttributionCapture(capture AndroidAttributionCapture) error {
	const op = "setAndroidAttributionCapture"
	if err := c.requireAndroidApp(); err != nil {
		return wrapErr(op, err)
	}
	profile := c.AndroidAppProfile()
	if err := validateAndroidAttributionCapture(capture, profile.DeviceID); err != nil {
		return wrapErr(op, err)
	}
	cache := androidObservedMediaCache(capture, *profile)
	if cache.Initialized {
		for _, params := range []map[string]string{profile.NativeParams, profile.LegacyNativeParams} {
			if observed, ok := params["af_media_source"]; ok && observed != *cache.Value {
				return wrapErr(op, errors.New("observed native media cache conflicts with effective profile"))
			}
		}
	}
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.androidAttribution != nil {
		return wrapErr(op, errors.New("installation already has an attribution capture"))
	}
	c.androidAttribution = cloneAndroidAttribution(&AndroidAttributionState{Capture: capture})
	c.androidAttribution.NativeMediaCache = cache
	if cache.Initialized {
		applyAttributionMedia(&c.androidApp.profile, *cache.Value)
	}
	return nil
}

// RestoreAndroidAttribution imports previously observed request/response state
// on a fresh client with the same CUID. Confirmed reports must include their
// successful HTTP status and exact raw response. Returned first-launch media
// is normalized from that response and applied to the profile without HTTP.
// Already-attempted reports remain attempted; they are never silently replayed.
func (c *Client) RestoreAndroidAttribution(state *AndroidAttributionState) error {
	const op = "restoreAndroidAttribution"
	if err := c.requireAndroidApp(); err != nil {
		return wrapErr(op, err)
	}
	if state == nil {
		return wrapErr(op, errors.New("observed attribution state is required"))
	}
	for _, report := range []AndroidAttributionReport{state.ClickReport, state.InstallReport, state.ReferrerReport} {
		if len(report.RawResponse) != 0 && !json.Valid(report.RawResponse) {
			return wrapErr(op, errors.New("observed attribution response must be valid JSON"))
		}
	}
	normalized := cloneAndroidAttribution(state)
	profile := c.AndroidAppProfile()
	if normalized.NativeMediaCache == nil && normalized.Capture.NativeMediaCache != nil {
		normalized.NativeMediaCache = androidObservedMediaCache(normalized.Capture, *profile)
	}
	if normalized.ReferrerReport.Succeeded {
		referrer, err := attributionReferrerFromRaw(normalized.ReferrerReport.RawResponse)
		if err != nil {
			return wrapErr(op, err)
		}
		if normalized.Referrer != nil && !reflect.DeepEqual(normalized.Referrer, referrer) {
			return wrapErr(op, errors.New("imported referrer conflicts with its actual response"))
		}
		normalized.Referrer = referrer
		if normalized.Capture.Install != nil && (normalized.Capture.Install.IsFirstLaunch || normalized.NativeMediaCache != nil) {
			mediaSource := androidReferrerMediaSource(referrer)
			var owner *int64
			if normalized.Capture.Install.IsFirstLaunch {
				owner = attributionWebmasterUK(referrer)
			}
			if (normalized.AppInstallMediaSource != nil && *normalized.AppInstallMediaSource != mediaSource) ||
				(normalized.WebmasterUK != nil && !reflect.DeepEqual(normalized.WebmasterUK, owner)) {
				return wrapErr(op, errors.New("imported installation attribution conflicts with its actual response"))
			}
			if (normalized.AfCampaign != nil && !reflect.DeepEqual(normalized.AfCampaign, referrer.Campaign)) ||
				(normalized.DeepLinkValue != nil && !reflect.DeepEqual(normalized.DeepLinkValue, referrer.DeepLinkValue)) {
				return wrapErr(op, errors.New("imported campaign/material cache conflicts with its actual response"))
			}
			normalized.WebmasterUK = owner
			if normalized.NativeMediaCache == nil && normalized.Capture.NativeMediaCache == nil {
				// Keep legacy imported/session semantics reviewable. New captures
				// include the separate process cache and never force a refresh.
				normalized.AppInstallMediaSource = &mediaSource
				applyAttributionMedia(profile, mediaSource)
			} else {
				if normalized.NativeMediaCache == nil {
					normalized.NativeMediaCache = androidObservedMediaCache(normalized.Capture, *profile)
				}
				normalized.AppInstallMediaSource = &mediaSource
				normalized.AfCampaign, normalized.DeepLinkValue = referrer.Campaign, referrer.DeepLinkValue
			}
		}
	}
	if normalized.NativeMediaCache == nil && normalized.Capture.NativeMediaCache != nil {
		normalized.NativeMediaCache = androidObservedMediaCache(normalized.Capture, *profile)
	}
	if normalized.NativeMediaCache != nil && normalized.NativeMediaCache.Initialized {
		applyAttributionMedia(profile, *normalized.NativeMediaCache.Value)
	}
	if err := validateAndroidAttributionState(normalized, *profile); err != nil {
		return wrapErr(op, err)
	}
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.androidAttribution != nil || c.cookies["ndus"] != "" || c.referral != nil || c.registrationToken != "" || c.androidApp.ready {
		return wrapErr(op, errors.New("attribution import requires a fresh unauthenticated client"))
	}
	c.androidApp.profile = *profile
	c.androidAttribution = normalized
	return nil
}

// AndroidAttribution returns an independent private-state snapshot. Input URLs
// and raw responses can contain provenance tokens; persist them privately.
func (c *Client) AndroidAttribution() *AndroidAttributionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneAndroidAttribution(c.androidAttribution)
}

func (c *Client) attributionBegin(operation string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.androidAttribution == nil {
		return false, errors.New("observed Android attribution capture is required")
	}
	report := c.attributionReportLocked(operation)
	if report.Succeeded {
		return false, nil
	}
	if report.Attempted {
		return false, errors.New("attribution report was already attempted; inspect its outcome before replaying")
	}
	report.Attempted = true
	return true, nil
}

func (c *Client) attributionReportLocked(operation string) *AndroidAttributionReport {
	switch operation {
	case "click":
		return &c.androidAttribution.ClickReport
	case "install":
		return &c.androidAttribution.InstallReport
	case "invite":
		return &c.androidAttribution.PostLogin.InviteReport
	case "material":
		return &c.androidAttribution.PostLogin.MaterialReport
	default:
		return &c.androidAttribution.ReferrerReport
	}
}

type androidAttributionEnvelope struct {
	Errno     *int            `json:"errno"`
	ErrMsg    string          `json:"errmsg"`
	RequestID json.RawMessage `json:"request_id"`
	Data      json.RawMessage `json:"data"`
}

func (c *Client) attributionRequest(ctx context.Context, operation string, options *requestOpts, native bool) (*androidAttributionEnvelope, error) {
	op := "androidAttribution" + strings.ToUpper(operation[:1]) + operation[1:]
	req, err := c.newRequest(ctx, options)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if native {
		req, err = c.androidAppAPIRequest(req)
		if err != nil {
			return nil, wrapErr(op, err)
		}
	}
	resp, err := c.doHTTP(req, c.timeout)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	defer resp.Body.Close()
	c.mu.Lock()
	c.attributionReportLocked(operation).HTTPStatus = resp.StatusCode
	c.mu.Unlock()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, androidAttributionResponseLimit+1))
	oversized := len(body) > androidAttributionResponseLimit
	if oversized {
		body = body[:androidAttributionResponseLimit]
	}
	var envelope androidAttributionEnvelope
	decodeErr := json.Unmarshal(body, &envelope)
	c.mu.Lock()
	report := c.attributionReportLocked(operation)
	report.RawBody = append([]byte(nil), body...)
	report.RawResponse, report.Errno, report.RequestID = nil, nil, ""
	if json.Valid(body) {
		report.RawResponse = append(json.RawMessage(nil), body...)
	}
	if decodeErr == nil {
		report.Errno = envelope.Errno
		report.RequestID = attributionRequestID(envelope.RequestID)
	}
	c.mu.Unlock()
	if readErr != nil || oversized {
		return nil, wrapErr(op, errors.New("attribution response is incomplete or exceeds its read limit"))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, wrapErr(op, &httpStatusError{StatusCode: resp.StatusCode})
	}
	if decodeErr != nil {
		return nil, wrapErr(op, errors.New("attribution response is not a valid JSON envelope"))
	}
	if envelope.Errno == nil {
		return nil, wrapErr(op, errors.New("attribution response is missing errno"))
	}
	if *envelope.Errno != 0 {
		// Preserve the complete private response, but avoid exposing reflected
		// deeplinks/referrers through a server-supplied error message.
		return nil, wrapErr(op, &APIError{Code: *envelope.Errno, Message: "attribution report rejected"})
	}
	return &envelope, nil
}

// ReportAndroidShareClick reports the captured public share-page event using
// its browser form contract. Native common query fields and account cookies do
// not belong to this browser operation. A confirmed report is not sent twice.
func (c *Client) ReportAndroidShareClick(ctx context.Context) error {
	const op = "reportAndroidShareClick"
	if err := c.requireAndroidApp(); err != nil {
		return wrapErr(op, err)
	}
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	state := c.AndroidAttribution()
	if state == nil || state.Capture.Click == nil {
		return wrapErr(op, errors.New("observed share-page click is required"))
	}
	begin, err := c.attributionBegin("click")
	if err != nil || !begin {
		return wrapErr(op, err)
	}
	click := state.Capture.Click
	form := newForm()
	for _, field := range [][2]string{{"pid", "tera_sharelink"}, {"c", click.PageURL}, {"pdetail", "header_button"},
		{"tera_link_id", click.TeraLinkID}, {"tera_link_type", strconv.Itoa(click.TeraLinkType)},
		{"lang", click.Language}, {"os_version", click.OSVersion}, {"device", click.Device},
		{"af_dp", click.DeepLink}, {"referrer", click.Referrer}} {
		form.Append(field[0], field[1])
	}
	if click.Agency != nil {
		form.Append("agency", *click.Agency)
	}
	if click.OpSource != nil {
		form.Append("op_source", *click.OpSource)
	}
	for _, key := range []string{"version", "devuid", "cuid"} {
		if value, exists := click.BridgeBody[key]; exists {
			form.Set(key, value)
		}
	}
	query := make(url.Values, len(click.CommonParams))
	for key, value := range click.CommonParams {
		query.Set(key, value)
	}
	page, _ := url.Parse(click.PageURL)
	referer := *page
	referer.Fragment, referer.RawFragment = "", ""
	headers := map[string]string{"User-Agent": click.UserAgent, "Referer": click.PageURL,
		"Origin": urlOrigin(page), "X-Requested-With": "XMLHttpRequest",
		"Accept": "application/json, text/plain, */*"}
	headers["Referer"] = referer.String()
	if click.BrowserCookies != "" {
		headers["Cookie"] = click.BrowserCookies
	}
	_, err = c.attributionRequest(ctx, "click", &requestOpts{method: http.MethodPost,
		path: urlOrigin(page) + "/api/srn/ck", query: query, form: form, noCookie: true,
		headers: headers}, false)
	if err != nil {
		return wrapErr(op, err)
	}
	c.mu.Lock()
	c.androidAttribution.ClickReport.Succeeded = true
	c.mu.Unlock()
	return nil
}

func androidInstallAttributionQuery(install *AndroidInstallAttribution) url.Values {
	query := url.Values{"clipboard": {""}, "device_country": {install.DeviceCountry},
		"device_lang": {install.DeviceLanguage}, "os_version": {install.OSVersion}, "device": {install.Device},
		"first_launch_time": {strconv.FormatInt(install.FirstLaunchTime, 10)}}
	if install.InstallTime != nil {
		query.Set("install_time", strconv.FormatInt(*install.InstallTime, 10))
	}
	return query
}

func androidAttributionEndpointField(key string) bool {
	switch key {
	case "clipboard", "device_country", "device_lang", "os_version", "device", "install_time", "first_launch_time", "referer_data":
		return true
	}
	return false
}

// ReportAndroidInstall uses the APK's POST /api/srn/ins @Query contract with an
// empty body. Installation timestamps and locale/model inputs are supplied by
// capture; the normal native transport supplies common runtime parameters.
func (c *Client) ReportAndroidInstall(ctx context.Context) error {
	const op = "reportAndroidInstall"
	if err := c.requireAndroidApp(); err != nil {
		return wrapErr(op, err)
	}
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	state := c.AndroidAttribution()
	if state == nil || state.Capture.Install == nil {
		return wrapErr(op, errors.New("observed Android installation inputs are required"))
	}
	begin, err := c.attributionBegin("install")
	if err != nil || !begin {
		return wrapErr(op, err)
	}
	_, err = c.attributionRequest(ctx, "install", &requestOpts{method: http.MethodPost,
		path: "/api/srn/ins", query: androidInstallAttributionQuery(state.Capture.Install)}, true)
	if err != nil {
		return wrapErr(op, err)
	}
	c.mu.Lock()
	c.androidAttribution.InstallReport.Succeeded = true
	c.mu.Unlock()
	return nil
}

// QueryAndroidInstallReferrer sends the exact Play referrer when available. A
// nil referrer omits referer_data, matching the APK's timeout/unavailable path.
// Successful nonnull data is cached; first launch stores MMKV media/campaign and
// the local Webmaster UK parsed only from returned deeplink. The initialized
// RequestCommonParams media cache stays unchanged for subsequent native calls.
func (c *Client) QueryAndroidInstallReferrer(ctx context.Context) (*AndroidReferrerData, error) {
	const op = "queryAndroidInstallReferrer"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	state := c.AndroidAttribution()
	if state == nil || state.Capture.Install == nil {
		return nil, wrapErr(op, errors.New("observed Android installation inputs are required"))
	}
	begin, err := c.attributionBegin("referrer")
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if !begin {
		return state.Referrer, nil
	}
	query := androidInstallAttributionQuery(state.Capture.Install)
	if state.Capture.InstallReferrer != nil {
		query.Set("referer_data", *state.Capture.InstallReferrer)
	}
	_, err = c.attributionRequest(ctx, "referrer", &requestOpts{method: http.MethodPost,
		path: "/api/srn/ref", query: query}, true)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	referrer, err := attributionReferrerFromRaw(c.AndroidAttribution().ReferrerReport.RawResponse)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	c.mu.Lock()
	c.androidAttribution.ReferrerReport.Succeeded = true
	c.androidAttribution.Referrer = referrer
	mediaSource := androidReferrerMediaSource(referrer)
	c.androidAttribution.AppInstallMediaSource = &mediaSource
	c.androidAttribution.AfCampaign, c.androidAttribution.DeepLinkValue = referrer.Campaign, referrer.DeepLinkValue
	if state.Capture.Install.IsFirstLaunch {
		c.androidAttribution.WebmasterUK = attributionWebmasterUK(referrer)
	}
	result := cloneAndroidAttribution(c.androidAttribution).Referrer
	c.mu.Unlock()
	return result, nil
}
