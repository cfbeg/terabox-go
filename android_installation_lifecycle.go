package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// AndroidInstallationLifecycleObservation is a snapshot from the same running
// guest installation. Dates are the APK's locale-selected strings, not ISO
// dates. TimeZone must be explicitly observed; no local-machine zone is guessed.
type AndroidInstallationLifecycleObservation struct {
	DeviceID             string `json:"device_id"`
	IsGuest              bool   `json:"is_guest"`
	Language             string `json:"language"`
	TimeZone             string `json:"time_zone"`
	DatePattern          string `json:"date_pattern"`
	ObservedToday        string `json:"observed_today"`
	LastUnloginDay       string `json:"last_unlogin_day"`
	DeviceActivated      bool   `json:"device_activated"`
	ActivatedTimeSeconds int64  `json:"activated_time_seconds,omitempty"`
}

// AndroidInstallationLifecycleState is private, installation-scoped state.
// Reports and observed native flags are distinct. An attempted unknown request
// remains attempted across restore, even if the native success flag is false.
type AndroidInstallationLifecycleState struct {
	Version         int                                     `json:"version"`
	Observation     AndroidInstallationLifecycleObservation `json:"observation"`
	UnloginReports  map[string]AndroidAttributionReport     `json:"unlogin_reports,omitempty"`
	DeviceReport    AndroidAttributionReport                `json:"device_report"`
	DeviceSignature *AndroidDeviceActivationSignature       `json:"device_signature,omitempty"`
}

type AndroidInstallationLifecycleResult struct {
	Attempted bool `json:"attempted"`
	Skipped   bool `json:"skipped"`
}

func androidUnloginDatePattern(language string) (string, string) {
	switch language {
	case "th", "vi", "ru", "ar", "es", "hi", "in", "pt":
		return "dd/MM/yyyy", "02/01/2006"
	case "en":
		return "MM-dd-yyyy", "01-02-2006"
	case "ja", "ko", "cn":
		return "MM/dd/yyyy", "01/02/2006"
	default:
		return "yyyy.MM.dd", "2006.01.02"
	}
}

func cloneInstallationLifecycle(state *AndroidInstallationLifecycleState) *AndroidInstallationLifecycleState {
	data, _ := json.Marshal(state)
	var copy AndroidInstallationLifecycleState
	_ = json.Unmarshal(data, &copy)
	return &copy
}

func validateInstallationLifecycle(state *AndroidInstallationLifecycleState) error {
	if state == nil || state.Version != 1 {
		return errors.New("invalid installation lifecycle state")
	}
	o := state.Observation
	pattern, layout := androidUnloginDatePattern(o.Language)
	if o.DeviceID == "" || !attributionStringValid(o.DeviceID) || !o.IsGuest || o.Language == "" ||
		!attributionStringValid(o.Language) || o.TimeZone == "" || o.TimeZone == "Local" || o.DatePattern != pattern || o.ActivatedTimeSeconds < 0 {
		return errors.New("lifecycle state requires an observed guest identity, language, date pattern and explicit device time zone")
	}
	if _, err := time.LoadLocation(o.TimeZone); err != nil {
		return errors.New("invalid observed device time zone")
	}
	if _, err := time.Parse(layout, o.ObservedToday); err != nil {
		return errors.New("observed native date does not match its captured pattern")
	}
	// The previous value can have a different pattern after a locale change.
	// Preserve it as an opaque bounded string: the APK compares strings directly.
	if len(o.LastUnloginDay) > 32 || !attributionStringValid(o.LastUnloginDay) || (!o.DeviceActivated && o.ActivatedTimeSeconds != 0) {
		return errors.New("invalid observed lifecycle flags or last-day value")
	}
	if len(state.UnloginReports) > 4096 {
		return errors.New("lifecycle journal exceeds its supported size")
	}
	for day, report := range state.UnloginReports {
		if len(day) > 32 || !attributionStringValid(day) || !validLifecycleReport(report) {
			return errors.New("invalid unlogin lifecycle journal")
		}
	}
	if !validLifecycleReport(state.DeviceReport) || state.DeviceReport.Attempted && state.DeviceSignature == nil {
		return errors.New("device lifecycle journal lacks its signature input")
	}
	return nil
}

func validLifecycleReport(report AndroidAttributionReport) bool {
	if !report.Attempted {
		return !report.Succeeded && report.HTTPStatus == 0 && report.Errno == nil && len(report.RawBody) == 0 && len(report.RawResponse) == 0
	}
	if !report.Succeeded {
		return true
	}
	var envelope androidAttributionEnvelope
	return report.HTTPStatus == 200 && report.Errno != nil && *report.Errno == 0 &&
		json.Unmarshal(report.RawResponse, &envelope) == nil && envelope.Errno != nil && *envelope.Errno == 0
}

func NewAndroidInstallationLifecycleState(observed AndroidInstallationLifecycleObservation) (*AndroidInstallationLifecycleState, error) {
	state := &AndroidInstallationLifecycleState{Version: 1, Observation: observed}
	if err := validateInstallationLifecycle(state); err != nil {
		return nil, err
	}
	return state, nil
}

func (c *Client) requireLifecycleGuest(state *AndroidInstallationLifecycleState) error {
	if err := c.requireAndroidApp(); err != nil {
		return err
	}
	if err := validateInstallationLifecycle(state); err != nil {
		return err
	}
	profile := c.AndroidAppProfile()
	ndus, _ := c.CookieValue("ndus")
	if profile.DeviceID != state.Observation.DeviceID || profile.UID != "" || profile.EncodedSK != "" || ndus != "" {
		return errors.New("lifecycle report requires the same observed guest installation without account credentials")
	}
	return nil
}

// ReportAndroidUnloginActive explicitly performs h40._.f's legacy GET when the
// APK's observed current day compares lexicographically greater than the stored
// day. This intentionally preserves the APK's locale-dependent comparison,
// including month/year-boundary suppression for non-sortable date patterns.
// It is never called automatically on login or registration.
func (c *Client) ReportAndroidUnloginActive(ctx context.Context, state *AndroidInstallationLifecycleState, observedToday string, persist func(*AndroidInstallationLifecycleState) error) (*AndroidInstallationLifecycleResult, error) {
	if err := c.requireAndroidApp(); err != nil {
		return nil, err
	}
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	if err := c.requireLifecycleGuest(state); err != nil {
		return nil, err
	}
	if persist == nil {
		return nil, errors.New("lifecycle persistence is required")
	}
	zone, _ := time.LoadLocation(state.Observation.TimeZone)
	_, layout := androidUnloginDatePattern(state.Observation.Language)
	if observedToday != time.UnixMilli(c.androidAppTime()).In(zone).Format(layout) {
		return nil, errors.New("current observed native day does not match the device zone and locale pattern")
	}
	if observedToday <= state.Observation.LastUnloginDay {
		return &AndroidInstallationLifecycleResult{Skipped: true}, nil
	}
	if prior := state.UnloginReports[observedToday]; prior.Attempted {
		return nil, errors.New("this native day's unlogin report was already attempted; no implicit replay")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state.UnloginReports == nil {
		state.UnloginReports = make(map[string]AndroidAttributionReport)
	}
	state.Observation.ObservedToday = observedToday
	state.UnloginReports[observedToday] = AndroidAttributionReport{Attempted: true}
	if persist(cloneInstallationLifecycle(state)) != nil {
		return nil, errors.New("unlogin pre-send state could not be persisted; no report was sent")
	}
	report, requestErr := c.lifecycleGET(ctx, "/api/analytics", url.Values{"type": {"unloginactive"}})
	state.UnloginReports[observedToday] = report
	if report.Succeeded {
		state.Observation.LastUnloginDay = observedToday
	}
	result := &AndroidInstallationLifecycleResult{Attempted: true}
	if persist(cloneInstallationLifecycle(state)) != nil {
		return result, errors.New("unlogin report was attempted but its outcome could not be persisted")
	}
	return result, requestErr
}

// AndroidDeviceActivationSignature is an observed signature from the same
// native installation/channel/clienttype and the exact millisecond timestamp.
type AndroidDeviceActivationSignature struct {
	DeviceID    string `json:"device_id"`
	Channel     string `json:"channel"`
	ClientType  int    `json:"clienttype"`
	TimestampMS int64  `json:"timestamp_ms"`
	Signature   string `json:"signature"`
}

type AndroidDeviceActivationSignRequest struct {
	DeviceID    string `json:"device_id"`
	Channel     string `json:"channel"`
	ClientType  int    `json:"clienttype"`
	TimestampMS int64  `json:"timestamp_ms"`
	Message     string `json:"message"`
}

// AndroidDeviceActivationSigner delegates hv.______.__ to the actual native
// installation; the SDK never recreates KeyMaker or fabricates its HMAC key.
type AndroidDeviceActivationSigner interface {
	SignAndroidDeviceActivation(context.Context, AndroidDeviceActivationSignRequest) (*AndroidDeviceActivationSignature, error)
}

type AndroidDeviceActivationOptions struct {
	ObservedSignature *AndroidDeviceActivationSignature
	Signer            AndroidDeviceActivationSigner
}

// ReportAndroidDeviceActivation explicitly sends the installation's one-time
// legacy report/device GET. Exactly one signature source is required. Only a
// complete errno=0 response updates the activated flag/time in the saved state.
func (c *Client) ReportAndroidDeviceActivation(ctx context.Context, state *AndroidInstallationLifecycleState, options AndroidDeviceActivationOptions, persist func(*AndroidInstallationLifecycleState) error) (*AndroidInstallationLifecycleResult, error) {
	if err := c.requireAndroidApp(); err != nil {
		return nil, err
	}
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	if err := c.requireLifecycleGuest(state); err != nil {
		return nil, err
	}
	if state.Observation.DeviceActivated {
		return &AndroidInstallationLifecycleResult{Skipped: true}, nil
	}
	if state.DeviceReport.Attempted {
		return nil, errors.New("device activation was already attempted; inspect its outcome before explicit recovery")
	}
	if persist == nil || (options.ObservedSignature == nil) == (options.Signer == nil) {
		return nil, errors.New("persistence and exactly one native signature source are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profile := c.AndroidAppProfile()
	signature := options.ObservedSignature
	if signature == nil {
		stamp := c.androidAppTime()
		message := strconv.Itoa(profile.ClientType) + profile.NativeChannel + profile.DeviceID + strconv.FormatInt(stamp, 10)
		var err error
		signature, err = options.Signer.SignAndroidDeviceActivation(ctx, AndroidDeviceActivationSignRequest{
			DeviceID: profile.DeviceID, Channel: profile.NativeChannel, ClientType: profile.ClientType, TimestampMS: stamp, Message: message})
		if err != nil {
			return nil, errors.New("native device signature could not be obtained; no activation report was sent")
		}
		if signature == nil || signature.TimestampMS != stamp {
			return nil, errors.New("native signer returned a different request timestamp; no activation report was sent")
		}
	}
	if signature == nil || signature.DeviceID != profile.DeviceID || signature.Channel != profile.NativeChannel || signature.ClientType != profile.ClientType || signature.TimestampMS <= 0 || signature.Signature == "" || len(signature.Signature) > 4096 || !attributionStringValid(signature.Signature) {
		return nil, errors.New("device activation signature does not match the observed installation")
	}
	copy := *signature
	state.DeviceSignature, state.DeviceReport.Attempted = &copy, true
	if persist(cloneInstallationLifecycle(state)) != nil {
		return nil, errors.New("device activation pre-send state could not be persisted; no report was sent")
	}
	report, requestErr := c.lifecycleGET(ctx, "/api/report/device", url.Values{"timestamp": {strconv.FormatInt(copy.TimestampMS, 10)}, "sign": {copy.Signature}})
	state.DeviceReport = report
	if report.Succeeded {
		state.Observation.DeviceActivated = true
		state.Observation.ActivatedTimeSeconds = c.androidAppTime() / 1000
	}
	result := &AndroidInstallationLifecycleResult{Attempted: true}
	if persist(cloneInstallationLifecycle(state)) != nil {
		return result, errors.New("device activation was attempted but its outcome could not be persisted")
	}
	return result, requestErr
}

func (c *Client) lifecycleGET(ctx context.Context, path string, query url.Values) (AndroidAttributionReport, error) {
	report := AndroidAttributionReport{Attempted: true}
	req, err := c.newRequest(ctx, &requestOpts{method: http.MethodGet, path: path, query: query})
	if err == nil {
		req, err = c.androidAppAPIRequestWithTransport(req, true)
	}
	if err != nil {
		return report, errors.New("installation lifecycle request could not be constructed")
	}
	endpointQuery := req.URL.Query()
	for key, values := range query {
		endpointQuery[key] = append([]string(nil), values...)
	}
	req.URL.RawQuery = endpointQuery.Encode()
	req = withObservedAPIRoute(req, "installationLifecycle", true)
	response, err := c.doHTTP(req, c.timeout)
	if err != nil {
		return report, errors.New("installation lifecycle request failed; retained outcome may be uncertain")
	}
	report.HTTPStatus = response.StatusCode
	body, readErr := io.ReadAll(io.LimitReader(response.Body, androidAttributionResponseLimit+1))
	closeErr := response.Body.Close()
	if len(body) > androidAttributionResponseLimit {
		body = body[:androidAttributionResponseLimit]
		readErr = errors.New("oversized lifecycle response")
	}
	report.RawBody = append([]byte(nil), body...)
	var envelope androidAttributionEnvelope
	if readErr == nil && json.Unmarshal(body, &envelope) == nil {
		report.RawResponse = append(json.RawMessage(nil), body...)
		report.Errno, report.RequestID = envelope.Errno, attributionRequestID(envelope.RequestID)
		report.Succeeded = closeErr == nil && response.StatusCode == 200 && envelope.Errno != nil && *envelope.Errno == 0
	}
	if !report.Succeeded {
		return report, errors.New("installation lifecycle response was not confirmed successful")
	}
	return report, nil
}
