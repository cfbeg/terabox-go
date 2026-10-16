package terabox

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

const statisticsEventLimit = 4 << 20

// AndroidStatisticsCapture holds one already serialized APK event batch. The
// SDK does not invent events, concatenate unknown schemas or infer a filename.
// Query is the statistics URL builder's observed query, not Retrofit common
// parameters. EventBytes and the capture are private installation data.
type AndroidStatisticsCapture struct {
	DeviceID   string            `json:"device_id"`
	Filename   string            `json:"filename"`
	Query      map[string]string `json:"query"`
	EventBytes []byte            `json:"event_bytes,omitempty"`
}

// AndroidStatisticsBatch is a restorable, single-attempt upload journal. A
// successful response removes EventBytes; a failed/uncertain attempt retains
// them and cannot be implicitly retransmitted. ID binds the immutable capture.
type AndroidStatisticsBatch struct {
	Version       int                      `json:"version"`
	ID            string                   `json:"id"`
	PayloadSHA256 string                   `json:"payload_sha256"`
	Capture       AndroidStatisticsCapture `json:"capture"`
	Report        AndroidAttributionReport `json:"report"`
}

func cloneStatisticsBatch(batch *AndroidStatisticsBatch) *AndroidStatisticsBatch {
	data, _ := json.Marshal(batch)
	var result AndroidStatisticsBatch
	_ = json.Unmarshal(data, &result)
	return &result
}

func statisticsBatchID(batch *AndroidStatisticsBatch) string {
	metadata := struct {
		DeviceID, Filename, PayloadSHA256 string
		Query                             map[string]string
	}{batch.Capture.DeviceID, batch.Capture.Filename, batch.PayloadSHA256, batch.Capture.Query}
	data, _ := json.Marshal(metadata)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func validateStatisticsCapture(capture AndroidStatisticsCapture) error {
	if capture.DeviceID == "" || !attributionStringValid(capture.DeviceID) || len(capture.DeviceID) > 1024 ||
		capture.Filename == "" || len(capture.Filename) > 128 || strings.ContainsAny(capture.Filename, "\r\n\x00\"\\/") || !utf8.ValidString(capture.Filename) {
		return errors.New("statistics capture requires its installation and a valid captured filename")
	}
	allowed := map[string]bool{"clienttype": true, "devuid": true, "channel": true, "version": true,
		"firstlaunchtime": true, "isVip": true, "vip_type": true, "carrier_country": true,
		"device_country": true, "phone_brand": true, "af_media_source": true, "lang": true,
		"versioncode": true, "ZID": true, "regDay": true, "ab_variant_a": true,
		"ab_variant_b": true, "ab_variant_c": true, "ab_variant_d": true, "ab_variant_e": true}
	for key, value := range capture.Query {
		if !allowed[key] || len(value) > 4096 || !attributionStringValid(value) {
			return errors.New("statistics query contains an unsupported or invalid captured field")
		}
	}
	if capture.Query["clienttype"] != "1" || capture.Query["devuid"] != capture.DeviceID || capture.Query["channel"] == "" || capture.Query["version"] == "" {
		return errors.New("statistics query must retain its observed Android identity, channel and version")
	}
	return nil
}

// NewAndroidStatisticsBatch copies captured event bytes without interpreting or
// altering their schema. The captured filename comes from the APK stats config.
func NewAndroidStatisticsBatch(capture AndroidStatisticsCapture) (*AndroidStatisticsBatch, error) {
	if err := validateStatisticsCapture(capture); err != nil {
		return nil, err
	}
	if len(capture.EventBytes) == 0 || len(capture.EventBytes) > statisticsEventLimit {
		return nil, errors.New("captured statistics batch is empty or exceeds its size limit")
	}
	batch := &AndroidStatisticsBatch{Version: 1, Capture: capture, PayloadSHA256: fmt.Sprintf("%x", sha256.Sum256(capture.EventBytes))}
	batch.ID = statisticsBatchID(batch)
	return cloneStatisticsBatch(batch), nil
}

func validateStatisticsBatch(batch *AndroidStatisticsBatch) error {
	if batch == nil || batch.Version != 1 || len(batch.PayloadSHA256) != 64 || batch.ID != statisticsBatchID(batch) {
		return errors.New("invalid or modified statistics batch")
	}
	if err := validateStatisticsCapture(batch.Capture); err != nil {
		return err
	}
	if batch.Report.Succeeded {
		var envelope androidAttributionEnvelope
		if !batch.Report.Attempted || batch.Report.HTTPStatus != 200 || batch.Report.Errno == nil || *batch.Report.Errno != 0 ||
			json.Unmarshal(batch.Report.RawResponse, &envelope) != nil || envelope.Errno == nil || *envelope.Errno != 0 || len(batch.Capture.EventBytes) != 0 {
			return errors.New("confirmed statistics batch lacks a matching response or retained a deleted payload")
		}
	} else if len(batch.Capture.EventBytes) == 0 || len(batch.Capture.EventBytes) > statisticsEventLimit || batch.PayloadSHA256 != fmt.Sprintf("%x", sha256.Sum256(batch.Capture.EventBytes)) {
		return errors.New("statistics payload does not match its captured digest")
	}
	if !batch.Report.Attempted && (batch.Report.HTTPStatus != 0 || batch.Report.Errno != nil || len(batch.Report.RawResponse) != 0 || len(batch.Report.RawBody) != 0) {
		return errors.New("statistics response state exists without an upload attempt")
	}
	return nil
}

// UploadAndroidStatistics reproduces n40._'s gzip userfile inside an ordinary
// multipart body, fixed boundary ***** and Content-Encoding: gzip header. The
// entire multipart body is NOT gzip-compressed. It deliberately uses the
// statistics query rather than appending native time/rand/common API fields.
// Persist must durably save each supplied snapshot: before transmission and
// after the outcome. It must not call back into this batch concurrently.
func (c *Client) UploadAndroidStatistics(ctx context.Context, batch *AndroidStatisticsBatch, persist func(*AndroidStatisticsBatch) error) error {
	const op = "uploadAndroidStatistics"
	if err := c.requireAndroidApp(); err != nil {
		return wrapErr(op, err)
	}
	if err := validateStatisticsBatch(batch); err != nil {
		return wrapErr(op, err)
	}
	if batch.Report.Succeeded {
		return nil
	}
	if batch.Report.Attempted {
		return wrapErr(op, errors.New("statistics batch was already attempted; inspect its saved outcome before any explicit recovery"))
	}
	if persist == nil {
		return wrapErr(op, errors.New("durable statistics batch persistence is required"))
	}
	if err := ctx.Err(); err != nil {
		return wrapErr(op, err)
	}
	profile := c.AndroidAppProfile()
	if batch.Capture.DeviceID != profile.DeviceID || batch.Capture.Query["channel"] != profile.NativeChannel || batch.Capture.Query["version"] != profile.Version {
		return wrapErr(op, errors.New("statistics capture belongs to a different Android installation or build"))
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Header.OS = 0 // Java GZIPOutputStream's platform byte.
	_, _ = writer.Write(batch.Capture.EventBytes)
	if err := writer.Close(); err != nil {
		return wrapErr(op, errors.New("statistics batch compression failed"))
	}
	var body bytes.Buffer
	fmt.Fprintf(&body, "--*****\r\nContent-Disposition: form-data; name=\"userfile\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", batch.Capture.Filename)
	body.Write(compressed.Bytes())
	body.WriteString("\r\n--*****--\r\n")
	host, _ := c.snapshot()
	query := url.Values{}
	for key, value := range batch.Capture.Query {
		query.Set(key, value)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(host, "/")+"/statistics?"+query.Encode(), bytes.NewReader(body.Bytes()))
	if err != nil {
		return wrapErr(op, errors.New("statistics request could not be constructed"))
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary=*****")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", profile.UserAgent)
	if ndus, _ := c.CookieValue("ndus"); ndus != "" {
		req.AddCookie(&http.Cookie{Name: "ndus", Value: ndus})
	}
	batch.Report.Attempted = true
	if err := persist(cloneStatisticsBatch(batch)); err != nil {
		return wrapErr(op, errors.New("statistics pre-send state could not be persisted; no upload was sent"))
	}
	response, requestErr := c.doHTTP(req, c.timeout)
	if response != nil {
		batch.Report.HTTPStatus = response.StatusCode
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, androidAttributionResponseLimit+1))
		closeErr := response.Body.Close()
		batch.Report.RawBody = append([]byte(nil), raw...)
		if len(raw) > androidAttributionResponseLimit {
			batch.Report.RawBody = batch.Report.RawBody[:androidAttributionResponseLimit]
			readErr = errors.New("statistics response exceeds its size limit")
		}
		var envelope androidAttributionEnvelope
		if readErr == nil && json.Unmarshal(raw, &envelope) == nil {
			batch.Report.RawResponse = append(json.RawMessage(nil), raw...)
			batch.Report.Errno = envelope.Errno
			batch.Report.RequestID = attributionRequestID(envelope.RequestID)
			if requestErr == nil && closeErr == nil && response.StatusCode == 200 && envelope.Errno != nil && *envelope.Errno == 0 {
				batch.Report.Succeeded = true
				batch.Capture.EventBytes = nil
			}
		}
		if readErr != nil || closeErr != nil {
			requestErr = errors.New("statistics response or its observation is incomplete")
		}
	}
	if err := persist(cloneStatisticsBatch(batch)); err != nil {
		return wrapErr(op, errors.New("statistics was attempted but its outcome could not be persisted"))
	}
	if requestErr != nil {
		return wrapErr(op, errors.New("statistics upload outcome is uncertain; inspect its retained journal"))
	}
	if !batch.Report.Succeeded {
		return wrapErr(op, errors.New("statistics upload was not confirmed successful"))
	}
	return nil
}

// AndroidAnalyticsEvent is the verified DevAction appsflyerReport input.
// IsReportFb means AppsFlyer AND FirebaseAnalytics, not Facebook. Both native
// SDK calls receive the same key and an empty parameter set on this bridge.
type AndroidAnalyticsEvent struct {
	Key        string `json:"key"`
	IsReportFb bool   `json:"isReportFb"`
}

// AndroidAnalyticsRequest is the executable adapter's single JSON stdin value.
type AndroidAnalyticsRequest struct {
	Version   int                   `json:"version"`
	Operation string                `json:"operation"`
	RequestID string                `json:"request_id"`
	DeviceID  string                `json:"device_id"`
	Event     AndroidAnalyticsEvent `json:"event"`
}

// AndroidAnalyticsReceipt confirms calls in the real SDK execution environment,
// not a third-party HTTP acknowledgement or a Webmaster acquisition credit.
type AndroidAnalyticsReceipt struct {
	Version         int    `json:"version"`
	RequestID       string `json:"request_id"`
	Key             string `json:"key"`
	AppsFlyerCalled bool   `json:"appsflyer_called"`
	FirebaseCalled  bool   `json:"firebase_called"`
	Environment     string `json:"environment"`
}

// AndroidAnalyticsBridge executes the event in an environment that has the
// actual AppsFlyer/Firebase SDKs and returns correlated execution evidence.
type AndroidAnalyticsBridge interface {
	ExecuteAndroidAnalytics(context.Context, AndroidAnalyticsRequest) (*AndroidAnalyticsReceipt, error)
}

// AndroidAnalyticsDispatch is single-attempt state for one bridge invocation.
type AndroidAnalyticsDispatch struct {
	Request   AndroidAnalyticsRequest  `json:"request"`
	Attempted bool                     `json:"attempted"`
	Receipt   *AndroidAnalyticsReceipt `json:"receipt,omitempty"`
}

func validAnalyticsRequest(request AndroidAnalyticsRequest) bool {
	return request.Version == 1 && request.Operation == "appsflyerReport" && len(request.RequestID) == 64 &&
		strings.IndexFunc(request.RequestID, func(r rune) bool { return !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') }) < 0 &&
		request.DeviceID != "" && len(request.DeviceID) <= 1024 && attributionStringValid(request.DeviceID) &&
		request.Event.Key != "" && len(request.Event.Key) <= 128 && attributionStringValid(request.Event.Key)
}

func validAnalyticsReceipt(request AndroidAnalyticsRequest, receipt *AndroidAnalyticsReceipt) bool {
	return receipt != nil && receipt.Version == 1 && receipt.RequestID == request.RequestID && receipt.Key == request.Event.Key &&
		receipt.AppsFlyerCalled && receipt.FirebaseCalled == request.Event.IsReportFb && receipt.Environment != "" &&
		len(receipt.Environment) <= 128 && attributionStringValid(receipt.Environment)
}

// NewAndroidAnalyticsDispatch binds a caller's durable, unique operation ID to
// one genuine observed event. Reuse the returned state when resuming a session.
func NewAndroidAnalyticsDispatch(operationID, deviceID string, event AndroidAnalyticsEvent) (*AndroidAnalyticsDispatch, error) {
	if operationID == "" || len(operationID) > 4096 || !attributionStringValid(operationID) {
		return nil, errors.New("analytics requires a nonempty operation ID")
	}
	data, _ := json.Marshal(struct {
		ID, DeviceID string
		Event        AndroidAnalyticsEvent
	}{operationID, deviceID, event})
	request := AndroidAnalyticsRequest{Version: 1, Operation: "appsflyerReport", RequestID: fmt.Sprintf("%x", sha256.Sum256(data)), DeviceID: deviceID, Event: event}
	if !validAnalyticsRequest(request) {
		return nil, errors.New("invalid observed analytics bridge event")
	}
	return &AndroidAnalyticsDispatch{Request: request}, nil
}

// ExecuteAndroidAnalytics durably marks an invocation before executing it.
// Missing/mismatched proof and adapter errors retain Attempted without a receipt;
// neither SDK is automatically invoked again after a partial/uncertain result.
func ExecuteAndroidAnalytics(ctx context.Context, dispatch *AndroidAnalyticsDispatch, bridge AndroidAnalyticsBridge, persist func(*AndroidAnalyticsDispatch) error) error {
	if dispatch == nil || !validAnalyticsRequest(dispatch.Request) || bridge == nil || persist == nil || (dispatch.Receipt != nil && (!dispatch.Attempted || !validAnalyticsReceipt(dispatch.Request, dispatch.Receipt))) {
		return errors.New("valid analytics state, execution adapter and persistence are required")
	}
	if dispatch.Receipt != nil {
		return nil
	}
	if dispatch.Attempted {
		return errors.New("analytics dispatch was already attempted; inspect the runtime before explicit recovery")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot := func() *AndroidAnalyticsDispatch {
		data, _ := json.Marshal(dispatch)
		var copy AndroidAnalyticsDispatch
		_ = json.Unmarshal(data, &copy)
		return &copy
	}
	dispatch.Attempted = true
	if err := persist(snapshot()); err != nil {
		return errors.New("analytics pre-execution state could not be persisted; adapter was not invoked")
	}
	receipt, err := bridge.ExecuteAndroidAnalytics(ctx, dispatch.Request)
	if err == nil && validAnalyticsReceipt(dispatch.Request, receipt) {
		dispatch.Receipt = receipt
	}
	if saveErr := persist(snapshot()); saveErr != nil {
		return errors.New("analytics was attempted but execution evidence could not be persisted")
	}
	if dispatch.Receipt == nil {
		return errors.New("analytics execution lacks correlated SDK evidence; do not implicitly replay")
	}
	return nil
}
