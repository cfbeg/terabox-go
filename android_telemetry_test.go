package terabox

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func statisticsFixture(t *testing.T) *AndroidStatisticsBatch {
	t.Helper()
	p := androidFixtureProfile()
	batch, err := NewAndroidStatisticsBatch(AndroidStatisticsCapture{DeviceID: p.DeviceID, Filename: "new_stats",
		Query: map[string]string{"clienttype": "1", "devuid": p.DeviceID, "channel": p.NativeChannel,
			"version": p.Version, "firstlaunchtime": "1700000000", "ZID": "", "ab_variant_b": ""},
		EventBytes: []byte("captured serialized batch\n\x00retained byte")})
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func TestStatisticsUploadUsesAPKFramingAndDurableDeletion(t *testing.T) {
	batch := statisticsFixture(t)
	original := append([]byte(nil), batch.Capture.EventBytes...)
	var checkpoints []*AndroidStatisticsBatch
	var observations []RequestObservation
	calls := 0
	client, _ := NewAndroidAppClient(androidFixtureProfile(), WithCookies("ndus=own-session; unrelated=must-not-forward"),
		WithRequestObserver(func(_ context.Context, o RequestObservation) error {
			observations = append(observations, o)
			return nil
		}),
		WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if len(checkpoints) != 1 || !checkpoints[0].Report.Attempted || checkpoints[0].Report.Succeeded {
				t.Fatal("upload began before durable attempted state")
			}
			if req.Method != "POST" || req.URL.Path != "/statistics" || req.Header.Get("Content-Encoding") != "gzip" || req.Header.Get("Content-Type") != "multipart/form-data; boundary=*****" || req.Header.Get("Cookie") != "ndus=own-session" {
				t.Fatal("statistics framing differs from APK", req.Method, req.URL.Path, req.Header)
			}
			query := req.URL.Query()
			if len(query) != len(batch.Capture.Query) || query.Has("rand") || query.Has("time") || query.Has("cuid") || query.Get("firstlaunchtime") != "1700000000" {
				t.Fatal("native API query was incorrectly applied to statistics", query)
			}
			raw, _ := io.ReadAll(req.Body)
			if !bytes.HasPrefix(raw, []byte("--*****\r\nContent-Disposition: form-data; name=\"userfile\"; filename=\"new_stats\"\r\nContent-Type: application/octet-stream\r\n\r\n")) || !bytes.HasSuffix(raw, []byte("\r\n--*****--\r\n")) {
				t.Fatal("multipart framing or gzip boundary is wrong")
			}
			reader := multipart.NewReader(bytes.NewReader(raw), "*****")
			part, err := reader.NextPart()
			if err != nil || part.FormName() != "userfile" || part.FileName() != "new_stats" {
				t.Fatal("incorrect uploaded part", err)
			}
			gz, err := gzip.NewReader(part)
			if err != nil {
				t.Fatal("userfile contents are not gzip", err)
			}
			decoded, err := io.ReadAll(gz)
			if err != nil || !bytes.Equal(decoded, original) || gz.OS != 0 {
				t.Fatal("captured event bytes changed", err)
			}
			_ = gz.Close()
			if _, err := reader.NextPart(); err != io.EOF {
				t.Fatal("unexpected extra statistics parts", err)
			}
			return clientResponse(req, 200, `{"errno":0,"request_id":123}`), nil
		})}))
	persist := func(state *AndroidStatisticsBatch) error { checkpoints = append(checkpoints, state); return nil }
	if err := client.UploadAndroidStatistics(context.Background(), batch, persist); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(checkpoints) != 2 || len(checkpoints[0].Capture.EventBytes) == 0 || !checkpoints[1].Report.Succeeded || len(checkpoints[1].Capture.EventBytes) != 0 || !batch.Report.Succeeded {
		t.Fatal("confirmed payload was deleted too early or not tombstoned")
	}
	if len(observations) != 2 || observations[1].Route != "statistics" {
		t.Fatal("statistics request was not observed")
	}
	if err := client.UploadAndroidStatistics(context.Background(), batch, persist); err != nil || calls != 1 {
		t.Fatal("confirmed batch retransmitted", err)
	}
	encoded, _ := json.Marshal(batch)
	var restored AndroidStatisticsBatch
	_ = json.Unmarshal(encoded, &restored)
	if err := client.UploadAndroidStatistics(context.Background(), &restored, persist); err != nil || calls != 1 {
		t.Fatal("restored tombstone retransmitted", err)
	}
}

func TestStatisticsFailuresRetainBatchAndNeverReplay(t *testing.T) {
	for _, mode := range []string{"transport", "nonzero", "missing_errno", "bad_json", "non200", "incomplete", "persist_before", "persist_after"} {
		t.Run(mode, func(t *testing.T) {
			calls, saves := 0, 0
			batch := statisticsFixture(t)
			client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if mode == "transport" {
					return nil, errors.New("private network error")
				}
				status, raw := 200, `{"errno":0}`
				switch mode {
				case "nonzero":
					raw = `{"errno":9}`
				case "missing_errno":
					raw = `{}`
				case "bad_json":
					raw = `broken`
				case "non200":
					status = 500
				}
				response := clientResponse(req, status, raw)
				if mode == "incomplete" {
					response.Body = &incompleteStatisticsBody{}
				}
				return response, nil
			})}))
			persist := func(*AndroidStatisticsBatch) error {
				saves++
				if mode == "persist_before" && saves == 1 || mode == "persist_after" && saves == 2 {
					return errors.New("private persistence path")
				}
				return nil
			}
			err := client.UploadAndroidStatistics(context.Background(), batch, persist)
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("upload failure was accepted or exposed details", err)
			}
			if !batch.Report.Attempted || (mode != "persist_after" && len(batch.Capture.EventBytes) == 0) {
				t.Fatal("uncertain payload was dropped")
			}
			priorCalls := calls
			_ = client.UploadAndroidStatistics(context.Background(), batch, persist)
			if calls != priorCalls {
				t.Fatal("attempted statistics batch retransmitted")
			}
			if mode == "persist_before" && calls != 0 {
				t.Fatal("network ran after failed pre-send persistence")
			}
		})
	}
}

type incompleteStatisticsBody struct{}

func (*incompleteStatisticsBody) Read(p []byte) (int, error) {
	return copy(p, `{"errno":0}`), errors.New("truncated")
}
func (*incompleteStatisticsBody) Close() error { return nil }

func TestStatisticsRejectsModifiedOrForeignInput(t *testing.T) {
	calls := 0
	client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return clientResponse(req, 200, `{"errno":0}`), nil
	})}))
	for _, mutate := range []func(*AndroidStatisticsBatch){
		func(b *AndroidStatisticsBatch) { b.Capture.EventBytes[0] ^= 1 },
		func(b *AndroidStatisticsBatch) { b.Capture.Query["rand"] = "invented" },
		func(b *AndroidStatisticsBatch) { b.Capture.Filename = "injected\r\nHeader:value" },
		func(b *AndroidStatisticsBatch) { b.Capture.DeviceID = "another" },
	} {
		batch := statisticsFixture(t)
		mutate(batch)
		if err := client.UploadAndroidStatistics(context.Background(), batch, func(*AndroidStatisticsBatch) error { return nil }); err == nil {
			t.Fatal("modified capture accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid capture reached network")
	}
}

type analyticsBridgeFunc func(context.Context, AndroidAnalyticsRequest) (*AndroidAnalyticsReceipt, error)

func (f analyticsBridgeFunc) ExecuteAndroidAnalytics(ctx context.Context, r AndroidAnalyticsRequest) (*AndroidAnalyticsReceipt, error) {
	return f(ctx, r)
}

func TestAnalyticsDispatchPersistsProofAndUnknown(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		dispatch, _ := NewAndroidAnalyticsDispatch("one-real-registration", "fixture-cuid", AndroidAnalyticsEvent{Key: "wap_email_register", IsReportFb: true})
		saves, calls := 0, 0
		persist := func(s *AndroidAnalyticsDispatch) error {
			saves++
			if !s.Attempted {
				t.Fatal("missing attempt")
			}
			return nil
		}
		adapter := analyticsBridgeFunc(func(_ context.Context, r AndroidAnalyticsRequest) (*AndroidAnalyticsReceipt, error) {
			calls++
			if saves != 1 {
				t.Fatal("adapter invoked before save")
			}
			if uncertain {
				return nil, errors.New("private SDK failure")
			}
			return &AndroidAnalyticsReceipt{Version: 1, RequestID: r.RequestID, Key: r.Event.Key, AppsFlyerCalled: true, FirebaseCalled: true, Environment: "real-runtime-proof"}, nil
		})
		err := ExecuteAndroidAnalytics(context.Background(), dispatch, adapter, persist)
		if uncertain && (err == nil || dispatch.Receipt != nil) || !uncertain && (err != nil || dispatch.Receipt == nil) {
			t.Fatal("incorrect analytics proof outcome", err)
		}
		_ = ExecuteAndroidAnalytics(context.Background(), dispatch, adapter, persist)
		if calls != 1 || saves != 2 {
			t.Fatal("analytics replayed or missing journals")
		}
	}
	dispatch, _ := NewAndroidAnalyticsDispatch("failed-disk", "fixture-cuid", AndroidAnalyticsEvent{Key: "wap_email_register"})
	calls := 0
	err := ExecuteAndroidAnalytics(context.Background(), dispatch, analyticsBridgeFunc(func(context.Context, AndroidAnalyticsRequest) (*AndroidAnalyticsReceipt, error) {
		calls++
		return nil, nil
	}), func(*AndroidAnalyticsDispatch) error { return errors.New("disk") })
	if err == nil || calls != 0 {
		t.Fatal("adapter invoked after failed persistence")
	}
}

// The test binary acts as a subprocess protocol fixture. Actual SDK execution
// is supplied by tools/android_analytics_bridge.py, not this test.
func TestAnalyticsExecutableFixture(t *testing.T) {
	if os.Getenv("TERABOX_ANALYTICS_HELPER") != "1" {
		return
	}
	var r AndroidAnalyticsRequest
	if json.NewDecoder(os.Stdin).Decode(&r) != nil {
		os.Exit(2)
	}
	receipt := AndroidAnalyticsReceipt{Version: 1, RequestID: r.RequestID, Key: r.Event.Key, AppsFlyerCalled: true, FirebaseCalled: r.Event.IsReportFb, Environment: "protocol-fixture"}
	switch os.Getenv("TERABOX_ANALYTICS_MODE") {
	case "wrong":
		receipt.RequestID = strings.Repeat("0", 64)
	case "large":
		os.Stdout.WriteString(strings.Repeat("x", 20<<10))
		os.Exit(0)
	case "timeout":
		time.Sleep(5 * time.Second)
	}
	_ = json.NewEncoder(os.Stdout).Encode(receipt)
	os.Exit(0)
}

func TestExecutableAnalyticsProtocol(t *testing.T) {
	executable, _ := os.Executable()
	dispatch, _ := NewAndroidAnalyticsDispatch("fixture-call", "fixture-cuid", AndroidAnalyticsEvent{Key: "wap_email_register", IsReportFb: true})
	t.Setenv("TERABOX_ANALYTICS_HELPER", "1")
	for _, mode := range []string{"success", "wrong", "large", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("TERABOX_ANALYTICS_MODE", mode)
			bridge := ExecutableAndroidAnalyticsBridge{Command: executable, Args: []string{"-test.run=^TestAnalyticsExecutableFixture$"}, Timeout: time.Second}
			receipt, err := bridge.ExecuteAndroidAnalytics(context.Background(), dispatch.Request)
			if mode == "success" && (err != nil || receipt == nil) || mode != "success" && err == nil {
				t.Fatal("incorrect subprocess evidence handling", err)
			}
		})
	}
}
