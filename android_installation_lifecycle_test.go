package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func lifecycleFixture(t *testing.T, language, last string) (*Client, *AndroidInstallationLifecycleState) {
	t.Helper()
	client, err := NewAndroidAppClient(androidFixtureProfile())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	client.androidApp.now = func() time.Time { return now }
	pattern, layout := androidUnloginDatePattern(language)
	state, err := NewAndroidInstallationLifecycleState(AndroidInstallationLifecycleObservation{
		DeviceID: client.AndroidAppProfile().DeviceID, IsGuest: true, Language: language, TimeZone: "UTC",
		DatePattern: pattern, ObservedToday: now.Format(layout), LastUnloginDay: last})
	if err != nil {
		t.Fatal(err)
	}
	return client, state
}

func TestInstallationUnloginDatePatternsAndLexicalGuard(t *testing.T) {
	for _, language := range []string{"th", "vi", "ru", "ar", "es", "hi", "in", "pt", "en", "ja", "ko", "cn", "unknown"} {
		t.Run(language, func(t *testing.T) {
			client, state := lifecycleFixture(t, language, "")
			calls, saves := 0, 0
			client.httpClient.Transport = clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if saves != 1 || req.Method != "GET" || req.URL.Path != "/api/analytics" || req.URL.Query().Get("type") != "unloginactive" || req.URL.Query().Has("rand") {
					t.Fatal("wrong unlogin wire or persistence order")
				}
				return clientResponse(req, 200, `{"errno":0}`), nil
			})
			persist := func(s *AndroidInstallationLifecycleState) error { saves++; return nil }
			result, err := client.ReportAndroidUnloginActive(context.Background(), state, state.Observation.ObservedToday, persist)
			if err != nil || !result.Attempted || saves != 2 || state.Observation.LastUnloginDay != state.Observation.ObservedToday {
				t.Fatal("missing confirmed daily state", err)
			}
			result, err = client.ReportAndroidUnloginActive(context.Background(), state, state.Observation.ObservedToday, persist)
			if err != nil || !result.Skipped || calls != 1 {
				t.Fatal("same native day repeated", err)
			}
		})
	}
	client, state := lifecycleFixture(t, "en", "12-31-2025")
	client.androidApp.now = func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }
	result, err := client.ReportAndroidUnloginActive(context.Background(), state, "01-01-2026", func(*AndroidInstallationLifecycleState) error { return nil })
	if err != nil || !result.Skipped {
		t.Fatal("APK's non-sortable lexical guard was replaced with chronological comparison", err)
	}
}

func TestInstallationUnloginUnknownAndGuestBinding(t *testing.T) {
	client, state := lifecycleFixture(t, "en", "")
	calls := 0
	client.httpClient.Transport = clientRoundTripFunc(func(req *http.Request) (*http.Response, error) { calls++; return clientResponse(req, 200, `{}`), nil })
	persist := func(*AndroidInstallationLifecycleState) error { return nil }
	_, err := client.ReportAndroidUnloginActive(context.Background(), state, state.Observation.ObservedToday, persist)
	if err == nil || state.Observation.LastUnloginDay != "" {
		t.Fatal("missing errno confirmed a day")
	}
	data, _ := json.Marshal(state)
	var restored AndroidInstallationLifecycleState
	_ = json.Unmarshal(data, &restored)
	_, err = client.ReportAndroidUnloginActive(context.Background(), &restored, state.Observation.ObservedToday, persist)
	if err == nil || calls != 1 {
		t.Fatal("uncertain native day replayed")
	}
	client.cookies["ndus"] = "own-authenticated-session"
	_, err = client.ReportAndroidUnloginActive(context.Background(), state, state.Observation.ObservedToday, persist)
	if err == nil || calls != 1 {
		t.Fatal("unlogin event sent with an authenticated client")
	}
}

type deviceSignerFunc func(context.Context, AndroidDeviceActivationSignRequest) (*AndroidDeviceActivationSignature, error)

func (f deviceSignerFunc) SignAndroidDeviceActivation(ctx context.Context, r AndroidDeviceActivationSignRequest) (*AndroidDeviceActivationSignature, error) {
	return f(ctx, r)
}

func TestInstallationDeviceSignerAndFlagPersistence(t *testing.T) {
	client, state := lifecycleFixture(t, "en", "")
	calls, saves := 0, 0
	var signed AndroidDeviceActivationSignRequest
	client.androidApp.profile.LegacyNativeParams = map[string]string{"sign": "stale-common-sign", "timestamp": "stale-time"}
	client.httpClient.Transport = clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if saves != 1 || req.Method != "GET" || req.URL.Path != "/api/report/device" || req.URL.Query().Get("sign") != "observed-native-signature" || req.URL.Query().Get("timestamp") != strconv.FormatInt(signed.TimestampMS, 10) || req.URL.Query().Has("rand") {
			t.Fatal("device wire or persistence differs")
		}
		return clientResponse(req, 200, `{"errno":0}`), nil
	})
	options := AndroidDeviceActivationOptions{Signer: deviceSignerFunc(func(_ context.Context, r AndroidDeviceActivationSignRequest) (*AndroidDeviceActivationSignature, error) {
		signed = r
		p := client.AndroidAppProfile()
		if r.Message != "1"+p.NativeChannel+p.DeviceID+strconv.FormatInt(r.TimestampMS, 10) {
			t.Fatal("native signing input order changed")
		}
		return &AndroidDeviceActivationSignature{DeviceID: r.DeviceID, Channel: r.Channel, ClientType: r.ClientType, TimestampMS: r.TimestampMS, Signature: "observed-native-signature"}, nil
	})}
	persist := func(s *AndroidInstallationLifecycleState) error {
		saves++
		if saves == 1 && s.Observation.DeviceActivated {
			t.Fatal("native flag changed before confirmation")
		}
		return nil
	}
	result, err := client.ReportAndroidDeviceActivation(context.Background(), state, options, persist)
	if err != nil || !result.Attempted || !state.Observation.DeviceActivated || state.Observation.ActivatedTimeSeconds != client.androidAppTime()/1000 || saves != 2 {
		t.Fatal("device activation not confirmed", err)
	}
	result, err = client.ReportAndroidDeviceActivation(context.Background(), state, options, persist)
	if err != nil || !result.Skipped || calls != 1 {
		t.Fatal("activated device resent", err)
	}
}

func TestInstallationDeviceUnknownAndPersistenceFailure(t *testing.T) {
	for _, mode := range []string{"foreign_signer", "persist_before", "transport", "nonzero", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			client, state := lifecycleFixture(t, "en", "")
			calls := 0
			client.httpClient.Transport = clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if mode == "transport" {
					return nil, errors.New("private network")
				}
				raw := `{"errno":9}`
				if mode == "malformed" {
					raw = `broken`
				}
				return clientResponse(req, 200, raw), nil
			})
			p := client.AndroidAppProfile()
			signature := &AndroidDeviceActivationSignature{DeviceID: p.DeviceID, Channel: p.NativeChannel, ClientType: 1, TimestampMS: client.androidAppTime(), Signature: "observed"}
			if mode == "foreign_signer" {
				signature.DeviceID = "foreign"
			}
			persist := func(*AndroidInstallationLifecycleState) error {
				if mode == "persist_before" {
					return errors.New("disk")
				}
				return nil
			}
			_, err := client.ReportAndroidDeviceActivation(context.Background(), state, AndroidDeviceActivationOptions{ObservedSignature: signature}, persist)
			if err == nil || state.Observation.DeviceActivated || state.Observation.ActivatedTimeSeconds != 0 {
				t.Fatal("unconfirmed device marked activated")
			}
			prior := calls
			if state.DeviceReport.Attempted {
				_, _ = client.ReportAndroidDeviceActivation(context.Background(), state, AndroidDeviceActivationOptions{ObservedSignature: signature}, persist)
				if calls != prior {
					t.Fatal("uncertain device report replayed")
				}
			}
			if (mode == "foreign_signer" || mode == "persist_before") && calls != 0 {
				t.Fatal("invalid or unpersisted request transmitted")
			}
		})
	}
}

func TestInstallationCustomSignerCannotChangeRequestedTimestamp(t *testing.T) {
	client, state := lifecycleFixture(t, "en", "")
	calls, saves := 0, 0
	client.httpClient.Transport = clientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected network")
	})
	signer := deviceSignerFunc(func(_ context.Context, r AndroidDeviceActivationSignRequest) (*AndroidDeviceActivationSignature, error) {
		return &AndroidDeviceActivationSignature{DeviceID: r.DeviceID, Channel: r.Channel, ClientType: r.ClientType,
			TimestampMS: r.TimestampMS - 1, Signature: "different-request-signature"}, nil
	})
	_, err := client.ReportAndroidDeviceActivation(context.Background(), state, AndroidDeviceActivationOptions{Signer: signer},
		func(*AndroidInstallationLifecycleState) error { saves++; return nil })
	if err == nil || calls != 0 || saves != 0 || state.DeviceReport.Attempted {
		t.Fatal("a signature for a different timestamp advanced the report")
	}
}
