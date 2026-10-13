package terabox

import (
	"context"
	"crypto/rc4"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

func activationFixtureProfile() AndroidAppProfile {
	profile := androidFixtureProfile()
	profile.UID = "12345"
	profile.ReportParams = map[string]string{"action": "ANDROID_ACTIVE_FRONTDESK", "needrookie": "1",
		"fcm_token": "fixture-fcm", "start_source": "frontdesk", "push_on": "1", "backup_on ": "00",
		"source": "fixture-source", "msg_id": "fixture-message", "channel_id": "fixture-channel", "bind_uid": "fixture-binding"}
	return profile
}

func activationFixtureSK() string {
	plain := []byte("activation-fixture-secret")
	encoded := make([]byte, len(plain))
	cipher, _ := rc4.NewCipher([]byte("12345"))
	cipher.XORKeyStream(encoded, plain)
	return base64.StdEncoding.EncodeToString(encoded)
}

func activationFixtureBody(fields map[string]any) string {
	data := map[string]any{"errno": 0, "uinfo": activationFixtureSK()}
	for key, value := range fields {
		data[key] = value
	}
	body, _ := json.Marshal(data)
	return string(body)
}

func TestAndroidActivationIsNewCleanupAndAtomicResponse(t *testing.T) {
	old := false
	stamp := int64(1791680000123)
	profile := activationFixtureProfile()
	profile.Activation = &AndroidActivationState{AccountUID: profile.UID, OldUser: &old,
		PendingPushMessageTimeMillis: &stamp}
	for _, test := range []struct {
		name       string
		fields     map[string]any
		wantOld    bool
		wantRookie bool
		wantErr    bool
	}{
		{"existing", map[string]any{"isnew": 0}, true, false, false},
		{"new", map[string]any{"isnew": 1}, false, true, false},
		{"unknown", map[string]any{"isnew": -1}, false, true, false},
		{"other", map[string]any{"isnew": 9}, false, true, false},
		{"absent", nil, false, true, false},
		{"null", map[string]any{"isnew": nil}, false, true, false},
		{"failed", map[string]any{"errno": 9, "isnew": 0}, false, true, true},
		{"missing-sk", map[string]any{"uinfo": "", "isnew": 0}, false, true, true},
		{"null-sk", map[string]any{"uinfo": nil, "isnew": 0}, false, true, true},
		{"invalid-sk", map[string]any{"uinfo": "invalid-base64", "isnew": 0}, false, true, true},
		{"invalid-isnew", map[string]any{"isnew": "0"}, false, true, true},
		{"invalid-media", map[string]any{"isnew": 0, "mediainfo": map[string]any{"videourl": "fixture\nurl"}}, false, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{
				Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					query := req.URL.Query()
					if query.Get("needrookie") != "1" || query.Get("source") != "fixture-source" || query.Get("msg_id") != "fixture-message" {
						t.Fatal("pending ReportUser fields were discarded before success")
					}
					return shareJSONResponse(req, activationFixtureBody(test.fields)), nil
				}),
			}))
			if err != nil {
				t.Fatal(err)
			}
			client.androidApp.now = func() time.Time { return time.UnixMilli(stamp) }
			before := client.AndroidAppProfile()
			err = client.RefreshAndroidAppConfig(context.Background())
			after := client.AndroidAppProfile()
			if test.wantErr {
				if err == nil || !reflect.DeepEqual(before, after) {
					t.Fatal("invalid response partially changed native account state")
				}
				return
			}
			if err != nil || after.Activation == nil || *after.Activation.OldUser != test.wantOld ||
				after.Activation.PendingPushMessageTimeMillis != nil || after.ReportParams["source"] != "" || after.ReportParams["msg_id"] != "" ||
				after.ReportParams["channel_id"] != "fixture-channel" || after.ReportParams["bind_uid"] != "fixture-binding" ||
				(after.ReportParams["needrookie"] == "1") != test.wantRookie {
				t.Fatalf("activation consumer state mismatch: %v", err)
			}
		})
	}
}

func TestAndroidActivationUnknownIsNewPreservesAbsentAndKnownOld(t *testing.T) {
	for _, knownOld := range []bool{false, true} {
		profile := activationFixtureProfile()
		delete(profile.ReportParams, "needrookie")
		if knownOld {
			old := true
			profile.Activation = &AndroidActivationState{AccountUID: profile.UID, OldUser: &old}
		}
		requests := 0
		client, _ := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{
			Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.Query().Has("needrookie") {
					t.Fatal("unknown or old-user state sent an invented rookie parameter")
				}
				return shareJSONResponse(req, activationFixtureBody(map[string]any{"isnew": -1})), nil
			}),
		}))
		if err := client.RefreshAndroidAppConfig(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := client.RefreshAndroidAppConfig(context.Background()); err != nil {
			t.Fatal(err)
		}
		state := client.AndroidAppProfile().Activation
		if requests != 2 || (state.OldUser != nil) != knownOld || (knownOld && !*state.OldUser) {
			t.Fatal("unknown isnew changed prior knowledge")
		}
	}
}

func TestAndroidActivationAccountActionCalendarGuardAndForce(t *testing.T) {
	for _, configValue := range []int64{4, 5, 6} {
		t.Run(strconv.FormatInt(configValue, 10), func(t *testing.T) {
			profile := activationFixtureProfile()
			requests := 0
			clock := time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC)
			client, _ := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{
				Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					requests++
					if req.URL.Query().Get("timestamp") != strconv.FormatInt(clock.UnixMilli(), 10) {
						t.Fatal("activation reused a captured ReportUser timestamp")
					}
					return shareJSONResponse(req, activationFixtureBody(map[string]any{"isnew": 0})), nil
				}),
			}))
			client.androidApp.now = func() time.Time { return clock }
			policy := &AndroidActivationPolicy{ConfigValue: &configValue, TimeZone: "UTC"}
			result, err := client.SendAndroidAppActivation(context.Background(), policy)
			if err != nil || !result.Attempted || result.Skipped || requests != 1 {
				t.Fatalf("initial activation: %v", err)
			}
			record := client.AndroidAppProfile().Activation.Actions["ANDROID_ACTIVE_FRONTDESK"]
			if (record.TimestampMillis != 0) != (configValue >= 5) || (record.Date != "") != (configValue < 5) {
				t.Fatal("start_config/c storage threshold differs from the APK")
			}
			result, err = client.SendAndroidAppActivation(context.Background(), policy)
			if err != nil || !result.Skipped || result.Attempted || requests != 1 {
				t.Fatal("same-day activation was repeated")
			}
			// Explicit SK refresh is never blocked by the scheduled guard.
			if err := client.RefreshAndroidAppConfig(context.Background()); err != nil || requests != 2 {
				t.Fatal("manual refresh was suppressed")
			}
			policy.Action = "ANDROID_ACTIVE_BACKGROUND_DOWNLOAD"
			result, err = client.SendAndroidAppActivation(context.Background(), policy)
			if err != nil || !result.Attempted || requests != 3 {
				t.Fatal("different action inherited another action's guard")
			}
			policy.Action = ""
			clock = clock.Add(time.Second)
			result, err = client.SendAndroidAppActivation(context.Background(), policy)
			if err != nil || !result.Attempted || requests != 4 {
				t.Fatal("next local date was suppressed as an elapsed interval")
			}
			if client.AndroidAppProfile().ReportParams["action"] != "ANDROID_ACTIVE_FRONTDESK" {
				t.Fatal("scheduled action override mutated captured action")
			}
		})
	}
}

func TestAndroidActivationRealFallbackModeMediaAndRestore(t *testing.T) {
	profile := activationFixtureProfile()
	requests := 0
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return shareJSONResponse(req, activationFixtureBody(map[string]any{"mediainfo": map[string]any{
			"picurl": "https://fixture.invalid/image", "videourl": "https://fixture.invalid/video", "videoname": "fixture"}})), nil
	})
	client, _ := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: transport}))
	clock := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	client.androidApp.now = func() time.Time { return clock }
	if _, err := client.SendAndroidAppActivation(context.Background(), &AndroidActivationPolicy{TimeZone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	saved := client.WebmasterRegistrationSession()
	if !saved.AndroidApp.Activation.UseTimestamp || saved.AndroidApp.Activation.MediaInfo.VideoName != "fixture" {
		t.Fatal("native fallback or media consumer is missing")
	}
	bytes, _ := json.Marshal(saved)
	var roundtrip WebmasterRegistrationSession
	if err := json.Unmarshal(bytes, &roundtrip); err != nil {
		t.Fatal(err)
	}
	guest := androidFixtureProfile()
	restored, _ := NewAndroidAppClient(guest, WithHTTPClient(&http.Client{Transport: transport}))
	if err := restored.RestoreWebmasterRegistrationSession(&roundtrip); err != nil {
		t.Fatal(err)
	}
	restored.androidApp.now = func() time.Time { return clock }
	result, err := restored.SendAndroidAppActivation(context.Background(), nil)
	if err != nil || !result.Skipped || requests != 1 {
		t.Fatal("JSON session lost its account/action activation guard")
	}
	// Returned and supplied snapshots cannot mutate the live client.
	saved.AndroidApp.Activation.Actions["ANDROID_ACTIVE_FRONTDESK"] = AndroidActivationRecord{Date: "261012"}
	snapshot := restored.AndroidAppProfile()
	snapshot.Activation.MediaInfo.VideoName = "changed"
	snapshot.Activation.Actions["ANDROID_ACTIVE_FRONTDESK"] = AndroidActivationRecord{Date: "261012"}
	if restored.AndroidAppProfile().Activation.MediaInfo.VideoName != "fixture" || client.AndroidAppProfile().Activation.Actions["ANDROID_ACTIVE_FRONTDESK"].TimestampMillis == 0 {
		t.Fatal("private activation snapshots alias a live account")
	}
	roundtrip.AndroidApp.Activation.AccountUID = "54321"
	rejected, _ := NewAndroidAppClient(guest)
	if err := rejected.RestoreWebmasterRegistrationSession(&roundtrip); err == nil {
		t.Fatal("activation state moved across native UID binding")
	}
}

func TestAndroidActivationClockChangeAndModeMigration(t *testing.T) {
	profile := activationFixtureProfile()
	clock := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	stamp := clock.UnixMilli()
	profile.Activation = &AndroidActivationState{AccountUID: profile.UID, UseTimestamp: true, TimeZone: "UTC",
		Actions: map[string]AndroidActivationRecord{"ANDROID_ACTIVE_FRONTDESK": {TimestampMillis: stamp}}}
	requests := 0
	client, _ := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return shareJSONResponse(req, activationFixtureBody(nil)), nil
	})}))
	client.androidApp.now = func() time.Time { return clock }
	clock = clock.Add(-time.Hour)
	if err := client.RefreshAndroidAppConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.AndroidAppProfile().Activation.Actions["ANDROID_ACTIVE_FRONTDESK"].TimestampMillis != stamp {
		t.Fatal("same-day clock adjustment regressed the private timestamp")
	}
	dateConfig := int64(4)
	result, err := client.SendAndroidAppActivation(context.Background(), &AndroidActivationPolicy{ConfigValue: &dateConfig})
	if err != nil || !result.Skipped || requests != 1 {
		t.Fatal("timestamp-to-date migration repeated a same-day action")
	}
	clock = clock.Add(24 * time.Hour)
	if _, err := client.SendAndroidAppActivation(context.Background(), &AndroidActivationPolicy{ConfigValue: &dateConfig}); err != nil {
		t.Fatal(err)
	}
	if client.AndroidAppProfile().Activation.Actions["ANDROID_ACTIVE_FRONTDESK"].Date != "261014" {
		t.Fatal("configured date mode did not save native yyMMdd")
	}
	timestampConfig := int64(5)
	result, err = client.SendAndroidAppActivation(context.Background(), &AndroidActivationPolicy{ConfigValue: &timestampConfig})
	if err != nil || !result.Skipped || requests != 2 {
		t.Fatal("date-to-timestamp migration repeated a same-day action")
	}
}

func TestAndroidActivationConcurrentGuardAndGuestProfileIsolation(t *testing.T) {
	profile := activationFixtureProfile()
	requests := 0
	client, _ := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return shareJSONResponse(req, activationFixtureBody(map[string]any{"isnew": 0})), nil
	})}))
	client.androidApp.now = func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := client.SendAndroidAppActivation(context.Background(), &AndroidActivationPolicy{TimeZone: "UTC"}); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if requests != 1 {
		t.Fatal("parallel scheduled activation bypassed the account guard")
	}
	// Reuse a valid APK build fixture for the profile factory.
	template := androidGuestTemplate()
	template.UID = profile.UID
	template.Activation = client.AndroidAppProfile().Activation
	guest, err := NewAndroidGuestProfile(template)
	if err != nil || guest.Activation != nil {
		t.Fatalf("fresh installation inherited account activation state: %v", err)
	}
}

func TestAndroidActivationResponseCrossingMidnightAndEmptyMedia(t *testing.T) {
	profile := activationFixtureProfile()
	profile.Activation = &AndroidActivationState{AccountUID: profile.UID, UseTimestamp: true, TimeZone: "UTC",
		MediaInfo: &AndroidActivationMediaInfo{VideoURL: "https://fixture.invalid/retained", VideoName: "retained"}}
	clock := time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC)
	requests := 0
	client, _ := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		clock = clock.Add(2 * time.Second)
		return shareJSONResponse(req, activationFixtureBody(map[string]any{"mediainfo": map[string]any{"picurl": "https://fixture.invalid/ignored", "videourl": ""}})), nil
	})}))
	client.androidApp.now = func() time.Time { return clock }
	if _, err := client.SendAndroidAppActivation(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	state := client.AndroidAppProfile().Activation
	if len(state.Actions) != 0 || state.MediaInfo.VideoName != "retained" {
		t.Fatal("cross-day response recorded a guard or empty video overwrote retained media")
	}
	if result, err := client.SendAndroidAppActivation(context.Background(), nil); err != nil || !result.Attempted || requests != 2 {
		t.Fatal("cross-day response suppressed a later same-day activation")
	}
	result, err := client.SendAndroidAppActivation(context.Background(), &AndroidActivationPolicy{Action: "ANDROID_ACTIVE_LOGOUT"})
	if err != nil || !result.Attempted || requests != 3 {
		t.Fatal("observed logout action failed")
	}
	if _, exists := client.AndroidAppProfile().Activation.Actions["ANDROID_ACTIVE_LOGOUT"]; exists {
		t.Fatal("logout entered the successful activation calendar guard")
	}
}

func TestAndroidActivationAccountChangedDuringRequest(t *testing.T) {
	profile := activationFixtureProfile()
	var client *Client
	client, _ = NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		client.mu.Lock()
		client.cookies["ndus"] = "changed-fixture-session"
		client.mu.Unlock()
		return shareJSONResponse(req, activationFixtureBody(map[string]any{"isnew": 0})), nil
	})}))
	before := client.AndroidAppProfile()
	if err := client.RefreshAndroidAppConfig(context.Background()); err == nil || !reflect.DeepEqual(before, client.AndroidAppProfile()) {
		t.Fatal("response from the old native session changed the current profile")
	}
}
