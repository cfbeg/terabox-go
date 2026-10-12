package terabox

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func androidGuestTemplate() AndroidAppProfile {
	profile := AndroidAppProfile{DeviceID: "captured-template-cuid", Version: "4.26.5",
		UserAgent:     "dubox;4.26.5;SDK_gphone_x86_64;android-android;11;JSbridge1.0.10;jointbridge;1.1.39;",
		NativeChannel: "android_11_SDK_gphone_x86_64_bd-dubox_1024074p", Language: "en_US", ClientType: 1,
		UID: "old-account", EncodedSK: "ignored-old-key", PSign: "old-psign",
		CKData: map[string]string{"ck_val": "old-bridge"}, NativeCKData: map[string]string{"ck_own": "old-native-bridge"},
		NativeParams: map[string]string{"devuid": "old-device", "cuid": "old-device", "channel": "old-channel",
			"uid": "old-uid", "userid": "old-uid", "ndus": "old-ndus", "bdstoken": "old-token", "rand": "old-signature",
			"secret_token": "old-token", "access_token": "old-token", "phone_brand": "fixture-brand", "versioncode": "726",
			"af_media_source": "old-install-campaign",
			"network_type":    "WIFI", "startDevTime": "1", "firstlaunchtime": "1", "ZID": "old-token", "isVip": "1", "vip_type": "2",
			"logid": base64.RawStdEncoding.EncodeToString([]byte("1,192.0.2.5,0"))},
		ReportParams: map[string]string{"action": "ANDROID_ACTIVE_FRONTDESK", "start_source": "0", "push_on": "0", "backup_on ": "0",
			"bind_uid": "old-uid", "fcm_token": "old-fcm", "source": "old-source", "msg_id": "old-message", "channel_id": "old-channel", "timestamp": "1"}}
	profile.Channel = profile.NativeChannel
	profile.LegacyNativeParams = copyAndroidStringMap(profile.NativeParams)
	page, _ := url.Parse("https://www.terabox.com/wap/hylogin/emailRegister?type=1&version=4.26.5&clienttype=1")
	query := page.Query()
	query.Set("devuid", profile.DeviceID)
	query.Set("cuid", profile.DeviceID)
	query.Set("channel", profile.Channel)
	query.Set("logId", profile.DeviceID+"1")
	query.Set("logid", profile.NativeParams["logid"])
	query.Set("startDevTime", "1")
	query.Set("firstlaunchtime", "1")
	query.Set("time", "1")
	page.RawQuery = query.Encode()
	profile.PageURL = page.String()
	return profile
}

func TestAndroidGuestCUIDMatchesExecutedAPK(t *testing.T) {
	// Original APK cesium.h.i(String) outputs, executed using its uppercase
	// MD5 input. Evidence: gemini/analysis/android-registration/
	// rotation_cuid_vectors.py and rotation_cuid_vectors.json.
	for _, fixture := range []struct{ androidID, cuid string }{
		{"0000000000000001", "FE177C96A20533626922D2C698B7F090|VSTLZFRAH"},
		{"0123456789abcdef", "CA42873BB9AF2FF285BE40BA5AED34DB|VLUK6HOUN"},
		{"fedcba9876543210", "6A988E4C6DE8619E28399B1F67F5C8A1|VZTOW2L3Y"},
		{"7fffffffffffffff", "3A91EAC43863F1637470BC901F971EC1|VMIXRVCVG"},
	} {
		got, err := androidCUID(fixture.androidID)
		if err != nil || got != fixture.cuid {
			t.Fatalf("CUID=%q error=%v, want APK oracle %q", got, err, fixture.cuid)
		}
	}
	for _, id := range []string{"", "0000000000000000", "0123456789abcde", "0123456789abcdef0", "0123456789abcdeg"} {
		if _, err := androidCUID(id); err == nil {
			t.Fatalf("accepted invalid Android ID %q", id)
		}
	}
}

func TestAndroidGuestProfilesSeparateConcurrentInstallations(t *testing.T) {
	template := androidGuestTemplate()
	original, _ := json.Marshal(template)
	const count = 64
	profiles := make(chan AndroidAppProfile, count)
	errors := make(chan error, count)
	var group sync.WaitGroup
	before := time.Now().UnixMilli()
	for i := 0; i < count; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			profile, err := NewAndroidGuestProfile(template)
			if err != nil {
				errors <- err
				return
			}
			profiles <- profile
		}()
	}
	group.Wait()
	after := time.Now().UnixMilli()
	close(profiles)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	seenID, seenUA, seenChannel := map[string]bool{}, map[string]bool{}, map[string]bool{}
	cuidPattern := regexp.MustCompile(`^[0-9A-F]{32}\|V[A-Z2-7]{8}$`)
	for profile := range profiles {
		if !cuidPattern.MatchString(profile.DeviceID) || seenID[profile.DeviceID] || seenUA[profile.UserAgent] || seenChannel[profile.NativeChannel] ||
			profile.DeviceID == template.DeviceID || profile.UserAgent == template.UserAgent || profile.NativeChannel == template.NativeChannel {
			t.Fatal("installations share their CUID, virtual model/UA or channel")
		}
		seenID[profile.DeviceID], seenUA[profile.UserAgent], seenChannel[profile.NativeChannel] = true, true, true
		parts := strings.Split(profile.UserAgent, ";")
		model, err := url.QueryUnescape(parts[2])
		if err != nil || !strings.HasPrefix(model, "SDK_gphone_x86_64_") || len(model) != len("SDK_gphone_x86_64_")+16 ||
			parts[5] != "JSbridge1.0.10" || parts[6] != "jointbridge" || parts[7] != "1.1.39" ||
			profile.NativeChannel != "android_11_"+model+"_bd-dubox_1024074p" {
			t.Fatal("generated UA and channel lost captured build constants")
		}
		id, err := androidCUID(strings.TrimPrefix(model, "SDK_gphone_x86_64_"))
		if err != nil || id != profile.DeviceID {
			t.Fatal("model Android ID and Cesium CUID describe different installations")
		}
		if profile.UID != "" || profile.EncodedSK != "" || profile.PSign != "" || profile.CKData != nil || profile.NativeCKData != nil ||
			profile.ReportParams["bind_uid"] != "" || profile.ReportParams["source"] != "" || profile.ReportParams["msg_id"] != "" ||
			profile.ReportParams["channel_id"] != "" || profile.ReportParams["fcm_token"] != "fcm_error_0" || profile.ReportParams["needrookie"] != "1" {
			t.Fatal("new guest retained old credentials or account configuration")
		}
		page, _ := url.Parse(profile.PageURL)
		query := page.Query()
		if query.Get("devuid") != profile.DeviceID || query.Get("cuid") != profile.DeviceID || query.Get("channel") != profile.Channel ||
			!strings.HasPrefix(query.Get("logId"), profile.DeviceID) || query.Get("firstlaunchtime") == "1" || query.Get("startDevTime") == "1" {
			t.Fatal("Hy URL retained a different installation's ID or launch time")
		}
		for _, values := range []map[string]string{profile.NativeParams, profile.LegacyNativeParams} {
			if values["af_media_source"] != "Undefined" {
				t.Fatal("new virtual installation inherited an old installation's attribution")
			}
			for _, key := range []string{"ndus", "uid", "userid", "bdstoken", "rand", "secret_token", "access_token"} {
				if _, exists := values[key]; exists {
					t.Fatal("native parameters retained old account credentials")
				}
			}
			if values["devuid"] != profile.DeviceID || values["cuid"] != profile.DeviceID || values["channel"] != profile.NativeChannel ||
				values["ZID"] != "" || values["isVip"] != "0" || values["vip_type"] != "0" || values["phone_brand"] != "fixture-brand" ||
				values["network_type"] != "WIFI" || values["versioncode"] != "726" {
				t.Fatal("native maps have inconsistent identity or changed build constants")
			}
			ms, err := strconv.ParseInt(values["time"], 10, 64)
			seconds, secondsErr := strconv.ParseInt(values["firstlaunchtime"], 10, 64)
			if err != nil || secondsErr != nil || ms < before || ms > after || seconds != ms/1000 || values["startDevTime"] != values["time"] ||
				query.Get("time") != values["time"] || profile.ReportParams["timestamp"] != values["time"] {
				t.Fatal("launch/report/Hy timestamps disagree")
			}
			assertAndroidGuestLogID(t, values["logid"], ms, "192.0.2.5")
		}
		client, err := NewAndroidAppClient(profile)
		if err != nil {
			t.Fatalf("generated profile does not construct an APK client: %v", err)
		}
		saved := client.WebmasterRegistrationSession()
		restored, err := NewAndroidAppClient(profile)
		if err != nil || restored.RestoreWebmasterRegistrationSession(saved) != nil || !reflect.DeepEqual(restored.AndroidAppProfile(), &profile) {
			t.Fatal("generated profile did not restore unchanged")
		}
		profile.NativeParams["phone_brand"] = "only-this-map"
		if profile.LegacyNativeParams["phone_brand"] != "fixture-brand" {
			t.Fatal("native and legacy maps share mutable storage")
		}
		profile.ReportParams["push_on"] = "only-this-map"
	}
	if len(seenID) != count {
		t.Fatal("not all guest installations were generated")
	}
	current, _ := json.Marshal(template)
	if string(current) != string(original) {
		t.Fatal("factory or output maps mutated the shared template")
	}
}

func assertAndroidGuestLogID(t *testing.T, encoded string, milliseconds int64, address string) {
	t.Helper()
	wire, err := base64.RawStdEncoding.DecodeString(encoded)
	parts := strings.Split(string(wire), ",")
	if err != nil || len(parts) != 3 || parts[0] != strconv.FormatInt(milliseconds, 10) || parts[1] != address {
		t.Fatal("log ID lost its timestamp, captured IP or APK Base64 encoding")
	}
	nonce, err := strconv.Atoi(parts[2])
	if err != nil || nonce < 0 || nonce >= 999999 {
		t.Fatal("log ID nonce is outside APK bounds")
	}
}

func TestAndroidGuestPreservesUAChannelAndScopedIPv6(t *testing.T) {
	template := androidGuestTemplate()
	template.Channel = template.UserAgent
	page, _ := url.Parse(template.PageURL)
	query := page.Query()
	query.Set("channel", template.Channel)
	const address = "fe80::1234:abcd%eth0"
	captured := base64.RawStdEncoding.EncodeToString([]byte("1," + address + ",5"))
	query.Set("logid", captured)
	page.RawQuery = query.Encode()
	template.PageURL = page.String()
	template.NativeParams["logid"], template.LegacyNativeParams["logid"] = captured, captured
	profile, err := NewAndroidGuestProfile(template)
	if err != nil || profile.Channel != profile.UserAgent {
		t.Fatalf("UA-derived Hy channel lost: %v", err)
	}
	page, _ = url.Parse(profile.PageURL)
	if page.Query().Get("channel") != profile.UserAgent {
		t.Fatal("Hy page retained the template's UA")
	}
	ms, _ := strconv.ParseInt(profile.NativeParams["time"], 10, 64)
	for _, value := range []string{profile.NativeParams["logid"], profile.LegacyNativeParams["logid"], page.Query().Get("logid")} {
		assertAndroidGuestLogID(t, value, ms, address)
	}
}

func TestAndroidGuestRejectsInvalidCapturedTemplate(t *testing.T) {
	for _, mutate := range []func(*AndroidAppProfile){
		func(p *AndroidAppProfile) { p.DeviceID = "" },
		func(p *AndroidAppProfile) { p.Version = "" },
		func(p *AndroidAppProfile) { p.ClientType = 5 },
		func(p *AndroidAppProfile) { p.UserAgent = "fixture-dubox-browser" },
		func(p *AndroidAppProfile) { p.NativeChannel = "android_11_DifferentModel_bd-dubox_1024074p" },
		func(p *AndroidAppProfile) { p.Channel = "unrelated-channel" },
		func(p *AndroidAppProfile) { p.PageURL = "https://example.com/wap/hylogin" },
		func(p *AndroidAppProfile) { p.PageURL = "https://www.terabox.com/wap/glodminer" },
		func(p *AndroidAppProfile) { p.NativeParams["logid"] = "not-base64" },
		func(p *AndroidAppProfile) {
			p.LegacyNativeParams["logid"] = base64.RawStdEncoding.EncodeToString([]byte("1,127.0.0.1,0"))
		},
		func(p *AndroidAppProfile) {
			p.NativeParams["logid"] = base64.RawStdEncoding.EncodeToString([]byte("1,0.0.0.0,0"))
		},
		func(p *AndroidAppProfile) { p.ReportParams["unexpected"] = "unexpected" },
	} {
		template := androidGuestTemplate()
		mutate(&template)
		profile, err := NewAndroidGuestProfile(template)
		if err == nil || !reflect.DeepEqual(profile, AndroidAppProfile{}) {
			t.Fatal("invalid captured template returned a usable guest")
		}
	}
}

func TestAndroidGuestMinimalTemplateDoesNotInventOptionalCapturedFields(t *testing.T) {
	template := androidGuestTemplate()
	template.NativeParams, template.LegacyNativeParams, template.ReportParams = nil, nil, nil
	template.PageURL = "https://www.terabox.com/wap/hylogin/emailRegister?type=1"
	profile, err := NewAndroidGuestProfile(template)
	if err != nil {
		t.Fatal(err)
	}
	for _, fields := range []map[string]string{profile.NativeParams, profile.LegacyNativeParams} {
		if fields["devuid"] != profile.DeviceID || fields["cuid"] != profile.DeviceID || fields["channel"] != profile.NativeChannel ||
			fields["logid"] != "" || fields["firstlaunchtime"] != "" || fields["phone_brand"] != "" {
			t.Fatal("minimal template invented captured IP, brand or startup fields")
		}
	}
	if profile.ReportParams != nil {
		t.Fatal("minimal template invented an optional report configuration")
	}
	if got := androidURLEncode("Model *~+ /日本語"); got != "Model+*%7E%2B+%2F%E6%97%A5%E6%9C%AC%E8%AA%9E" {
		t.Fatalf("APK Java URLEncoder mismatch: %s", got)
	}
}
