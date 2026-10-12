package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func attributionText(value string) *string { return &value }
func attributionTime(value int64) *int64   { return &value }

func attributionFixtureCapture(profile AndroidAppProfile) AndroidAttributionCapture {
	return AndroidAttributionCapture{
		DeviceID: profile.DeviceID,
		Click: &AndroidClickAttribution{
			PageURL: "https://terabox.com/s/1observed?entry=actual", UserAgent: "Mozilla/5.0 (Linux; Android 13; Observed Device)",
			DeepLink: "dubox://share_detail?uk=123&shareid=456&surl=observed", TeraLinkID: "1700000000000-12345678", TeraLinkType: 1,
			Language: "ja-JP", OSVersion: "android 13", Device: "Observed Device", Referrer: "https://example.test/source",
			Agency: attributionText(""), OpSource: attributionText("observed_campaign"),
			CommonParams: map[string]string{"app_id": "250528", "web": "1", "channel": "dubox", "clienttype": "5",
				"jsToken": "observed-browser-token", "dp-logid": "observed-browser-logid", "version": "0", "devuid": "0", "cuid": "0", "lang": "ja"},
			BrowserCookies: "observed_browser=cookie-value",
		},
		Install: &AndroidInstallAttribution{
			DeviceCountry: "JP", DeviceLanguage: "ja", OSVersion: "13", Device: "Observed Device",
			InstallTime: attributionTime(1700000000123), FirstLaunchTime: 1700000001000, IsFirstLaunch: true,
		},
		InstallReferrer: attributionText("utm_source=actual&utm_content=a%26b&af_dp=dubox%3A%2F%2Fshare_detail%3Fuk%3D123"),
	}
}

func attributionFixtureClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	profile := androidFixtureProfile()
	profile.NativeParams = map[string]string{"af_media_source": "Undefined", "captured_native": "value", "device_country": "stale-template-country",
		"device_lang": "stale-template-language", "install_time": "stale-template-time", "referer_data": "stale-template-referrer"}
	profile.LegacyNativeParams = map[string]string{"af_media_source": "Undefined"}
	client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetAndroidAttributionCapture(attributionFixtureCapture(profile)); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestAndroidAttributionCapturedWireAndMediaPropagation(t *testing.T) {
	ctx := context.Background()
	var paths []string
	var client *Client
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		var body []byte
		var err error
		if req.Body != nil {
			body, err = io.ReadAll(req.Body)
		}
		if err != nil {
			t.Fatal(err)
		}
		state := client.AndroidAttribution()
		capture := state.Capture
		q := req.URL.Query()
		switch req.URL.Path {
		case "/api/srn/ck":
			wantQuery := make(url.Values, len(capture.Click.CommonParams))
			for key, value := range capture.Click.CommonParams {
				wantQuery.Set(key, value)
			}
			if req.Method != http.MethodPost || !reflect.DeepEqual(q, wantQuery) || req.Header.Get("Cookie") != capture.Click.BrowserCookies ||
				req.UserAgent() != capture.Click.UserAgent || req.Header.Get("X-Requested-With") != "XMLHttpRequest" ||
				req.Header.Get("Referer") != capture.Click.PageURL || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Errorf("click transport differs from captured browser contract")
			}
			form, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatal(err)
			}
			want := url.Values{"pid": {"tera_sharelink"}, "c": {capture.Click.PageURL}, "pdetail": {"header_button"},
				"tera_link_id": {capture.Click.TeraLinkID}, "tera_link_type": {"1"}, "agency": {""}, "op_source": {"observed_campaign"},
				"lang": {"ja-JP"}, "os_version": {"android 13"}, "device": {"Observed Device"}, "af_dp": {capture.Click.DeepLink},
				"referrer": {capture.Click.Referrer}}
			if !reflect.DeepEqual(form, want) {
				t.Errorf("click form does not preserve captured values")
			}
			return shareJSONResponse(req, `{"errno":0,"request_id":"click-request","data":{"observed_extra":"retained"}}`), nil
		case "/api/srn/ins", "/api/srn/ref":
			if req.Method != http.MethodPost || len(body) != 0 || q.Get("cuid") != capture.DeviceID ||
				q.Get("devuid") != capture.DeviceID || q.Get("clienttype") != "1" || q.Get("af_media_source") != "Undefined" ||
				!strings.HasSuffix(req.URL.RawQuery, "&rand") || q.Has("web") || q.Has("app_id") ||
				q.Has("uk") || q.Has("shareid") || q.Has("bind_uid") || q.Has("code") || q.Has("is_first_launch") {
				t.Errorf("native attribution contract contains wrong body/common/owner fields")
			}
			for key, values := range androidInstallAttributionQuery(capture.Install) {
				if !reflect.DeepEqual(q[key], values) {
					t.Errorf("observed install field %q changed", key)
				}
			}
			if req.URL.Path == "/api/srn/ins" {
				if q.Has("referer_data") {
					t.Error("install request invented a referrer input")
				}
				return shareJSONResponse(req, `{"errno":0,"request_id":123}`), nil
			}
			if q.Get("referer_data") != *capture.InstallReferrer || q.Has("referrer_data") {
				t.Error("referrer input was modified or wire name changed")
			}
			return shareJSONResponse(req, `{"errno":0,"request_id":"ref-request","data":{"mediaSource":"server-source","status":"Non-organic","agency":null,"campaign":"server-campaign","code":"actual-server-code","adSet":"server-ad","opSource":"returned","deepLinkValue":"returned-value","deeplink":"dubox://share_detail?uk=789&shareid=999","future":{"kept":true}}}`), nil
		case "/api/shorturlinfo":
			if q.Get("af_media_source") != "server-source" {
				t.Error("legacy native request did not use returned first-launch media source")
			}
			return shareJSONResponse(req, `{"errno":0,"shareid":456,"uk":123,"list":[]}`), nil
		default:
			t.Fatalf("unexpected request path %q", req.URL.Path)
			return nil, nil
		}
	})
	client = attributionFixtureClient(t, transport)
	if err := client.ReportAndroidShareClick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.ReportAndroidInstall(ctx); err != nil {
		t.Fatal(err)
	}
	referrer, err := client.QueryAndroidInstallReferrer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state := client.AndroidAttribution()
	if referrer.MediaSource == nil || *referrer.MediaSource != "server-source" || state.WebmasterUK == nil || *state.WebmasterUK != 789 ||
		state.AppInstallMediaSource == nil || *state.AppInstallMediaSource != "server-source" || state.InstallReport.RequestID != "123" ||
		!strings.Contains(string(state.ReferrerReport.RawResponse), `"future":{"kept":true}`) {
		t.Fatal("server attribution/raw response/derived installation state was not preserved")
	}
	profile := client.AndroidAppProfile()
	if profile.NativeParams["af_media_source"] != "server-source" || profile.LegacyNativeParams["af_media_source"] != "server-source" || profile.ReportParams["bind_uid"] != "" {
		t.Fatal("media propagation or owner/bind separation failed")
	}
	if _, err := client.GetShareInfo(ctx, "observed"); err != nil {
		t.Fatal(err)
	}
	// A caller mutating snapshots cannot corrupt installation state.
	*referrer.MediaSource = "caller-mutation"
	*state.Capture.InstallReferrer = "caller-mutation"
	state.ReferrerReport.RawResponse[0] = 'x'
	if *client.AndroidAttribution().Referrer.MediaSource != "server-source" {
		t.Fatal("returned attribution contains shared mutable state")
	}
	for _, report := range []func(context.Context) error{client.ReportAndroidShareClick, client.ReportAndroidInstall} {
		if err := report(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.QueryAndroidInstallReferrer(ctx); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 4 {
		t.Fatal("confirmed attribution reports were replayed")
	}
	// Saved sessions preserve response-derived media and successful dedup state.
	body, err := json.Marshal(client.WebmasterRegistrationSession())
	if err != nil {
		t.Fatal(err)
	}
	var saved WebmasterRegistrationSession
	if err := json.Unmarshal(body, &saved); err != nil {
		t.Fatal(err)
	}
	restored, err := NewAndroidAppClient(*saved.AndroidApp, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreWebmasterRegistrationSession(&saved); err != nil {
		t.Fatal(err)
	}
	if err := restored.ReportAndroidShareClick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restored.ReportAndroidInstall(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.QueryAndroidInstallReferrer(ctx); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 4 || *restored.AndroidAttribution().AppInstallMediaSource != "server-source" {
		t.Fatal("restored installation lost report dedup or media source")
	}
}

func TestAndroidAttributionNullableReferrerAndFirstLaunchCache(t *testing.T) {
	for _, test := range []struct {
		name        string
		referrer    *string
		firstLaunch bool
		data        string
		wantMedia   string
	}{
		{"unavailable omitted", nil, true, `{"mediaSource":null,"deeplink":"dubox://share_detail?uk=-1"}`, "null"},
		{"actual empty retained", attributionText(""), true, `{"mediaSource":"  "}`, "null"},
		{"later launch retains existing install cache", attributionText("actual"), false, `{"mediaSource":"new-observation","deeplink":"dubox://share_detail?uk=123"}`, "Undefined"},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := androidFixtureProfile()
			profile.NativeParams = map[string]string{"af_media_source": "Undefined"}
			profile.LegacyNativeParams = map[string]string{"af_media_source": "Undefined"}
			capture := attributionFixtureCapture(profile)
			capture.InstallReferrer = test.referrer
			capture.Install.IsFirstLaunch = test.firstLaunch
			capture.Install.InstallTime = nil   // actual package-information failure
			capture.Install.FirstLaunchTime = 0 // actual empty saved cache
			transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				q := req.URL.Query()
				if q.Has("referer_data") != (test.referrer != nil) || (test.referrer != nil && q.Get("referer_data") != *test.referrer) || q.Has("install_time") {
					t.Error("nullable observed inputs changed or were manufactured")
				}
				return shareJSONResponse(req, `{"errno":0,"data":`+test.data+`}`), nil
			})
			client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil {
				t.Fatal(err)
			}
			if err := client.SetAndroidAttributionCapture(capture); err != nil {
				t.Fatal(err)
			}
			if _, err := client.QueryAndroidInstallReferrer(context.Background()); err != nil {
				t.Fatal(err)
			}
			state := client.AndroidAttribution()
			if client.AndroidAppProfile().NativeParams["af_media_source"] != test.wantMedia ||
				(!test.firstLaunch && (state.WebmasterUK != nil || state.AppInstallMediaSource != nil)) {
				t.Fatal("first-launch-only cache updates were not respected")
			}
			if !test.firstLaunch && (state.Referrer.MediaSource == nil || *state.Referrer.MediaSource != "new-observation") {
				t.Fatal("later-launch raw attribution result was lost")
			}
		})
	}
}

func TestAndroidAttributionFailurePreservedAndNoBlindReplay(t *testing.T) {
	for _, test := range []struct{ name, response string }{
		{"missing errno", `{"data":{"mediaSource":"fabricated"}}`},
		{"null data", `{"errno":0,"data":null}`},
		{"wrong data type", `{"errno":0,"data":[]}`},
		{"wrong envelope type", `[]`},
		{"rejected", `{"errno":9,"request_id":"denied","errmsg":"private-referrer-token","data":{"mediaSource":"fabricated"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			client := attributionFixtureClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				return shareJSONResponse(req, test.response), nil
			}))
			if _, err := client.QueryAndroidInstallReferrer(context.Background()); err == nil || strings.Contains(err.Error(), "private-referrer-token") {
				t.Fatal("failed attribution was accepted or raw server error leaked")
			}
			state := client.AndroidAttribution()
			if state.ReferrerReport.Succeeded || !state.ReferrerReport.Attempted || string(state.ReferrerReport.RawResponse) != test.response ||
				state.Referrer != nil || state.AppInstallMediaSource != nil || client.AndroidAppProfile().NativeParams["af_media_source"] != "Undefined" {
				t.Fatal("failed attribution changed installation cache or lost response")
			}
			saved := client.WebmasterRegistrationSession()
			restored, err := NewAndroidAppClient(*saved.AndroidApp)
			if err != nil {
				t.Fatal(err)
			}
			if err := restored.RestoreWebmasterRegistrationSession(saved); err != nil {
				t.Fatal(err)
			}
			if _, err := restored.QueryAndroidInstallReferrer(context.Background()); err == nil || requests != 1 {
				t.Fatal("previously uncertain report was blindly replayed")
			}
		})
	}
	client := attributionFixtureClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Post", URL: req.URL.String(), Err: errors.New("connection interrupted")}
	}))
	if err := client.ReportAndroidInstall(context.Background()); err == nil || strings.Contains(err.Error(), "cuid=") {
		t.Fatal("unknown HTTP result was accepted or signed URL exposed")
	}
	saved := client.WebmasterRegistrationSession()
	if saved.AndroidAttribution.InstallReport.Succeeded || !saved.AndroidAttribution.InstallReport.Attempted || len(saved.AndroidAttribution.InstallReport.RawResponse) != 0 {
		t.Fatal("unknown transport outcome was not distinguished")
	}
	restored, err := NewAndroidAppClient(*saved.AndroidApp)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreWebmasterRegistrationSession(saved); err != nil {
		t.Fatal(err)
	}
	if err := restored.ReportAndroidInstall(context.Background()); err == nil {
		t.Fatal("unknown transport outcome was replayed after restore")
	}
}

func TestAndroidAttributionImportObservedResponsesAndFreshness(t *testing.T) {
	profile := androidFixtureProfile()
	profile.NativeParams = map[string]string{"af_media_source": "Undefined"}
	profile.LegacyNativeParams = map[string]string{"af_media_source": "Undefined"}
	zero := 0
	state := &AndroidAttributionState{
		Capture: attributionFixtureCapture(profile),
		ReferrerReport: AndroidAttributionReport{Attempted: true, Succeeded: true, HTTPStatus: 200, Errno: &zero,
			RequestID: "observed-ref", RawResponse: json.RawMessage(`{"errno":0,"request_id":"observed-ref","data":{"mediaSource":"observed-source","deeplink":"dubox://share_detail?uk=987","campaign":"preserved"}}`)},
	}
	requests := 0
	client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected network request")
	})}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RestoreAndroidAttribution(state); err != nil {
		t.Fatal(err)
	}
	observed := client.AndroidAttribution()
	if observed.Referrer == nil || observed.AppInstallMediaSource == nil || *observed.AppInstallMediaSource != "observed-source" ||
		observed.WebmasterUK == nil || *observed.WebmasterUK != 987 || client.AndroidAppProfile().NativeParams["af_media_source"] != "observed-source" {
		t.Fatal("import failed to normalize actual response-derived first-launch state")
	}
	if _, err := client.QueryAndroidInstallReferrer(context.Background()); err != nil || requests != 0 {
		t.Fatal("imported confirmed report was replayed")
	}
	if state.Referrer != nil || state.AppInstallMediaSource != nil || profile.NativeParams["af_media_source"] != "Undefined" {
		t.Fatal("import mutated caller-owned state/profile")
	}
	if err := client.RestoreAndroidAttribution(state); err == nil {
		t.Fatal("attribution import replaced an existing installation state")
	}
	// A session restore cannot erase existing attempts on the target client.
	saved := client.WebmasterRegistrationSession()
	if err := client.RestoreWebmasterRegistrationSession(saved); err == nil {
		t.Fatal("session restore replaced an existing attribution capture")
	}
	for _, mutate := range []func(*AndroidAttributionState){
		func(s *AndroidAttributionState) { s.ReferrerReport.HTTPStatus = 0 },
		func(s *AndroidAttributionState) { s.ReferrerReport.RequestID = "invented" },
		func(s *AndroidAttributionState) {
			s.ReferrerReport.RawResponse = json.RawMessage(`{"errno":9,"request_id":"observed-ref","data":{}}`)
		},
		func(s *AndroidAttributionState) {
			s.Referrer = &AndroidReferrerData{MediaSource: attributionText("invented")}
		},
		func(s *AndroidAttributionState) { s.AppInstallMediaSource = attributionText("invented") },
	} {
		bad := cloneAndroidAttribution(state)
		mutate(bad)
		fresh, err := NewAndroidAppClient(profile)
		if err != nil {
			t.Fatal(err)
		}
		if err := fresh.RestoreAndroidAttribution(bad); err == nil || fresh.AndroidAttribution() != nil || fresh.AndroidAppProfile().NativeParams["af_media_source"] != "Undefined" {
			t.Fatal("invalid observed response accepted or failed import mutated client")
		}
	}
	// SDK sessions must include their normalized derived state, not a partial
	// externally observed response that has not passed the import operation.
	saved = client.WebmasterRegistrationSession()
	saved.AndroidAttribution.AppInstallMediaSource = nil
	fresh, err := NewAndroidAppClient(*saved.AndroidApp)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.RestoreWebmasterRegistrationSession(saved); err == nil {
		t.Fatal("incomplete normalized first-launch session was accepted")
	}
}

func TestAndroidAttributionWebViewClickBridgeAndFragment(t *testing.T) {
	profile := androidFixtureProfile()
	capture := attributionFixtureCapture(profile)
	capture.Click.PageURL += "#actual-fragment"
	capture.Click.CommonParams = map[string]string{"app_id": "250528", "web": "1", "channel": profile.UserAgent, "clienttype": "1",
		"jsToken": "observed-token", "dp-logid": "observed-log-id", "version": profile.Version, "devuid": profile.DeviceID, "cuid": profile.DeviceID,
		"lang": "ja_JP", "time": "1700000000000", "rand": "0", "zid": ""}
	capture.Click.BridgeBody = map[string]string{"version": profile.Version, "devuid": profile.DeviceID, "cuid": profile.DeviceID, "lang": capture.Click.Language}
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Referer") != strings.Split(capture.Click.PageURL, "#")[0] {
			t.Error("browser Referer retained URL fragment")
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if req.PostForm.Get("c") != capture.Click.PageURL || req.PostForm.Get("lang") != capture.Click.Language || len(req.PostForm["lang"]) != 1 || req.URL.Query().Get("lang") != "ja_JP" || req.URL.Query().Get("cuid") != profile.DeviceID {
			t.Error("observed WebView common query/bridge replacement/actual location.href changed")
		}
		return shareJSONResponse(req, `{"errno":0}`), nil
	})
	client, err := NewAndroidAppClient(profile, WithCookies("ndus=must-not-use-native-cookie"), WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetAndroidAttributionCapture(capture); err != nil {
		t.Fatal(err)
	}
	if err := client.ReportAndroidShareClick(context.Background()); err != nil {
		t.Fatal(err)
	}
	bad := capture
	bad.Click = &AndroidClickAttribution{}
	*bad.Click = *capture.Click
	bad.Click.CommonParams = copyAndroidStringMap(capture.Click.CommonParams)
	bad.Click.CommonParams["cuid"] = "different-installation"
	fresh, err := NewAndroidAppClient(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.SetAndroidAttributionCapture(bad); err == nil {
		t.Fatal("WebView browser query transplanted from another installation")
	}
}

func TestAndroidAttributionCaptureBindingAndSessionValidation(t *testing.T) {
	profile := androidFixtureProfile()
	client, err := NewAndroidAppClient(profile)
	if err != nil {
		t.Fatal(err)
	}
	capture := attributionFixtureCapture(profile)
	capture.DeviceID = "different-installation"
	if err := client.SetAndroidAttributionCapture(capture); err == nil || client.AndroidAttribution() != nil {
		t.Fatal("capture was transplanted to a different installation")
	}
	capture.DeviceID = profile.DeviceID
	capture.Install.Clipboard = "invented-upload-log"
	if err := client.SetAndroidAttributionCapture(capture); err == nil {
		t.Fatal("non-APK clipboard report accepted")
	}
	capture.Install.Clipboard = ""
	if err := client.SetAndroidAttributionCapture(capture); err != nil {
		t.Fatal(err)
	}
	*capture.InstallReferrer = "caller-mutation"
	if *client.AndroidAttribution().Capture.InstallReferrer == "caller-mutation" {
		t.Fatal("capture stores caller-owned mutable strings")
	}
	if err := client.SetAndroidAttributionCapture(capture); err == nil {
		t.Fatal("capture was replaced after binding")
	}
	for _, mutate := range []func(*WebmasterRegistrationSession){
		func(saved *WebmasterRegistrationSession) {
			saved.AndroidAttribution.Capture.DeviceID = "other-installation"
		},
		func(saved *WebmasterRegistrationSession) { saved.AndroidAttribution.InstallReport.Succeeded = true },
		func(saved *WebmasterRegistrationSession) {
			saved.AndroidAttribution.AppInstallMediaSource = attributionText("invented-source")
		},
	} {
		saved := client.WebmasterRegistrationSession()
		mutate(saved)
		restored, err := NewAndroidAppClient(*saved.AndroidApp)
		if err != nil {
			t.Fatal(err)
		}
		if err := restored.RestoreWebmasterRegistrationSession(saved); err == nil || restored.AndroidAttribution() != nil {
			t.Fatal("invalid saved attribution accepted or restore mutated the client on failure")
		}
	}
}
