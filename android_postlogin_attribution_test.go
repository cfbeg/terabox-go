package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"testing"
)

func TestAndroidMaterialSceneAPKMapping(t *testing.T) {
	for _, test := range []struct {
		scene string
		want  *AndroidMaterialSources
	}{
		{"", nil}, {"  ", nil}, {"aiPicture", &AndroidMaterialSources{Ad: "aipicture", Native: "aipicture"}},
		{"aiPPT", &AndroidMaterialSources{Ad: "na_aippt", Native: "na_aippt"}},
		{"teraAI", &AndroidMaterialSources{Ad: "teraai", Native: "teraai"}},
		{"scanPage", &AndroidMaterialSources{Ad: "terascan", Native: "terascan"}},
		{"aiSearch", &AndroidMaterialSources{Ad: "aisearch", Native: "aisearch"}},
		{"transcribe", &AndroidMaterialSources{Ad: "aitranscribe", Native: "aitranscribe"}},
		{"aiCoding", &AndroidMaterialSources{Ad: "ai_coding", Native: "ai_coding"}},
		{"shortPlay", &AndroidMaterialSources{Ad: "shortplay", Native: "shortplay"}},
		{"fb_real_scene", &AndroidMaterialSources{Facebook: "real_scene"}}, {"fb_", nil},
		{"observed_other", &AndroidMaterialSources{Native: "observed_other"}},
	} {
		if got := androidMaterialSources(&test.scene); !reflect.DeepEqual(got, test.want) {
			t.Errorf("scene %q: got %#v, want %#v", test.scene, got, test.want)
		}
	}
}

func TestAndroidPostLoginAttributionOwnAccountWireAndRestore(t *testing.T) {
	ctx := context.Background()
	profile := androidFixtureProfile()
	profile.NativeParams = map[string]string{"af_media_source": "Undefined", "code": "stale-template-code", "ad_material_source": "stale"}
	profile.LegacyNativeParams = map[string]string{"af_media_source": "Undefined"}
	cfg := androidSignatureConfig()
	profile.UID, profile.EncodedSK = cfg.UID, cfg.EncodedSK
	var paths []string
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		q := req.URL.Query()
		if q.Get("af_media_source") != "Undefined" || q.Get("rand") == "" || q.Get("rand") == "0" {
			t.Error("authenticated native common query or frozen media cache is wrong")
		}
		switch req.URL.Path {
		case "/api/srn/ref":
			return shareJSONResponse(req, `{"errno":0,"data":{"mediaSource":"new-source","campaign":"actual-campaign","deepLinkValue":"actual-value","code":"actual-returned-code","deeplink":"dubox://share_detail?uk=555"}}`), nil
		case "/api/activity/invite/v1/reportinvite":
			if req.Method != http.MethodGet || q.Get("code") != "actual-returned-code" || q.Has("uk") || q.Has("bind_uid") {
				t.Error("invite code was altered or invented from owner")
			}
			return shareJSONResponse(req, `{"errno":0,"request_id":"invite-actual"}`), nil
		case "/newmain/reporter/userattribute":
			if req.Method != http.MethodPost || q.Get("ad_material_source") != "" || q.Get("na_material_source") != "" || q.Get("fb_material_source") != "actual_scene" || !q.Has("ad_material_source") || !q.Has("na_material_source") {
				t.Error("material query differs from native scene mapping")
			}
			if req.Body != nil {
				b, _ := io.ReadAll(req.Body)
				if len(b) != 0 {
					t.Error("material report has a nonempty body")
				}
			}
			return shareJSONResponse(req, `{"errno":0,"request_id":"material-actual","future":"preserved"}`), nil
		default:
			return nil, errors.New("unexpected test request")
		}
	})
	client, err := NewAndroidAppClient(profile, WithCookies("ndus=fixture-own-ndus"), WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	capture := attributionFixtureCapture(profile)
	capture.MaterialSourceScene = attributionText("fb_actual_scene")
	if err = client.SetAndroidAttributionCapture(capture); err != nil {
		t.Fatal(err)
	}
	if _, err = client.QueryAndroidInstallReferrer(ctx); err != nil {
		t.Fatal(err)
	}
	if err = client.ReportAndroidPostLoginAttribution(ctx); err != nil {
		t.Fatal(err)
	}
	state := client.AndroidAttribution()
	if state.AfCampaign == nil || *state.AfCampaign != "actual-campaign" || state.DeepLinkValue == nil || *state.DeepLinkValue != "actual-value" || state.PostLogin == nil || !state.PostLogin.InviteReport.Succeeded || !state.PostLogin.MaterialReport.Succeeded || state.NativeMediaCache.Value == nil || *state.NativeMediaCache.Value != "Undefined" {
		t.Fatal("separate stored/cache/post-login state was lost")
	}
	if err = client.ReportAndroidPostLoginAttribution(ctx); err != nil || len(paths) != 3 {
		t.Fatal("confirmed report was repeated")
	}
	body, _ := json.Marshal(client.WebmasterRegistrationSession())
	var saved WebmasterRegistrationSession
	if err = json.Unmarshal(body, &saved); err != nil {
		t.Fatal(err)
	}
	restored, err := NewAndroidAppClient(*saved.AndroidApp, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.RestoreWebmasterRegistrationSession(&saved); err != nil {
		t.Fatal(err)
	}
	if err = restored.ReportAndroidPostLoginAttribution(ctx); err != nil || len(paths) != 3 {
		t.Fatal("saved post-login attempts were replayed")
	}
	saved.AndroidAttribution.PostLogin.InviteCode = attributionText("555")
	fresh, _ := NewAndroidAppClient(*saved.AndroidApp)
	if err = fresh.RestoreWebmasterRegistrationSession(&saved); err == nil {
		t.Fatal("owner-substituted saved code was accepted")
	}
}

func TestAndroidPostLoginAttributionNoFabricatedInputsAndUnknownNotReplayed(t *testing.T) {
	profile := androidFixtureProfile()
	requests := 0
	client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("uncertain transport")
	})}))
	if err != nil {
		t.Fatal(err)
	}
	if err = client.ReportAndroidPostLoginAttribution(context.Background()); err != nil || requests != 0 {
		t.Fatal("missing capture caused report")
	}
	if err = client.SetAndroidAttributionCapture(attributionFixtureCapture(profile)); err != nil {
		t.Fatal(err)
	}
	if err = client.ReportAndroidPostLoginAttribution(context.Background()); err != nil || requests != 0 {
		t.Fatal("share owner or unconfirmed code caused report")
	}
	client.mu.Lock()
	client.androidAttribution.Capture.MaterialSourceScene = attributionText("aiSearch")
	client.mu.Unlock()
	if err = client.ReportAndroidPostLoginAttribution(context.Background()); err == nil || requests != 0 {
		t.Fatal("unauthenticated eligible report did not stop locally")
	}
	client.mu.Lock()
	cfg := androidSignatureConfig()
	client.androidApp.profile.UID, client.androidApp.profile.EncodedSK = cfg.UID, cfg.EncodedSK
	client.cookies["ndus"] = "fixture"
	client.mu.Unlock()
	if err = client.ReportAndroidPostLoginAttribution(context.Background()); err == nil || requests != 1 {
		t.Fatal("uncertain report outcome was not surfaced")
	}
	if err = client.ReportAndroidPostLoginAttribution(context.Background()); err == nil || requests != 1 {
		t.Fatal("uncertain report was replayed")
	}
	state := client.AndroidAttribution()
	if !state.PostLogin.MaterialReport.Attempted || state.PostLogin.MaterialReport.Succeeded || state.PostLogin.InviteReport.Attempted {
		t.Fatal("uncertain report or missing invite state changed")
	}
}

func TestAndroidMediaCacheUninitializedStoredReadsOnce(t *testing.T) {
	profile := androidFixtureProfile()
	client, _ := NewAndroidAppClient(profile)
	capture := attributionFixtureCapture(profile)
	capture.NativeMediaCache = &AndroidNativeMediaCache{}
	capture.StoredMediaSource = attributionText("actual-prior-store")
	if err := client.SetAndroidAttributionCapture(capture); err != nil {
		t.Fatal(err)
	}
	client.initializeAndroidAttributionMediaCache()
	client.mu.Lock()
	client.androidAttribution.AppInstallMediaSource = attributionText("later-server-result")
	client.androidAttribution.ReferrerReport.Succeeded = true
	client.mu.Unlock()
	client.initializeAndroidAttributionMediaCache()
	if client.AndroidAppProfile().NativeParams["af_media_source"] != "actual-prior-store" {
		t.Fatal("later MMKV store overwrote initialized native cache")
	}
}

func TestAndroidMediaCacheActualAPKGetterReplayCases(t *testing.T) {
	body, err := os.ReadFile("testdata/android_media_cache_wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		CodeOffset string `json:"code_offset"`
		Cases      []struct {
			Initial *string `json:"initial_cache"`
			Before  *string `json:"stored_before"`
			After   string  `json:"stored_after"`
			First   string  `json:"first_native_value"`
			Later   string  `json:"later_native_value"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.CodeOffset != "0xcf181c" || len(fixture.Cases) != 4 {
		t.Fatal("fixture is not actual APK getter replay")
	}
	for _, test := range fixture.Cases {
		profile := androidFixtureProfile()
		client, _ := NewAndroidAppClient(profile)
		capture := attributionFixtureCapture(profile)
		capture.NativeMediaCache = &AndroidNativeMediaCache{Initialized: test.Initial != nil, Value: test.Initial}
		capture.StoredMediaSource = test.Before
		if err = client.SetAndroidAttributionCapture(capture); err != nil {
			t.Fatal(err)
		}
		client.initializeAndroidAttributionMediaCache()
		if got := client.AndroidAppProfile().NativeParams["af_media_source"]; got != test.First {
			t.Fatalf("first native cache %q; actual APK %q", got, test.First)
		}
		client.mu.Lock()
		client.androidAttribution.AppInstallMediaSource = &test.After
		client.androidAttribution.ReferrerReport.Succeeded = true
		client.mu.Unlock()
		client.initializeAndroidAttributionMediaCache()
		if got := client.AndroidAppProfile().LegacyNativeParams["af_media_source"]; got != test.Later {
			t.Fatalf("later native cache %q; actual APK %q", got, test.Later)
		}
	}
}

func TestAndroidLaterLaunchReturnedCodeReportsWithoutMaterialOrOwnerBinding(t *testing.T) {
	profile := androidFixtureProfile()
	profile.NativeParams = map[string]string{"af_media_source": "Undefined"}
	profile.LegacyNativeParams = map[string]string{"af_media_source": "Undefined"}
	cfg := androidSignatureConfig()
	profile.UID, profile.EncodedSK = cfg.UID, cfg.EncodedSK
	var paths []string
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		switch req.URL.Path {
		case "/api/srn/ref":
			return shareJSONResponse(req, `{"errno":0,"data":{"mediaSource":"later-selected-media","code":"real-later-code","campaign":"later-campaign","deeplink":"dubox://share_detail?uk=555"}}`), nil
		case "/api/activity/invite/v1/reportinvite":
			if req.URL.Query().Get("code") != "real-later-code" {
				t.Error("later genuine code was lost")
			}
			return shareJSONResponse(req, `{"errno":0}`), nil
		default:
			t.Fatal("later launch fabricated a material report")
			return nil, nil
		}
	})
	client, err := NewAndroidAppClient(profile, WithCookies("ndus=fixture"), WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	capture := attributionFixtureCapture(profile)
	capture.Install.IsFirstLaunch = false
	capture.MaterialSourceScene = attributionText("aiSearch")
	if err = client.SetAndroidAttributionCapture(capture); err != nil {
		t.Fatal(err)
	}
	if _, err = client.QueryAndroidInstallReferrer(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = client.ReportAndroidPostLoginAttribution(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := client.AndroidAttribution()
	if len(paths) != 2 || state.WebmasterUK != nil || state.PostLogin.MaterialSources != nil || state.PostLogin.MaterialReport.Attempted || *state.AppInstallMediaSource != "later-selected-media" || client.AndroidAppProfile().NativeParams["af_media_source"] != "Undefined" {
		t.Fatal("later-launch store/code/material/cache conditions diverged from APK")
	}
	saved := client.WebmasterRegistrationSession()
	restored, _ := NewAndroidAppClient(*saved.AndroidApp)
	if err = restored.RestoreWebmasterRegistrationSession(saved); err != nil {
		t.Fatal(err)
	}
}
