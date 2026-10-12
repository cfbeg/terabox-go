package terabox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This fixture retains the names, multiplicity and public values from the Play
// APK's actual interceptor output. Private identity/referrer values are synthetic.
func TestAndroidPlayAttributionObservedNativeWire(t *testing.T) {
	data, err := os.ReadFile("testdata/android_play_attribution_wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		NowMS           int64                     `json:"now_ms"`
		NativeParams    map[string]string         `json:"native_params"`
		Install         AndroidInstallAttribution `json:"install"`
		InstallReferrer string                    `json:"install_referrer"`
		Requests        []struct {
			Path, Method, Body string
			Query              url.Values
			Headers            http.Header
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	profile := androidFixtureProfile()
	profile.NativeParams = fixture.NativeParams
	profile.NativeChannel = fixture.NativeParams["channel"]
	profile.Language = fixture.NativeParams["lang"]
	profile.DeviceID = fixture.NativeParams["cuid"]
	seen := 0
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if seen >= len(fixture.Requests) {
			t.Fatal("native attribution made an extra request")
		}
		want := fixture.Requests[seen]
		seen++
		var body []byte
		if req.Body != nil {
			var err error
			body, err = io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
		}
		if req.Method != want.Method || req.URL.Host != "terabox.com" || req.URL.Path != want.Path || string(body) != want.Body ||
			req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
			req.Header.Get("Referer") != "https://terabox.com/" || req.UserAgent() != profile.UserAgent ||
			req.Header.Get("X-Requested-With") != "" || req.Header.Get("Accept") != "" {
			t.Error("request method/body/headers differ from the observed native transport")
		}
		if !reflect.DeepEqual(req.Header.Values("Cookie"), want.Headers.Values("Cookie")) || len(want.Headers.Values("Cookie")) != 1 {
			t.Error("native attribution omitted the observed explicit empty guest Cookie header")
		}
		got := req.URL.Query()
		// The native logid's random suffix changes per request. Check its actual
		// timestamp/IP/nonce contract before comparing every remaining field.
		decoded, err := base64.RawStdEncoding.DecodeString(got.Get("logid"))
		parts := strings.Split(string(decoded), ",")
		if err != nil || len(parts) != 3 || parts[0] != strconv.FormatInt(fixture.NowMS, 10) || parts[1] != "127.0.0.1" {
			t.Fatal("native logid lost the observed IP or request timestamp")
		}
		nonce, err := strconv.Atoi(parts[2])
		if err != nil || nonce < 0 || nonce >= 999999 {
			t.Fatal("native logid nonce is outside the APK's range")
		}
		got.Set("logid", want.Query.Get("logid"))
		if !reflect.DeepEqual(got, want.Query) {
			t.Error("native query differs from the captured field names, values or multiplicity")
			for key, values := range want.Query {
				if !reflect.DeepEqual(got[key], values) {
					t.Errorf("sanitized observed field %q: got %q, want %q", key, got[key], values)
				}
			}
			for key := range got {
				if !want.Query.Has(key) {
					t.Errorf("unexpected native field %q", key)
				}
			}
		}
		if !strings.Contains(req.URL.RawQuery, "device_country=JP&device_country=jp") || !strings.HasSuffix(req.URL.RawQuery, "&rand") {
			t.Error("endpoint/common country order or guest bare rand was changed")
		}
		if req.URL.Path == "/api/srn/ref" {
			return shareJSONResponse(req, `{"errno":0,"data":{"mediaSource":"fixture-returned-source"}}`), nil
		}
		return shareJSONResponse(req, `{"errno":0}`), nil
	})
	client, err := NewAndroidAppClient(profile, WithAPIHost("https://terabox.com"), WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	client.androidApp.now = func() time.Time { return time.UnixMilli(fixture.NowMS) }
	capture := AndroidAttributionCapture{DeviceID: profile.DeviceID, Install: &fixture.Install,
		InstallReferrer: &fixture.InstallReferrer}
	if err := client.SetAndroidAttributionCapture(capture); err != nil {
		t.Fatal(err)
	}
	if err := client.ReportAndroidInstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.QueryAndroidInstallReferrer(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen != 2 || !reflect.DeepEqual(client.AndroidAppProfile().NativeParams, fixture.NativeParams) {
		t.Fatal("native reporting missed a captured request or mutated the captured common inputs")
	}
}

func TestAndroidAttributionCookieHeaderPreservesObservedGuestAndAccountValues(t *testing.T) {
	for _, test := range []struct {
		name          string
		input, want   []string
		authenticated bool
	}{
		{"guest_unset", nil, []string{""}, false},
		{"guest_explicit_empty", []string{""}, []string{""}, false},
		{"account", []string{"ndus=fixture-session; locale=ja"}, []string{"ndus=fixture-session; locale=ja"}, true},
		{"account_multiple_headers", []string{"ndus=fixture-session", "locale=ja"}, []string{"ndus=fixture-session", "locale=ja"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := androidFixtureProfile()
			if test.authenticated {
				signing := androidSignatureConfig()
				profile.UID, profile.EncodedSK = signing.UID, signing.EncodedSK
			}
			client, err := NewAndroidAppClient(profile)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/api/srn/ins", "/api/srn/ref"} {
				request, _ := http.NewRequest(http.MethodPost, "https://terabox.com"+path, nil)
				if test.input != nil {
					request.Header["Cookie"] = append([]string(nil), test.input...)
				}
				original := request.Header.Clone()
				sent, err := client.androidAppAPIRequest(request)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(sent.Header.Values("Cookie"), test.want) || !reflect.DeepEqual(request.Header, original) {
					t.Fatal("native attribution lost a Cookie value or mutated the endpoint request")
				}
				if test.authenticated {
					cookie, err := sent.Cookie("ndus")
					if err != nil || cookie.Value != "fixture-session" || len(sent.URL.Query().Get("rand")) != 40 {
						t.Fatal("authenticated attribution lost its native session or signer")
					}
				}
			}
		})
	}
	client, err := NewAndroidAppClient(androidFixtureProfile())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/account/uinfo", "/api/shorturlinfo", "/share/list"} {
		request, _ := http.NewRequest(http.MethodPost, "https://terabox.com"+path, nil)
		sent, err := client.androidAppAPIRequest(request)
		if err != nil || len(sent.Header.Values("Cookie")) != 0 {
			t.Fatal("unobserved endpoints inherited the attribution-only guest Cookie header")
		}
	}
}

func TestAndroidAttributionCountryUsesOnlyObservedCommonValue(t *testing.T) {
	for _, common := range []struct {
		name  string
		value *string
		want  []string
	}{
		{"unobserved", nil, []string{"JP"}},
		{"lowercase", attributionText("jp"), []string{"JP", "jp"}},
		{"same", attributionText("JP"), []string{"JP", "JP"}},
		{"empty", attributionText(""), []string{"JP", ""}},
	} {
		t.Run(common.name, func(t *testing.T) {
			profile := androidFixtureProfile()
			profile.NativeParams = map[string]string{"install_time": "stale", "device_lang": "stale", "referer_data": "stale"}
			if common.value != nil {
				profile.NativeParams["device_country"] = *common.value
			}
			client, err := NewAndroidAppClient(profile)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/api/srn/ins", "/api/srn/ref"} {
				query := androidInstallAttributionQuery(&AndroidInstallAttribution{DeviceCountry: "JP", DeviceLanguage: "ja"})
				request, _ := http.NewRequest(http.MethodPost, "https://terabox.com"+path+"?"+query.Encode(), nil)
				for repeat := 0; repeat < 2; repeat++ {
					sent, err := client.androidAppAPIRequest(request)
					if err != nil {
						t.Fatal(err)
					}
					got := sent.URL.Query()
					if !reflect.DeepEqual(got["device_country"], common.want) || got.Get("device_lang") != "ja" || got.Has("install_time") || got.Has("referer_data") {
						t.Fatal("country duplication invented an observation or changed an endpoint-owned field")
					}
				}
				if !reflect.DeepEqual(request.URL.Query()["device_country"], []string{"JP"}) {
					t.Fatal("common country was appended to the original endpoint request")
				}
			}
		})
	}
}
