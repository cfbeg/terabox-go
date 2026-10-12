package terabox

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type androidHyUIReplay struct {
	Scenario string `json:"scenario"`
	Requests []struct {
		DocumentURL string         `json:"document_url"`
		URL         string         `json:"url"`
		Params      map[string]any `json:"params"`
		Data        map[string]any `json:"data"`
	} `json:"requests"`
	Navigations []struct {
		URL string `json:"url"`
	} `json:"navigations"`
}

func TestAndroidHyRegistrationFollowsAPKUIReplayAndRestoresVerification(t *testing.T) {
	// This fixture executes the APK UI and request builders together. The
	// native-default and explicit from=share scenarios have different SendCode
	// attribution; both lose the initial native channel through Vue navigation.
	encoded, err := os.ReadFile("testdata/android_hy_route_wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []androidHyUIReplay
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Scenario, func(t *testing.T) {
			if len(fixture.Requests) != 3 || len(fixture.Navigations) != 2 {
				t.Fatal("incomplete APK UI fixture")
			}
			first := fixture.Requests[0]
			profile := AndroidAppProfile{
				DeviceID: fmt.Sprint(first.Params["devuid"]), Version: fmt.Sprint(first.Params["version"]),
				UserAgent: fmt.Sprint(fixture.Requests[1].Params["channel"]), NativeChannel: fmt.Sprint(first.Params["channel"]),
				Channel: fmt.Sprint(first.Params["channel"]), Language: fmt.Sprint(first.Params["lang"]),
				PageURL: first.DocumentURL, PSign: fmt.Sprint(first.Data["psign"]), ClientType: 1,
			}
			profile.NativeParams = map[string]string{"devuid": profile.DeviceID, "cuid": profile.DeviceID, "channel": profile.NativeChannel}
			profile.LegacyNativeParams = copyAndroidStringMap(profile.NativeParams)
			privateKey, keyResponse := androidPubkeyFixture(t)
			steps := []string{"/wap/hylogin/emailRegister", first.URL, fixture.Requests[1].URL, "/passport/getpubkey", fixture.Requests[2].URL}
			next, bootstraps := 0, 0
			transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if next >= len(steps) || req.URL.Path != steps[next] {
					t.Fatalf("unexpected request %s at step %d", req.URL.Path, next)
				}
				next++
				if req.Header.Get("User-Agent") != profile.UserAgent {
					t.Fatal("UI navigation changed the captured native User-Agent")
				}
				if next == 1 {
					bootstraps++
					if req.Method != http.MethodGet || req.URL.String() != first.DocumentURL {
						t.Fatalf("initial Hy document differs: %s %s", req.Method, req.URL)
					}
					response := shareJSONResponse(req, `<script>var templateData={"pcftoken":"fixture-pcf"};</script>`)
					response.Header.Add("Set-Cookie", "browserid=fixture-browser; Path=/; Secure")
					return response, nil
				}
				if err := req.ParseForm(); err != nil {
					t.Fatal(err)
				}
				requestIndex := map[string]int{fixture.Requests[0].URL: 0, fixture.Requests[1].URL: 1, fixture.Requests[2].URL: 2}[req.URL.Path]
				if req.URL.Path == "/passport/getpubkey" {
					requestIndex = 2
				}
				want := fixture.Requests[requestIndex]
				page, _ := url.Parse(want.DocumentURL)
				if req.Method != http.MethodPost || req.Header.Get("Referer") != want.DocumentURL ||
					req.Header.Get("Origin") != urlOrigin(page) || req.Header.Get("X-Requested-With") != "XMLHttpRequest" {
					t.Fatalf("request did not originate from the active APK document: %s headers=%v", req.URL.Path, req.Header)
				}
				if len(req.URL.Query()) != len(want.Params) {
					t.Fatalf("APK query fields differ: got %v want %v", req.URL.Query(), want.Params)
				}
				for name, value := range want.Params {
					if req.URL.Query().Get(name) != fmt.Sprint(value) {
						t.Errorf("%s query %s=%q, want %v", req.URL.Path, name, req.URL.Query().Get(name), value)
					}
				}
				if cookie, err := req.Cookie("browserid"); err != nil || cookie.Value != "fixture-browser" {
					t.Fatal("active Hy document lost its bootstrap cookie")
				}
				if requestIndex > 0 {
					if cookie, err := req.Cookie("email_ticket"); err != nil || cookie.Value != "fixture-ticket" {
						t.Fatal("restored verification lost the SendCode cookie")
					}
				}
				if req.URL.Path == "/passport/getpubkey" {
					return shareJSONResponse(req, keyResponse), nil
				}
				if len(req.PostForm) != len(want.Data) {
					t.Fatalf("APK form fields differ: got %v want %v", req.PostForm, want.Data)
				}
				for name, value := range want.Data {
					if name == "pwd" {
						ciphertext, err := base64.URLEncoding.DecodeString(req.PostForm.Get(name))
						if err != nil {
							t.Fatal(err)
						}
						plain, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
						if err != nil || string(plain) != fmt.Sprintf("%x32", md5.Sum([]byte("Abcdef12345!"))) {
							t.Fatalf("APK password preprocessing differs: %v", err)
						}
					} else if req.PostForm.Get(name) != fmt.Sprint(value) {
						t.Errorf("%s form %s=%q, want %v", req.URL.Path, name, req.PostForm.Get(name), value)
					}
				}
				switch requestIndex {
				case 0:
					response := shareJSONResponse(req, `{"code":0,"token":"fixture-registration-token"}`)
					response.Header.Add("Set-Cookie", "email_ticket=fixture-ticket; Path=/; Secure")
					return response, nil
				case 1:
					return shareJSONResponse(req, `{"code":0}`), nil
				default:
					return shareJSONResponse(req, `{"code":0,"data":{"ndus":"fixture-only-auth-token","userid":"12345"}}`), nil
				}
			})
			newClient := func() *Client {
				client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: transport}))
				if err != nil {
					t.Fatal(err)
				}
				client.androidApp.now = func() time.Time { return time.UnixMilli(1791792000123) }
				return client
			}
			client := newClient()
			if first.Data["reg_source"] == "share" {
				client.referral = &WebmasterReferral{ShareURL: "https://terabox.com/s/1fixture", ShareFromSURL: "fixture", ShareID: 1, WebmasterUK: 2, Source: "share"}
			}
			sent, err := client.RegisterSendCode(context.Background(), "fixture@example.invalid")
			if err != nil || sent == nil || sent.Token != "fixture-registration-token" {
				t.Fatalf("SendCode failed: response=%+v error=%v", sent, err)
			}
			assertPage := func(client *Client, want string) {
				t.Helper()
				current := client.AndroidAppProfile()
				if current.PageURL != want || current.Channel != profile.UserAgent || current.DeviceID != profile.DeviceID ||
					current.NativeChannel != profile.NativeChannel || current.PSign != profile.PSign ||
					!reflect.DeepEqual(current.NativeParams, profile.NativeParams) || !reflect.DeepEqual(current.LegacyNativeParams, profile.LegacyNativeParams) {
					t.Fatalf("navigation lost active URL or native bridge identity: %+v", current)
				}
			}
			assertPage(client, fixture.Navigations[0].URL)
			savedJSON, err := json.Marshal(client.WebmasterRegistrationSession())
			if err != nil {
				t.Fatal(err)
			}
			var saved WebmasterRegistrationSession
			if err := json.Unmarshal(savedJSON, &saved); err != nil {
				t.Fatal(err)
			}
			if saved.PCFToken != "fixture-pcf" || saved.RegistrationToken != sent.Token || saved.AndroidApp.PageURL != fixture.Navigations[0].URL {
				t.Fatal("SendCode snapshot lost the active verification document or token")
			}
			client = newClient()
			if err := client.RestoreWebmasterRegistrationSession(&saved); err != nil {
				t.Fatal(err)
			}
			client.androidApp.now = func() time.Time { return time.UnixMilli(1791792000123) }
			assertPage(client, fixture.Navigations[0].URL)
			if _, err := client.RegisterVerify(context.Background(), saved.RegistrationToken, "1234"); err != nil {
				t.Fatal(err)
			}
			assertPage(client, fixture.Navigations[1].URL)
			finished, err := client.RegisterFinish(context.Background(), saved.RegistrationToken, "Abcdef12345!")
			if err != nil || finished == nil || finished.NDUS != "fixture-only-auth-token" || client.AndroidAppProfile().UID != "12345" || next != len(steps) || bootstraps != 1 {
				t.Fatalf("restored APK flow failed: response=%+v error=%v requests=%d bootstraps=%d", finished, err, next, bootstraps)
			}
			assertPage(client, fixture.Navigations[1].URL)
		})
	}
}

func TestAndroidHyRejectedStepsKeepCurrentDocumentAndSession(t *testing.T) {
	for _, stage := range []string{"send", "verify"} {
		for _, test := range []struct {
			name, body   string
			transportErr error
			wantError    bool
		}{
			{name: "code rejected", body: `{"code":58,"msg":"rejected"}`},
			{name: "errno rejected", body: `{"code":0,"errno":51,"errmsg":"rejected"}`},
			{name: "challenge", body: `{"errno":460030,"errmsg":"dragdrop"}`, wantError: true},
			{name: "missing code", body: `{"data":{}}`, wantError: true},
			{name: "transport failed", transportErr: errors.New("fixture response lost"), wantError: true},
		} {
			t.Run(stage+"/"+test.name, func(t *testing.T) {
				profile := androidFixtureProfile()
				path := "/passport/register_v4/sendcode"
				if stage == "verify" {
					path = "/passport/register_v4/verify"
					profile.PageURL = "https://www.terabox.com/wap/hylogin/emailVerfify?from=share"
					profile.Channel = profile.UserAgent
				}
				requests := 0
				client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					requests++
					if req.URL.Path != path || req.Header.Get("Referer") != profile.PageURL {
						t.Fatalf("unexpected request for rejected step: %s headers=%v", req.URL, req.Header)
					}
					if test.transportErr != nil {
						return nil, test.transportErr
					}
					response := shareJSONResponse(req, test.body)
					response.Header.Add("Set-Cookie", "failed_step=must-not-commit; Path=/")
					return response, nil
				})}))
				if err != nil {
					t.Fatal(err)
				}
				client.androidApp.ready = true
				client.data.pcfToken = "fixture-pcf"
				client.registrationToken = "fixture-current-token"
				client.cookies["browserid"] = "fixture-browser"
				before := client.WebmasterRegistrationSession()
				var response *PassportResponse
				if stage == "send" {
					response, err = client.RegisterSendCode(context.Background(), "fixture@example.invalid")
				} else {
					response, err = client.RegisterVerify(context.Background(), "fixture-current-token", "1234")
				}
				if (err != nil) != test.wantError || requests != 1 {
					t.Fatalf("unexpected rejected-step result: response=%+v error=%v requests=%d", response, err, requests)
				}
				if after := client.WebmasterRegistrationSession(); !reflect.DeepEqual(after, before) {
					t.Fatalf("failed %s advanced its document or committed session state: before=%+v after=%+v", stage, before, after)
				}
			})
		}
	}
}
