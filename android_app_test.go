package terabox

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func androidFixtureProfile() AndroidAppProfile {
	return AndroidAppProfile{DeviceID: "fixture-cuid", Version: "4.26.5", UserAgent: "fixture-dubox-android-webview",
		NativeChannel: "android_11_fixture_bd-dubox_1024074p", Channel: "fixture-channel", Language: "ja",
		PageURL: "https://www.terabox.com/wap/hylogin/emailRegister?type=1&channel=fixture-channel",
		PSign:   "fixture-psign", ClientType: 1}
}

func androidPubkeyFixture(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	padding := aes.BlockSize - len(public)%aes.BlockSize
	for i := 0; i < padding; i++ {
		public = append(public, byte(padding))
	}
	secret, iv := "0123456789abcdef", "abcdefghijklmnop"
	block, _ := aes.NewCipher([]byte(secret))
	ciphertext := make([]byte, len(public))
	cipher.NewCBCEncrypter(block, []byte(iv)).CryptBlocks(ciphertext, public)
	body, _ := json.Marshal(map[string]any{"code": 0, "data": map[string]string{
		"pp1": ToURLSafeBase64(iv + base64.StdEncoding.EncodeToString(ciphertext)), "pp2": secret, "pp4": "fixture-pp4"}})
	return key, string(body)
}

func TestAndroidAppRegistrationMatchesAPKReplay(t *testing.T) {
	fixture, err := os.ReadFile("testdata/android_h5_wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected []struct {
		URL    string         `json:"url"`
		Params map[string]any `json:"params"`
		Data   map[string]any `json:"data"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(fixture)))
	decoder.UseNumber()
	if err := decoder.Decode(&expected); err != nil {
		t.Fatal(err)
	}
	privateKey, keyResponse := androidPubkeyFixture(t)
	steps := []string{"/wap/hylogin/emailRegister", "/passport/register_v4/sendcode", "/passport/register_v4/verify", "/passport/getpubkey", "/passport/register_v4/finish"}
	next := 0
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if next >= len(steps) || req.URL.Path != steps[next] {
			t.Fatalf("unexpected request %s at step %d", req.URL.Path, next)
		}
		next++
		if req.Header.Get("User-Agent") != "fixture-dubox-android-webview" {
			t.Fatal("lost captured app User-Agent")
		}
		if req.URL.Path == steps[0] {
			if req.Header.Get("Cookie") != "" {
				t.Fatal("invented a guest cookie")
			}
			response := shareJSONResponse(req, `<script>window.__INITIAL_STATE__={"pcftoken":"fixture-pcf"};</script>`)
			response.Header.Add("Set-Cookie", "__bid_n=fixture-visitor; Path=/; HttpOnly")
			return response, nil
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if req.Method != http.MethodPost || req.PostForm.Get("client") != "android" || req.PostForm.Get("pcftoken") != "fixture-pcf" ||
			req.Header.Get("X-Requested-With") != "XMLHttpRequest" || !strings.Contains(req.Header.Get("Cookie"), "__bid_n=fixture-visitor") {
			t.Fatalf("not the Hy app request: method=%s form=%v headers=%v", req.Method, req.PostForm, req.Header)
		}
		if req.URL.Path == "/passport/getpubkey" {
			return shareJSONResponse(req, keyResponse), nil
		}
		index := map[string]int{steps[1]: 0, steps[2]: 1, steps[4]: 2}[req.URL.Path]
		want := expected[index]
		if len(req.URL.Query()) != len(want.Params) || len(req.PostForm) != len(want.Data) {
			t.Fatalf("APK shape differs: query=%v form=%v", req.URL.Query(), req.PostForm)
		}
		for key, value := range want.Params {
			if req.URL.Query().Get(key) != fmt.Sprint(value) {
				t.Errorf("query %s=%q, want %v", key, req.URL.Query().Get(key), value)
			}
		}
		for key, value := range want.Data {
			if key == "pwd" {
				ciphertext, err := base64.URLEncoding.DecodeString(req.PostForm.Get(key))
				if err != nil {
					t.Fatal(err)
				}
				plain, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
				if err != nil || string(plain) != fmt.Sprintf("%x32", md5.Sum([]byte("Abcdef12345"))) {
					t.Fatalf("APK password preprocessing differs: %v", err)
				}
			} else if req.PostForm.Get(key) != fmt.Sprint(value) {
				t.Errorf("form %s=%q, want %v", key, req.PostForm.Get(key), value)
			}
		}
		switch index {
		case 0:
			response := shareJSONResponse(req, `{"code":0,"token":"fixture-registration-token"}`)
			response.Header.Add("Set-Cookie", "email_ticket=fixture-ticket; Path=/")
			return response, nil
		case 1:
			if !strings.Contains(req.Header.Get("Cookie"), "email_ticket=fixture-ticket") {
				t.Fatal("registration cookie not preserved")
			}
			return shareJSONResponse(req, `{"code":0,"data":null}`), nil
		default:
			return shareJSONResponse(req, `{"code":0,"data":{"ndus":"fixture-native-session","userid":"9007199254740993"}}`), nil
		}
	})}))
	if err != nil {
		t.Fatal(err)
	}
	client.androidApp.now = func() time.Time { return time.UnixMilli(1791680000123) }
	client.referral = &WebmasterReferral{ShareURL: "https://www.terabox.com/s/1fixture", ShareFromSURL: "fixture", ShareID: 1, WebmasterUK: 2, Source: "share"}
	sent, err := client.RegisterSendCode(context.Background(), "fixture@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterVerify(context.Background(), sent.Token, "1234"); err != nil {
		t.Fatal(err)
	}
	finished, err := client.RegisterFinish(context.Background(), sent.Token, "Abcdef12345")
	if err != nil || finished.NDUS != "fixture-native-session" || client.AndroidAppProfile().UID != "9007199254740993" || next != len(steps) {
		t.Fatalf("native account was not preserved: response=%+v error=%v requests=%d", finished, err, next)
	}
	if ndus, _ := client.CookieValue("ndus"); ndus != finished.NDUS {
		t.Fatal("JSON native ndus was not committed as a cookie")
	}
	if _, err := client.RegisterFinish(context.Background(), sent.Token, "Abcdef12345"); err == nil {
		t.Fatal("registration was repeatable after success")
	}
}

func TestAndroidAppProfileValidationAndSnapshots(t *testing.T) {
	profile := androidFixtureProfile()
	profile.CKData = map[string]string{"ck_val": "fixture-ck"}
	profile.NativeParams = map[string]string{"device_country": "fixture-country"}
	profile.LegacyNativeParams = map[string]string{"app_name": "dubox"}
	profile.NativeCKData = map[string]string{"ck_val": "fixture-native-ck"}
	client, err := NewAndroidAppClient(profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.CKData["ck_val"], profile.NativeParams["device_country"] = "changed", "changed"
	snapshot := client.AndroidAppProfile()
	snapshot.LegacyNativeParams["app_name"], snapshot.NativeCKData["ck_val"] = "changed", "changed"
	got := client.AndroidAppProfile()
	if got.CKData["ck_val"] != "fixture-ck" || got.NativeParams["device_country"] != "fixture-country" || got.LegacyNativeParams["app_name"] != "dubox" || got.NativeCKData["ck_val"] != "fixture-native-ck" {
		t.Fatal("profile maps were shared with callers")
	}
	if client.CookieString() != "" || client.WebmasterRegistrationSession() == nil {
		t.Fatal("guest bootstrap invented cookies or lacked a profile-only recovery snapshot")
	}
	for _, mutate := range []func(*AndroidAppProfile){
		func(p *AndroidAppProfile) { p.DeviceID = "" }, func(p *AndroidAppProfile) { p.NativeChannel = "" },
		func(p *AndroidAppProfile) { p.UserAgent = "web" }, func(p *AndroidAppProfile) { p.ClientType = 0 },
		func(p *AndroidAppProfile) { p.PageURL = "https://www.terabox.com/wap/outlogin/login" },
	} {
		bad := androidFixtureProfile()
		mutate(&bad)
		if _, err := NewAndroidAppClient(bad); err == nil {
			t.Fatal("invalid app identity accepted")
		}
	}
}

func TestAndroidAppSessionRestoreKeepsProtocolWithoutReferral(t *testing.T) {
	client, _ := NewAndroidAppClient(androidFixtureProfile())
	client.androidApp.ready = true
	client.data.pcfToken = "fixture-pcf"
	client.registrationToken = "fixture-registration-token"
	client.registrationFinished = true
	client.registrationConfirmed = true
	client.cookies["ndus"] = "fixture-session"
	client.androidApp.profile.UID = "9007199254740993"
	saved := client.WebmasterRegistrationSession()
	encoded, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip WebmasterRegistrationSession
	if err := json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	before := client.AndroidAppProfile()
	fresh := NewClient("")
	if err := fresh.RestoreWebmasterRegistrationSession(&roundtrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fresh.AndroidAppProfile(), before) || fresh.cookies["ndus"] != "fixture-session" || !fresh.registrationFinished || fresh.referral != nil {
		t.Fatal("app-only restore lost its native identity or state")
	}
	if err := fresh.validateReferralRegistrationToken(saved.RegistrationToken); err == nil {
		t.Fatal("restored finish could be repeated")
	}
	if err := fresh.RestoreWebmasterRegistrationSession(&roundtrip); err == nil {
		t.Fatal("restore accepted a used client")
	}
}

func TestAndroidAppRejectsWebBootstrapAndFSEC(t *testing.T) {
	for _, page := range []string{`<script>var templateData={"pcftoken":"fixture"};window.fsec={};</script>`, `<html>No PCF token</html>`} {
		requests := 0
		client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			if req.URL.Path != "/wap/hylogin/emailRegister" {
				t.Fatalf("fallback/request before valid app bootstrap: %s", req.URL.Path)
			}
			return shareJSONResponse(req, page), nil
		})}))
		if _, err := client.UpdateAppData(context.Background(), ""); err == nil || requests != 0 {
			t.Fatal("app client fetched the Web main page")
		}
		if _, err := client.RegisterSendCode(context.Background(), "fixture@example.invalid"); err == nil || requests != 1 {
			t.Fatal("invalid/fsec bootstrap proceeded with plain email")
		}
	}
}

func TestAndroidAppNativeAndHyRandFamilies(t *testing.T) {
	client, _ := NewAndroidAppClient(androidFixtureProfile())
	client.androidApp.now = func() time.Time { return time.UnixMilli(1791680000123) }
	for _, path := range []string{"/share/list", "/share/transfer", "/api/shorturlinfo"} {
		req, _ := http.NewRequest(http.MethodGet, "https://www.terabox.com"+path+"?web=1&jsToken=web-token&bdstoken=web-bds&shorturl=fixture", nil)
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("Accept", "application/json, text/plain, */*")
		original := req.URL.String()
		sent, err := client.androidAppAPIRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		if req.URL.String() != original || sent.Header.Get("X-Requested-With") != "" || sent.Header.Get("Accept") != "" || sent.Header.Get("Referer") != "https://terabox.com/" {
			t.Fatal("native request mutated its caller or inherited XHR headers")
		}
		query := sent.URL.Query()
		if query.Has("web") || query.Has("jsToken") || query.Has("bdstoken") || query.Get("channel") != client.AndroidAppProfile().NativeChannel {
			t.Fatal("native request used Web/H5 parameters")
		}
		if path == "/api/shorturlinfo" {
			if query.Has("rand") {
				t.Fatal("old guest transport added rand")
			}
		} else if !strings.HasSuffix(sent.URL.RawQuery, "&rand") || strings.Contains(sent.URL.RawQuery, "rand=") || query.Has("app_id") {
			t.Fatal("new guest Retrofit did not preserve bare rand/native app-id absence")
		}
	}
	hy, err := client.androidH5Query()
	if err != nil || hy.Get("rand") != "0" || hy.Get("channel") != "fixture-channel" {
		t.Fatal("Hy guest did not use its distinct rand/channel family")
	}
}

func TestAndroidAppErrorsDoNotExposeBridgeTokens(t *testing.T) {
	profile := androidFixtureProfile()
	profile.CKData = map[string]string{"ck_tk": "fixture-secret-token"}
	client, _ := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("connection unavailable")
	})}))
	client.androidApp.ready = true
	client.data.pcfToken = "fixture-pcf"
	_, err := client.RegisterSendCode(context.Background(), "fixture@example.invalid")
	if err == nil || strings.Contains(err.Error(), "fixture-secret-token") || strings.Contains(err.Error(), "ck_tk") {
		t.Fatalf("bridge token appeared in error: %v", err)
	}
}

func TestAndroidAppNativeLogIDRetainsCapturedIPAndRefreshesTime(t *testing.T) {
	captured := base64.RawStdEncoding.EncodeToString([]byte("1,10.0.2.16,5"))
	value, err := refreshAndroidLogID(captured, 1791680000123)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := base64.RawStdEncoding.DecodeString(value)
	parts := strings.Split(string(decoded), ",")
	nonce, err := strconv.Atoi(parts[2])
	if parts[0] != "1791680000123" || parts[1] != "10.0.2.16" || err != nil || nonce < 0 || nonce > 999998 || strings.Contains(value, "=") {
		t.Fatal("native logid does not match the APK timestamp/IP/random format")
	}
	if _, err := refreshAndroidLogID("not-a-captured-logid", 1); err == nil {
		t.Fatal("logid refresh invented an IP for invalid capture")
	}
}

func TestAndroidAppFinishRejectsNativeCookieMismatch(t *testing.T) {
	response := &PassportResponse{Data: json.RawMessage(`{"ndus":"json-session","userid":"9007199254740993"}`)}
	if _, _, err := androidFinishIdentity(response, "cookie-session"); err == nil {
		t.Fatal("native account and cookie sessions were combined")
	}
	ndus, uid, err := androidFinishIdentity(response, "")
	if err != nil || ndus != "json-session" || uid != "9007199254740993" {
		t.Fatal("native JSON identity or precision was lost")
	}
	response.Data = json.RawMessage(`{"ndus":"json-session","uk":123}`)
	if _, _, err := androidFinishIdentity(response, ""); err == nil {
		t.Fatal("Web UK was inferred as the Android UID")
	}
}

func TestAndroidAppPSignUsesNativePubkeyAndFallback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		profile := androidFixtureProfile()
		profile.PSign = ""
		calls := 0
		client, _ := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.Method != http.MethodPost || req.URL.Path != "/passport/getpubkey" {
				t.Fatal("native psign used a Web prerequisite")
			}
			_ = req.ParseForm()
			if req.PostForm.Get("client") != "android" || req.PostForm.Get("pass_version") != "2.0" {
				t.Fatal("native psign bootstrap did not use its 2.0 passport family")
			}
			if fail {
				return shareJSONResponse(req, `{"code":19}`), nil
			}
			return shareJSONResponse(req, `{"code":0,"data":{"pp3":"fixture-native-pp3"}}`), nil
		})}))
		if err := client.resolveAndroidPSign(context.Background()); err != nil {
			t.Fatal(err)
		}
		pp3 := "fixture-native-pp3"
		if fail {
			pp3 = "dubox"
		}
		if client.AndroidAppProfile().PSign != androidPSign(profile.DeviceID, pp3) || calls != 1 {
			t.Fatal("native psign hash/fallback changed")
		}
	}
}

func TestAndroidAppRefreshConfigKeepsRegisteredAccount(t *testing.T) {
	profile := androidFixtureProfile()
	profile.UID = "12345"
	profile.ReportParams = map[string]string{"action": "ANDROID_ACTIVE_FRONTDESK", "needrookie": "1",
		"fcm_token": "fixture-fcm", "start_source": "frontdesk", "push_on": "1", "backup_on ": "00"}
	profile.LegacyNativeParams = map[string]string{"app_id": "250528", "app_name": "fixture-native-name"}
	secret := []byte("updated-fixture-secret")
	cipher, _ := rc4.NewCipher([]byte(profile.UID))
	ciphertext := make([]byte, len(secret))
	cipher.XORKeyStream(ciphertext, secret)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	goodBody, _ := json.Marshal(map[string]any{"errno": 0, "uinfo": encoded})
	for _, body := range []string{string(goodBody), `{"errno":9,"errmsg":"not available"}`, `{"errno":0,"uinfo":""}`, `{"errno":0,"uinfo":"bad-base64"}`, `{"code":0,"uinfo":"ignored"}`, `{"errno":0,"data":{"uinfo":"ignored"}}`} {
		t.Run(body, func(t *testing.T) {
			requests := 0
			client, err := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				query := req.URL.Query()
				if req.Method != http.MethodGet || req.URL.Path != "/api/report/user" || query.Get("timestamp") != "1791680000123" ||
					query.Get("action") != "ANDROID_ACTIVE_FRONTDESK" || query.Get("backup_on ") != "00" || query.Get("app_name") != "fixture-native-name" ||
					query.Get("bdstoken") != fmt.Sprintf("%x", md5.Sum([]byte("fixture-session"))) || query.Has("rand") {
					t.Fatalf("not the legacy native ReportUser request: %s %s", req.Method, req.URL)
				}
				return shareJSONResponse(req, body), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			client.androidApp.now = func() time.Time { return time.UnixMilli(1791680000123) }
			client.registrationFinished, client.registrationConfirmed = true, true
			err = client.RefreshAndroidAppConfig(context.Background())
			if body == string(goodBody) {
				if err != nil || client.AndroidAppProfile().EncodedSK != encoded {
					t.Fatalf("native config not retained: %v", err)
				}
				request, _ := http.NewRequest(http.MethodGet, "https://www.terabox.com/share/list", nil)
				request.AddCookie(&http.Cookie{Name: "ndus", Value: "fixture-session"})
				signed, err := client.androidAppAPIRequest(request)
				if err != nil || len(signed.URL.Query().Get("rand")) != 40 {
					t.Fatalf("configured account did not use native signing: %v", err)
				}
			} else if err == nil || client.AndroidAppProfile().EncodedSK != "" {
				t.Fatal("invalid configuration response was accepted")
			}
			if requests != 1 || client.cookies["ndus"] != "fixture-session" || !client.registrationFinished || !client.registrationConfirmed || client.AndroidAppProfile().UID != profile.UID {
				t.Fatal("config refresh discarded or repeated registration")
			}
		})
	}
	client, _ := NewAndroidAppClient(androidFixtureProfile())
	if err := client.RefreshAndroidAppConfig(context.Background()); err == nil {
		t.Fatal("guest refreshed another account's config")
	}
}
