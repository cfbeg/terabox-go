package terabox

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const referralTestURL = "https://terabox.com/s/1Ab_c-key?pwd=1234"

type referralTestWire struct {
	t             *testing.T
	key           *rsa.PrivateKey
	publicKeyJSON string
	prepared      bool
	source        string
	fallback      bool
	metadata      string
	sendBody      string
	verifyBody    string
	finishBody    string
	finishNDUS    string
	finishError   error
	loginBody     string
	expectedNDUS  string
	refreshNDUS   string
	transferBody  string
	transferError error
	refreshError  error
	paths         []string
}

func referralTestNewWire(t *testing.T) *referralTestWire {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	pad := aes.BlockSize - len(publicKey)%aes.BlockSize
	plain := append(publicKey, []byte(strings.Repeat(string(byte(pad)), pad))...)
	secret := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")
	block, err := aes.NewCipher(secret)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	publicJSON, err := json.Marshal(map[string]any{
		"code": 0,
		"data": map[string]string{
			"pp1": string(iv) + base64.StdEncoding.EncodeToString(encrypted),
			"pp2": string(secret),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &referralTestWire{
		t: t, key: key, publicKeyJSON: string(publicJSON),
		metadata:     `{"errno":0,"shareid":101,"uk":202,"list":[{"fs_id":303,"path":"/shared.txt"}]}`,
		sendBody:     `{"code":0,"token":"registration-token","data":null}`,
		verifyBody:   `{"code":0,"data":null}`,
		finishBody:   `{"code":0,"data":null}`,
		finishNDUS:   "registered-session",
		expectedNDUS: "registered-session",
		loginBody:    `{"errno":0,"uk":404}`,
		transferBody: `{"errno":0,"task_id":1}`,
	}
}

func (w *referralTestWire) client() *Client {
	return NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(w.roundTrip)}))
}

func (w *referralTestWire) count(path string) int {
	count := 0
	for _, got := range w.paths {
		if got == path {
			count++
		}
	}
	return count
}

func (w *referralTestWire) roundTrip(req *http.Request) (*http.Response, error) {
	w.paths = append(w.paths, req.URL.Path)
	if err := req.ParseForm(); err != nil {
		return nil, err
	}
	for _, localField := range []string{"share_from_surl", "webmaster_uk"} {
		if req.PostForm.Has(localField) || req.URL.Query().Has(localField) {
			w.t.Errorf("local attribution field %s leaked onto %s", localField, req.URL.Path)
		}
		if _, err := req.Cookie(localField); err == nil {
			w.t.Errorf("local attribution field %s was invented as a cookie", localField)
		}
	}
	checkAnonymous := func() {
		if _, err := req.Cookie("ndus"); err == nil {
			w.t.Errorf("anonymous request %s carried an authenticated cookie", req.URL.Path)
		}
		if w.prepared && req.URL.Path != "/api/shorturlinfo" {
			cookie, err := req.Cookie("server_referral")
			if err != nil || cookie.Value != "issued-by-share" {
				w.t.Errorf("server-issued referral cookie lost on %s: %s", req.URL.Path, req.Header.Get("Cookie"))
			}
		}
	}
	checkAuthenticated := func() {
		for name, want := range map[string]string{"ndus": w.expectedNDUS, "server_referral": "issued-by-share", "browserid": "browser-session", "finish_state": "issued-by-finish"} {
			cookie, err := req.Cookie(name)
			if err != nil || cookie.Value != want {
				w.t.Errorf("authenticated request %s lost %s: %s", req.URL.Path, name, req.Header.Get("Cookie"))
			}
		}
	}
	checkRegistration := func(sourceFields bool) {
		checkAnonymous()
		wantReferer := "https://www.terabox.com"
		if w.prepared {
			wantReferer = referralTestURL
		}
		if req.Header.Get("Referer") != wantReferer {
			w.t.Errorf("Referer on %s = %q, want %q", req.URL.Path, req.Header.Get("Referer"), wantReferer)
		}
		if req.PostForm.Get("pcftoken") != "passport-session" {
			w.t.Errorf("passport session token missing on %s: %v", req.URL.Path, req.PostForm)
		}
		if w.prepared && sourceFields {
			wantSource := w.source
			if wantSource == "" || req.URL.Path == "/passport/register_v4/sendcode" {
				wantSource = "share"
			}
			if req.PostForm.Get("reg_source") != wantSource || req.URL.Query().Get("reg_source") != wantSource || req.PostForm.Get("first_referer") != "terabox.com" {
				w.t.Errorf("registration source fields wrong on %s: query=%v body=%v", req.URL.Path, req.URL.Query(), req.PostForm)
			}
			if req.URL.Path == "/passport/register_v4/sendcode" {
				wantKoltype := "0"
				if w.source == "web_share" {
					wantKoltype = "1"
				}
				if req.PostForm.Get("koltype") != wantKoltype || req.URL.Query().Get("koltype") != wantKoltype {
					w.t.Errorf("sendcode koltype = query %q form %q, want %q", req.URL.Query().Get("koltype"), req.PostForm.Get("koltype"), wantKoltype)
				}
			} else if req.PostForm.Has("koltype") || req.URL.Query().Has("koltype") {
				w.t.Error("finish unexpectedly carried the sendcode-only koltype")
			}
		} else if req.PostForm.Has("reg_source") || req.URL.Query().Has("reg_source") || req.PostForm.Has("first_referer") || req.URL.Query().Has("first_referer") || req.PostForm.Has("koltype") || req.URL.Query().Has("koltype") {
			w.t.Errorf("unexpected registration source fields on %s: query=%v body=%v", req.URL.Path, req.URL.Query(), req.PostForm)
		}
		if req.URL.Query().Has("first_referer") {
			w.t.Errorf("first_referer must remain a form field on %s", req.URL.Path)
		}
	}

	switch req.URL.Path {
	case "/api/shorturlinfo":
		checkAnonymous()
		if req.URL.Query().Get("shorturl") != "1Ab_c-key" {
			w.t.Errorf("shorturlinfo did not add exactly one leading 1: %v", req.URL.Query())
		}
		body := w.metadata
		if w.fallback {
			body = `{"errno":400210}`
		}
		response := authTestJSON(req, body)
		response.Header.Add("Set-Cookie", "server_referral=issued-by-share; Secure; Path=/")
		return response, nil
	case "/share/list":
		checkAnonymous()
		if req.URL.Query().Get("shorturl") != "Ab_c-key" {
			w.t.Errorf("share/list received an unnormalized key: %v", req.URL.Query())
		}
		return authTestJSON(req, w.metadata), nil
	case "/wap/outlogin/emailRegister":
		checkAnonymous()
		response := authTestJSON(req, `<script>var templateData = {"pcftoken":"passport-session"};</script>`)
		response.Header.Add("Set-Cookie", "browserid=browser-session; Secure; Path=/")
		return response, nil
	case "/passport/register_v4/sendcode":
		checkRegistration(true)
		if req.PostForm.Get("email") != "new@example.invalid" {
			w.t.Errorf("registration email lost: %v", req.PostForm)
		}
		return authTestJSON(req, w.sendBody), nil
	case "/passport/register_v4/verify":
		checkRegistration(false)
		if req.PostForm.Get("token") != "registration-token" || req.PostForm.Get("code") != "123456" {
			w.t.Errorf("verification payload changed: %v", req.PostForm)
		}
		return authTestJSON(req, w.verifyBody), nil
	case "/passport/getpubkey":
		if req.Header.Get("Cookie") != "" {
			w.t.Error("public key request received session cookies")
		}
		return authTestJSON(req, w.publicKeyJSON), nil
	case "/passport/register_v4/finish":
		checkRegistration(true)
		if req.PostForm.Get("token") != "registration-token" {
			w.t.Errorf("registration token lost: %v", req.PostForm)
		}
		encrypted, err := base64.URLEncoding.DecodeString(req.PostForm.Get("pwd"))
		if err != nil {
			return nil, err
		}
		password, err := rsa.DecryptPKCS1v15(rand.Reader, w.key, encrypted)
		if err != nil {
			return nil, err
		}
		if string(password) != "e99a18c428cb38d5f260853678922e0332" {
			w.t.Errorf("registration password encryption changed: %q", password)
		}
		if w.finishError != nil {
			return nil, w.finishError
		}
		response := authTestJSON(req, w.finishBody)
		if w.finishNDUS != "" {
			response.Header.Add("Set-Cookie", "ndus="+w.finishNDUS+"; Secure; Path=/; HttpOnly")
		}
		response.Header.Add("Set-Cookie", "finish_state=issued-by-finish; Secure; Path=/")
		return response, nil
	case "/main":
		checkAuthenticated()
		if w.refreshError != nil {
			return nil, w.refreshError
		}
		response := authTestJSON(req, `<script>var templateData = {"jsToken":"authenticated-js","bdstoken":"authenticated-bds","uk":404};</script>`)
		if w.refreshNDUS != "" {
			response.Header.Add("Set-Cookie", "ndus="+w.refreshNDUS+"; Secure; Path=/; HttpOnly")
			w.expectedNDUS = w.refreshNDUS
		}
		return response, nil
	case "/api/check/login":
		checkAuthenticated()
		return authTestJSON(req, w.loginBody), nil
	case "/share/transfer":
		checkAuthenticated()
		query := req.URL.Query()
		if query.Get("shareid") != "101" || query.Get("from") != "202" || query.Get("jsToken") != "authenticated-js" || query.Get("bdstoken") != "authenticated-bds" {
			w.t.Errorf("transfer metadata/session lost: %v", query)
		}
		if req.PostForm.Get("fsidlist") != "[303]" || req.PostForm.Get("path") != "/destination" {
			w.t.Errorf("transfer selection changed: %v", req.PostForm)
		}
		if w.transferError != nil {
			return nil, w.transferError
		}
		return authTestJSON(req, w.transferBody), nil
	default:
		w.t.Errorf("unexpected referral request: %s", req.URL)
		return nil, errors.New("unexpected referral request")
	}
}

func referralTestPrepareAndSend(t *testing.T, w *referralTestWire, client *Client) string {
	t.Helper()
	w.prepared = true
	ref, err := client.PrepareWebmasterReferral(context.Background(), referralTestURL)
	if err != nil || ref == nil || ref.ShareFromSURL != "Ab_c-key" || ref.WebmasterUK != 202 || ref.ShareID != 101 {
		t.Fatalf("prepare result=%+v error=%v", ref, err)
	}
	sent, err := client.RegisterSendCode(context.Background(), "new@example.invalid")
	if err != nil || sent == nil || sent.Code != 0 || sent.Token != "registration-token" {
		t.Fatalf("sendcode result=%+v error=%v", sent, err)
	}
	return sent.Token
}

func referralTestOptions() *WebmasterTransferOptions {
	return &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/destination", OnDup: "newcopy"}
}

func TestWebmasterReferralRegistrationFlow(t *testing.T) {
	for _, test := range []struct {
		name     string
		metadata string
		fallback bool
	}{
		{"numeric identifiers", `{"errno":0,"shareid":101,"uk":202,"list":[{"fs_id":303}]}`, false},
		{"string identifiers", `{"errno":0,"share_id":"101","uk":"202","list":[{"fs_id":303}]}`, false},
		{"fallback with owner string", `{"errno":0,"shareid":"101","uk_str":"202","list":[{"fs_id":303}]}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := referralTestNewWire(t)
			wire.metadata, wire.fallback = test.metadata, test.fallback
			client := wire.client()
			token := referralTestPrepareAndSend(t, wire, client)
			verified, err := client.RegisterVerify(context.Background(), token, "123456")
			if err != nil || verified == nil || verified.Code != 0 {
				t.Fatalf("verification result=%+v error=%v", verified, err)
			}
			result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
			if err != nil || result == nil || result.Registration == nil || result.Registration.NDUS != "registered-session" || result.Transfer == nil || result.Transfer.Errno != 0 || result.Transfer.TaskID != 1 {
				t.Fatalf("registration/transfer result=%+v error=%v", result, err)
			}
			if result.Session == nil || result.Session.NDUS != "registered-session" || result.Session.Referral.WebmasterUK != 202 {
				t.Fatalf("authenticated recovery session lost: %+v", result.Session)
			}
			wantPaths := []string{"/api/shorturlinfo"}
			if test.fallback {
				wantPaths = append(wantPaths, "/share/list")
			}
			wantPaths = append(wantPaths, "/wap/outlogin/emailRegister", "/passport/register_v4/sendcode", "/passport/register_v4/verify", "/passport/getpubkey", "/passport/register_v4/finish", "/main", "/share/transfer")
			if !reflect.DeepEqual(wire.paths, wantPaths) {
				t.Errorf("request order=%v, want %v", wire.paths, wantPaths)
			}
			if _, err := client.RegisterFinish(context.Background(), token, "abc123"); err == nil {
				t.Error("registration was allowed to finish twice after creating the account")
			}
			if wire.count("/passport/register_v4/finish") != 1 {
				t.Error("repeated finish sent a second account-creation request")
			}
		})
	}
}

func TestWebmasterReferralRegistrationSaveAndRestoreBeforeVerify(t *testing.T) {
	wire := referralTestNewWire(t)
	client := wire.client()
	token := referralTestPrepareAndSend(t, wire, client)
	saved := client.WebmasterRegistrationSession()
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	var restored WebmasterRegistrationSession
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	client = wire.client()
	if err := client.RestoreWebmasterRegistrationSession(&restored); err != nil {
		t.Fatal(err)
	}
	verified, err := client.RegisterVerify(context.Background(), token, "123456")
	if err != nil || verified.Code != 0 {
		t.Fatalf("restored verify=%+v error=%v", verified, err)
	}
	result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
	if err != nil || result == nil || result.Session == nil || result.Session.NDUS != "registered-session" || result.Transfer == nil {
		t.Fatalf("restored registration result=%+v error=%v", result, err)
	}
	if wire.count("/passport/register_v4/sendcode") != 1 {
		t.Fatal("resume sent the email verification code again")
	}
	data, err = json.Marshal(result.Session)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "abc123") || strings.Contains(string(data), "123456") {
		t.Errorf("session serialized the password or verification code: %s", data)
	}
}

func TestWebmasterReferralTransferFailuresKeepRegisteredAccount(t *testing.T) {
	transportFailure := errors.New("transfer connection interrupted")
	for _, kind := range []string{"API", "transport", "token refresh"} {
		t.Run(kind, func(t *testing.T) {
			wire := referralTestNewWire(t)
			switch kind {
			case "API":
				wire.transferBody = `{"errno":12,"errmsg":"transfer denied"}`
			case "transport":
				wire.transferError = transportFailure
			case "token refresh":
				wire.refreshError = transportFailure
			}
			client := wire.client()
			token := referralTestPrepareAndSend(t, wire, client)
			result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
			if err == nil || result == nil || result.Registration == nil || result.Registration.NDUS != "registered-session" || result.Session == nil || result.Session.NDUS != "registered-session" {
				t.Fatalf("registered account lost after %s failure: result=%+v error=%v", kind, result, err)
			}
			if kind == "API" {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Code != 12 || result.Transfer == nil || result.Transfer.Errno != 12 {
					t.Fatalf("transfer API failure lost: result=%+v error=%v", result, err)
				}
			} else if !errors.Is(err, transportFailure) {
				t.Errorf("transport cause was lost: %v", err)
			}
			data, err := json.Marshal(result.Session)
			if err != nil {
				t.Fatal(err)
			}
			var saved WebmasterRegistrationSession
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			wire.transferBody = `{"errno":0,"task_id":1}`
			wire.transferError, wire.refreshError = nil, nil
			resumed := wire.client()
			if err := resumed.RestoreWebmasterRegistrationSession(&saved); err != nil {
				t.Fatal(err)
			}
			transferred, err := resumed.TransferWebmasterReferral(context.Background(), referralTestOptions())
			if err != nil || transferred == nil || transferred.TaskID != 1 {
				t.Fatalf("transfer-only resume failed: response=%+v error=%v", transferred, err)
			}
			if wire.count("/passport/register_v4/finish") != 1 || wire.count("/passport/register_v4/sendcode") != 1 {
				t.Error("transfer retry repeated registration")
			}
		})
	}
}

func TestWebmasterReferralRejectsInvalidTransferOptionsBeforeRegistration(t *testing.T) {
	wire := referralTestNewWire(t)
	client := wire.client()
	token := referralTestPrepareAndSend(t, wire, client)
	for _, test := range []struct {
		name string
		opts *WebmasterTransferOptions
	}{
		{"nil", nil},
		{"no files", &WebmasterTransferOptions{Destination: "/destination"}},
		{"invalid file", &WebmasterTransferOptions{FSIDs: []int64{0}, Destination: "/destination"}},
		{"relative destination", &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "destination"}},
		{"parent path", &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/a/../destination"}},
		{"dot path", &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/./destination"}},
		{"backslash", &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/a\\destination"}},
		{"CRLF", &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/destination\r\n"}},
		{"invalid duplicate policy", &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/destination", OnDup: "fail"}},
		{"unverified skip policy", &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/destination", OnDup: "skip"}},
		{"unverified overwrite policy", &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/destination", OnDup: "overwrite"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := len(wire.paths)
			result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", test.opts)
			if err == nil || result != nil || len(wire.paths) != before {
				t.Fatalf("invalid options reached registration: result=%+v error=%v requests=%v", result, err, wire.paths[before:])
			}
		})
	}
}

func TestWebmasterReferralCannotChangeAfterRegistrationStarts(t *testing.T) {
	wire := referralTestNewWire(t)
	client := wire.client()
	referralTestPrepareAndSend(t, wire, client)
	before := len(wire.paths)
	if _, err := client.PrepareWebmasterReferral(context.Background(), "https://terabox.com/s/1another"); err == nil {
		t.Fatal("changing the prepared link after sendcode succeeded")
	}
	if len(wire.paths) != before || client.WebmasterReferral().ShareURL != referralTestURL {
		t.Fatal("rejected referral replacement changed state or made a request")
	}
	if _, err := client.RegisterVerify(context.Background(), "different-token", "123456"); err == nil {
		t.Fatal("verification accepted an unrelated registration token")
	}
	if _, err := client.RegisterFinishWithReferral(context.Background(), "different-token", "abc123", referralTestOptions()); err == nil {
		t.Fatal("registration accepted an unrelated token")
	}
	if len(wire.paths) != before {
		t.Fatal("token mismatch reached the server")
	}
}

func TestRegistrationWithoutReferralKeepsExistingWireContract(t *testing.T) {
	wire := referralTestNewWire(t)
	client := wire.client()
	sent, err := client.RegisterSendCode(context.Background(), "new@example.invalid")
	if err != nil || sent.Token != "registration-token" {
		t.Fatalf("plain sendcode=%+v error=%v", sent, err)
	}
	if _, err := client.RegisterVerify(context.Background(), sent.Token, "123456"); err != nil {
		t.Fatal(err)
	}
	finished, err := client.RegisterFinish(context.Background(), sent.Token, "abc123")
	if err != nil || finished.NDUS != "registered-session" {
		t.Fatalf("plain finish=%+v error=%v", finished, err)
	}
	if client.WebmasterReferral() != nil || client.WebmasterRegistrationSession() != nil || wire.count("/share/transfer") != 0 {
		t.Fatal("plain registration unexpectedly started a referral flow")
	}
	if ndus, _ := client.CookieValue("ndus"); ndus != "" {
		t.Error("plain RegisterFinish changed the documented session-return contract")
	}
}

func TestWebmasterReferralRegistrationFailureDoesNotTransfer(t *testing.T) {
	for _, kind := range []string{"API", "missing NDUS"} {
		t.Run(kind, func(t *testing.T) {
			wire := referralTestNewWire(t)
			wire.finishNDUS = ""
			if kind == "API" {
				wire.finishBody = `{"code":11,"msg":"already registered"}`
			}
			client := wire.client()
			token := referralTestPrepareAndSend(t, wire, client)
			result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
			if err == nil || result == nil || result.Registration == nil || result.Session == nil || result.Transfer != nil {
				t.Fatalf("registration failure result=%+v error=%v", result, err)
			}
			if kind == "API" {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Code != 11 {
					t.Errorf("registration API error lost: %v", err)
				}
			}
			if wire.count("/main") != 0 || wire.count("/share/transfer") != 0 {
				t.Error("registration failure proceeded to authenticated transfer")
			}
		})
	}
}

func TestWebmasterReferralRequiresPreparation(t *testing.T) {
	wire := referralTestNewWire(t)
	client := wire.client()
	if result, err := client.RegisterFinishWithReferral(context.Background(), "token", "abc123", referralTestOptions()); err == nil || result != nil {
		t.Fatalf("unprepared finish result=%+v error=%v", result, err)
	}
	if result, err := client.TransferWebmasterReferral(context.Background(), referralTestOptions()); err == nil || result != nil {
		t.Fatalf("unprepared transfer result=%+v error=%v", result, err)
	}
	if len(wire.paths) != 0 {
		t.Fatal("unprepared referral flow made a request")
	}
}

func TestWebmasterReferralUnknownRegistrationKeepsSessionAndChecksBeforeTransfer(t *testing.T) {
	wire := referralTestNewWire(t)
	wire.finishBody = `{"code":`
	client := wire.client()
	token := referralTestPrepareAndSend(t, wire, client)
	result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
	if err == nil || result == nil || result.Registration == nil || result.Registration.NDUS != "registered-session" || result.Session == nil || result.Session.NDUS != "registered-session" || result.Session.RegistrationConfirmed {
		t.Fatalf("unknown registration discarded the acquired session or claimed success: result=%+v error=%v", result, err)
	}
	if result.Registration.Code == 0 || result.Transfer != nil || wire.count("/share/transfer") != 0 {
		t.Fatal("malformed finish response was treated as registration success")
	}
	before := len(wire.paths)
	if _, err := client.RegisterFinish(context.Background(), token, "abc123"); err == nil {
		t.Fatal("unknown registration resent account creation")
	}
	if len(wire.paths) != before {
		t.Fatal("account creation was repeated while the outcome was unknown")
	}
	data, err := json.Marshal(result.Session)
	if err != nil {
		t.Fatal(err)
	}
	var saved WebmasterRegistrationSession
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	resumed := wire.client()
	if err := resumed.RestoreWebmasterRegistrationSession(&saved); err != nil {
		t.Fatal(err)
	}
	transferred, err := resumed.TransferWebmasterReferral(context.Background(), referralTestOptions())
	if err != nil || transferred == nil || transferred.TaskID != 1 {
		t.Fatalf("unknown outcome could not recover by checking login: response=%+v error=%v", transferred, err)
	}
	if wire.count("/api/check/login") != 1 || wire.count("/passport/register_v4/finish") != 1 {
		t.Fatalf("unknown outcome recovery requests=%v", wire.paths)
	}
	if !resumed.WebmasterRegistrationSession().RegistrationConfirmed {
		t.Fatal("authenticated recovery did not confirm the preserved account")
	}
}

func TestWebmasterReferralSessionRestoreRejectsInvalidSnapshots(t *testing.T) {
	wire := referralTestNewWire(t)
	client := wire.client()
	referralTestPrepareAndSend(t, wire, client)
	original := client.WebmasterRegistrationSession()
	for _, test := range []struct {
		name   string
		change func(*WebmasterRegistrationSession)
	}{
		{"mismatched URL key", func(saved *WebmasterRegistrationSession) { saved.Referral.ShareFromSURL = "different" }},
		{"missing owner", func(saved *WebmasterRegistrationSession) { saved.Referral.WebmasterUK = 0 }},
		{"missing share", func(saved *WebmasterRegistrationSession) { saved.Referral.ShareID = 0 }},
		{"untrusted origin", func(saved *WebmasterRegistrationSession) { saved.WebHost = "https://example.invalid" }},
		{"host path", func(saved *WebmasterRegistrationSession) { saved.WebHost = "https://www.terabox.com/path" }},
		{"mismatched auth cookie", func(saved *WebmasterRegistrationSession) { saved.NDUS = "not-in-cookies" }},
		{"invalid registration source", func(saved *WebmasterRegistrationSession) { saved.Referral.Source = "unverified-source" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			saved := *original
			test.change(&saved)
			fresh := wire.client()
			before := fresh.CookieString()
			if err := fresh.RestoreWebmasterRegistrationSession(&saved); err == nil {
				t.Fatal("invalid snapshot restored successfully")
			}
			if fresh.WebmasterReferral() != nil || fresh.CookieString() != before {
				t.Fatal("failed restore modified the client")
			}
		})
	}
	if err := client.RestoreWebmasterRegistrationSession(original); err == nil {
		t.Fatal("restore overwrote an active referral registration")
	}
}

func TestWebmasterReferralSendCodeCannotProceedWithoutRegistrationToken(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"missing token", `{"code":0,"data":null}`, true},
		{"existing email", `{"code":11,"msg":"already registered"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := referralTestNewWire(t)
			wire.prepared, wire.sendBody = true, test.body
			client := wire.client()
			if _, err := client.PrepareWebmasterReferral(context.Background(), referralTestURL); err != nil {
				t.Fatal(err)
			}
			sent, err := client.RegisterSendCode(context.Background(), "new@example.invalid")
			if (err != nil) != test.wantErr || sent == nil || sent.Token != "" {
				t.Fatalf("sendcode response=%+v error=%v", sent, err)
			}
			if !test.wantErr && sent.Code != 11 {
				t.Error("existing-email API code was not preserved")
			}
			before := len(wire.paths)
			if _, err := client.RegisterFinishWithReferral(context.Background(), "unissued-token", "abc123", referralTestOptions()); err == nil {
				t.Error("registration continued after unsuccessful token acquisition")
			}
			if len(wire.paths) != before || client.WebmasterRegistrationSession().NDUS != "" {
				t.Error("token acquisition failure proceeded to create an account")
			}
		})
	}
}

func TestWebmasterReferralUnknownRegistrationRequiresSuccessfulAccountCheck(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{"API error", `{"errno":-6,"show_msg":"not logged in"}`},
		{"missing account ID", `{"errno":0}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := referralTestNewWire(t)
			wire.finishBody, wire.loginBody = `{"code":`, test.body
			client := wire.client()
			token := referralTestPrepareAndSend(t, wire, client)
			result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
			if err == nil || result == nil || result.Session == nil || result.Session.NDUS != "registered-session" {
				t.Fatalf("unknown registration did not preserve its session: result=%+v error=%v", result, err)
			}
			transfer, err := client.TransferWebmasterReferral(context.Background(), referralTestOptions())
			if err == nil || transfer != nil || client.WebmasterRegistrationSession().RegistrationConfirmed {
				t.Fatalf("failed account check permitted transfer: response=%+v error=%v", transfer, err)
			}
			if wire.count("/share/transfer") != 0 || wire.count("/main") != 0 || wire.count("/passport/register_v4/finish") != 1 {
				t.Errorf("failed account check proceeded to transfer or repeated registration: %v", wire.paths)
			}
		})
	}
}

func TestWebmasterReferralEmptyFinishResponseRequiresAccountCheck(t *testing.T) {
	for _, body := range []string{`{}`, `null`} {
		t.Run(body, func(t *testing.T) {
			wire := referralTestNewWire(t)
			wire.finishBody = body
			client := wire.client()
			token := referralTestPrepareAndSend(t, wire, client)
			result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
			if err == nil || result == nil || result.Registration == nil || result.Registration.Code == 0 || result.Registration.NDUS != "registered-session" || result.Session == nil || result.Session.RegistrationConfirmed {
				t.Fatalf("empty finish body claimed confirmed success: result=%+v error=%v", result, err)
			}
			if wire.count("/share/transfer") != 0 || wire.count("/main") != 0 {
				t.Error("empty finish body proceeded directly to authenticated transfer")
			}
			transferred, err := client.TransferWebmasterReferral(context.Background(), referralTestOptions())
			if err != nil || transferred == nil || transferred.TaskID != 1 || wire.count("/api/check/login") != 1 {
				t.Fatalf("empty finish body recovery skipped account verification: response=%+v error=%v requests=%v", transferred, err, wire.paths)
			}
		})
	}
}

func TestWebmasterReferralSessionTracksRotatedAuthenticationCookie(t *testing.T) {
	wire := referralTestNewWire(t)
	wire.refreshNDUS = "refreshed-session"
	wire.transferBody = `{"errno":12,"errmsg":"transfer denied"}`
	client := wire.client()
	token := referralTestPrepareAndSend(t, wire, client)
	result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
	if err == nil || result == nil || result.Session == nil || result.Session.NDUS != "refreshed-session" || result.Registration == nil || result.Registration.NDUS != "registered-session" {
		t.Fatalf("rotated session was lost after transfer failure: result=%+v error=%v", result, err)
	}
	current := NewClient("", WithCookies(result.Session.Cookies))
	if cookie, _ := current.CookieValue("ndus"); cookie != result.Session.NDUS {
		t.Errorf("snapshot token %q disagrees with its cookie %q", result.Session.NDUS, cookie)
	}
	data, err := json.Marshal(result.Session)
	if err != nil {
		t.Fatal(err)
	}
	var saved WebmasterRegistrationSession
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	resumed := wire.client()
	if err := resumed.RestoreWebmasterRegistrationSession(&saved); err != nil {
		t.Fatalf("rotated session could not be restored: %v", err)
	}
	wire.transferBody = `{"errno":0,"task_id":1}`
	transfer, err := resumed.TransferWebmasterReferral(context.Background(), referralTestOptions())
	if err != nil || transfer == nil || transfer.TaskID != 1 || wire.count("/passport/register_v4/finish") != 1 {
		t.Fatalf("rotated session transfer-only retry=%+v error=%v requests=%v", transfer, err, wire.paths)
	}
}

func TestWebmasterReferralUnknownFinishWithoutNDUSCannotRepeatRegistration(t *testing.T) {
	for _, kind := range []string{"successful response without NDUS", "malformed response", "transport failure"} {
		t.Run(kind, func(t *testing.T) {
			wire := referralTestNewWire(t)
			wire.finishNDUS = ""
			switch kind {
			case "malformed response":
				wire.finishBody = `{"code":`
			case "transport failure":
				wire.finishError = errors.New("connection lost after submitting registration")
			}
			client := wire.client()
			token := referralTestPrepareAndSend(t, wire, client)
			result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
			if err == nil || result == nil || result.Session == nil || result.Session.NDUS != "" || result.Session.RegistrationConfirmed || result.Transfer != nil {
				t.Fatalf("unconfirmed account creation outcome=%+v error=%v", result, err)
			}
			data, err := json.Marshal(result.Session)
			if err != nil {
				t.Fatal(err)
			}
			var saved WebmasterRegistrationSession
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			resumed := wire.client()
			if err := resumed.RestoreWebmasterRegistrationSession(&saved); err != nil {
				t.Fatal(err)
			}
			before := len(wire.paths)
			for _, flow := range []*Client{client, resumed} {
				if _, err := flow.RegisterFinish(context.Background(), token, "abc123"); err == nil {
					t.Error("uncertain account creation was repeated")
				}
				if _, err := flow.RegisterSendCode(context.Background(), "new@example.invalid"); err == nil {
					t.Error("email code was resent after uncertain account creation")
				}
			}
			if len(wire.paths) != before || wire.count("/passport/register_v4/finish") != 1 || wire.count("/share/transfer") != 0 {
				t.Errorf("uncertain outcome repeated registration or transferred: %v", wire.paths)
			}
		})
	}
}

func TestWebmasterReferralDialogSourcesSurviveRegistrationAndRestore(t *testing.T) {
	for _, test := range []struct {
		name    string
		source  string
		restore bool
	}{
		{"empty source defaults to share", "", false},
		{"webmaster dialog", "web_share", true},
		{"video dialog", "web_share_videoplay", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := referralTestNewWire(t)
			wire.prepared, wire.source = true, test.source
			client := wire.client()
			ref, err := client.PrepareWebmasterReferralWithOptions(context.Background(), referralTestURL, &WebmasterReferralOptions{Source: test.source})
			wantSource := test.source
			if wantSource == "" {
				wantSource = "share"
			}
			if err != nil || ref == nil || ref.Source != wantSource {
				t.Fatalf("prepared source = %+v, error = %v, want %q", ref, err, wantSource)
			}
			sent, err := client.RegisterSendCode(context.Background(), "new@example.invalid")
			if err != nil || sent == nil || sent.Token != "registration-token" {
				t.Fatalf("source-specific sendcode=%+v error=%v", sent, err)
			}
			if test.restore {
				data, err := json.Marshal(client.WebmasterRegistrationSession())
				if err != nil {
					t.Fatal(err)
				}
				var saved WebmasterRegistrationSession
				if err := json.Unmarshal(data, &saved); err != nil {
					t.Fatal(err)
				}
				if saved.Referral.Source != wantSource {
					t.Fatalf("dialog source lost in JSON session: %+v", saved.Referral)
				}
				client = wire.client()
				if err := client.RestoreWebmasterRegistrationSession(&saved); err != nil {
					t.Fatal(err)
				}
			}
			verified, err := client.RegisterVerify(context.Background(), sent.Token, "123456")
			if err != nil || verified == nil || verified.Code != 0 {
				t.Fatalf("source-specific verify=%+v error=%v", verified, err)
			}
			result, err := client.RegisterFinishWithReferral(context.Background(), sent.Token, "abc123", referralTestOptions())
			if err != nil || result == nil || result.Transfer == nil || result.Transfer.TaskID != 1 || result.Session == nil || result.Session.Referral.Source != wantSource {
				t.Fatalf("source-specific finish/transfer=%+v error=%v", result, err)
			}
			if wire.count("/passport/register_v4/sendcode") != 1 || wire.count("/passport/register_v4/finish") != 1 {
				t.Errorf("dialog-source flow repeated a registration step: %v", wire.paths)
			}
		})
	}
}

func TestWebmasterReferralRejectsUnknownSourceBeforeRequest(t *testing.T) {
	wire := referralTestNewWire(t)
	client := wire.client()
	ref, err := client.PrepareWebmasterReferralWithOptions(context.Background(), referralTestURL, &WebmasterReferralOptions{Source: "unverified-source"})
	if err == nil || ref != nil || len(wire.paths) != 0 || client.WebmasterReferral() != nil {
		t.Fatalf("invalid source changed state or made a request: referral=%+v error=%v requests=%v", ref, err, wire.paths)
	}
}

func TestWebmasterReferralRequiresExplicitPassportResultCodes(t *testing.T) {
	t.Run("sendcode with token but no code", func(t *testing.T) {
		wire := referralTestNewWire(t)
		wire.prepared, wire.sendBody = true, `{"token":"registration-token"}`
		client := wire.client()
		if _, err := client.PrepareWebmasterReferral(context.Background(), referralTestURL); err != nil {
			t.Fatal(err)
		}
		if sent, err := client.RegisterSendCode(context.Background(), "new@example.invalid"); err == nil {
			t.Fatalf("response with no result code was accepted: %+v", sent)
		}
		before := len(wire.paths)
		if _, err := client.RegisterFinishWithReferral(context.Background(), "registration-token", "abc123", referralTestOptions()); err == nil {
			t.Error("sendcode with no explicit success code issued a usable registration token")
		}
		if len(wire.paths) != before {
			t.Error("missing sendcode result code proceeded to account creation")
		}
	})
	t.Run("verify with no code", func(t *testing.T) {
		wire := referralTestNewWire(t)
		wire.verifyBody = `{}`
		client := wire.client()
		token := referralTestPrepareAndSend(t, wire, client)
		if verified, err := client.RegisterVerify(context.Background(), token, "123456"); err == nil {
			t.Fatalf("empty verification response was accepted: %+v", verified)
		}
		if wire.count("/passport/register_v4/finish") != 0 || wire.count("/share/transfer") != 0 {
			t.Error("empty verification response triggered account creation or transfer")
		}
	})
}

func TestWebmasterReferralFinishPreservesErrnoWithoutCodeAndAllowsRetry(t *testing.T) {
	wire := referralTestNewWire(t)
	wire.finishBody, wire.finishNDUS = `{"errno":12,"errmsg":"rejected"}`, ""
	client := wire.client()
	token := referralTestPrepareAndSend(t, wire, client)
	result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 12 || apiErr.Message != "rejected" || result == nil || result.Registration == nil || result.Registration.Errno != 12 || result.Registration.ErrMsg != "rejected" {
		t.Fatalf("errno-only finish failure was lost: result=%+v error=%v", result, err)
	}
	if result.Session == nil || result.Session.FinishAttempted || result.Session.RegistrationConfirmed || result.Session.NDUS != "" || result.Transfer != nil {
		t.Fatalf("explicit server rejection left an uncertain account-creation marker: %+v", result)
	}
	if wire.count("/share/transfer") != 0 {
		t.Fatal("rejected registration proceeded to transfer")
	}
	wire.finishBody, wire.finishNDUS = `{"code":0,"data":null}`, "registered-session"
	result, err = client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
	if err != nil || result == nil || result.Transfer == nil || result.Transfer.TaskID != 1 || wire.count("/passport/register_v4/finish") != 2 {
		t.Fatalf("explicit rejection prevented a subsequent registration retry: result=%+v error=%v requests=%v", result, err, wire.paths)
	}
}

func TestWebmasterReferralCanceledFinishWithCachedKeyDoesNotAttemptRegistration(t *testing.T) {
	wire := referralTestNewWire(t)
	client := wire.client()
	token := referralTestPrepareAndSend(t, wire, client)
	key, err := client.GetPublicKey(context.Background())
	if err != nil || key == nil || key.Code != 0 {
		t.Fatalf("public key preparation=%+v error=%v", key, err)
	}
	before := len(wire.paths)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	registration, err := client.RegisterFinish(ctx, token, "abc123")
	if !errors.Is(err, context.Canceled) || registration != nil || len(wire.paths) != before {
		t.Fatalf("canceled finish sent a request or lost cancellation: registration=%+v error=%v requests=%v", registration, err, wire.paths[before:])
	}
	saved := client.WebmasterRegistrationSession()
	if saved == nil || saved.FinishAttempted || saved.NDUS != "" || saved.RegistrationConfirmed {
		t.Fatalf("pre-canceled finish changed account-creation state: %+v", saved)
	}
	result, err := client.RegisterFinishWithReferral(context.Background(), token, "abc123", referralTestOptions())
	if err != nil || result == nil || result.Transfer == nil || result.Transfer.TaskID != 1 || wire.count("/passport/register_v4/finish") != 1 || wire.count("/passport/getpubkey") != 1 {
		t.Fatalf("canceled finish prevented a subsequent normal-context retry: result=%+v error=%v requests=%v", result, err, wire.paths)
	}
}
