package terabox

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestRegisterVerifyRejectsInvalidCodeBeforeBootstrap(t *testing.T) {
	for _, test := range []struct {
		name, code string
	}{
		{"empty", ""},
		{"short", "123"},
		{"long", "12345"},
		{"six digits", "123456"},
		{"letter", "12a4"},
		{"sign", "-123"},
		{"decimal", "1.23"},
		{"leading space", " 1234"},
		{"trailing space", "1234 "},
		{"newline", "123\n"},
		{"fullwidth digits", "１２３４"},
		{"Arabic-Indic digits", "١٢٣٤"},
		{"mixed unicode digit", "123４"},
		{"NUL", "1\x0034"},
		{"invalid UTF-8", "\xff234"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{
				Transport: shareRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					return nil, errors.New("invalid code must not bootstrap or send verification")
				}),
			}))
			if err != nil {
				t.Fatal(err)
			}
			client.registrationToken = "fixture-token"
			page := client.AndroidAppProfile().PageURL
			response, err := client.RegisterVerify(context.Background(), "fixture-token", test.code)
			var wrapped *Error
			if response != nil || !errors.As(err, &wrapped) || wrapped.Op != "regVerify" ||
				!strings.Contains(err.Error(), "exactly 4 ASCII digits") || calls != 0 {
				t.Fatalf("response=%v error=%v requests=%d", response, err, calls)
			}
			if client.androidApp.ready || client.registrationToken != "fixture-token" ||
				client.AndroidAppProfile().PageURL != page || client.CookieString() != "" {
				t.Fatal("invalid OTP changed registration state")
			}
		})
	}
}

func TestRegisterVerifyPreservesFourDigitCodeOnNormalWire(t *testing.T) {
	for _, code := range []string{"0000", "0007", "0123", "1234", "9999"} {
		t.Run(code, func(t *testing.T) {
			calls := 0
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{
				Transport: shareRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					if request.Method != http.MethodPost || request.URL.Path != "/passport/register_v4/verify" {
						t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
					}
					if err := request.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if request.PostForm.Get("code") != code || request.PostForm.Get("skip_code") != "0" ||
						request.PostForm.Get("token") != "fixture-token" || request.PostForm.Get("g_identity") != "" {
						t.Fatal("verification changed the OTP or normal APK form")
					}
					return shareJSONResponse(request, `{"code":0,"data":null}`), nil
				}),
			}))
			if err != nil {
				t.Fatal(err)
			}
			client.androidApp.ready, client.data.pcfToken, client.registrationToken = true, "fixture-pcf", "fixture-token"
			response, err := client.RegisterVerify(context.Background(), "fixture-token", code)
			if err != nil || response == nil || response.Code != 0 || calls != 1 {
				t.Fatalf("response=%v error=%v requests=%d", response, err, calls)
			}
		})
	}
}

func TestPassportLoginRejectsInvalidPreLoginBeforeRequest(t *testing.T) {
	for _, pre := range []*PreLoginResponse{nil, {Code: 10, Msg: "invalid email"}} {
		calls := 0
		cli, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("request must not be sent")
		})}))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := cli.PassportLogin(context.Background(), pre, "test@example.invalid", "Abcdef123!")
		if err == nil || resp != nil || calls != 0 {
			t.Fatalf("response=%v error=%v requests=%d", resp, err, calls)
		}
		if pre != nil {
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Code != pre.Code || apiErr.Message != pre.Msg {
				t.Fatalf("prelogin code lost: %v", err)
			}
		}
	}
}

func TestPassportFlowsPreserveHyPublicKeyFailure(t *testing.T) {
	for _, login := range []bool{false, true} {
		calls := 0
		cli, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Path != "/passport/getpubkey" || req.Method != http.MethodPost {
				t.Fatalf("flow continued: %s %s", req.Method, req.URL.Path)
			}
			return shareJSONResponse(req, `{"code":7,"msg":"key unavailable"}`), nil
		})}))
		cli.androidApp.ready, cli.data.pcfToken, cli.registrationToken = true, "fixture-pcf", "fixture-token"
		var resp *PassportResponse
		var err error
		if login {
			resp, err = cli.PassportLogin(context.Background(), &PreLoginResponse{}, "test@example.invalid", "Abcdef123!")
		} else {
			resp, err = cli.RegisterFinish(context.Background(), "fixture-token", "Abcdef123!")
		}
		var apiErr *APIError
		if resp != nil || !errors.As(err, &apiErr) || apiErr.Code != 7 || apiErr.Message != "key unavailable" || calls != 1 {
			t.Fatalf("response=%v error=%v requests=%d", resp, err, calls)
		}
	}
}

func TestRegisterFinishValidatesAPKPasswordBeforeRequest(t *testing.T) {
	for _, password := range []string{"", "short", "12345678", "abcdefgh", "Abcdefgh", "Abcdef1234567890123456"} {
		cli, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatal("invalid password sent a request")
			return nil, nil
		})}))
		cli.registrationToken = "fixture-token"
		resp, err := cli.RegisterFinish(context.Background(), "fixture-token", password)
		if err != nil || resp == nil || resp.Code != -2 {
			t.Fatalf("invalid password accepted: response=%v error=%v", resp, err)
		}
	}
}

func TestPassportLoginUsesAPKNativePrandAndIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	pre := &PreLoginResponse{Seval: "server-seval", Random: "123", Timestamp: 456}
	calls := 0
	cli, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Path != "/passport/login" || req.Method != http.MethodPost {
			t.Fatalf("unexpected %s %s", req.Method, req.URL.Path)
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		encrypted := req.PostForm.Get("pwd")
		ciphertext, err := base64.URLEncoding.DecodeString(encrypted)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := rsa.DecryptPKCS1v15(rand.Reader, key, ciphertext)
		if err != nil || string(plain) != fmt.Sprintf("%x32", md5.Sum([]byte("Abcdef123!"))) {
			t.Fatalf("password transformation: %v", err)
		}
		want := fmt.Sprintf("%x", md5.Sum([]byte("server-seval-test@example.invalid-"+encrypted+"-123-456-fixture-cuid-android")))
		if req.PostForm.Get("prand") != want || req.PostForm.Get("client") != "android" || req.PostForm.Get("pass_version") != "2.8" {
			t.Fatal("not the APK Hy login profile/bridge prand")
		}
		return shareJSONResponse(req, `{"code":0,"data":{"ndus":"fixture-session","userid":"12345"}}`), nil
	})}))
	cli.androidApp.ready, cli.data.pcfToken, cli.data.pubKey = true, "fixture-pcf", string(public)
	resp, err := cli.PassportLogin(context.Background(), pre, "test@example.invalid", "Abcdef123!")
	if err != nil || resp.NDUS != "fixture-session" || cli.AndroidAppProfile().UID != "12345" || calls != 1 {
		t.Fatalf("native login result=%+v error=%v", resp, err)
	}
}

func TestPassportChallengeKeepsAPKPageAndRequestID(t *testing.T) {
	cli, _ := NewAndroidAppClient(androidFixtureProfile())
	response := &PassportResponse{Errno: 460030, ErrMsg: "dragdrop", RequestIDString: "9007199254740993"}
	var challenge *LoginChallengeError
	if !errors.As(cli.maybeChallenge(response, false), &challenge) || challenge.RequestID != response.RequestIDString || challenge.ChallengeURL != cli.AndroidAppProfile().PageURL {
		t.Fatal("app challenge context lost or a browser-only URL was invented")
	}
}
