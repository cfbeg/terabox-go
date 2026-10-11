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
	"testing"
)

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
		resp, err := cli.PassportLogin(context.Background(), pre, "test@example.invalid", "Abcdef123")
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
			resp, err = cli.PassportLogin(context.Background(), &PreLoginResponse{}, "test@example.invalid", "Abcdef123")
		} else {
			resp, err = cli.RegisterFinish(context.Background(), "fixture-token", "Abcdef123")
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
		if err != nil || string(plain) != fmt.Sprintf("%x32", md5.Sum([]byte("Abcdef123"))) {
			t.Fatalf("password transformation: %v", err)
		}
		want := fmt.Sprintf("%x", md5.Sum([]byte("server-seval-test@example.invalid-"+encrypted+"-123-456-fixture-cuid-android")))
		if req.PostForm.Get("prand") != want || req.PostForm.Get("client") != "android" || req.PostForm.Get("pass_version") != "2.8" {
			t.Fatal("not the APK Hy login profile/bridge prand")
		}
		return shareJSONResponse(req, `{"code":0,"data":{"ndus":"fixture-session","userid":"12345"}}`), nil
	})}))
	cli.androidApp.ready, cli.data.pcfToken, cli.data.pubKey = true, "fixture-pcf", string(public)
	resp, err := cli.PassportLogin(context.Background(), pre, "test@example.invalid", "Abcdef123")
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
