package terabox

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"
)

func TestPassportLoginRejectsInvalidPreLoginBeforeRequest(t *testing.T) {
	for _, pre := range []*PreLoginResponse{nil, {Code: 10, Msg: "invalid email"}} {
		calls := 0
		cli := NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("request must not be sent")
		})}))
		resp, err := cli.PassportLogin(context.Background(), pre, "test@example.invalid", "abc123")
		if err == nil || resp != nil || calls != 0 {
			t.Fatalf("response=%v error=%v requests=%d for prelogin %v", resp, err, calls, pre)
		}
		if pre != nil {
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Code != pre.Code || apiErr.Message != pre.Msg {
				t.Fatalf("original prelogin error lost: %v", err)
			}
		}
	}
}

func TestPassportFlowsPreservePublicKeyFailure(t *testing.T) {
	for _, flow := range []string{"login", "registration"} {
		t.Run(flow, func(t *testing.T) {
			calls := 0
			cli := NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Path != "/passport/getpubkey" {
					t.Fatalf("flow proceeded after public key failure: %s", req.URL.Path)
				}
				return authTestJSON(req, `{"code":7,"msg":"key unavailable"}`), nil
			})}))
			var resp *PassportResponse
			var err error
			if flow == "login" {
				resp, err = cli.PassportLogin(context.Background(), &PreLoginResponse{}, "test@example.invalid", "abc123")
			} else {
				resp, err = cli.RegisterFinish(context.Background(), "registration-token", "abc123")
			}
			var apiErr *APIError
			if resp != nil || !errors.As(err, &apiErr) || apiErr.Code != 7 || apiErr.Message != "key unavailable" || calls != 1 {
				t.Fatalf("response=%v error=%v requests=%d", resp, err, calls)
			}
			// GetPublicKey itself keeps the existing response-code contract.
			key, err := cli.GetPublicKey(context.Background())
			if err != nil || key.Code != 7 || key.Msg != "key unavailable" {
				t.Fatalf("GetPublicKey changed its API error contract: response=%v error=%v", key, err)
			}
		})
	}
}

func TestRegisterFinishValidatesPasswordBeforeRequest(t *testing.T) {
	for _, password := range []string{"", "short", "123456", "abcdefghijklmnop"} {
		t.Run(password, func(t *testing.T) {
			calls := 0
			cli := NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("request must not be sent")
			})}))
			resp, err := cli.RegisterFinish(context.Background(), "registration-token", password)
			if err != nil || resp == nil || resp.Code != -2 || calls != 0 {
				t.Fatalf("response=%v error=%v requests=%d", resp, err, calls)
			}
		})
	}
}

func TestPassportLoginKeepsEncryptedPasswordAndSessionToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	calls := 0
	cli := NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Path != "/passport/login" {
			t.Fatalf("unexpected request to %s", req.URL.Path)
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		encrypted, err := base64.URLEncoding.DecodeString(req.Form.Get("pwd"))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := rsa.DecryptPKCS1v15(rand.Reader, key, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if string(plain) != "e99a18c428cb38d5f260853678922e0332" {
			t.Fatalf("unexpected encrypted login payload: %q", plain)
		}
		if req.Form.Get("seval") != "server-seval" || req.Form.Get("random") != "123" || req.Form.Get("timestamp") != "456" {
			t.Fatalf("prelogin fields lost: %v", req.Form)
		}
		resp := authTestJSON(req, `{"code":0,"data":{}}`)
		resp.Header.Add("Set-Cookie", "ndus=session-token; Path=/; Secure; HttpOnly")
		return resp, nil
	})}))
	cli.updateData(func(d *appData) { d.pubKey = string(publicKey) })
	pre := &PreLoginResponse{Seval: "server-seval", Random: "123", Timestamp: 456}
	resp, err := cli.PassportLogin(context.Background(), pre, "test@example.invalid", "abc123")
	if err != nil || resp == nil || resp.Code != 0 || resp.NDUS != "session-token" || calls != 1 {
		t.Fatalf("response=%v error=%v requests=%d", resp, err, calls)
	}
}
