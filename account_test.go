package terabox

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestCheckLoginUsesAPKNativeAccountRequest(t *testing.T) {
	calls := 0
	profile := androidFixtureProfile()
	profile.LegacyNativeParams = map[string]string{"app_name": "dubox", "network_type": "wifi"}
	client, err := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPost || req.URL.Path != "/api/account/uinfo" {
			t.Error("APK account verification used a different path or verb")
		}
		if err := req.ParseForm(); err != nil {
			return nil, err
		}
		wantHash := fmt.Sprintf("%x", md5.Sum([]byte("fixture-session")))
		if req.PostForm.Get("bdstoken") != wantHash || req.URL.Query().Has("bdstoken") || req.URL.Query().Has("rand") ||
			req.URL.Query().Get("network_type") != "wifi" || req.URL.Query().Get("clienttype") != "1" {
			t.Error("native account check lost the legacy query or native POST form")
		}
		if req.Header.Get("Cookie") != "ndus=fixture-session" || req.Header.Get("Referer") != "https://terabox.com/" || req.Header.Get("X-Requested-With") != "" {
			t.Error("native account check lost the APK cookie/header contract")
		}
		return shareJSONResponse(req, `{"errno":0,"uk":"9007199254740993"}`), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.CheckLogin(context.Background())
	if err != nil || response.UK != 9007199254740993 || calls != 1 || client.Account().ID != response.UK {
		t.Fatalf("account=%v error=%v calls=%d", response, err, calls)
	}
	if client.AndroidAppProfile().UID != "" {
		t.Fatal("account UK was inferred as NativeUID")
	}
}

func TestAccountReplyRequiresExplicitStatusAndIdentity(t *testing.T) {
	for _, body := range []string{`{}`, `{"errno":0}`, `{"errno":0,"uk":"broken"}`} {
		var response CheckLoginResponse
		if err := json.Unmarshal([]byte(body), &response); err == nil {
			t.Errorf("invalid account body accepted: %s", body)
		}
	}
	var rejected CheckLoginResponse
	if err := json.Unmarshal([]byte(`{"errno":-6,"errmsg":"login required"}`), &rejected); err != nil || rejected.Errno != -6 {
		t.Fatalf("rejection lost: %v", err)
	}
	client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("missing credentials must stop before network")
		return nil, nil
	})}))
	if _, err := client.CheckLogin(context.Background()); err == nil || !strings.Contains(err.Error(), "ndus") {
		t.Fatal("account verification did not require a session")
	}
}
