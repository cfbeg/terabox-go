package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const referralTestURL = "https://terabox.com/s/1Ab_c-key?pwd=1234"

func appReferralClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestPrepareReferralUsesAPKSourceAndNativeMetadata(t *testing.T) {
	calls := 0
	client := appReferralClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("X-Requested-With") != "" || req.URL.Query().Get("channel") != androidFixtureProfile().NativeChannel {
			t.Fatal("not the native share metadata family")
		}
		if req.URL.Path == "/api/shorturlinfo" {
			return shareJSONResponse(req, `{"errno":400210,"errmsg":"need verify_v2"}`), nil
		}
		if req.URL.Path != "/share/list" {
			t.Fatalf("unexpected metadata path: %s", req.URL.Path)
		}
		return shareJSONResponse(req, `{"errno":0,"share_id":123,"uk":456,"list":[{"fs_id":"789","path":"/shared.bin"}]}`), nil
	}))
	ref, err := client.PrepareWebmasterReferral(context.Background(), referralTestURL)
	if err != nil || ref.Source != "share" || ref.ShareID != 123 || ref.WebmasterUK != 456 || ref.ShareFromSURL != "Ab_c-key" || calls != 2 {
		t.Fatalf("referral=%+v error=%v calls=%d", ref, err, calls)
	}
	for _, source := range []string{"web_share", "web_share_videoplay", "unverified"} {
		if _, err := client.PrepareWebmasterReferralWithOptions(context.Background(), referralTestURL, &WebmasterReferralOptions{Source: source}); err == nil || calls != 2 {
			t.Fatal("browser-only source was accepted or sent")
		}
	}
	client.registrationToken = "fixture-token"
	if _, err := client.PrepareWebmasterReferral(context.Background(), referralTestURL); err == nil || calls != 2 {
		t.Fatal("referral changed after registration started")
	}
}

func TestReferralSnapshotRestoresOnlyMatchingAppIdentity(t *testing.T) {
	client := appReferralClient(t, nil)
	client.referral = &WebmasterReferral{ShareURL: referralTestURL, ShareFromSURL: "Ab_c-key", ShareID: 123, WebmasterUK: 456, Source: "share"}
	client.registrationToken, client.data.pcfToken = "fixture-token", "fixture-pcf"
	client.androidApp.ready = true
	saved := client.WebmasterRegistrationSession()
	fresh := appReferralClient(t, nil)
	if err := fresh.RestoreWebmasterRegistrationSession(saved); err != nil {
		t.Fatal(err)
	}
	if fresh.referral.ShareURL != referralTestURL || fresh.registrationToken != "fixture-token" || !fresh.androidApp.ready {
		t.Fatal("snapshot lost app state")
	}
	bad := *saved
	bad.AndroidApp = nil
	if err := appReferralClient(t, nil).RestoreWebmasterRegistrationSession(&bad); err == nil {
		t.Fatal("legacy session restored without an app profile")
	}
	changed := androidFixtureProfile()
	changed.DeviceID = "different-captured-device"
	other, _ := NewAndroidAppClient(changed)
	if err := other.RestoreWebmasterRegistrationSession(saved); err == nil {
		t.Fatal("snapshot replaced another app identity")
	}
	changed = androidFixtureProfile()
	changed.NativeChannel = "android_different_captured_channel"
	other, _ = NewAndroidAppClient(changed)
	if err := other.RestoreWebmasterRegistrationSession(saved); err == nil {
		t.Fatal("snapshot replaced another native app channel")
	}
	bad = *saved
	bad.Cookies, bad.NDUS = "ndus=one-session", "different-session"
	if err := appReferralClient(t, nil).RestoreWebmasterRegistrationSession(&bad); err == nil {
		t.Fatal("mismatched NDUS/cookie session accepted")
	}
}

func preparedAppReferral(t *testing.T, transport http.RoundTripper) *Client {
	client := appReferralClient(t, transport)
	client.referral = &WebmasterReferral{ShareURL: referralTestURL, ShareFromSURL: "Ab_c-key", ShareID: 123, WebmasterUK: 456, Source: "share"}
	client.androidApp.ready, client.data.pcfToken, client.registrationToken = true, "fixture-pcf", "fixture-token"
	_, key := androidPubkeyFixture(t)
	var response PublicKeyResponse
	if err := json.Unmarshal([]byte(key), &response); err != nil {
		t.Fatal(err)
	}
	public, err := DecryptAES(response.Data.PP1, response.Data.PP2)
	if err != nil {
		t.Fatal(err)
	}
	client.data.pubKey = public
	return client
}

func TestReferralFinishUnknownPreservesSessionAndBlocksRepeat(t *testing.T) {
	for _, body := range []string{`{"code":0,`, `{"data":{"ndus":"unconfirmed"}}`, `{"code":0,"data":{"userid":"12345"}}`} {
		calls := 0
		client := preparedAppReferral(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Path != "/passport/register_v4/finish" {
				t.Fatalf("unexpected request %s", req.URL.Path)
			}
			response := shareJSONResponse(req, body)
			response.Header.Add("Set-Cookie", "ndus=fixture-uncertain-session; Path=/")
			return response, nil
		}))
		result, err := client.RegisterFinishWithReferral(context.Background(), "fixture-token", "Abcdef123!", &WebmasterTransferOptions{FSIDs: []int64{789}, Destination: "/"})
		if err == nil || result == nil || result.Session == nil || !result.Session.FinishAttempted || result.Session.RegistrationConfirmed || result.Session.NDUS != "fixture-uncertain-session" || calls != 1 {
			t.Fatalf("unknown finish state lost: result=%+v error=%v", result, err)
		}
		fresh := appReferralClient(t, nil)
		if err := fresh.RestoreWebmasterRegistrationSession(result.Session); err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.RegisterSendCode(context.Background(), "fixture@example.invalid"); err == nil {
			t.Fatal("unknown finish permitted new registration")
		}
		if _, err := client.RegisterFinish(context.Background(), "fixture-token", "Abcdef123!"); err == nil || calls != 1 {
			t.Fatal("unknown finish was sent twice")
		}
	}
}

func TestReferralTransferFailureKeepsConfirmedAccount(t *testing.T) {
	finishes, transfers := 0, 0
	client := preparedAppReferral(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/passport/register_v4/finish":
			finishes++
			return shareJSONResponse(req, `{"code":0,"data":{"ndus":"fixture-session","userid":"12345"}}`), nil
		case "/share/transfer":
			transfers++
			if transfers == 1 {
				return shareJSONResponse(req, `{"errno":12,"errmsg":"retry transfer"}`), nil
			}
			return shareJSONResponse(req, `{"errno":0,"task_id":"987"}`), nil
		default:
			t.Fatalf("non-APK or repeat account request %s", req.URL.Path)
			return nil, nil
		}
	}))
	opts := &WebmasterTransferOptions{FSIDs: []int64{789}, Destination: "/"}
	result, err := client.RegisterFinishWithReferral(context.Background(), "fixture-token", "Abcdef123!", opts)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 12 || result.Registration.NDUS != "fixture-session" || !result.Session.RegistrationConfirmed || result.Session.AndroidApp.UID != "12345" {
		t.Fatal("transfer error discarded native registration")
	}
	transfer, err := client.TransferWebmasterReferral(context.Background(), opts)
	if err != nil || transfer.TaskID != 987 || finishes != 1 || transfers != 2 {
		t.Fatal("transfer retry repeated registration")
	}
	if _, err := client.RegisterFinish(context.Background(), "fixture-token", "Abcdef123!"); err == nil || finishes != 1 {
		t.Fatal("confirmed finish was repeatable")
	}
}

func TestReferralRegistrationRejectsDifferentTokenWithoutHTTP(t *testing.T) {
	client := preparedAppReferral(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("mismatched token sent HTTP")
		return nil, nil
	}))
	for _, token := range []string{"", "different-token"} {
		if _, err := client.RegisterVerify(context.Background(), token, "1234"); err == nil {
			t.Fatal("mismatched verify token accepted")
		}
		if _, err := client.RegisterFinish(context.Background(), token, "Abcdef123!"); err == nil {
			t.Fatal("mismatched finish token accepted")
		}
	}
}

func TestReferralSendAndVerifyRejectMissingCodeBeforeCookies(t *testing.T) {
	for _, verify := range []bool{false, true} {
		client := preparedAppReferral(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			response := shareJSONResponse(req, `{"token":"fixture-token"}`)
			response.Header.Add("Set-Cookie", "proof=unconfirmed; Path=/")
			return response, nil
		}))
		var err error
		if verify {
			_, err = client.RegisterVerify(context.Background(), "fixture-token", "1234")
		} else {
			_, err = client.RegisterSendCode(context.Background(), "fixture@example.invalid")
		}
		if err == nil || !strings.Contains(err.Error(), "missing code") {
			t.Fatal("missing registration result code accepted")
		}
		if _, ok := client.CookieValue("proof"); ok {
			t.Fatal("unconfirmed cookie committed")
		}
	}
}
