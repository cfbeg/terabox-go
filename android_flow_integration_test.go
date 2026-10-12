package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDynamicHyBootstrapFSECAndRestoredVerifiedFlow(t *testing.T) {
	const page = `<script>window.templateData={pcftoken:['runtime','pcf'].join('-')};window.jsToken='observed-runtime-token';window.fsec={encrypt:function(v){return '12345678encrypted('+v+')'}};</script>`
	_, key := androidPubkeyFixture(t)
	profile := androidFixtureProfile()
	profile.PageURL += "&from=share"
	var paths []string
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		if req.URL.Path == "/wap/hylogin/emailRegister" {
			return shareJSONResponse(req, page), nil
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if req.URL.Query().Get("jsToken") != "observed-runtime-token" || req.PostForm.Get("pcftoken") != "runtime-pcf" {
			t.Fatal("runtime bootstrap globals were lost")
		}
		switch req.URL.Path {
		case "/passport/register_v4/sendcode":
			if req.PostForm.Get("email") != "encrypted(fixture@example.invalid)" || req.Header.Get("fs-ex-st") != "1" || req.PostForm.Get("reg_source") != "share" {
				t.Fatal("APK FSEC/send source branch differs")
			}
			return shareJSONResponse(req, `{"code":0,"token":"runtime-token"}`), nil
		case "/passport/register_v4/verify":
			return shareJSONResponse(req, `{"code":0}`), nil
		case "/passport/getpubkey":
			return shareJSONResponse(req, key), nil
		case "/passport/register_v4/finish":
			return shareJSONResponse(req, `{"code":0,"data":{"ndus":"runtime-session","userid":"123"}}`), nil
		default:
			t.Fatalf("unexpected path %s", req.URL.Path)
			return nil, errors.New("unexpected")
		}
	})
	client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	sent, err := client.RegisterSendCode(context.Background(), "fixture@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(client.WebmasterRegistrationSession())
	var saved WebmasterRegistrationSession
	if json.Unmarshal(data, &saved) != nil || saved.HyRuntime == nil {
		t.Fatal("runtime was not saved")
	}
	client, err = NewAndroidAppClient(*saved.AndroidApp, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil || client.RestoreWebmasterRegistrationSession(&saved) != nil {
		t.Fatal("pending runtime restoration failed")
	}
	if _, err = client.RegisterVerify(context.Background(), sent.Token, "1234"); err != nil {
		t.Fatal(err)
	}
	if _, err = client.RegisterFinish(context.Background(), sent.Token, "Fixture123!"); err != nil {
		t.Fatal(err)
	}
	finished := client.WebmasterRegistrationSession()
	fresh, _ := NewAndroidAppClient(*finished.AndroidApp)
	if err = fresh.RestoreWebmasterRegistrationSession(finished); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5 {
		t.Fatal("restoration unexpectedly bootstrapped or repeated registration")
	}
}

func TestChallengeIdentityIsRequestBoundAndPreserved(t *testing.T) {
	profile := androidFixtureProfile()
	call := 0
	client, _ := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/wap/hylogin/emailRegister" {
			return shareJSONResponse(req, `<script>var templateData={"pcftoken":"challenge-pcf"};</script>`), nil
		}
		call++
		if call == 1 {
			return shareJSONResponse(req, `{"errno":460030,"errmsg":"dragdrop","request_id_string":"9007199254740993"}`), nil
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if req.PostForm.Get("g_identity") != "actually-completed-token" {
			t.Fatal("provided challenge identity was not used")
		}
		return shareJSONResponse(req, `{"code":0,"token":"challenge-registration-token"}`), nil
	})}))
	reply, err := client.RegisterSendCode(context.Background(), "fixture@example.invalid")
	var challenge *LoginChallengeError
	if !errors.As(err, &challenge) || reply == nil || len(reply.RawBody) == 0 {
		t.Fatal("challenge evidence was discarded")
	}
	if client.SetAndroidChallengeIdentity(&AndroidChallengeIdentity{RequestID: "other", Token: "token"}) == nil {
		t.Fatal("wrong request identity accepted")
	}
	saved := client.WebmasterRegistrationSession()
	fresh, _ := NewAndroidAppClient(*saved.AndroidApp, WithHTTPClient(client.httpClient))
	if fresh.RestoreWebmasterRegistrationSession(saved) != nil {
		t.Fatal("pending challenge lost on restore")
	}
	if fresh.SetAndroidChallengeIdentity(&AndroidChallengeIdentity{RequestID: challenge.RequestID, Token: "actually-completed-token"}) != nil {
		t.Fatal("actual identity rejected")
	}
	if _, err = fresh.RegisterSendCode(context.Background(), "fixture@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if fresh.WebmasterRegistrationSession().PendingChallenge != nil {
		t.Fatal("completed challenge was not cleared")
	}
}

func TestFinishPreservesNativeTokenWhenUIDIsMissing(t *testing.T) {
	_, key := androidPubkeyFixture(t)
	client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "getpubkey") {
			return shareJSONResponse(req, key), nil
		}
		return shareJSONResponse(req, `{"code":0,"data":{"ndus":"native-only-token"}}`), nil
	})}))
	client.androidApp.ready = true
	client.data.pcfToken = "pcf"
	client.registrationToken = "token"
	reply, err := client.RegisterFinish(context.Background(), "token", "Fixture123!")
	if err == nil || reply == nil || reply.NDUS != "native-only-token" || len(reply.RawBody) == 0 {
		t.Fatal("recoverable response token or evidence was lost")
	}
	state := client.WebmasterRegistrationSession()
	if state.NDUS != "native-only-token" || state.RegistrationConfirmed || state.AndroidApp.UID != "" {
		t.Fatal("missing UID was invented or registration prematurely confirmed")
	}
}

func TestHTTPFailureRetainsMalformedPrivateBodyWithoutInvalidJSON(t *testing.T) {
	client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		response := shareJSONResponse(req, "not-json private error")
		response.StatusCode = 503
		return response, nil
	})}))
	client.androidApp.ready = true
	client.data.pcfToken = "pcf"
	reply, err := client.RegisterSendCode(context.Background(), "fixture@example.invalid")
	if err == nil || reply == nil || string(reply.RawBody) != "not-json private error" || len(reply.Raw) != 0 || reply.HTTPStatus != 503 {
		t.Fatal("HTTP failure evidence was lost or represented as invalid RawMessage")
	}
	if _, err = json.Marshal(reply); err != nil {
		t.Fatal("private recovery body cannot be serialized")
	}
}

type truncatedAPKReader struct{}

func (truncatedAPKReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestInterruptedResponseRetainsReceivedPrivateBytes(t *testing.T) {
	const partial = `{"code":0,"data":`
	client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		response := shareJSONResponse(req, "")
		response.Body = io.NopCloser(io.MultiReader(strings.NewReader(partial), truncatedAPKReader{}))
		return response, nil
	})}))
	client.androidApp.ready = true
	client.data.pcfToken = "pcf"
	reply, err := client.RegisterSendCode(context.Background(), "fixture@example.invalid")
	if err == nil || reply == nil || string(reply.RawBody) != partial || len(reply.Raw) != 0 || reply.HTTPStatus != 200 {
		t.Fatal("interrupted response discarded received evidence")
	}
	if client.WebmasterRegistrationSession().RegistrationToken != "" {
		t.Fatal("partial success envelope was treated as confirmed SendCode")
	}
	if _, err = json.Marshal(reply); err != nil {
		t.Fatal("interrupted response is not serializable")
	}
}
