package terabox

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
)

type shareNativeWireFixture struct {
	Transfer, Task, Listing struct {
		Method, Path string
		Query, Form  map[string]string
	}
	Report struct {
		Method, Path string
		Body         json.RawMessage
	}
}

func loadShareNativeWire(t *testing.T) shareNativeWireFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/android_share_detail_wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var result shareNativeWireFixture
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func legacyShareProfile() AndroidAppProfile {
	p := nativeShareTestProfile()
	p.NativeParams = map[string]string{"fixture_new_transport": "new"}
	p.LegacyNativeParams = map[string]string{"app_id": "250528", "app_name": "dubox", "fixture_old_transport": "old", "bot_uk": "wrong-cached-bot", "wm_token": "wrong-cached-marker"}
	p.LegacyNativeParams["bdstoken"], p.LegacyNativeParams["web"], p.LegacyNativeParams["rand"] = "stale-hash", "1", "stale-signature"
	p.NativeCKData = map[string]string{"ck_val": "observed-fixture-ck"}
	return p
}

func TestShareDetailLegacyWireAndNativePOSTToken(t *testing.T) {
	fixture := loadShareNativeWire(t).Transfer
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed=%v", signed), func(t *testing.T) {
			profile := legacyShareProfile()
			if signed {
				config := androidSignatureConfig()
				profile.UID, profile.EncodedSK = config.UID, config.EncodedSK
			}
			requests := 0
			client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.Method != fixture.Method || req.URL.Path != fixture.Path {
					t.Fatalf("wrong native save: %s %s", req.Method, req.URL.Path)
				}
				q := req.URL.Query()
				for key, expected := range fixture.Query {
					if !q.Has(key) || q.Get(key) != expected {
						t.Errorf("legacy endpoint query %s differs", key)
					}
				}
				if q.Get("fixture_old_transport") != "old" || q.Get("app_id") != "250528" || q.Get("app_name") != "dubox" || q.Has("fixture_new_transport") || q.Has("wm_token") || q.Has("bdstoken") || q.Has("web") {
					t.Error("legacy save used another request family or field provenance")
				}
				if err := req.ParseForm(); err != nil {
					t.Fatal(err)
				}
				for key, expected := range fixture.Form {
					if req.PostForm.Get(key) != expected {
						t.Errorf("legacy form %s differs", key)
					}
				}
				if req.PostForm.Get("bdstoken") != fmt.Sprintf("%x", md5.Sum([]byte("fixture-session"))) {
					t.Error("native POST token must bind source NDUS in body")
				}
				if q.Has("rand") != signed {
					t.Error("legacy guest signing state changed")
				}
				if signed {
					unsigned := *req.URL
					params := unsigned.Query()
					params.Del("rand")
					unsigned.RawQuery = params.Encode()
					signer, err := NewAndroidSigner(AndroidSigningConfig{DeviceID: profile.DeviceID, UID: profile.UID, EncodedSK: profile.EncodedSK, Version: profile.Version})
					if err != nil {
						t.Fatal(err)
					}
					expected, err := signer.SignURL(unsigned.String(), "fixture-session")
					if err != nil || expected != req.URL.String() {
						t.Error("legacy save did not use the verified native signature")
					}
				}
				if req.Header.Get("User-Agent") != profile.UserAgent || req.Header.Get("Referer") != "https://terabox.com/" {
					t.Error("legacy native headers changed")
				}
				return shareJSONResponse(req, `{"errno":0,"taskid":"7","request_id":"9007199254740993"}`), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			client.mergeCookies([]*http.Cookie{{Name: "ndus", Value: "fixture-session"}})
			response, err := client.TransferShare(context.Background(), 101, 202, []int64{303, 304}, "/saved", &ShareTransferOptions{Route: ShareTransferRouteShareDetailLegacy, SEKey: "observed%2Bkey"})
			if err != nil || response == nil || response.TaskID != 7 || len(response.Raw) == 0 || response.RequestID.String() != "9007199254740993" || requests != 1 {
				t.Fatalf("legacy save result=%v err=%v requests=%d", response, err, requests)
			}
		})
	}
}

func TestLegacyTransferResponseAliasesAndPerFileResults(t *testing.T) {
	for _, body := range []string{`{"errno":0,"taskid":"7"}`, `{"errno":0,"task_id":7}`, `{"errno":0,"taskid":7,"task_id":7}`} {
		var r ShareTransferResponse
		if err := json.Unmarshal([]byte(body), &r); err != nil || r.TaskID != 7 {
			t.Fatalf("APK task ID aliases were not normalized: %s %v", body, err)
		}
	}
	var ambiguous ShareTransferResponse
	if json.Unmarshal([]byte(`{"errno":0,"taskid":7,"task_id":8}`), &ambiguous) == nil {
		t.Fatal("conflicting task identifiers accepted")
	}
	for _, tc := range []struct {
		body   string
		reject bool
		errno  int
	}{
		{`{"errno":0,"info":[{"errno":0,"path":"/saved/source.txt"}]}`, false, 0},
		{`{"errno":0,"info":[{"errno":0},{"errno":12}]}`, false, 12},
		{`{"errno":0,"info":[{}]}`, true, 0},
		{`{"errno":0,"extra":{"list":[]}}`, true, 0},
	} {
		client, err := NewAndroidAppClient(nativeShareTestProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) { return shareJSONResponse(req, tc.body), nil })}))
		if err != nil {
			t.Fatal(err)
		}
		r, err := client.TransferShare(context.Background(), 101, 202, []int64{303}, "/saved", &ShareTransferOptions{Route: ShareTransferRouteShareDetailLegacy})
		if tc.reject {
			if err == nil {
				t.Errorf("invalid legacy result accepted: %s", tc.body)
			}
			continue
		}
		if err != nil || r.Errno != tc.errno || len(r.Info) == 0 || len(r.Raw) == 0 {
			t.Fatalf("per-file legacy result lost: %s result=%v err=%v", tc.body, r, err)
		}
	}
}

func TestShareViewMatchesNativeJSONAndDistinctUK(t *testing.T) {
	fixture := loadShareNativeWire(t).Report
	profile := nativeShareTestProfile()
	profile.UID = "202" // NativeUID must not be treated as UK.
	profile.NativeParams = map[string]string{"web": "1", "jsToken": "stale-fixture-js", "bdstoken": "stale-fixture-hash", "app_id": "250528", "app_name": "dubox", "rand": "stale-signature"}
	requests := 0
	client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Method != fixture.Method || req.URL.Path != fixture.Path || req.Header.Get("Content-Type") != "application/json; charset=UTF-8" {
			t.Fatal("received-link report has incorrect native JSON transport")
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		var actual, expected any
		if err := json.Unmarshal(body, &actual); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(fixture.Body, &expected); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("received-link body differs: %s", body)
		}
		if !strings.HasSuffix(req.URL.RawQuery, "&rand") || req.URL.Query().Has("web") {
			t.Fatal("report used another API family")
		}
		for _, key := range []string{"jsToken", "bdstoken"} {
			if req.URL.Query().Has(key) {
				t.Errorf("new native transport reused stale %s", key)
			}
		}
		if req.URL.Query().Get("app_id") != "250528" || req.URL.Query().Get("app_name") != "dubox" {
			t.Error("observed native common application fields were discarded")
		}
		return shareJSONResponse(req, `{"errno":0,"data":{"has_more":false,"list":[]}}`), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.ReportShareView(context.Background(), &ShareViewOptions{OwnerUK: 202, ChainSURL: "1fixturekey", ShareURL: "https://terabox.com/s/11fixturekey"})
	if err != nil || response == nil || response.Skipped || response.HTTPStatus != 200 || len(response.Raw) == 0 || requests != 1 {
		t.Fatalf("report result=%v err=%v", response, err)
	}
}

func TestShareViewContextGuardsAndActualSourceConsistency(t *testing.T) {
	client, _ := NewAndroidAppClient(nativeShareTestProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("excluded or invalid native entry must not send")
		return nil, nil
	})}))
	for _, opts := range []*ShareViewOptions{{OwnerUK: 202, FromHive: true}, {OwnerUK: 202, FromReceivedList: true}, {OwnerUK: 202, AccountUK: 202}} {
		r, err := client.ReportShareView(context.Background(), opts)
		if err != nil || r == nil || !r.Skipped || r.SkipReason == "" {
			t.Fatal("native entry exclusion missing")
		}
	}
	for _, opts := range []*ShareViewOptions{{OwnerUK: 0}, {OwnerUK: 202, ChainSURL: "full/url"}, {OwnerUK: 202, ChainSURL: "other", ShareURL: "https://terabox.com/s/1actual"}} {
		if _, err := client.ReportShareView(context.Background(), opts); err == nil {
			t.Fatal("report accepted invented or ambiguous key")
		}
	}
	client.updateParams(func(p *accountParams) { p.accountID = 202 })
	if r, err := client.ReportShareView(context.Background(), &ShareViewOptions{OwnerUK: 202}); err != nil || !r.Skipped {
		t.Fatal("verified own UK was ignored")
	}
	if _, err := client.ReportShareView(context.Background(), &ShareViewOptions{OwnerUK: 303, AccountUK: 404}); err == nil {
		t.Fatal("unverified UK overrode the verified account")
	}
	client.updateParams(func(p *accountParams) { p.accountID = 0 })
	client.mergeCookies([]*http.Cookie{{Name: "ndus", Value: "fixture-session"}})
	if _, err := client.ReportShareView(context.Background(), &ShareViewOptions{OwnerUK: 202, ChainSURL: "actual"}); err == nil {
		t.Fatal("authenticated client reported without an observed true account UK")
	}
}

func TestNativeTaskQueryAndSavedFileList(t *testing.T) {
	fixture := loadShareNativeWire(t)
	requests := 0
	client, err := NewAndroidAppClient(legacyShareProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Query().Get("fixture_old_transport") != "old" || req.URL.Query().Has("fixture_new_transport") || req.URL.Query().Has("rand") {
			t.Fatal("verification used the wrong native transport")
		}
		switch req.URL.Path {
		case fixture.Task.Path:
			if req.Method != fixture.Task.Method || req.URL.Query().Get("taskid") != "7" || req.URL.Query().Has("bdstoken") {
				t.Fatal("task query wire changed")
			}
			if err := req.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if req.PostForm.Get("filelist") != "[{}]" || req.PostForm.Has("ck_val") || req.PostForm.Get("bdstoken") != fmt.Sprintf("%x", md5.Sum([]byte("fixture-session"))) {
				t.Fatal("task query did not mirror null-input native poll")
			}
			return shareJSONResponse(req, `{"errno":0,"status":"success","progress":100,"task_errno":0,"list":[{"from":"/source.txt","to":"/saved/source.txt","error_code":0,"to_fs_id":"404"}]}`), nil
		case fixture.Listing.Path:
			if req.Method != fixture.Listing.Method {
				t.Fatal("file list must be GET")
			}
			q := req.URL.Query()
			for key, expected := range fixture.Listing.Query {
				if q.Get(key) != expected {
					t.Errorf("list query %s changed", key)
				}
			}
			if q.Get("bdstoken") != fmt.Sprintf("%x", md5.Sum([]byte("fixture-session"))) || req.Body != nil {
				t.Fatal("legacy GET token/query placement changed")
			}
			return shareJSONResponse(req, `{"errno":0,"list":[{"fs_id":"404","path":"/saved/source.txt","server_filename":"source.txt","size":"10"}]}`), nil
		default:
			return nil, errors.New("verification unexpectedly requested another endpoint")
		}
	})}))
	if err != nil {
		t.Fatal(err)
	}
	client.mergeCookies([]*http.Cookie{{Name: "ndus", Value: "fixture-session"}})
	task, err := client.QueryShareTransferTask(context.Background(), 7)
	if err != nil || !task.Completed() || task.List[0].ToFSID != 404 {
		t.Fatalf("task=%v err=%v", task, err)
	}
	listing, err := client.ListFiles(context.Background(), "/saved", nil)
	if err != nil || len(listing.List) != 1 || listing.List[0].FSID != int64(task.List[0].ToFSID) || requests != 2 {
		t.Fatalf("listing=%v err=%v", listing, err)
	}
}

func TestNativeCompletionRejectsFalseSuccess(t *testing.T) {
	for _, body := range []string{`{}`, `{"errno":null}`, `{"errno":0}`, `{"errno":0,"status":"success"}`, `{"errno":0,"status":"unknown"}`} {
		var r ShareTransferTaskResponse
		if json.Unmarshal([]byte(body), &r) == nil {
			t.Errorf("invalid task accepted: %s", body)
		}
	}
	for _, body := range []string{`{"errno":0,"status":"pending"}`, `{"errno":0,"status":"running"}`, `{"errno":0,"status":"failed","task_errno":9}`, `{"errno":0,"status":"success","list":[]}`, `{"errno":0,"status":"success","list":[{"error_code":9}]}`, `{"errno":0,"status":"success","task_errno":9,"list":[{"error_code":0}]}`} {
		var r ShareTransferTaskResponse
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		if r.Completed() {
			t.Errorf("unfinished or failed task reported complete: %s", body)
		}
	}
	for _, body := range []string{`{}`, `{"errno":null}`, `{"errno":0}`, `{"errno":0,"list":null}`} {
		var r FileListResponse
		if json.Unmarshal([]byte(body), &r) == nil {
			t.Errorf("invalid listing accepted: %s", body)
		}
	}
	for _, body := range []string{`{}`, `{"errno":null}`} {
		var r ShareViewReportResponse
		if json.Unmarshal([]byte(body), &r) == nil {
			t.Errorf("invalid report accepted: %s", body)
		}
	}
}

func TestShareViewAcceptsActualCallbackAcknowledgementWithoutList(t *testing.T) {
	for _, body := range []string{`{"errno":0}`, `{"errno":0,"data":{}}`, `{"errno":0,"data":{"list":null}}`, `{"errno":0,"data":{"list":[]}}`} {
		client, err := NewAndroidAppClient(nativeShareTestProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) { return shareJSONResponse(req, body), nil })}))
		if err != nil {
			t.Fatal(err)
		}
		r, err := client.ReportShareView(context.Background(), &ShareViewOptions{OwnerUK: 202, ChainSURL: "fixturekey"})
		if err != nil || r == nil || r.Errno != 0 || r.HTTPStatus != 200 || r.Skipped {
			t.Fatalf("native callback acknowledgement rejected: %s err=%v", body, err)
		}
	}
}

func TestReportUserEndpointFieldsCannotBeOverwrittenByCommonCapture(t *testing.T) {
	profile := androidFixtureProfile()
	cfg := androidSignatureConfig()
	profile.UID = cfg.UID
	profile.ReportParams = map[string]string{"action": "ANDROID_ACTIVE_FRONTDESK", "channel_id": "observed-channel", "bind_uid": "observed-binding", "needrookie": "1", "fcm_token": "observed-fcm", "start_source": "observed-frontdesk", "push_on": "1", "backup_on ": "00"}
	profile.LegacyNativeParams = map[string]string{"app_id": "250528", "app_name": "observed-native-name"}
	for key := range profile.ReportParams {
		profile.LegacyNativeParams[key] = "wrong-cached-value"
	}
	for _, key := range []string{"source", "msg_id", "timestamp"} {
		profile.LegacyNativeParams[key] = "wrong-cached-value"
	}
	requests := 0
	client, err := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Path != "/api/report/user" || req.Method != http.MethodGet {
			t.Fatal("config refresh changed native endpoint")
		}
		q := req.URL.Query()
		for key, actual := range profile.ReportParams {
			if q.Get(key) != actual {
				t.Errorf("ReportUser endpoint field %s overwritten", key)
			}
		}
		if q.Has("source") || q.Has("msg_id") || q.Get("timestamp") == "wrong-cached-value" || q.Get("timestamp") == "" {
			t.Error("missing optional ReportUser fields or actual timestamp inherited stale values")
		}
		if q.Get("app_id") != "250528" || q.Get("app_name") != "observed-native-name" {
			t.Error("genuine native common application metadata lost")
		}
		return shareJSONResponse(req, `{"errno":0,"uinfo":"`+cfg.EncodedSK+`"}`), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	client.registrationConfirmed = true
	client.registrationFinished = true
	if err := client.RefreshAndroidAppConfig(context.Background()); err != nil || requests != 1 {
		t.Fatalf("ReportUser refresh failed: err=%v requests=%d", err, requests)
	}
}

func TestReferralTransferRetainsFailedWireEvidenceWithoutConfirmingAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"http_error_with_success_shaped_json", http.StatusServiceUnavailable, `{"errno":0,"taskid":7}`},
		{"http_error_with_non_json_body", http.StatusBadGateway, "private fixture gateway failure"},
		{"json_parse_error", http.StatusOK, "incomplete private fixture JSON"},
		{"legacy_response_schema_error", http.StatusOK, `{"errno":0}`},
		{"legacy_per_file_schema_error", http.StatusOK, `{"errno":0,"info":[{"path":"/saved/source.txt"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := nativeShareTestProfile()
			profile.UID = "12345"
			calls := 0
			client, err := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodPost || req.URL.Path != "/share/transfer" {
					t.Fatal("failed save unexpectedly invoked another operation")
				}
				response := shareJSONResponse(req, tc.body)
				response.StatusCode = tc.status
				return response, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			client.referral = &WebmasterReferral{ShareURL: "https://terabox.com/s/1fixture", ShareFromSURL: "fixture", ShareID: 101, WebmasterUK: 202}
			client.registrationFinished, client.registrationConfirmed = true, true
			response, err := client.TransferWebmasterReferral(context.Background(), &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/saved", Route: ShareTransferRouteShareDetailLegacy})
			if err == nil || response == nil || string(response.RawBody) != tc.body || calls != 1 {
				t.Fatalf("private failed save evidence lost: err=%v responseNil=%v requests=%d", err, response == nil, calls)
			}
			if json.Valid([]byte(tc.body)) {
				if string(response.Raw) != tc.body {
					t.Fatal("failed JSON wire envelope lost")
				}
			} else if len(response.Raw) != 0 {
				t.Fatal("invalid JSON bytes were wrapped as JSON")
			}
		})
	}
}

func TestNDUSOnlyReferralTransferSnapshotRemainsRestorable(t *testing.T) {
	profile := nativeShareTestProfile()
	requests := 0
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		switch req.URL.Path {
		case "/api/account/uinfo":
			return shareJSONResponse(req, `{"errno":0,"uk":901}`), nil
		case "/share/transfer":
			return shareJSONResponse(req, `{"errno":0,"taskid":7}`), nil
		default:
			return nil, errors.New("NDUS-only transfer invoked an unrelated endpoint")
		}
	})
	client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	saved := &WebmasterRegistrationSession{AndroidApp: &profile, WebHost: "https://www.terabox.com", Cookies: "ndus=fixture-session", NDUS: "fixture-session", FinishAttempted: true, Referral: WebmasterReferral{ShareURL: "https://terabox.com/s/1fixture", ShareFromSURL: "fixture", ShareID: 101, WebmasterUK: 202, Source: "share"}}
	if err := client.RestoreWebmasterRegistrationSession(saved); err != nil {
		t.Fatal(err)
	}
	response, err := client.TransferWebmasterReferral(context.Background(), &WebmasterTransferOptions{FSIDs: []int64{303}, Destination: "/saved", Route: ShareTransferRouteShareDetailLegacy})
	if err != nil || response == nil || response.TaskID != 7 || requests != 2 || client.Account().ID != 901 {
		t.Fatalf("verified NDUS-only transfer failed: err=%v requests=%d", err, requests)
	}
	snapshot := client.WebmasterRegistrationSession()
	if snapshot.RegistrationConfirmed || snapshot.AndroidApp.UID != "" || snapshot.NDUS != saved.NDUS || !snapshot.FinishAttempted {
		t.Fatal("account UK verification invented complete native registration identity")
	}
	restored, err := NewAndroidAppClient(*snapshot.AndroidApp)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreWebmasterRegistrationSession(snapshot); err != nil {
		t.Fatalf("SDK generated a snapshot that cannot restore: %v", err)
	}
	if restored.WebmasterRegistrationSession().RegistrationConfirmed || restored.AndroidAppProfile().UID != "" {
		t.Fatal("restore synthesized missing native registration identity")
	}
}
