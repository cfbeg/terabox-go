package terabox

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func nativeShareTestProfile() AndroidAppProfile {
	return AndroidAppProfile{DeviceID: "captured-fixture-cuid", Version: AndroidAPKVersion,
		UserAgent:     "dubox;4.26.5;fixture;android-android;11;JSbridge1.0.10;jointbridge;1.1.39;",
		NativeChannel: "android_11_fixture_bd-dubox_1024074p", Channel: "hy-fixture-channel",
		Language: "en_US", ClientType: 1,
		PageURL: "https://www.terabox.com/wap/hylogin/emailRegister?type=1&channel=hy-fixture-channel"}
}

func checkNativeShareRequest(t *testing.T, req *http.Request, bareRand bool) {
	t.Helper()
	query := req.URL.Query()
	for _, key := range []string{"web", "jsToken", "bdstoken", "by", "order", "dp-logid"} {
		if query.Has(key) {
			t.Errorf("native request carried Web-only field %s", key)
		}
	}
	if query.Get("clienttype") != "1" || query.Get("devuid") != "captured-fixture-cuid" ||
		query.Get("version") != AndroidAPKVersion || query.Get("channel") != "android_11_fixture_bd-dubox_1024074p" {
		t.Errorf("native request lost its app profile: %v", query)
	}
	if req.Header.Get("User-Agent") != nativeShareTestProfile().UserAgent || req.Header.Get("Referer") != "https://terabox.com/" ||
		req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || req.Header.Get("X-Requested-With") != "" || req.Header.Get("Accept") != "" {
		t.Errorf("native request has incorrect headers: %v", req.Header)
	}
	hasBare := false
	for _, item := range strings.Split(req.URL.RawQuery, "&") {
		hasBare = hasBare || item == "rand"
	}
	if hasBare != bareRand || (!bareRand && query.Has("rand")) {
		t.Errorf("native guest rand shape = %q, want bare=%t", req.URL.RawQuery, bareRand)
	}
}

func TestAndroidAppShareMetadataMatchesNativeCallers(t *testing.T) {
	for _, endpoint := range []string{"/api/shorturlinfo", "/share/list"} {
		t.Run(endpoint, func(t *testing.T) {
			calls := 0
			client, err := NewAndroidAppClient(nativeShareTestProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Path != endpoint || req.Method != http.MethodGet {
					return nil, errors.New("native metadata unexpectedly bootstrapped a Web page")
				}
				checkNativeShareRequest(t, req, endpoint == "/share/list")
				q := req.URL.Query()
				if q.Get("root") != "1" || !q.Has("bot_uk") || q.Get("bot_uk") != "" {
					t.Errorf("native metadata lost root or bot fields: %v", q)
				}
				if endpoint == "/api/shorturlinfo" {
					if q.Get("shorturl") != "1fixture-key" || q.Get("type") != "0" || q.Has("scene") {
						t.Errorf("legacy native short-url request changed: %v", q)
					}
				} else if q.Get("shorturl") != "fixture-key" || q.Get("page") != "0" || q.Get("num") != "100" ||
					!q.Has("dir") || q.Get("dir") != "" || !q.Has("scene") || q.Get("timestamp") != "1791680000" || q.Has("app_id") {
					t.Errorf("native root-list request changed: %v", q)
				}
				return shareJSONResponse(req, `{"errno":0,"share_id":"101","uk":"202","list":[{"fs_id":"303","category":"6"}]}`), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			client.androidApp.now = func() time.Time { return time.UnixMilli(1791680000123) }
			var response *ShareInfoResponse
			if endpoint == "/api/shorturlinfo" {
				response, err = client.GetShareInfo(context.Background(), "fixture-key")
			} else {
				response, err = client.GetShareList(context.Background(), "fixture-key", 1)
			}
			if err != nil || response == nil || response.ShareID != 101 || calls != 1 {
				t.Fatalf("native metadata response=%v error=%v requests=%d", response, err, calls)
			}
		})
	}
}

func TestAndroidAppTransferUsesNativeFormWithoutWebBootstrap(t *testing.T) {
	calls := 0
	client, err := NewAndroidAppClient(nativeShareTestProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Path != "/share/transfer" || req.Method != http.MethodPost {
			return nil, errors.New("native transfer unexpectedly bootstrapped a Web page")
		}
		checkNativeShareRequest(t, req, true)
		if err := req.ParseForm(); err != nil {
			return nil, err
		}
		q := req.URL.Query()
		if q.Get("shareid") != "101" || q.Get("from") != "202" || !q.Has("bot_uk") ||
			q.Has("async") || q.Has("ondup") || q.Has("app_id") || req.PostForm.Get("async") != "1" ||
			req.PostForm.Get("ondup") != "newcopy" || req.PostForm.Get("path") != "/saved" || req.PostForm.Get("fsidlist") != "[303, 304]" {
			t.Errorf("native transfer query/form differ from IApi.d: query=%v form=%v", q, req.PostForm)
		}
		cookie, err := req.Cookie("ndus")
		if err != nil || cookie.Value != "fixture-session" {
			t.Error("native transfer lost its authenticated cookie")
		}
		return shareJSONResponse(req, `{"errno":0,"task_id":7}`), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	client.mergeCookies([]*http.Cookie{{Name: "ndus", Value: "fixture-session"}})
	response, err := client.TransferShare(context.Background(), 101, 202, []int64{303, 304}, "/saved", nil)
	if err != nil || response == nil || response.TaskID != 7 || calls != 1 {
		t.Fatalf("native transfer response=%v error=%v requests=%d", response, err, calls)
	}
}
