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

type shareRoundTripFunc func(*http.Request) (*http.Response, error)

func (f shareRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func shareJSONResponse(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func TestShareMetadataRequestShapesAndCookies(t *testing.T) {
	for _, test := range []struct {
		name string
		list bool
		body string
	}{
		{name: "metadata", body: `{"errno":0,"request_id":9007199254740993,"shareid":"123","uk_str":"456","list":[{"fs_id":789,"path":"/shared.bin"}]}`},
		{name: "list", list: true, body: `{"errno":0,"request_id":9007199254740993,"share_id":123,"uk":456,"list":[{"fs_id":789,"path":"/shared.bin"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			c := NewClient("saved-session", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodGet {
					t.Fatalf("method=%q", req.Method)
				}
				wantPath := "/api/shorturlinfo"
				wantKey := "11key_-"
				if test.list {
					wantPath = "/share/list"
					wantKey = "1key_-"
				}
				query := req.URL.Query()
				if req.URL.Path != wantPath || query.Get("shorturl") != wantKey || query.Get("root") != "1" {
					t.Fatalf("unexpected request: %s", req.URL)
				}
				if query.Get("jsToken") != "local-token" || query.Get("dp-logid") != "local-log" || query.Get("app_id") != "250528" || query.Get("web") != "1" || query.Get("channel") != "dubox" || query.Get("clienttype") != "0" {
					t.Fatalf("missing common params: %v", query)
				}
				if test.list && (query.Get("page") != "2" || query.Get("num") != "20000" || query.Get("by") != "name" || query.Get("order") != "asc") {
					t.Fatalf("unexpected list params: %v", query)
				}
				if _, ok := query["scene"]; !ok || query.Get("scene") != "" {
					t.Fatalf("unexpected scene: %v", query)
				}
				if !strings.Contains(req.Header.Get("Cookie"), "ndus=saved-session") || req.Header.Get("X-Requested-With") != "XMLHttpRequest" {
					t.Fatalf("missing client headers: %v", req.Header)
				}
				if req.Header.Get("Referer") != "https://www.terabox.com" {
					t.Fatalf("unexpected ordinary metadata Referer: %q", req.Header.Get("Referer"))
				}
				response := shareJSONResponse(req, test.body)
				response.Header.Add("Set-Cookie", "BDCLND=visitor-proof; Path=/; Secure")
				return response, nil
			})}))
			c.updateData(func(data *appData) { data.jsToken = "local-token"; data.logID = "local-log" })
			var response *ShareInfoResponse
			var err error
			if test.list {
				response, err = c.GetShareList(context.Background(), "1key_-", 2)
			} else {
				response, err = c.GetShareInfo(context.Background(), "1key_-")
			}
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || response.ShareID != 123 || response.UK != 456 || string(response.RequestID) != "9007199254740993" || len(response.List) != 1 || response.List[0].FSID != 789 {
				t.Fatalf("unexpected metadata: %+v; calls=%d", response, calls)
			}
			if value, ok := c.CookieValue("BDCLND"); !ok || value != "visitor-proof" {
				t.Fatalf("visitor cookie not retained: value=%q exists=%v", value, ok)
			}
		})
	}
}

func TestShareMetadataWorksWithoutLoginToken(t *testing.T) {
	for _, list := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "list"}[list], func(t *testing.T) {
			c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				wantPath, wantKey := "/api/shorturlinfo", "1normalized"
				if list {
					wantPath, wantKey = "/share/list", "normalized"
				}
				query := req.URL.Query()
				if req.Method != http.MethodGet || req.URL.Path != wantPath || query.Get("shorturl") != wantKey || query.Get("root") != "1" {
					t.Fatalf("unexpected unauthenticated request: %s %s", req.Method, req.URL)
				}
				if query.Has("web") || query.Has("jsToken") {
					t.Fatalf("anonymous metadata sent web or an empty token: %v", query)
				}
				if query.Get("app_id") != "250528" || query.Get("channel") != "dubox" || query.Get("clienttype") != "0" || query.Get("dp-logid") != "0" || !query.Has("scene") || query.Get("scene") != "" {
					t.Fatalf("anonymous metadata lost common params: %v", query)
				}
				if list && (query.Get("page") != "1" || query.Get("num") != "20000" || query.Get("by") != "name" || query.Get("order") != "asc") {
					t.Fatalf("anonymous metadata lost list params: %v", query)
				}
				if req.Header.Get("Cookie") != "lang=en" || req.Header.Get("Referer") != "https://www.terabox.com" || req.Header.Get("X-Requested-With") != "XMLHttpRequest" {
					t.Fatalf("anonymous metadata headers changed: %v", req.Header)
				}
				return shareJSONResponse(req, `{"errno":0,"share_id":123,"uk":456,"list":[]}`), nil
			})}))
			var response *ShareInfoResponse
			var err error
			if list {
				response, err = c.GetShareList(context.Background(), "normalized", 0)
			} else {
				response, err = c.GetShareInfo(context.Background(), "normalized")
			}
			if err != nil || response.List == nil || len(response.List) != 0 {
				t.Fatalf("empty public share list: response=%+v err=%v", response, err)
			}
		})
	}
}

func TestShareMetadataPreservesAPIErrors(t *testing.T) {
	for _, list := range []bool{false, true} {
		c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return shareJSONResponse(req, `{"errno":400210,"errmsg":"need verify_v2","request_id":123}`), nil
		})}))
		var response *ShareInfoResponse
		var err error
		if list {
			response, err = c.GetShareList(context.Background(), "normalized", 1)
		} else {
			response, err = c.GetShareInfo(context.Background(), "normalized")
		}
		if err != nil || response.Errno != 400210 || response.ErrMsg != "need verify_v2" {
			t.Fatalf("API error lost: response=%+v err=%v", response, err)
		}
	}
}

func TestShareMetadataRejectsMalformedResponsesBeforeCookies(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"errno":null}`, `{"errno":0}`, `{"errno":0,"share_id":123,"uk":456}`, `{"errno":0,"share_id":123,"uk":456,"list":null}`, `{"errno":0,"shareid":123,"uk_str":"bad"}`, `{"errno":0,`, `<html>404</html>`} {
		t.Run(body, func(t *testing.T) {
			c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				response := shareJSONResponse(req, body)
				response.Header.Add("Set-Cookie", "BDCLND=wrong; Path=/")
				return response, nil
			})}))
			if response, err := c.GetShareList(context.Background(), "normalized", 1); err == nil || response != nil {
				t.Fatalf("malformed body accepted: response=%+v err=%v", response, err)
			}
			if _, exists := c.CookieValue("BDCLND"); exists {
				t.Fatal("cookie was retained from invalid metadata")
			}
		})
	}
}

func TestShareMetadataValidatesKeysBeforeNetwork(t *testing.T) {
	var calls int
	c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return shareJSONResponse(req, `{}`), nil
	})}))
	for _, key := range []string{"", "https://www.terabox.com/s/1key", "/key", "key?x=1", "key#fragment", "key\n", "日本語"} {
		if _, err := c.GetShareInfo(context.Background(), key); err == nil {
			t.Errorf("metadata accepted key %q", key)
		}
		if _, err := c.GetShareList(context.Background(), key, 1); err == nil {
			t.Errorf("list accepted key %q", key)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid keys caused %d requests", calls)
	}
}

func TestTransferShareRequestAndResponse(t *testing.T) {
	for _, onDup := range []string{"", "newcopy"} {
		t.Run(onDup, func(t *testing.T) {
			var calls int
			c := NewClient("saved-session", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodPost || req.URL.Path != "/share/transfer" {
					t.Fatalf("unexpected transfer request: %s %s", req.Method, req.URL)
				}
				query := req.URL.Query()
				wantOnDup := onDup
				if wantOnDup == "" {
					wantOnDup = "newcopy"
				}
				if query.Get("shareid") != "123" || query.Get("from") != "456" || query.Get("ondup") != wantOnDup || query.Get("async") != "1" || query.Get("jsToken") != "local-token" || query.Get("dp-logid") != "local-log" {
					t.Fatalf("unexpected transfer query: %v", query)
				}
				if query.Get("web") != "1" {
					t.Fatal("authenticated transfer lost its web flag")
				}
				if _, exists := query["scene"]; exists {
					t.Fatal("purchased_list scene added to ordinary transfer")
				}
				if req.Header.Get("Referer") != "https://www.terabox.com" || req.Header.Get("X-Requested-With") != "XMLHttpRequest" {
					t.Fatalf("unexpected ordinary transfer headers: %v", req.Header)
				}
				if err := req.ParseForm(); err != nil {
					return nil, err
				}
				if req.PostForm.Get("fsidlist") != "[789,790]" || req.PostForm.Get("path") != "/日本語 folder" || len(req.PostForm) != 2 {
					t.Fatalf("unexpected transfer form: %v", req.PostForm)
				}
				return shareJSONResponse(req, `{"errno":0,"request_id":"9007199254740993","task_id":"987","extra":{"list":[{"fs_id":789}]}}`), nil
			})}))
			c.updateData(func(data *appData) { data.jsToken = "local-token"; data.logID = "local-log" })
			response, err := c.TransferShare(context.Background(), 123, 456, []int64{789, 790}, "/日本語 folder", &ShareTransferOptions{OnDup: onDup})
			if err != nil || response.Errno != 0 || response.TaskID != 987 || string(response.RequestID) != "9007199254740993" || calls != 1 {
				t.Fatalf("unexpected transfer result: response=%+v err=%v calls=%d", response, err, calls)
			}
			var extra struct{ List []FileEntry }
			if err := json.Unmarshal(response.Extra, &extra); err != nil || len(extra.List) != 1 || extra.List[0].FSID != 789 {
				t.Fatalf("extra was lost: %s err=%v", response.Extra, err)
			}
		})
	}
}

func TestTransferSharePreservesAPIErrorsWithoutRetry(t *testing.T) {
	var calls int
	c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Query().Get("web") != "1" {
			t.Fatal("transfer without ndus lost its existing web flag")
		}
		return shareJSONResponse(req, `{"errno":400810,"errmsg":"token rejected","request_id":123}`), nil
	})}))
	c.updateData(func(data *appData) { data.jsToken = "local-token" })
	response, err := c.TransferShare(context.Background(), 123, 456, []int64{789}, "/", nil)
	if err != nil || response.Errno != 400810 || response.ErrMsg != "token rejected" || calls != 1 {
		t.Fatalf("API result changed: response=%+v err=%v calls=%d", response, err, calls)
	}
}

func TestTransferShareAcceptsAsyncAndCompletedResults(t *testing.T) {
	for _, body := range []string{
		`{"errno":0,"task_id":"987"}`,
		`{"errno":0,"extra":{"list":[{"from_fs_id":789,"to_fs_id":790}]}}`,
	} {
		t.Run(body, func(t *testing.T) {
			c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				return shareJSONResponse(req, body), nil
			})}))
			c.updateData(func(data *appData) { data.jsToken = "local-token" })
			if response, err := c.TransferShare(context.Background(), 123, 456, []int64{789}, "/", nil); err != nil || response.Errno != 0 {
				t.Fatalf("valid result rejected: response=%+v err=%v", response, err)
			}
		})
	}
}

func TestTransferShareRejectsMissingStatus(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"errno":null}`, `{"errno":"0"}`, `{"errno":0}`, `{"errno":0,"task_id":0,"extra":{}}`, `{"errno":0,"extra":null}`, `{"errno":0,`, `<html>404</html>`} {
		t.Run(body, func(t *testing.T) {
			c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				return shareJSONResponse(req, body), nil
			})}))
			c.updateData(func(data *appData) { data.jsToken = "local-token" })
			if response, err := c.TransferShare(context.Background(), 123, 456, []int64{789}, "/", nil); err == nil || response != nil {
				t.Fatalf("malformed transfer response accepted: response=%+v err=%v", response, err)
			}
		})
	}
}

func TestTransferShareValidatesBeforeNetwork(t *testing.T) {
	for _, test := range []struct {
		name    string
		shareID int64
		ownerUK int64
		ids     []int64
		dest    string
		onDup   string
	}{
		{name: "zero share", ownerUK: 456, ids: []int64{789}, dest: "/"},
		{name: "negative share", shareID: -123, ownerUK: 456, ids: []int64{789}, dest: "/"},
		{name: "zero owner", shareID: 123, ids: []int64{789}, dest: "/"},
		{name: "nil files", shareID: 123, ownerUK: 456, dest: "/"},
		{name: "empty files", shareID: 123, ownerUK: 456, ids: []int64{}, dest: "/"},
		{name: "invalid file", shareID: 123, ownerUK: 456, ids: []int64{789, -1}, dest: "/"},
		{name: "empty destination", shareID: 123, ownerUK: 456, ids: []int64{789}},
		{name: "relative destination", shareID: 123, ownerUK: 456, ids: []int64{789}, dest: "folder"},
		{name: "parent directory", shareID: 123, ownerUK: 456, ids: []int64{789}, dest: "/../folder"},
		{name: "current directory", shareID: 123, ownerUK: 456, ids: []int64{789}, dest: "/./folder"},
		{name: "control character", shareID: 123, ownerUK: 456, ids: []int64{789}, dest: "/folder\x00"},
		{name: "backslash", shareID: 123, ownerUK: 456, ids: []int64{789}, dest: "/folder\\sub"},
		{name: "invalid duplication option", shareID: 123, ownerUK: 456, ids: []int64{789}, dest: "/", onDup: "anything"},
		{name: "unverified skip", shareID: 123, ownerUK: 456, ids: []int64{789}, dest: "/", onDup: "skip"},
		{name: "unverified overwrite", shareID: 123, ownerUK: 456, ids: []int64{789}, dest: "/", onDup: "overwrite"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return shareJSONResponse(req, `{}`), nil
			})}))
			if _, err := c.TransferShare(context.Background(), test.shareID, test.ownerUK, test.ids, test.dest, &ShareTransferOptions{OnDup: test.onDup}); err == nil {
				t.Fatal("invalid input accepted")
			}
			if calls != 0 {
				t.Fatalf("invalid input caused %d requests", calls)
			}
		})
	}
}

func TestShareMetadataNetworkErrorsDoNotChangeCookies(t *testing.T) {
	transportFailure := errors.New("connection interrupted")
	for _, test := range []struct {
		name   string
		status int
		err    error
	}{
		{name: "transport", err: transportFailure},
		{name: "HTTP failure", status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := NewClient("", WithCookies("BDCLND=old-proof"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if test.err != nil {
					return nil, test.err
				}
				response := shareJSONResponse(req, `{"errno":0,"share_id":123,"uk":456,"list":[]}`)
				response.StatusCode = test.status
				response.Header.Add("Set-Cookie", "BDCLND=wrong; Path=/")
				return response, nil
			})}))
			_, err := c.GetShareList(context.Background(), "normalized", 1)
			if err == nil || test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("network error lost: %v", err)
			}
			if value, _ := c.CookieValue("BDCLND"); value != "old-proof" {
				t.Fatal("cookie changed after failed request")
			}
		})
	}
}

func TestShareRequestsUsePreparedReferralReferer(t *testing.T) {
	const source = "https://terabox.com/s/1normalized"
	var calls int
	c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("Referer") != source || req.Header.Get("X-Requested-With") != "XMLHttpRequest" {
			t.Fatalf("referral request headers: %v", req.Header)
		}
		if req.URL.Path == "/share/transfer" {
			return shareJSONResponse(req, `{"errno":0,"task_id":987}`), nil
		}
		return shareJSONResponse(req, `{"errno":0,"shareid":123,"uk":456,"list":[]}`), nil
	})}))
	c.updateData(func(data *appData) { data.jsToken = "local-token" })
	c.mu.Lock()
	c.referral = &WebmasterReferral{ShareURL: source, ShareFromSURL: "normalized", ShareID: 123, WebmasterUK: 456}
	c.mu.Unlock()
	if _, err := c.GetShareInfo(context.Background(), "normalized"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetShareList(context.Background(), "normalized", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TransferShare(context.Background(), 123, 456, []int64{789}, "/", nil); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("requests=%d; want 3", calls)
	}
}
