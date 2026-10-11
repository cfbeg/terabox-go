package terabox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type shareRoundTripFunc func(*http.Request) (*http.Response, error)

func (f shareRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
func shareJSONResponse(req *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestAPKShareReplyValidation(t *testing.T) {
	for _, body := range []string{`{}`, `{"errno":0}`, `{"errno":0,"share_id":101,"uk":202}`, `{"errno":0,"share_id":101,"uk":202,"list":null}`} {
		client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) { return shareJSONResponse(req, body), nil })}))
		if _, err := client.GetShareList(context.Background(), "fixture", 1); err == nil {
			t.Errorf("invalid APK share body accepted: %s", body)
		}
	}
	var transfer ShareTransferResponse
	if err := json.Unmarshal([]byte(`{}`), &transfer); err == nil {
		t.Fatal("transfer status was silently defaulted")
	}
}

func TestAPKTransferSelectionValidatedBeforeRequest(t *testing.T) {
	client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("invalid selection must stop before HTTP")
		return nil, nil
	})}))
	for _, test := range []struct {
		ids         []int64
		destination string
		policy      string
	}{
		{nil, "/", "newcopy"}, {[]int64{0}, "/", "newcopy"}, {[]int64{303}, "relative", "newcopy"},
		{[]int64{303}, "/a/../b", "newcopy"}, {[]int64{303}, "/", "overwrite"},
	} {
		if _, err := client.TransferShare(context.Background(), 101, 202, test.ids, test.destination, &ShareTransferOptions{OnDup: test.policy}); err == nil {
			t.Fatal("invalid native transfer was accepted")
		}
	}
}
