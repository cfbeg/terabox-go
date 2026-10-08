package terabox

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestDownloadRejectsIncompleteHomeInfo(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"errno":0,"data":{}}`,
		`{"errno":0,"data":{"sign1":"Plaintext","timestamp":1}}`,
		`{"errno":0,"data":{"sign3":"Key","timestamp":1}}`,
		`{"errno":0,"data":{"sign1":"Plaintext","sign3":"Key"}}`,
		`{"errno":0,"data":{"sign1":"Plaintext","sign3":"Key","timestamp":-1}}`,
	} {
		t.Run(body, func(t *testing.T) {
			calls := 0
			cli := NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Path != "/api/home/info" {
					t.Fatalf("download proceeded after malformed home info: %s", req.URL.Path)
				}
				return authTestJSON(req, body), nil
			})}))
			resp, err := cli.Download(context.Background(), []int64{1})
			if err == nil || resp != nil || calls != 1 {
				t.Fatalf("response=%v error=%v requests=%d", resp, err, calls)
			}
		})
	}
}

func TestDownloadUsesHomeInfoSigningFields(t *testing.T) {
	calls := 0
	cli := NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Path == "/api/home/info" {
			return authTestJSON(req, `{"errno":0,"data":{"sign1":"Plaintext","sign3":"Key","timestamp":123}}`), nil
		}
		if req.URL.Path != "/api/download" {
			t.Fatalf("unexpected request to %s", req.URL.Path)
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if req.Form.Get("sign") != "u/MW6NlArwrT" || req.Form.Get("timestamp") != "123" || req.Form.Get("fidlist") != "[1,2]" {
			t.Fatalf("incorrect download form: %v", req.Form)
		}
		return authTestJSON(req, `{"errno":0,"dlink":[]}`), nil
	})}))
	resp, err := cli.Download(context.Background(), []int64{1, 2})
	if err != nil || resp == nil || resp.Errno != 0 || calls != 2 {
		t.Fatalf("response=%v error=%v requests=%d", resp, err, calls)
	}
}

func TestDownloadPreservesHomeInfoFailure(t *testing.T) {
	calls := 0
	cli := NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		return authTestJSON(req, `{"errno":-6}`), nil
	})}))
	resp, err := cli.Download(context.Background(), []int64{1})
	var apiErr *APIError
	if resp != nil || !errors.As(err, &apiErr) || apiErr.Code != -6 || calls != 1 {
		t.Fatalf("response=%v error=%v requests=%d", resp, err, calls)
	}
	// A nonzero errno remains a normal response from the single endpoint.
	home, err := cli.GetHomeInfo(context.Background())
	if err != nil || home.Errno != -6 {
		t.Fatalf("GetHomeInfo changed its API error contract: response=%v error=%v", home, err)
	}
}
