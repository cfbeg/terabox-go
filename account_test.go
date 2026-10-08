package terabox

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type authTestTransport func(*http.Request) (*http.Response, error)

func (f authTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func authTestJSON(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func TestCheckLoginRejectsInvalidRegionPrefix(t *testing.T) {
	for _, prefix := range []string{
		"example.invalid/", "example.invalid?", "jp.foo", "jp:443", "foo@bar",
		" jp", "jp ", "-jp", "jp-", "_jp", "日本", strings.Repeat("a", 64),
	} {
		t.Run(prefix, func(t *testing.T) {
			calls := 0
			cli := NewClient("test-token", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				resp := authTestJSON(req, `{"errno":0,"uk":42}`)
				resp.Header.Set("region-domain-prefix", prefix)
				return resp, nil
			})}))
			before, _, _ := cli.snapshot()
			resp, err := cli.CheckLogin(context.Background())
			if err == nil || resp != nil {
				t.Fatalf("got response %v, error %v; want rejected region", resp, err)
			}
			if calls != 1 {
				t.Fatalf("made %d requests; want 1", calls)
			}
			after, _, _ := cli.snapshot()
			if after != before || cli.Account().ID != 0 {
				t.Fatalf("invalid region changed state: host=%q, account=%d", after, cli.Account().ID)
			}
		})
	}
}

func TestCheckLoginFollowsValidRegion(t *testing.T) {
	for _, prefix := range []string{"jp", "A", "region-1", strings.Repeat("a", 63)} {
		t.Run(prefix, func(t *testing.T) {
			calls := 0
			cli := NewClient("test-token", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Header.Get("Cookie") != "lang=en; ndus=test-token" {
					t.Fatalf("session cookie missing: %q", req.Header.Get("Cookie"))
				}
				resp := authTestJSON(req, `{"errno":0,"uk":42}`)
				if calls == 1 {
					resp.Header.Set("region-domain-prefix", prefix)
				} else if req.URL.Host != prefix+"."+TeraBoxDomain {
					t.Fatalf("regional host = %q", req.URL.Host)
				}
				return resp, nil
			})}))
			resp, err := cli.CheckLogin(context.Background())
			if err != nil || resp == nil || resp.UK != 42 || calls != 2 || cli.Account().ID != 42 {
				t.Fatalf("response=%v error=%v requests=%d account=%+v", resp, err, calls, cli.Account())
			}
		})
	}
}

func TestGetCurrentUserInfoPreservesLoginFailure(t *testing.T) {
	calls := 0
	cli := NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Path != "/api/check/login" {
			t.Fatalf("unexpected request to %s", req.URL.Path)
		}
		return authTestJSON(req, `{"errno":-6,"show_msg":"login required"}`), nil
	})}))
	resp, err := cli.GetCurrentUserInfo(context.Background())
	var apiErr *APIError
	if resp != nil || !errors.As(err, &apiErr) || apiErr.Code != -6 || apiErr.Message != "login required" {
		t.Fatalf("response=%v error=%v; want original login failure", resp, err)
	}
	if calls != 1 {
		t.Fatalf("made %d requests; want 1", calls)
	}
	// The single-endpoint method still returns the API result without a Go error.
	login, err := cli.CheckLogin(context.Background())
	if err != nil || login.Errno != -6 {
		t.Fatalf("CheckLogin changed its API error contract: response=%v error=%v", login, err)
	}
}

func TestGetCurrentUserInfoDoesNotCacheFailedRecords(t *testing.T) {
	cli := NewClient("", WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
		return authTestJSON(req, `{"errno":-6,"records":[{"uk":42,"uname":"invalid","vip_type":2}]}`), nil
	})}))
	cli.updateParams(func(p *accountParams) {
		p.accountID = 42
		p.accountName = "original"
	})
	resp, err := cli.GetCurrentUserInfo(context.Background())
	if err != nil || resp.Errno != -6 {
		t.Fatalf("response=%v error=%v", resp, err)
	}
	account := cli.Account()
	if account.Name != "original" || account.IsVIP || account.VIPType != 0 {
		t.Fatalf("failed response changed account: %+v", account)
	}
}
