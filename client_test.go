package terabox

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type clientRoundTripFunc func(*http.Request) (*http.Response, error)

func (f clientRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
func clientResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestRequestTimeoutHonorsEarlierDeadline(t *testing.T) {
	for _, test := range []struct {
		name            string
		parent, timeout time.Duration
		callerWins      bool
	}{
		{"request deadline", time.Minute, time.Second, false},
		{"caller deadline", time.Second, time.Minute, true},
		{"disabled timeout", time.Minute, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), test.parent)
			defer cancel()
			parentDeadline, _ := ctx.Deadline()
			var requestCtx context.Context
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requestCtx = req.Context()
				return clientResponse(req, http.StatusOK, ""), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.terabox.com/share/list", nil)
			before := time.Now()
			response, err := client.doHTTP(req, test.timeout)
			if err != nil {
				t.Fatal(err)
			}
			deadline, ok := requestCtx.Deadline()
			if !ok || (test.callerWins && !deadline.Equal(parentDeadline)) || (!test.callerWins && (deadline.After(before.Add(test.timeout+time.Second)) || !deadline.Before(parentDeadline))) {
				t.Fatal("incorrect request deadline")
			}
			if requestCtx.Err() != nil {
				t.Fatal("request canceled before body close")
			}
			response.Body.Close()
			if test.timeout > 0 && !errors.Is(requestCtx.Err(), context.Canceled) {
				t.Fatal("timeout context was not released")
			}
			if ctx.Err() != nil {
				t.Fatal("body close canceled caller context")
			}
		})
	}
}

func TestAndroidTransportRejectsUnprofiledAndUnsupportedPaths(t *testing.T) {
	requests := 0
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return clientResponse(req, http.StatusOK, ""), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/main", "/wap/outlogin/login", "/api/check/login", "/api/upload", "/share/webmaster/operateplan"} {
		req, _ := http.NewRequest(http.MethodGet, "https://www.terabox.com"+path, nil)
		if _, err := client.doHTTP(req, 0); err == nil {
			t.Errorf("unsupported path %s was accepted", path)
		}
	}
	var zero Client
	req, _ := http.NewRequest(http.MethodGet, "https://www.terabox.com/share/list", nil)
	if _, err := zero.doHTTP(req, 0); err == nil {
		t.Fatal("unprofiled client reached HTTP")
	}
	if requests != 0 {
		t.Fatal("unsupported request reached the transport")
	}
}

func TestAndroidHyRedirectFailureDoesNotCommitState(t *testing.T) {
	for _, target := range []string{"https://unrelated.invalid/wap/hylogin/emailRegister", "https://www.terabox.com/main", "http://www.terabox.com/wap/hylogin/emailRegister"} {
		t.Run(target, func(t *testing.T) {
			calls := 0
			profile := androidFixtureProfile()
			profile.PSign = "fixture-psign"
			client, err := NewAndroidAppClient(profile, WithCookies("ndus=existing-session"), WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				response := clientResponse(req, http.StatusFound, "")
				response.Header.Set("Location", target)
				response.Header.Add("Set-Cookie", "ndus=replacement-session")
				return response, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			before, cookies := client.snapshot()
			if err := client.loadAndroidHyPage(context.Background()); err == nil {
				t.Fatal("non-APK redirect accepted")
			}
			after, current := client.snapshot()
			if calls != 1 || before != after || cookies != current {
				t.Fatal("failed redirect changed saved state")
			}
		})
	}
}

func TestCustomClientKeepsAPKCookieAndRedirectPolicy(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	origin, _ := url.Parse("https://www.terabox.com")
	jar.SetCookies(origin, []*http.Cookie{{Name: "ndus", Value: "external-jar-session"}})
	redirects := 0
	supplied := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { redirects++; return nil },
		Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Cookie") != "ndus=internal-session" {
				t.Error("external cookie jar changed the APK session")
			}
			return clientResponse(req, http.StatusOK, `{"errno":0,"uk":"42"}`), nil
		})}
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithCookies("ndus=internal-session"), WithHTTPClient(supplied))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CheckLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.httpClient.CheckRedirect(nil, nil) != http.ErrUseLastResponse || redirects != 0 || supplied.Jar != jar || jar.Cookies(origin)[0].Value != "external-jar-session" {
		t.Fatal("supplied client was modified or redirect policy lost")
	}
	if _, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(nil)); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitLocalAPKAPIHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/account/uinfo" || req.Method != http.MethodPost {
			t.Error("unexpected APK account request")
		}
		io.WriteString(w, `{"errno":0,"uk":"42"}`)
	}))
	defer server.Close()
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithAPIHost(server.URL), WithCookies("ndus=fixture-session"), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CheckLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
}
