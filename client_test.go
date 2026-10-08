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

func (f clientRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func clientResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

const clientPage = `<script>var templateData = {"csrf":"new-csrf","pcftoken":"new-pcf","bdstoken":"new-bds","jsToken":"new-js","uk":123,"userVipIdentity":0};</script>`

func TestRequestTimeoutHonorsEarlierDeadline(t *testing.T) {
	for _, tc := range []struct {
		name            string
		parent, timeout time.Duration
		callerWins      bool
	}{
		{"request deadline", time.Minute, time.Second, false},
		{"caller deadline", time.Second, time.Minute, true},
		{"disabled timeout", time.Minute, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.parent)
			defer cancel()
			parentDeadline, _ := ctx.Deadline()
			var requestCtx context.Context
			c := NewClient("", WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				requestCtx = r.Context()
				return clientResponse(r, http.StatusOK, ""), nil
			})}))
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.terabox.com/main", nil)
			if err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			resp, err := c.doHTTP(req, tc.timeout)
			if err != nil {
				t.Fatal(err)
			}
			deadline, ok := requestCtx.Deadline()
			if !ok || (tc.callerWins && !deadline.Equal(parentDeadline)) ||
				(!tc.callerWins && (deadline.After(before.Add(tc.timeout+time.Second)) || !deadline.Before(parentDeadline))) {
				t.Fatalf("incorrect request deadline: %v, caller: %v", deadline, parentDeadline)
			}
			if requestCtx.Err() != nil {
				t.Fatalf("request canceled before response body was closed: %v", requestCtx.Err())
			}
			resp.Body.Close()
			if tc.timeout > 0 && !errors.Is(requestCtx.Err(), context.Canceled) {
				t.Fatalf("internal request context not canceled on close: %v", requestCtx.Err())
			}
			if ctx.Err() != nil {
				t.Fatalf("caller context canceled by body close: %v", ctx.Err())
			}
		})
	}
}

func TestUpdateAppDataPreservesStateOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"HTTP error", http.StatusInternalServerError, clientPage},
		{"invalid JSON", http.StatusOK, `<script>var templateData = {broken};</script>`},
		{"missing template", http.StatusOK, "<html>temporary error</html>"},
		{"empty template", http.StatusOK, `<script>var templateData = {};</script>`},
		{"missing main token", http.StatusOK, `<script>var templateData = {"pcftoken":"new-pcf"};</script>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient("old-session", WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				res := clientResponse(r, tc.status, tc.body)
				res.Header.Set("Set-Cookie", "ndus=replacement-session")
				return res, nil
			})}))
			old := appData{csrf: "old-csrf", pcfToken: "old-pcf", bdsToken: "old-bds", jsToken: "old-js", logID: "old-log"}
			c.updateData(func(d *appData) { *d = old })
			c.updateParams(func(p *accountParams) { p.accountID, p.isVIP, p.vipType = 42, true, 2 })
			oldAccount := c.Account()
			if _, err := c.UpdateAppData(context.Background(), ""); err == nil {
				t.Fatal("invalid page was accepted")
			}
			if c.dataSnapshot() != old || c.Account() != oldAccount {
				t.Fatal("failed page refresh changed cached session or account state")
			}
			if cookie, _ := c.CookieValue("ndus"); cookie != "old-session" {
				t.Fatal("failed page refresh replaced the session cookie")
			}
		})
	}
}

func TestUpdateAppDataLoginPagePreservesUnrelatedTokens(t *testing.T) {
	c := NewClient("", WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return clientResponse(r, http.StatusOK, `<script>var templateData = {"pcftoken":"login-pcf"};</script>`), nil
	})}))
	c.updateData(func(d *appData) { d.jsToken, d.bdsToken = "existing-js", "existing-bds" })
	c.updateParams(func(p *accountParams) { p.accountID = 42 })
	if _, err := c.UpdateAppData(context.Background(), "wap/outlogin/login"); err != nil {
		t.Fatal(err)
	}
	d := c.dataSnapshot()
	if d.pcfToken != "login-pcf" || d.jsToken != "existing-js" || d.bdsToken != "existing-bds" || c.Account().ID != 42 {
		t.Fatalf("partial page erased unrelated state: %+v, %+v", d, c.Account())
	}
}

func TestUpdateAppDataRegionalRedirectsWithCustomClient(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			originalRedirectCalls := 0
			h := &http.Client{
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error { originalRedirectCalls++; return nil },
				Transport: clientRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						res := clientResponse(r, status, "")
						res.Header.Set("Location", "https://regional.terabox.com/main")
						res.Header.Set("Set-Cookie", "browserid=redirect-state; Secure; Path=/")
						return res, nil
					}
					if r.URL.Host != "regional.terabox.com" || !strings.Contains(r.Header.Get("Cookie"), "browserid=redirect-state") ||
						!strings.Contains(r.Header.Get("Cookie"), "ndus=test-session") {
						t.Errorf("regional request lost host or session cookies: %s, %s", r.URL, r.Header.Get("Cookie"))
					}
					return clientResponse(r, http.StatusOK, clientPage), nil
				}),
			}
			c := NewClient("test-session", WithHTTPClient(h))
			c.SetVIPDefaults()
			if _, err := c.UpdateAppData(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
			webHost, _, _ := c.snapshot()
			if calls != 2 || webHost != "https://regional.terabox.com" || c.Account().ID != 123 || c.Account().IsVIP {
				t.Fatalf("regional refresh did not commit state: calls=%d host=%s account=%+v", calls, webHost, c.Account())
			}
			if originalRedirectCalls != 0 {
				t.Fatal("custom client automatically followed redirect")
			}
			if h.CheckRedirect(nil, nil) != nil || originalRedirectCalls != 1 {
				t.Fatal("supplied client's redirect policy was mutated")
			}
		})
	}
}

func TestUpdateAppDataRejectsUntrustedRedirects(t *testing.T) {
	for _, target := range []string{
		"https://unrelated.invalid/main",
		"https://terabox.com.unrelated.invalid/main",
		"http://regional.terabox.com/main",
		"https://user@regional.terabox.com/main",
		"//unrelated.invalid/main",
		"file:///tmp/page",
	} {
		t.Run(target, func(t *testing.T) {
			calls := 0
			c := NewClient("test-session", WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				res := clientResponse(r, http.StatusFound, "")
				res.Header.Set("Location", target)
				return res, nil
			})}))
			if _, err := c.UpdateAppData(context.Background(), ""); err == nil {
				t.Fatal("untrusted redirect was accepted")
			}
			host, _, _ := c.snapshot()
			if calls != 1 || host != "https://www.terabox.com" {
				t.Fatalf("redirect destination was contacted or stored: calls=%d host=%s", calls, host)
			}
		})
	}
}

func TestExplicitLocalHostAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("ndus"); err != nil || cookie.Value != "test-session" {
			t.Error("explicit local endpoint did not receive session cookie")
		}
		io.WriteString(w, clientPage)
	}))
	defer server.Close()
	c := NewClient("test-session", WithWebHost(server.URL), WithHTTPClient(server.Client()))
	if _, err := c.UpdateAppData(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestCustomHTTPClientNilUsesDefault(t *testing.T) {
	c := NewClient("", WithHTTPClient(nil))
	if c.httpClient == nil || c.httpClient.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("nil option lost the default client or manual redirect policy")
	}
}

func TestUpdateAppDataFailedRedirectDoesNotCommitCookies(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			c := NewClient("existing-session", WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					res := clientResponse(r, http.StatusFound, "")
					res.Header.Set("Location", "https://regional.terabox.com/main")
					res.Header.Add("Set-Cookie", "ndus=redirect-session")
					res.Header.Add("Set-Cookie", "browserid=redirect-browser")
					return res, nil
				}
				if !strings.Contains(r.Header.Get("Cookie"), "ndus=redirect-session") ||
					!strings.Contains(r.Header.Get("Cookie"), "browserid=redirect-browser") {
					t.Error("next redirect hop did not receive its local cookie state")
				}
				return clientResponse(r, status, "<html>invalid page</html>"), nil
			})}))
			old := c.CookieString()
			if _, err := c.UpdateAppData(context.Background(), ""); err == nil {
				t.Fatal("invalid final page was accepted")
			}
			host, _, _ := c.snapshot()
			if calls != 2 || c.CookieString() != old || host != "https://www.terabox.com" {
				t.Fatalf("failed redirect committed state: calls=%d host=%s cookies=%s", calls, host, c.CookieString())
			}
		})
	}
}

func TestCustomHTTPClientJarDoesNotBypassCookiePolicy(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("https://www.terabox.com")
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, []*http.Cookie{{Name: "ndus", Value: "external-jar-session"}})
	h := &http.Client{Jar: jar, Transport: clientRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Cookie") != "" {
			t.Errorf("noCookie request received cookies from the supplied jar: %s", r.Header.Get("Cookie"))
		}
		res := clientResponse(r, http.StatusOK, `{"code":42}`)
		res.Header.Set("Set-Cookie", "ndus=unexpected-replacement")
		return res, nil
	})}
	c := NewClient("internal-session", WithHTTPClient(h))
	if _, err := c.GetSysCfg(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPublicKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.Jar != jar || len(jar.Cookies(u)) != 1 || jar.Cookies(u)[0].Value != "external-jar-session" {
		t.Fatal("supplied client's cookie jar was mutated")
	}
	if cookie, _ := c.CookieValue("ndus"); cookie != "internal-session" {
		t.Fatal("external jar replaced internal session state")
	}
}
