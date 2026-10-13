package terabox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const shareBrowserFixtureAsset = "https://s5.teraboxcdn.com/fe-opera-static/node-static-v4/fe-webv4-wap-share/js/main.fixture.js"

func shareBrowserFixtureOptions() AndroidShareBrowserOptions {
	return AndroidShareBrowserOptions{UserAgent: "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ1A.221205.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36", Language: "ja-JP"}
}

func shareBrowserFixtureInput() AndroidShareLinkReferrerInput {
	agency := "h1__0_G2"
	return AndroidShareLinkReferrerInput{
		PageURL:  "https://www.terabox.com/wap/share/filelist?surl=fixture&order=name",
		DeepLink: "dubox://share_detail?shareid=456&uk=123&share_create_time=1700000000&randsk=fixture%2Bkey%3D&share_expired_time=0&source=af_link&share_file_count=1&surl=fixture",
		Agency:   &agency, TeraLinkType: 1,
	}
}

func shareBrowserFixturePage(tokenSource string) string {
	return `<html><script>window.templateData={pcftoken:'different-share-document'};</script>` +
		`<script>` + tokenSource + `</script>` +
		`<script>window.__INITIAL_STATE__={lang:'en',loginCenter:{uk:0},share:{shareInfoRetrieved:false,shareInfo:{surl:'fixture',shareid:456,uk:123,share_create_time:1700000000,expiredtype:0,filesTotal:1,randsk:'fixture%2Bkey%3D'}}};(function(){var s;(s=document.currentScript||document.scripts[document.scripts.length-1]).parentNode.removeChild(s);}());</script>` +
		`<script defer src="` + shareBrowserFixtureAsset + `"></script></html>`
}

func shareBrowserFixtureProvider(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("testdata/android_share_browser_provider.js")
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func shareBrowserFixtureResponse(request *http.Request, body string, headers http.Header, status int) *http.Response {
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: request}
}

func TestAndroidShareBrowserFreshPageProviderAndLinkedClick(t *testing.T) {
	provider := shareBrowserFixtureProvider(t)
	pageRequests, assetRequests := 0, 0
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			t.Fatal("provider sent a mutating request")
		}
		if req.Header.Get("User-Agent") != shareBrowserFixtureOptions().UserAgent || req.Header.Get("Accept-Language") != "ja-JP" {
			t.Fatal("provider did not preserve its browser inputs")
		}
		if strings.Contains(req.Header.Get("Cookie"), "ndus") || strings.Contains(req.Header.Get("Cookie"), "native_cookie") {
			t.Fatal("native account cookies leaked into browser context")
		}
		switch req.URL.Path {
		case "/wap/share/filelist":
			pageRequests++
			if req.Header.Get("Cookie") != "" {
				t.Fatal("a fresh page request reused prior browser cookies")
			}
			token := `try {eval(decodeURIComponent('function%20fn(a)%7Bwindow.jsToken%3Da%7D%3Bfn(%22actual-dynamic-bootstrap%22)'))}catch(e){}`
			return shareBrowserFixtureResponse(req, shareBrowserFixturePage(token+`;window.jsToken+=':'+document.cookie;document.cookie='bootstrap=runtime; Path=/; Secure';`),
				http.Header{"Set-Cookie": {fmt.Sprintf("fresh=%d; Path=/; Secure", pageRequests), "private=hidden; Path=/; Secure; HttpOnly", "page_only=excluded; Path=/wap/share; Secure"}}, 200), nil
		case "/fe-opera-static/node-static-v4/fe-webv4-wap-share/js/main.fixture.js":
			assetRequests++
			if req.Header.Get("Cookie") != "" || req.Header.Get("Referer") != shareBrowserFixtureInput().PageURL {
				t.Fatal("CDN request mixed cookies or lost page referrer")
			}
			return shareBrowserFixtureResponse(req, provider, nil, 200), nil
		default:
			t.Fatalf("provider unexpectedly requested %s", req.URL.Path)
			return nil, nil
		}
	})
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: transport}), WithCookies("ndus=native_cookie; native_cookie=native-only"))
	if err != nil {
		t.Fatal(err)
	}
	// An existing Hy token must not become the public share-page token.
	client.data.jsToken = "hy-document-token"
	var first AndroidGeneratedShareLinkAttribution
	for i := 0; i < 2; i++ {
		result, err := client.PrepareAndroidGeneratedShareLinkAttribution(context.Background(), shareBrowserFixtureInput(), shareBrowserFixtureOptions())
		if err != nil {
			t.Fatal(err)
		}
		click := result.Click
		if click == nil || !strings.HasPrefix(click.CommonParams["jsToken"], "actual-dynamic-bootstrap:") ||
			!strings.Contains(click.CommonParams["jsToken"], fmt.Sprintf("fresh=%d", i+1)) ||
			!strings.Contains(click.CommonParams["jsToken"], "page_only=excluded") ||
			strings.Contains(click.CommonParams["jsToken"], "private=") {
			t.Fatal("page bootstrap was not evaluated with its own visible cookie context")
		}
		if !strings.Contains(click.BrowserCookies, "private=hidden") || !strings.Contains(click.BrowserCookies, "bootstrap=runtime") || strings.Contains(click.BrowserCookies, "page_only") {
			t.Fatal("click cookies do not match the browser's request path and HttpOnly state")
		}
		if click.PageURL != result.Input.PageURL || click.DeepLink != result.Input.DeepLink || click.TeraLinkID != result.Generated.TeraLinkID || result.ProviderSHA256 == "" {
			t.Fatal("click and referrer lost their shared producer context")
		}
		inner, err := url.QueryUnescape(result.Generated.InstallReferrer)
		if err != nil {
			t.Fatal(err)
		}
		query, err := url.ParseQuery(inner)
		if err != nil || query.Get("tera_link_id") != click.TeraLinkID || query.Get("c") != click.PageURL || query.Get("af_dp") != click.DeepLink {
			t.Fatal("referrer encoded different click inputs")
		}
		if click.Language != "ja-JP" || click.CommonParams["lang"] != "en" || click.OSVersion != "android 13" || click.Device != "pixel 7" || click.Referrer != "" {
			t.Fatal("browser and page language/device/referrer contracts were conflated")
		}
		if i == 0 {
			first = result
		} else if first.Click.BrowserCookies == click.BrowserCookies || first.Click.CommonParams["dp-logid"] == click.CommonParams["dp-logid"] || first.Generated.TeraLinkID == result.Generated.TeraLinkID {
			t.Fatal("registrations reused browser identity, provider or click ID")
		}
	}
	if pageRequests != 2 || assetRequests != 2 || client.dataSnapshot().jsToken != "hy-document-token" {
		t.Fatal("provider changed native/Hy state or did not use one browser per call")
	}
}

func TestAndroidShareBrowserRedirectContextAndHostProtection(t *testing.T) {
	provider := shareBrowserFixtureProvider(t)
	for _, destination := range []string{
		"https://www.terabox.com/wap/share/filelist?surl=fixture&order=redirected",
		"https://not-terabox.example/wap/share/filelist?surl=fixture",
		"http://www.terabox.com/wap/share/filelist?surl=fixture",
		"https://www.terabox.com:8443/wap/share/filelist?surl=fixture",
		"https://www.terabox.com/wap/share/filelist?surl=other",
		"https://www.terabox.com/wap/hylogin?surl=fixture",
	} {
		t.Run(destination, func(t *testing.T) {
			calls := 0
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return shareBrowserFixtureResponse(req, "", http.Header{"Location": {destination}, "Set-Cookie": {"redirect=own; Path=/; Secure"}}, 302), nil
				}
				if req.URL.Hostname() == "s5.teraboxcdn.com" {
					return shareBrowserFixtureResponse(req, provider, nil, 200), nil
				}
				if req.URL.Hostname() != "www.terabox.com" {
					t.Fatal("unsupported redirect destination was requested")
				}
				return shareBrowserFixtureResponse(req, shareBrowserFixturePage(`window.jsToken='from-own-share';`), nil, 200), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.PrepareAndroidGeneratedShareLinkAttribution(context.Background(), shareBrowserFixtureInput(), shareBrowserFixtureOptions())
			if strings.HasSuffix(destination, "order=redirected") {
				if err != nil || result.Input.PageURL != destination || result.Click.PageURL != destination || !strings.Contains(result.Click.BrowserCookies, "redirect=own") {
					t.Fatal("same-share redirect context was not retained")
				}
			} else if err == nil {
				t.Fatal("unsupported or mismatched page redirect was accepted")
			}
		})
	}
}

func TestAndroidShareBrowserBootstrapRejectsMissingUnsupportedAndWrongShare(t *testing.T) {
	provider := shareBrowserFixtureProvider(t)
	base := shareBrowserFixturePage(`window.jsToken='actual-share-token';`)
	tests := map[string]string{
		"missing token":              strings.ReplaceAll(base, `window.jsToken='actual-share-token';`, ""),
		"SSR token is not global":    strings.ReplaceAll(base, `window.jsToken='actual-share-token';`, `window.__INITIAL_STATE__={jsToken:'not-browser-global'};`),
		"caught network unsupported": strings.ReplaceAll(base, `window.jsToken='actual-share-token';`, `try{fetch('/api/forbidden')}catch(e){}window.jsToken='fallback-forbidden';`),
		"caught canvas unsupported":  strings.ReplaceAll(base, `window.jsToken='actual-share-token';`, `try{document.createElement('canvas')}catch(e){}window.jsToken='fallback-forbidden';`),
		"caught unknown navigator":   strings.ReplaceAll(base, `window.jsToken='actual-share-token';`, `try{navigator.platform}catch(e){}window.jsToken='fallback-forbidden';`),
		"wrong shareid":              strings.ReplaceAll(base, "shareid:456", "shareid:999"),
		"wrong owner":                strings.ReplaceAll(base, "uk:123", "uk:999"),
		"wrong randsk":               strings.ReplaceAll(base, "fixture%2Bkey%3D", "different%2Bkey%3D"),
		"wrong count":                strings.ReplaceAll(base, "filesTotal:1", "filesTotal:2"),
		"missing metadata":           strings.ReplaceAll(base, "share_create_time:1700000000,", ""),
		"missing provider":           strings.ReplaceAll(base, shareBrowserFixtureAsset, "https://s5.teraboxcdn.com/unrelated.js"),
		"bad provider host":          strings.ReplaceAll(base, "s5.teraboxcdn.com", "not-terabox.example"),
		"invalid token type":         strings.ReplaceAll(base, `window.jsToken='actual-share-token';`, `window.jsToken={secret:'unsupported'};`),
		"wrong language type":        strings.ReplaceAll(base, "lang:'en'", "lang:7"),
	}
	for name, page := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				body := page
				if req.URL.Hostname() == "s5.teraboxcdn.com" {
					body = provider
				}
				return shareBrowserFixtureResponse(req, body, nil, 200), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.PrepareAndroidGeneratedShareLinkAttribution(context.Background(), shareBrowserFixtureInput(), shareBrowserFixtureOptions())
			if err == nil || strings.Contains(err.Error(), "actual-share-token") || strings.Contains(err.Error(), "fixture%2Bkey%3D") {
				t.Fatal("invalid page context accepted or private input leaked in its error")
			}
		})
	}
}

func TestAndroidShareBrowserBoundsCancellationAndInputs(t *testing.T) {
	for _, options := range []AndroidShareBrowserOptions{
		{UserAgent: androidFixtureProfile().UserAgent, Language: "en-US"},
		{UserAgent: shareBrowserFixtureOptions().UserAgent, Language: "en-US\r\nsecret"},
		{UserAgent: shareBrowserFixtureOptions().UserAgent, Language: ""},
	} {
		if validateAndroidShareBrowserOptions(options) == nil {
			t.Fatal("invalid or native browser identity accepted")
		}
	}
	for name, body := range map[string]string{
		"oversized page":    strings.Repeat(" ", androidShareBrowserMaxPage+1),
		"endless bootstrap": shareBrowserFixturePage(`while(true){};window.jsToken='never-evaluated';`),
		"oversized inline":  shareBrowserFixturePage(`window.jsToken='` + strings.Repeat("x", androidShareBrowserMaxInline) + `';`),
	} {
		t.Run(name, func(t *testing.T) {
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				return shareBrowserFixtureResponse(req, body, nil, 200), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, err = client.PrepareAndroidGeneratedShareLinkAttribution(ctx, shareBrowserFixtureInput(), shareBrowserFixtureOptions())
			if err == nil {
				t.Fatal("bootstrap bounds or deadline were not enforced")
			}
		})
	}
}
