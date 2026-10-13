package terabox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

const (
	androidShareBrowserMaxPage   = 4 << 20
	androidShareBrowserMaxAsset  = 4 << 20
	androidShareBrowserMaxInline = 512 << 10
	androidShareBrowserMaxTotal  = 8 << 20
	androidShareBrowserDeadline  = 45 * time.Second
	androidShareBrowserJSBudget  = 2 * time.Second
)

// AndroidShareBrowserOptions selects a new ordinary Android browser context.
// UserAgent must be a browser UA without the dubox native bridge marker.
// Language is navigator.language; the page can independently select its own
// interceptor language. Neither value is borrowed from a saved Chrome session.
type AndroidShareBrowserOptions struct {
	UserAgent string `json:"user_agent"`
	Language  string `json:"language"`
}

// AndroidGeneratedShareLinkAttribution joins a real, freshly loaded public
// share-page context with one generated click ID/referrer. Click contains
// private browser cookies and the page's evaluated token. Store it with the
// registration session, never in logs. This result does not claim an actual
// Play installation or a successful click HTTP response.
type AndroidGeneratedShareLinkAttribution struct {
	Input          AndroidShareLinkReferrerInput     `json:"input"`
	Generated      AndroidGeneratedShareLinkReferrer `json:"generated"`
	Click          *AndroidClickAttribution          `json:"click"`
	ProviderSHA256 string                            `json:"provider_sha256"`
}

// PrepareAndroidGeneratedShareLinkAttribution reads the public share page and
// its referenced main bundle using an independent, initially empty cookie jar.
// It evaluates the actual jsToken bootstrap and dp-logid provider in Go. It
// does not execute the page UI, analytics, native bridge, or send /api/srn/ck.
// The returned click and referrer use exactly the same generated link ID,
// final page location, deeplink and optional producer inputs.
func (c *Client) PrepareAndroidGeneratedShareLinkAttribution(ctx context.Context, input AndroidShareLinkReferrerInput, options AndroidShareBrowserOptions) (AndroidGeneratedShareLinkAttribution, error) {
	const op = "prepareAndroidGeneratedShareLinkAttribution"
	if err := c.requireAndroidApp(); err != nil {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, err)
	}
	input.Agency = copyAndroidShareOptionalString(input.Agency)
	input.OpSource = copyAndroidShareOptionalString(input.OpSource)
	// Validate the supplied share/deeplink metadata before making an HTTP call.
	if _, err := generateAndroidShareLinkReferrer(input, time.Unix(0, 0), strings.NewReader(strings.Repeat("\x00", 64))); err != nil {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, errors.New("share-page producer inputs are invalid"))
	}
	if err := validateAndroidShareBrowserOptions(options); err != nil {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, err)
	}
	ctx, cancel := context.WithTimeout(ctx, androidShareBrowserDeadline)
	defer cancel()
	browser, err := newAndroidShareBrowser(c.httpClient, options, c.timeout)
	if err != nil {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, err)
	}
	pageAddress, _ := url.Parse(input.PageURL)
	page, finalPage, err := browser.get(ctx, pageAddress, false, nil)
	if err != nil {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, err)
	}
	// A redirect must preserve the share and any explicitly selected op_source.
	// Revalidation also excludes a redirected Hy/login page.
	input.PageURL = finalPage.String()
	if _, err := generateAndroidShareLinkReferrer(input, time.Unix(0, 0), strings.NewReader(strings.Repeat("\x00", 64))); err != nil {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, errors.New("share-page redirect conflicts with producer inputs"))
	}
	token, logID, language, providerDigest, err := browser.providers(ctx, page, finalPage, input)
	if err != nil {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, err)
	}
	generated, err := GenerateAndroidShareLinkReferrer(input)
	if err != nil {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, err)
	}
	osVersion, device := androidShareBrowserDevice(options.UserAgent)
	if osVersion == "" || device == "" || device == "k" {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, errors.New("browser device extraction requires an explicit Android model"))
	}
	clickURL := *finalPage
	clickURL.Path, clickURL.RawPath, clickURL.RawQuery, clickURL.Fragment, clickURL.RawFragment = "/api/srn/ck", "", "", "", ""
	click := &AndroidClickAttribution{
		PageURL: input.PageURL, UserAgent: options.UserAgent, DeepLink: input.DeepLink,
		TeraLinkID: generated.TeraLinkID, TeraLinkType: 1, Language: options.Language,
		OSVersion: osVersion, Device: device, Referrer: "",
		Agency: copyAndroidShareOptionalString(input.Agency), OpSource: copyAndroidShareOptionalString(input.OpSource),
		BrowserCookies: browser.cookieHeader(&clickURL, false),
		CommonParams: map[string]string{"app_id": "250528", "web": "1", "channel": "dubox", "clienttype": "5",
			"jsToken": token, "dp-logid": logID, "version": "0", "devuid": "0", "cuid": "0", "lang": language},
	}
	if err := validateAndroidClickCommonParams(click, ""); err != nil {
		return AndroidGeneratedShareLinkAttribution{}, wrapErr(op, errors.New("share-page provider produced unsupported click parameters"))
	}
	return AndroidGeneratedShareLinkAttribution{Input: input, Generated: generated, Click: click, ProviderSHA256: providerDigest}, nil
}

func copyAndroidShareOptionalString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func validateAndroidShareBrowserOptions(options AndroidShareBrowserOptions) error {
	ua := strings.ToLower(options.UserAgent)
	if len(options.UserAgent) > 1024 || strings.TrimSpace(options.UserAgent) == "" || !attributionStringValid(options.UserAgent) ||
		!strings.Contains(ua, "android") || !strings.Contains(ua, "mozilla/") || strings.Contains(ua, "dubox") || strings.Contains(ua, "; wv") {
		return errors.New("an ordinary Android browser User-Agent is required")
	}
	if len(options.Language) > 64 || strings.TrimSpace(options.Language) == "" || !attributionStringValid(options.Language) ||
		strings.ContainsAny(options.Language, ";, \t") {
		return errors.New("a valid browser navigator language is required")
	}
	return nil
}

type androidShareBrowser struct {
	http    *http.Client
	jar     *cookiejar.Jar
	visible *cookiejar.Jar
	options AndroidShareBrowserOptions
}

func newAndroidShareBrowser(original *http.Client, options AndroidShareBrowserOptions, timeout time.Duration) (*androidShareBrowser, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, errors.New("cannot allocate share-page browser cookie jar")
	}
	visible, err := cookiejar.New(nil)
	if err != nil {
		return nil, errors.New("cannot allocate share-page visible cookie jar")
	}
	copy := *original
	copy.Jar = nil
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if timeout <= 0 || timeout > androidShareBrowserDeadline {
		timeout = defaultTimeout
	}
	if copy.Timeout <= 0 || copy.Timeout > timeout {
		copy.Timeout = timeout
	}
	return &androidShareBrowser{http: &copy, jar: jar, visible: visible, options: options}, nil
}

func validAndroidShareBrowserURL(address *url.URL, asset bool) bool {
	if address == nil || address.Scheme != "https" || address.Opaque != "" || address.User != nil || address.Port() != "" ||
		address.Fragment != "" || !attributionStringValid(address.String()) {
		return false
	}
	host := strings.ToLower(address.Hostname())
	if host == TeraBoxDomain || strings.HasSuffix(host, "."+TeraBoxDomain) {
		return true
	}
	return asset && (host == "teraboxcdn.com" || strings.HasSuffix(host, ".teraboxcdn.com"))
}

func (browser *androidShareBrowser) cookieHeader(address *url.URL, visible bool) string {
	jar := browser.jar
	if visible {
		jar = browser.visible
	}
	var parts []string
	for _, cookie := range jar.Cookies(address) {
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(parts, "; ")
}

func (browser *androidShareBrowser) get(ctx context.Context, address *url.URL, asset bool, referrer *url.URL) (string, *url.URL, error) {
	maxSize := androidShareBrowserMaxPage
	if asset {
		maxSize = androidShareBrowserMaxAsset
	}
	current := *address
	for hop := 0; hop <= 8; hop++ {
		if !validAndroidShareBrowserURL(&current, asset) {
			return "", nil, errors.New("share-page fetch has an unsupported origin")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return "", nil, errors.New("share-page fetch could not construct a request")
		}
		request.Header.Set("User-Agent", browser.options.UserAgent)
		request.Header.Set("Accept-Language", browser.options.Language)
		request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		if asset {
			request.Header.Set("Accept", "*/*")
		}
		if referrer != nil {
			request.Header.Set("Referer", referrer.String())
		}
		if cookie := browser.cookieHeader(&current, false); cookie != "" {
			request.Header.Set("Cookie", cookie)
		}
		response, err := browser.http.Do(request)
		if err != nil {
			return "", nil, errors.New("share-page fetch failed")
		}
		cookies := response.Cookies()
		if len(cookies) > 64 {
			_ = response.Body.Close()
			return "", nil, errors.New("share-page response exceeded the supported cookie count")
		}
		for _, cookie := range cookies {
			if len(cookie.Name)+len(cookie.Value)+len(cookie.Path)+len(cookie.Domain) > 8192 {
				_ = response.Body.Close()
				return "", nil, errors.New("share-page response exceeded the supported cookie size")
			}
		}
		browser.jar.SetCookies(&current, cookies)
		for _, cookie := range cookies {
			if !cookie.HttpOnly {
				browser.visible.SetCookies(&current, []*http.Cookie{cookie})
			} else {
				// A server can make an existing same-name/path cookie HttpOnly.
				// Its prior visible value must then disappear from document.cookie.
				hidden := *cookie
				hidden.MaxAge = -1
				browser.visible.SetCookies(&current, []*http.Cookie{&hidden})
			}
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			_ = response.Body.Close()
			next, parseErr := current.Parse(response.Header.Get("Location"))
			if parseErr != nil || response.Header.Get("Location") == "" || !validAndroidShareBrowserURL(next, asset) {
				return "", nil, errors.New("share-page redirect has an unsupported destination")
			}
			current = *next
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return "", nil, errors.New("share-page fetch returned an unsuccessful HTTP status")
		}
		content, readErr := io.ReadAll(io.LimitReader(response.Body, int64(maxSize)+1))
		_ = response.Body.Close()
		if readErr != nil || len(content) > maxSize || !utf8.Valid(content) {
			return "", nil, errors.New("share-page response exceeded bootstrap bounds or was incomplete")
		}
		return string(content), &current, nil
	}
	return "", nil, errors.New("share-page redirect exceeded the supported hop count")
}

var androidShareBrowserToken = regexp.MustCompile(`\bjsToken\b`)
var androidShareBrowserState = regexp.MustCompile(`\b(?:templateData|__INITIAL_STATE__)\b`)
var androidShareBrowserOS = regexp.MustCompile(`android[^;]*`)

func androidShareBrowserDevice(userAgent string) (string, string) {
	ua := strings.ToLower(userAgent)
	os := androidShareBrowserOS.FindString(ua)
	// Go RE2 has no lookahead: use the same final " build" delimiter that
	// module 1f03's /android.*; ?(.*(?= build))/ uses for ordinary Android UAs.
	start := strings.Index(ua, "android")
	end := strings.LastIndex(ua, " build")
	device := ""
	if start >= 0 && end > start {
		if separator := strings.LastIndex(ua[start:end], ";"); separator >= 0 {
			device = strings.TrimPrefix(ua[start+separator+1:end], " ")
		}
	} else if start >= 0 {
		part := strings.SplitN(ua[start+len("android"):], ")", 2)[0]
		segments := strings.Split(part, ";")
		if len(segments) > 1 {
			// The source fallback does not trim this field.
			device = segments[1]
		}
	}
	return os, device
}

// Only the current public bundle's pure provider modules can be required.
// Capturing webpack registration does not invoke its application entry array.
const androidShareBrowserProviderLoader = `
var __shareModules = Object.create(null), __shareCache = Object.create(null);
window.webpackJsonp = {push:function(payload){
  if(!payload || !payload[1] || typeof payload[1] !== 'object') throw Error('unsupported webpack registration');
  Object.keys(payload[1]).forEach(function(id){__shareModules[id]=payload[1][id];});
}};
function __shareRequire(id){
  if(['4471','d0fc','51cd','4583','7404'].indexOf(id)===-1) throw Error('unsupported provider dependency');
  if(__shareCache[id]) return __shareCache[id].exports;
  if(typeof __shareModules[id]!=='function') throw Error('missing share provider');
  var entry={exports:{}};__shareCache[id]=entry;
  __shareModules[id](entry,entry.exports,__shareRequire);return entry.exports;
}
__shareRequire.d=function(target,key,getter){Object.defineProperty(target,key,{enumerable:true,get:getter});};
__shareRequire.n=function(target){var getter=function(){return target;};Object.defineProperty(getter,'a',{get:getter});return getter;};
`

func (browser *androidShareBrowser) providers(ctx context.Context, page string, address *url.URL, input AndroidShareLinkReferrerInput) (string, string, string, string, error) {
	vm := goja.New()
	vm.SetMaxCallStackSize(256)
	var entropyFailed, unsupported bool
	vm.SetRandSource(func() float64 {
		value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 53))
		if err != nil {
			entropyFailed = true
			return 0
		}
		return float64(value.Int64()) / (1 << 53)
	})
	global := vm.GlobalObject()
	for _, name := range []string{"window", "self", "globalThis"} {
		_ = vm.Set(name, global)
	}
	navigator := vm.NewObject()
	_ = navigator.Set("userAgent", browser.options.UserAgent)
	_ = navigator.Set("language", browser.options.Language)
	_ = navigator.Set("languages", []string{browser.options.Language})
	_ = vm.Set("navigator", navigator)
	_ = vm.Set("location", map[string]string{"href": address.String(), "origin": urlOrigin(address), "pathname": address.Path,
		"search": "?" + address.RawQuery, "hash": "", "protocol": address.Scheme + ":", "host": address.Host, "hostname": address.Hostname()})
	document := vm.NewObject()
	_ = document.Set("referrer", "")
	_ = document.Set("URL", address.String())
	_ = vm.Set("document", document)
	_ = vm.Set("console", map[string]any{"log": func(...any) {}, "warn": func(...any) {}, "error": func(...any) {}})
	_ = vm.Set("__shareReadCookie", func() string { return browser.cookieHeader(address, true) })
	_ = vm.Set("__shareWriteCookie", func(value string) {
		if len(value) > 8192 || !attributionStringValid(value) {
			unsupported = true
			panic(vm.NewTypeError("invalid bootstrap cookie"))
		}
		response := &http.Response{Header: http.Header{"Set-Cookie": []string{value}}}
		cookies := response.Cookies()
		if len(cookies) != 1 || cookies[0].HttpOnly {
			unsupported = true
			panic(vm.NewTypeError("unsupported bootstrap cookie"))
		}
		browser.jar.SetCookies(address, cookies)
		browser.visible.SetCookies(address, cookies)
	})
	_ = vm.Set("__shareUnsupported", func() {
		unsupported = true
		panic(vm.NewTypeError("unsupported browser bootstrap operation"))
	})
	setup := `Object.defineProperty(document,'cookie',{get:__shareReadCookie,set:__shareWriteCookie});
document.createElement=__shareUnsupported; document.querySelector=__shareUnsupported;
window.fetch=__shareUnsupported; window.XMLHttpRequest=__shareUnsupported;
window.setTimeout=__shareUnsupported; window.setInterval=__shareUnsupported;
window.localStorage={getItem:__shareUnsupported,setItem:__shareUnsupported};
window.sessionStorage={getItem:__shareUnsupported,setItem:__shareUnsupported};
['platform','hardwareConcurrency','userAgentData','webdriver','plugins','mimeTypes'].forEach(function(name){Object.defineProperty(navigator,name,{get:__shareUnsupported});});
['screen','crypto','indexedDB'].forEach(function(name){Object.defineProperty(window,name,{get:__shareUnsupported});});
`
	run := func(source string) (goja.Value, error) {
		if err := ctx.Err(); err != nil {
			return nil, errors.New("share-page bootstrap was cancelled")
		}
		done := make(chan struct{})
		timer := time.AfterFunc(androidShareBrowserJSBudget, func() { vm.Interrupt("share-page bootstrap execution deadline") })
		go func() {
			select {
			case <-ctx.Done():
				vm.Interrupt("share-page bootstrap cancelled")
			case <-done:
			}
		}()
		value, err := vm.RunString(source)
		timer.Stop()
		close(done)
		if err != nil || unsupported || entropyFailed {
			return nil, errors.New("share-page bootstrap evaluation failed or needs an unsupported browser input")
		}
		return value, nil
	}
	if _, err := run(setup + androidShareBrowserProviderLoader); err != nil {
		return "", "", "", "", err
	}
	var mainURL *url.URL
	total, inlineCount, tokenCount := 0, 0, 0
	for _, script := range hyInlineScript.FindAllStringSubmatch(page, -1) {
		attrs := hyScriptAttributes(script[1])
		kind := strings.ToLower(strings.TrimSpace(attrs["type"]))
		if _, noModule := attrs["nomodule"]; noModule || (kind != "" && kind != "text/javascript" && kind != "application/javascript") {
			continue
		}
		if source := attrs["src"]; source != "" {
			asset, err := address.Parse(source)
			if err == nil && strings.HasPrefix(asset.Path, "/fe-opera-static/node-static-v4/fe-webv4-wap-share/js/main.") && strings.HasSuffix(asset.Path, ".js") {
				if !validAndroidShareBrowserURL(asset, true) || mainURL != nil {
					return "", "", "", "", errors.New("share-page provider asset is ambiguous or has an unsupported origin")
				}
				mainURL = asset
			}
			continue
		}
		source := script[2]
		isToken := androidShareBrowserToken.MatchString(source)
		if !isToken && !androidShareBrowserState.MatchString(source) {
			continue
		}
		inlineCount++
		total += len(source)
		if isToken {
			tokenCount++
		}
		if len(source) > androidShareBrowserMaxInline || total > androidShareBrowserMaxTotal || inlineCount > 16 {
			return "", "", "", "", errors.New("share-page inline bootstrap exceeds execution bounds")
		}
		// The live SSR producer removes its own <script> after assigning the
		// state. Support this exact cleanup operation without a rendered DOM.
		currentScript, parent := vm.NewObject(), vm.NewObject()
		removed := false
		_ = parent.Set("removeChild", func(call goja.FunctionCall) goja.Value {
			if removed || !call.Argument(0).StrictEquals(currentScript) {
				unsupported = true
				panic(vm.NewTypeError("unsupported bootstrap DOM operation"))
			}
			removed = true
			return currentScript
		})
		_ = currentScript.Set("parentNode", parent)
		_ = document.Set("currentScript", currentScript)
		if _, err := run(source); err != nil {
			return "", "", "", "", err
		}
		_ = document.Set("currentScript", goja.Null())
	}
	if tokenCount == 0 || mainURL == nil {
		return "", "", "", "", errors.New("share-page did not supply an executable token bootstrap and provider asset")
	}
	// The browser SSR document must name exactly the prepared native share.
	// In particular, a fresh page's access key may not silently replace the
	// metadata already bound into the generated installation's deeplink.
	metadata, err := run(`(function(){
var s=window.__INITIAL_STATE__, share=s&&s.share, info=share&&share.shareInfo;
if(!info)throw Error('share SSR metadata unavailable');
var result={};
[['surl','surl'],['shareid','shareid'],['uk','uk'],['share_create_time','share_create_time'],['expiredtype','share_expired_time'],['filesTotal','share_file_count'],['randsk','randsk']].forEach(function(pair){
if(!Object.prototype.hasOwnProperty.call(info,pair[0]))throw Error('share SSR metadata incomplete');
result[pair[1]]=String(info[pair[0]]);
});return result;
})()`)
	if err != nil {
		return "", "", "", "", err
	}
	deep, _ := url.Parse(input.DeepLink)
	expected, _ := url.ParseQuery(deep.RawQuery)
	observed := metadata.ToObject(vm)
	for _, key := range []string{"surl", "shareid", "uk", "share_create_time", "share_expired_time", "share_file_count", "randsk"} {
		value := observed.Get(key).String()
		if key == "randsk" {
			// The share store retains the producer's already encoded key.
			// One query decode is needed for comparison with the parsed deeplink.
			value, err = url.QueryUnescape(value)
			if err != nil {
				return "", "", "", "", errors.New("share-page access key has invalid encoding")
			}
		}
		if len(expected[key]) != 1 || expected.Get(key) != value {
			return "", "", "", "", errors.New("share-page SSR metadata conflicts with the prepared native share")
		}
	}
	provider, _, err := browser.get(ctx, mainURL, true, address)
	if err != nil {
		return "", "", "", "", err
	}
	if total+len(provider) > androidShareBrowserMaxTotal {
		return "", "", "", "", errors.New("share-page provider exceeds execution bounds")
	}
	if _, err := run(provider); err != nil {
		return "", "", "", "", err
	}
	value, err := run(`(function(){
var common=__shareRequire('7404').a();
var state=window.__INITIAL_STATE__;
var lang=state&&state.lang;
if(typeof common.jsToken!=='string'||!common.jsToken||typeof common['dp-logid']!=='string'||!/^\d{20}$/.test(common['dp-logid']))throw Error('invalid real provider values');
if(typeof lang!=='string'||!lang)throw Error('page interceptor language unavailable');
return {token:common.jsToken,logid:common['dp-logid'],lang:lang};
})()`)
	if err != nil {
		return "", "", "", "", err
	}
	object := value.ToObject(vm)
	token, logID, language := object.Get("token").String(), object.Get("logid").String(), object.Get("lang").String()
	if len(token) > 16384 || len(language) > 64 || !attributionStringValid(token) || !attributionStringValid(logID) || !attributionStringValid(language) {
		return "", "", "", "", errors.New("share-page provider returned invalid bounded values")
	}
	digest := sha256.Sum256([]byte(provider))
	return token, logID, language, hex.EncodeToString(digest[:]), nil
}
