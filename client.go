package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// TeraBoxDomain is the default TeraBox domain.
	TeraBoxDomain = "terabox.com"

	defaultTimeout       = 10 * time.Second
	defaultUploadTimeout = 5 * time.Minute
	verAndroid           = "3.44.2"
	defaultUserAgent     = "terabox;1.40.0.132;PC;PC-Windows;10.0.26100;WindowsTeraBox"
)

// appData holds session tokens refreshed by UpdateAppData.
type appData struct {
	csrf     string
	logID    string
	pcfToken string
	bdsToken string
	jsToken  string
	pubKey   string
}

// accountParams mirrors the params exposed by the JS TeraBoxApp.
type accountParams struct {
	accountID      int64
	accountName    string
	isVIP          bool
	vipType        int
	spaceUsed      int64
	spaceTotal     int64
	spaceAvailable int64
	cursor         string
}

// AccountInfo is a snapshot of the client's account state.
type AccountInfo struct {
	ID             int64
	Name           string
	IsVIP          bool
	VIPType        int // 0: regular, 1: premium, 2: super premium
	SpaceUsed      int64
	SpaceTotal     int64
	SpaceAvailable int64
}

// Client is a TeraBox API client (the Go counterpart of TeraBoxApp).
// All methods are safe for concurrent use; mutable state is guarded
// internally. Use NewClient to create one.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger

	timeout       time.Duration
	uploadTimeout time.Duration

	lang      string
	userAgent string

	mu             sync.RWMutex
	fileDiffMu     sync.Mutex
	cookies        map[string]string
	trustedOrigins map[string]struct{}
	whost          string
	uhost          string
	data           appData
	params         accountParams
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the per-request timeout for regular API calls
// (default 10s, matching the JS client). A caller-supplied context
// with an earlier deadline always wins.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithUploadTimeout sets the per-chunk upload timeout (default 5min).
// The JS client aborted chunk uploads after 10s, which breaks large
// chunks on slow links; set this to 0 to rely solely on context.
func WithUploadTimeout(d time.Duration) Option {
	return func(c *Client) { c.uploadTimeout = d }
}

// WithHTTPClient supplies a custom *http.Client (e.g. with a proxy
// transport). Its configuration is copied, except redirects and cookies are
// managed by this package. A nil client leaves the default in place.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			clone := *h
			clone.Jar = nil
			clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}
			c.httpClient = &clone
		}
	}
}

// WithLogger wires log messages (hostname changes, retries) to the
// given logger. Nil disables logging (default).
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) { c.logger = l }
}

// WithLanguage sets the lang parameter (default "en").
func WithLanguage(lang string) Option {
	return func(c *Client) {
		c.lang = lang
		c.cookies["lang"] = lang
	}
}

// WithUserAgent overrides the desktop-app User-Agent string. The
// server validates this UA loosely, but newer app versions may become
// necessary over time, so it is configurable.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// WithWebHost overrides the main API host (default https://www.terabox.com).
func WithWebHost(host string) Option {
	return func(c *Client) { c.whost = host }
}

// WithUploadHost overrides the upload host before locateupload discovery.
func WithUploadHost(host string) Option {
	return func(c *Client) { c.uhost = host }
}

// WithCookies restores a previously saved cookie string (see CookieString),
// resuming a session across process restarts — including the browserid /
// pcftoken state a captcha challenge was issued under, which must be kept
// between the challenge and the post-solve retry. Pass a bare ndus value
// as the first argument to NewClient instead.
func WithCookies(serialized string) Option {
	return func(c *Client) {
		for _, kv := range strings.Split(serialized, ";") {
			kv = strings.TrimSpace(kv)
			if kv == "" {
				continue
			}
			if name, value, ok := strings.Cut(kv, "="); ok {
				c.cookies[name] = value
			}
		}
	}
}

// NewClient creates a TeraBox client authenticated with an ndus cookie
// (copy it from a browser session, or obtain one via PassportLogin or
// RegisterFinish). An empty ndus creates an unauthenticated client,
// which is enough for the passport login/registration flows.
func NewClient(ndus string, opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // redirects handled manually
			},
		},
		timeout:       defaultTimeout,
		uploadTimeout: defaultUploadTimeout,
		lang:          "en",
		userAgent:     defaultUserAgent,
		cookies:       map[string]string{"lang": "en"},
		whost:         "https://www." + TeraBoxDomain,
		uhost:         "https://c-all." + TeraBoxDomain,
	}
	c.data.logID = "0" // initial
	c.params.cursor = "null"
	c.params.spaceTotal = 1 << 30
	c.params.spaceAvailable = c.params.spaceTotal

	if ndus != "" {
		c.cookies["ndus"] = ndus
	}
	for _, opt := range opts {
		opt(c)
	}
	c.trustedOrigins = make(map[string]struct{})
	for _, host := range []string{c.whost, c.uhost} {
		if u, err := url.Parse(host); err == nil && u.Host != "" {
			c.trustedOrigins[urlOrigin(u)] = struct{}{}
		}
	}
	return c
}

// Account returns a consistent snapshot of the client's account state.
func (c *Client) Account() AccountInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return AccountInfo{
		ID:             c.params.accountID,
		Name:           c.params.accountName,
		IsVIP:          c.params.isVIP,
		VIPType:        c.params.vipType,
		SpaceUsed:      c.params.spaceUsed,
		SpaceTotal:     c.params.spaceTotal,
		SpaceAvailable: c.params.spaceAvailable,
	}
}

// SetVIPDefaults forces premium defaults (2 GiB space hint).
func (c *Client) SetVIPDefaults() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.params.isVIP = true
	c.params.vipType = 1
	c.params.spaceTotal = 2 * (1 << 30)
	c.params.spaceAvailable = c.params.spaceTotal
}

// CookieString serializes the client's cookie state, e.g. to persist and
// later reuse the session (pass the ndus value to NewClient to resume).
func (c *Client) CookieString() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cookieHeaderLocked()
}

// CookieValue returns a single cookie value (e.g. "ndus").
func (c *Client) CookieValue(name string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.cookies[name]
	return v, ok
}

// appQuery returns the standard TeraBox app parameters used in query strings.
func (c *Client) appQuery() url.Values {
	return url.Values{
		"app_id":     {"250528"},
		"web":        {"1"},
		"channel":    {"dubox"},
		"clienttype": {"0"},
	}
}

func (c *Client) snapshot() (webHost, uploadHost, cookieHeader string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.whost, c.uhost, c.cookieHeaderLocked()
}

func (c *Client) cookieHeaderLocked() string {
	return serializeCookies(c.cookies)
}

func serializeCookies(cookies map[string]string) string {
	if len(cookies) == 0 {
		return ""
	}
	names := make([]string, 0, len(cookies))
	for n := range cookies {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(n)
		b.WriteByte('=')
		b.WriteString(cookies[n])
	}
	return b.String()
}

// mergeCookies persists Set-Cookie values into the client's flat cookie
// store (same semantics as the JS tough-cookie usage: a single cookie jar
// reused across TeraBox hosts, which matters when the regional hostname
// changes mid-session). Expired cookies are removed.
func (c *Client) mergeCookies(cs []*http.Cookie) {
	if len(cs) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	mergeCookieValues(c.cookies, cs)
}

func mergeCookieValues(cookies map[string]string, cs []*http.Cookie) {
	now := time.Now()
	for _, ck := range cs {
		if ck.MaxAge < 0 || (!ck.Expires.IsZero() && ck.Expires.Before(now)) {
			delete(cookies, ck.Name)
			continue
		}
		cookies[ck.Name] = ck.Value
	}
}

func (c *Client) dataSnapshot() appData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

func (c *Client) updateData(fn func(*appData)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(&c.data)
}

func (c *Client) updateParams(fn func(*accountParams)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(&c.params)
}

func (c *Client) warn(msg string, args ...any) {
	if c.logger != nil {
		c.logger.Warn(msg, args...)
	}
}

func (c *Client) logError(msg string, args ...any) {
	if c.logger != nil {
		c.logger.Error(msg, args...)
	}
}

// cancelOnCloseBody cancels the per-request timeout context when the
// response body is closed. It must NOT be canceled at Do() return:
// http.Client.Do returns as soon as the response headers arrive, so
// canceling there would make every subsequent body Read fail with
// "context canceled".
type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// doHTTP executes a request, using the earlier of the caller's deadline
// and the given per-request timeout. The timeout
// covers the whole exchange, including reading the body: the internal
// timeout context lives until the body is closed.
func (c *Client) doHTTP(req *http.Request, timeout time.Duration) (*http.Response, error) {
	if err := c.validateEndpoint(req.URL); err != nil {
		return nil, err
	}
	ctx := req.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		req = req.WithContext(ctx)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, err
	}
	if cancel != nil {
		resp.Body = cancelOnCloseBody{resp.Body, cancel}
	}
	return resp, nil
}

func urlOrigin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// validateEndpoint permits HTTPS TeraBox hosts and explicitly configured
// origins. The latter also allows local HTTP test servers without allowing
// a server response to introduce a new insecure or unrelated endpoint.
func (c *Client) validateEndpoint(u *url.URL) error {
	if u == nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("invalid API endpoint")
	}
	if _, ok := c.trustedOrigins[urlOrigin(u)]; ok {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "https" && (host == TeraBoxDomain || strings.HasSuffix(host, "."+TeraBoxDomain)) {
		return nil
	}
	return fmt.Errorf("untrusted API endpoint: %s", urlOrigin(u))
}

// backoffSleep waits between retry attempts (500ms, 1s, 2s, 4s, ...,
// capped at 30s),
// aborting early if the context is done. This replaces the fixed 500ms
// sleep used by the JS client.
func backoffSleep(ctx context.Context, attempt int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d := min(500*time.Millisecond<<uint(min(max(attempt, 0), 6)), 30*time.Second)
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// requestOpts describes one JSON API request.
type requestOpts struct {
	method   string
	path     string // absolute URL, or absolute-path resolved against whost
	query    url.Values
	form     *formValues
	headers  map[string]string
	noCookie bool          // skip the Cookie header (getsyscfg, getpubkey)
	timeout  time.Duration // 0 → client default
	// onResponse, when set, is invoked after the status check and before
	// the body is decoded/closed (used to harvest Set-Cookie headers).
	onResponse func(*http.Response)
}

// doJSON performs the request and JSON-decodes the body into out.
// Non-200 statuses become *httpStatusError wrapped in *Error.
func (c *Client) doJSON(ctx context.Context, op string, ro *requestOpts, out any) error {
	req, err := c.newRequest(ctx, ro)
	if err != nil {
		return wrapErr(op, err)
	}

	timeout := ro.timeout
	if timeout == 0 {
		timeout = c.timeout
	}
	resp, err := c.doHTTP(req, timeout)
	if err != nil {
		return wrapErr(op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return wrapErr(op, &httpStatusError{StatusCode: resp.StatusCode})
	}
	if ro.onResponse != nil {
		ro.onResponse(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return wrapErr(op, err)
	}
	return nil
}

// newRequest builds the *http.Request for requestOpts.
func (c *Client) newRequest(ctx context.Context, ro *requestOpts) (*http.Request, error) {
	webHost, _, cookieHeader := c.snapshot()

	rawURL := ro.path
	if strings.HasPrefix(rawURL, "/") {
		rawURL = webHost + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if ro.query != nil {
		encoded := ro.query.Encode()
		if u.RawQuery != "" {
			u.RawQuery += "&" + encoded
		} else {
			u.RawQuery = encoded
		}
	}

	var body io.Reader
	if ro.form != nil {
		body = strings.NewReader(ro.form.String())
	}
	method := ro.method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	if !ro.noCookie && cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}
	if ro.form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range ro.headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// TemplateData is the `<script>var templateData = ...</script>` block of
// the TeraBox web pages; it carries the session tokens used by many APIs.
type TemplateData struct {
	Csrf            string `json:"csrf"`
	PcfToken        string `json:"pcftoken"`
	BdsToken        string `json:"bdstoken"`
	JsToken         string `json:"jsToken"`
	UK              int64  `json:"uk"`
	UserVipIdentity int    `json:"userVipIdentity"`
}

var (
	jsTokenInnerRe  = regexp.MustCompile(`%28%22(.*)%22%29`)
	jsTokenWindowRe = regexp.MustCompile(`window\.jsToken%20%3D%20a%7D%3Bfn%28%22(.*)%22%29`)
)

// extractTemplateData mirrors the JS
// /<script>var templateData = (.*);<\/script>/ match followed by
// split(';</script>')[0].
func extractTemplateData(page string) string {
	const marker = "<script>var templateData = "
	i := strings.Index(page, marker)
	if i < 0 {
		return ""
	}
	rest := page[i+len(marker):]
	j := strings.Index(rest, ";</script>")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// UpdateAppData fetches a TeraBox web page, refreshes the session tokens
// (csrf, bdstoken, pcftoken, jsToken), follows redirects manually so the
// regional hostname change is tracked, and merges Set-Cookie values.
// Pass customPath like "wap/outlogin/login" to fetch a specific page;
// empty means "/main".
func (c *Client) UpdateAppData(ctx context.Context, customPath string) (*TemplateData, error) {
	const op = "updateAppData"
	const maxAttempts = 5 // 1 try + 4 retries on timeout (JS: retries=4)

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := backoffSleep(ctx, attempt-1); err != nil {
				return nil, wrapErr(op, err)
			}
		}
		td, err := c.updateAppDataOnce(ctx, customPath)
		if err == nil {
			return td, nil
		}
		lastErr = err
		// Retry only when OUR internal per-request timeout fired; if the
		// caller's context is done, stop immediately.
		if ctx.Err() != nil {
			return nil, wrapErr(op, errors.Join(err, ctx.Err()))
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			return nil, wrapErr(op, err)
		}
		c.warn("updateAppData: timeout, retrying", "attempt", attempt+1)
	}
	return nil, wrapErr(op, lastErr)
}

// updateAppDataOnce performs a single UpdateAppData pass.
func (c *Client) updateAppDataOnce(ctx context.Context, customPath string) (*TemplateData, error) {
	const maxRedirects = 5

	c.mu.RLock()
	webHost := c.whost
	localCookies := make(map[string]string, len(c.cookies))
	for name, value := range c.cookies {
		localCookies[name] = value
	}
	c.mu.RUnlock()
	var pendingCookies []*http.Cookie
	target := "/main"
	if customPath != "" {
		target = "/" + strings.TrimPrefix(customPath, "/")
	}
	rawURL := webHost + target

	var resp *http.Response
	for hops := 0; ; hops++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.userAgent)
		cookieHeader := serializeCookies(localCookies)
		if cookieHeader != "" {
			req.Header.Set("Cookie", cookieHeader)
		}

		resp, err = c.doHTTP(req, c.timeout+10*time.Second)
		if err != nil {
			return nil, err
		}

		sc := resp.StatusCode
		if sc != http.StatusMovedPermanently && sc != http.StatusFound && sc != http.StatusSeeOther &&
			sc != http.StatusTemporaryRedirect && sc != http.StatusPermanentRedirect {
			break
		}

		if resp.Header.Get("Location") == "" {
			resp.Body.Close()
			return nil, errors.New("redirect response without Location header")
		}
		if hops >= maxRedirects {
			resp.Body.Close()
			return nil, errors.New("too many redirects")
		}
		next, err := resp.Location()
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		if err := c.validateEndpoint(next); err != nil {
			resp.Body.Close()
			return nil, err
		}
		cookies := resp.Cookies()
		mergeCookieValues(localCookies, cookies)
		pendingCookies = append(pendingCookies, cookies...)
		resp.Body.Close()
		resp = nil
		webHost = urlOrigin(next)
		rawURL = next.String()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{StatusCode: resp.StatusCode}
	}

	page, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	td := &TemplateData{}
	hasVIPIdentity := false
	if raw := extractTemplateData(string(page)); raw != "" {
		if err := json.Unmarshal([]byte(raw), td); err != nil {
			return nil, fmt.Errorf("invalid templateData: %w", err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			return nil, fmt.Errorf("invalid templateData: %w", err)
		}
		if v, ok := fields["userVipIdentity"]; ok && strings.TrimSpace(string(v)) != "null" {
			hasVIPIdentity = true
		}
	}

	if td.JsToken != "" {
		if m := jsTokenInnerRe.FindStringSubmatch(td.JsToken); len(m) > 1 {
			td.JsToken = m[1]
		}
	} else if m := jsTokenWindowRe.FindStringSubmatch(string(page)); len(m) > 1 {
		td.JsToken = m[1]
	}

	if td.Csrf == "" && td.PcfToken == "" && td.BdsToken == "" && td.JsToken == "" {
		return nil, errors.New("page does not contain usable session tokens")
	}
	if target == "/main" && td.JsToken == "" {
		return nil, errors.New("jsToken is unavailable (login required)")
	}

	pendingCookies = append(pendingCookies, resp.Cookies()...)
	c.mu.Lock()
	mergeCookieValues(c.cookies, pendingCookies)
	oldHost := c.whost
	c.whost = webHost
	if logID := resp.Header.Get("logid"); logID != "" {
		c.data.logID = logID
	}
	if td.Csrf != "" {
		c.data.csrf = td.Csrf
	}
	if td.PcfToken != "" {
		c.data.pcfToken = td.PcfToken
	}
	if td.BdsToken != "" {
		c.data.bdsToken = td.BdsToken
	}
	if td.JsToken != "" {
		c.data.jsToken = td.JsToken
	}
	if td.UK > 0 {
		c.params.accountID = td.UK
		if hasVIPIdentity {
			c.params.isVIP = td.UserVipIdentity > 0
			if c.params.isVIP {
				c.params.vipType = 1
			} else {
				c.params.vipType = 0
			}
		}
	}
	c.mu.Unlock()
	if oldHost != webHost {
		c.warn("default hostname changed", "host", webHost)
	}

	return td, nil
}

// ensureJSToken makes sure a jsToken is available, calling UpdateAppData
// when necessary.
func (c *Client) ensureJSToken(ctx context.Context) error {
	c.mu.RLock()
	need := c.data.jsToken == ""
	c.mu.RUnlock()
	if !need {
		return nil
	}
	if _, err := c.UpdateAppData(ctx, ""); err != nil {
		return err
	}
	c.mu.RLock()
	ok := c.data.jsToken != ""
	c.mu.RUnlock()
	if !ok {
		return errors.New("jsToken is unavailable")
	}
	return nil
}
