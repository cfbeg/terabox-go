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
	"sort"
	"strings"
	"sync"
	"time"
)

const TeraBoxDomain = "terabox.com"
const defaultTimeout = 10 * time.Second

// appData contains only the tokens used by the APK's Hy login page.
type appData struct {
	pcfToken string
	jsToken  string
	pubKey   string
}

type accountParams struct{ accountID int64 }

// AccountInfo is a snapshot of the authenticated account identifier.
type AccountInfo struct{ ID int64 }

// Client executes the APK-derived Hy and native protocols. Construct clients
// with NewAndroidAppClient; there is no unprofiled or desktop constructor.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	timeout    time.Duration
	lang       string
	userAgent  string

	mu                    sync.RWMutex
	cookies               map[string]string
	trustedOrigins        map[string]struct{}
	whost                 string
	data                  appData
	params                accountParams
	registrationMu        sync.Mutex
	attributionMu         sync.Mutex
	androidAttribution    *AndroidAttributionState
	referral              *WebmasterReferral
	registrationToken     string
	registrationNDUS      string
	registrationConfirmed bool
	registrationFinished  bool
	androidApp            *androidAppState
}

type Option func(*Client)

// WithTimeout sets the per-request timeout. An earlier caller deadline wins.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// WithHTTPClient copies transport/timeouts, keeping cookies and redirects under
// the APK client's control. The supplied client is not modified.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			clone := *h
			clone.Jar = nil
			clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
			c.httpClient = &clone
		}
	}
}

func WithLogger(logger *slog.Logger) Option { return func(c *Client) { c.logger = logger } }

// WithAPIHost overrides the API origin and explicitly trusts it, for example
// when using a local HTTP fixture. The captured Hy page remains mandatory.
func WithAPIHost(host string) Option { return func(c *Client) { c.whost = host } }

// WithCookies restores actual APK session cookies, including an existing ndus.
func WithCookies(serialized string) Option {
	return func(c *Client) {
		for _, item := range strings.Split(serialized, ";") {
			if name, value, ok := strings.Cut(strings.TrimSpace(item), "="); ok && name != "" {
				c.cookies[name] = value
			}
		}
	}
}

// newClient allocates transport state; only NewAndroidAppClient exposes it
// after validating and installing the captured Android profile.
func newClient(opts ...Option) *Client {
	c := &Client{httpClient: &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, timeout: defaultTimeout, cookies: make(map[string]string), whost: "https://www." + TeraBoxDomain}
	for _, opt := range opts {
		opt(c)
	}
	c.trustedOrigins = make(map[string]struct{})
	if origin, err := url.Parse(c.whost); err == nil && origin.Host != "" {
		c.trustedOrigins[urlOrigin(origin)] = struct{}{}
	}
	return c
}

func (c *Client) requireAndroidApp() error {
	if c == nil {
		return errors.New("NewAndroidAppClient with a captured APK profile is required")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.androidApp == nil || c.httpClient == nil {
		return errors.New("NewAndroidAppClient with a captured APK profile is required")
	}
	return nil
}

func (c *Client) Account() AccountInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return AccountInfo{ID: c.params.accountID}
}

func (c *Client) CookieString() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cookieHeaderLocked()
}

func (c *Client) CookieValue(name string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, ok := c.cookies[name]
	return value, ok
}

func (c *Client) snapshot() (apiHost, cookieHeader string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.whost, c.cookieHeaderLocked()
}

func (c *Client) cookieHeaderLocked() string { return serializeCookies(c.cookies) }

func serializeCookies(cookies map[string]string) string {
	names := make([]string, 0, len(cookies))
	for name := range cookies {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+cookies[name])
	}
	return strings.Join(parts, "; ")
}

func (c *Client) mergeCookies(cookies []*http.Cookie) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mergeCookieValues(c.cookies, cookies)
}

func mergeCookieValues(cookies map[string]string, updates []*http.Cookie) {
	for _, cookie := range updates {
		if cookie.MaxAge < 0 || (!cookie.Expires.IsZero() && cookie.Expires.Before(time.Now())) {
			delete(cookies, cookie.Name)
		} else {
			cookies[cookie.Name] = cookie.Value
		}
	}
}

func (c *Client) dataSnapshot() appData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

func (c *Client) updateData(update func(*appData)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	update(&c.data)
}

func (c *Client) updateParams(update func(*accountParams)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	update(&c.params)
}

func (c *Client) warn(message string, args ...any) {
	if c.logger != nil {
		c.logger.Warn(message, args...)
	}
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body cancelOnCloseBody) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

func (c *Client) doHTTP(req *http.Request, timeout time.Duration) (*http.Response, error) {
	if err := c.requireAndroidApp(); err != nil {
		return nil, err
	}
	if err := c.validateEndpoint(req.URL); err != nil {
		return nil, err
	}
	if !apkRequestPath(req.URL.Path) {
		return nil, errors.New("request path is outside the supported APK protocol")
	}
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, stop := context.WithTimeout(req.Context(), timeout)
		cancel = stop
		req = req.WithContext(ctx)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		var requestErr *url.Error
		if errors.As(err, &requestErr) {
			op := requestErr.Op
			// http.Client may wrap a transport's own url.Error. Strip every
			// URL-bearing layer so the inner error cannot expose signed URLs.
			for errors.As(err, &requestErr) {
				err = requestErr.Err
			}
			err = fmt.Errorf("Android app HTTP %s: %w", op, err)
		}
		return nil, err
	}
	if cancel != nil {
		resp.Body = cancelOnCloseBody{resp.Body, cancel}
	}
	return resp, nil
}

func urlOrigin(u *url.URL) string { return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) }

func apkRequestPath(path string) bool {
	if path == "/wap/hylogin" || strings.HasPrefix(path, "/wap/hylogin/") {
		return true
	}
	switch path {
	case "/passport/getpubkey", "/passport/prelogin", "/passport/login",
		"/passport/register_v4/sendcode", "/passport/register_v4/verify", "/passport/register_v4/finish",
		"/api/shorturlinfo", "/share/list", "/share/transfer", "/api/report/user", "/api/account/uinfo",
		"/api/srn/ck", "/api/srn/ins", "/api/srn/ref",
		"/rest/1.0/imact/miner/pull", "/rest/1.0/imact/miner/start", "/rest/1.0/imact/miner/getitem",
		"/rest/1.0/imact/miner/finishgame", "/rest/1.0/inte/system/getrecord",
		"/rest/1.0/imact/miner/queryvideo", "/rest/1.0/imact/puzzle/query",
		"/rest/1.0/task/new/act/querybyname", "/rest/1.0/task/common/querystart",
		"/rest/1.0/task/common/reportstart", "/rest/1.0/task/common/report", "/rest/1.0/task/common/receive":
		return true
	}
	return false
}

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

type requestOpts struct {
	method     string
	path       string
	query      url.Values
	form       *formValues
	headers    map[string]string
	noCookie   bool
	timeout    time.Duration
	onResponse func(*http.Response)
}

func (c *Client) doJSON(ctx context.Context, op string, options *requestOpts, out any) error {
	if err := c.requireAndroidApp(); err != nil {
		return wrapErr(op, err)
	}
	req, err := c.newRequest(ctx, options)
	if err != nil {
		return wrapErr(op, err)
	}
	req, err = c.androidAppAPIRequest(req)
	if err != nil {
		return wrapErr(op, err)
	}
	timeout := options.timeout
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
	if options.onResponse != nil {
		options.onResponse(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return wrapErr(op, err)
	}
	return nil
}

func (c *Client) newRequest(ctx context.Context, options *requestOpts) (*http.Request, error) {
	host, cookies := c.snapshot()
	rawURL := options.path
	if strings.HasPrefix(rawURL, "/") {
		rawURL = host + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if options.query != nil {
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += options.query.Encode()
	}
	var body io.Reader
	if options.form != nil {
		body = strings.NewReader(options.form.String())
	}
	method := options.method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	if !options.noCookie && cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
	if options.form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for key, value := range options.headers {
		req.Header.Set(key, value)
	}
	return req, nil
}

// TemplateData contains the values consumed by the APK's Hy login bundle.
type TemplateData struct {
	PcfToken string `json:"pcftoken"`
	JsToken  string `json:"jsToken"`
}
