package terabox

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// AndroidAppProfile contains the runtime identity captured from the Android
// app. UID and EncodedSK may be empty for a guest. Channel is the Hy page's
// channel, whereas NativeChannel is used by the app's native API transport.
type AndroidAppProfile struct {
	DeviceID           string            `json:"device_id"`
	Version            string            `json:"version"`
	UserAgent          string            `json:"user_agent"`
	NativeChannel      string            `json:"native_channel"`
	Channel            string            `json:"channel"`
	Language           string            `json:"language"`
	PageURL            string            `json:"page_url"`
	UID                string            `json:"uid,omitempty"`
	EncodedSK          string            `json:"encoded_sk,omitempty"`
	PSign              string            `json:"psign,omitempty"`
	CKData             map[string]string `json:"ck_data,omitempty"`
	NativeParams       map[string]string `json:"native_params,omitempty"`
	LegacyNativeParams map[string]string `json:"legacy_native_params,omitempty"`
	NativeCKData       map[string]string `json:"native_ck_data,omitempty"`
	ReportParams       map[string]string `json:"report_params,omitempty"`
	ClientType         int               `json:"client_type"`
}

type androidAppState struct {
	profile AndroidAppProfile
	bootMu  sync.Mutex
	ready   bool
	now     func() time.Time
}

func copyAndroidAppProfile(profile AndroidAppProfile) AndroidAppProfile {
	if profile.CKData != nil {
		copy := make(map[string]string, len(profile.CKData))
		for key, value := range profile.CKData {
			copy[key] = value
		}
		profile.CKData = copy
	}
	if profile.NativeParams != nil {
		copy := make(map[string]string, len(profile.NativeParams))
		for key, value := range profile.NativeParams {
			copy[key] = value
		}
		profile.NativeParams = copy
	}
	profile.LegacyNativeParams = copyAndroidStringMap(profile.LegacyNativeParams)
	profile.NativeCKData = copyAndroidStringMap(profile.NativeCKData)
	profile.ReportParams = copyAndroidStringMap(profile.ReportParams)
	return profile
}

func copyAndroidStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

func validateAndroidAppProfile(profile AndroidAppProfile) (AndroidAppProfile, error) {
	for name, value := range map[string]string{
		"device ID": profile.DeviceID, "version": profile.Version,
		"User-Agent": profile.UserAgent, "native channel": profile.NativeChannel,
		"language": profile.Language, "Hy page URL": profile.PageURL,
	} {
		if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
			return profile, fmt.Errorf("Android app %s must be nonempty valid UTF-8 without control characters", name)
		}
	}
	page, err := url.Parse(profile.PageURL)
	if err != nil || page.User != nil || page.Fragment != "" || page.Scheme != "https" ||
		(page.Hostname() != TeraBoxDomain && !strings.HasSuffix(page.Hostname(), "."+TeraBoxDomain)) ||
		(page.Path != "/wap/hylogin" && !strings.HasPrefix(page.Path, "/wap/hylogin/")) {
		return profile, errors.New("Android app PageURL must be an HTTPS TeraBox Hy-login page")
	}
	if profile.ClientType != 1 {
		return profile, errors.New("Android app client type must be the captured Android value 1")
	}
	if profile.Channel == "" {
		profile.Channel = page.Query().Get("channel")
		if profile.Channel == "" {
			profile.Channel = profile.UserAgent
		}
	}
	if !strings.Contains(strings.ToLower(profile.UserAgent), "dubox") ||
		strings.ContainsAny(profile.Channel+profile.UID+profile.PSign, "\r\n\x00") {
		return profile, errors.New("Android app profile requires its captured dubox User-Agent and valid channel/identity")
	}
	if profile.EncodedSK != "" {
		if _, err := NewAndroidSigner(AndroidSigningConfig{DeviceID: profile.DeviceID, UID: profile.UID,
			EncodedSK: profile.EncodedSK, Version: profile.Version, Channel: profile.NativeChannel}); err != nil {
			return profile, err
		}
	}
	for key, value := range profile.CKData {
		if (key != "ck_st" && key != "ck_val" && key != "ck_own" && key != "ck_tk") ||
			!utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
			return profile, errors.New("Android app CKData contains an invalid runtime field")
		}
	}
	for key, value := range profile.NativeParams {
		if key == "" || strings.ContainsAny(key, "\r\n\x00&=?") || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
			return profile, errors.New("Android app NativeParams contains an invalid runtime field")
		}
	}
	for _, values := range []map[string]string{profile.LegacyNativeParams, profile.NativeCKData} {
		for key, value := range values {
			if key == "" || strings.ContainsAny(key, "\r\n\x00&=?") || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
				return profile, errors.New("Android app native runtime map contains an invalid field")
			}
		}
	}
	allowedReport := map[string]bool{"action": true, "channel_id": true, "bind_uid": true,
		"needrookie": true, "fcm_token": true, "source": true, "msg_id": true,
		"start_source": true, "push_on": true, "backup_on ": true, "timestamp": true}
	for key, value := range profile.ReportParams {
		if !allowedReport[key] || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
			return profile, errors.New("Android app ReportParams contains an invalid runtime field")
		}
	}
	return copyAndroidAppProfile(profile), nil
}

// NewAndroidAppClient creates the APK's native/Hy protocol client without
// network activity. It requires a captured profile and does not invent a device
// identity. The existing NewClient and WithAndroidSigner retain their behavior.
func NewAndroidAppClient(profile AndroidAppProfile, opts ...Option) (*Client, error) {
	profile, err := validateAndroidAppProfile(profile)
	if err != nil {
		return nil, wrapErr("newAndroidAppClient", err)
	}
	page, _ := url.Parse(profile.PageURL)
	initial := []Option{
		func(c *Client) { c.cookies = make(map[string]string) },
		WithWebHost(urlOrigin(page)), WithUserAgent(profile.UserAgent),
	}
	c := NewClient("", append(initial, opts...)...)
	c.userAgent, c.lang = profile.UserAgent, profile.Language
	c.androidApp = &androidAppState{profile: profile, now: time.Now}
	return c, nil
}

// AndroidAppProfile returns a private-state snapshot, including the resolved
// psign and the native UID obtained after registration or login.
func (c *Client) AndroidAppProfile() *AndroidAppProfile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.androidApp == nil {
		return nil
	}
	profile := copyAndroidAppProfile(c.androidApp.profile)
	return &profile
}

func (c *Client) isAndroidApp() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.androidApp != nil
}

func (c *Client) androidAppTime() int64 {
	c.mu.RLock()
	now := c.androidApp.now
	c.mu.RUnlock()
	return now().UnixMilli()
}

func (c *Client) androidAppSigner(profile AndroidAppProfile) (*AndroidSigner, error) {
	return NewAndroidSigner(AndroidSigningConfig{DeviceID: profile.DeviceID, UID: profile.UID,
		EncodedSK: profile.EncodedSK, Version: profile.Version, Channel: profile.NativeChannel})
}

func (c *Client) androidH5Rand(profile AndroidAppProfile, timestamp int64) (string, error) {
	// URLHandler returns the original URL without a native SK. JSONObject.put
	// then removes the null rand key, and the Hy JS destructuring defaults to 0.
	if profile.EncodedSK == "" {
		return "0", nil
	}
	signer, err := c.androidAppSigner(profile)
	if err != nil {
		return "", err
	}
	ndus, _ := c.CookieValue("ndus")
	signed, err := signer.SignURL("https://www.terabox.com/?time="+strconv.FormatInt(timestamp, 10)+"&version="+url.QueryEscape(profile.Version), ndus)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(signed)
	if value := u.Query().Get("rand"); value != "" {
		return value, nil
	}
	return "0", nil
}

func (c *Client) androidH5Query() (url.Values, error) {
	profile := *c.AndroidAppProfile()
	timestamp := c.androidAppTime()
	rand, err := c.androidH5Rand(profile, timestamp)
	if err != nil {
		return nil, err
	}
	query := url.Values{"language_type": {""}, "app_id": {"250528"}, "web": {"1"},
		"clienttype": {strconv.Itoa(profile.ClientType)}, "channel": {profile.Channel},
		"version": {profile.Version}, "devuid": {profile.DeviceID}, "cuid": {profile.DeviceID},
		"lang": {profile.Language}, "time": {strconv.FormatInt(timestamp, 10)}, "rand": {rand},
		"zid": {""}, "jsToken": {c.dataSnapshot().jsToken}}
	for key, value := range profile.CKData {
		query.Set(key, value)
	}
	return query, nil
}

func (c *Client) androidH5Form() *formValues {
	profile := c.AndroidAppProfile()
	form := newForm()
	form.Append("version", profile.Version)
	form.Append("devuid", profile.DeviceID)
	form.Append("cuid", profile.DeviceID)
	form.Append("lang", profile.Language)
	form.Append("client", "android")
	form.Append("pass_version", "2.8")
	form.Append("clientfrom", "h5")
	form.Append("psign", profile.PSign)
	form.Append("pcftoken", c.dataSnapshot().pcfToken)
	return form
}

func (c *Client) androidH5Headers() map[string]string {
	profile := c.AndroidAppProfile()
	page, _ := url.Parse(profile.PageURL)
	return map[string]string{"Referer": profile.PageURL, "Origin": urlOrigin(page),
		"X-Requested-With": "XMLHttpRequest", "Accept": "application/json, text/plain, */*"}
}

// androidAppAPIRequest is the native API path. Guest Retrofit requests carry a
// bare rand; the explicit H5 rand=0 fallback belongs only to the Hy builder.
func (c *Client) androidAppAPIRequest(req *http.Request) (*http.Request, error) {
	profile := c.AndroidAppProfile()
	if profile == nil || strings.Contains(req.URL.Path, "/passport/") {
		return req, nil
	}
	clone := req.Clone(req.Context())
	query := clone.URL.Query()
	query.Del("web")
	query.Del("jsToken")
	query.Del("bdstoken")
	query.Del("rand")
	legacy := clone.URL.Path == "/api/shorturlinfo" || clone.URL.Path == "/api/report/user"
	params := profile.NativeParams
	if legacy {
		params = profile.LegacyNativeParams
	} else {
		query.Del("app_id")
		query.Del("app_name")
	}
	for key, value := range params {
		query.Set(key, value)
	}
	query.Del("rand")
	if legacy {
		if cookie, err := clone.Cookie("ndus"); err == nil && cookie.Value != "" {
			query.Set("bdstoken", fmt.Sprintf("%x", md5.Sum([]byte(cookie.Value))))
		}
	}
	query.Set("clienttype", strconv.Itoa(profile.ClientType))
	query.Set("channel", profile.NativeChannel)
	query.Set("version", profile.Version)
	query.Set("devuid", profile.DeviceID)
	query.Set("cuid", profile.DeviceID)
	query.Set("lang", profile.Language)
	timestamp := c.androidAppTime()
	query.Set("time", strconv.FormatInt(timestamp, 10))
	if captured := query.Get("logid"); captured != "" {
		logID, err := refreshAndroidLogID(captured, timestamp)
		if err != nil {
			return nil, err
		}
		query.Set("logid", logID)
	}
	clone.URL.RawQuery = query.Encode()
	clone.Header.Del("X-Requested-With")
	clone.Header.Del("Accept")
	clone.Header.Set("Referer", "https://terabox.com/")
	clone.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	clone.Header.Set("User-Agent", profile.UserAgent)
	if profile.EncodedSK != "" {
		signer, err := c.androidAppSigner(*profile)
		if err != nil {
			return nil, err
		}
		ndus := ""
		if cookie, err := clone.Cookie("ndus"); err == nil {
			ndus = cookie.Value
		}
		signed, err := signer.SignURL(clone.URL.String(), ndus)
		if err != nil {
			return nil, err
		}
		clone.URL, err = url.Parse(signed)
		if err != nil {
			return nil, err
		}
	} else if !legacy {
		// New Retrofit's nullable rand parameter is rendered as a bare name by
		// OkHttp. The old shorturlinfo transport skips signing for a guest.
		clone.URL.RawQuery += "&rand"
	}
	return clone, nil
}

func refreshAndroidLogID(captured string, timestamp int64) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(captured, "="))
	parts := strings.Split(string(decoded), ",")
	if err != nil || len(parts) != 3 {
		return "", errors.New("Android app logid must contain the captured native timestamp/IP/random tuple")
	}
	nonce, err := rand.Int(rand.Reader, big.NewInt(999999))
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%d,%s,%d", timestamp, parts[1], nonce))), nil
}

func (c *Client) ensureAndroidApp(ctx context.Context) error {
	c.mu.RLock()
	state := c.androidApp
	c.mu.RUnlock()
	state.bootMu.Lock()
	defer state.bootMu.Unlock()
	c.mu.RLock()
	ready := state.ready
	c.mu.RUnlock()
	if ready {
		return nil
	}
	if err := c.resolveAndroidPSign(ctx); err != nil {
		return err
	}
	return c.loadAndroidHyPage(ctx)
}

func androidPSign(deviceID, pp3 string) string {
	first := fmt.Sprintf("%x", md5.Sum([]byte(deviceID+"android"+pp3)))
	return fmt.Sprintf("%x", md5.Sum([]byte(first+pp3)))
}

func (c *Client) resolveAndroidPSign(ctx context.Context) error {
	profile := c.AndroidAppProfile()
	if profile.PSign != "" {
		return nil
	}
	form := newForm()
	form.Append("client", "android")
	form.Append("pass_version", "2.0")
	form.Append("devuid", profile.DeviceID)
	form.Append("psign", "")
	query := url.Values{"app_id": {"250528"}, "clienttype": {strconv.Itoa(profile.ClientType)},
		"channel": {profile.NativeChannel}, "version": {profile.Version}, "devuid": {profile.DeviceID},
		"cuid": {profile.DeviceID}, "lang": {profile.Language}, "time": {strconv.FormatInt(c.androidAppTime(), 10)}}
	for key, value := range profile.LegacyNativeParams {
		query.Set(key, value)
	}
	query.Del("rand")
	timestamp := c.androidAppTime()
	query.Set("time", strconv.FormatInt(timestamp, 10))
	if captured := query.Get("logid"); captured != "" {
		logID, err := refreshAndroidLogID(captured, timestamp)
		if err != nil {
			return err
		}
		query.Set("logid", logID)
	}
	var response struct {
		Code int `json:"code"`
		Data struct {
			PP3 string `json:"pp3"`
		} `json:"data"`
	}
	pp3 := "dubox"
	err := c.doJSON(ctx, "androidAppPSign", &requestOpts{method: http.MethodPost,
		path: "/passport/getpubkey", query: query, form: form,
		headers: map[string]string{"Referer": "https://terabox.com/"}}, &response)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil && response.Code == 0 && response.Data.PP3 != "" {
		pp3 = response.Data.PP3
	}
	c.mu.Lock()
	c.androidApp.profile.PSign = androidPSign(profile.DeviceID, pp3)
	c.mu.Unlock()
	return nil
}

var androidObjectAssignment = regexp.MustCompile(`(?:var\s+|let\s+|const\s+|window\.)?(templateData|__INITIAL_STATE__)\s*=\s*`)
var androidFSEC = regexp.MustCompile(`(?i)(?:window\s*\.\s*fsec\s*=|(?:var|let|const)\s+fsec\s*=|<script[^>]+src\s*=[^>]*fsec)`)

func androidPageObjects(page string) []string {
	var objects []string
	for _, match := range androidObjectAssignment.FindAllStringIndex(page, -1) {
		start := match[1]
		if start >= len(page) || page[start] != '{' {
			continue
		}
		depth, quoted, escaped := 0, false, false
		for i := start; i < len(page); i++ {
			ch := page[i]
			if quoted {
				if escaped {
					escaped = false
				} else if ch == '\\' {
					escaped = true
				} else if ch == '"' {
					quoted = false
				}
				continue
			}
			if ch == '"' {
				quoted = true
			} else if ch == '{' {
				depth++
			} else if ch == '}' {
				depth--
				if depth == 0 {
					objects = append(objects, page[start:i+1])
					break
				}
			}
		}
	}
	return objects
}

func (c *Client) loadAndroidHyPage(ctx context.Context) error {
	profile := c.AndroidAppProfile()
	target, _ := url.Parse(profile.PageURL)
	_, _, cookies := c.snapshot()
	var pending []*http.Cookie
	for hops := 0; ; hops++ {
		if target.Path != "/wap/hylogin" && !strings.HasPrefix(target.Path, "/wap/hylogin/") {
			return errors.New("Android Hy bootstrap redirected outside the app login pages")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", profile.UserAgent)
		if cookies != "" {
			req.Header.Set("Cookie", cookies)
		}
		response, err := c.doHTTP(req, c.timeout)
		if err != nil {
			return err
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			if hops >= 5 {
				response.Body.Close()
				return errors.New("too many Android Hy redirects")
			}
			next, err := response.Location()
			if err == nil {
				err = c.validateEndpoint(next)
			}
			pending = append(pending, response.Cookies()...)
			response.Body.Close()
			if err != nil {
				return err
			}
			target = next
			values := make(map[string]string)
			for _, cookie := range pending {
				values[cookie.Name] = cookie.Value
			}
			cookies = c.CookieString()
			if extra := serializeCookies(values); extra != "" {
				cookies += "; " + extra
			}
			continue
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return &httpStatusError{StatusCode: response.StatusCode}
		}
		page, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		response.Body.Close()
		if readErr != nil {
			return readErr
		}
		if androidFSEC.Match(page) {
			return errors.New("Android Hy page requires fsec email encryption; capture its encryptor before sending email")
		}
		var data TemplateData
		for _, raw := range androidPageObjects(string(page)) {
			var entry TemplateData
			if err := json.Unmarshal([]byte(raw), &entry); err != nil {
				return fmt.Errorf("invalid Android Hy page data: %w", err)
			}
			if entry.PcfToken != "" {
				data = entry
				break
			}
		}
		if data.PcfToken == "" {
			return errors.New("Android Hy page did not provide pcftoken")
		}
		pending = append(pending, response.Cookies()...)
		c.mu.Lock()
		mergeCookieValues(c.cookies, pending)
		c.whost = urlOrigin(target)
		c.data.pcfToken, c.data.jsToken = data.PcfToken, data.JsToken
		c.androidApp.profile.PageURL = target.String()
		c.androidApp.ready = true
		c.mu.Unlock()
		return nil
	}
}

func (c *Client) androidH5JSON(ctx context.Context, op, path string, form *formValues, out any, onResponse func(*http.Response)) error {
	query, err := c.androidH5Query()
	if err != nil {
		return wrapErr(op, err)
	}
	return c.doJSON(ctx, op, &requestOpts{method: http.MethodPost, path: path,
		query: query, form: form, headers: c.androidH5Headers(), onResponse: onResponse}, out)
}

func (c *Client) doPassportJSON(ctx context.Context, op string, options *requestOpts, out any) error {
	if !c.isAndroidApp() {
		return c.doJSON(ctx, op, options, out)
	}
	if err := c.ensureAndroidApp(ctx); err != nil {
		return wrapErr(op, err)
	}
	query, err := c.androidH5Query()
	if err != nil {
		return wrapErr(op, err)
	}
	copy := *options
	copy.query, copy.headers, copy.noCookie = query, c.androidH5Headers(), false
	if copy.method == http.MethodGet {
		copy.query.Set("psign", c.AndroidAppProfile().PSign)
	}
	return c.doJSON(ctx, op, &copy, out)
}

func (c *Client) registrationSessionTracked() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.referral != nil || c.androidApp != nil
}

func androidPasswordValid(password string) bool {
	if len(password) < 8 || len(password) > 20 {
		return false
	}
	var kinds [4]bool
	for _, ch := range password {
		switch {
		case ch >= 'a' && ch <= 'z':
			kinds[0] = true
		case ch >= 'A' && ch <= 'Z':
			kinds[1] = true
		case ch >= '0' && ch <= '9':
			kinds[2] = true
		default:
			kinds[3] = true
		}
	}
	count := 0
	for _, found := range kinds {
		if found {
			count++
		}
	}
	return count >= 3
}

func androidLoginPRand(pre *PreLoginResponse, email, encrypted, deviceID string) string {
	value := pre.SevalVal() + "-" + email + "-" + encrypted + "-" + pre.RandomVal() + "-" +
		strconv.FormatInt(pre.TimestampVal(), 10) + "-" + deviceID + "-android"
	return fmt.Sprintf("%x", md5.Sum([]byte(value)))
}

func androidFinishIdentity(response *PassportResponse, cookieNDUS string) (string, string, error) {
	var data struct {
		NDUS string          `json:"ndus"`
		UID  json.RawMessage `json:"userid"`
	}
	if err := json.Unmarshal(response.Data, &data); err != nil {
		return "", "", fmt.Errorf("invalid Android account result: %w", err)
	}
	var uid string
	if len(data.UID) > 0 && data.UID[0] == '"' {
		if err := json.Unmarshal(data.UID, &uid); err != nil {
			return "", "", err
		}
	} else {
		uid = string(data.UID)
	}
	if parsed, err := strconv.ParseUint(uid, 10, 64); err != nil || parsed == 0 || data.NDUS == "" {
		return "", "", errors.New("Android account result is missing native ndus or userid")
	}
	if cookieNDUS != "" && cookieNDUS != data.NDUS {
		return "", "", errors.New("Android account ndus does not match its response cookie")
	}
	return data.NDUS, uid, nil
}

// RefreshAndroidAppConfig performs the app's separate post-login ReportUser
// request. Persist the successful registration first. Refresh failures leave
// the native account and its existing configuration intact.
func (c *Client) RefreshAndroidAppConfig(ctx context.Context) error {
	const op = "refreshAndroidAppConfig"
	profile := c.AndroidAppProfile()
	ndus, _ := c.CookieValue("ndus")
	if profile == nil || profile.UID == "" || ndus == "" {
		return wrapErr(op, errors.New("own authenticated Android UID and ndus are required"))
	}
	if len(profile.ReportParams) == 0 || profile.ReportParams["action"] != "ANDROID_ACTIVE_FRONTDESK" ||
		profile.ReportParams["start_source"] == "" || profile.ReportParams["push_on"] == "" || profile.ReportParams["backup_on "] == "" {
		return wrapErr(op, errors.New("captured foreground ReportParams are required for Android configuration refresh"))
	}
	query := url.Values{}
	for key, value := range profile.ReportParams {
		query.Set(key, value)
	}
	query.Set("timestamp", strconv.FormatInt(c.androidAppTime(), 10))
	var response struct {
		Errno *int   `json:"errno"`
		Code  *int   `json:"code"`
		Msg   string `json:"errmsg"`
		Alias string `json:"error_msg"`
		UInfo string `json:"uinfo"`
	}
	if err := c.doJSON(ctx, op, &requestOpts{method: http.MethodGet,
		path: "/api/report/user", query: query}, &response); err != nil {
		return err
	}
	code := 0
	if response.Code != nil && *response.Code != 0 {
		code = *response.Code
	} else if response.Errno == nil {
		return wrapErr(op, errors.New("Android configuration response is missing errno"))
	} else {
		code = *response.Errno
	}
	if code != 0 {
		message := response.Msg
		if message == "" {
			message = response.Alias
		}
		return wrapErr(op, &APIError{Code: code, Message: message})
	}
	if response.UInfo == "" {
		return wrapErr(op, errors.New("Android configuration response is missing uinfo"))
	}
	if _, err := DecodeAndroidSK(profile.UID, response.UInfo); err != nil {
		return wrapErr(op, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cookies["ndus"] != ndus || c.androidApp.profile.UID != profile.UID {
		return wrapErr(op, errors.New("Android account changed during configuration refresh"))
	}
	c.androidApp.profile.EncodedSK = response.UInfo
	return nil
}
