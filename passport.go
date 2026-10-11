package terabox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// PreLoginResponse is the /passport/prelogin result.
// Older responses carried seval/random/timestamp at the top level; the
// live server nests them under data (and random can be a JSON number),
// so both layouts are decoded and resolved by the accessor methods.
type PreLoginResponse struct {
	Code      int    `json:"code"`
	LogID     int64  `json:"logid"`
	Msg       string `json:"msg"`
	Seval     string `json:"seval"`
	Random    string `json:"random"`
	Timestamp int64  `json:"timestamp"`
	Data      struct {
		Seval     string      `json:"seval"`
		Random    json.Number `json:"random"`
		Timestamp int64       `json:"timestamp"`
	} `json:"data"`
}

// SevalVal resolves the seval, preferring the observed nested layout.
func (p *PreLoginResponse) SevalVal() string {
	if p.Data.Seval != "" {
		return p.Data.Seval
	}
	return p.Seval
}

// RandomVal resolves the random value as a string.
func (p *PreLoginResponse) RandomVal() string {
	if p.Data.Random != "" {
		return p.Data.Random.String()
	}
	return p.Random
}

// TimestampVal resolves the timestamp.
func (p *PreLoginResponse) TimestampVal() int64 {
	if p.Data.Timestamp != 0 {
		return p.Data.Timestamp
	}
	return p.Timestamp
}

// PassportResponse is a generic passport response (login, register steps).
// Data is left raw because its shape varies with the flow state.
type PassportResponse struct {
	Code  int             `json:"code"`
	LogID int64           `json:"logid"`
	Msg   string          `json:"msg"`
	Data  json.RawMessage `json:"data"`
	// Errno/ErrMsg appear on risk-control responses (e.g. errno 460030
	// "dragdrop") which use a different field convention.
	Errno  int    `json:"errno"`
	ErrMsg string `json:"errmsg"`
	// RequestID/RequestIDString accompany risk-control responses; the
	// string variant preserves full precision (the numeric request_id
	// loses bits past float64 in JSON tooling). It identifies the
	// challenge on the anticapt page.
	RequestID       json.Number `json:"request_id"`
	RequestIDString string      `json:"request_id_string"`
	// Token is the registration token returned by RegisterSendCode at the
	// top level (it is NOT nested under data).
	Token       string `json:"token"`
	RetryPeriod int    `json:"retry_period"`
	CanSkipCode int    `json:"can_skip_code"`
	// NDUS is the native data.ndus from successful app login/registration,
	// checked against a Set-Cookie ndus when one is returned.
	NDUS        string `json:"-"`
	codePresent bool
}

// UnmarshalJSON records whether the passport result code was actually supplied.
// Referral registration needs that distinction before accepting a new session.
func (r *PassportResponse) UnmarshalJSON(b []byte) error {
	type plain PassportResponse
	var wire struct {
		plain
		Code *int `json:"code"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	*r = PassportResponse(wire.plain)
	if wire.Code != nil {
		r.Code = *wire.Code
		r.codePresent = true
	}
	return nil
}

// PublicKeyResponse is the /passport/getpubkey result.
type PublicKeyResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		PP1 string `json:"pp1"`
		PP2 string `json:"pp2"`
		PP3 string `json:"pp3"`
		PP4 string `json:"pp4"`
	} `json:"data"`
}

// extractNDUS pulls the ndus cookie out of a response's Set-Cookie headers.
func extractNDUS(r *http.Response) string {
	for _, ck := range r.Cookies() {
		if ck.Name == "ndus" {
			return ck.Value
		}
	}
	return ""
}

// PassportPreLogin initiates the password login flow.
func (c *Client) PassportPreLogin(ctx context.Context, email string) (*PreLoginResponse, error) {
	const op = "passportPreLogin"
	if err := c.ensureAndroidApp(ctx); err != nil {
		return nil, wrapErr(op, err)
	}

	form := c.androidH5Form()
	form.Append("email", email)
	page, _ := url.Parse(c.AndroidAppProfile().PageURL)
	form.Append("pass_logid", page.Query().Get("logId"))

	var resp PreLoginResponse
	err := c.doPassportJSON(ctx, op, &requestOpts{
		method:  http.MethodPost,
		path:    "/passport/prelogin",
		form:    form,
		headers: c.androidH5Headers(),
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// PassportLogin completes the password login flow. On success resp.NDUS
// contains the native ndus token, retained together with native UID on Client.
//
// When TeraBox risk control refuses the login (errno 460030 "dragdrop",
// or a silent code=0 with null data), it returns a *LoginChallengeError;
// its ChallengeURL can be shown to the user for manual captcha solving.
func (c *Client) PassportLogin(ctx context.Context, pre *PreLoginResponse, email, password string) (*PassportResponse, error) {
	const op = "passportLogin"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	if pre == nil {
		return nil, wrapErr(op, fmt.Errorf("prelogin response is nil"))
	}
	if pre.Code != 0 {
		return nil, wrapErr(op, &APIError{Code: pre.Code, Message: pre.Msg})
	}
	if c.dataSnapshot().pubKey == "" {
		key, err := c.GetPublicKey(ctx)
		if err != nil {
			return nil, wrapErr(op, err)
		}
		if key.Code != 0 {
			return nil, wrapErr(op, &APIError{Code: key.Code, Message: key.Msg})
		}
	}
	encpwd, err := EncryptRSA(password, c.dataSnapshot().pubKey, RSAMD5Preprocess)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	encpwd = ToURLSafeBase64(encpwd)

	seval := pre.SevalVal()
	random := pre.RandomVal()
	profile := c.AndroidAppProfile()
	prand := androidLoginPRand(pre, email, encpwd, profile.DeviceID)

	form := c.androidH5Form()
	form.Append("prand", prand)
	form.Append("email", email)
	form.Append("pwd", encpwd)
	form.Append("seval", seval)
	form.Append("random", random)
	form.Append("timestamp", strconv.FormatInt(pre.TimestampVal(), 10))
	page, _ := url.Parse(profile.PageURL)
	form.Append("vcode", "")
	form.Append("vcode_str", "")
	form.Append("pass_logid", page.Query().Get("logId"))
	form.Append("g_identity", "")
	form.Append("identity", "")
	form.Append("op_type", "2")
	form.Append("membership_info", "1")
	form.Append("choose_email", "0")

	var resp PassportResponse
	var ndus string
	var pendingCookies []*http.Cookie
	err = c.doPassportJSON(ctx, op, &requestOpts{
		method:  http.MethodPost,
		path:    "/passport/login",
		form:    form,
		headers: c.androidH5Headers(),
		onResponse: func(r *http.Response) {
			ndus = extractNDUS(r)
			pendingCookies = r.Cookies()
		},
	}, &resp)
	if err != nil {
		return nil, err
	}
	if chErr := c.maybeChallenge(&resp, true); chErr != nil {
		return nil, chErr
	}
	if resp.Code == 0 && resp.Errno == 0 {
		var uid string
		ndus, uid, err = androidFinishIdentity(&resp, ndus)
		if err != nil {
			return &resp, wrapErr(op, err)
		}
		c.mu.Lock()
		mergeCookieValues(c.cookies, pendingCookies)
		c.cookies["ndus"] = ndus
		c.androidApp.profile.UID = uid
		c.mu.Unlock()
		resp.NDUS = ndus
		c.applyAndroidAccountRegion(&resp)
	}
	return &resp, nil
}

// RegisterSendCode sends a registration verification code to the email.
// Code semantics: 0 OK, 10 invalid email, 11 already registered,
// 60 too fast (wait ~60s). On success the registration token is in
// resp.Token; pass it to RegisterVerify / RegisterFinish.
// A prepared WebmasterReferral adds the shared-page registration source
// and retains server cookies for the remaining steps.
func (c *Client) RegisterSendCode(ctx context.Context, email string) (*PassportResponse, error) {
	const op = "regSendCode"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	c.mu.RLock()
	completed := c.registrationFinished
	c.mu.RUnlock()
	if completed {
		return nil, wrapErr(op, fmt.Errorf("registration already returned a session; retry only the referral transfer"))
	}
	if err := c.ensureAndroidApp(ctx); err != nil {
		return nil, wrapErr(op, err)
	}

	form := c.androidH5Form()
	form.Append("email", email)
	form.Append("op_type", "1")
	form.Append("choose_email", "0")
	form.Append("g_identity", "")
	c.registrationSource(form)

	var resp PassportResponse
	var pendingCookies []*http.Cookie
	err := c.doPassportJSON(ctx, op, &requestOpts{
		method:     http.MethodPost,
		path:       "/passport/register_v4/sendcode",
		form:       form,
		headers:    c.androidH5Headers(),
		onResponse: func(r *http.Response) { pendingCookies = r.Cookies() },
	}, &resp)
	if err != nil {
		return nil, err
	}
	if chErr := c.maybeChallenge(&resp, false); chErr != nil {
		return nil, chErr
	}
	if resp.Code == 0 && resp.Errno == 0 {
		if !resp.codePresent {
			return &resp, wrapErr(op, fmt.Errorf("registration response is missing code"))
		}
		if resp.Token == "" {
			return &resp, wrapErr(op, fmt.Errorf("registration response is missing token"))
		}
		c.mu.Lock()
		mergeCookieValues(c.cookies, pendingCookies)
		c.registrationToken = resp.Token
		c.mu.Unlock()
		c.advanceAndroidRegistrationPage(true)
	}
	return &resp, nil
}

// RegisterVerify verifies the registration code sent by email.
// Code semantics: 0 OK, 58/59 wrong email code (58 observed live).
func (c *Client) RegisterVerify(ctx context.Context, regToken, code string) (*PassportResponse, error) {
	const op = "regVerify"
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	if err := c.validateReferralRegistrationToken(regToken); err != nil {
		return nil, wrapErr(op, err)
	}

	form := c.androidH5Form()
	form.Append("token", regToken)
	form.Append("code", code)
	form.Append("skip_code", "0")
	form.Append("support_unify", "1")
	form.Append("g_identity", "")

	var resp PassportResponse
	var pendingCookies []*http.Cookie
	err := c.doPassportJSON(ctx, op, &requestOpts{
		method:     http.MethodPost,
		path:       "/passport/register_v4/verify",
		form:       form,
		headers:    c.androidH5Headers(),
		onResponse: func(r *http.Response) { pendingCookies = r.Cookies() },
	}, &resp)
	if err != nil {
		return nil, err
	}
	if chErr := c.maybeChallenge(&resp, false); chErr != nil {
		return nil, chErr
	}
	if resp.Code == 0 && resp.Errno == 0 {
		if !resp.codePresent {
			return &resp, wrapErr(op, fmt.Errorf("verification response is missing code"))
		}
		c.mergeCookies(pendingCookies)
		c.advanceAndroidRegistrationPage(false)
	}
	return &resp, nil
}

// RegisterFinish completes registration by setting the account password
// (8-20 characters, at least three character kinds). The Client retains
// the native ndus and UID from the successful account response;
// use RegisterFinishWithReferral to additionally submit a shared transfer.
func (c *Client) RegisterFinish(ctx context.Context, regToken, password string) (*PassportResponse, error) {
	const op = "regFinish"
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	if err := c.validateReferralRegistrationToken(regToken); err != nil {
		return nil, wrapErr(op, err)
	}
	if !androidPasswordValid(password) {
		return &PassportResponse{Code: -2, LogID: 0, Msg: "invalid password"}, nil
	}

	if c.dataSnapshot().pubKey == "" {
		key, err := c.GetPublicKey(ctx)
		if err != nil {
			return nil, wrapErr(op, err)
		}
		if key.Code != 0 {
			return nil, wrapErr(op, &APIError{Code: key.Code, Message: key.Msg})
		}
	}

	encpwd, err := EncryptRSA(password, c.dataSnapshot().pubKey, RSAMD5Preprocess)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	encpwd = ToURLSafeBase64(encpwd)

	form := c.androidH5Form()
	form.Append("token", regToken)
	form.Append("pwd", encpwd)
	form.Append("g_identity", "")
	form.Append("access_token", "")

	var resp PassportResponse
	var ndus string
	var pendingCookies []*http.Cookie
	if err := ctx.Err(); err != nil {
		return nil, wrapErr(op, err)
	}
	c.mu.Lock()
	c.registrationFinished = true
	c.mu.Unlock()
	err = c.doPassportJSON(ctx, op, &requestOpts{
		method:  http.MethodPost,
		path:    "/passport/register_v4/finish",
		form:    form,
		headers: c.androidH5Headers(),
		onResponse: func(r *http.Response) {
			ndus = extractNDUS(r)
			pendingCookies = r.Cookies()
		},
	}, &resp)
	if err != nil {
		// A returned session cookie can outlive a malformed response. Preserve
		// it for account-status checks instead of silently repeating account
		// creation. The response code is explicitly unknown in this case.
		if ndus != "" {
			c.commitReferralRegistration(pendingCookies, ndus, false)
			return &PassportResponse{Code: -1, Msg: "registration outcome unknown", NDUS: ndus}, err
		}
		return nil, err
	}
	if chErr := c.maybeChallenge(&resp, false); chErr != nil {
		c.resetReferralFinishAttempt()
		return nil, chErr
	}
	if !resp.codePresent && resp.Errno == 0 {
		if ndus != "" {
			c.commitReferralRegistration(pendingCookies, ndus, false)
		}
		return &PassportResponse{Code: -1, Msg: "registration outcome unknown", NDUS: ndus},
			wrapErr(op, fmt.Errorf("registration response is missing code; check account state before retrying registration"))
	}
	if resp.Code != 0 || resp.Errno != 0 {
		c.resetReferralFinishAttempt()
	}
	if resp.Code == 0 && resp.Errno == 0 {
		nativeNDUS, uid, identityErr := androidFinishIdentity(&resp, ndus)
		if identityErr != nil {
			if ndus != "" {
				c.commitReferralRegistration(pendingCookies, ndus, false)
			}
			resp.NDUS = ndus
			return &resp, wrapErr(op, identityErr)
		}
		ndus = nativeNDUS
		pendingCookies = append(pendingCookies, &http.Cookie{Name: "ndus", Value: ndus})
		c.mu.Lock()
		c.androidApp.profile.UID = uid
		c.mu.Unlock()
		resp.NDUS = ndus
		c.commitReferralRegistration(pendingCookies, ndus, true)
		c.applyAndroidAccountRegion(&resp)
	}
	return &resp, nil
}

// GetPublicKey fetches the server RSA public key used to encrypt passwords
// and stores it in the app client state using the Hy POST request profile.
func (c *Client) GetPublicKey(ctx context.Context) (*PublicKeyResponse, error) {
	const op = "getPublicKey"
	if err := c.ensureAndroidApp(ctx); err != nil {
		return nil, wrapErr(op, err)
	}

	var resp PublicKeyResponse
	err := c.doPassportJSON(ctx, op, &requestOpts{
		method: http.MethodPost,
		path:   "/passport/getpubkey",
		form:   c.androidH5Form(),
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Code == 0 {
		pubKey, err := DecryptAES(resp.Data.PP1, resp.Data.PP2)
		if err != nil {
			return nil, wrapErr(op, err)
		}
		c.updateData(func(d *appData) { d.pubKey = pubKey })
	}
	return &resp, nil
}

// LoginChallengeError preserves the APK Hy flow's per-request verification
// response. ChallengeURL is the captured Hy page containing the app challenge
// UI; RequestID identifies the refused request. Keep the same app session when
// completing verification rather than starting a fresh registration.
type LoginChallengeError struct {
	Errno        int    // server errno (460030 when explicit)
	Code         int    // server code field
	ErrMsg       string // server errmsg/msg
	RequestID    string // request id identifying the challenge, if any
	ChallengeURL string // captured Hy page; app handles the supplied RequestID
}

func (e *LoginChallengeError) Error() string {
	return fmt.Sprintf("terabox: passport call blocked by risk control (errno=%d code=%d msg=%q); solve the captcha manually: %s",
		e.Errno, e.Code, e.ErrMsg, e.ChallengeURL)
}

func isNullJSON(d json.RawMessage) bool {
	s := strings.TrimSpace(string(d))
	return s == "" || s == "null"
}

func (c *Client) challengeURL() string {
	if profile := c.AndroidAppProfile(); profile != nil {
		return profile.PageURL
	}
	return ""
}

// maybeChallenge converts a passport risk-control response into a
// *LoginChallengeError, or nil when the response is not a refusal.
// nullDataMeansChallenge: for /passport/login a code=0 response with null
// data is a silent refusal; for the register endpoints code=0+null data
// is a legitimate success shape (the token is top-level).
func (c *Client) maybeChallenge(resp *PassportResponse, nullDataMeansChallenge bool) error {
	explicit := resp.Errno == 460030 || strings.EqualFold(resp.ErrMsg, "dragdrop")
	silent := nullDataMeansChallenge && resp.Code == 0 && isNullJSON(resp.Data)
	if !explicit && !silent {
		return nil
	}
	msg := resp.ErrMsg
	if msg == "" {
		msg = resp.Msg
	}
	if msg == "" && silent {
		msg = "login refused (code=0 with null data; risk control)"
	}
	id := resp.RequestIDString
	if id == "" && resp.RequestID != "" {
		id = resp.RequestID.String()
	}
	return &LoginChallengeError{
		Errno:        resp.Errno,
		Code:         resp.Code,
		ErrMsg:       msg,
		RequestID:    id,
		ChallengeURL: c.challengeURL(),
	}
}
