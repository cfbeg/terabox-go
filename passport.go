package terabox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	// NDUS is extracted from the Set-Cookie header on successful
	// PassportLogin / RegisterFinish calls.
	NDUS string `json:"-"`
}

// PublicKeyResponse is the /passport/getpubkey result.
type PublicKeyResponse struct {
	Code int `json:"code"`
	Data struct {
		PP1 string `json:"pp1"`
		PP2 string `json:"pp2"`
	} `json:"data"`
}

// PassportInfoResponse is the /passport/get_info result.
type PassportInfoResponse struct {
	Errno int `json:"errno"`
	Data  struct {
		DisplayName string `json:"display_name"`
	} `json:"data"`
}

// passportForm returns the common form fields for passport calls.
func (c *Client) passportForm() *formValues {
	data := c.dataSnapshot()
	f := newForm()
	f.Append("client", "web")
	f.Append("pass_version", "2.8")
	f.Append("clientfrom", "h5")
	f.Append("pcftoken", data.pcfToken)
	return f
}

func (c *Client) passportHeaders() map[string]string {
	webHost, _, _ := c.snapshot()
	return map[string]string{"Referer": webHost}
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
	if c.dataSnapshot().pcfToken == "" {
		if _, err := c.UpdateAppData(ctx, "wap/outlogin/login"); err != nil {
			return nil, wrapErr(op, err)
		}
	}

	form := c.passportForm()
	form.Append("email", email)

	var resp PreLoginResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method:  http.MethodPost,
		path:    "/passport/prelogin",
		form:    form,
		headers: c.passportHeaders(),
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// PassportLogin completes the password login flow. On success resp.NDUS
// contains the ndus token; create a new client with it.
//
// When TeraBox risk control refuses the login (errno 460030 "dragdrop",
// or a silent code=0 with null data), it returns a *LoginChallengeError;
// its ChallengeURL can be shown to the user for manual captcha solving.
func (c *Client) PassportLogin(ctx context.Context, pre *PreLoginResponse, email, password string) (*PassportResponse, error) {
	const op = "passportLogin"
	if c.dataSnapshot().pubKey == "" {
		if _, err := c.GetPublicKey(ctx); err != nil {
			return nil, wrapErr(op, err)
		}
	}
	browserid, _ := c.CookieValue("browserid")

	encpwd, err := EncryptRSA(password, c.dataSnapshot().pubKey, RSAMD5Preprocess)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	encpwd = ToURLSafeBase64(encpwd)

	seval := pre.SevalVal()
	random := pre.RandomVal()
	prand := PRandGen("web", seval, encpwd, email, browserid, random)

	form := c.passportForm()
	form.Append("prand", prand)
	form.Append("email", email)
	form.Append("pwd", encpwd)
	form.Append("seval", seval)
	form.Append("random", random)
	form.Append("timestamp", strconv.FormatInt(pre.TimestampVal(), 10))

	var resp PassportResponse
	var ndus string
	err = c.doJSON(ctx, op, &requestOpts{
		method:  http.MethodPost,
		path:    "/passport/login",
		form:    form,
		headers: c.passportHeaders(),
		onResponse: func(r *http.Response) {
			ndus = extractNDUS(r)
		},
	}, &resp)
	if err != nil {
		return nil, err
	}
	if chErr := c.maybeChallenge(&resp, true); chErr != nil {
		return nil, chErr
	}
	if resp.Code == 0 {
		resp.NDUS = ndus
	}
	return &resp, nil
}

// RegisterSendCode sends a registration verification code to the email.
// Code semantics: 0 OK, 10 invalid email, 11 already registered,
// 60 too fast (wait ~60s). On success the registration token is in
// resp.Token; pass it to RegisterVerify / RegisterFinish.
func (c *Client) RegisterSendCode(ctx context.Context, email string) (*PassportResponse, error) {
	const op = "regSendCode"
	if c.dataSnapshot().pcfToken == "" {
		if _, err := c.UpdateAppData(ctx, "wap/outlogin/emailRegister"); err != nil {
			return nil, wrapErr(op, err)
		}
	}

	form := c.passportForm()
	form.Append("email", email)

	var resp PassportResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method:  http.MethodPost,
		path:    "/passport/register_v4/sendcode",
		form:    form,
		headers: c.passportHeaders(),
	}, &resp)
	if err != nil {
		return nil, err
	}
	if chErr := c.maybeChallenge(&resp, false); chErr != nil {
		return nil, chErr
	}
	return &resp, nil
}

// RegisterVerify verifies the registration code sent by email.
// Code semantics: 0 OK, 58/59 wrong email code (58 observed live).
func (c *Client) RegisterVerify(ctx context.Context, regToken, code string) (*PassportResponse, error) {
	const op = "regVerify"

	form := c.passportForm()
	form.Append("token", regToken)
	form.Append("code", code)

	var resp PassportResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method:  http.MethodPost,
		path:    "/passport/register_v4/verify",
		form:    form,
		headers: c.passportHeaders(),
	}, &resp)
	if err != nil {
		return nil, err
	}
	if chErr := c.maybeChallenge(&resp, false); chErr != nil {
		return nil, chErr
	}
	return &resp, nil
}

// RegisterFinish completes registration by setting the account password
// (6-15 characters, at least one Latin letter). On success resp.NDUS
// contains the ndus token; create a new client with it.
func (c *Client) RegisterFinish(ctx context.Context, regToken, password string) (*PassportResponse, error) {
	const op = "regFinish"
	if c.dataSnapshot().pubKey == "" {
		if _, err := c.GetPublicKey(ctx); err != nil {
			return nil, wrapErr(op, err)
		}
	}

	hasLetter := false
	for i := 0; i < len(password); i++ {
		ch := password[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' {
			hasLetter = true
			break
		}
	}
	if len(password) < 6 || len(password) > 15 || !hasLetter {
		return &PassportResponse{Code: -2, LogID: 0, Msg: "invalid password"}, nil
	}

	encpwd, err := EncryptRSA(password, c.dataSnapshot().pubKey, RSAMD5Preprocess)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	encpwd = ToURLSafeBase64(encpwd)

	form := c.passportForm()
	form.Append("token", regToken)
	form.Append("pwd", encpwd)

	var resp PassportResponse
	var ndus string
	err = c.doJSON(ctx, op, &requestOpts{
		method:  http.MethodPost,
		path:    "/passport/register_v4/finish",
		form:    form,
		headers: c.passportHeaders(),
		onResponse: func(r *http.Response) {
			ndus = extractNDUS(r)
		},
	}, &resp)
	if err != nil {
		return nil, err
	}
	if chErr := c.maybeChallenge(&resp, false); chErr != nil {
		return nil, chErr
	}
	if resp.Code == 0 {
		resp.NDUS = ndus
	}
	return &resp, nil
}

// GetPublicKey fetches the server RSA public key used to encrypt passwords
// and stores it in the client state. The JS client sends no Cookie header
// on this call.
func (c *Client) GetPublicKey(ctx context.Context) (*PublicKeyResponse, error) {
	const op = "getPublicKey"

	var resp PublicKeyResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method:   http.MethodGet,
		path:     "/passport/getpubkey",
		noCookie: true,
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

// PassportGetInfo retrieves passport user information for the current
// session and stores the account display name.
func (c *Client) PassportGetInfo(ctx context.Context) (*PassportInfoResponse, error) {
	const op = "passportGetInfo"

	var resp PassportInfoResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/passport/get_info",
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Errno == 0 {
		name := resp.Data.DisplayName
		c.updateParams(func(p *accountParams) { p.accountName = name })
	}
	return &resp, nil
}

// LoginChallengeError is returned when TeraBox risk control refuses a
// passport call: either explicitly (errno 460030, errmsg "dragdrop") or
// silently (login answered code=0 with null data). ChallengeURL is the
// captcha page a human opens in a browser on the same network: with a
// request id it is the anticapt page tied to the refused request,
// otherwise the loginprotect fallback page.
//
// Challenges are per-request: every refusal issues a fresh RequestID
// (browser-verifying one request does not clear later ones), so always
// use the newest ChallengeURL, solve it, then retry the login.
type LoginChallengeError struct {
	Errno        int    // server errno (460030 when explicit)
	Code         int    // server code field
	ErrMsg       string // server errmsg/msg
	RequestID    string // request id identifying the challenge, if any
	ChallengeURL string // captcha page for manual solving
}

func (e *LoginChallengeError) Error() string {
	return fmt.Sprintf("terabox: passport call blocked by risk control (errno=%d code=%d msg=%q); solve the captcha manually: %s",
		e.Errno, e.Code, e.ErrMsg, e.ChallengeURL)
}

func isNullJSON(d json.RawMessage) bool {
	s := strings.TrimSpace(string(d))
	return s == "" || s == "null"
}

// challengeURL builds the captcha page URL for manual solving. With a
// request id it is the anticapt page tied to the refused request
// (observed browser flow: anticapt → /captcha/getslide →
// /captcha/checkslide); otherwise it falls back to loginprotect.
func (c *Client) challengeURL(resp *PassportResponse) string {
	webHost, _, _ := c.snapshot()
	id := resp.RequestIDString
	if id == "" && resp.RequestID != "" {
		id = resp.RequestID.String()
	}
	if id != "" {
		return webHost + "/anticapt?type=dragdrop&requestId=" + id +
			"&lang=" + c.lang + "&platform=web"
	}
	return webHost + "/wap/outlogin/loginprotect"
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
		ChallengeURL: c.challengeURL(resp),
	}
}
