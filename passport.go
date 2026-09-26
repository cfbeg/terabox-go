package terabox

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// PreLoginResponse is the /passport/prelogin result.
type PreLoginResponse struct {
	Code      int             `json:"code"`
	LogID     int64           `json:"logid"`
	Msg       string          `json:"msg"`
	Seval     string          `json:"seval"`
	Random    string          `json:"random"`
	Timestamp int64           `json:"timestamp"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// PassportResponse is a generic passport response (login, register steps).
// Data is left raw because its shape varies with the flow state.
type PassportResponse struct {
	Code  int             `json:"code"`
	LogID int64           `json:"logid"`
	Msg   string          `json:"msg"`
	Data  json.RawMessage `json:"data"`
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

	prand := PRandGen("web", pre.Seval, encpwd, email, browserid, pre.Random)

	form := c.passportForm()
	form.Append("prand", prand)
	form.Append("email", email)
	form.Append("pwd", encpwd)
	form.Append("seval", pre.Seval)
	form.Append("random", pre.Random)
	form.Append("timestamp", strconv.FormatInt(pre.Timestamp, 10))

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
	if resp.Code == 0 {
		resp.NDUS = ndus
	}
	return &resp, nil
}

// RegisterSendCode sends a registration verification code to the email.
// Code semantics: 0 OK, 10 invalid email, 11 already registered,
// 60 too fast (wait ~60s).
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
	return &resp, nil
}

// RegisterVerify verifies the registration code sent by email.
// Code semantics: 0 OK, 59 wrong email code.
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
