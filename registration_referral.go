package terabox

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// WebmasterReferral records the shared link used to enter registration.
// ShareFromSURL and WebmasterUK are local attribution metadata, not invented
// passport form fields or cookies. The wire flow uses the web client's
// reg_source, first_referer, Referer, and actual server-issued cookies.
type WebmasterReferral struct {
	ShareURL      string      `json:"share_url"`
	ShareFromSURL string      `json:"share_from_surl"`
	WebmasterUK   int64       `json:"webmaster_uk"`
	ShareID       int64       `json:"share_id"`
	Files         []FileEntry `json:"files,omitempty"`
	Source        string      `json:"source,omitempty"`
}

// WebmasterReferralOptions selects one of the shared-page sources observed in
// the current Web dialog. Empty Source uses "share". "web_share" enables the
// dialog's koltype=1 sendcode path; "web_share_videoplay" is also supported.
type WebmasterReferralOptions struct {
	Source string
}

func validateReferralSource(source string) error {
	if source != "" && source != "share" && source != "web_share" && source != "web_share_videoplay" {
		return errors.New("registration source must be share, web_share, or web_share_videoplay")
	}
	return nil
}

func cloneWebmasterReferral(ref *WebmasterReferral) *WebmasterReferral {
	if ref == nil {
		return nil
	}
	clone := *ref
	clone.Files = append([]FileEntry(nil), ref.Files...)
	return &clone
}

// WebmasterReferral returns a copy of the prepared registration attribution.
func (c *Client) WebmasterReferral() *WebmasterReferral {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneWebmasterReferral(c.referral)
}

// PrepareWebmasterReferral resolves a public shared link before RegisterSendCode.
// Use a separate unauthenticated Client per registration. This method reads
// public share metadata only; it does not register an account or transfer files.
func (c *Client) PrepareWebmasterReferral(ctx context.Context, shareURL string) (*WebmasterReferral, error) {
	return c.PrepareWebmasterReferralWithOptions(ctx, shareURL, nil)
}

// PrepareWebmasterReferralWithOptions prepares the same shared-link flow with
// an explicitly selected Web dialog source.
func (c *Client) PrepareWebmasterReferralWithOptions(ctx context.Context, shareURL string, opts *WebmasterReferralOptions) (*WebmasterReferral, error) {
	const op = "prepareWebmasterReferral"
	source := "share"
	if opts != nil && opts.Source != "" {
		source = opts.Source
	}
	if err := validateReferralSource(source); err != nil {
		return nil, wrapErr(op, err)
	}
	surl, err := ParseShareURL(shareURL)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	c.mu.RLock()
	ndus := c.cookies["ndus"]
	started := c.registrationToken != "" || c.registrationFinished
	c.mu.RUnlock()
	if ndus != "" || started {
		return nil, wrapErr(op, errors.New("prepare referral on an unauthenticated client before sending a registration code"))
	}
	info, err := c.GetShareInfo(ctx, surl)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	// The current shorturlinfo endpoint may request verification while the
	// public share/list endpoint can still resolve the same link anonymously.
	if info.Errno == 400210 {
		info, err = c.GetShareList(ctx, surl, 1)
		if err != nil {
			return nil, wrapErr(op, err)
		}
	}
	if info.Errno != 0 {
		return nil, wrapErr(op, &APIError{Code: info.Errno, Message: info.ErrMsg})
	}
	if int64(info.ShareID) <= 0 || int64(info.UK) <= 0 {
		return nil, wrapErr(op, errors.New("share metadata is missing its owner or share ID"))
	}
	ref := &WebmasterReferral{
		ShareURL: shareURL, ShareFromSURL: surl,
		WebmasterUK: int64(info.UK), ShareID: int64(info.ShareID),
		Files:  append([]FileEntry(nil), info.List...),
		Source: source,
	}
	c.mu.Lock()
	c.referral = cloneWebmasterReferral(ref)
	c.mu.Unlock()
	return ref, nil
}

// WebmasterRegistrationSession preserves referral and cookie state across
// the email verification step or a transfer retry. It contains credentials;
// passwords and verification codes are never included.
type WebmasterRegistrationSession struct {
	Referral              WebmasterReferral `json:"referral"`
	Cookies               string            `json:"cookies"`
	WebHost               string            `json:"web_host"`
	RegistrationToken     string            `json:"registration_token,omitempty"`
	NDUS                  string            `json:"ndus,omitempty"`
	PCFToken              string            `json:"pcf_token,omitempty"`
	RegistrationConfirmed bool              `json:"registration_confirmed"`
	FinishAttempted       bool              `json:"finish_attempted"`
}

// WebmasterRegistrationSession returns a serializable snapshot, or nil when
// no referral was prepared. Restore it on a fresh client with
// RestoreWebmasterRegistrationSession before continuing the registration.
func (c *Client) WebmasterRegistrationSession() *WebmasterRegistrationSession {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.referral == nil {
		return nil
	}
	return &WebmasterRegistrationSession{
		Referral: *cloneWebmasterReferral(c.referral), Cookies: c.cookieHeaderLocked(),
		WebHost: c.whost, RegistrationToken: c.registrationToken,
		PCFToken: c.data.pcfToken, RegistrationConfirmed: c.registrationConfirmed,
		NDUS: c.cookies["ndus"], FinishAttempted: c.registrationFinished,
	}
}

// RestoreWebmasterRegistrationSession restores a saved referral flow on a fresh
// unauthenticated client. WebHost must be a trusted endpoint; custom origins
// must first be configured explicitly with WithWebHost.
func (c *Client) RestoreWebmasterRegistrationSession(saved *WebmasterRegistrationSession) error {
	const op = "restoreWebmasterRegistrationSession"
	if saved == nil {
		return wrapErr(op, errors.New("registration session required"))
	}
	surl, err := ParseShareURL(saved.Referral.ShareURL)
	if err != nil {
		return wrapErr(op, err)
	}
	if surl != saved.Referral.ShareFromSURL || saved.Referral.ShareID <= 0 || saved.Referral.WebmasterUK <= 0 {
		return wrapErr(op, errors.New("invalid referral metadata"))
	}
	if err := validateReferralSource(saved.Referral.Source); err != nil {
		return wrapErr(op, err)
	}
	host, err := url.Parse(saved.WebHost)
	if err != nil {
		return wrapErr(op, err)
	}
	if err := c.validateEndpoint(host); err != nil {
		return wrapErr(op, err)
	}
	if host.Path != "" || host.RawQuery != "" || host.Fragment != "" {
		return wrapErr(op, errors.New("web host must contain only an origin"))
	}
	// Reuse the established CookieString format without adding local metadata
	// to the Cookie header. The incoming client remains untouched on failure.
	restored := NewClient("", WithCookies(saved.Cookies))
	if restored.cookies["ndus"] != saved.NDUS {
		return wrapErr(op, errors.New("saved registration token does not match its session cookie"))
	}
	if saved.RegistrationConfirmed && saved.NDUS == "" {
		return wrapErr(op, errors.New("confirmed registration is missing its session cookie"))
	}
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cookies["ndus"] != "" || c.referral != nil || c.registrationToken != "" || c.registrationNDUS != "" {
		return wrapErr(op, errors.New("restore requires a fresh unauthenticated client"))
	}
	c.cookies = restored.cookies
	c.whost = saved.WebHost
	c.referral = cloneWebmasterReferral(&saved.Referral)
	c.registrationToken = saved.RegistrationToken
	c.registrationNDUS = saved.NDUS
	c.registrationConfirmed = saved.RegistrationConfirmed
	c.registrationFinished = saved.FinishAttempted || saved.NDUS != ""
	c.data = appData{logID: "0", pcfToken: saved.PCFToken}
	c.params = accountParams{cursor: "null", spaceTotal: 1 << 30, spaceAvailable: 1 << 30}
	return nil
}

func (c *Client) registrationHeaders() map[string]string {
	headers := c.passportHeaders()
	if ref := c.WebmasterReferral(); ref != nil {
		headers["Referer"] = ref.ShareURL
	}
	return headers
}

// registrationSource follows the shared-page dialog's default source. Verify
// does not carry these fields in the current web client.
func (c *Client) registrationSource(form *formValues, finishing bool) url.Values {
	ref := c.WebmasterReferral()
	if ref == nil {
		return nil
	}
	u, _ := url.Parse(ref.ShareURL) // validated when the context was prepared
	source := ref.Source
	if source == "" {
		source = "share"
	}
	query := url.Values{}
	if !finishing {
		koltype := 0
		if source == "web_share" {
			koltype = 1
		}
		if source == "web_share" || source == "web_share_videoplay" {
			source = "share"
		}
		form.Append("koltype", strconv.Itoa(koltype))
		query.Set("koltype", strconv.Itoa(koltype))
	}
	form.Append("reg_source", source)
	form.Append("first_referer", u.Hostname())
	query.Set("reg_source", source)
	return query
}

func (c *Client) validateReferralRegistrationToken(token string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.referral == nil {
		return nil
	}
	if c.registrationFinished {
		return errors.New("registration finish was already attempted; check account state and retry only the referral transfer")
	}
	if token == "" || c.registrationToken == "" || token != c.registrationToken {
		return errors.New("registration token does not match the prepared referral session")
	}
	return nil
}

func (c *Client) commitReferralRegistration(cookies []*http.Cookie, ndus string, confirmed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mergeCookieValues(c.cookies, cookies)
	c.registrationNDUS = ndus
	c.registrationConfirmed = confirmed
	c.registrationFinished = true
	// Anonymous web tokens must not be reused for an authenticated transfer.
	c.data.jsToken = ""
	c.data.bdsToken = ""
	c.data.csrf = ""
	c.params = accountParams{cursor: "null", spaceTotal: 1 << 30, spaceAvailable: 1 << 30}
}

func (c *Client) resetReferralFinishAttempt() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.referral != nil {
		c.registrationFinished = false
	}
}

// WebmasterTransferOptions selects the shared files and destination explicitly.
// A successful request may enqueue an asynchronous task; TaskID is not proof
// of transfer completion or of a webmaster acquisition count.
type WebmasterTransferOptions struct {
	FSIDs       []int64
	Destination string
	OnDup       string
}

// WebmasterRegistrationResult keeps registration and transfer outcomes
// separate. It is returned even if a later transfer fails, so callers can save
// Session and retry the transfer without creating the account again.
type WebmasterRegistrationResult struct {
	Registration *PassportResponse
	Session      *WebmasterRegistrationSession
	Transfer     *ShareTransferResponse
}

// RegisterFinishWithReferral finishes registration, then submits an explicit
// shared-file transfer using the newly authenticated session. A non-nil result
// with an error can contain a successfully created account. Do not repeat
// registration after such an error; use TransferWebmasterReferral instead.
func (c *Client) RegisterFinishWithReferral(ctx context.Context, regToken, password string, opts *WebmasterTransferOptions) (*WebmasterRegistrationResult, error) {
	const op = "registerFinishWithReferral"
	if c.WebmasterReferral() == nil {
		return nil, wrapErr(op, errors.New("prepare a webmaster referral before registration"))
	}
	if err := validateWebmasterTransferOptions(opts); err != nil {
		return nil, wrapErr(op, err)
	}
	registration, err := c.RegisterFinish(ctx, regToken, password)
	result := &WebmasterRegistrationResult{Registration: registration, Session: c.WebmasterRegistrationSession()}
	if err != nil {
		return result, wrapErr(op, err)
	}
	if registration.Code != 0 || registration.Errno != 0 {
		code := registration.Code
		if registration.Errno != 0 {
			code = registration.Errno
		}
		message := registration.Msg
		if message == "" {
			message = registration.ErrMsg
		}
		return result, wrapErr(op, &APIError{Code: code, Message: message})
	}
	if registration.NDUS == "" {
		return result, wrapErr(op, errors.New("registration response is missing an authenticated session; check account state before retrying registration"))
	}
	result.Transfer, err = c.TransferWebmasterReferral(ctx, opts)
	result.Session = c.WebmasterRegistrationSession()
	if err != nil {
		return result, wrapErr(op, err)
	}
	return result, nil
}

func validateWebmasterTransferOptions(opts *WebmasterTransferOptions) error {
	if opts == nil || len(opts.FSIDs) == 0 {
		return errors.New("select shared file IDs before finishing registration")
	}
	_, err := validateShareTransfer(opts.FSIDs, opts.Destination, &ShareTransferOptions{OnDup: opts.OnDup})
	return err
}

// TransferWebmasterReferral submits or retries only the transfer for a prepared,
// authenticated referral flow. It never sends a registration code or finishes
// registration again. Server task acceptance does not certify referral credit.
func (c *Client) TransferWebmasterReferral(ctx context.Context, opts *WebmasterTransferOptions) (*ShareTransferResponse, error) {
	const op = "transferWebmasterReferral"
	if err := validateWebmasterTransferOptions(opts); err != nil {
		return nil, wrapErr(op, err)
	}
	ref := c.WebmasterReferral()
	ndus, _ := c.CookieValue("ndus")
	if ref == nil || ndus == "" {
		return nil, wrapErr(op, errors.New("prepared referral and authenticated session required"))
	}
	c.mu.RLock()
	confirmed := c.registrationConfirmed
	c.mu.RUnlock()
	if !confirmed {
		login, err := c.CheckLogin(ctx)
		if err != nil {
			return nil, wrapErr(op, err)
		}
		if login.Errno != 0 {
			return nil, wrapErr(op, &APIError{Code: login.Errno, Message: login.ShowMsg})
		}
		if login.UK <= 0 {
			return nil, wrapErr(op, errors.New("registration session could not be confirmed"))
		}
		c.mu.Lock()
		c.registrationConfirmed = true
		c.mu.Unlock()
	}
	transfer, err := c.TransferShare(ctx, ref.ShareID, ref.WebmasterUK, opts.FSIDs, opts.Destination, &ShareTransferOptions{OnDup: opts.OnDup})
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if transfer.Errno != 0 {
		return transfer, wrapErr(op, &APIError{Code: transfer.Errno, Message: transfer.ErrMsg})
	}
	return transfer, nil
}
