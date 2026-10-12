package terabox

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"unicode/utf8"
)

// WebmasterReferral records the shared link used to enter registration.
// ShareFromSURL and WebmasterUK are local attribution metadata, not invented
// passport form fields or cookies. The APK Hy flow sends reg_source=share
// during SendCode and retains its captured app profile and server cookies.
type WebmasterReferral struct {
	ShareURL        string `json:"share_url"`
	ShareFromSURL   string `json:"share_from_surl"`
	WebmasterUK     int64  `json:"webmaster_uk"`
	ShareID         int64  `json:"share_id"`
	ShareCreateTime *int64 `json:"share_create_time,omitempty"`
	// ShareExpiredTime retains expiredtype, as used by the JS deeplink producer;
	// despite its wire name, it is not an expiration timestamp.
	ShareExpiredTime *int64      `json:"share_expired_time,omitempty"`
	ShareFileCount   *int64      `json:"share_file_count,omitempty"`
	Randsk           string      `json:"randsk,omitempty"`
	Files            []FileEntry `json:"files,omitempty"`
	Source           string      `json:"source,omitempty"`
}

// WebmasterReferralOptions selects the APK's shared-page source "share".
type WebmasterReferralOptions struct {
	Source string
}

func validateReferralSource(source string) error {
	if source != "" && source != "share" {
		return errors.New("registration source must be the APK's share source")
	}
	return nil
}

func cloneWebmasterReferral(ref *WebmasterReferral) *WebmasterReferral {
	if ref == nil {
		return nil
	}
	clone := *ref
	clone.Files = append([]FileEntry(nil), ref.Files...)
	for _, field := range []struct {
		source *int64
		target **int64
	}{
		{ref.ShareCreateTime, &clone.ShareCreateTime}, {ref.ShareExpiredTime, &clone.ShareExpiredTime}, {ref.ShareFileCount, &clone.ShareFileCount},
	} {
		if field.source != nil {
			value := *field.source
			*field.target = &value
		}
	}
	return &clone
}

func validateWebmasterShareLinkMetadata(ref *WebmasterReferral) error {
	for _, field := range []*int64{ref.ShareCreateTime, ref.ShareExpiredTime, ref.ShareFileCount} {
		if field != nil && *field < 0 {
			return errors.New("invalid optional share-link numeric metadata")
		}
	}
	if !attributionStringValid(ref.Randsk) || shareURLHasControl(ref.Randsk) {
		return errors.New("invalid share-link access key metadata")
	}
	return nil
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
// the APK's share source.
func (c *Client) PrepareWebmasterReferralWithOptions(ctx context.Context, shareURL string, opts *WebmasterReferralOptions) (*WebmasterReferral, error) {
	const op = "prepareWebmasterReferral"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
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
	for _, field := range []struct {
		source *Int64ish
		target **int64
	}{
		{info.CTime, &ref.ShareCreateTime}, {info.ExpiredType, &ref.ShareExpiredTime}, {info.FCount, &ref.ShareFileCount},
	} {
		if field.source != nil {
			value := int64(*field.source)
			*field.target = &value
		}
	}
	ref.Randsk = info.Randsk
	if err := validateWebmasterShareLinkMetadata(ref); err != nil {
		return nil, wrapErr(op, err)
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
	Referral              WebmasterReferral         `json:"referral"`
	Cookies               string                    `json:"cookies"`
	WebHost               string                    `json:"web_host"`
	RegistrationToken     string                    `json:"registration_token,omitempty"`
	NDUS                  string                    `json:"ndus,omitempty"`
	PCFToken              string                    `json:"pcf_token,omitempty"`
	HyJSToken             string                    `json:"hy_js_token,omitempty"`
	HyRuntime             *AndroidHyRuntimeSnapshot `json:"hy_runtime,omitempty"`
	HyRuntimeJSToken      string                    `json:"hy_runtime_js_token,omitempty"`
	PendingChallenge      *AndroidPassportChallenge `json:"pending_challenge,omitempty"`
	ChallengeIdentity     *AndroidChallengeIdentity `json:"challenge_identity,omitempty"`
	RegistrationConfirmed bool                      `json:"registration_confirmed"`
	FinishAttempted       bool                      `json:"finish_attempted"`
	AndroidApp            *AndroidAppProfile        `json:"android_app,omitempty"`
	AndroidAttribution    *AndroidAttributionState  `json:"android_attribution,omitempty"`
}

// WebmasterRegistrationSession returns a serializable app snapshot, including
// registrations without a referral. Restore it on a fresh app client with
// RestoreWebmasterRegistrationSession before continuing the registration.
func (c *Client) WebmasterRegistrationSession() *WebmasterRegistrationSession {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.androidApp == nil {
		return nil
	}
	result := &WebmasterRegistrationSession{
		Cookies: c.cookieHeaderLocked(),
		WebHost: c.whost, RegistrationToken: c.registrationToken,
		PCFToken: c.data.pcfToken, HyJSToken: c.data.jsToken, RegistrationConfirmed: c.registrationConfirmed,
		NDUS: c.cookies["ndus"], FinishAttempted: c.registrationFinished,
	}
	if c.referral != nil {
		result.Referral = *cloneWebmasterReferral(c.referral)
	}
	profile := copyAndroidAppProfile(c.androidApp.profile)
	result.AndroidApp = &profile
	if c.androidApp.hyRuntime != nil {
		result.HyRuntime = c.androidApp.hyRuntime.snapshot()
		result.HyRuntimeJSToken = c.androidApp.runtimeJSToken
	}
	result.PendingChallenge = cloneAndroidPassportChallenge(c.data.pendingChallenge)
	result.ChallengeIdentity = cloneAndroidChallengeIdentity(c.data.challengeIdentity)
	result.AndroidAttribution = cloneAndroidAttribution(c.androidAttribution)
	return result
}

// RestoreWebmasterRegistrationSession restores a saved referral flow on a fresh
// unauthenticated client. WebHost must be a trusted endpoint; custom origins
// must first be configured explicitly with WithAPIHost.
func (c *Client) RestoreWebmasterRegistrationSession(saved *WebmasterRegistrationSession) error {
	const op = "restoreWebmasterRegistrationSession"
	if saved == nil || saved.AndroidApp == nil {
		return wrapErr(op, errors.New("registration session with a captured Android profile is required"))
	}
	if err := c.requireAndroidApp(); err != nil {
		return wrapErr(op, err)
	}
	if !utf8.ValidString(saved.HyJSToken) {
		return wrapErr(op, errors.New("saved Hy JavaScript token must be valid UTF-8"))
	}
	if saved.Referral.ShareURL != "" {
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
		if err := validateWebmasterShareLinkMetadata(&saved.Referral); err != nil {
			return wrapErr(op, err)
		}
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
	restored, err := NewAndroidAppClient(*saved.AndroidApp, WithCookies(saved.Cookies))
	if err != nil {
		return wrapErr(op, err)
	}
	if saved.RegistrationConfirmed && saved.AndroidApp.UID == "" {
		return wrapErr(op, errors.New("confirmed Android registration is missing its native UID"))
	}
	if saved.RegistrationToken != "" && saved.PCFToken == "" {
		return wrapErr(op, errors.New("saved Android registration is missing its Hy pcftoken"))
	}
	if restored.cookies["ndus"] != saved.NDUS {
		return wrapErr(op, errors.New("saved registration token does not match its session cookie"))
	}
	if saved.RegistrationConfirmed && saved.NDUS == "" {
		return wrapErr(op, errors.New("confirmed registration is missing its session cookie"))
	}
	if err := validateAndroidChallengeSnapshot(saved.PendingChallenge, saved.ChallengeIdentity); err != nil {
		return wrapErr(op, err)
	}
	runtime, err := restoreAndroidHyRuntime(context.Background(), saved.HyRuntime, restored.androidApp.profile, saved.PCFToken, saved.HyRuntimeJSToken)
	if err != nil {
		return wrapErr(op, err)
	}
	if saved.HyRuntime != nil && saved.NDUS == "" && saved.HyJSToken != saved.HyRuntimeJSToken {
		return wrapErr(op, errors.New("saved Hy runtime token does not match its active page"))
	}
	if err := validateAndroidAttributionState(saved.AndroidAttribution, restored.androidApp.profile); err != nil {
		return wrapErr(op, err)
	}
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cookies["ndus"] != "" || c.referral != nil || c.registrationToken != "" || c.registrationNDUS != "" || c.androidAttribution != nil {
		return wrapErr(op, errors.New("restore requires a fresh unauthenticated client"))
	}
	if c.androidApp.ready || c.androidApp.profile.DeviceID != saved.AndroidApp.DeviceID ||
		c.androidApp.profile.Version != saved.AndroidApp.Version ||
		c.androidApp.profile.UserAgent != restored.androidApp.profile.UserAgent ||
		c.androidApp.profile.NativeChannel != restored.androidApp.profile.NativeChannel ||
		c.androidApp.profile.ClientType != restored.androidApp.profile.ClientType ||
		c.androidApp.profile.Language != restored.androidApp.profile.Language {
		return wrapErr(op, errors.New("restore requires a fresh client with the same Android identity"))
	}
	c.cookies = restored.cookies
	c.whost = saved.WebHost
	if saved.Referral.ShareURL != "" {
		c.referral = cloneWebmasterReferral(&saved.Referral)
	}
	c.registrationToken = saved.RegistrationToken
	c.registrationNDUS = saved.NDUS
	c.registrationConfirmed = saved.RegistrationConfirmed
	c.registrationFinished = saved.FinishAttempted || saved.NDUS != ""
	c.data = appData{pcfToken: saved.PCFToken, jsToken: saved.HyJSToken,
		pendingChallenge: cloneAndroidPassportChallenge(saved.PendingChallenge), challengeIdentity: cloneAndroidChallengeIdentity(saved.ChallengeIdentity)}
	c.params = accountParams{}
	c.androidApp = restored.androidApp
	c.androidApp.hyRuntime, c.androidApp.runtimeJSToken = runtime, saved.HyRuntimeJSToken
	c.androidAttribution = cloneAndroidAttribution(saved.AndroidAttribution)
	c.androidApp.ready = saved.PCFToken != "" && c.androidApp.profile.PSign != ""
	c.userAgent, c.lang = c.androidApp.profile.UserAgent, c.androidApp.profile.Language
	return nil
}

// registrationSource follows the APK Hy screen's SendCode source field.
func (c *Client) registrationSource(form *formValues) {
	page, _ := url.Parse(c.AndroidAppProfile().PageURL)
	if page.Query().Get("from") == "share" {
		form.Append("reg_source", "share")
	}
}

func (c *Client) validateReferralRegistrationToken(token string) error {
	if err := c.requireAndroidApp(); err != nil {
		return err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
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
	// The Hy page's anonymous JavaScript token is not native transfer state.
	c.data.jsToken = ""
	c.params = accountParams{}
}

func (c *Client) resetReferralFinishAttempt() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.registrationFinished = false
}

// WebmasterTransferOptions selects the shared files and destination explicitly.
// A successful request may enqueue an asynchronous task; TaskID is not proof
// of transfer completion or of a webmaster acquisition count.
type WebmasterTransferOptions struct {
	FSIDs       []int64
	Destination string
	OnDup       string
	Route       ShareTransferRoute
	SEKey       string
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
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
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
	_, err := validateShareTransfer(opts.FSIDs, opts.Destination, &ShareTransferOptions{OnDup: opts.OnDup, Route: opts.Route, SEKey: opts.SEKey})
	return err
}

// TransferWebmasterReferral submits or retries only the transfer for a prepared,
// authenticated referral flow. It never sends a registration code or finishes
// registration again. Server task acceptance does not certify referral credit.
func (c *Client) TransferWebmasterReferral(ctx context.Context, opts *WebmasterTransferOptions) (*ShareTransferResponse, error) {
	const op = "transferWebmasterReferral"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
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
		// CheckLogin confirms that the observed NDUS is valid. Its numeric UK
		// does not establish the distinct native registration UID. A missing
		// UID must remain an unconfirmed, restorable registration snapshot.
		c.registrationConfirmed = c.androidApp.profile.UID != ""
		c.mu.Unlock()
	}
	transfer, err := c.TransferShare(ctx, ref.ShareID, ref.WebmasterUK, opts.FSIDs, opts.Destination, &ShareTransferOptions{OnDup: opts.OnDup, Route: opts.Route, SEKey: opts.SEKey})
	if err != nil {
		return transfer, wrapErr(op, err)
	}
	if transfer.Errno != 0 {
		return transfer, wrapErr(op, &APIError{Code: transfer.Errno, Message: transfer.ErrMsg})
	}
	return transfer, nil
}
