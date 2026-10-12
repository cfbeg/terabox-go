package terabox

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// AndroidPassportChallenge identifies one actual refused Hy request.
type AndroidPassportChallenge struct {
	RequestID string `json:"request_id"`
	Path      string `json:"path"`
}

// AndroidChallengeIdentity carries a token obtained by completing that actual
// challenge. It is private recovery input; the SDK does not generate it.
type AndroidChallengeIdentity struct {
	RequestID string `json:"request_id"`
	Path      string `json:"path"`
	Token     string `json:"token"`
}

func cloneAndroidPassportChallenge(value *AndroidPassportChallenge) *AndroidPassportChallenge {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneAndroidChallengeIdentity(value *AndroidChallengeIdentity) *AndroidChallengeIdentity {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func androidChallengePath(path string) bool {
	switch path {
	case "/passport/register_v4/sendcode", "/passport/register_v4/verify", "/passport/register_v4/finish", "/passport/prelogin", "/passport/login":
		return true
	}
	return false
}

func validateAndroidChallengeSnapshot(pending *AndroidPassportChallenge, identity *AndroidChallengeIdentity) error {
	valid := func(value string) bool { return utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00") }
	if pending != nil && (!androidChallengePath(pending.Path) || !valid(pending.RequestID) || len(pending.RequestID) > 4096) {
		return errors.New("saved Android passport challenge is invalid")
	}
	if identity != nil && (pending == nil || identity.RequestID != pending.RequestID || identity.Path != pending.Path ||
		!valid(identity.Token) || strings.TrimSpace(identity.Token) == "" || len(identity.Token) > 16384) {
		return errors.New("Android challenge identity must match the actual pending request")
	}
	return nil
}

func (c *Client) SetAndroidChallengeIdentity(identity *AndroidChallengeIdentity) error {
	const op = "setAndroidChallengeIdentity"
	if err := c.requireAndroidApp(); err != nil {
		return wrapErr(op, err)
	}
	if identity == nil {
		return wrapErr(op, errors.New("actual challenge identity is required"))
	}
	c.registrationMu.Lock()
	defer c.registrationMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	copy := cloneAndroidChallengeIdentity(identity)
	if copy.Path == "" && c.data.pendingChallenge != nil {
		copy.Path = c.data.pendingChallenge.Path
	}
	if err := validateAndroidChallengeSnapshot(c.data.pendingChallenge, copy); err != nil {
		return wrapErr(op, err)
	}
	c.data.challengeIdentity = copy
	return nil
}

func (c *Client) androidChallengeForm(path string, form *formValues) {
	c.mu.RLock()
	identity := cloneAndroidChallengeIdentity(c.data.challengeIdentity)
	c.mu.RUnlock()
	if identity != nil && identity.Path == path {
		form.Set("g_identity", identity.Token)
	}
}

func (c *Client) clearAndroidChallenge(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data.pendingChallenge != nil && c.data.pendingChallenge.Path == path {
		c.data.pendingChallenge = nil
		c.data.challengeIdentity = nil
	}
}
