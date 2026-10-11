package terabox

import (
	"encoding/json"
	"net/url"
	"strings"
)

// applyAndroidAccountRegion follows sendLoginResults -> ek.____.T(null,
// region_domain_prefix). Call it after committing the validated native UID
// and NDUS. Optional routing metadata must not undo account confirmation.
func (c *Client) applyAndroidAccountRegion(response *PassportResponse) {
	if c == nil || response == nil || response.Code != 0 || response.Errno != 0 {
		return
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(response.Data, &data); err != nil {
		c.warn("ignoring invalid Android account region metadata")
		return
	}
	raw, present := data["region_domain_prefix"]
	if !present {
		return
	}
	var prefix string
	if err := json.Unmarshal(raw, &prefix); err != nil || !validRegionPrefix(prefix) {
		// Do not log untrusted response values: they can contain credentials.
		c.warn("ignoring invalid Android account region metadata")
		return
	}
	prefix = strings.ToLower(prefix)
	host := TeraBoxDomain
	if prefix != "www" {
		host = prefix + "." + host
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.androidApp == nil || c.androidApp.profile.UID == "" || c.cookies["ndus"] == "" {
		return
	}
	current, err := url.Parse(c.whost)
	if err != nil || current.Scheme != "https" || current.User != nil || current.Opaque != "" ||
		current.Path != "" || current.RawQuery != "" || current.Fragment != "" ||
		(current.Port() != "" && current.Port() != "443") {
		return
	}
	currentHost := strings.ToLower(current.Hostname())
	if currentHost != TeraBoxDomain && !strings.HasSuffix(currentHost, "."+TeraBoxDomain) {
		// Explicit fixture/custom API origins stay under caller control.
		return
	}
	for _, label := range strings.Split(currentHost, ".") {
		if !validRegionPrefix(label) {
			return
		}
	}
	c.whost = "https://" + host
}
