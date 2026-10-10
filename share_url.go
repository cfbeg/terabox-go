package terabox

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseShareURL extracts the normalized surl from an HTTPS TeraBox share URL.
// It accepts /s/1<key> and /sharing/link?surl=<key> on terabox.com or one of
// its subdomains. The /s/ prefix contains an extra leading 1; a query surl
// is already normalized and is returned unchanged. Other query parameters,
// such as pwd, are ignored. Bare keys, fragments, userinfo, nonstandard
// ports, and ambiguous or malformed share identifiers are rejected.
func ParseShareURL(rawURL string) (string, error) {
	const op = "parseShareURL"
	invalid := func(message string) (string, error) {
		return "", wrapErr(op, fmt.Errorf("invalid share URL: %s", message))
	}
	if strings.Contains(rawURL, "#") {
		return invalid("fragments are not supported")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", wrapErr(op, fmt.Errorf("invalid share URL: %w", err))
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Opaque != "" {
		return invalid("an absolute HTTPS URL is required")
	}
	if u.User != nil {
		return invalid("userinfo is not supported")
	}
	host := strings.ToLower(u.Hostname())
	if host != TeraBoxDomain && !strings.HasSuffix(host, "."+TeraBoxDomain) {
		return invalid("host must belong to terabox.com")
	}
	// Validate every label rather than accepting malformed names that merely
	// end in .terabox.com, such as an empty label or one containing a slash.
	if len(host) > 253 {
		return invalid("host is too long")
	}
	for _, label := range strings.Split(host, ".") {
		if !validRegionPrefix(label) {
			return invalid("host contains an invalid DNS label")
		}
	}
	if u.Port() != "" && u.Port() != "443" {
		return invalid("only the HTTPS port 443 is supported")
	}
	if strings.Contains(u.Host, ":") && u.Port() == "" {
		return invalid("port is empty")
	}
	escapedPath := strings.ToLower(u.EscapedPath())
	if strings.Contains(escapedPath, "%2f") || strings.Contains(escapedPath, "%5c") || shareURLHasControl(u.Path) {
		return invalid("path contains an escaped separator or a control character")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", wrapErr(op, fmt.Errorf("invalid share URL query: %w", err))
	}
	for name, values := range query {
		if shareURLHasControl(name) {
			return invalid("query contains a control character")
		}
		for _, value := range values {
			if shareURLHasControl(value) {
				return invalid("query contains a control character")
			}
		}
	}
	if len(query["surl"]) > 1 {
		return invalid("surl must occur only once")
	}

	var key string
	switch {
	case strings.HasPrefix(u.Path, "/s/1"):
		if _, exists := query["surl"]; exists {
			return invalid("path and query cannot both specify surl")
		}
		key = strings.TrimPrefix(u.Path, "/s/1")
	case u.Path == "/sharing/link":
		values := query["surl"]
		if len(values) != 1 {
			return invalid("query must contain one surl")
		}
		key = values[0]
	default:
		return invalid("unsupported share path")
	}
	if err := validateShareKey(key); err != nil {
		return invalid(err.Error())
	}
	return key, nil
}

// validateShareKey validates an already normalized surl; it never removes a
// leading 1, which belongs only to the /s/1<key> URL representation.
func validateShareKey(key string) error {
	if key == "" {
		return fmt.Errorf("surl must not be empty")
	}
	for i := 0; i < len(key); i++ {
		ch := key[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return fmt.Errorf("surl must contain only ASCII letters, digits, underscores, or hyphens")
		}
	}
	return nil
}

func shareURLHasControl(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return true
		}
	}
	return false
}
