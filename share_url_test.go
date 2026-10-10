package terabox

import (
	"strings"
	"testing"
)

func TestParseShareURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"report example", "https://terabox.com/s/1CmvhJKlhNQbrXOrye-toRw", "CmvhJKlhNQbrXOrye-toRw"},
		{"www", "https://www.terabox.com/s/1Ab_c-123", "Ab_c-123"},
		{"regional host", "https://jp.terabox.com/s/1key", "key"},
		{"nested subdomain", "https://a.b.terabox.com/s/1key", "key"},
		{"uppercase origin", "HTTPS://WWW.TERABOX.COM/s/1Key", "Key"},
		{"explicit HTTPS port", "https://terabox.com:443/s/1key", "key"},
		{"remove one leading digit", "https://terabox.com/s/11key", "1key"},
		{"short key", "https://terabox.com/s/1A", "A"},
		{"variable length", "https://terabox.com/s/1" + strings.Repeat("a", 80), strings.Repeat("a", 80)},
		{"path extras ignored", "https://terabox.com/s/1key?pwd=1234&tracking=example", "key"},
		{"query key", "https://www.terabox.com/sharing/link?surl=Ab_c-123", "Ab_c-123"},
		{"query leading digit unchanged", "https://terabox.com/sharing/link?surl=1key", "1key"},
		{"query one unchanged", "https://terabox.com/sharing/link?surl=1", "1"},
		{"query extras ignored", "https://terabox.com/sharing/link?pwd=1234&surl=key&tracking=example", "key"},
		{"encoded query name", "https://terabox.com/sharing/link?%73url=key", "key"},
		{"encoded ASCII query key", "https://terabox.com/sharing/link?surl=%31key", "1key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseShareURL(test.url)
			if err != nil || got != test.want {
				t.Fatalf("ParseShareURL(%q) = (%q, %v), want %q", test.url, got, err, test.want)
			}
		})
	}
}

func TestParseShareURLRejectsInvalidAndAmbiguousURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"bare key", "CmvhJKlhNQbrXOrye-toRw"},
		{"relative path", "/s/1key"},
		{"scheme relative", "//terabox.com/s/1key"},
		{"plain HTTP", "http://terabox.com/s/1key"},
		{"opaque URL", "https:terabox.com/s/1key"},
		{"userinfo", "https://user@terabox.com/s/1key"},
		{"password userinfo", "https://user:pass@terabox.com/s/1key"},
		{"nonstandard port", "https://terabox.com:8443/s/1key"},
		{"empty port", "https://terabox.com:/s/1key"},
		{"nonnumeric port", "https://terabox.com:abc/s/1key"},
		{"false domain suffix", "https://terabox.com.example.com/s/1key"},
		{"false domain prefix", "https://notterabox.com/s/1key"},
		{"false host with userinfo", "https://terabox.com@evil.example/s/1key"},
		{"empty DNS label", "https://a..terabox.com/s/1key"},
		{"invalid DNS label", "https://a_b.terabox.com/s/1key"},
		{"hyphen DNS label", "https://-a.terabox.com/s/1key"},
		{"long DNS label", "https://" + strings.Repeat("a", 64) + ".terabox.com/s/1key"},
		{"trailing domain dot", "https://terabox.com./s/1key"},
		{"empty path key", "https://terabox.com/s/"},
		{"only path prefix", "https://terabox.com/s/1"},
		{"missing leading one", "https://terabox.com/s/key"},
		{"extra path segment", "https://terabox.com/s/1key/extra"},
		{"trailing path slash", "https://terabox.com/s/1key/"},
		{"dot path segment", "https://terabox.com/s/1key/../other"},
		{"query extra path", "https://terabox.com/sharing/link/extra?surl=key"},
		{"query absent", "https://terabox.com/sharing/link"},
		{"query empty", "https://terabox.com/sharing/link?surl="},
		{"query no value", "https://terabox.com/sharing/link?surl"},
		{"query duplicate", "https://terabox.com/sharing/link?surl=first&surl=second"},
		{"encoded duplicate name", "https://terabox.com/sharing/link?surl=first&%73url=second"},
		{"path and query conflict", "https://terabox.com/s/1first?surl=second"},
		{"unverified mobile path", "https://terabox.com/wap/share/filelist?surl=key"},
		{"fragment identifier", "https://terabox.com/sharing/link#surl=key"},
		{"fragment overrides query", "https://terabox.com/sharing/link?surl=first#surl=second"},
		{"fragment on path", "https://terabox.com/s/1key#surl=other"},
		{"empty fragment", "https://terabox.com/s/1key#"},
		{"escaped path separator", "https://terabox.com/s/1key%2Fextra"},
		{"escaped path route separator", "https://terabox.com/sharing%2Flink?surl=key"},
		{"escaped backslash", "https://terabox.com/s/1key%5Cextra"},
		{"query escaped slash", "https://terabox.com/sharing/link?surl=key%2Fextra"},
		{"query escaped ampersand", "https://terabox.com/sharing/link?surl=key%26surl%3Dother"},
		{"double encoded separator", "https://terabox.com/s/1key%252Fextra"},
		{"escaped path CRLF", "https://terabox.com/s/1key%0D%0Aheader"},
		{"escaped query CRLF", "https://terabox.com/sharing/link?surl=key%0D%0Aheader"},
		{"escaped extra query CRLF", "https://terabox.com/s/1key?pwd=%0d%0a"},
		{"raw CRLF", "https://terabox.com/s/1key\r\nheader"},
		{"null character", "https://terabox.com/sharing/link?surl=key%00"},
		{"unicode key", "https://terabox.com/s/1日本語"},
		{"punctuation key", "https://terabox.com/sharing/link?surl=key.txt"},
		{"plus key", "https://terabox.com/sharing/link?surl=key+extra"},
		{"malformed query escaping", "https://terabox.com/sharing/link?surl=key&pwd=%zz"},
		{"malformed query separator", "https://terabox.com/sharing/link?surl=key;pwd=1234"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseShareURL(test.url)
			if err == nil || got != "" {
				t.Fatalf("ParseShareURL(%q) = (%q, %v), want an error and no key", test.url, got, err)
			}
		})
	}
}
