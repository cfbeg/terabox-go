package terabox

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AndroidShareLinkReferrerInput supplies the public share page's inputs to its
// header_button Google Play route. DeepLink must already contain the supplied
// share metadata; this function never generates a share access key. PageURL is
// the exact browser location.href, including the order of its query fields.
// Agency nil reproduces JavaScript undefined; a pointer to "" retains empty.
// OpSource, when supplied, must match the page's op_source query; the producer
// does not append it as an additional referrer field.
type AndroidShareLinkReferrerInput struct {
	PageURL      string  `json:"page_url"`
	DeepLink     string  `json:"deep_link"`
	Agency       *string `json:"agency,omitempty"`
	OpSource     *string `json:"op_source,omitempty"`
	TeraLinkType int     `json:"tera_link_type,omitempty"`
}

// AndroidGeneratedShareLinkReferrer is a Go-generated input, not a value
// obtained from the Google Play Install Referrer API. InstallReferrer matches
// the observed browser-to-Play encoding layer: encodeURIComponent of the
// producer's inner query. Native /ref query-encodes that value once more.
type AndroidGeneratedShareLinkReferrer struct {
	InstallReferrer string `json:"install_referrer"`
	TeraLinkID      string `json:"tera_link_id"`
	GeneratedAtMS   int64  `json:"generated_at_ms"`
}

// GenerateAndroidShareLinkReferrer reproduces the inspected share-page
// header_button producer without network requests. It creates a fresh
// timestamp/eight-digit cryptographic random link ID for each call. Store the
// result with AndroidAttributionProvenanceShareLinkGenerated; it does not claim
// a Play installation, callback or successful attribution response.
func GenerateAndroidShareLinkReferrer(input AndroidShareLinkReferrerInput) (AndroidGeneratedShareLinkReferrer, error) {
	return generateAndroidShareLinkReferrer(input, time.Now(), rand.Reader)
}

func generateAndroidShareLinkReferrer(input AndroidShareLinkReferrerInput, now time.Time, entropy io.Reader) (AndroidGeneratedShareLinkReferrer, error) {
	const op = "generateAndroidShareLinkReferrer"
	invalid := func(message string) (AndroidGeneratedShareLinkReferrer, error) {
		return AndroidGeneratedShareLinkReferrer{}, wrapErr(op, errors.New(message))
	}
	if !attributionStringValid(input.PageURL) || !attributionStringValid(input.DeepLink) {
		return invalid("share page and deeplink must be valid UTF-8 without control characters")
	}
	for _, value := range []*string{input.Agency, input.OpSource} {
		if value != nil && !attributionStringValid(*value) {
			return invalid("share-link optional inputs contain invalid characters")
		}
	}
	page, err := url.Parse(input.PageURL)
	if err != nil || page.User != nil || page.Opaque != "" || page.Scheme != "https" || page.Host == "" {
		return invalid("share page must be an absolute HTTPS TeraBox URL")
	}
	pageQuery, err := url.ParseQuery(page.RawQuery)
	if err != nil {
		return invalid("share page query is invalid")
	}
	var surl string
	if page.Path == "/wap/share/filelist" {
		if len(pageQuery["surl"]) != 1 {
			return invalid("share page requires one normalized surl")
		}
		surl = pageQuery.Get("surl")
		_, err = ParseShareURL("https://" + page.Host + "/sharing/link?surl=" + url.QueryEscape(surl))
	} else {
		surl, err = ParseShareURL(input.PageURL)
	}
	if err != nil {
		return invalid("share page has an invalid host or share identifier")
	}
	deep, err := url.Parse(input.DeepLink)
	if err != nil || deep.Scheme != "dubox" || deep.Host != "share_detail" || deep.User != nil || deep.Path != "" || deep.Fragment != "" {
		return invalid("deeplink must be the supplied dubox share_detail URL")
	}
	deepQuery, err := url.ParseQuery(deep.RawQuery)
	if err != nil || len(deepQuery["surl"]) != 1 || deepQuery.Get("surl") != surl {
		return invalid("deeplink must contain the same single normalized surl as the share page")
	}
	for _, key := range []string{"uk", "shareid"} {
		value := deepQuery.Get(key)
		identifier, err := strconv.ParseInt(value, 10, 64)
		if len(deepQuery[key]) != 1 || err != nil || identifier <= 0 || strconv.FormatInt(identifier, 10) != value {
			return invalid("deeplink requires unambiguous positive share and owner identifiers")
		}
		if values, exists := pageQuery[key]; exists && (len(values) != 1 || values[0] != value) {
			return invalid("share page and deeplink identifiers conflict")
		}
	}
	for _, query := range []url.Values{pageQuery, deepQuery} {
		for key, values := range query {
			if shareURLHasControl(key) {
				return invalid("share query contains control characters")
			}
			for _, value := range values {
				if shareURLHasControl(value) {
					return invalid("share query contains control characters")
				}
			}
		}
	}
	if input.OpSource != nil && (len(pageQuery["op_source"]) != 1 || pageQuery.Get("op_source") != *input.OpSource) {
		return invalid("op_source input must match the share page query")
	}
	if pageQuery.Has("tera_link_id") || pageQuery.Has("tera_link_type") {
		return invalid("share page query conflicts with newly generated link identifiers")
	}
	linkType := input.TeraLinkType
	if linkType == 0 {
		linkType = 1
	}
	if linkType != 1 || now.UnixMilli() < 0 {
		return invalid("header-button generation requires link type 1 and a nonnegative generation time")
	}
	nonce, err := rand.Int(entropy, big.NewInt(100000000))
	if err != nil {
		return invalid("cannot generate the share-link random identifier")
	}
	linkID := fmt.Sprintf("%d-%08d", now.UnixMilli(), nonce.Int64())
	agency := "undefined"
	if input.Agency != nil {
		agency = *input.Agency
	}
	// This order and raw location.search copy match module 1f03. Sorting or
	// rebuilding the page query changes the producer, particularly literal '+'.
	inner := "utm_source=tera_sharelink&utm_campaign=header_button"
	inner += "&" + page.RawQuery
	inner += "&tera_link_id=" + linkID + "&tera_link_type=" + strconv.Itoa(linkType) +
		"&c=" + androidEncodeURIComponent(input.PageURL) + "&af_dp=" + androidEncodeURIComponent(input.DeepLink) + "&agency=" + agency
	return AndroidGeneratedShareLinkReferrer{InstallReferrer: androidEncodeURIComponent(inner), TeraLinkID: linkID, GeneratedAtMS: now.UnixMilli()}, nil
}

// ResolveAndroidShareLinkReferrerInput builds the shared page's canonical G2
// header route from a prepared native referral. It makes no additional HTTP
// request: ctime, expiredtype, randsk and fcount must have been returned by the
// real metadata endpoint. Missing fields are an error, including absent expiry
// type (the valid observed value 0 must not be confused with absence).
func (c *Client) ResolveAndroidShareLinkReferrerInput(ctx context.Context, shareURL string) (AndroidShareLinkReferrerInput, error) {
	const op = "resolveAndroidShareLinkReferrerInput"
	invalid := func(message string) (AndroidShareLinkReferrerInput, error) {
		return AndroidShareLinkReferrerInput{}, wrapErr(op, errors.New(message))
	}
	if err := c.requireAndroidApp(); err != nil {
		return AndroidShareLinkReferrerInput{}, wrapErr(op, err)
	}
	if err := ctx.Err(); err != nil {
		return AndroidShareLinkReferrerInput{}, wrapErr(op, err)
	}
	surl, err := ParseShareURL(shareURL)
	if err != nil {
		return invalid("a valid public share URL is required")
	}
	ref := c.WebmasterReferral()
	if ref == nil || ref.ShareFromSURL != surl || ref.WebmasterUK <= 0 || ref.ShareID <= 0 {
		return invalid("share URL must match its prepared native referral")
	}
	if ref.ShareCreateTime == nil || ref.ShareExpiredTime == nil || ref.ShareFileCount == nil || ref.Randsk == "" {
		return invalid("native referral metadata lacks share-link creation, expiry type, access key or file count")
	}
	if err := validateWebmasterShareLinkMetadata(ref); err != nil {
		return invalid("native referral contains invalid share-link metadata")
	}
	pageURL := "https://www.terabox.com/wap/share/filelist?surl=" + surl
	// e259 uses Object.entries().join with the already percent-encoded randsk
	// from the share store; encoding it again changes the native access key.
	deepLink := "dubox://share_detail?shareid=" + strconv.FormatInt(ref.ShareID, 10) +
		"&uk=" + strconv.FormatInt(ref.WebmasterUK, 10) + "&share_create_time=" + strconv.FormatInt(*ref.ShareCreateTime, 10) +
		"&randsk=" + ref.Randsk + "&share_expired_time=" + strconv.FormatInt(*ref.ShareExpiredTime, 10) +
		"&source=af_link&share_file_count=" + strconv.FormatInt(*ref.ShareFileCount, 10) + "&surl=" + surl
	// This is an explicitly selected generated header route, rather than an
	// agency observed from a browser or a Play install. Its browser defaults are
	// share flag h1, no video override, empty channel source, no CTR hit, and G2.
	agency := "h1__0_G2"
	return AndroidShareLinkReferrerInput{PageURL: pageURL, DeepLink: deepLink, Agency: &agency, TeraLinkType: 1}, nil
}

// encodeURIComponent escapes UTF-8 bytes and leaves JavaScript's literal
// punctuation !'()*~ intact. url.QueryEscape uses '+' for spaces and a
// different safe set, so it cannot reproduce the share-page producer.
func androidEncodeURIComponent(value string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte("-_.!~*'()", b) >= 0 {
			out.WriteByte(b)
		} else {
			out.WriteByte('%')
			out.WriteByte(hex[b>>4])
			out.WriteByte(hex[b&15])
		}
	}
	return out.String()
}
