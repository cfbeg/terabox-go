package terabox

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// AndroidAPKVersion is the version of the APK used to verify native signing.
const AndroidAPKVersion = "4.26.5"

// AndroidAPKCertificateMD5 is MD5 of the inspected APK's first signing
// certificate DER, matching PackageInfo.signatures[0].toByteArray().
const AndroidAPKCertificateMD5 = "8d46bdb64111ea036427cb485633aedd"

// AndroidSigningConfig supplies the runtime values used by URLHandler.
// EncodedSK is the app/server configuration value net_param_sk, encrypted
// under UID. It is not a fixed APK secret and cannot be inferred from NDUS.
type AndroidSigningConfig struct {
	DeviceID  string
	UID       string
	EncodedSK string
	// Version is used when the HTTP integration supplies a missing version
	// parameter. Empty uses AndroidAPKVersion.
	Version string
	// Channel is the runtime app channel (android_<release>_<model>_bd-dubox_
	// <build-channel>). Client integration requires it rather than inventing
	// an Android device identity. SignURL itself does not use this field.
	Channel string
	// UserAgent optionally supplies the captured app UA for signed API calls.
	// Passport and HTML session-refresh requests retain the client's UA.
	UserAgent string
}

// AndroidSigner implements the URLHandler native path whose Java invocation
// was found in APK 4.26.5. It is immutable and safe for concurrent use.
type AndroidSigner struct {
	deviceID  string
	uid       string
	version   string
	secret    []byte
	channel   string
	userAgent string
}

// NewAndroidSigner validates the app's runtime signing configuration and
// decodes net_param_sk with the same Base64/RC4 operation as the native helper.
func NewAndroidSigner(cfg AndroidSigningConfig) (*AndroidSigner, error) {
	const op = "newAndroidSigner"
	if cfg.Version == "" {
		cfg.Version = AndroidAPKVersion
	}
	for name, value := range map[string]string{"device ID": cfg.DeviceID, "UID": cfg.UID, "version": cfg.Version} {
		if value == "" || !utf8.ValidString(value) {
			return nil, wrapErr(op, fmt.Errorf("%s must be nonempty valid UTF-8", name))
		}
	}
	secret, err := DecodeAndroidSK(cfg.UID, cfg.EncodedSK)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if !utf8.ValidString(cfg.Channel) || strings.ContainsAny(cfg.Channel, "\r\n") ||
		strings.ContainsAny(cfg.UserAgent, "\r\n") {
		return nil, wrapErr(op, errors.New("channel and User-Agent must not contain line breaks; channel must be valid UTF-8"))
	}
	return &AndroidSigner{deviceID: cfg.DeviceID, uid: cfg.UID, version: cfg.Version,
		secret: secret, channel: cfg.Channel, userAgent: cfg.UserAgent}, nil
}

var (
	androidRandPattern    = regexp.MustCompile(`[?|&]rand=(.*?)&`)
	androidTimePattern    = regexp.MustCompile(`[?|&]time=(.*?)&`)
	androidVersionPattern = regexp.MustCompile(`[?|&]version=(.*?)&`)
)

// SignURL mirrors URLHandler.handlerURL: an existing rand is retained;
// otherwise a 40-character rand is appended when nonempty time and version
// parameters exist. The native regex uses raw URL values, without decoding or
// sorting other parameters. This method does not inject a separate sign field.
// HTTP integration supplies time in epoch milliseconds, not Unix seconds.
func (s *AndroidSigner) SignURL(rawURL, ndus string) (string, error) {
	const op = "signAndroidURL"
	if s == nil || s.uid == "" || s.deviceID == "" {
		return "", wrapErr(op, errors.New("initialized Android signer required"))
	}
	if !utf8.ValidString(rawURL) || !utf8.ValidString(ndus) {
		return "", wrapErr(op, errors.New("URL and NDUS must be valid UTF-8"))
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", wrapErr(op, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", wrapErr(op, errors.New("absolute HTTP(S) URL without userinfo or fragment required"))
	}
	// JNI returns Modified UTF-8, so regex capture and digest inputs use those
	// bytes. The original Go URL is retained for its equivalent wire encoding.
	search := string(androidJNIBytes(rawURL)) + "&"
	if androidRandPattern.MatchString(search) {
		return rawURL, nil
	}
	timestamp := androidTimePattern.FindStringSubmatch(search)
	version := androidVersionPattern.FindStringSubmatch(search)
	if len(timestamp) < 2 || timestamp[1] == "" || len(version) < 2 || version[1] == "" {
		return rawURL, nil
	}
	inner := androidSHA1(androidJNIBytes(ndus))
	data := append([]byte(inner), androidJNIBytes(s.uid)...)
	data = append(data, s.secret...)
	data = append(data, timestamp[1]...)
	data = append(data, androidJNIBytes(s.deviceID)...)
	data = append(data, version[1]...)
	data = append(data, androidLegacySuffix...)
	return rawURL + "&rand=" + androidSHA1(data), nil
}

// AndroidSDKRandInput contains the six strings, in JNI declaration order,
// accepted by RandAlgorithm.getRand in libnetdisk-security-rand.so.
// Payload is the string hashed first; Key decrypts EncodedSK. The suffix
// components are Time, DeviceID, Version, and the APK certificate MD5.
// The SDK native function is present in this APK, but an active Java call
// to it was not found; Client integration uses URLHandler instead.
type AndroidSDKRandInput struct {
	DeviceID       string // JNI string 1
	Version        string // JNI string 2
	Time           string // JNI string 3; callers select its representation
	EncodedSK      string // JNI string 4
	Payload        string // JNI string 5
	Key            string // JNI string 6
	CertificateMD5 string // empty uses the inspected APK's certificate
}

// ComputeAndroidSDKRand reproduces the exported SDK native calculation.
// It returns the native digest only; it does not choose an HTTP request shape.
func ComputeAndroidSDKRand(input AndroidSDKRandInput) (string, error) {
	const op = "computeAndroidSDKRand"
	for name, value := range map[string]string{
		"device ID": input.DeviceID, "version": input.Version, "time": input.Time,
		"payload": input.Payload, "key": input.Key,
	} {
		if !utf8.ValidString(value) {
			return "", wrapErr(op, fmt.Errorf("%s must be valid UTF-8", name))
		}
	}
	if input.CertificateMD5 == "" {
		input.CertificateMD5 = AndroidAPKCertificateMD5
	}
	input.CertificateMD5 = strings.ToLower(input.CertificateMD5)
	if !CheckMD5Value(input.CertificateMD5) {
		return "", wrapErr(op, errors.New("certificate MD5 must be 32 hexadecimal characters"))
	}
	secret, err := DecodeAndroidSK(input.Key, input.EncodedSK)
	if err != nil {
		return "", wrapErr(op, err)
	}
	inner := androidSHA1(androidJNIBytes(input.Payload))
	data := append([]byte(inner), androidJNIBytes(input.Key)...)
	data = append(data, secret...)
	data = append(data, androidJNIBytes(input.Time)...)
	data = append(data, androidJNIBytes(input.DeviceID)...)
	data = append(data, androidJNIBytes(input.Version)...)
	data = append(data, input.CertificateMD5...)
	return androidSHA1(data), nil
}

// WithAndroidSigner enables the verified URLHandler signature for JSON API
// calls and chunk uploads. It supplies the Android common query values and
// reads the current NDUS cookie for each request. The default client remains
// the Web/desktop client when no signer is supplied. Passport endpoints are
// excluded, matching the APK interceptor; HTML token refresh is also kept on
// its existing Web transport path.
func WithAndroidSigner(s *AndroidSigner) Option {
	return func(c *Client) { c.androidSigner = s }
}

// SetAndroidSigner replaces or disables signing after account/config changes.
// Construct a new immutable signer when UID or net_param_sk changes. Nil
// restores the existing Web/desktop request behavior.
func (c *Client) SetAndroidSigner(s *AndroidSigner) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.androidSigner = s
}

func (c *Client) signAndroidRequest(req *http.Request) (*http.Request, error) {
	for _, segment := range strings.Split(req.URL.Path, "/") {
		if segment == "passport" {
			return req, nil
		}
	}
	c.mu.RLock()
	signer := c.androidSigner
	c.mu.RUnlock()
	if signer == nil {
		return req, nil
	}
	if signer.channel == "" {
		return nil, errors.New("Android API signing requires the runtime app channel")
	}
	// Sign the session actually present in this request's cookie snapshot.
	// A concurrent refresh may already have changed the client's cookie map.
	ndus := ""
	if cookie, err := req.Cookie("ndus"); err == nil {
		ndus = cookie.Value
	}
	u := *req.URL
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	// Preserve supplied time/version exactly. These are the actual URL values
	// used by URLHandler, even if an endpoint supplies its own version.
	if query.Get("time") == "" {
		query.Set("time", strconv.FormatInt(time.Now().UnixMilli(), 10))
	}
	if query.Get("version") == "" {
		query.Set("version", signer.version)
	}
	query.Set("devuid", signer.deviceID)
	query.Set("cuid", signer.deviceID)
	query.Set("clienttype", "1")
	query.Set("channel", signer.channel)
	query.Del("web")
	u.RawQuery = query.Encode()
	signedURL, err := signer.SignURL(u.String(), ndus)
	if err != nil {
		return nil, err
	}
	u2, err := url.Parse(signedURL)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.URL = u2
	if signer.userAgent != "" {
		clone.Header.Set("User-Agent", signer.userAgent)
	}
	return clone, nil
}
