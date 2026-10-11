package terabox

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
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
	// Version records the inspected app version. Empty uses AndroidAPKVersion;
	// SignURL uses the raw version query value supplied by the caller.
	Version string
}

// AndroidSigner implements the URLHandler native path whose Java invocation
// was found in APK 4.26.5. It is immutable and safe for concurrent use.
type AndroidSigner struct {
	deviceID         string
	uid              string
	version          string
	secret           []byte
	encodedSKPresent bool
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
	var secret []byte
	if cfg.EncodedSK != "" {
		var err error
		secret, err = DecodeAndroidSK(cfg.UID, cfg.EncodedSK)
		if err != nil {
			return nil, wrapErr(op, err)
		}
	}
	return &AndroidSigner{deviceID: cfg.DeviceID, uid: cfg.UID, version: cfg.Version,
		secret: secret, encodedSKPresent: cfg.EncodedSK != ""}, nil
}

var (
	androidRandPattern    = regexp.MustCompile(`[?|&]rand=(.*?)&`)
	androidTimePattern    = regexp.MustCompile(`[?|&]time=(.*?)&`)
	androidVersionPattern = regexp.MustCompile(`[?|&]version=(.*?)&`)
)

// SignURL mirrors URLHandler.handlerURL: absent net_param_sk leaves the URL
// unchanged. With a configured SK, an existing rand is retained;
// otherwise a 40-character rand is appended when nonempty time and version
// parameters exist. The native regex uses raw URL values, without decoding or
// sorting other parameters. This method does not inject a separate sign field.
// The app supplies time in epoch milliseconds, not Unix seconds.
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
	// The native handler checks the encoded Java getSK() string before URL
	// parsing. A nonempty SK decrypting to a leading NUL still passes this gate.
	if !s.encodedSKPresent {
		return rawURL, nil
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
	return rawURL + "&rand=" + androidLegacyRand(s.deviceID, s.uid, s.secret, []byte(timestamp[1]), []byte(version[1]), ndus), nil
}

// androidLegacyRand is the digest calculation after URLHandler's guards. The
// SDK-based legacy oracle vectors test this calculation separately from gates.
func androidLegacyRand(deviceID, uid string, secret, timestamp, version []byte, ndus string) string {
	inner := androidSHA1(androidJNIBytes(ndus))
	data := append([]byte(inner), androidJNIBytes(uid)...)
	data = append(data, secret...)
	data = append(data, timestamp...)
	data = append(data, androidJNIBytes(deviceID)...)
	data = append(data, version...)
	data = append(data, androidLegacySuffix...)
	return androidSHA1(data)
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
