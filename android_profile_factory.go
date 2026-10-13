package terabox

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"math/bits"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NewAndroidGuestProfile creates a new virtual APK installation from captured
// build constants. It generates a Cesium CUID and unique model/UA/channel, clears
// old account credentials and clones runtime maps. It performs no network or
// filesystem operations; callers should persist the result before first use.
// NewAndroidAppClient itself never generates or replaces a supplied identity.
func NewAndroidGuestProfile(template AndroidAppProfile) (AndroidAppProfile, error) {
	const op = "newAndroidGuestProfile"
	// These runtime values will not be reused, so old SK/CK values need not be
	// valid for the new installation. Validate all retained build/request fields.
	template.UID, template.EncodedSK, template.PSign = "", "", ""
	template.CKData, template.NativeCKData = nil, nil
	template.Activation = nil
	captured, err := validateAndroidAppProfile(template)
	if err != nil {
		return AndroidAppProfile{}, wrapErr(op, err)
	}
	profile, err := newAndroidGuestProfile(&captured)
	if err != nil {
		return AndroidAppProfile{}, wrapErr(op, err)
	}
	validated, err := validateAndroidAppProfile(*profile)
	if err != nil {
		return AndroidAppProfile{}, wrapErr(op, err)
	}
	return validated, nil
}

type androidBuildTemplate struct {
	model, release, assetChannel string
	uaParts                      []string
}

// androidTemplateBuild reads the APK's Build.MODEL/RELEASE-derived UA and
// channel. The APK/package and bridge versions are installation constants.
func androidTemplateBuild(profile *AndroidAppProfile) (androidBuildTemplate, error) {
	if profile == nil {
		return androidBuildTemplate{}, errors.New("Android profile template is required")
	}
	parts := strings.Split(profile.UserAgent, ";")
	if len(parts) != 9 || parts[0] != "dubox" || parts[1] != profile.Version || parts[3] != "android-android" || parts[8] != "" {
		return androidBuildTemplate{}, errors.New("Android profile template requires the APK's native dubox User-Agent format")
	}
	model, err := url.QueryUnescape(parts[2])
	if err != nil || model == "" || strings.ContainsAny(model, ";\r\n\x00") {
		return androidBuildTemplate{}, errors.New("Android profile template contains an invalid model")
	}
	release, err := url.QueryUnescape(parts[4])
	if err != nil || release == "" || strings.ContainsAny(release, ";\r\n\x00") {
		return androidBuildTemplate{}, errors.New("Android profile template contains an invalid OS release")
	}
	prefix := "android_" + release + "_" + model + "_bd-dubox_"
	if !strings.HasPrefix(profile.NativeChannel, prefix) || len(profile.NativeChannel) == len(prefix) {
		return androidBuildTemplate{}, errors.New("Android profile template UA and native channel describe different builds")
	}
	if profile.Channel != "" && profile.Channel != profile.NativeChannel && profile.Channel != profile.UserAgent {
		return androidBuildTemplate{}, errors.New("Android profile template requires its native channel or app User-Agent as the Hy channel")
	}
	return androidBuildTemplate{model: model, release: release,
		assetChannel: strings.TrimPrefix(profile.NativeChannel, prefix), uaParts: parts}, nil
}

// newAndroidGuestProfile creates one virtual installation from the captured APK
// template. Its random Android ID feeds the APK's Cesium CUID algorithm; its
// unique virtual Build.MODEL feeds the APK's UA and channel formulas. The
// profile is kept throughout the account session and saved for recovery.
func newAndroidGuestProfile(template *AndroidAppProfile) (*AndroidAppProfile, error) {
	build, err := androidTemplateBuild(template)
	if err != nil {
		return nil, err
	}
	var seed [8]byte
	for seed == [8]byte{} {
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, fmt.Errorf("generate Android installation ID: %w", err)
		}
	}
	androidID := hex.EncodeToString(seed[:])
	cuid, err := androidCUID(androidID)
	if err != nil {
		return nil, fmt.Errorf("generate APK CUID: %w", err)
	}
	now := time.Now()
	profile := *template
	profile.DeviceID = cuid
	model := build.model + "_" + androidID
	build.uaParts[2] = androidURLEncode(model)
	profile.UserAgent = strings.Join(build.uaParts, ";")
	profile.NativeChannel = "android_" + build.release + "_" + model + "_bd-dubox_" + build.assetChannel
	profile.Channel = profile.NativeChannel
	if template.Channel == template.UserAgent {
		profile.Channel = profile.UserAgent
	}

	// Account credentials, cached CUID-dependent psign, and opaque inspection
	// values belong to the old installation. A fresh APK guest starts without
	// them and resolves its own psign/PCF/cookies and post-login UID/SK.
	profile.UID, profile.EncodedSK, profile.PSign = "", "", ""
	profile.CKData, profile.NativeCKData = nil, nil
	profile.Activation = nil
	profile.NativeParams, err = freshAndroidParams(template.NativeParams, &profile, now)
	if err != nil {
		return nil, err
	}
	profile.LegacyNativeParams, err = freshAndroidParams(template.LegacyNativeParams, &profile, now)
	if err != nil {
		return nil, err
	}
	profile.ReportParams = copyAndroidStringMap(template.ReportParams)
	for _, key := range []string{"bind_uid", "source", "msg_id", "channel_id"} {
		delete(profile.ReportParams, key)
	}
	if profile.ReportParams != nil {
		// h40._.h reads the new account's MMKV token with this APK default.
		profile.ReportParams["fcm_token"] = "fcm_error_0"
		profile.ReportParams["needrookie"] = "1"
	}
	if _, present := profile.ReportParams["timestamp"]; present {
		profile.ReportParams["timestamp"] = strconv.FormatInt(now.UnixMilli(), 10)
	}

	page, err := url.Parse(template.PageURL)
	if err != nil {
		return nil, errors.New("invalid Android profile page URL")
	}
	query := page.Query()
	query.Set("devuid", cuid)
	if query.Has("cuid") {
		query.Set("cuid", cuid)
	}
	if query.Has("channel") {
		query.Set("channel", profile.Channel)
	}
	if query.Has("logId") {
		query.Set("logId", cuid+strconv.FormatInt(now.UnixMilli(), 10))
	}
	for key, value := range map[string]string{"startDevTime": strconv.FormatInt(now.UnixMilli(), 10),
		"firstlaunchtime": strconv.FormatInt(now.Unix(), 10), "time": strconv.FormatInt(now.UnixMilli(), 10)} {
		if query.Has(key) {
			query.Set(key, value)
		}
	}
	if query.Get("logid") != "" {
		logID, err := freshAndroidLogID(query.Get("logid"), now)
		if err != nil {
			return nil, err
		}
		query.Set("logid", logID)
	}
	page.RawQuery = query.Encode()
	profile.PageURL = page.String()
	return &profile, nil
}

func freshAndroidParams(template map[string]string, profile *AndroidAppProfile, now time.Time) (map[string]string, error) {
	values := copyAndroidStringMap(template)
	if values == nil {
		values = make(map[string]string)
	}
	for _, key := range []string{"ndus", "uid", "userid", "bdstoken", "rand", "secret_token", "access_token"} {
		delete(values, key)
	}
	if _, present := values["af_media_source"]; present {
		// A template's previous installation attribution is not provenance for
		// a new virtual installation. Only a real first-launch result sets it.
		values["af_media_source"] = "Undefined"
	}
	for key, value := range map[string]string{"devuid": profile.DeviceID, "cuid": profile.DeviceID,
		"channel": profile.NativeChannel, "clienttype": strconv.Itoa(profile.ClientType),
		"version": profile.Version, "lang": profile.Language, "time": strconv.FormatInt(now.UnixMilli(), 10)} {
		values[key] = value
	}
	for key, value := range map[string]string{"startDevTime": strconv.FormatInt(now.UnixMilli(), 10),
		"firstlaunchtime": strconv.FormatInt(now.Unix(), 10), "ZID": "", "isVip": "0", "vip_type": "0"} {
		if _, present := values[key]; present {
			values[key] = value
		}
	}
	if values["logid"] != "" {
		logID, err := freshAndroidLogID(values["logid"], now)
		if err != nil {
			return nil, err
		}
		values["logid"] = logID
	}
	return values, nil
}

func freshAndroidLogID(captured string, now time.Time) (string, error) {
	if _, err := capturedAndroidLogIP(captured); err != nil {
		return "", err
	}
	return refreshAndroidLogID(captured, now.UnixMilli())
}

func capturedAndroidLogIP(captured string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(captured, "="))
	parts := strings.Split(string(decoded), ",")
	if err != nil || len(parts) != 3 {
		return "", errors.New("Android profile logid requires its captured native timestamp/IP/random tuple")
	}
	// InetAddress.getHostAddress can include an IPv6 interface scope. Keep it
	// verbatim: net.ParseIP would reject the APK's captured "%interface" suffix.
	ip, err := netip.ParseAddr(parts[1])
	if err != nil || ip.IsLoopback() || ip.IsUnspecified() {
		return "", errors.New("Android profile logid requires a captured non-loopback IP")
	}
	return parts[1], nil
}

// Java URLEncoder uses application/x-www-form-urlencoded, retaining '*' but
// escaping '~'. The APK applies it to Build.MODEL and Build.VERSION.RELEASE.
func androidURLEncode(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(value), "%2A", "*"), "~", "%7E")
}

// androidCUID reproduces the APK's fresh Cesium Android-ID branch. The input
// identifies a virtual guest profile; this does not change an Android device's
// Settings.Secure.android_id or import its previously cached CUID.
//
// APK 4.26.5, classes10.dex: cesium.h.e at 0xa05054 hashes "com.baidu" plus
// Android ID, h.i at 0xa04cf8 encodes the five-byte Cesium state, and h$a.u at
// 0xa04900 joins the uppercase digest and "|V" suffix. Invalid Android IDs
// use a different UUID fallback in the APK, which this helper does not model.
func androidCUID(androidID string) (string, error) {
	if len(androidID) != 16 || androidID == "0000000000000000" {
		return "", errors.New("Android ID must be 16 nonzero hexadecimal characters")
	}
	for _, ch := range androidID {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F') {
			return "", errors.New("Android ID must be 16 nonzero hexadecimal characters")
		}
	}
	digest := fmt.Sprintf("%X", md5.Sum([]byte("com.baidu"+androidID)))
	state := uint64(1<<40 - 1)
	input := make([]byte, len(digest), len(digest)+25)
	copy(input, digest)
	appendState := func() {
		for shift := 0; shift < 40; shift += 8 {
			input = append(input, byte(state>>shift))
		}
	}
	appendState()
	// cesium.a._ constructor (0xa02268) selects four stages. The first ANDs
	// CRC32 into bits 8..39; subsequent stages XOR their hashes into the state.
	crc := crc32.ChecksumIEEE(input)
	state = state&0xff | uint64(crc)<<8
	appendState()
	state ^= uint64(androidCUIDXXHash32(input))
	appendState()
	state ^= uint64(androidCUIDXXHash32(input)) << 1
	appendState()
	state ^= uint64(crc32.ChecksumIEEE(input)) << 7
	var encoded [5]byte
	for i := range encoded {
		encoded[i] = byte(state >> (8 * i))
	}
	return digest + "|V" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(encoded[:]), nil
}

// androidCUIDXXHash32 matches cesium.a.c, including its length>16 block-path
// condition (finalizer code_item 0xa040bc). CUID's stage inputs are 42 and 47
// bytes, so both always use that block path. All arithmetic wraps at 32 bits.
func androidCUIDXXHash32(data []byte) uint32 {
	const (
		prime1 uint32 = 0x9e3779b1
		prime2 uint32 = 0x85ebca77
		prime3 uint32 = 0xc2b2ae3d
		prime4 uint32 = 0x27d4eb2f
		prime5 uint32 = 0x165667b1
	)
	var hash uint32
	position := 0
	if len(data) >= 16 {
		lanes := [4]uint32{0x24234428, prime2, 0, 0x61c8864f}
		for position+16 <= len(data) {
			for i := range lanes {
				lanes[i] = bits.RotateLeft32(lanes[i]+binary.LittleEndian.Uint32(data[position+4*i:])*prime2, 13) * prime1
			}
			position += 16
		}
		if len(data) > 16 {
			hash = bits.RotateLeft32(lanes[0], 1) + bits.RotateLeft32(lanes[1], 7) + bits.RotateLeft32(lanes[2], 12) + bits.RotateLeft32(lanes[3], 18)
		} else {
			hash = lanes[2] + prime5
		}
	} else {
		hash = prime5
	}
	hash += uint32(len(data))
	for position+4 <= len(data) {
		hash = bits.RotateLeft32(hash+binary.LittleEndian.Uint32(data[position:])*prime3, 17) * prime4
		position += 4
	}
	for _, ch := range data[position:] {
		hash = bits.RotateLeft32(hash+uint32(ch)*prime5, 11) * prime1
	}
	hash ^= hash >> 15
	hash *= prime2
	hash ^= hash >> 13
	hash *= prime3
	hash ^= hash >> 16
	return hash
}
