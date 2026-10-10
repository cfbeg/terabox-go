package terabox

import (
	"bytes"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// androidLegacySuffix is the literal appended by libdubox-security.so 4.26.5
// before the legacy URL handler's final SHA-1.
const androidLegacySuffix = "ae5821440fab5e1a61a025f014bd8972"

// DecodeAndroidSK reproduces the APK's Base64/RC4 secret decoder. userID is
// encoded as JNI Modified UTF-8 and used as the RC4 key; encodedSK is standard
// Base64 with no line breaks. The returned bytes stop at the first NUL, as the
// native helper constructs its result with strlen. DecodeAndroidSK rejects
// ciphertext longer than 255 bytes so the native 256-byte buffer would remain
// NUL-terminated. It does not derive a key from account cookies.
func DecodeAndroidSK(userID, encodedSK string) ([]byte, error) {
	const op = "decodeAndroidSK"
	if userID == "" {
		return nil, wrapErr(op, errors.New("user ID required"))
	}
	if !utf8.ValidString(userID) {
		return nil, wrapErr(op, errors.New("user ID must be valid UTF-8"))
	}
	if encodedSK == "" {
		return nil, wrapErr(op, errors.New("encoded SK required"))
	}
	if strings.ContainsAny(encodedSK, "\r\n") {
		return nil, wrapErr(op, errors.New("encoded SK must not contain line breaks"))
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encodedSK)
	if err != nil {
		return nil, wrapErr(op, fmt.Errorf("invalid standard Base64 SK: %w", err))
	}
	if len(ciphertext) > 255 {
		return nil, wrapErr(op, errors.New("decoded SK ciphertext exceeds the native buffer limit of 255 bytes"))
	}
	key := androidJNIBytes(userID)
	// The native key scheduler runs exactly 256 rounds, so bytes beyond the
	// first 256 cannot be consumed even when its length argument is larger.
	if len(key) > 256 {
		key = key[:256]
	}
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plain, ciphertext)
	if n := bytes.IndexByte(plain, 0); n >= 0 {
		plain = plain[:n]
	}
	return plain, nil
}

// androidJNIBytes converts valid Go UTF-8 into the Modified UTF-8 returned by
// JNI GetStringUTFChars: NUL uses C0 80 and supplementary characters use two
// separately encoded UTF-16 surrogates. Public callers validate UTF-8 first.
func androidJNIBytes(value string) []byte {
	units := utf16.Encode([]rune(value))
	encoded := make([]byte, 0, len(value))
	for _, unit := range units {
		switch {
		case unit != 0 && unit <= 0x7f:
			encoded = append(encoded, byte(unit))
		case unit <= 0x7ff:
			encoded = append(encoded, 0xc0|byte(unit>>6), 0x80|byte(unit&0x3f))
		default:
			encoded = append(encoded, 0xe0|byte(unit>>12), 0x80|byte((unit>>6)&0x3f), 0x80|byte(unit&0x3f))
		}
	}
	return encoded
}

func androidSHA1(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}
