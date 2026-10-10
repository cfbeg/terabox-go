package terabox

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDecodeAndroidSKRC4Vectors(t *testing.T) {
	// Published RC4 vectors, with ciphertext converted to standard Base64.
	for _, test := range []struct {
		key, encoded, want string
	}{
		{"Key", "u/MW6NlArwrT", "Plaintext"},
		{"Wiki", "ECG/BCA=", "pedia"},
		{"Secret", "RaAfZF/DWzg1UlRLm/U=", "Attack at dawn"},
		// Independent RC4 fixtures exercise native strlen truncation.
		{"key", "ag5X7VDuEiY=", "abc"},
		{"key", "CxhVhEg=", ""},
	} {
		got, err := DecodeAndroidSK(test.key, test.encoded)
		if err != nil || string(got) != test.want {
			t.Errorf("DecodeAndroidSK(%q, %q) = (%q, %v), want %q", test.key, test.encoded, got, err, test.want)
		}
	}
}

func TestAndroidJNIBytes(t *testing.T) {
	for _, test := range []struct {
		value, wantHex string
	}{
		{"", ""},
		{"plain ASCII", "706c61696e204153434949"},
		{"u\x00id", "75c0806964"},
		{"uid-日本", "7569642de697a5e69cac"},
		{"uid-😀", "7569642deda0bdedb880"},
		{"\u007f\u0080\u07ff\u0800", "7fc280dfbfe0a080"},
	} {
		got := hex.EncodeToString(androidJNIBytes(test.value))
		if got != test.wantHex {
			t.Errorf("JNI bytes for %q = %s, want %s", test.value, got, test.wantHex)
		}
	}
}

func TestDecodeAndroidSKUsesModifiedUTF8Key(t *testing.T) {
	// Independent fixtures use UTF-16 code units encoded as Modified UTF-8.
	for _, test := range []struct {
		userID, encoded string
	}{
		{"u\x00id", "dPvaEOTX1mgHwg=="},
		{"uid-日本", "8kMtZYPVESn0tQ=="},
		{"uid-😀", "1WrpSqIrZ/IxRA=="},
		{strings.Repeat("a", 256) + "other", "cdL8bC2w4WZdBg=="},
	} {
		got, err := DecodeAndroidSK(test.userID, test.encoded)
		if err != nil || string(got) != "android-sk" {
			t.Errorf("user ID %q: decoded = (%q, %v), want android-sk", test.userID, got, err)
		}
	}
}

func TestDecodeAndroidSKRejectsInvalidInputs(t *testing.T) {
	for _, test := range []struct {
		name, userID, encoded string
	}{
		{"empty user ID", "", "u/MW6NlArwrT"},
		{"invalid user ID UTF-8", string([]byte{0xff}), "u/MW6NlArwrT"},
		{"empty encoded SK", "Key", ""},
		{"invalid Base64", "Key", "not-base64"},
		{"unpadded Base64", "Key", "ECG/BCA"},
		{"URL-safe alphabet", "Key", "u_MW6NlArwrT"},
		{"CRLF", "Key", "u/MW\r\n6NlArwrT"},
		{"trailing newline", "Key", "u/MW6NlArwrT\n"},
		{"oversized decoded value", "Key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 256))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := DecodeAndroidSK(test.userID, test.encoded); err == nil || got != nil {
				t.Fatalf("decoded = (%q, %v), want rejection", got, err)
			}
		})
	}
}

func TestDecodeAndroidSKNativeBufferBoundary(t *testing.T) {
	// RC4 is a stream cipher: arbitrary 255-byte ciphertext is still valid.
	encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 255))
	if _, err := DecodeAndroidSK("Key", encoded); err != nil {
		t.Fatalf("native buffer boundary rejected: %v", err)
	}
}

func TestAndroidSHA1(t *testing.T) {
	if got := androidSHA1([]byte("abc")); got != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		t.Fatalf("SHA-1 = %s", got)
	}
}
