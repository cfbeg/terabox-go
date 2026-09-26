package terabox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// SignDownload generates a signed download token using the RC4 stream
// cipher with key s1 over input s2, returned as standard Base64.
// It mirrors the inline KSA+PRGA of the JS signDownload() exactly.
func SignDownload(s1, s2 string) string {
	// JS reads charCodeAt (UTF-16 code units) and truncates to a byte when
	// storing into a Uint8Array. Runes reproduce that for BMP text; the
	// token data involved is ASCII in practice.
	key := []rune(s1)
	k := make([]byte, len(key))
	for i, r := range key {
		k[i] = byte(r)
	}
	data := []rune(s2)
	d := make([]byte, len(data))
	for i, r := range data {
		d[i] = byte(r)
	}

	var p [256]byte
	for i := 0; i < 256; i++ {
		p[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(p[i]) + int(k[i%len(k)])) % 256
		p[i], p[j] = p[j], p[i]
	}

	result := make([]byte, len(d))
	ii, jj := 0, 0
	for q := 0; q < len(d); q++ {
		ii = (ii + 1) % 256
		jj = (jj + int(p[ii])) % 256
		p[ii], p[jj] = p[jj], p[ii]
		kByte := p[(int(p[ii])+int(p[jj]))%256]
		result[q] = d[q] ^ kByte
	}

	return base64.StdEncoding.EncodeToString(result)
}

// CheckMD5Value reports whether s is a 32-character lowercase hex MD5 hash.
func CheckMD5Value(md5 string) bool {
	if len(md5) != 32 {
		return false
	}
	for i := 0; i < len(md5); i++ {
		c := md5[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// CheckMD5Slice reports whether every element in arr is a valid MD5 hash.
// An empty slice is reported as invalid, matching the JS checkMd5arr.
func CheckMD5Slice(arr []string) bool {
	if len(arr) == 0 {
		return false
	}
	for _, item := range arr {
		if !CheckMD5Value(item) {
			return false
		}
	}
	return true
}

// DecodeMD5 applies the custom reversible transformation TeraBox/Baidu use
// to obfuscate server-returned MD5 values. The 9th character must be in
// 'g'..'v' (encoding the original hex digit); malformed input is returned
// unchanged, as the JS version does.
func DecodeMD5(md5 string) string {
	if len(md5) != 32 {
		return md5
	}
	c9 := md5[9]
	if c9 < 'g' || c9 > 'v' {
		return md5
	}
	restored := fmt.Sprintf("%x", c9-'g')
	o := md5[:9] + restored + md5[10:]

	n := make([]byte, len(o))
	for i := 0; i < len(o); i++ {
		v, err := hexNibble(o[i])
		if err != nil {
			return md5
		}
		n[i] = "0123456789abcdef"[v^byte(i&15)]
	}
	return string(n[8:16]) + string(n[0:8]) + string(n[24:32]) + string(n[16:24])
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, errors.New("not a hex digit")
}

// ToURLSafeBase64 converts standard Base64 to URL-safe Base64 (RFC 4648 §5).
func ToURLSafeBase64(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "+", "-"), "/", "_")
}

// ToStandardBase64 converts URL-safe Base64 back to standard Base64.
func ToStandardBase64(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "-", "+"), "_", "/")
}

// DecryptAES decrypts data in the TeraBox passport scheme: pp1 is a
// URL-safe Base64 string whose first 16 characters are the IV and whose
// remainder is standard-Base64 AES-128-CBC ciphertext; pp2 is the 16-byte
// key (URL-safe Base64 converted back to standard). Returns UTF-8 plaintext.
func DecryptAES(pp1, pp2 string) (string, error) {
	pp1 = ToStandardBase64(pp1)
	pp2 = ToStandardBase64(pp2)
	if len(pp1) < 16 {
		return "", errors.New("decryptAES: input too short")
	}
	cipherText := pp1[16:]
	key := []byte(pp2)
	iv := []byte(pp1[:16])

	if len(key) != aes.BlockSize {
		return "", fmt.Errorf("decryptAES: key length is %d, want 16", len(key))
	}
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("decryptAES: %w", err)
	}
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return "", fmt.Errorf("decryptAES: ciphertext length %d is not a multiple of the block size", len(raw))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("decryptAES: %w", err)
	}
	plain := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, raw)

	// PKCS#7 unpad, as Node's decipher.final() does by default.
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(plain) {
		return "", errors.New("decryptAES: invalid padding")
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return "", errors.New("decryptAES: invalid padding")
		}
	}
	return string(plain[:len(plain)-pad]), nil
}

// RSA encryption preprocessing modes for EncryptRSA.
const (
	// RSADirect encrypts the message directly.
	RSADirect = 1
	// RSAMD5Preprocess encrypts md5hex(message) + length prefix instead.
	RSAMD5Preprocess = 2
)

// EncryptRSA encrypts a message with an RSA public key in PEM format using
// PKCS#1 v1.5 padding and returns standard Base64. With RSAMD5Preprocess the
// payload is md5(message) hex + length prefix, as used by TeraBox login.
func EncryptRSA(message, publicKeyPEM string, mode int) (string, error) {
	if mode == RSAMD5Preprocess {
		sum := md5.Sum([]byte(message))
		md5hex := hex.EncodeToString(sum[:])
		prefix := ""
		if len(md5hex) < 10 {
			prefix = "0"
		}
		message = md5hex + prefix + fmt.Sprint(len(md5hex))
	}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", errors.New("encryptRSA: invalid PEM block")
	}

	var pub *rsa.PublicKey
	if pk, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		pub = pk
	} else if anyKey, err2 := x509.ParsePKIXPublicKey(block.Bytes); err2 == nil {
		pk, ok := anyKey.(*rsa.PublicKey)
		if !ok {
			return "", errors.New("encryptRSA: PEM contains a non-RSA key")
		}
		pub = pk
	} else {
		return "", fmt.Errorf("encryptRSA: cannot parse public key: %v / %v", err, err2)
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(message))
	if err != nil {
		return "", fmt.Errorf("encryptRSA: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// PRandGen generates the pseudo-random SHA-1 token from combined client
// parameters used by the passport login flow.
func PRandGen(client, seval, encpwd, email, browserid, random string) string {
	combined := client + "-" + seval + "-" + encpwd + "-" + email + "-" + browserid + "-" + random
	sum := sha1.Sum([]byte(combined))
	return hex.EncodeToString(sum[:])
}
