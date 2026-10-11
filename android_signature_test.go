package terabox

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type androidSignatureFixtures struct {
	Vectors []struct {
		Name, Algorithm, DeviceID, Version, Time, NDUS, UID, EncodedSK, CertificateMD5, ExpectedRand string
	}
	SKVectors []struct {
		Name, UID, EncodedSK, ExpectedSKHex string
	}
}

func androidSignatureLoadFixtures(t *testing.T) androidSignatureFixtures {
	t.Helper()
	data, err := os.ReadFile("testdata/android_signature_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures androidSignatureFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func androidSignatureConfig() AndroidSigningConfig {
	return AndroidSigningConfig{
		DeviceID: "device-id-123", UID: "12345", EncodedSK: "I1BbEElqIRzyRLrZtgH/fZwf",
		Version: "4.26.5",
	}
}

func androidSignatureSigner(t *testing.T, cfg AndroidSigningConfig) *AndroidSigner {
	t.Helper()
	signer, err := NewAndroidSigner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestAndroidSignatureNativeOracleVectors(t *testing.T) {
	fixtures := androidSignatureLoadFixtures(t)
	compared := map[string]int{}
	for _, vector := range fixtures.Vectors {
		t.Run(vector.Algorithm+"/"+vector.Name, func(t *testing.T) {
			if vector.Name == "unpaired-surrogate" {
				// Java strings permit lone UTF-16 surrogates. Go's valid-UTF-8
				// public API deliberately excludes them, and encoding/json
				// replaces them with U+FFFD, so this oracle input cannot be
				// represented faithfully by a valid Go UTF-8 string.
				t.Skip("lone UTF-16 surrogate is outside the valid-UTF-8 API contract")
			}
			var got string
			var err error
			switch vector.Algorithm {
			case "sdk":
				got, err = ComputeAndroidSDKRand(AndroidSDKRandInput{
					DeviceID: vector.DeviceID, Version: vector.Version, Time: vector.Time,
					EncodedSK: vector.EncodedSK, Payload: vector.NDUS, Key: vector.UID,
					CertificateMD5: vector.CertificateMD5,
				})
			case "legacy":
				// The oracle executes SDK digest machinery with the legacy
				// suffix. It does not execute URLHandler's missing-SK guard
				// or URL parsing; those have dedicated regression tests.
				var secret []byte
				secret, err = DecodeAndroidSK(vector.UID, vector.EncodedSK)
				if err == nil {
					got = androidLegacyRand(vector.DeviceID, vector.UID, secret, androidJNIBytes(vector.Time), androidJNIBytes(vector.Version), vector.NDUS)
				}
			default:
				t.Fatalf("unknown native oracle algorithm %q", vector.Algorithm)
			}
			if err != nil || got != vector.ExpectedRand {
				t.Fatalf("native oracle mismatch: digest=%q error=%v, want %s", got, err, vector.ExpectedRand)
			}
			compared[vector.Algorithm]++
		})
	}
	if compared["sdk"] != 13 || compared["legacy"] != 13 {
		t.Fatalf("native oracle coverage = %v, want 13 representable vectors per algorithm", compared)
	}
	for _, vector := range fixtures.SKVectors {
		t.Run("SK/"+vector.Name, func(t *testing.T) {
			got, err := DecodeAndroidSK(vector.UID, vector.EncodedSK)
			if err != nil || hex.EncodeToString(got) != vector.ExpectedSKHex {
				t.Fatalf("native SK oracle mismatch: secret=%x error=%v, want %s", got, err, vector.ExpectedSKHex)
			}
		})
	}
	if len(fixtures.SKVectors) != 8 {
		t.Fatalf("SK oracle coverage = %d, want 8 vectors", len(fixtures.SKVectors))
	}
}

func TestAndroidSignURLMissingSKGateUsesEncodedValue(t *testing.T) {
	const raw = "https://www.terabox.com/api/list?time=1700000000123&version=4.26.5"
	cfg := androidSignatureConfig()
	cfg.EncodedSK = ""
	signer := androidSignatureSigner(t, cfg)
	if got, err := signer.SignURL(raw, "ndus-ascii"); err != nil || got != raw {
		t.Fatalf("native missing-SK gate must preserve the URL: got=%q error=%v", got, err)
	}
	// This nonempty encrypted value decodes to a secret beginning with NUL.
	// URLHandler gates on the Java encoded value, not the decoded secret length.
	cfg.UID, cfg.EncodedSK = "key", "CxhVhEg="
	signer = androidSignatureSigner(t, cfg)
	if len(signer.secret) != 0 {
		t.Fatalf("leading-NUL fixture decoded to %x, want empty", signer.secret)
	}
	got, err := signer.SignURL(raw, "ndus-ascii")
	if err != nil || !strings.HasPrefix(got, raw+"&rand=") || len(strings.TrimPrefix(got, raw+"&rand=")) != 40 {
		t.Fatalf("nonempty encoded SK must pass the guard: got=%q error=%v", got, err)
	}
}

func TestAndroidSignURLPreservesNativeRawURLBehavior(t *testing.T) {
	signer := androidSignatureSigner(t, androidSignatureConfig())
	for _, raw := range []string{
		"https://terabox.com/api/list",
		"https://terabox.com/api/list?time=1700000000123",
		"https://terabox.com/api/list?version=4.26.5",
		"https://terabox.com/api/list?time=&version=4.26.5",
		"https://terabox.com/api/list?time=1700000000123&version=",
		"https://terabox.com/api/list?time=1700000000123&version=4.26.5&rand=existing%2f+value",
		"https://terabox.com/api/list?rand=&time=1700000000123&version=4.26.5",
	} {
		got, err := signer.SignURL(raw, "ndus-ascii")
		if err != nil || got != raw {
			t.Errorf("native no-op changed URL: got=%q error=%v, want %q", got, err, raw)
		}
	}
	for _, raw := range []string{
		"https://terabox.com/api/list?z=last&time=1700000000123&version=4.26.5&a=first",
		"https://terabox.com/api/list?version=4.26.5&z=last&time=1700000000123",
		// The native character class really includes '|', not just '?'/ '&'.
		"https://terabox.com/api/list?z=value|time=1700000000123&version=4.26.5",
	} {
		want := raw + "&rand=934acf1aa3e5237089c8b9d6c0cbbe26dd3b04c0"
		got, err := signer.SignURL(raw, "ndus-ascii")
		if err != nil || got != want {
			t.Errorf("raw URL order or legacy digest changed: got=%q error=%v, want %q", got, err, want)
		}
	}
	// This independent SHA-1 fixture uses the native oracle's ASCII digest
	// input with the timestamp/version replaced by their literal percent forms.
	raw := "https://terabox.com/api/list?time=%31%37%30%30%30%30%30%30%30%30%31%32%33&version=%34%2e26%2e5"
	want := raw + "&rand=811389c2332eaec7b17714508eb61c002feeff44"
	if got, err := signer.SignURL(raw, "ndus-ascii"); err != nil || got != want {
		t.Fatalf("URL values were decoded before signing: got=%q error=%v, want %q", got, err, want)
	}
}

func TestAndroidSigningRejectsInvalidConfigAndInputs(t *testing.T) {
	invalidUTF8 := string([]byte{0xff})
	for _, change := range []func(*AndroidSigningConfig){
		func(c *AndroidSigningConfig) { c.DeviceID = "" },
		func(c *AndroidSigningConfig) { c.UID = "" },
		func(c *AndroidSigningConfig) { c.EncodedSK = "not-base64" },
		func(c *AndroidSigningConfig) { c.DeviceID = invalidUTF8 },
		func(c *AndroidSigningConfig) { c.UID = invalidUTF8 },
		func(c *AndroidSigningConfig) { c.Version = invalidUTF8 },
	} {
		cfg := androidSignatureConfig()
		change(&cfg)
		if signer, err := NewAndroidSigner(cfg); err == nil || signer != nil {
			t.Fatalf("invalid signing configuration was accepted: signer=%v error=%v", signer, err)
		}
	}
	signer := androidSignatureSigner(t, androidSignatureConfig())
	for _, raw := range []string{"/relative", "https://user@terabox.com/api/list", "https://terabox.com/api/list#fragment", invalidUTF8} {
		if signed, err := signer.SignURL(raw, "ndus"); err == nil || signed != "" {
			t.Errorf("invalid URL accepted: signed=%q error=%v", signed, err)
		}
	}
	if _, err := signer.SignURL("https://terabox.com/api/list?time=1&version=4.26.5", invalidUTF8); err == nil {
		t.Error("invalid UTF-8 session token accepted")
	}
	if _, err := ComputeAndroidSDKRand(AndroidSDKRandInput{DeviceID: "id", Version: "v", Time: "1", EncodedSK: "u/MW6NlArwrT", Key: "Key", Payload: invalidUTF8}); err == nil {
		t.Error("SDK calculation accepted invalid UTF-8 payload")
	}
}

func TestAndroidSDKRandDefaultCertificateMatchesNativeOracle(t *testing.T) {
	fixtures := androidSignatureLoadFixtures(t)
	for _, vector := range fixtures.Vectors {
		if vector.Algorithm != "sdk" || vector.Name != "ascii" {
			continue
		}
		got, err := ComputeAndroidSDKRand(AndroidSDKRandInput{
			DeviceID: vector.DeviceID, Version: vector.Version, Time: vector.Time,
			EncodedSK: vector.EncodedSK, Payload: vector.NDUS, Key: vector.UID,
		})
		if err != nil || got != vector.ExpectedRand {
			t.Fatalf("default APK certificate digest=%q error=%v, want native %s", got, err, vector.ExpectedRand)
		}
		return
	}
	t.Fatal("SDK ASCII certificate oracle is missing")
}
