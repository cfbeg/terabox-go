package terabox

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
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
		Version: "4.26.5", Channel: "android_14_TestDevice_bd-dubox_web", UserAgent: "captured-android-agent",
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
		func(c *AndroidSigningConfig) { c.Channel = "bad\r\nchannel" },
		func(c *AndroidSigningConfig) { c.UserAgent = "bad\nagent" },
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

func androidSignatureCheckRequest(t *testing.T, req *http.Request, signer *AndroidSigner, cfg AndroidSigningConfig, earliest int64) {
	t.Helper()
	query := req.URL.Query()
	if query.Get("devuid") != cfg.DeviceID || query.Get("cuid") != cfg.DeviceID || query.Get("clienttype") != "1" || query.Get("channel") != cfg.Channel || query.Has("web") {
		t.Errorf("Android common query is wrong: %v", query)
	}
	if query.Get("version") != cfg.Version || req.Header.Get("User-Agent") != cfg.UserAgent {
		t.Errorf("Android version/UA = %q/%q, want %q/%q", query.Get("version"), req.Header.Get("User-Agent"), cfg.Version, cfg.UserAgent)
	}
	timestamp, err := strconv.ParseInt(query.Get("time"), 10, 64)
	if err != nil || timestamp < earliest || timestamp > time.Now().UnixMilli() {
		t.Errorf("time = %q, want current epoch milliseconds", query.Get("time"))
	}
	ndus := ""
	if cookie, err := req.Cookie("ndus"); err == nil {
		ndus = cookie.Value
	}
	actual := req.URL.String()
	unsigned := strings.TrimSuffix(actual, "&rand="+query.Get("rand"))
	expected, err := signer.SignURL(unsigned, ndus)
	if err != nil || query.Get("rand") == "" || actual != expected {
		t.Errorf("request signature disagrees with its cookie snapshot: actual=%s expected=%s error=%v", actual, expected, err)
	}
}

func TestAndroidSignerJSONIntegrationKeepsFormBody(t *testing.T) {
	cfg := androidSignatureConfig()
	signer := androidSignatureSigner(t, cfg)
	earliest := time.Now().UnixMilli()
	calls := 0
	client := NewClient("ndus-ascii", WithAndroidSigner(signer), WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		androidSignatureCheckRequest(t, req, signer, cfg, earliest)
		switch req.URL.Path {
		case "/api/quota":
			return authTestJSON(req, `{"errno":0,"total":1000,"used":1}`), nil
		case "/api/create":
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			form, err := url.ParseQuery(string(body))
			if err != nil || form.Get("path") != "/directory with spaces" || form.Get("isdir") != "1" || form.Get("block_list") != "[]" || req.ContentLength != int64(len(body)) {
				t.Errorf("signing changed form body or content length: %q length=%d error=%v", body, req.ContentLength, err)
			}
			return authTestJSON(req, `{"errno":0,"fs_id":123}`), nil
		default:
			return nil, errors.New("unexpected signed JSON endpoint")
		}
	})}))
	if _, err := client.GetQuota(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateDir(context.Background(), "/directory with spaces"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("signed JSON requests=%d, want 2", calls)
	}
}

type androidSignatureCountingReader struct {
	*bytes.Reader
	reads int
}

func (r *androidSignatureCountingReader) Read(p []byte) (int, error) {
	r.reads++
	return r.Reader.Read(p)
}

func TestAndroidSignerUploadChunkRetainsStreamingBody(t *testing.T) {
	cfg := androidSignatureConfig()
	signer := androidSignatureSigner(t, cfg)
	content := bytes.Repeat([]byte("streamed chunk content"), 4096)
	src := &androidSignatureCountingReader{Reader: bytes.NewReader(content)}
	earliest := time.Now().UnixMilli()
	client := NewClient("ndus-ascii", WithAndroidSigner(signer), WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
		if src.reads != 0 {
			t.Error("signing buffered the chunk before handing the request to the transport")
		}
		androidSignatureCheckRequest(t, req, signer, cfg, earliest)
		if req.URL.Path != "/rest/2.0/pcs/superfile2" || req.URL.Query().Get("uploadid") != "local-upload" || req.ContentLength <= int64(len(content)) {
			t.Errorf("signed upload target/content length changed: %s, length=%d", req.URL, req.ContentLength)
		}
		reader, err := req.MultipartReader()
		if err != nil {
			return nil, err
		}
		part, err := reader.NextPart()
		if err != nil {
			return nil, err
		}
		got, err := io.ReadAll(part)
		if err != nil || part.FormName() != "file" || !bytes.Equal(got, content) || src.reads == 0 {
			t.Errorf("streamed chunk changed: bytes=%d error=%v reads=%d", len(got), err, src.reads)
		}
		if _, err := reader.NextPart(); err != io.EOF {
			t.Errorf("multipart upload ended incorrectly: %v", err)
		}
		return authTestJSON(req, `{"error_code":0,"md5":"`+uploadTestMD5(content)+`"}`), nil
	})}))
	if _, err := client.UploadChunk(context.Background(), uploadTestData(content, int64(len(content))), 0, src, int64(len(content))); err != nil {
		t.Fatal(err)
	}
}

func TestAndroidSignerKeepsWebPassportAndHTMLRequests(t *testing.T) {
	// A missing Android channel would reject any signed request, so this also
	// detects accidental signing of the deliberately preserved Web flows.
	cfg := androidSignatureConfig()
	cfg.Channel = ""
	signer := androidSignatureSigner(t, cfg)
	client := NewClient("ndus-ascii", WithAndroidSigner(signer), WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
		query := req.URL.Query()
		if query.Has("rand") || query.Has("devuid") || query.Has("time") || req.Header.Get("User-Agent") != defaultUserAgent {
			t.Errorf("Android profile changed preserved Web request: %s UA=%q", req.URL, req.Header.Get("User-Agent"))
		}
		switch req.URL.Path {
		case "/main":
			return authTestJSON(req, clientPage), nil
		case "/passport/register_v4/sendcode":
			if err := req.ParseForm(); err != nil {
				return nil, err
			}
			if req.PostForm.Get("client") != "web" || req.PostForm.Get("pass_version") != "2.8" {
				t.Errorf("Android signer changed the Web passport form: %v", req.PostForm)
			}
			return authTestJSON(req, `{"code":0,"token":"registration-token"}`), nil
		default:
			return nil, errors.New("unexpected preserved Web endpoint")
		}
	})}))
	if _, err := client.UpdateAppData(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterSendCode(context.Background(), "test@example.invalid"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/passport/prelogin", "/api/passport/nested"} {
		req, _ := http.NewRequest(http.MethodGet, "https://www.terabox.com"+path+"?web=1", nil)
		got, err := client.signAndroidRequest(req)
		if err != nil || got != req {
			t.Errorf("exact passport path segment was not excluded: path=%s request=%v error=%v", path, got, err)
		}
	}
}

func TestAndroidSignerRequiresChannelBeforeTransport(t *testing.T) {
	cfg := androidSignatureConfig()
	cfg.Channel = ""
	signer := androidSignatureSigner(t, cfg)
	calls := 0
	client := NewClient("ndus-ascii", WithAndroidSigner(signer), WithHTTPClient(&http.Client{Transport: authTestTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("must not reach transport")
	})}))
	if _, err := client.GetQuota(context.Background()); err == nil {
		t.Error("missing runtime channel was accepted by JSON integration")
	}
	src := &androidSignatureCountingReader{Reader: bytes.NewReader([]byte("abc"))}
	if _, err := client.UploadChunk(context.Background(), uploadTestData([]byte("abc"), 3), 0, src, 3); err == nil {
		t.Error("missing runtime channel was accepted by chunk integration")
	}
	if calls != 0 || src.reads != 0 {
		t.Errorf("invalid profile sent/read a chunk: requests=%d reads=%d", calls, src.reads)
	}
	// Only an exact segment excludes passport; a substring is not enough.
	req, _ := http.NewRequest(http.MethodGet, "https://www.terabox.com/api/passportish", nil)
	if _, err := client.signAndroidRequest(req); err == nil {
		t.Error("passport substring incorrectly bypassed Android profile validation")
	}
}

func TestAndroidSignerSessionRotationSwapAndDisable(t *testing.T) {
	cfg := androidSignatureConfig()
	signer := androidSignatureSigner(t, cfg)
	activeSigner, activeConfig := signer, cfg
	earliest := time.Now().UnixMilli()
	quotaCalls := 0
	client := NewClient("first-session", WithAndroidSigner(signer), WithHTTPClient(&http.Client{Transport: authTestTransport(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/main":
			if req.URL.Query().Has("rand") || req.Header.Get("User-Agent") != defaultUserAgent {
				t.Error("session rotation was routed through Android signing")
			}
			response := authTestJSON(req, clientPage)
			response.Header.Add("Set-Cookie", "ndus=rotated-session; Path=/; Secure")
			return response, nil
		case "/api/quota":
			quotaCalls++
			androidSignatureCheckRequest(t, req, activeSigner, activeConfig, earliest)
			wantCookie := "rotated-session"
			if quotaCalls == 1 {
				wantCookie = "first-session"
			}
			cookie, err := req.Cookie("ndus")
			if err != nil || cookie.Value != wantCookie {
				t.Errorf("request did not use current session: got=%v error=%v, want %q", cookie, err, wantCookie)
			}
			return authTestJSON(req, `{"errno":0}`), nil
		case "/rest/recent/listall":
			query := req.URL.Query()
			if query.Has("rand") || query.Has("time") || query.Has("devuid") || query.Get("web") != "1" || query.Get("clienttype") != "0" || query.Get("channel") != "dubox" || req.Header.Get("User-Agent") != defaultUserAgent {
				t.Errorf("disabled signer did not restore Web behavior: %s UA=%q", req.URL, req.Header.Get("User-Agent"))
			}
			return authTestJSON(req, `{"errno":0,"list":[]}`), nil
		default:
			return nil, errors.New("unexpected signer-rotation endpoint")
		}
	})}))
	if _, err := client.GetQuota(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateAppData(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetQuota(context.Background()); err != nil {
		t.Fatal(err)
	}
	activeConfig.UID, activeConfig.EncodedSK, activeConfig.DeviceID = "54321", "NWleEZ2wD6ajaQ5TsfCHgA==", "different-device"
	activeSigner = androidSignatureSigner(t, activeConfig)
	client.SetAndroidSigner(activeSigner)
	if _, err := client.GetQuota(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.SetAndroidSigner(nil)
	if _, err := client.GetRecentUploads(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if quotaCalls != 3 {
		t.Fatalf("signed quota calls=%d, want 3", quotaCalls)
	}
}

func TestAndroidSignerUsesRequestCookieSnapshot(t *testing.T) {
	signer := androidSignatureSigner(t, androidSignatureConfig())
	// Model a concurrent session refresh after a request took its cookies:
	// the client already has the new value while this request retains the old.
	client := NewClient("new-session", WithAndroidSigner(signer))
	req, _ := http.NewRequest(http.MethodGet, "https://www.terabox.com/api/quota?time=1700000000123&version=4.26.5", nil)
	req.Header.Set("Cookie", "ndus=old-request-session")
	signed, err := client.signAndroidRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	actual := signed.URL.String()
	unsigned := strings.TrimSuffix(actual, "&rand="+signed.URL.Query().Get("rand"))
	expected, err := signer.SignURL(unsigned, "old-request-session")
	if err != nil || actual != expected || signed.Header.Get("Cookie") != req.Header.Get("Cookie") {
		t.Fatalf("signature/header snapshot diverged: actual=%s expected=%s error=%v cookie=%q", actual, expected, err, signed.Header.Get("Cookie"))
	}
	other, err := signer.SignURL(unsigned, "new-session")
	if err != nil || actual == other {
		t.Fatal("signature used the refreshed client cookie instead of the request cookie")
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

func TestAndroidSignerPreservesEndpointParametersAndDefaultsVersion(t *testing.T) {
	cfg := androidSignatureConfig()
	cfg.Version = ""
	signer := androidSignatureSigner(t, cfg)
	client := NewClient("ndus-ascii", WithAndroidSigner(signer))
	req, _ := http.NewRequest(http.MethodGet, "https://www.terabox.com/api/list?time=1234567890123&version=endpoint-version&rand=upstream-token&web=1", nil)
	signed, err := client.signAndroidRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	query := signed.URL.Query()
	if query.Get("time") != "1234567890123" || query.Get("version") != "endpoint-version" || query.Get("rand") != "upstream-token" || len(query["rand"]) != 1 || query.Has("web") {
		t.Fatalf("endpoint time/version/rand was overwritten or duplicated: %v", query)
	}
	req, _ = http.NewRequest(http.MethodGet, "https://www.terabox.com/api/list", nil)
	signed, err = client.signAndroidRequest(req)
	if err != nil || signed.URL.Query().Get("version") != AndroidAPKVersion {
		t.Fatalf("missing version did not use inspected APK default: request=%v error=%v", signed, err)
	}
}
