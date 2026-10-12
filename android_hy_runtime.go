package terabox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

const (
	hyRuntimeMaxScript  = 512 << 10
	hyRuntimeMaxTotal   = 2 << 20
	hyRuntimeMaxScripts = 32
	hyRuntimeMaxTape    = 4096
	hyRuntimeDeadline   = 2 * time.Second
)

// AndroidHyRuntimeSnapshot contains private, observed bootstrap sources and
// their execution inputs. It belongs to exactly one Android identity. The
// source can contain authentication tokens and must be kept with the session.
// This is a bootstrap interpreter, not a browser: DOM fingerprinting, native
// bridges, network APIs, application modules, and CAPTCHA are not executed.
type AndroidHyRuntimeSnapshot struct {
	Version        int                      `json:"version"`
	DeviceID       string                   `json:"device_id"`
	AppVersion     string                   `json:"app_version"`
	NativeChannel  string                   `json:"native_channel"`
	UserAgent      string                   `json:"user_agent"`
	Language       string                   `json:"language"`
	PageURL        string                   `json:"page_url"`
	VisibleCookies string                   `json:"visible_cookies,omitempty"`
	Scripts        []AndroidHyRuntimeScript `json:"scripts"`
	Random         []float64                `json:"random,omitempty"`
	Times          []int64                  `json:"times,omitempty"`
	Entropy        []string                 `json:"entropy,omitempty"`
	Calls          []AndroidHyRuntimeCall   `json:"calls,omitempty"`
}

type AndroidHyRuntimeScript struct {
	URL    string `json:"url,omitempty"`
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
}

// Calls preserve encryptor closure state across session restoration. Only the
// APK's explicitly encrypted fields are passed to this function; passwords
// remain in their separate RSA protocol.
type AndroidHyRuntimeCall struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

type androidHyAssetFetcher func(context.Context, *url.URL) (string, error)

type androidHyRuntime struct {
	mu                                            sync.Mutex
	vm                                            *goja.Runtime
	capture                                       AndroidHyRuntimeSnapshot
	randomPosition, timePosition, entropyPosition int
	replaying                                     bool
	unsupported                                   bool
	fsec                                          bool
	clock                                         func() time.Time
}

var hyScriptAttribute = regexp.MustCompile(`(?is)([a-z][a-z0-9:_-]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?`)
var hyBootstrapSource = regexp.MustCompile(`\b(?:jsToken|templateData|__INITIAL_STATE__|fsec)\b`)

func hyScriptAttributes(raw string) map[string]string {
	values := make(map[string]string)
	for _, m := range hyScriptAttribute.FindAllStringSubmatch(raw, -1) {
		value := m[2]
		if value == "" {
			value = m[3]
		}
		if value == "" {
			value = m[4]
		}
		values[strings.ToLower(m[1])] = html.UnescapeString(value)
	}
	return values
}

func hyRuntimeSource(source, address string) AndroidHyRuntimeScript {
	digest := sha256.Sum256([]byte(source))
	return AndroidHyRuntimeScript{URL: address, Source: source, SHA256: hex.EncodeToString(digest[:])}
}

func resolveAndroidHyBootstrap(ctx context.Context, page string, profile AndroidAppProfile, visibleCookies string, fetch androidHyAssetFetcher) (TemplateData, *androidHyRuntime, error) {
	data, literalErr := androidHyBootstrap(page)
	if literalErr == nil && !androidFSEC.MatchString(page) {
		return data, nil, nil
	}
	base, err := url.Parse(profile.PageURL)
	if err != nil {
		return TemplateData{}, nil, errors.New("invalid Android Hy runtime page")
	}
	snapshot := AndroidHyRuntimeSnapshot{Version: 1, DeviceID: profile.DeviceID,
		AppVersion: profile.Version, NativeChannel: profile.NativeChannel,
		UserAgent: profile.UserAgent, Language: profile.Language, PageURL: profile.PageURL,
		VisibleCookies: visibleCookies}
	total := 0
	for _, script := range hyInlineScript.FindAllStringSubmatch(page, -1) {
		attrs := hyScriptAttributes(script[1])
		kind := strings.ToLower(strings.TrimSpace(attrs["type"]))
		_, noModule := attrs["nomodule"]
		if noModule || (kind != "" && kind != "text/javascript" && kind != "application/javascript") {
			continue
		}
		source, address := script[2], ""
		if src := attrs["src"]; src != "" {
			// Only a referenced FSEC bootstrap asset is requested. Rendering,
			// analytics, device-fingerprinting and CAPTCHA assets are separate.
			if !strings.Contains(strings.ToLower(src), "fsec") {
				continue
			}
			asset, err := base.Parse(src)
			if err != nil || !validHyRuntimeAssetURL(asset) || fetch == nil {
				return TemplateData{}, nil, errors.New("Android Hy FSEC bootstrap asset cannot be loaded")
			}
			source, err = fetch(ctx, asset)
			if err != nil {
				return TemplateData{}, nil, errors.New("Android Hy FSEC bootstrap asset fetch failed")
			}
			address = asset.String()
		} else if !hyBootstrapSource.MatchString(source) {
			continue
		}
		if len(source) > hyRuntimeMaxScript || total+len(source) > hyRuntimeMaxTotal || len(snapshot.Scripts) >= hyRuntimeMaxScripts {
			return TemplateData{}, nil, errors.New("Android Hy bootstrap source exceeds execution bounds")
		}
		total += len(source)
		snapshot.Scripts = append(snapshot.Scripts, hyRuntimeSource(source, address))
	}
	if len(snapshot.Scripts) == 0 {
		return TemplateData{}, nil, errors.New("Android Hy dynamic bootstrap did not provide executable captured sources")
	}
	runtime, err := newAndroidHyRuntime(ctx, &snapshot, false)
	if err != nil {
		return TemplateData{}, nil, err
	}
	data, err = runtime.globals(ctx)
	if err != nil {
		return TemplateData{}, nil, err
	}
	if androidFSEC.MatchString(page) && !runtime.fsec {
		return TemplateData{}, nil, errors.New("Android Hy FSEC bootstrap did not supply an encrypt function")
	}
	return data, runtime, nil
}

func validHyRuntimeAssetURL(asset *url.URL) bool {
	if asset == nil || asset.Scheme != "https" || asset.User != nil || asset.Fragment != "" || asset.Port() != "" {
		return false
	}
	host := strings.ToLower(asset.Hostname())
	return host == TeraBoxDomain || strings.HasSuffix(host, "."+TeraBoxDomain) ||
		host == "teraboxcdn.com" || strings.HasSuffix(host, ".teraboxcdn.com")
}

func cloneAndroidHyRuntimeSnapshot(snapshot *AndroidHyRuntimeSnapshot) *AndroidHyRuntimeSnapshot {
	if snapshot == nil {
		return nil
	}
	copy := *snapshot
	copy.Scripts = append([]AndroidHyRuntimeScript(nil), snapshot.Scripts...)
	copy.Random = append([]float64(nil), snapshot.Random...)
	copy.Times = append([]int64(nil), snapshot.Times...)
	copy.Entropy = append([]string(nil), snapshot.Entropy...)
	copy.Calls = append([]AndroidHyRuntimeCall(nil), snapshot.Calls...)
	return &copy
}

func (r *androidHyRuntime) snapshot() *AndroidHyRuntimeSnapshot {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneAndroidHyRuntimeSnapshot(&r.capture)
}

func validateAndroidHyRuntimeSnapshot(snapshot *AndroidHyRuntimeSnapshot, profile AndroidAppProfile) error {
	if snapshot == nil {
		return nil
	}
	if snapshot.Version != 1 || snapshot.DeviceID != profile.DeviceID || snapshot.AppVersion != profile.Version ||
		snapshot.NativeChannel != profile.NativeChannel || snapshot.UserAgent != profile.UserAgent || snapshot.Language != profile.Language {
		return errors.New("saved Hy runtime belongs to a different Android identity")
	}
	page, err := url.Parse(snapshot.PageURL)
	current, currentErr := url.Parse(profile.PageURL)
	if err != nil || currentErr != nil || page.User != nil || page.Fragment != "" || page.Scheme != "https" || urlOrigin(page) != urlOrigin(current) ||
		(page.Path != "/wap/hylogin" && !strings.HasPrefix(page.Path, "/wap/hylogin/")) {
		return errors.New("saved Hy runtime page does not match its Android identity")
	}
	if len(snapshot.Scripts) == 0 || len(snapshot.Scripts) > hyRuntimeMaxScripts ||
		len(snapshot.Random) > hyRuntimeMaxTape || len(snapshot.Times) > hyRuntimeMaxTape ||
		len(snapshot.Entropy) > hyRuntimeMaxTape || len(snapshot.Calls) > hyRuntimeMaxTape ||
		!utf8.ValidString(snapshot.VisibleCookies) || strings.ContainsAny(snapshot.VisibleCookies, "\r\n\x00") {
		return errors.New("saved Hy runtime exceeds execution bounds")
	}
	total := 0
	for _, script := range snapshot.Scripts {
		total += len(script.Source)
		digest := sha256.Sum256([]byte(script.Source))
		if len(script.Source) > hyRuntimeMaxScript || total > hyRuntimeMaxTotal || !utf8.ValidString(script.Source) || script.SHA256 != hex.EncodeToString(digest[:]) {
			return errors.New("saved Hy runtime source integrity check failed")
		}
		if script.URL != "" {
			address, err := url.Parse(script.URL)
			if err != nil || !validHyRuntimeAssetURL(address) {
				return errors.New("saved Hy runtime asset origin is invalid")
			}
		}
	}
	for _, random := range snapshot.Random {
		if !(random >= 0 && random < 1) {
			return errors.New("saved Hy runtime random input is invalid")
		}
	}
	entropyTotal := 0
	for _, entropy := range snapshot.Entropy {
		bytes, err := base64.StdEncoding.DecodeString(entropy)
		entropyTotal += len(bytes)
		if err != nil || len(bytes) > 65536 || entropyTotal > hyRuntimeMaxTotal {
			return errors.New("saved Hy runtime entropy input is invalid")
		}
	}
	callTotal := 0
	for _, call := range snapshot.Calls {
		callTotal += len(call.Input) + len(call.Output)
		if len(call.Input) > 4096 || len(call.Output) > 65536 || callTotal > hyRuntimeMaxTotal || !utf8.ValidString(call.Input) || !utf8.ValidString(call.Output) {
			return errors.New("saved Hy runtime encryptor call exceeds execution bounds")
		}
	}
	return nil
}

func restoreAndroidHyRuntime(ctx context.Context, snapshot *AndroidHyRuntimeSnapshot, profile AndroidAppProfile, pcf, token string) (*androidHyRuntime, error) {
	if snapshot == nil {
		return nil, nil
	}
	if err := validateAndroidHyRuntimeSnapshot(snapshot, profile); err != nil {
		return nil, err
	}
	runtime, err := newAndroidHyRuntime(ctx, snapshot, true)
	if err != nil {
		return nil, err
	}
	data, err := runtime.globals(ctx)
	if err != nil || data.PcfToken != pcf || data.JsToken != token {
		return nil, errors.New("saved Hy runtime globals do not match the saved session")
	}
	for _, call := range snapshot.Calls {
		output, err := runtime.encrypt(ctx, call.Input)
		if err != nil || output != call.Output {
			return nil, errors.New("saved Hy encryptor replay did not match its captured state")
		}
	}
	if runtime.randomPosition != len(snapshot.Random) || runtime.timePosition != len(snapshot.Times) || runtime.entropyPosition != len(snapshot.Entropy) {
		return nil, errors.New("saved Hy runtime input replay is incomplete")
	}
	runtime.replaying = false
	return runtime, nil
}

func newAndroidHyRuntime(ctx context.Context, snapshot *AndroidHyRuntimeSnapshot, replay bool) (*androidHyRuntime, error) {
	r := &androidHyRuntime{vm: goja.New(), capture: *cloneAndroidHyRuntimeSnapshot(snapshot), replaying: replay, clock: time.Now}
	r.vm.SetMaxCallStackSize(256)
	r.vm.SetRandSource(r.random)
	r.vm.SetTimeSource(r.now)
	global := r.vm.GlobalObject()
	for _, name := range []string{"window", "self", "globalThis"} {
		_ = r.vm.Set(name, global)
	}
	navigator := r.vm.NewObject()
	_ = navigator.Set("userAgent", snapshot.UserAgent)
	_ = navigator.Set("language", snapshot.Language)
	_ = navigator.Set("languages", []string{snapshot.Language})
	_ = r.vm.Set("navigator", navigator)
	page, _ := url.Parse(snapshot.PageURL)
	_ = r.vm.Set("location", map[string]string{"href": snapshot.PageURL, "origin": urlOrigin(page), "pathname": page.Path, "search": "?" + page.RawQuery, "hash": "", "protocol": page.Scheme + ":", "host": page.Host, "hostname": page.Hostname()})
	_ = r.vm.Set("document", map[string]any{"cookie": snapshot.VisibleCookies, "URL": snapshot.PageURL})
	_ = r.vm.Set("console", map[string]any{"log": func(...any) {}, "warn": func(...any) {}, "error": func(...any) {}})
	_ = r.vm.Set("__hyUnsupported", r.blocked)
	// Missing browser observations must not become fabricated fallback
	// fingerprints, even when downloaded code catches the resulting error.
	_, err := r.run(ctx, `(function(){function observed(o){return new Proxy(o,{get:function(t,k){if(k in t)return t[k];return __hyUnsupported();},set:function(){return __hyUnsupported();}});}window.navigator=observed(window.navigator);window.document=observed(window.document);["screen","innerWidth","innerHeight","outerWidth","outerHeight","devicePixelRatio","localStorage","sessionStorage","indexedDB","openDatabase","Android","WebViewJavascriptBridge"].forEach(function(k){Object.defineProperty(window,k,{get:__hyUnsupported,set:__hyUnsupported,configurable:false});});})()`)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"fetch", "XMLHttpRequest", "WebSocket", "Image", "Worker", "setTimeout", "setInterval", "requestAnimationFrame", "postMessage"} {
		_ = r.vm.Set(name, r.blocked)
	}
	_ = r.vm.Set("atob", func(call goja.FunctionCall) goja.Value {
		decoded, err := base64.StdEncoding.DecodeString(call.Argument(0).String())
		if err != nil || len(decoded) > 65536 {
			panic(r.vm.NewTypeError("invalid bootstrap base64"))
		}
		codes := make([]rune, len(decoded))
		for i, b := range decoded {
			codes[i] = rune(b)
		}
		return r.vm.ToValue(string(codes))
	})
	_ = r.vm.Set("btoa", func(call goja.FunctionCall) goja.Value {
		text := []rune(call.Argument(0).String())
		if len(text) > 65536 {
			panic(r.vm.NewTypeError("bootstrap base64 exceeds bounds"))
		}
		bytes := make([]byte, len(text))
		for i, ch := range text {
			if ch > 255 {
				panic(r.vm.NewTypeError("bootstrap base64 requires byte characters"))
			}
			bytes[i] = byte(ch)
		}
		return r.vm.ToValue(base64.StdEncoding.EncodeToString(bytes))
	})
	_ = r.vm.Set("__hyEntropy", r.entropy)
	// The callable receives real cryptographic randomness. Its byte stream is
	// saved solely to replay this exact encryptor's private closure state.
	_, err = r.run(ctx, `Object.defineProperty(globalThis,"crypto",{value:{getRandomValues:function(a){if(!ArrayBuffer.isView(a)||a instanceof DataView||a instanceof Float32Array||a instanceof Float64Array)throw new TypeError("integer typed array required");var b=new Uint8Array(a.buffer,a.byteOffset,a.byteLength),v=__hyEntropy(b.length);for(var i=0;i<b.length;i++)b[i]=v[i];return a;}}});`)
	if err != nil {
		return nil, err
	}
	for i, script := range snapshot.Scripts {
		if _, err := r.run(ctx, script.Source); err != nil {
			return nil, fmt.Errorf("Android Hy captured bootstrap script %d could not execute in its bounded runtime", i+1)
		}
	}
	value, err := r.run(ctx, `!!window.fsec && typeof window.fsec.encrypt === 'function'`)
	if err != nil {
		return nil, errors.New("Android Hy FSEC property could not be inspected")
	}
	r.fsec = value.ToBoolean()
	return r, nil
}

func (r *androidHyRuntime) blocked(call goja.FunctionCall) goja.Value {
	r.unsupported = true
	panic(r.vm.NewTypeError("bootstrap requires an unsupported browser operation"))
}

func (r *androidHyRuntime) random() float64 {
	if r.replaying {
		if r.randomPosition >= len(r.capture.Random) {
			panic(r.vm.NewTypeError("captured random input exhausted"))
		}
		value := r.capture.Random[r.randomPosition]
		r.randomPosition++
		return value
	}
	if len(r.capture.Random) >= hyRuntimeMaxTape {
		panic(r.vm.NewTypeError("bootstrap random input exceeds bounds"))
	}
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(r.vm.NewTypeError("bootstrap randomness unavailable"))
	}
	value := float64(binary.LittleEndian.Uint64(bytes[:])>>11) / (1 << 53)
	r.capture.Random = append(r.capture.Random, value)
	return value
}

func (r *androidHyRuntime) now() time.Time {
	if r.replaying {
		if r.timePosition >= len(r.capture.Times) {
			panic(r.vm.NewTypeError("captured time input exhausted"))
		}
		value := r.capture.Times[r.timePosition]
		r.timePosition++
		return time.UnixMilli(value)
	}
	if len(r.capture.Times) >= hyRuntimeMaxTape {
		panic(r.vm.NewTypeError("bootstrap time input exceeds bounds"))
	}
	value := r.clock().UnixMilli()
	r.capture.Times = append(r.capture.Times, value)
	return time.UnixMilli(value)
}

func (r *androidHyRuntime) entropy(call goja.FunctionCall) goja.Value {
	length := call.Argument(0).ToInteger()
	if length < 0 || length > 65536 {
		panic(r.vm.NewTypeError("bootstrap entropy exceeds bounds"))
	}
	var bytes []byte
	if r.replaying {
		if r.entropyPosition >= len(r.capture.Entropy) {
			panic(r.vm.NewTypeError("captured entropy input exhausted"))
		}
		bytes, _ = base64.StdEncoding.DecodeString(r.capture.Entropy[r.entropyPosition])
		r.entropyPosition++
		if int64(len(bytes)) != length {
			panic(r.vm.NewTypeError("captured entropy input length differs"))
		}
	} else {
		if len(r.capture.Entropy) >= hyRuntimeMaxTape {
			panic(r.vm.NewTypeError("bootstrap entropy input exceeds bounds"))
		}
		total := int(length)
		for _, encoded := range r.capture.Entropy {
			total += base64.StdEncoding.DecodedLen(len(encoded))
		}
		if total > hyRuntimeMaxTotal {
			panic(r.vm.NewTypeError("bootstrap entropy input exceeds aggregate bounds"))
		}
		bytes = make([]byte, int(length))
		if _, err := rand.Read(bytes); err != nil {
			panic(r.vm.NewTypeError("bootstrap randomness unavailable"))
		}
		r.capture.Entropy = append(r.capture.Entropy, base64.StdEncoding.EncodeToString(bytes))
	}
	values := make([]int, len(bytes))
	for i, b := range bytes {
		values[i] = int(b)
	}
	return r.vm.ToValue(values)
}

func (r *androidHyRuntime) bounded(ctx context.Context, callback func() (goja.Value, error)) (goja.Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	guard, cancel := context.WithTimeout(ctx, hyRuntimeDeadline)
	defer cancel()
	done := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-guard.Done():
			r.vm.Interrupt("bootstrap execution deadline")
		case <-done:
		}
	}()
	value, err := callback()
	close(done)
	<-joined
	r.vm.ClearInterrupt()
	if guard.Err() != nil {
		return nil, errors.New("Android Hy runtime execution deadline exceeded")
	}
	if r.unsupported {
		return nil, errors.New("Android Hy bootstrap requires an unobserved browser operation")
	}
	return value, err
}

func (r *androidHyRuntime) run(ctx context.Context, source string) (goja.Value, error) {
	return r.bounded(ctx, func() (goja.Value, error) { return r.vm.RunString(source) })
}

func (r *androidHyRuntime) globals(ctx context.Context) (TemplateData, error) {
	value, err := r.run(ctx, `(function(){var s=window.__INITIAL_STATE__||{},t=window.templateData||{},p=s.pcftoken||t.pcftoken||"",j=window.jsToken||"";if(typeof p!=="string"||typeof j!=="string")throw new TypeError("bootstrap tokens must be strings");return {pcf:p,token:j};})()`)
	if err != nil {
		return TemplateData{}, errors.New("Android Hy runtime did not provide valid global tokens")
	}
	obj := value.ToObject(r.vm)
	data := TemplateData{PcfToken: obj.Get("pcf").String(), JsToken: obj.Get("token").String()}
	if data.PcfToken == "" || len(data.PcfToken) > 65536 || len(data.JsToken) > 65536 {
		return TemplateData{}, errors.New("Android Hy runtime did not provide bounded pcftoken")
	}
	return data, nil
}

func (r *androidHyRuntime) encrypt(ctx context.Context, input string) (string, error) {
	if len(input) > 4096 || !utf8.ValidString(input) {
		return "", errors.New("Android Hy FSEC input exceeds bounds")
	}
	// Property getters and the UTF-16 slice execute under the same deadline as
	// the encryptor. No unbounded JavaScript property access occurs in Go.
	functionValue, err := r.run(ctx, `(function(input){if(!window.fsec)return input;var encrypted=window.fsec.encrypt(input);if(typeof encrypted!=="string")throw new TypeError("FSEC output must be a string");return encrypted.slice(8);})`)
	if err != nil {
		return "", errors.New("Android Hy FSEC wrapper could not execute")
	}
	function, _ := goja.AssertFunction(functionValue)
	value, err := r.bounded(ctx, func() (goja.Value, error) { return function(goja.Undefined(), r.vm.ToValue(input)) })
	if err != nil {
		return "", errors.New("Android Hy FSEC encryption failed")
	}
	if _, ok := value.Export().(string); !ok {
		return "", errors.New("Android Hy FSEC encryption did not return a string")
	}
	if len(value.String()) > 65536 {
		return "", errors.New("Android Hy FSEC result exceeds bounds")
	}
	return value.String(), nil
}

func androidHyEncryptedFields(path string) []string {
	switch path {
	case "/passport/login", "/passport/register":
		return []string{"email", "mobile"}
	case "/passport/register_v4/sendcode", "/passport/prelogin", "/passport/resetpwd_code",
		"/passport/verify/resetpwd_code", "/passport/resetpwd_code_finish", "/passport/resetpwd",
		"/passport/account/info", "/passport/binding", "/passport/verify/protect", "/passport/merge":
		return []string{"email"}
	}
	return nil
}

func (r *androidHyRuntime) encryptForm(ctx context.Context, path string, form *formValues) (*formValues, bool, error) {
	if r == nil || form == nil {
		return form, false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fields := androidHyEncryptedFields(path)
	if len(fields) == 0 {
		return form, false, nil
	}
	copy := &formValues{keys: append([]string(nil), form.keys...), values: append([]string(nil), form.values...)}
	changed, present := true, false
	for _, field := range fields {
		for i, key := range form.keys {
			if key != field || form.values[i] == "" {
				continue
			}
			present = true
			input := form.values[i]
			output, err := r.encrypt(ctx, input)
			if err != nil {
				return nil, false, err
			}
			if r.fsec {
				if len(r.capture.Calls) >= hyRuntimeMaxTape {
					return nil, false, errors.New("Android Hy FSEC call history exceeds bounds")
				}
				total := len(input) + len(output)
				for _, call := range r.capture.Calls {
					total += len(call.Input) + len(call.Output)
				}
				if total > hyRuntimeMaxTotal {
					return nil, false, errors.New("Android Hy FSEC call history exceeds aggregate bounds")
				}
				r.capture.Calls = append(r.capture.Calls, AndroidHyRuntimeCall{Input: input, Output: output})
			}
			if output == input {
				changed = false
			}
			copy.values[i] = output
		}
	}
	// Oa() returns the entire original data object if even one truthy target
	// field was not encrypted. fs-ex-st accompanies only full transformation.
	if !present || !changed {
		return form, false, nil
	}
	return copy, true, nil
}
