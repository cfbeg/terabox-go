package terabox

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAndroidHyRuntimeMatchesAPKEncryptionReplay(t *testing.T) {
	encoded, err := os.ReadFile("testdata/android_hy_fsec_replay.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name      string            `json:"name"`
			Encryptor *string           `json:"encryptor"`
			Fields    []string          `json:"fields"`
			Input     map[string]string `json:"input"`
			Output    map[string]string `json:"output"`
			Encrypted bool              `json:"encrypted"`
		} `json:"cases"`
	}
	if json.Unmarshal(encoded, &fixture) != nil || len(fixture.Cases) != 6 {
		t.Fatal("actual APK wrapper replay fixture is invalid")
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			source := `var templateData={pcftoken:['page','pcf'].join('-')};`
			if test.Encryptor != nil {
				source += `window.fsec={encrypt:` + *test.Encryptor + `};`
			}
			_, runtime, err := resolveAndroidHyBootstrap(context.Background(), `<script>`+source+`</script>`, androidFixtureProfile(), "", nil)
			if err != nil {
				t.Fatal(err)
			}
			path := "/passport/register_v4/sendcode"
			if len(test.Fields) == 2 {
				path = "/passport/login"
			}
			form, changed, err := runtime.encryptForm(context.Background(), path, newFormFrom(test.Input))
			if err != nil {
				t.Fatal(err)
			}
			actual := make(map[string]string, len(form.keys))
			for i, key := range form.keys {
				actual[key] = form.values[i]
			}
			if changed != test.Encrypted || !reflect.DeepEqual(actual, test.Output) {
				t.Fatal("FSEC wrapper differs from actual APK offline replay")
			}
		})
	}
}

func TestAndroidHyDynamicBootstrapUsesCapturedSourceAndEnvironment(t *testing.T) {
	profile := androidFixtureProfile()
	page := `<script>var templateData={pcftoken: ['page','pcf'].join('-')};
	window.jsToken=window.navigator.userAgent + ':' + window.location.pathname + ':' + document.cookie;
	window.fsec={encrypt:function(value){return 'PREFIX08'+value.split('').reverse().join('');}};</script>`
	data, runtime, err := resolveAndroidHyBootstrap(context.Background(), page, profile, "visible=observed", nil)
	if err != nil {
		t.Fatal(err)
	}
	if data.PcfToken != "page-pcf" || data.JsToken != profile.UserAgent+":/wap/hylogin/emailRegister:visible=observed" || runtime == nil {
		t.Fatal("dynamic global bootstrap did not use its own captured source and inputs")
	}
	form := newFormFrom(map[string]string{"email": "mail@example.invalid", "token": "registration-token", "pwd": "RSA-password"})
	encrypted, changed, err := runtime.encryptForm(context.Background(), "/passport/register_v4/sendcode", form)
	if err != nil || !changed {
		t.Fatalf("captured encrypt function did not run: %v", err)
	}
	if encrypted.values[0] == "" || form.String() == encrypted.String() || !strings.Contains(encrypted.String(), "pwd=RSA-password") {
		t.Fatal("FSEC changed a non-email field or did not transform email")
	}
	for _, path := range []string{"/passport/register_v4/verify", "/passport/register_v4/finish", "/passport/getpubkey"} {
		actual, changed, err := runtime.encryptForm(context.Background(), path, form)
		if err != nil || changed || actual != form {
			t.Fatal("APK unencrypted endpoint used FSEC")
		}
	}
}

func TestAndroidHyRuntimePreservesAllOrNothingAPKEncryptionRule(t *testing.T) {
	profile := androidFixtureProfile()
	for _, source := range []string{
		`window.fsec={encrypt:function(e){return 'PREFIX08'+(e==='unchanged' ? e : 'encrypted:'+e);}};`,
		`window.fsec={encrypt:function(e){return 'PREFIX08'+e;}};`,
	} {
		page := `<script>var templateData={"pcftoken":"pcf"};` + source + `</script>`
		_, runtime, err := resolveAndroidHyBootstrap(context.Background(), page, profile, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		form := newFormFrom(map[string]string{"email": "email", "mobile": "unchanged"})
		actual, changed, err := runtime.encryptForm(context.Background(), "/passport/login", form)
		if err != nil || changed || actual != form {
			t.Fatal("Oa() all-target-fields condition differs from APK")
		}
	}
}

func TestAndroidHyRuntimeCaptureReplaysEntropyTimeAndClosure(t *testing.T) {
	profile := androidFixtureProfile()
	page := `<script>var start=Date.now(), random=Math.random();var templateData={pcftoken:'pcf:'+start+':'+random};
	var seed=new Uint8Array(4);crypto.getRandomValues(seed);window.jsToken=Array.from(seed).join(',');
	var counter=0;window.fsec={encrypt:function(e){var n=new Uint8Array(3);crypto.getRandomValues(n);return 'PREFIX08'+e+':'+(++counter)+':'+Date.now()+':'+Math.random()+':'+Array.from(n).join(',');}};</script>`
	data, runtime, err := resolveAndroidHyBootstrap(context.Background(), page, profile, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	form := newFormFrom(map[string]string{"email": "private@example.invalid"})
	for i := 0; i < 2; i++ {
		if _, changed, err := runtime.encryptForm(context.Background(), "/passport/prelogin", form); err != nil || !changed {
			t.Fatal(err)
		}
	}
	encoded, err := json.Marshal(runtime.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var snapshot AndroidHyRuntimeSnapshot
	if json.Unmarshal(encoded, &snapshot) != nil {
		t.Fatal("snapshot JSON failed")
	}
	restored, err := restoreAndroidHyRuntime(context.Background(), &snapshot, profile, data.PcfToken, data.JsToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.snapshot().Calls) != 2 {
		t.Fatal("replayed encryption calls were duplicated")
	}
	third, changed, err := restored.encryptForm(context.Background(), "/passport/prelogin", form)
	if err != nil || !changed || !strings.Contains(third.String(), "%3A3%3A") {
		t.Fatal("encryptor closure state was lost on restore")
	}
	if len(restored.snapshot().Calls) != 3 {
		t.Fatal("resumed encryption call was not saved")
	}
	mutated := *cloneAndroidHyRuntimeSnapshot(&snapshot)
	mutated.Calls[0].Output = "different"
	if _, err := restoreAndroidHyRuntime(context.Background(), &mutated, profile, data.PcfToken, data.JsToken); err == nil {
		t.Fatal("changed encryptor history accepted")
	}
	profile.DeviceID = "different-device"
	if _, err := restoreAndroidHyRuntime(context.Background(), &snapshot, profile, data.PcfToken, data.JsToken); err == nil {
		t.Fatal("bootstrap source transplanted between Android identities")
	}
}

func TestAndroidHyRuntimeDoesNotInventBrowserCapabilitiesOrSendNetwork(t *testing.T) {
	profile := androidFixtureProfile()
	for _, source := range []string{
		`try{fetch('/passport/register_v4/sendcode');}catch(e){};window.jsToken='fallback';`,
		`try{document.createElement('canvas');}catch(e){};window.jsToken='fallback';`,
		`try{navigator.platform;}catch(e){};window.jsToken='fallback';`,
		`try{window.screen;}catch(e){};window.jsToken='fallback';`,
		`window.jsToken=(function(){while(true){} })();`,
	} {
		page := `<script>var templateData={pcftoken:'pcf'};` + source + `</script>`
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _, err := resolveAndroidHyBootstrap(ctx, page, profile, "", nil)
		cancel()
		if err == nil {
			t.Fatal("unsupported browser environment or execution without bound accepted")
		}
		if strings.Contains(err.Error(), "fallback") {
			t.Fatal("error exposed token/source content")
		}
	}
}

func TestAndroidHyRuntimeFetchesOnlyReferencedFSECDependency(t *testing.T) {
	profile := androidFixtureProfile()
	page := `<script>var templateData={"pcftoken":"pcf"};</script><script src="https://s5.teraboxcdn.com/assets/fsec.js"></script><script src="https://www.google.com/recaptcha/enterprise.js"></script>`
	requests := 0
	_, runtime, err := resolveAndroidHyBootstrap(context.Background(), page, profile, "", func(ctx context.Context, address *url.URL) (string, error) {
		requests++
		if address.String() != "https://s5.teraboxcdn.com/assets/fsec.js" {
			t.Fatal("unexpected external asset request")
		}
		return `window.fsec={encrypt:function(e){return 'PREFIX08encrypted:'+e;}};`, nil
	})
	if err != nil || runtime == nil || requests != 1 {
		t.Fatalf("captured asset dependency not loaded: %v", err)
	}
	for _, address := range []string{"https://outside.invalid/fsec.js", "http://www.terabox.com/fsec.js", "https://www.terabox.com:443/fsec.js"} {
		requests = 0
		bad := `<script>var templateData={"pcftoken":"pcf"};</script><script src="` + address + `"></script>`
		if _, _, err := resolveAndroidHyBootstrap(context.Background(), bad, profile, "", func(context.Context, *url.URL) (string, error) { requests++; return "", nil }); err == nil || requests != 0 {
			t.Fatal("untrusted FSEC dependency fetched")
		}
	}
}

func TestAndroidHyLiteralFastPathKeepsOptionalGlobalsAndOldSession(t *testing.T) {
	data, runtime, err := resolveAndroidHyBootstrap(context.Background(), `<script>var templateData={"pcftoken":"observed"};</script><script src="https://www.terabox.com/ndbs/nd_bundle.js"></script>`, androidFixtureProfile(), "", func(context.Context, *url.URL) (string, error) {
		t.Fatal("literal bootstrap fetched unrelated fingerprint asset")
		return "", nil
	})
	if err != nil || data.PcfToken != "observed" || data.JsToken != "" || runtime != nil {
		t.Fatal("literal fast path changed")
	}
	if runtime, err := restoreAndroidHyRuntime(context.Background(), nil, androidFixtureProfile(), "observed", ""); err != nil || runtime != nil {
		t.Fatal("legacy session runtime default changed")
	}
}
