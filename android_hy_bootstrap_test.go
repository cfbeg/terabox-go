package terabox

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestAndroidHyBootstrapUsesRuntimeGlobalSources(t *testing.T) {
	for _, test := range []struct{ name, page, pcf, token string }{
		{"template before initial", `<script>var templateData={"pcftoken":"template-pcf","jsToken":"wrong-template-token"};window.__INITIAL_STATE__={"pcftoken":"initial-pcf","jsToken":"wrong-state-token"};window.jsToken="global-token";</script>`, "initial-pcf", "global-token"},
		{"initial before template", `<script>window.__INITIAL_STATE__={"pcftoken":"initial-pcf"};var templateData={"pcftoken":"template-pcf"};</script>`, "initial-pcf", ""},
		{"fallback", `<script>window.__INITIAL_STATE__={"pcftoken":""};var templateData={"pcftoken":"template-pcf","jsToken":"not-global"};</script>`, "template-pcf", ""},
		{"irrelevant object token types", `<script>window.__INITIAL_STATE__={"pcftoken":"initial-pcf","jsToken":true};var templateData={"pcftoken":"template-pcf","jsToken":{}};window.jsToken='global-token';</script>`, "initial-pcf", "global-token"},
		{"latest assignment", `<script>var templateData={"pcftoken":"first"};var templateData={"pcftoken":"last"};var jsToken='first';window.jsToken='last';</script>`, "last", "last"},
		{"string and comment distractors", `<script>// window.jsToken="comment";
/*window.__INITIAL_STATE__={"pcftoken":"comment"};*/ var text="window.jsToken='text'";var templateData={"pcftoken":"actual"};</script>`, "actual", ""},
		{"function local token", `<script>function unused(){var jsToken='local';}var templateData={"pcftoken":"actual"};</script>`, "actual", ""},
		{"global comparison is read only", `<script>function read(){return window.jsToken==='known';}var templateData={"pcftoken":"actual"};</script>`, "actual", ""},
		{"regex and member distractors", `<script>var re=/window.jsToken='regex'/;var object={};object.window.jsToken='member';var templateData={"pcftoken":"actual"};</script>`, "actual", ""},
		{"ASI literal assignment", "<script>var templateData={\"pcftoken\":\"actual\"}\nwindow.jsToken='global'\nvar unrelated=1;</script>", "actual", "global"},
		{"script JSON distractor", `<script type="application/json">{"description":"window.jsToken='text'"}</script><script>window.templateData={"pcftoken":"actual"};</script>`, "actual", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := androidFixtureProfile()
			client, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				return shareJSONResponse(req, test.page), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			if err := client.loadAndroidHyPage(context.Background()); err != nil {
				t.Fatal(err)
			}
			query, err := client.androidH5Query()
			if err != nil {
				t.Fatal(err)
			}
			if client.androidH5Form().String() == "" || client.dataSnapshot().pcfToken != test.pcf || query.Get("jsToken") != test.token {
				t.Fatal("bootstrap differs from APK wa()/Dr() runtime global selection")
			}
		})
	}
}

func TestAndroidHyBootstrapLiteralEscapesAndUnsupportedDynamic(t *testing.T) {
	for _, test := range []struct{ literal, token string }{
		{`"quote\"slash\\unicode\u0061"`, "quote\"slash\\unicodea"},
		{`'single\'quote\x41\uD83D\uDE00'`, "single'quoteA😀"},
		{`"\u{1F600}\b\f\n\r\t\v\0"`, "😀\b\f\n\r\t\v\x00"},
		{"'continued\\\nline'", "continuedline"},
		{`'slash\/identity\z'`, "slash/identityz"},
		{`'\u0041}'`, "A}"},
	} {
		page := `<script>var templateData={"pcftoken":"actual"};var jsToken=` + test.literal + `;</script>`
		data, err := androidHyBootstrap(page)
		if err != nil || data.JsToken != test.token {
			t.Fatalf("observed JS literal decoded incorrectly: %v", err)
		}
	}
	for _, rhs := range []string{`generateToken()`, `'literal'+secret()`, `JSON.parse('"token"')`, "`computed${value}`", `'\uD800'`, `'\xZZ'`, `'\01'`} {
		page := `<script>var templateData={"pcftoken":"actual"};window.jsToken=` + rhs + `;</script>`
		if _, err := androidHyBootstrap(page); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatal("unsupported dynamic/malformed global token was accepted")
		}
	}
	for _, conditional := range []string{`if(condition)window.jsToken='conditional';`, `condition&& (window.jsToken='conditional');`, `function delayed(){window.jsToken='later';}`} {
		if _, err := androidHyBootstrap(`<script>var templateData={"pcftoken":"actual"};` + conditional + `</script>`); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatal("conditional/function assignment was treated as an observed unconditional global value")
		}
	}
}

func TestAndroidHyBootstrapRedirectCookieReplacementAndDeletion(t *testing.T) {
	requests := 0
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithCookies("sid=old; gone=old; retain=present"),
		WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			if requests == 1 {
				response := shareJSONResponse(req, "")
				response.StatusCode = http.StatusFound
				response.Header.Set("Location", "https://www.terabox.com/wap/hylogin/emailRegister?type=1&redirected=1")
				response.Header.Add("Set-Cookie", "sid=new; Path=/")
				response.Header.Add("Set-Cookie", "gone=; Max-Age=0; Path=/")
				return response, nil
			}
			var values = map[string]string{}
			for _, cookie := range req.Cookies() {
				if _, exists := values[cookie.Name]; exists {
					t.Error("redirect request sent duplicate cookie names")
				}
				values[cookie.Name] = cookie.Value
			}
			if !reflect.DeepEqual(values, map[string]string{"sid": "new", "retain": "present"}) {
				t.Error("redirect request failed to replace/delete previous cookies")
			}
			response := shareJSONResponse(req, `<script>var templateData={"pcftoken":"actual"};</script>`)
			response.Header.Add("Set-Cookie", "final=observed; Path=/")
			return response, nil
		})}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.loadAndroidHyPage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || client.CookieString() != "final=observed; retain=present; sid=new" {
		t.Fatal("redirect/final cookies were not committed correctly")
	}
}

func TestAndroidHyInvalidBootstrapRetainsAccountAndCookies(t *testing.T) {
	for _, page := range []string{
		`<script>var templateData={"pcftoken":"actual"};window.jsToken=dynamicValue();</script>`,
		`<script>window.fsec={};var templateData={"pcftoken":"actual"};</script>`,
		`<html>missing PCF</html>`,
	} {
		requests := 0
		client, err := NewAndroidAppClient(androidFixtureProfile(), WithCookies("sid=original"), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			response := shareJSONResponse(req, page)
			response.Header.Add("Set-Cookie", "sid=replaced; Path=/")
			if requests == 1 {
				response.StatusCode = http.StatusFound
				response.Header.Set("Location", "https://www.terabox.com/wap/hylogin/emailRegister?type=1&other=1")
			}
			return response, nil
		})}))
		if err != nil {
			t.Fatal(err)
		}
		before, _ := json.Marshal(client.WebmasterRegistrationSession())
		if err := client.loadAndroidHyPage(context.Background()); err == nil {
			t.Fatal("invalid bootstrap accepted")
		}
		after, _ := json.Marshal(client.WebmasterRegistrationSession())
		if string(before) != string(after) || client.androidApp.ready {
			t.Fatal("invalid bootstrap committed partial account/cookie state")
		}
	}
}

func TestAndroidHySessionPreservesActualGlobalToken(t *testing.T) {
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return shareJSONResponse(req, `<script>var templateData={"pcftoken":"actual"};window.jsToken='actual-global-token';</script>`), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.loadAndroidHyPage(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(client.WebmasterRegistrationSession())
	if err != nil {
		t.Fatal(err)
	}
	var saved WebmasterRegistrationSession
	if err := json.Unmarshal(body, &saved); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewAndroidAppClient(*saved.AndroidApp)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.RestoreWebmasterRegistrationSession(&saved); err != nil {
		t.Fatal(err)
	}
	query, err := fresh.androidH5Query()
	if err != nil || query.Get("jsToken") != "actual-global-token" {
		t.Fatal("actual Hy global token was lost during session restore")
	}
	deleteOld := map[string]json.RawMessage{}
	json.Unmarshal(body, &deleteOld)
	delete(deleteOld, "hy_js_token")
	legacy, _ := json.Marshal(deleteOld)
	json.Unmarshal(legacy, &saved)
	// JSON Unmarshal into a reused struct retains absent fields; old sessions
	// are decoded into fresh structs, as production importers do.
	saved = WebmasterRegistrationSession{}
	json.Unmarshal(legacy, &saved)
	old, err := NewAndroidAppClient(*saved.AndroidApp)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.RestoreWebmasterRegistrationSession(&saved); err != nil {
		t.Fatal(err)
	}
	query, err = old.androidH5Query()
	if err != nil || query.Get("jsToken") != "" {
		t.Fatal("legacy missing global token did not retain empty default")
	}
}
