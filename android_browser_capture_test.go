package terabox

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func browserObservationFixture() AndroidShareClickObservation {
	query := url.Values{"app_id": {"250528"}, "web": {"1"}, "channel": {"dubox"}, "clienttype": {"5"}, "jsToken": {"observed-browser-token"},
		"dp-logid": {"observed-log-id"}, "version": {"0"}, "devuid": {"0"}, "cuid": {"0"}, "lang": {"en"}}
	form := url.Values{"pid": {"tera_sharelink"}, "c": {"https://www.terabox.com/wap/share/filelist?surl=fixture#files"}, "pdetail": {"header_button"},
		"tera_link_id": {"observed-link-id"}, "tera_link_type": {"2"}, "lang": {"en"}, "os_version": {""}, "device": {""},
		"af_dp": {"dubox://share_detail?uk=202&shareid=101&surl=fixture"}, "referrer": {""}, "agency": {""}}
	return AndroidShareClickObservation{Method: "POST", URL: "https://www.terabox.com/api/srn/ck?" + query.Encode(), Body: form.Encode(),
		Headers: map[string]string{"User-Agent": "Mozilla/5.0 observed-browser", "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
			"Referer": "https://www.terabox.com/wap/share/filelist?surl=fixture", "Origin": "https://www.terabox.com", "Cookie": "observed=private-browser-cookie"},
		ObservedAt: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
}

func TestParseAndroidShareClickObservationPreservesBrowserWireInputs(t *testing.T) {
	observed := browserObservationFixture()
	click, err := ParseAndroidShareClickObservation("fixture-installation", observed)
	if err != nil {
		t.Fatal(err)
	}
	if click.CommonParams["devuid"] != "0" || click.CommonParams["jsToken"] != "observed-browser-token" || click.BrowserCookies != observed.Headers["Cookie"] ||
		click.PageURL != "https://www.terabox.com/wap/share/filelist?surl=fixture#files" || click.Agency == nil || *click.Agency != "" || click.OpSource != nil ||
		len(click.BridgeBody) != 0 || click.Language != "en" || click.TeraLinkID != "observed-link-id" {
		t.Fatal("browser capture altered observed inputs or nullable fields")
	}
	click.CommonParams["jsToken"] = "changed-copy"
	if !strings.Contains(observed.URL, "observed-browser-token") {
		t.Fatal("adapter mutated observation")
	}
}

func TestParseAndroidShareClickObservationPreservesNativeBridge(t *testing.T) {
	observed := browserObservationFixture()
	endpoint, _ := url.Parse(observed.URL)
	query := endpoint.Query()
	for key, value := range map[string]string{"clienttype": "1", "channel": "observed-native-channel", "version": "4.26.5", "devuid": "fixture-installation", "cuid": "fixture-installation", "rand": "observed-signature", "time": "123"} {
		query.Set(key, value)
	}
	endpoint.RawQuery = query.Encode()
	observed.URL = endpoint.String()
	form, _ := url.ParseQuery(observed.Body)
	for _, key := range []string{"version", "devuid", "cuid"} {
		form.Set(key, query.Get(key))
	}
	form.Set("lang", "ja")
	observed.Body = form.Encode()
	click, err := ParseAndroidShareClickObservation("fixture-installation", observed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(click.BridgeBody, map[string]string{"version": "4.26.5", "devuid": "fixture-installation", "cuid": "fixture-installation", "lang": "ja"}) ||
		click.Language != "ja" || click.CommonParams["lang"] != "en" {
		t.Fatal("bridge final body language or native identity was overwritten")
	}
	form.Set("cuid", "different-installation")
	observed.Body = form.Encode()
	if _, err := ParseAndroidShareClickObservation("fixture-installation", observed); err == nil {
		t.Fatal("mismatched bridge body accepted")
	}
}

func TestParseAndroidShareClickObservationRejectsUnsafeOrAmbiguousInputs(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*AndroidShareClickObservation)
	}{
		{"missing method", func(o *AndroidShareClickObservation) { o.Method = "" }},
		{"wrong method", func(o *AndroidShareClickObservation) { o.Method = "GET" }},
		{"missing observation time", func(o *AndroidShareClickObservation) { o.ObservedAt = time.Time{} }},
		{"nil headers", func(o *AndroidShareClickObservation) { o.Headers = nil }},
		{"missing body", func(o *AndroidShareClickObservation) { o.Body = "" }},
		{"foreign origin", func(o *AndroidShareClickObservation) {
			o.URL = strings.Replace(o.URL, "www.terabox.com", "terabox.com.attacker.invalid", 1)
		}},
		{"plain HTTP", func(o *AndroidShareClickObservation) { o.URL = strings.Replace(o.URL, "https:", "http:", 1) }},
		{"userinfo", func(o *AndroidShareClickObservation) {
			o.URL = strings.Replace(o.URL, "https://", "https://private:secret@", 1)
		}},
		{"port", func(o *AndroidShareClickObservation) { o.URL = strings.Replace(o.URL, ".com/", ".com:8443/", 1) }},
		{"wrong endpoint", func(o *AndroidShareClickObservation) {
			o.URL = strings.Replace(o.URL, "/api/srn/ck", "/api/srn/ref", 1)
		}},
		{"encoded path", func(o *AndroidShareClickObservation) {
			o.URL = strings.Replace(o.URL, "/api/srn/ck", "/api/srn/%63k", 1)
		}},
		{"duplicate query", func(o *AndroidShareClickObservation) { o.URL += "&jsToken=another-private-token" }},
		{"empty query token", func(o *AndroidShareClickObservation) { o.URL = strings.Replace(o.URL, "observed-browser-token", "", 1) }},
		{"missing query field", func(o *AndroidShareClickObservation) { o.URL = strings.Replace(o.URL, "web=1", "", 1) }},
		{"duplicate form", func(o *AndroidShareClickObservation) { o.Body += "&tera_link_id=other" }},
		{"unknown body", func(o *AndroidShareClickObservation) { o.Body += "&unknown_private_field=secret" }},
		{"browser native body", func(o *AndroidShareClickObservation) { o.Body += "&version=0" }},
		{"browser native signing", func(o *AndroidShareClickObservation) { o.URL += "&rand=private-signature" }},
		{"missing referer", func(o *AndroidShareClickObservation) { delete(o.Headers, "Referer") }},
		{"different referer", func(o *AndroidShareClickObservation) {
			o.Headers["Referer"] = "https://www.terabox.com/wap/share/other"
		}},
		{"foreign origin header", func(o *AndroidShareClickObservation) { o.Headers["Origin"] = "https://attacker.invalid" }},
		{"header duplicates", func(o *AndroidShareClickObservation) { o.Headers["user-agent"] = "other-private-agent" }},
		{"header injection", func(o *AndroidShareClickObservation) { o.Headers["Cookie"] = "private\r\ninjection" }},
		{"wrong content type", func(o *AndroidShareClickObservation) { o.Headers["Content-Type"] = "application/json" }},
		{"invalid body encoding", func(o *AndroidShareClickObservation) { o.Body += "&agency=%zz" }},
		{"foreign form page", func(o *AndroidShareClickObservation) {
			o.Body = strings.Replace(o.Body, "www.terabox.com", "other.terabox.com", 1)
		}},
		{"unsupported producer", func(o *AndroidShareClickObservation) { o.Body = strings.Replace(o.Body, "header_button", "other", 1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := browserObservationFixture()
			test.change(&observed)
			if _, err := ParseAndroidShareClickObservation("fixture-installation", observed); err == nil {
				t.Fatal("invalid observation accepted")
			} else if err.Error() != "invalid Android share click observation" {
				t.Fatal("private inputs appeared in an error")
			}
		})
	}
	if _, err := ParseAndroidShareClickObservation("", browserObservationFixture()); err == nil {
		t.Fatal("missing installation binding accepted")
	}
}
