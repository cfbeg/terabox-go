package terabox

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func accountRegionFixture(t *testing.T, opts ...Option) *Client {
	t.Helper()
	profile := androidFixtureProfile()
	profile.UID = "77"
	options := append([]Option{WithCookies("ndus=region-fixture-session")}, opts...)
	client, err := NewAndroidAppClient(profile, options...)
	if err != nil {
		t.Fatal(err)
	}
	client.registrationConfirmed = true
	return client
}

func TestAndroidAccountRegionMapping(t *testing.T) {
	for _, test := range []struct {
		name, current, prefix, want string
	}{
		{"www uses bare domain", "https://www.terabox.com", "www", "https://terabox.com"},
		{"region from www", "https://www.terabox.com", "jp", "https://jp.terabox.com"},
		{"region from bare domain", "https://terabox.com", "jp", "https://jp.terabox.com"},
		{"return to default region", "https://jp.terabox.com", "www", "https://terabox.com"},
		{"valid single label", "https://terabox.com", "ap-south", "https://ap-south.terabox.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := accountRegionFixture(t, WithAPIHost(test.current))
			page := client.AndroidAppProfile().PageURL
			data, _ := json.Marshal(map[string]string{"region_domain_prefix": test.prefix})
			client.applyAndroidAccountRegion(&PassportResponse{Data: data, NDUS: "region-fixture-session"})
			if got, _ := client.snapshot(); got != test.want {
				t.Fatalf("API origin = %q, want %q", got, test.want)
			}
			if client.AndroidAppProfile().PageURL != page {
				t.Fatal("region response changed the captured Hy URL")
			}
		})
	}
}

func TestAndroidAccountRegionPreservesExplicitCustomOrigins(t *testing.T) {
	for _, origin := range []string{
		"http://127.0.0.1:8123", "https://fixture.invalid", "https://terabox.com.fixture.invalid",
		"http://www.terabox.com", "https://jp.terabox.com:8443", "https://www.terabox.com/custom",
	} {
		t.Run(origin, func(t *testing.T) {
			client := accountRegionFixture(t, WithAPIHost(origin))
			client.applyAndroidAccountRegion(&PassportResponse{Data: json.RawMessage(`{"region_domain_prefix":"jp"}`)})
			if got, _ := client.snapshot(); got != origin {
				t.Fatalf("explicit API origin changed to %q", got)
			}
		})
	}
}

func TestAndroidAccountRegionRequiresConfirmedIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		uid  string
		ndus string
	}{
		{"no UID", "", "region-fixture-session"},
		{"no NDUS", "77", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := androidFixtureProfile()
			profile.UID = test.uid
			client, err := NewAndroidAppClient(profile, WithCookies("ndus="+test.ndus))
			if err != nil {
				t.Fatal(err)
			}
			before, _ := client.snapshot()
			client.applyAndroidAccountRegion(&PassportResponse{Data: json.RawMessage(`{"region_domain_prefix":"jp"}`)})
			if got, _ := client.snapshot(); got != before {
				t.Fatal("region metadata routed an account before native identity was committed")
			}
		})
	}
	client := accountRegionFixture(t)
	for _, response := range []*PassportResponse{
		nil, {Code: 1, Data: json.RawMessage(`{"region_domain_prefix":"jp"}`)},
		{Errno: 1, Data: json.RawMessage(`{"region_domain_prefix":"jp"}`)},
		{Data: json.RawMessage(`{"url_domain_prefix":"jp"}`)},
		{Data: json.RawMessage(`{}`)},
	} {
		before, _ := client.snapshot()
		client.applyAndroidAccountRegion(response)
		if got, _ := client.snapshot(); got != before {
			t.Fatal("failed or absent account region changed API routing")
		}
	}
}

func TestAndroidAccountRegionNativeRoutingAndSessionRestore(t *testing.T) {
	requests := 0
	transport := shareRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Scheme != "https" || request.URL.Host != "jp.terabox.com" ||
			request.URL.Path != "/api/account/uinfo" || request.Method != http.MethodPost {
			t.Fatalf("native account check used the wrong regional endpoint: %s", request.URL)
		}
		if request.Header.Get("Cookie") != "ndus=region-fixture-session" {
			t.Fatal("native account check lost its confirmed session")
		}
		return shareJSONResponse(request, `{"errno":0,"uk":"91"}`), nil
	})
	client := accountRegionFixture(t, WithHTTPClient(&http.Client{Transport: transport}))
	page := client.AndroidAppProfile().PageURL
	client.applyAndroidAccountRegion(&PassportResponse{Data: json.RawMessage(`{"region_domain_prefix":"jp"}`)})
	if _, err := client.CheckLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved := client.WebmasterRegistrationSession()
	if saved.WebHost != "https://jp.terabox.com" || saved.AndroidApp.PageURL != page {
		t.Fatal("snapshot lost regional routing or rewrote the captured Hy URL")
	}
	encoded, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	var decoded WebmasterRegistrationSession
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewAndroidAppClient(*saved.AndroidApp, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.RestoreWebmasterRegistrationSession(&decoded); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.CheckLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || fresh.AndroidAppProfile().UID != "77" || fresh.Account().ID != 91 {
		t.Fatal("restored regional checks lost native identity or confused it with UK")
	}
}

func TestAndroidAccountRegionInvalidMetadataKeepsAccountAndSecrets(t *testing.T) {
	for _, raw := range []string{
		`null`, `17`, `true`, `{}`, `[]`, `""`, `"jp.evil.invalid"`, `"jp/evil"`,
		`"region-fixture-session@evil.invalid"`, `"https://evil.invalid"`, `"jp:444"`,
		`" jp"`, `"jp\r\nHost: evil.invalid"`, `"-jp"`, `"jp-"`,
	} {
		t.Run(raw, func(t *testing.T) {
			var logs bytes.Buffer
			requests := 0
			client := accountRegionFixture(t, WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
				WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					requests++
					if request.URL.Host != "www.terabox.com" {
						t.Fatal("invalid response metadata routed credentials away from the current origin")
					}
					return shareJSONResponse(request, `{"errno":0,"uk":91}`), nil
				})}))
			client.applyAndroidAccountRegion(&PassportResponse{NDUS: "region-fixture-session",
				Data: json.RawMessage(`{"region_domain_prefix":` + raw + `}`)})
			if _, err := client.CheckLogin(context.Background()); err != nil {
				t.Fatal(err)
			}
			if requests != 1 || !client.WebmasterRegistrationSession().RegistrationConfirmed ||
				client.AndroidAppProfile().UID != "77" {
				t.Fatal("invalid optional metadata discarded the confirmed account")
			}
			if got, _ := client.CookieValue("ndus"); got != "region-fixture-session" {
				t.Fatal("invalid region metadata changed the confirmed session")
			}
			if !strings.Contains(logs.String(), "WARN") || strings.Contains(logs.String(), "region-fixture-session") ||
				strings.Contains(logs.String(), "evil.invalid") {
				t.Fatal("region warning was missing or disclosed untrusted metadata")
			}
		})
	}
}
