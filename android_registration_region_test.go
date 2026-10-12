package terabox

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAndroidFinishAppliesRegionOnlyAfterPreservingAccount(t *testing.T) {
	_, publicKey := androidPubkeyFixture(t)
	for _, test := range []struct{ name, region, want string }{
		{"regional", `"jp"`, "jp.terabox.com"},
		{"default", `"www"`, "terabox.com"},
		{"untrusted", `"outside.example"`, "www.terabox.com"},
		{"wrong optional type", `123`, "www.terabox.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/passport/getpubkey":
					return shareJSONResponse(request, publicKey), nil
				case "/passport/register_v4/finish":
					return shareJSONResponse(request, `{"code":0,"data":{"ndus":"confirmed-fixture-session","userid":"77","region_domain_prefix":`+test.region+`}}`), nil
				case "/api/account/uinfo":
					if request.URL.Host != test.want {
						t.Fatal("post-registration native request did not use the returned region")
					}
					cookie, err := request.Cookie("ndus")
					if err != nil || cookie.Value != "confirmed-fixture-session" {
						t.Fatal("optional region handling lost the account")
					}
					return shareJSONResponse(request, `{"errno":0,"uk":"88"}`), nil
				default:
					t.Fatalf("unexpected operation %s", request.URL.Path)
					return nil, nil
				}
			})}))
			if err != nil {
				t.Fatal(err)
			}
			client.androidApp.ready = true
			client.data.pcfToken = "fixture-pcf"
			client.registrationToken = "fixture-token"
			response, err := client.RegisterFinish(context.Background(), "fixture-token", "Abcdef12345!")
			if err != nil || response.NDUS != "confirmed-fixture-session" || client.AndroidAppProfile().UID != "77" {
				t.Fatal("valid registration was lost due to optional routing metadata")
			}
			if _, err := client.CheckLogin(context.Background()); err != nil {
				t.Fatal(err)
			}
			saved := client.WebmasterRegistrationSession()
			if !saved.RegistrationConfirmed || saved.NDUS != response.NDUS || saved.WebHost != "https://"+test.want {
				t.Fatal("confirmed account or routing was not saved")
			}
			data, _ := json.Marshal(saved)
			var restored WebmasterRegistrationSession
			json.Unmarshal(data, &restored)
			fresh, _ := NewAndroidAppClient(*restored.AndroidApp)
			if err := fresh.RestoreWebmasterRegistrationSession(&restored); err != nil {
				t.Fatal(err)
			}
		})
	}
}
