package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const shareEntryFixtureDeep = "dubox://share_detail?shareid=456&uk=123&randsk=access%2Bkey%3D&source=af_link&surl=observed"

func shareEntryFixtureReferral() *WebmasterReferral {
	return &WebmasterReferral{ShareURL: "https://terabox.com/s/1observed", ShareFromSURL: "observed",
		WebmasterUK: 123, ShareID: 456, Randsk: "access%2Bkey%3D", Source: "share"}
}

func shareEntryFixtureClient(t *testing.T, deepLink string, transport http.RoundTripper) *Client {
	t.Helper()
	client := attributionFixtureClient(t, transport)
	client.mu.Lock()
	capture := client.androidAttribution.Capture
	capture.Click.DeepLink = shareEntryFixtureDeep
	capture.InstallReferrer = attributionText(androidEncodeURIComponent("utm_source=tera_sharelink&af_dp=" + androidEncodeURIComponent(shareEntryFixtureDeep)))
	capture.Provenance = AndroidAttributionProvenanceShareLinkGenerated
	client.androidAttribution.Capture = capture
	client.mu.Unlock()
	body, _ := json.Marshal(map[string]any{"errno": 0, "request_id": 19, "data": map[string]any{
		"mediaSource": "tera_sharelink", "campaign": "server-preserved", "deeplink": deepLink}})
	client.mu.Lock()
	errno := 0
	client.androidAttribution.ReferrerReport = AndroidAttributionReport{Attempted: true, Succeeded: true,
		HTTPStatus: 200, Errno: &errno, RequestID: "19", RawResponse: body, RawBody: append([]byte(nil), body...)}
	referrer, err := attributionReferrerFromRaw(body)
	if err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	client.androidAttribution.Referrer = referrer
	media := "tera_sharelink"
	client.androidAttribution.AppInstallMediaSource = &media
	client.androidAttribution.AfCampaign = referrer.Campaign
	client.androidAttribution.DeepLinkValue = referrer.DeepLinkValue
	client.androidAttribution.WebmasterUK = attributionWebmasterUK(referrer)
	client.referral = cloneWebmasterReferral(shareEntryFixtureReferral())
	client.mu.Unlock()
	return client
}

func authenticateShareEntryFixture(t *testing.T, client *Client, ownUK int64) {
	t.Helper()
	client.mu.Lock()
	client.cookies["ndus"] = "fixture-authenticated-session"
	client.androidApp.profile.UID = "native-uid-distinct-from-uk"
	client.registrationFinished, client.registrationConfirmed = true, true
	client.mu.Unlock()
	client.updateParams(func(params *accountParams) { params.accountID = ownUK })
}

func stageAndDispatchShareEntryFixture(t *testing.T, client *Client) {
	t.Helper()
	stage, err := client.StageAndroidFirstLaunchShareEntry(shareEntryFixtureReferral())
	if err != nil || stage == nil || !stage.Pending || stage.Jumped || stage.Resolved.Randsk != "access+key=" {
		t.Fatalf("stage failed: %v", err)
	}
	if _, err := client.DispatchAndroidFirstLaunchShareEntry(); err != nil {
		t.Fatal(err)
	}
}

func TestFirstLaunchShareEntryGuestRejectionThenAuthenticatedNewScreen(t *testing.T) {
	requests, durable := 0, false
	var client *Client
	client = shareEntryFixtureClient(t, shareEntryFixtureDeep, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Path != "/rest/receive/report" || req.Method != http.MethodPost {
			t.Fatal("new screen used an unobserved endpoint")
		}
		body, _ := io.ReadAll(req.Body)
		if string(body) != `{"list":[{"optype":4,"scene":2,"unikey":"observed"}],"origin":0}` {
			t.Fatalf("share screen request changed: %s", body)
		}
		if requests == 1 {
			if req.Header.Get("Cookie") != "" {
				t.Fatal("guest entry unexpectedly authenticated")
			}
			return shareJSONResponse(req, `{"errno":-6,"request_id":30}`), nil
		}
		if !durable || !client.AndroidAttribution().ShareEntry.Authenticated.Report.Attempted || !strings.Contains(req.Header.Get("Cookie"), "ndus=fixture-authenticated-session") {
			t.Fatal("authenticated screen side effect preceded its durable new-entry journal")
		}
		return shareJSONResponse(req, `{"errno":0,"request_id":31}`), nil
	}))
	stageAndDispatchShareEntryFixture(t, client)
	guest, err := client.ReportShareView(context.Background(), &ShareViewOptions{OwnerUK: 123, ChainSURL: "observed"})
	if err != nil || guest.Errno != -6 {
		t.Fatal("guest response was not retained independently")
	}
	authenticateShareEntryFixture(t, client, 777)
	opts := &AndroidAuthenticatedShareEntryOptions{AccountUK: 777, BeforeSend: func(saved *WebmasterRegistrationSession) error {
		if saved.AndroidAttribution.ShareEntry.Authenticated.Report.Succeeded || !saved.AndroidAttribution.ShareEntry.Authenticated.Report.Attempted {
			t.Fatal("before-send state is not an uncertain new entry")
		}
		durable = true
		return nil
	}}
	response, err := client.ReportAndroidAuthenticatedShareEntry(context.Background(), opts)
	if err != nil || response.Errno != 0 || response.HTTPStatus != 200 || requests != 2 {
		t.Fatalf("authenticated entry failed: %v", err)
	}
	state := client.AndroidAttribution()
	if !state.ShareEntry.Jumped || state.ShareEntry.Pending || !state.ShareEntry.Authenticated.Report.Succeeded || state.ShareEntry.Authenticated.AccountUK != 777 || state.ShareEntry.Authenticated.AccountUID == "777" || guest.Errno != -6 {
		t.Fatal("first-launch route or separate own-account report state was lost")
	}
	if err := validateAndroidAttributionState(state, *client.AndroidAppProfile()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DispatchAndroidFirstLaunchShareEntry(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReportAndroidAuthenticatedShareEntry(context.Background(), opts); err != nil || requests != 2 {
		t.Fatal("confirmed entry was dispatched/reported again")
	}
	// Private snapshots cannot mutate pending/jumped or the endpoint response.
	state.ShareEntry.Authenticated.Report.RawResponse[0] = 'x'
	if !json.Valid(client.AndroidAttribution().ShareEntry.Authenticated.Report.RawResponse) {
		t.Fatal("share entry snapshot aliases client state")
	}
}

func TestAuthenticatedShareEntryUnknownAttemptSurvivesSessionRestore(t *testing.T) {
	requests := 0
	transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("connection interrupted after request")
	})
	client := shareEntryFixtureClient(t, shareEntryFixtureDeep, transport)
	stageAndDispatchShareEntryFixture(t, client)
	authenticateShareEntryFixture(t, client, 777)
	if _, err := client.ReportAndroidAuthenticatedShareEntry(context.Background(), &AndroidAuthenticatedShareEntryOptions{AccountUK: 777}); err == nil {
		t.Fatal("ambiguous side effect was called successful")
	}
	saved := client.WebmasterRegistrationSession()
	profile := *saved.AndroidApp
	restored, err := NewAndroidAppClient(profile, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreWebmasterRegistrationSession(saved); err != nil {
		t.Fatal(err)
	}
	restored.updateParams(func(params *accountParams) { params.accountID = 777 })
	if _, err := restored.ReportAndroidAuthenticatedShareEntry(context.Background(), &AndroidAuthenticatedShareEntryOptions{AccountUK: 777}); err == nil || requests != 1 {
		t.Fatal("uncertain restored authenticated entry was silently repeated")
	}
	saved.Cookies, saved.NDUS = "ndus=other-session", "other-session"
	other, _ := NewAndroidAppClient(profile)
	if err := other.RestoreWebmasterRegistrationSession(saved); err == nil {
		t.Fatal("entry journal was moved to a different authenticated session")
	}
}

func TestAuthenticatedShareEntryDurableCheckpointFailureNeverSends(t *testing.T) {
	client := shareEntryFixtureClient(t, shareEntryFixtureDeep, shareRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("request sent after checkpoint persistence failed")
		return nil, nil
	}))
	stageAndDispatchShareEntryFixture(t, client)
	authenticateShareEntryFixture(t, client, 777)
	if _, err := client.ReportAndroidAuthenticatedShareEntry(context.Background(), &AndroidAuthenticatedShareEntryOptions{AccountUK: 777,
		BeforeSend: func(*WebmasterRegistrationSession) error { return errors.New("disk unavailable") }}); err == nil {
		t.Fatal("durable checkpoint failure was hidden")
	}
	if !client.AndroidAttribution().ShareEntry.Authenticated.Report.Attempted {
		t.Fatal("durable uncertainty guard was cleared")
	}
	if _, err := client.ReportAndroidAuthenticatedShareEntry(context.Background(), &AndroidAuthenticatedShareEntryOptions{AccountUK: 777}); err == nil {
		t.Fatal("checkpoint-failed attempt was retried implicitly")
	}
}

func TestFirstLaunchShareEntryExclusionsAndUnsupportedRouter(t *testing.T) {
	for _, test := range []struct {
		name           string
		deep           string
		ownUK          int64
		hive, received bool
		wantSkip       string
	}{
		{"hive", shareEntryFixtureDeep, 777, true, false, "hive"},
		{"received", shareEntryFixtureDeep, 777, false, true, "received_list"},
		{"self", shareEntryFixtureDeep, 123, false, false, "self_share"},
		{"unsupported", "dubox://some_other_route?uk=123", 777, false, false, "unsupported_route"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := shareEntryFixtureClient(t, test.deep, shareRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("excluded route sent a network request")
				return nil, nil
			}))
			stage, err := client.StageAndroidFirstLaunchShareEntry(shareEntryFixtureReferral())
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := client.DispatchAndroidFirstLaunchShareEntry()
			if err != nil {
				t.Fatal(err)
			}
			authenticateShareEntryFixture(t, client, test.ownUK)
			response, err := client.ReportAndroidAuthenticatedShareEntry(context.Background(), &AndroidAuthenticatedShareEntryOptions{
				AccountUK: test.ownUK, FromHive: test.hive, FromReceivedList: test.received})
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "unsupported" {
				if stage.SkipReason != test.wantSkip || stage.Pending || stage.Jumped || resolved != nil || response != nil {
					t.Fatal("unsupported router synthesized a shared screen")
				}
			} else if !response.Skipped || response.SkipReason != test.wantSkip || client.AndroidAttribution().ShareEntry.Authenticated.Report.Attempted {
				t.Fatal("native screen exclusion was not retained without side effects")
			}
			if err := validateAndroidAttributionState(client.AndroidAttribution(), *client.AndroidAppProfile()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFirstLaunchShareEntryRejectsConflictingIdentityAndUnverifiedUK(t *testing.T) {
	for _, mutation := range []func(*WebmasterReferral){
		func(ref *WebmasterReferral) { ref.ShareID++ },
		func(ref *WebmasterReferral) { ref.WebmasterUK++ },
		func(ref *WebmasterReferral) {
			ref.ShareFromSURL = "other"
			ref.ShareURL = "https://terabox.com/s/1other"
		},
		func(ref *WebmasterReferral) { ref.Randsk = "different%2Bkey" },
	} {
		client := shareEntryFixtureClient(t, shareEntryFixtureDeep, nil)
		ref := shareEntryFixtureReferral()
		mutation(ref)
		if _, err := client.StageAndroidFirstLaunchShareEntry(ref); err == nil || client.AndroidAttribution().ShareEntry != nil {
			t.Fatal("conflicting public/returned share metadata was accepted or committed")
		}
	}
	client := shareEntryFixtureClient(t, shareEntryFixtureDeep, shareRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unverified own account UK sent a request")
		return nil, nil
	}))
	stageAndDispatchShareEntryFixture(t, client)
	authenticateShareEntryFixture(t, client, 777)
	if _, err := client.ReportAndroidAuthenticatedShareEntry(context.Background(), &AndroidAuthenticatedShareEntryOptions{AccountUK: 123}); err == nil {
		t.Fatal("share owner substituted for verified own account")
	}
	client.updateParams(func(params *accountParams) { params.accountID = 0 })
	if _, err := client.ReportAndroidAuthenticatedShareEntry(context.Background(), &AndroidAuthenticatedShareEntryOptions{AccountUK: 777}); err == nil {
		t.Fatal("caller-provided UK bypassed CheckLogin verification")
	}
}

func TestFirstLaunchShareEntryBackwardCompatibilityAndSavedBinding(t *testing.T) {
	client := shareEntryFixtureClient(t, shareEntryFixtureDeep, nil)
	// Legacy snapshots without the new field remain restorable unchanged.
	state := client.AndroidAttribution()
	if err := validateAndroidAttributionState(state, *client.AndroidAppProfile()); err != nil {
		t.Fatal(err)
	}
	legacy := shareEntryFixtureReferral()
	legacy.Randsk = ""
	stage, err := client.StageAndroidFirstLaunchShareEntry(legacy)
	if err != nil || stage.SkipReason != "insufficient_metadata" || stage.Pending || stage.Resolved != nil {
		t.Fatal("old incomplete metadata caused a fictional route or invalid registration")
	}
	if err := validateAndroidAttributionState(client.AndroidAttribution(), *client.AndroidAppProfile()); err != nil {
		t.Fatal(err)
	}
	client = shareEntryFixtureClient(t, shareEntryFixtureDeep, nil)
	stageAndDispatchShareEntryFixture(t, client)
	state = client.AndroidAttribution()
	state.Capture.InstallReferrer = attributionText("changed-installation-referrer")
	if err := validateAndroidAttributionState(state, *client.AndroidAppProfile()); err == nil {
		t.Fatal("saved once marker was rebound to another original capture")
	}
	state = client.AndroidAttribution()
	state.ShareEntry.Pending = true
	if err := validateAndroidAttributionState(state, *client.AndroidAppProfile()); err == nil {
		t.Fatal("saved consumed route was made pending again")
	}
	stage, err = client.StageAndroidFirstLaunchShareEntry(shareEntryFixtureReferral())
	if err != nil || stage.Pending || !stage.Jumped {
		t.Fatal("staging reset a previously dispatched once marker")
	}
	if !reflect.DeepEqual(stage.Resolved, client.AndroidAttribution().ShareEntry.Resolved) {
		t.Fatal("repeat stage changed resolved native inputs")
	}
	// The resolved key is one query decode; '+' is not converted into space.
	parsed, _ := url.Parse(shareEntryFixtureDeep)
	if stage.Resolved.Randsk != parsed.Query().Get("randsk") || strings.Contains(stage.Resolved.Randsk, " ") {
		t.Fatal("native route lost the nested literal plus")
	}
}

func TestAuthenticatedShareEntryRejectedOrMalformedResponseIsNotRetried(t *testing.T) {
	for _, body := range []string{`{"errno":-6,"request_id":40}`, `{"errno":0`, `{"data":{}}`} {
		t.Run(body, func(t *testing.T) {
			requests := 0
			transport := shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				return shareJSONResponse(req, body), nil
			})
			client := shareEntryFixtureClient(t, shareEntryFixtureDeep, transport)
			stageAndDispatchShareEntryFixture(t, client)
			authenticateShareEntryFixture(t, client, 777)
			if _, err := client.ReportAndroidAuthenticatedShareEntry(context.Background(), &AndroidAuthenticatedShareEntryOptions{AccountUK: 777}); err == nil {
				t.Fatal("rejected/malformed native callback was treated as success")
			}
			state := client.AndroidAttribution()
			if !state.ShareEntry.Authenticated.Report.Attempted || state.ShareEntry.Authenticated.Report.Succeeded || string(state.ShareEntry.Authenticated.Report.RawBody) != body {
				t.Fatal("failed native callback lost its private wire evidence")
			}
			if err := validateAndroidAttributionState(state, *client.AndroidAppProfile()); err != nil {
				t.Fatal(err)
			}
			saved := client.WebmasterRegistrationSession()
			restored, err := NewAndroidAppClient(*saved.AndroidApp, WithHTTPClient(&http.Client{Transport: transport}))
			if err != nil || restored.RestoreWebmasterRegistrationSession(saved) != nil {
				t.Fatal("failed new-entry journal did not restore")
			}
			restored.updateParams(func(params *accountParams) { params.accountID = 777 })
			if _, err := restored.ReportAndroidAuthenticatedShareEntry(context.Background(), &AndroidAuthenticatedShareEntryOptions{AccountUK: 777}); err == nil || requests != 1 {
				t.Fatal("failed native callback was automatically resent after restore")
			}
		})
	}
}
