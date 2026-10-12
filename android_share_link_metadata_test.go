package terabox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestAndroidShareLinkResolverPreservesNativeMetadataAndSnapshot(t *testing.T) {
	requests := 0
	client := appReferralClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Path != "/api/shorturlinfo" {
			t.Fatal("resolver metadata changed native request path")
		}
		return shareJSONResponse(req, `{"errno":0,"shareid":"123","uk":"456","ctime":"1700000000","expiredtype":0,"fcount":1,"randsk":"synthetic%2Bkey%3D","list":[]}`), nil
	}))
	profile := client.AndroidAppProfile()
	ref, err := client.PrepareWebmasterReferral(context.Background(), referralTestURL)
	if err != nil {
		t.Fatal(err)
	}
	if ref.ShareCreateTime == nil || *ref.ShareCreateTime != 1700000000 || ref.ShareExpiredTime == nil || *ref.ShareExpiredTime != 0 || ref.ShareFileCount == nil || *ref.ShareFileCount != 1 {
		t.Fatal("native metadata lost its optional presence or value")
	}
	input, err := client.ResolveAndroidShareLinkReferrerInput(context.Background(), referralTestURL)
	if err != nil {
		t.Fatal(err)
	}
	wantDeep := "dubox://share_detail?shareid=123&uk=456&share_create_time=1700000000&randsk=synthetic%2Bkey%3D&share_expired_time=0&source=af_link&share_file_count=1&surl=Ab_c-key"
	if input.PageURL != "https://www.terabox.com/wap/share/filelist?surl=Ab_c-key" || input.DeepLink != wantDeep || input.Agency == nil || *input.Agency != "h1__0_G2" || requests != 1 {
		t.Fatal("resolver changed the e259 metadata order, encoded randsk again or made another request")
	}
	if _, err := GenerateAndroidShareLinkReferrer(input); err != nil {
		t.Fatal(err)
	}
	deep, _ := url.Parse(input.DeepLink)
	if deep.Query().Get("randsk") != "synthetic+key=" || len(deep.Query()["surl"]) != 1 {
		t.Fatal("metadata access key or page query suffix was changed")
	}
	*ref.ShareCreateTime, *ref.ShareExpiredTime, *ref.ShareFileCount = 0, 9, 8
	ref.Randsk = "mutated"
	if !reflect.DeepEqual(profile, client.AndroidAppProfile()) {
		t.Fatal("resolver mutated Android profile")
	}
	saved := client.WebmasterRegistrationSession()
	encoded, _ := json.Marshal(saved)
	var roundtrip WebmasterRegistrationSession
	if err := json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	restored, err := NewAndroidAppClient(*roundtrip.AndroidApp)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreWebmasterRegistrationSession(&roundtrip); err != nil {
		t.Fatal(err)
	}
	*roundtrip.Referral.ShareCreateTime = 1
	got, err := restored.ResolveAndroidShareLinkReferrerInput(context.Background(), referralTestURL)
	if err != nil || got.DeepLink != wantDeep {
		t.Fatal("saved optional metadata was omitted, aliased or reinterpreted as expiry timestamp")
	}
	if _, err := restored.ResolveAndroidShareLinkReferrerInput(context.Background(), "https://terabox.com/s/1Different"); err == nil {
		t.Fatal("resolver accepted another share's metadata")
	}
}

func TestAndroidShareLinkMetadataMissingAndMalformedInputs(t *testing.T) {
	for _, response := range []string{
		`{"errno":0,"shareid":123,"uk":456,"list":[]}`,
		`{"errno":0,"shareid":123,"uk":456,"ctime":1700000000,"fcount":1,"randsk":"synthetic%3D","list":[]}`,
		`{"errno":0,"shareid":123,"uk":456,"ctime":1700000000,"expiredtype":0,"fcount":-1,"randsk":"synthetic%3D","list":[]}`,
	} {
		client := appReferralClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) { return shareJSONResponse(req, response), nil }))
		_, prepareErr := client.PrepareWebmasterReferral(context.Background(), referralTestURL)
		_, resolveErr := client.ResolveAndroidShareLinkReferrerInput(context.Background(), referralTestURL)
		if prepareErr == nil && resolveErr == nil {
			t.Fatal("missing or invalid metadata was fabricated")
		}
	}
	client := appReferralClient(t, nil)
	client.referral = &WebmasterReferral{ShareURL: referralTestURL, ShareFromSURL: "Ab_c-key", ShareID: 123, WebmasterUK: 456, ShareFileCount: attributionTime(-1)}
	saved := client.WebmasterRegistrationSession()
	fresh, _ := NewAndroidAppClient(*saved.AndroidApp)
	if err := fresh.RestoreWebmasterRegistrationSession(saved); err == nil || fresh.WebmasterReferral() != nil {
		t.Fatal("invalid optional metadata was restored or mutated the target")
	}
	var info ShareInfoResponse
	if err := json.Unmarshal([]byte(`{"errno":0,"shareid":123,"uk":456,"ctime":null,"expiredtype":0,"fcount":"1"}`), &info); err != nil || info.CTime != nil || info.ExpiredType == nil || *info.ExpiredType != 0 || info.FCount == nil || *info.FCount != 1 {
		t.Fatal("optional native metadata presence decoding is incorrect")
	}
	if strings.Contains(string(info.Raw), "synthetic") {
		t.Fatal("unexpected metadata mutation")
	}
}
