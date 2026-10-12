package terabox

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAndroidAttributionProvenanceValidationAndLegacyRestore(t *testing.T) {
	for _, test := range []struct {
		name, provenance  string
		install, referrer bool
		wantError         bool
	}{
		{"legacy_unavailable", "", true, false, false},
		{"legacy_value", "", true, true, false},
		{"observed_empty", AndroidAttributionProvenancePlayObserved, true, true, false},
		{"generated_empty", AndroidAttributionProvenanceShareLinkGenerated, true, true, false},
		{"observed_missing_value", AndroidAttributionProvenancePlayObserved, true, false, true},
		{"generated_missing_value", AndroidAttributionProvenanceShareLinkGenerated, true, false, true},
		{"generated_missing_install", AndroidAttributionProvenanceShareLinkGenerated, false, true, true},
		{"unknown", "unsupported-private-marker", true, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := androidFixtureProfile()
			original := copyAndroidAppProfile(profile)
			capture := attributionFixtureCapture(profile)
			capture.Provenance = test.provenance
			if !test.install {
				capture.Install = nil
			}
			if !test.referrer {
				capture.InstallReferrer = nil
			} else {
				capture.InstallReferrer = attributionText("")
			}
			client, err := NewAndroidAppClient(profile)
			if err != nil {
				t.Fatal(err)
			}
			err = client.SetAndroidAttributionCapture(capture)
			if test.wantError {
				if err == nil || client.AndroidAttribution() != nil {
					t.Fatal("invalid provenance was accepted or mutated state")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(client.WebmasterRegistrationSession())
			if err != nil {
				t.Fatal(err)
			}
			var saved WebmasterRegistrationSession
			if err := json.Unmarshal(encoded, &saved); err != nil {
				t.Fatal(err)
			}
			restored, err := NewAndroidAppClient(*saved.AndroidApp)
			if err != nil {
				t.Fatal(err)
			}
			if err := restored.RestoreWebmasterRegistrationSession(&saved); err != nil {
				t.Fatal(err)
			}
			got := restored.AndroidAttribution()
			if got.Capture.Provenance != test.provenance || !reflect.DeepEqual(got.Capture.InstallReferrer, capture.InstallReferrer) || !reflect.DeepEqual(profile, original) {
				t.Fatal("roundtrip relabeled provenance, changed its referrer or mutated the caller's profile")
			}
		})
	}
}
