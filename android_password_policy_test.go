package terabox

import (
	"encoding/json"
	"os"
	"testing"
)

func TestAndroidPasswordPolicyMatchesActualAPKValidator(t *testing.T) {
	data, err := os.ReadFile("testdata/android_password_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			Valid    bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 10 {
		t.Fatal("APK replay must cover kinds, charset and length boundaries")
	}
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			if got := androidPasswordValid(item.Password); got != item.Valid {
				t.Fatalf("password validity=%t, APK returned %t", got, item.Valid)
			}
		})
	}
}
