package terabox

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func generatedShareLinkInput() AndroidShareLinkReferrerInput {
	return AndroidShareLinkReferrerInput{PageURL: "https://www.terabox.com/wap/share/filelist?surl=fixture-key",
		DeepLink: "dubox://share_detail?shareid=42&uk=7&randsk=synthetic%2B%3D&surl=fixture-key", Agency: attributionText("h1__0_G2")}
}

func referrerNonceReader(n uint32) *bytes.Reader {
	var data [4]byte
	binary.BigEndian.PutUint32(data[:], n)
	return bytes.NewReader(data[:])
}

func TestAndroidShareLinkReferrerMatchesOriginalJavaScriptOracle(t *testing.T) {
	data, err := os.ReadFile("testdata/android_share_link_referrer_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SourceSHA256 string `json:"source_sha256"`
		Vectors      []struct {
			Name             string
			Input            AndroidShareLinkReferrerInput
			NowMS            int64 `json:"now_ms"`
			Nonce            uint32
			ExpectedReferrer string `json:"expected_referrer"`
			ExpectedLinkID   string `json:"expected_link_id"`
			ExpectedStoreURL string `json:"expected_store_url"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 6 || fixture.SourceSHA256 != "d5940789b440515e21452c0ebf1bbca5a05dc35a9cb30e7c0a7dd951aee1cfea" {
		t.Fatal("original share-page JavaScript oracle provenance is missing")
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			original, _ := json.Marshal(v.Input)
			got, err := generateAndroidShareLinkReferrer(v.Input, time.UnixMilli(v.NowMS), referrerNonceReader(v.Nonce))
			if err != nil {
				t.Fatal(err)
			}
			if got.InstallReferrer != v.ExpectedReferrer || got.TeraLinkID != v.ExpectedLinkID || got.GeneratedAtMS != v.NowMS {
				t.Fatal("generated result differs from the unchanged JavaScript producer")
			}
			store := "https://play.google.com/store/apps/details?id=com.dubox.drive&referrer=" + androidEncodeURIComponent(got.InstallReferrer)
			if store != v.ExpectedStoreURL {
				t.Fatal("the original Play redirect's encoding boundary changed")
			}
			after, _ := json.Marshal(v.Input)
			if !bytes.Equal(original, after) {
				t.Fatal("referrer generation mutated caller inputs")
			}
		})
	}
}

func TestAndroidShareLinkReferrerRejectsConflictingAndInvalidInputs(t *testing.T) {
	for name, mutate := range map[string]func(*AndroidShareLinkReferrerInput){
		"foreign_host": func(in *AndroidShareLinkReferrerInput) {
			in.PageURL = "https://terabox.com.example/wap/share/filelist?surl=fixture-key"
		},
		"invalid_dns": func(in *AndroidShareLinkReferrerInput) {
			in.PageURL = "https://bad..terabox.com/wap/share/filelist?surl=fixture-key"
		},
		"wrong_page_share": func(in *AndroidShareLinkReferrerInput) {
			in.PageURL = "https://terabox.com/wap/share/filelist?surl=other-share"
		},
		"duplicate_surl": func(in *AndroidShareLinkReferrerInput) { in.PageURL += "&surl=fixture-key" },
		"owner_conflict": func(in *AndroidShareLinkReferrerInput) { in.PageURL += "&uk=8" },
		"bad_scheme": func(in *AndroidShareLinkReferrerInput) {
			in.DeepLink = strings.Replace(in.DeepLink, "dubox:", "https:", 1)
		},
		"missing_owner":   func(in *AndroidShareLinkReferrerInput) { in.DeepLink = strings.Replace(in.DeepLink, "uk=7&", "", 1) },
		"duplicate_owner": func(in *AndroidShareLinkReferrerInput) { in.DeepLink += "&uk=7" },
		"zero_id": func(in *AndroidShareLinkReferrerInput) {
			in.DeepLink = strings.Replace(in.DeepLink, "shareid=42", "shareid=0", 1)
		},
		"malformed_query":      func(in *AndroidShareLinkReferrerInput) { in.DeepLink += "&extra=%zz" },
		"op_source_unobserved": func(in *AndroidShareLinkReferrerInput) { in.OpSource = attributionText("") },
		"op_source_conflict": func(in *AndroidShareLinkReferrerInput) {
			in.PageURL += "&op_source=actual"
			in.OpSource = attributionText("other")
		},
		"generated_id_conflict": func(in *AndroidShareLinkReferrerInput) { in.PageURL += "&tera_link_id=old" },
		"invalid_utf8":          func(in *AndroidShareLinkReferrerInput) { in.Agency = attributionText(string([]byte{0xff})) },
		"negative_type":         func(in *AndroidShareLinkReferrerInput) { in.TeraLinkType = -1 },
		"unobserved_type":       func(in *AndroidShareLinkReferrerInput) { in.TeraLinkType = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			input := generatedShareLinkInput()
			mutate(&input)
			if got, err := GenerateAndroidShareLinkReferrer(input); err == nil || got.InstallReferrer != "" || got.TeraLinkID != "" {
				t.Fatal("invalid generator input returned a referrer")
			}
		})
	}
	if _, err := generateAndroidShareLinkReferrer(generatedShareLinkInput(), time.UnixMilli(1700000000000), bytes.NewReader(nil)); err == nil {
		t.Fatal("entropy failure was ignored")
	}
	if _, err := generateAndroidShareLinkReferrer(generatedShareLinkInput(), time.UnixMilli(-1), referrerNonceReader(1)); err == nil {
		t.Fatal("invalid generation time was accepted")
	}
}

func TestAndroidShareLinkReferrerConcurrentIndependentIdentifiers(t *testing.T) {
	const count = 128
	input := generatedShareLinkInput()
	results := make(chan AndroidGeneratedShareLinkReferrer, count)
	errors := make(chan error, count)
	var workers sync.WaitGroup
	for i := 0; i < count; i++ {
		workers.Add(1)
		go func(n uint32) {
			defer workers.Done()
			got, err := generateAndroidShareLinkReferrer(input, time.UnixMilli(1700000000000), referrerNonceReader(n))
			if err != nil {
				errors <- err
				return
			}
			results <- got
		}(uint32(i))
	}
	workers.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for got := range results {
		if seen[got.TeraLinkID] || got.GeneratedAtMS != 1700000000000 {
			t.Fatal("concurrent generators shared an identifier or timestamp")
		}
		seen[got.TeraLinkID] = true
		plain, err := url.PathUnescape(got.InstallReferrer)
		if err != nil || !strings.Contains(plain, "tera_link_id="+got.TeraLinkID+"&tera_link_type=1") {
			t.Fatal("identifier is not bound to its generated referrer")
		}
	}
	if len(seen) != count || !reflect.DeepEqual(input, generatedShareLinkInput()) {
		t.Fatal("parallel generation lost results or mutated the shared input")
	}
}
