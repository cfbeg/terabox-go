package terabox

import "testing"

func TestSignDownloadKnownVector(t *testing.T) {
	// RC4("Key", "Plaintext") = bbf316e8d940af0ad3.
	if got := SignDownload("Key", "Plaintext"); got != "u/MW6NlArwrT" {
		t.Fatalf("token=%q, want known RC4 vector", got)
	}
}

func TestSignDownloadEmptyKey(t *testing.T) {
	for _, data := range []string{"", "nonempty"} {
		if got := SignDownload("", data); got != "" {
			t.Fatalf("SignDownload with empty key returned %q", got)
		}
	}
}
