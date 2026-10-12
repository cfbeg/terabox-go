package terabox

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestShareViewJournalRoundTripPreservesOriginalWireAndHTTP(t *testing.T) {
	body := []byte(`{"errno":0,"request_id":9007199254740993,"data":{"list":[],"extra":"kept"},"future":"preserved"}`)
	response := ShareViewReportResponse{HTTPStatus: 200}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	response.RawBody = append([]byte(nil), body...)
	for repeat := 0; repeat < 4; repeat++ {
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		var restored ShareViewReportResponse
		if err = json.Unmarshal(encoded, &restored); err != nil {
			t.Fatal(err)
		}
		if restored.HTTPStatus != 200 || !reflect.DeepEqual(restored.RawBody, body) || string(restored.Raw) != string(body) || restored.RequestID.String() != "9007199254740993" {
			t.Fatal("journal restore dropped HTTP/wire metadata or recursively wrapped the original response")
		}
		response = restored
	}
	response.RawBody = nil // Prior journals saved only valid Raw, not raw bytes.
	encoded, _ := json.Marshal(response)
	var oldRestored ShareViewReportResponse
	if err := json.Unmarshal(encoded, &oldRestored); err != nil || string(oldRestored.Raw) != string(body) {
		t.Fatal("legacy raw-only journal recursively wrapped wire metadata", err)
	}
}

func TestShareViewSkippedJournalValidatesKnownLocalReason(t *testing.T) {
	for _, reason := range []string{"hive", "received_list", "self_share"} {
		response := ShareViewReportResponse{Skipped: true, SkipReason: reason}
		encoded, _ := json.Marshal(response)
		var restored ShareViewReportResponse
		if err := json.Unmarshal(encoded, &restored); err != nil || !restored.Skipped || restored.SkipReason != reason || len(restored.Raw) != 0 {
			t.Fatal("valid local skipped report could not restore", err)
		}
	}
	for _, body := range []string{
		`{"errno":0,"skipped":true,"skip_reason":"invented"}`,
		`{"errno":0,"skipped":true,"skip_reason":"hive","http_status":200}`,
		`{"errno":1,"skipped":true,"skip_reason":"hive"}`,
		`{"errno":0,"skipped":true,"skip_reason":"hive","data":{"list":[]}}`,
		`{"errno":0,"skip_reason":"hive","data":{"list":[]}}`,
	} {
		var response ShareViewReportResponse
		if json.Unmarshal([]byte(body), &response) == nil {
			t.Fatal("inconsistent saved skip state was accepted")
		}
	}
	var live ShareViewReportResponse
	live.HTTPStatus = 200
	if err := json.Unmarshal([]byte(`{"errno":0,"skipped":true,"skip_reason":"hive"}`), &live); err != nil || live.Skipped || live.SkipReason != "" || live.HTTPStatus != 200 {
		t.Fatal("actual explicit API acknowledgement was rejected or inherited a server-controlled local skip flag", err)
	}
}

func TestShareViewSavedWireConsistencyPreservesLargeNumbers(t *testing.T) {
	response := ShareViewReportResponse{Errno: 0, HTTPStatus: 200, Data: json.RawMessage(`{"list":[],"id":9007199254740993}`), RawBody: []byte(`{"errno":0,"data":{"list":[],"id":9007199254740992}}`)}
	encoded, _ := json.Marshal(response)
	var restored ShareViewReportResponse
	if json.Unmarshal(encoded, &restored) == nil {
		t.Fatal("saved data mismatched its actual raw response beyond float precision")
	}
}
