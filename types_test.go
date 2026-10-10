package terabox

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"strconv"
	"testing"
)

const stringFileEntryJSON = `{"fs_id":"9007199254740993","path":"/共有.bin","server_filename":"共有.bin","size":"9007199254740995","isdir":"1","md5":"d41d8cd98f00b204e9800998ecf8427e","server_ctime":"1760000001","server_mtime":"1760000002","local_ctime":"1750000003","local_mtime":"1750000004","category":"6"}`

func numericFileEntry() FileEntry {
	return FileEntry{
		FSID: 9007199254740993, Path: "/共有.bin", ServerFilename: "共有.bin",
		Size: 9007199254740995, IsDir: 1, MD5: "d41d8cd98f00b204e9800998ecf8427e",
		ServerCTime: 1760000001, ServerMTime: 1760000002,
		LocalCTime: 1750000003, LocalMTime: 1750000004, Category: 6,
	}
}

func TestFileEntryAcceptsNumericStringsAndNumbers(t *testing.T) {
	want := numericFileEntry()
	numbers, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{stringFileEntryJSON, string(numbers)} {
		var got FileEntry
		if err := json.Unmarshal([]byte(body), &got); err != nil || got != want {
			t.Fatalf("file entry lost integer precision or string fields: got=%+v error=%v", got, err)
		}
	}
	// Unmarshalling compatibility must not change the public field types or
	// their existing numeric representation when marshalled.
	type plain FileEntry
	previous, err := json.Marshal(plain(want))
	if err != nil {
		t.Fatal(err)
	}
	if string(numbers) != string(previous) {
		t.Fatalf("FileEntry JSON changed: got=%s want=%s", numbers, previous)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(numbers, &wire); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"fs_id", "size", "isdir", "server_ctime", "server_mtime", "local_ctime", "local_mtime", "category"} {
		if wire[field][0] == '"' {
			t.Errorf("numeric field %s was marshalled as a string", field)
		}
	}
}

func TestFileEntryNullAndMissingFieldsPreserveExistingValues(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"fs_id":null,"size":null,"isdir":null,"server_ctime":null,"server_mtime":null,"local_ctime":null,"local_mtime":null,"category":null}`} {
		var empty FileEntry
		if err := json.Unmarshal([]byte(body), &empty); err != nil || empty != (FileEntry{}) {
			t.Fatalf("null/missing fields changed zero entry: %+v, %v", empty, err)
		}
		want := numericFileEntry()
		got := want
		if err := json.Unmarshal([]byte(body), &got); err != nil || got != want {
			t.Fatalf("null/missing fields changed existing entry: %+v, %v", got, err)
		}
	}
	want := numericFileEntry()
	got := want
	want.Category = 3
	if err := json.Unmarshal([]byte(`{"category":"3"}`), &got); err != nil || got != want {
		t.Fatalf("partial string update changed unrelated fields: %+v, %v", got, err)
	}
}

func TestFileEntryRejectsInvalidNumericFields(t *testing.T) {
	for _, field := range []string{"fs_id", "size", "isdir", "server_ctime", "server_mtime", "local_ctime", "local_mtime", "category"} {
		t.Run(field, func(t *testing.T) {
			for _, value := range []string{`""`, `"invalid"`, `"1.5"`, `"1e3"`, `1.5`, `true`, `[]`, `{}`, `"9223372036854775808"`, `"-9223372036854775809"`} {
				want := numericFileEntry()
				got := want
				body := fmt.Sprintf(`{"path":"/changed","%s":%s}`, field, value)
				if err := json.Unmarshal([]byte(body), &got); err == nil {
					t.Errorf("invalid %s accepted: %s", field, value)
				} else if got != want {
					t.Errorf("invalid %s changed receiver: %+v", field, got)
				}
			}
		})
	}
}

func TestFileEntryRejectsNativeIntOverflow(t *testing.T) {
	overflow := new(big.Int).Lsh(big.NewInt(1), uint(strconv.IntSize-1)).String()
	for _, field := range []string{"isdir", "category"} {
		var entry FileEntry
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"%s":"%s"}`, field, overflow)), &entry); err == nil {
			t.Errorf("%s accepted a value outside the %d-bit int range", field, strconv.IntSize)
		}
	}
}

func TestGetShareListDecodesStringFileEntryFields(t *testing.T) {
	c := NewClient("", WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/share/list" {
			t.Fatalf("unexpected public-list request: %s %s", req.Method, req.URL.Path)
		}
		return shareJSONResponse(req, `{"errno":0,"share_id":"858486528090","uk_str":"9007199254740997","list":[`+stringFileEntryJSON+`]}`), nil
	})}))
	response, err := c.GetShareList(context.Background(), "shared-key", 1)
	if err != nil {
		t.Fatal(err)
	}
	if response.ShareID != 858486528090 || response.UK != 9007199254740997 || !reflect.DeepEqual(response.List, []FileEntry{numericFileEntry()}) {
		t.Fatalf("public share list lost string-number values: %+v", response)
	}
}
