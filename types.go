package terabox

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Int64ish is an int64 that accepts either a JSON number or a JSON string
// (the server is inconsistent: e.g. /api/download returns dlink[].fs_id
// as a string while listings return numbers).
type Int64ish int64

// UnmarshalJSON accepts a JSON number or numeric string.
func (v *Int64ish) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		return nil
	}
	s = strings.Trim(s, `"`)
	if s == "" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*v = Int64ish(n)
	return nil
}

// Error describes a failed TeraBox API call.
type Error struct {
	Op  string
	Err error
}

func (e *Error) Error() string { return "terabox: " + e.Op + ": " + e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

// APIError preserves a server result code when a multi-request operation
// cannot complete. Single-request methods still expose codes in responses.
type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("API error %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("API error %d", e.Code)
}

func wrapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Op: op, Err: err}
}

// errnoResp is embedded by response types that report a TeraBox `errno` code.
type errnoResp struct {
	Errno int `json:"errno"`
}

// requestIDs normalizes a response field that arrives either as a single
// number or as an array of numbers.
type requestIDs []int64

func (r *requestIDs) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return nil
	}
	if s[0] == '[' {
		return json.Unmarshal(data, (*[]int64)(r))
	}
	var single int64
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*r = requestIDs{single}
	return nil
}

// FileEntry is a single file or directory in a remote listing
// (api/list, api/search, api/categorylist, api/recycle/list).
type FileEntry struct {
	FSID           int64  `json:"fs_id"`
	Path           string `json:"path"`
	ServerFilename string `json:"server_filename"`
	Size           int64  `json:"size"`
	IsDir          int    `json:"isdir"`
	MD5            string `json:"md5"`
	ServerCTime    int64  `json:"server_ctime"`
	ServerMTime    int64  `json:"server_mtime"`
	LocalCTime     int64  `json:"local_ctime"`
	LocalMTime     int64  `json:"local_mtime"`
	Category       int    `json:"category"`
}

type fileEntryInteger Int64ish

func (v *fileEntryInteger) UnmarshalJSON(b []byte) error {
	if strings.TrimSpace(string(b)) == `""` {
		return fmt.Errorf("file entry integer is empty")
	}
	value := Int64ish(*v)
	if err := value.UnmarshalJSON(b); err != nil {
		return err
	}
	*v = fileEntryInteger(value)
	return nil
}

// UnmarshalJSON accepts the numbers or numeric strings used by public-share
// listings while preserving FileEntry's existing integer fields and JSON output.
func (f *FileEntry) UnmarshalJSON(b []byte) error {
	type plain FileEntry
	wire := struct {
		plain
		FSID        fileEntryInteger `json:"fs_id"`
		Size        fileEntryInteger `json:"size"`
		IsDir       fileEntryInteger `json:"isdir"`
		ServerCTime fileEntryInteger `json:"server_ctime"`
		ServerMTime fileEntryInteger `json:"server_mtime"`
		LocalCTime  fileEntryInteger `json:"local_ctime"`
		LocalMTime  fileEntryInteger `json:"local_mtime"`
		Category    fileEntryInteger `json:"category"`
	}{
		plain: plain(*f), FSID: fileEntryInteger(f.FSID), Size: fileEntryInteger(f.Size),
		IsDir: fileEntryInteger(f.IsDir), Category: fileEntryInteger(f.Category),
		ServerCTime: fileEntryInteger(f.ServerCTime), ServerMTime: fileEntryInteger(f.ServerMTime),
		LocalCTime: fileEntryInteger(f.LocalCTime), LocalMTime: fileEntryInteger(f.LocalMTime),
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	if int64(int(wire.IsDir)) != int64(wire.IsDir) {
		return fmt.Errorf("file entry isdir overflows int")
	}
	if int64(int(wire.Category)) != int64(wire.Category) {
		return fmt.Errorf("file entry category overflows int")
	}
	result := FileEntry(wire.plain)
	result.FSID, result.Size = int64(wire.FSID), int64(wire.Size)
	result.IsDir, result.Category = int(wire.IsDir), int(wire.Category)
	result.ServerCTime, result.ServerMTime = int64(wire.ServerCTime), int64(wire.ServerMTime)
	result.LocalCTime, result.LocalMTime = int64(wire.LocalCTime), int64(wire.LocalMTime)
	*f = result
	return nil
}

// ListResponse is the response of directory/search/category/recycle listings.
type ListResponse struct {
	errnoResp
	RequestID json.Number `json:"request_id,omitempty"`
	GUID      int64       `json:"guid,omitempty"`
	List      []FileEntry `json:"list"`
}

// httpStatusError is returned when the API answers with an unexpected status.
type httpStatusError struct{ StatusCode int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP error! Status: %d", e.StatusCode)
}
