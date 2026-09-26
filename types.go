package terabox

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Error describes a failed TeraBox API call.
type Error struct {
	Op  string
	Err error
}

func (e *Error) Error() string { return "terabox: " + e.Op + ": " + e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

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
