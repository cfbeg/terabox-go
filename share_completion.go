package terabox

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// appendAndroidLegacyNDUSToken reproduces lj._.c for native POST form data.
// The authenticated legacy GET transport adds this NDUS hash to the URL.
func (c *Client) appendAndroidLegacyNDUSToken(form *formValues) {
	for _, key := range form.keys {
		if key == "bdstoken" {
			return
		}
	}
	if ndus, ok := c.CookieValue("ndus"); ok && ndus != "" {
		form.Append("bdstoken", fmt.Sprintf("%x", md5.Sum([]byte(ndus))))
	}
}

// ShareTransferTaskFile preserves FileManagerTaskListInfoResponse's fields.
type ShareTransferTaskFile struct {
	From      string          `json:"from,omitempty"`
	To        string          `json:"to,omitempty"`
	Path      string          `json:"path,omitempty"`
	ErrorCode int             `json:"error_code"`
	ToFSID    Int64ish        `json:"to_fs_id,omitempty"`
	FromMeta  json.RawMessage `json:"from_meta,omitempty"`
	ToMeta    json.RawMessage `json:"to_meta,omitempty"`
}

// ShareTransferTaskResponse is the native /api/taskquery result. Errno zero
// alone is insufficient: running and pending tasks have not completed.
type ShareTransferTaskResponse struct {
	RawBody   []byte                  `json:"raw_body,omitempty"`
	Errno     int                     `json:"errno"`
	ErrMsg    string                  `json:"errmsg,omitempty"`
	RequestID json.Number             `json:"request_id,omitempty"`
	Status    string                  `json:"status"`
	Progress  int                     `json:"progress,omitempty"`
	Total     int                     `json:"total,omitempty"`
	TaskErrno int                     `json:"task_errno,omitempty"`
	List      []ShareTransferTaskFile `json:"list,omitempty"`
	Raw       json.RawMessage         `json:"raw,omitempty"`
}

func (r *ShareTransferTaskResponse) UnmarshalJSON(data []byte) error {
	r.Raw = append(json.RawMessage(nil), data...)
	type plain ShareTransferTaskResponse
	var wire struct {
		plain
		Errno *int `json:"errno"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Errno == nil {
		return errors.New("share transfer task response is missing errno")
	}
	*r = ShareTransferTaskResponse(wire.plain)
	r.Raw, r.Errno = append(json.RawMessage(nil), data...), *wire.Errno
	if r.Errno != 0 {
		return nil
	}
	switch r.Status {
	case "running", "pending", "failed":
	case "success":
		if r.List == nil {
			return errors.New("successful share transfer task response is missing result list")
		}
	default:
		return errors.New("share transfer task response has an unknown or absent status")
	}
	return nil
}

// Completed requires the native success state and successful per-file results.
// Callers should additionally verify the expected files through ListFiles.
func (r *ShareTransferTaskResponse) Completed() bool {
	if r == nil || r.Errno != 0 || r.TaskErrno != 0 || r.Status != "success" || len(r.List) == 0 {
		return false
	}
	for _, file := range r.List {
		if file.ErrorCode != 0 {
			return false
		}
	}
	return true
}

// QueryShareTransferTask makes one status request matching the ordinary native
// save callback: b0.b -> service.___.h -> ln.__.u with all optional retry inputs
// null. JSONObject.put(null) produces filelist=[{}]. It does not retry a save.
func (c *Client) QueryShareTransferTask(ctx context.Context, taskID int64) (*ShareTransferTaskResponse, error) {
	const op = "queryShareTransferTask"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	if taskID <= 0 {
		return nil, wrapErr(op, errors.New("positive share transfer task ID required"))
	}
	if ndus, _ := c.CookieValue("ndus"); ndus == "" {
		return nil, wrapErr(op, errors.New("an authenticated ndus is required to query a share transfer task"))
	}
	form := newForm()
	form.Append("filelist", "[{}]")
	c.appendAndroidLegacyNDUSToken(form)
	var response ShareTransferTaskResponse
	err := c.doJSON(ctx, op, &requestOpts{method: http.MethodPost, path: "/api/taskquery",
		query: url.Values{"taskid": {strconv.FormatInt(taskID, 10)}}, form: form, legacyNative: true}, &response)
	return &response, err
}

// FileListOptions supplies the native directory listing parameters. Start is
// zero based; SDK defaults are Limit=100 and Order=name.
type FileListOptions struct {
	Start       int
	Limit       int
	Order       string
	Descending  bool
	Preset      bool
	SecretToken string
}

// FileListResponse is the authenticated native /api/list listing.
type FileListResponse struct {
	RawBody   []byte          `json:"raw_body,omitempty"`
	Errno     int             `json:"errno"`
	ErrMsg    string          `json:"errmsg,omitempty"`
	RequestID json.Number     `json:"request_id,omitempty"`
	List      []FileEntry     `json:"list"`
	Raw       json.RawMessage `json:"raw,omitempty"`
}

func (r *FileListResponse) UnmarshalJSON(data []byte) error {
	r.Raw = append(json.RawMessage(nil), data...)
	type plain FileListResponse
	var wire struct {
		plain
		Errno *int `json:"errno"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Errno == nil {
		return errors.New("file list response is missing errno")
	}
	*r = FileListResponse(wire.plain)
	r.Raw, r.Errno = append(json.RawMessage(nil), data...), *wire.Errno
	if r.Errno == 0 && r.List == nil {
		return errors.New("successful file list response is missing list")
	}
	return nil
}

// ListFiles reads one directory page using ln.__.p's legacy native GET path.
// It checks existing NDUS directly and never bootstraps a browser or logs in.
func (c *Client) ListFiles(ctx context.Context, directory string, opts *FileListOptions) (*FileListResponse, error) {
	const op = "listFiles"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	if _, err := validateShareTransfer([]int64{1}, directory, nil); err != nil {
		return nil, wrapErr(op, err)
	}
	if ndus, _ := c.CookieValue("ndus"); ndus == "" {
		return nil, wrapErr(op, errors.New("an authenticated ndus is required for native file listing"))
	}
	settings := FileListOptions{Limit: 100, Order: "name"}
	if opts != nil {
		settings = *opts
		if settings.Limit == 0 {
			settings.Limit = 100
		}
		if settings.Order == "" {
			settings.Order = "name"
		}
	}
	if settings.Start < 0 || settings.Limit <= 0 || settings.Limit > 1000 || shareURLHasControl(settings.Order) || shareURLHasControl(settings.SecretToken) {
		return nil, wrapErr(op, errors.New("invalid native file listing parameters"))
	}
	query := url.Values{"dir": {directory}, "start": {strconv.Itoa(settings.Start)}, "limit": {strconv.Itoa(settings.Limit)}, "order": {settings.Order}, "preset": {"0"}}
	if settings.Preset {
		query.Set("preset", "1")
	}
	if settings.Descending {
		query.Set("desc", "")
	}
	if settings.SecretToken != "" {
		query.Set("secret_token", settings.SecretToken)
	}
	var response FileListResponse
	err := c.doJSON(ctx, op, &requestOpts{method: http.MethodGet, path: "/api/list", query: query, legacyNative: true}, &response)
	return &response, err
}
