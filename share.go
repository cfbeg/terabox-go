package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ShareInfoResponse is metadata returned by /api/shorturlinfo or /share/list.
// ShareID normalizes the shareid and share_id fields. UK accepts the numeric
// uk or uk_str field; UKString preserves uk_str when it is supplied.
type ShareInfoResponse struct {
	Errno     int         `json:"errno"`
	ErrMsg    string      `json:"errmsg,omitempty"`
	RequestID json.Number `json:"request_id,omitempty"`
	ShareID   Int64ish    `json:"shareid"`
	UK        Int64ish    `json:"uk"`
	UKString  string      `json:"uk_str,omitempty"`
	List      []FileEntry `json:"list"`
}

// UnmarshalJSON accepts both metadata endpoints' identifier fields and
// requires an explicit errno so an unrelated JSON body is not a success.
func (r *ShareInfoResponse) UnmarshalJSON(b []byte) error {
	type plain ShareInfoResponse
	var wire struct {
		plain
		Errno   *int     `json:"errno"`
		ShareID Int64ish `json:"share_id"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	if wire.Errno == nil {
		return errors.New("share response is missing errno")
	}
	result := ShareInfoResponse(wire.plain)
	result.Errno = *wire.Errno
	if result.ShareID == 0 {
		result.ShareID = wire.ShareID
	}
	if result.UK == 0 && result.UKString != "" {
		uk, err := strconv.ParseInt(result.UKString, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid share owner uk_str: %w", err)
		}
		result.UK = Int64ish(uk)
	}
	*r = result
	return nil
}

// ShareTransferResponse is the /share/transfer result. An asynchronous
// transfer may return TaskID; Extra preserves optional server metadata.
// Errno zero acknowledges the request, which can still require task polling.
type ShareTransferResponse struct {
	Errno     int             `json:"errno"`
	ErrMsg    string          `json:"errmsg,omitempty"`
	RequestID json.Number     `json:"request_id,omitempty"`
	TaskID    Int64ish        `json:"task_id,omitempty"`
	Extra     json.RawMessage `json:"extra,omitempty"`
}

func (r *ShareTransferResponse) UnmarshalJSON(b []byte) error {
	type plain ShareTransferResponse
	var wire struct {
		plain
		Errno *int `json:"errno"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	if wire.Errno == nil {
		return errors.New("share transfer response is missing errno")
	}
	result := ShareTransferResponse(wire.plain)
	result.Errno = *wire.Errno
	*r = result
	return nil
}

// ShareTransferOptions controls duplicate handling during TransferShare.
type ShareTransferOptions struct {
	// OnDup is "newcopy" (default). Other values are rejected because they
	// have not been verified for the public share transfer endpoint.
	OnDup string
}

func (c *Client) shareQuery() url.Values {
	query := c.appQuery()
	data := c.dataSnapshot()
	if data.jsToken != "" {
		query.Set("jsToken", data.jsToken)
	}
	query.Set("dp-logid", data.logID)
	return query
}

// GetShareInfo retrieves public share metadata. surl is an already normalized
// key returned by ParseShareURL; the endpoint requires its extra leading 1.
// Verification requirements are returned as a nonzero response Errno.
func (c *Client) GetShareInfo(ctx context.Context, surl string) (*ShareInfoResponse, error) {
	const op = "getShareInfo"
	if err := validateShareKey(surl); err != nil {
		return nil, wrapErr(op, err)
	}
	query := c.shareQuery()
	query.Set("shorturl", "1"+surl)
	query.Set("root", "1")
	query.Set("scene", "")
	return c.getShareMetadata(ctx, op, "/api/shorturlinfo", query, false)
}

// GetShareList retrieves one page of root files and the share's identifiers.
// surl is already normalized; unlike shorturlinfo, share/list receives it
// without an added 1. A nonpositive page uses page 1. The page size is 20000.
func (c *Client) GetShareList(ctx context.Context, surl string, page int) (*ShareInfoResponse, error) {
	const op = "getShareList"
	if err := validateShareKey(surl); err != nil {
		return nil, wrapErr(op, err)
	}
	if page <= 0 {
		page = 1
	}
	query := c.shareQuery()
	query.Set("shorturl", surl)
	query.Set("root", "1")
	query.Set("page", strconv.Itoa(page))
	query.Set("num", "20000")
	query.Set("by", "name")
	query.Set("order", "asc")
	query.Set("scene", "")
	return c.getShareMetadata(ctx, op, "/share/list", query, true)
}

func (c *Client) getShareMetadata(ctx context.Context, op, endpoint string, query url.Values, requireList bool) (*ShareInfoResponse, error) {
	// Anonymous metadata requests with web=1 receive a verification response
	// instead of the public share result. Authenticated reads retain the flag.
	if ndus, _ := c.CookieValue("ndus"); ndus == "" {
		query.Del("web")
	}
	var response ShareInfoResponse
	var pendingCookies []*http.Cookie
	headers := c.registrationHeaders()
	headers["Accept"] = "application/json, text/plain, */*"
	headers["X-Requested-With"] = "XMLHttpRequest"
	err := c.doJSON(ctx, op, &requestOpts{
		method:     http.MethodGet,
		path:       endpoint,
		query:      query,
		headers:    headers,
		onResponse: func(resp *http.Response) { pendingCookies = resp.Cookies() },
	}, &response)
	if err != nil {
		return nil, err
	}
	if response.Errno == 0 {
		if response.ShareID <= 0 || response.UK <= 0 {
			return nil, wrapErr(op, errors.New("successful share response is missing valid share and owner IDs"))
		}
		if requireList && response.List == nil {
			return nil, wrapErr(op, errors.New("successful share list response is missing list"))
		}
	}
	c.mergeCookies(pendingCookies)
	return &response, nil
}

// TransferShare saves selected shared files to an absolute remote directory.
// It sends shareid/from as query parameters and fsidlist/path as form fields,
// matching the public web client. File IDs must belong to the given share.
// A successful asynchronous response does not mean the task has finished.
func (c *Client) TransferShare(ctx context.Context, shareID, ownerUK int64, fsIDs []int64, dest string, opts *ShareTransferOptions) (*ShareTransferResponse, error) {
	const op = "transferShare"
	if shareID <= 0 || ownerUK <= 0 {
		return nil, wrapErr(op, errors.New("positive share and owner IDs required"))
	}
	onDup, err := validateShareTransfer(fsIDs, dest, opts)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if err := c.ensureJSToken(ctx); err != nil {
		return nil, wrapErr(op, err)
	}
	query := c.shareQuery()
	query.Set("shareid", strconv.FormatInt(shareID, 10))
	query.Set("from", strconv.FormatInt(ownerUK, 10))
	query.Set("ondup", onDup)
	query.Set("async", "1")
	query.Set("bdstoken", c.dataSnapshot().bdsToken)
	fileIDs, err := json.Marshal(fsIDs)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	form := newForm()
	form.Append("fsidlist", string(fileIDs))
	form.Append("path", dest)
	var response ShareTransferResponse
	headers := c.registrationHeaders()
	headers["Accept"] = "application/json, text/plain, */*"
	headers["X-Requested-With"] = "XMLHttpRequest"
	err = c.doJSON(ctx, op, &requestOpts{
		method:  http.MethodPost,
		path:    "/share/transfer",
		query:   query,
		form:    form,
		headers: headers,
	}, &response)
	if err != nil {
		return nil, err
	}
	if response.Errno == 0 && response.TaskID <= 0 {
		var extra struct {
			List []json.RawMessage `json:"list"`
		}
		if err := json.Unmarshal(response.Extra, &extra); err != nil || extra.List == nil {
			return nil, wrapErr(op, errors.New("successful share transfer response is missing a task ID or result list"))
		}
	}
	return &response, nil
}

// validateShareTransfer is shared by transfer and registration workflows so
// invalid transfer options can be rejected before either workflow begins.
func validateShareTransfer(fsIDs []int64, dest string, opts *ShareTransferOptions) (string, error) {
	if len(fsIDs) == 0 {
		return "", errors.New("at least one file ID required")
	}
	for _, id := range fsIDs {
		if id <= 0 {
			return "", errors.New("file IDs must be positive")
		}
	}
	if !strings.HasPrefix(dest, "/") || strings.Contains(dest, "\\") || shareURLHasControl(dest) {
		return "", errors.New("destination must be an absolute remote directory without control characters or backslashes")
	}
	for _, segment := range strings.Split(dest, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("destination must not contain dot path segments")
		}
	}
	onDup := "newcopy"
	if opts != nil && opts.OnDup != "" {
		onDup = opts.OnDup
	}
	if onDup != "newcopy" {
		return "", errors.New("duplicate handling must be newcopy")
	}
	return onDup, nil
}
