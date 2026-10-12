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
	Errno       int             `json:"errno"`
	ErrMsg      string          `json:"errmsg,omitempty"`
	RequestID   json.Number     `json:"request_id,omitempty"`
	ShareID     Int64ish        `json:"shareid"`
	UK          Int64ish        `json:"uk"`
	UKString    string          `json:"uk_str,omitempty"`
	CTime       *Int64ish       `json:"ctime,omitempty"`
	ExpiredType *Int64ish       `json:"expiredtype,omitempty"`
	Randsk      string          `json:"randsk,omitempty"`
	FCount      *Int64ish       `json:"fcount,omitempty"`
	List        []FileEntry     `json:"list"`
	Raw         json.RawMessage `json:"raw,omitempty"`
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
	result.Raw = append(json.RawMessage(nil), b...)
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
	RawBody    []byte            `json:"raw_body,omitempty"`
	HTTPStatus int               `json:"http_status,omitempty"`
	Errno      int               `json:"errno"`
	ErrMsg     string            `json:"errmsg,omitempty"`
	RequestID  json.Number       `json:"request_id,omitempty"`
	TaskID     Int64ish          `json:"task_id,omitempty"`
	Info       []json.RawMessage `json:"info,omitempty"`
	Extra      json.RawMessage   `json:"extra,omitempty"`
	Raw        json.RawMessage   `json:"raw,omitempty"`
}

func (r *ShareTransferResponse) UnmarshalJSON(b []byte) error {
	type plain ShareTransferResponse
	var wire struct {
		plain
		Errno        *int     `json:"errno"`
		LegacyTaskID Int64ish `json:"taskid"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	if wire.Errno == nil {
		return errors.New("share transfer response is missing errno")
	}
	result := ShareTransferResponse(wire.plain)
	if result.TaskID != 0 && wire.LegacyTaskID != 0 && result.TaskID != wire.LegacyTaskID {
		return errors.New("share transfer response has conflicting task identifiers")
	}
	if result.TaskID == 0 {
		result.TaskID = wire.LegacyTaskID
	}
	result.Raw = append(json.RawMessage(nil), b...)
	result.Errno = *wire.Errno
	*r = result
	return nil
}

// ShareTransferRoute identifies the APK screen's actual HTTP implementation.
type ShareTransferRoute string

const (
	// ShareTransferRouteRetrofit is the IApi.d route used by multi-share screens.
	ShareTransferRouteRetrofit ShareTransferRoute = "retrofit"
	// ShareTransferRouteShareDetailLegacy is NewFileListInfoFragment's ln.__.B route.
	ShareTransferRouteShareDetailLegacy ShareTransferRoute = "share_detail_legacy"
)

// ShareTransferOptions controls duplicate handling and the APK screen route.
type ShareTransferOptions struct {
	// OnDup is "newcopy" (default). Other values are rejected because they
	// have not been verified for the public share transfer endpoint.
	OnDup string
	// Route defaults to Retrofit for compatibility. The ordinary share_detail
	// screen explicitly uses ShareTransferRouteShareDetailLegacy.
	Route ShareTransferRoute
	// SEKey is an observed share access key, as supplied by the native screen.
	// It is supported only on the verified share_detail legacy route.
	SEKey string
}

// GetShareInfo retrieves public share metadata. surl is an already normalized
// key returned by ParseShareURL; the endpoint requires its extra leading 1.
// Verification requirements are returned as a nonzero response Errno.
func (c *Client) GetShareInfo(ctx context.Context, surl string) (*ShareInfoResponse, error) {
	const op = "getShareInfo"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	if err := validateShareKey(surl); err != nil {
		return nil, wrapErr(op, err)
	}
	query := url.Values{}
	query.Set("shorturl", "1"+surl)
	query.Set("root", "1")
	query.Set("type", "0")
	query.Set("bot_uk", "")
	return c.getShareMetadata(ctx, op, "/api/shorturlinfo", query, false)
}

// GetShareList retrieves one page of root files and the share's identifiers.
// surl is already normalized; unlike shorturlinfo, share/list receives it
// without an added 1. The public page argument is one-based, mapped to the
// APK's zero-based root listing with 100 entries per page.
func (c *Client) GetShareList(ctx context.Context, surl string, page int) (*ShareInfoResponse, error) {
	const op = "getShareList"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	if err := validateShareKey(surl); err != nil {
		return nil, wrapErr(op, err)
	}
	if page <= 0 {
		page = 1
	}
	query := url.Values{}
	query.Set("shorturl", surl)
	query.Set("root", "1")
	query.Set("page", strconv.Itoa(page-1))
	query.Set("num", "100")
	query.Set("dir", "")
	query.Set("timestamp", strconv.FormatInt(c.androidAppTime()/1000, 10))
	query.Set("bot_uk", "")
	query.Set("scene", "")
	return c.getShareMetadata(ctx, op, "/share/list", query, true)
}

func (c *Client) getShareMetadata(ctx context.Context, op, endpoint string, query url.Values, requireList bool) (*ShareInfoResponse, error) {
	var response ShareInfoResponse
	var pendingCookies []*http.Cookie
	err := c.doJSON(ctx, op, &requestOpts{
		method:     http.MethodGet,
		path:       endpoint,
		query:      query,
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
// matching APK IApi.d. async and ondup belong to the native form body.
// File IDs must belong to the given share.
// A successful asynchronous response does not mean the task has finished.
// A non-nil response with an error preserves received private wire evidence;
// its default or parsed errno is never proof that the request was accepted.
func (c *Client) TransferShare(ctx context.Context, shareID, ownerUK int64, fsIDs []int64, dest string, opts *ShareTransferOptions) (*ShareTransferResponse, error) {
	const op = "transferShare"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	if shareID <= 0 || ownerUK <= 0 {
		return nil, wrapErr(op, errors.New("positive share and owner IDs required"))
	}
	onDup, err := validateShareTransfer(fsIDs, dest, opts)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	query := url.Values{}
	query.Set("shareid", strconv.FormatInt(shareID, 10))
	query.Set("from", strconv.FormatInt(ownerUK, 10))
	query.Set("bot_uk", "")
	legacy := opts != nil && opts.Route == ShareTransferRouteShareDetailLegacy
	var selection any = fsIDs
	if legacy {
		stringIDs := make([]string, len(fsIDs))
		for i, id := range fsIDs {
			stringIDs[i] = strconv.FormatInt(id, 10)
		}
		selection = stringIDs
		if opts.SEKey != "" {
			decoded, decodeErr := url.QueryUnescape(opts.SEKey)
			if decodeErr != nil || shareURLHasControl(decoded) {
				return nil, wrapErr(op, errors.New("share access key has invalid URL encoding or control characters"))
			}
			query.Set("sekey", decoded)
		}
	}
	fileIDs, err := json.Marshal(selection)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	form := newForm()
	if legacy {
		// ln.__.B builds the destination first and JSONArray<String> selection;
		// the Retrofit branch uses List<Long>.toString() with spaces.
		form.Append("path", dest)
		form.Append("async", "1")
		form.Append("fsidlist", string(fileIDs))
		form.Append("ondup", onDup)
	} else {
		form.Append("fsidlist", strings.ReplaceAll(string(fileIDs), ",", ", "))
		form.Append("async", "1")
		form.Append("ondup", onDup)
	}
	for key, value := range c.AndroidAppProfile().NativeCKData {
		if key == "path" || key == "async" || key == "fsidlist" || key == "filelist" || key == "ondup" {
			return nil, wrapErr(op, errors.New("native check data contains a transfer-owned field"))
		}
		form.Append(key, value)
	}
	if !legacy {
		form.Append("path", dest)
	}
	if legacy {
		c.appendAndroidLegacyNDUSToken(form)
	}
	var response ShareTransferResponse
	err = c.doJSON(ctx, op, &requestOpts{
		method:       http.MethodPost,
		path:         "/share/transfer",
		query:        query,
		form:         form,
		legacyNative: legacy,
	}, &response)
	if err != nil {
		return &response, err
	}
	if response.Errno == 0 && response.TaskID <= 0 {
		if legacy {
			// mn.e parses ManageResponse: synchronous legacy results require
			// info[], and the first nonzero per-file errno becomes the result.
			if response.Info == nil {
				return &response, wrapErr(op, errors.New("legacy share transfer response is missing a task ID or per-file info"))
			}
			for _, rawInfo := range response.Info {
				var info struct {
					Errno *int `json:"errno"`
				}
				if err := json.Unmarshal(rawInfo, &info); err != nil || info.Errno == nil {
					return &response, wrapErr(op, errors.New("legacy share transfer per-file result is missing errno"))
				}
				if *info.Errno != 0 && response.Errno == 0 {
					response.Errno = *info.Errno
				}
			}
			return &response, nil
		}
		var extra struct {
			List []json.RawMessage `json:"list"`
		}
		if err := json.Unmarshal(response.Extra, &extra); err != nil || extra.List == nil {
			return &response, wrapErr(op, errors.New("successful share transfer response is missing a task ID or result list"))
		}
	}
	return &response, nil
}

// validateShareTransfer is shared by transfer and registration workflows so
// invalid transfer options can be rejected before either workflow begins.
func validateShareTransfer(fsIDs []int64, dest string, opts *ShareTransferOptions) (string, error) {
	if opts != nil {
		if opts.Route != "" && opts.Route != ShareTransferRouteRetrofit && opts.Route != ShareTransferRouteShareDetailLegacy {
			return "", errors.New("unknown APK share transfer route")
		}
		if opts.SEKey != "" && opts.Route != ShareTransferRouteShareDetailLegacy {
			return "", errors.New("share access key requires the share_detail legacy route")
		}
		if shareURLHasControl(opts.SEKey) {
			return "", errors.New("share access key contains a control character")
		}
		if opts.SEKey != "" {
			decoded, err := url.QueryUnescape(opts.SEKey)
			if err != nil || shareURLHasControl(decoded) {
				return "", errors.New("share access key has invalid URL encoding or control characters")
			}
		}
	}
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
