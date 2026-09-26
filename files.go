package terabox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

// errno codes that trigger a token refresh-and-retry.
const (
	errnoPrecreateVerify  = 4000023
	errnoFileManagerRetry = 450016
)

// CreateDirResponse is the /api/create (isdir=1) result.
type CreateDirResponse struct {
	Errno int    `json:"errno"`
	FSID  int64  `json:"fs_id"`
	Path  string `json:"path"`
}

// RecycleClearResponse is the /api/recycle/clear result.
type RecycleClearResponse struct {
	Errno int `json:"errno"`
}

// FileManagerResponse is the /api/filemanager result.
type FileManagerResponse struct {
	Errno  int             `json:"errno"`
	TaskID int64           `json:"taskid"`
	Info   json.RawMessage `json:"info"`
}

// FMCopyMove is one entry of a copy/move filemanager filelist.
type FMCopyMove struct {
	Path    string `json:"path"`
	Dest    string `json:"dest"`
	NewName string `json:"newname"`
	OnDup   string `json:"ondup,omitempty"`
}

// FMRename is one entry of a rename filemanager filelist.
type FMRename struct {
	ID      int64  `json:"id,omitempty"`
	Path    string `json:"path"`
	NewName string `json:"newname"`
}

// FileMetaTarget identifies a file for GetFileMeta.
type FileMetaTarget struct {
	FSID int64  `json:"fs_id"`
	Path string `json:"path"`
}

// FileMeta is one entry of the /api/filemetas result.
type FileMeta struct {
	FSID           int64  `json:"fs_id"`
	Path           string `json:"path"`
	ServerFilename string `json:"server_filename"`
	Size           int64  `json:"size"`
	IsDir          int    `json:"isdir"`
	MD5            string `json:"md5"`
	DLink          string `json:"dlink"`
}

// FileMetaResponse is the /api/filemetas result.
type FileMetaResponse struct {
	Errno int        `json:"errno"`
	Info  []FileMeta `json:"info"`
}

// RecentUploadsResponse is the /rest/recent/listall result.
type RecentUploadsResponse struct {
	Errno int             `json:"errno"`
	List  json.RawMessage `json:"list"`
}

// FileDiffResponse is the accumulated /api/filediff result.
type FileDiffResponse struct {
	Errno      int                  `json:"errno"`
	Cursor     string               `json:"cursor"`
	HasMore    bool                 `json:"has_more"`
	Reset      bool                 `json:"reset"`
	Entries    map[string]FileEntry `json:"entries"`
	RequestIDs requestIDs           `json:"request_id"`
}

// PanTokenResponse is the /api/pantoken result.
type PanTokenResponse struct {
	Errno  int    `json:"errno"`
	Token  string `json:"token"`
	Expire int64  `json:"expire"`
}

// GetRemoteDir retrieves the contents of a remote directory.
func (c *Client) GetRemoteDir(ctx context.Context, dir string, page int) (*ListResponse, error) {
	const op = "getRemoteDir"

	form := newForm()
	form.Append("order", "name")
	form.Append("desc", "0")
	form.Append("dir", dir)
	form.Append("num", "20000")
	form.Append("page", strconv.Itoa(page))
	form.Append("showempty", "0")

	var resp ListResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodPost,
		path:   "/api/list",
		form:   form,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Search looks for remote files and directories matching term.
func (c *Client) Search(ctx context.Context, term string, page int) (*ListResponse, error) {
	const op = "search"
	query := url.Values{
		"order":     {"name"},
		"desc":      {"0"},
		"num":       {"1000"},
		"page":      {strconv.Itoa(page)},
		"recursion": {"1"},
		"key":       {term},
	}

	var resp ListResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/api/search",
		query:  query,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCategoryList lists remote files of a given category
// (1: video, 2: audio, 3: pictures, 4: documents, 6: other).
func (c *Client) GetCategoryList(ctx context.Context, categoryID int, dir string, page int) (*ListResponse, error) {
	const op = "getCategoryList"

	form := newForm()
	form.Append("order", "name")
	form.Append("desc", "0")
	form.Append("dir", dir)
	form.Append("num", "20000")
	form.Append("page", strconv.Itoa(page))
	form.Append("category", strconv.Itoa(categoryID))

	var resp ListResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodPost,
		path:   "/api/categorylist",
		form:   form,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetRecycleBin retrieves the contents of the recycle bin.
func (c *Client) GetRecycleBin(ctx context.Context, page int) (*ListResponse, error) {
	const op = "getRecycleBin"
	query := url.Values{
		"desc": {"0"},
		"num":  {"20000"},
		"page": {strconv.Itoa(page)},
	}

	var resp ListResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/api/recycle/list",
		query:  query,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ClearRecycleBin deletes all items in the recycle bin.
func (c *Client) ClearRecycleBin(ctx context.Context) (*RecycleClearResponse, error) {
	const op = "clearRecycleBin"

	var resp RecycleClearResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/api/recycle/clear",
		query:  url.Values{"async": {"1"}},
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateDir creates a remote directory. Its response carries fs_id only
// when the API decides to return one; errno -7 means the path is invalid.
func (c *Client) CreateDir(ctx context.Context, dir string) (*CreateDirResponse, error) {
	const op = "createDir"

	form := newForm()
	form.Append("path", dir)
	form.Append("isdir", "1")
	form.Append("block_list", "[]")

	var resp CreateDirResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodPost,
		path:   "/api/create",
		query:  url.Values{"a": {"commit"}},
		form:   form,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// fileManager performs a delete/copy/move/rename operation, refreshing
// the app tokens and retrying once on errno 450016.
func (c *Client) fileManager(ctx context.Context, opera string, fmparams any) (*FileManagerResponse, error) {
	const op = "filemanager"

	filelist, err := json.Marshal(fmparams)
	if err != nil {
		return nil, wrapErr(op, err)
	}

	for attempt := 0; ; attempt++ {
		if err := c.ensureJSToken(ctx); err != nil {
			return nil, wrapErr(op, err)
		}
		query := c.appQuery()
		query.Set("jsToken", c.dataSnapshot().jsToken)
		query.Set("onnest", "fail")
		query.Set("opera", opera)

		form := newForm()
		form.Append("filelist", string(filelist))

		var resp FileManagerResponse
		err := c.doJSON(ctx, op, &requestOpts{
			method: http.MethodPost,
			path:   "/api/filemanager",
			query:  query,
			form:   form,
		}, &resp)
		if err != nil {
			return nil, err
		}
		if resp.Errno != errnoFileManagerRetry || attempt >= 1 {
			return &resp, nil
		}
		if _, err := c.UpdateAppData(ctx, ""); err != nil {
			return nil, wrapErr(op, err)
		}
	}
}

// DeleteFiles deletes remote files and directories.
func (c *Client) DeleteFiles(ctx context.Context, paths []string) (*FileManagerResponse, error) {
	return c.fileManager(ctx, "delete", paths)
}

// CopyFiles copies remote files.
func (c *Client) CopyFiles(ctx context.Context, items []FMCopyMove) (*FileManagerResponse, error) {
	return c.fileManager(ctx, "copy", items)
}

// MoveFiles moves remote files.
func (c *Client) MoveFiles(ctx context.Context, items []FMCopyMove) (*FileManagerResponse, error) {
	return c.fileManager(ctx, "move", items)
}

// RenameFiles renames remote files.
func (c *Client) RenameFiles(ctx context.Context, items []FMRename) (*FileManagerResponse, error) {
	return c.fileManager(ctx, "rename", items)
}

// GetFileMeta retrieves metadata (including download links) for remote files.
func (c *Client) GetFileMeta(ctx context.Context, targets []FileMetaTarget) (*FileMetaResponse, error) {
	const op = "getFileMeta"

	target, err := json.Marshal(targets)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	form := newForm()
	form.Append("dlink", "1")
	form.Append("origin", "dlna")
	form.Append("target", string(target))

	var resp FileMetaResponse
	err = c.doJSON(ctx, op, &requestOpts{
		method: http.MethodPost,
		path:   "/api/filemetas",
		form:   form,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetRecentUploads retrieves the account's recent uploads.
func (c *Client) GetRecentUploads(ctx context.Context, page int) (*RecentUploadsResponse, error) {
	const op = "getRecentUploads"

	query := c.appQuery()
	query.Set("version", verAndroid)

	var resp RecentUploadsResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/rest/recent/listall",
		query:  query,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// fileDiffOnce fetches one /api/filediff page starting at cursor.
func (c *Client) fileDiffOnce(ctx context.Context, cursor string) (*FileDiffResponse, error) {
	const op = "fileDiff"

	query := c.appQuery()
	query.Set("block_list", "1")

	form := newForm()
	form.Append("cursor", cursor)
	if cursor == "null" {
		form.Append("c", "full")
	}
	form.Append("action", "manual")

	var resp FileDiffResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodPost,
		path:   "/api/filediff",
		query:  query,
		form:   form,
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Errno == 0 {
		next := resp.Cursor
		c.updateParams(func(p *accountParams) { p.cursor = next })
	}
	return &resp, nil
}

// FileDiff retrieves file difference (delta) information for
// synchronization, following has_more pagination (at most 100 extra
// pages) and merging entries. On request failure the stored cursor is
// reset so the next call performs a full sync.
func (c *Client) FileDiff(ctx context.Context) (*FileDiffResponse, error) {
	const op = "fileDiff"
	const maxPages = 100

	c.mu.RLock()
	cursor := c.params.cursor
	c.mu.RUnlock()

	resetCursor := func() {
		c.updateParams(func(p *accountParams) { p.cursor = "null" })
	}

	res, err := c.fileDiffOnce(ctx, cursor)
	if err != nil {
		resetCursor()
		return nil, err
	}

	for pages := 0; res.Errno == 0 && res.HasMore && pages < maxPages; pages++ {
		c.mu.RLock()
		cursor = c.params.cursor
		c.mu.RUnlock()

		next, err := c.fileDiffOnce(ctx, cursor)
		if err != nil {
			resetCursor()
			return nil, err
		}
		if next.Errno != 0 {
			break
		}
		res.Reset = next.Reset
		res.RequestIDs = append(res.RequestIDs, next.RequestIDs...)
		if res.Entries == nil {
			res.Entries = map[string]FileEntry{}
		}
		for k, v := range next.Entries {
			res.Entries[k] = v
		}
		res.HasMore = next.HasMore
	}
	return res, nil
}

// GenPanToken generates a PAN token for subsequent API requests.
func (c *Client) GenPanToken(ctx context.Context) (*PanTokenResponse, error) {
	const op = "genPanToken"

	query := c.appQuery()
	query.Set("lang", c.lang)
	query.Set("u", "https://www."+TeraBoxDomain)

	var resp PanTokenResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/api/pantoken",
		query:  query,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
