package terabox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// HomeInfoResponse is the /api/home/info result. SignB is derived locally.
type HomeInfoResponse struct {
	Errno int `json:"errno"`
	Data  struct {
		Sign1     string `json:"sign1"`
		Sign3     string `json:"sign3"`
		Timestamp int64  `json:"timestamp"`
		SignB     string `json:"-"`
	} `json:"data"`
}

// DLinkEntry is one entry of the /api/download result.
type DLinkEntry struct {
	FSID           int64  `json:"fs_id"`
	DLink          string `json:"dlink"`
	ServerFilename string `json:"server_filename"`
	Size           int64  `json:"size"`
	IsDir          int    `json:"isdir"`
}

// DownloadResponse is the /api/download result.
type DownloadResponse struct {
	Errno int          `json:"errno"`
	DLink []DLinkEntry `json:"dlink"`
}

// GetHomeInfo retrieves the home page info; on success Data.SignB is
// computed from the returned sign1/sign3 values.
func (c *Client) GetHomeInfo(ctx context.Context) (*HomeInfoResponse, error) {
	const op = "getHomeInfo"

	var resp HomeInfoResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/api/home/info",
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Errno == 0 {
		resp.Data.SignB = SignDownload(resp.Data.Sign3, resp.Data.Sign1)
	}
	return &resp, nil
}

// Download requests download links for the given file IDs.
func (c *Client) Download(ctx context.Context, fsIDs []int64) (*DownloadResponse, error) {
	const op = "download"

	homeInfo, err := c.GetHomeInfo(ctx)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if homeInfo.Errno != 0 {
		return nil, wrapErr(op, errors.New("API error! Bad HomeInfo response"))
	}

	fidList, err := json.Marshal(fsIDs)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	form := newForm()
	form.Append("fidlist", string(fidList))
	form.Append("type", "dlink")
	form.Append("vip", "2")
	form.Append("sign", homeInfo.Data.SignB)
	form.Append("timestamp", strconv.FormatInt(homeInfo.Data.Timestamp, 10))
	form.Append("need_speed", "1")

	var resp DownloadResponse
	err = c.doJSON(ctx, op, &requestOpts{
		method: http.MethodPost,
		path:   "/api/download",
		form:   form,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
