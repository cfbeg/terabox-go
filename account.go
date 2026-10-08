package terabox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// CheckLoginResponse is the /api/check/login result.
type CheckLoginResponse struct {
	Errno     int         `json:"errno"`
	ShowMsg   string      `json:"show_msg"`
	UK        int64       `json:"uk"`
	RequestID json.Number `json:"request_id"`
}

// MembershipResponse is the /rest/2.0/membership/proxy/user result.
type MembershipResponse struct {
	ErrorCode int `json:"error_code"`
	Data      struct {
		MemberInfo struct {
			IsVIP int `json:"is_vip"`
		} `json:"member_info"`
	} `json:"data"`
}

// UserRecord is one record of /api/user/getinfo.
type UserRecord struct {
	UK      int64  `json:"uk"`
	UName   string `json:"uname"`
	VIPType int    `json:"vip_type"`
	Avatar  string `json:"avatar"`
}

// UserInfoResponse is the /api/user/getinfo result.
type UserInfoResponse struct {
	Errno   int          `json:"errno"`
	Records []UserRecord `json:"records"`
}

// QuotaResponse is the /api/quota result. Available is derived locally.
type QuotaResponse struct {
	Errno     int   `json:"errno"`
	Total     int64 `json:"total"`
	Used      int64 `json:"used"`
	Available int64 `json:"-"`
}

// BirthdayResponse is the /main/age/set result.
type BirthdayResponse struct {
	Errno int `json:"errno"`
}

// CoinsResponse is the /rest/1.0/inte/system/getrecord result.
type CoinsResponse struct {
	Errno   int             `json:"errno"`
	Records json.RawMessage `json:"records"`
}

// GetSysCfg retrieves the system configuration. Its schema is open-ended,
// so the decoded JSON is returned as a map. The JS client sends no Cookie
// header on this call.
func (c *Client) GetSysCfg(ctx context.Context) (map[string]any, error) {
	const op = "getSysCfg"
	query := url.Values{
		"clienttype":        {"0"},
		"language_type":     {c.lang},
		"cfg_category_keys": {"[]"},
		"version":           {"0"},
	}

	var resp map[string]any
	err := c.doJSON(ctx, op, &requestOpts{
		method:   http.MethodGet,
		path:     "/api/getsyscfg",
		query:    query,
		noCookie: true,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// CheckLogin checks the login status of the current session. When the
// server answers with a region-domain-prefix header the default hostname
// switches to that region and the request is retried (at most 3 requests).
func (c *Client) CheckLogin(ctx context.Context) (*CheckLoginResponse, error) {
	const op = "checkLogin"
	const maxAttempts = 3

	for attempt := 0; ; attempt++ {
		var regionPrefix string
		var resp CheckLoginResponse
		err := c.doJSON(ctx, op, &requestOpts{
			method: http.MethodGet,
			path:   "/api/check/login",
			onResponse: func(r *http.Response) {
				regionPrefix = r.Header.Get("region-domain-prefix")
			},
		}, &resp)
		if err != nil {
			return nil, err
		}
		if regionPrefix != "" && !validRegionPrefix(regionPrefix) {
			return nil, wrapErr(op, fmt.Errorf("invalid region-domain-prefix %q", regionPrefix))
		}
		if regionPrefix != "" && attempt+1 < maxAttempts {
			newHost := "https://" + regionPrefix + "." + TeraBoxDomain
			c.mu.Lock()
			c.whost = newHost
			c.mu.Unlock()
			c.warn("default hostname changed", "host", newHost)
			continue
		}
		if resp.Errno == 0 {
			uk := resp.UK
			c.updateParams(func(p *accountParams) { p.accountID = uk })
		}
		return &resp, nil
	}
}

// validRegionPrefix accepts one ASCII DNS label, so the regional hostname
// cannot introduce a different domain, URL path, userinfo, or port.
func validRegionPrefix(prefix string) bool {
	if len(prefix) == 0 || len(prefix) > 63 || prefix[0] == '-' || prefix[len(prefix)-1] == '-' {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		ch := prefix[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

// UserMembership fetches the membership info and stores the VIP status.
func (c *Client) UserMembership(ctx context.Context) (*MembershipResponse, error) {
	const op = "userMembership"

	var resp MembershipResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/rest/2.0/membership/proxy/user",
		query:  url.Values{"method": {"query"}},
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.ErrorCode == 0 {
		isVIP := resp.Data.MemberInfo.IsVIP > 0
		c.updateParams(func(p *accountParams) {
			p.isVIP = isVIP
			if !isVIP {
				p.vipType = 0
			}
		})
	}
	return &resp, nil
}

// GetUserInfo retrieves information for a specific user ID.
func (c *Client) GetUserInfo(ctx context.Context, userID int64) (*UserInfoResponse, error) {
	const op = "getUserInfo"
	if userID <= 0 {
		return nil, wrapErr(op, fmt.Errorf("%d is not user id", userID))
	}
	query := url.Values{
		"user_list":        {"[" + strconv.FormatInt(userID, 10) + "]"},
		"need_relation":    {"0"},
		"need_secret_info": {"1"},
	}

	var resp UserInfoResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/api/user/getinfo",
		query:  query,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCurrentUserInfo retrieves the current user's information and stores
// name and VIP status. It resolves the account ID via CheckLogin when it
// is not yet known.
func (c *Client) GetCurrentUserInfo(ctx context.Context) (*UserInfoResponse, error) {
	const op = "getCurrentUserInfo"
	if c.Account().ID == 0 {
		login, err := c.CheckLogin(ctx)
		if err != nil {
			return nil, wrapErr(op, err)
		}
		if login.Errno != 0 {
			return nil, wrapErr(op, &APIError{Code: login.Errno, Message: login.ShowMsg})
		}
	}
	curUser, err := c.GetUserInfo(ctx, c.Account().ID)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if curUser.Errno == 0 && len(curUser.Records) > 0 {
		thisUser := curUser.Records[0]
		c.updateParams(func(p *accountParams) {
			p.accountName = thisUser.UName
			p.isVIP = thisUser.VIPType > 0
			p.vipType = thisUser.VIPType
		})
	}
	return curUser, nil
}

// GetQuota retrieves storage quota info for the current account and stores
// it in the client state.
func (c *Client) GetQuota(ctx context.Context) (*QuotaResponse, error) {
	const op = "getQuota"

	var resp QuotaResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/api/quota",
		query:  url.Values{"checkexpire": {"1"}, "checkfree": {"1"}},
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Errno == 0 {
		resp.Available = resp.Total - resp.Used
		c.updateParams(func(p *accountParams) {
			p.spaceAvailable = resp.Available
			p.spaceTotal = resp.Total
			p.spaceUsed = resp.Used
		})
	}
	return &resp, nil
}

// SetUserBirthday sets the user birthday (YYYY-MM-DD) and adult status.
func (c *Client) SetUserBirthday(ctx context.Context, birthday string, isAdult int) (*BirthdayResponse, error) {
	const op = "setUserBirthday"

	var resp BirthdayResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/main/age/set",
		query:  url.Values{"birthday": {birthday}, "is_adult": {strconv.Itoa(isAdult)}},
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCoinsCount retrieves the user's coins records.
func (c *Client) GetCoinsCount(ctx context.Context) (*CoinsResponse, error) {
	const op = "getCoinsCount"

	var resp CoinsResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/rest/1.0/inte/system/getrecord",
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
