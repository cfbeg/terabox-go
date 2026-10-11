package terabox

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// CheckLoginResponse is the account identifier returned by the APK's own
// POST /api/account/uinfo. UK is distinct from the Android native UID.
type CheckLoginResponse struct {
	Errno     int         `json:"errno"`
	ShowMsg   string      `json:"errmsg,omitempty"`
	UK        int64       `json:"uk"`
	RequestID json.Number `json:"request_id,omitempty"`
}

func (response *CheckLoginResponse) UnmarshalJSON(data []byte) error {
	var wire struct {
		Errno     *int        `json:"errno"`
		ErrMsg    string      `json:"errmsg"`
		ShowMsg   string      `json:"show_msg"`
		UK        Int64ish    `json:"uk"`
		RequestID json.Number `json:"request_id"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Errno == nil {
		return errors.New("APK account response is missing errno")
	}
	if *wire.Errno == 0 && wire.UK <= 0 {
		return errors.New("APK account response is missing a positive account identifier")
	}
	message := wire.ErrMsg
	if message == "" {
		message = wire.ShowMsg
	}
	*response = CheckLoginResponse{Errno: *wire.Errno, ShowMsg: message, UK: int64(wire.UK), RequestID: wire.RequestID}
	return nil
}

// CheckLogin validates an existing ndus through dx._.i's APK-native account
// request. It does not send a password or turn the returned UK into NativeUID.
func (c *Client) CheckLogin(ctx context.Context) (*CheckLoginResponse, error) {
	const op = "checkLogin"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	ndus, _ := c.CookieValue("ndus")
	if ndus == "" {
		return nil, wrapErr(op, errors.New("an existing ndus is required for APK account verification"))
	}
	// lj._ adds this native NDUS hash to the endpoint form for POST requests;
	// it is unrelated to the browser's HTML token bootstrap.
	form := newForm()
	form.Append("bdstoken", fmt.Sprintf("%x", md5.Sum([]byte(ndus))))
	var response CheckLoginResponse
	err := c.doJSON(ctx, op, &requestOpts{method: http.MethodPost,
		path: "/api/account/uinfo", form: form}, &response)
	if err != nil {
		return nil, err
	}
	if response.Errno == 0 {
		c.updateParams(func(params *accountParams) { params.accountID = response.UK })
	}
	return &response, nil
}
