package terabox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
)

// ShareViewOptions describes the actual share_detail entry. AccountUK is the
// account's numeric UK (Account.B in the APK), not the signing NativeUID.
// Leave it zero for a guest; CheckLogin's verified UK is used when available.
// An authenticated client must have an observed UK from either source.
type ShareViewOptions struct {
	OwnerUK   int64
	AccountUK int64
	ShareURL  string
	// ChainSURL is the already normalized short URL carried by the native entry.
	// If omitted, ShareURL is parsed. A leading 1 is never removed from this field.
	ChainSURL        string
	FromHive         bool
	FromReceivedList bool
}

// ShareViewReportResponse is the received-link report result. It reports an API
// operation only; it does not establish referral credit or rewards.
type ShareViewReportResponse struct {
	RawBody    []byte          `json:"raw_body,omitempty"`
	Errno      int             `json:"errno"`
	ErrMsg     string          `json:"errmsg,omitempty"`
	RequestID  json.Number     `json:"request_id,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
	HTTPStatus int             `json:"http_status,omitempty"`
	Skipped    bool            `json:"skipped,omitempty"`
	SkipReason string          `json:"skip_reason,omitempty"`
}

func (r *ShareViewReportResponse) UnmarshalJSON(data []byte) error {
	type plain ShareViewReportResponse
	var wire struct {
		plain
		Errno *int `json:"errno"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Errno == nil {
		return errors.New("share view report response is missing errno")
	}
	result := ShareViewReportResponse(wire.plain)
	result.Errno = *wire.Errno
	if r.HTTPStatus != 0 {
		// onResponse has already observed an actual HTTP exchange. Local
		// journal fields are not server-controlled API success/skip metadata.
		result.HTTPStatus = r.HTTPStatus
		result.RawBody, result.Raw = nil, nil
		result.Skipped, result.SkipReason = false, ""
	}
	if result.HTTPStatus < 0 || result.HTTPStatus > 599 || result.HTTPStatus > 0 && result.HTTPStatus < 100 {
		return errors.New("saved share view report has an invalid HTTP status")
	}
	if result.Skipped {
		validReason := result.SkipReason == "hive" || result.SkipReason == "received_list" || result.SkipReason == "self_share"
		if !validReason || result.HTTPStatus != 0 || result.Errno != 0 || result.ErrMsg != "" || result.RequestID != "" || len(result.Data) != 0 || len(result.Raw) != 0 || len(result.RawBody) != 0 {
			return errors.New("saved skipped share view report has inconsistent reason or HTTP metadata")
		}
		*r = result
		return nil
	}
	if result.SkipReason != "" {
		return errors.New("share view report has a skip reason without skipped state")
	}
	// h30.t1$_._ checks the response's errno and reports completion without
	// reading data/list. A flat explicit errno=0 is a valid acknowledgement;
	// it does not establish received-list contents or referral credit.
	observed := result.Raw
	if len(result.RawBody) != 0 {
		observed = result.RawBody
	}
	if len(observed) != 0 {
		var actual struct {
			Errno     *int            `json:"errno"`
			ErrMsg    string          `json:"errmsg"`
			RequestID json.Number     `json:"request_id"`
			Data      json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(observed, &actual); err != nil || actual.Errno == nil || *actual.Errno != result.Errno || actual.ErrMsg != result.ErrMsg || actual.RequestID != result.RequestID {
			return errors.New("saved share view metadata does not match its original wire response")
		}
		var originalData, restoredData any
		decodeData := func(body json.RawMessage, target *any) error {
			if len(body) == 0 {
				return nil
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.UseNumber()
			return decoder.Decode(target)
		}
		if decodeData(actual.Data, &originalData) != nil || decodeData(result.Data, &restoredData) != nil || !reflect.DeepEqual(originalData, restoredData) {
			return errors.New("saved share view data does not match its original wire response")
		}
		result.Raw = append(json.RawMessage(nil), observed...)
	} else {
		result.Raw = append(json.RawMessage(nil), data...)
	}
	*r = result
	return nil
}

// ReportShareView reproduces the shared-screen received-link report:
// NewFileListInfoFragment -> ChainInfoViewModel.h -> h30.t1 -> IApi.______.
// The APK skips Hive entries, received-link history entries and self shares.
// This method sends once and never retries an ambiguous side effect.
func (c *Client) ReportShareView(ctx context.Context, opts *ShareViewOptions) (*ShareViewReportResponse, error) {
	const op = "reportShareView"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	if opts == nil || opts.OwnerUK <= 0 || opts.AccountUK < 0 {
		return nil, wrapErr(op, errors.New("share view requires a positive owner UK and nonnegative account UK"))
	}
	response := &ShareViewReportResponse{}
	if opts.FromHive {
		response.Skipped, response.SkipReason = true, "hive"
		return response, nil
	}
	if opts.FromReceivedList {
		response.Skipped, response.SkipReason = true, "received_list"
		return response, nil
	}
	accountUK := c.Account().ID
	if opts.AccountUK != 0 {
		if accountUK != 0 && accountUK != opts.AccountUK {
			return nil, wrapErr(op, errors.New("share view account UK conflicts with the verified account"))
		}
		accountUK = opts.AccountUK
	}
	if ndus, _ := c.CookieValue("ndus"); ndus != "" && accountUK == 0 {
		return nil, wrapErr(op, errors.New("authenticated share view requires an observed account UK"))
	}
	if opts.OwnerUK == accountUK {
		response.Skipped, response.SkipReason = true, "self_share"
		return response, nil
	}
	surl := opts.ChainSURL
	if surl == "" {
		var err error
		surl, err = ParseShareURL(opts.ShareURL)
		if err != nil {
			return nil, wrapErr(op, err)
		}
	} else if err := validateShareKey(surl); err != nil {
		return nil, wrapErr(op, err)
	}
	if opts.ShareURL != "" {
		urlSURL, err := ParseShareURL(opts.ShareURL)
		if err != nil {
			return nil, wrapErr(op, err)
		}
		if urlSURL != surl {
			return nil, wrapErr(op, errors.New("share view URL and captured chain short URL disagree"))
		}
	}
	body, err := json.Marshal(struct {
		List []struct {
			OpType int    `json:"optype"`
			Scene  int    `json:"scene"`
			UniKey string `json:"unikey"`
		} `json:"list"`
		Origin int `json:"origin"`
	}{List: []struct {
		OpType int    `json:"optype"`
		Scene  int    `json:"scene"`
		UniKey string `json:"unikey"`
	}{{4, 2, surl}}, Origin: 0})
	if err != nil {
		return nil, wrapErr(op, err)
	}
	err = c.doJSON(ctx, op, &requestOpts{method: http.MethodPost, path: "/rest/receive/report", jsonBody: body,
		onResponse: func(r *http.Response) { response.HTTPStatus = r.StatusCode },
	}, response)
	return response, err
}
