package terabox

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// OperatePlanResponse is the /share/webmaster/operateplan result.
// The response code convention for this endpoint is not documented, so
// both errno (API-style) and code (passport-style) are decoded.
type OperatePlanResponse struct {
	Errno     int             `json:"errno"`
	Code      int             `json:"code"`
	Msg       string          `json:"msg"`
	ErrInfo   string          `json:"errinfo"`
	RequestID json.Number     `json:"request_id,omitempty"`
	Data      json.RawMessage `json:"data"`
}

// WebmasterOperatePlan performs a webmaster plan operation via
// /share/webmaster/operateplan. It was observed in the browser when
// joining the webmaster program from the join-us page with
// plan_id=201, opt_type=1. The jsToken/bdstoken pair is fetched via
// UpdateAppData when missing; uk defaults to the current account ID
// (0 when not yet known, matching the observed request).
//
// Verified live: the first join returns errno=0; calling it again on an
// already-joined account returns errno=22003 (msg/data empty).
func (c *Client) WebmasterOperatePlan(ctx context.Context, planID, optType int) (*OperatePlanResponse, error) {
	const op = "webmasterOperatePlan"

	if err := c.ensureJSToken(ctx); err != nil {
		return nil, wrapErr(op, err)
	}
	data := c.dataSnapshot()

	query := c.appQuery()
	query.Set("jsToken", data.jsToken)
	query.Set("plan_id", strconv.Itoa(planID))
	query.Set("opt_type", strconv.Itoa(optType))
	query.Set("uk", strconv.FormatInt(c.Account().ID, 10))
	query.Set("bdstoken", data.bdsToken)

	webHost, _, _ := c.snapshot()
	var resp OperatePlanResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/share/webmaster/operateplan",
		query:  query,
		headers: map[string]string{
			"Accept":           "application/json, text/plain, */*",
			"X-Requested-With": "XMLHttpRequest",
			"Referer":          webHost,
		},
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
