package terabox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

// AndroidResolvedShareEntry is the share_detail input selected by the native
// first-launch router. Source is the returned deeplink source, not Hy's from.
type AndroidResolvedShareEntry struct {
	ShareID  int64  `json:"share_id"`
	OwnerUK  int64  `json:"owner_uk"`
	SURL     string `json:"surl"`
	Randsk   string `json:"randsk"`
	Source   string `json:"source,omitempty"`
	ShareURL string `json:"share_url"`
}

// AndroidShareEntryState models aw.b.t -> pending -> MergeWapAndAFLaunch.
// Dispatch consumes the pending value once; it never repeats an HTTP report.
// The authenticated screen is a separate new entry from any earlier guest
// received-link report and has its own durable request journal.
type AndroidShareEntryState struct {
	DeviceID      string                               `json:"device_id"`
	Provenance    string                               `json:"provenance,omitempty"`
	CaptureSHA256 string                               `json:"capture_sha256"`
	DeepLink      string                               `json:"deep_link"`
	Expected      WebmasterReferral                    `json:"expected"`
	Pending       bool                                 `json:"pending"`
	Jumped        bool                                 `json:"deep_value_jumped"`
	SkipReason    string                               `json:"skip_reason,omitempty"`
	Resolved      *AndroidResolvedShareEntry           `json:"resolved,omitempty"`
	Authenticated *AndroidAuthenticatedShareEntryState `json:"authenticated,omitempty"`
}

// AndroidAuthenticatedShareEntryState binds a new shared-screen entry to the
// verified own account. AccountUK and native AccountUID remain distinct.
type AndroidAuthenticatedShareEntryState struct {
	AccountUK        int64                    `json:"account_uk"`
	AccountUID       string                   `json:"account_uid"`
	NDUSSHA256       string                   `json:"ndus_sha256"`
	FromHive         bool                     `json:"from_hive,omitempty"`
	FromReceivedList bool                     `json:"from_received_list,omitempty"`
	SkipReason       string                   `json:"skip_reason,omitempty"`
	Report           AndroidAttributionReport `json:"report"`
}

// AndroidAuthenticatedShareEntryOptions selects a new authenticated screen.
// AccountUK must already have been verified by this client's CheckLogin.
// BeforeSend persists the attempted session before the side effect. An error
// leaves the attempt guarded, because its persisted disposition is uncertain.
type AndroidAuthenticatedShareEntryOptions struct {
	AccountUK        int64
	FromHive         bool
	FromReceivedList bool
	BeforeSend       func(*WebmasterRegistrationSession) error
}

func androidShareEntryDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func androidShareCaptureDigest(capture AndroidAttributionCapture) string {
	body, _ := json.Marshal(capture)
	return androidShareEntryDigest(body)
}

func androidShareEntryExpected(ref *WebmasterReferral) WebmasterReferral {
	copy := cloneWebmasterReferral(ref)
	copy.Files = nil
	return *copy
}

func resolveAndroidShareEntry(deepLink string, expected *WebmasterReferral) (*AndroidResolvedShareEntry, string, error) {
	u, err := url.Parse(deepLink)
	if err != nil || !attributionStringValid(deepLink) || u.User != nil || u.Fragment != "" {
		return nil, "", errors.New("returned first-launch deeplink is invalid")
	}
	if (u.Scheme != "dubox" && u.Scheme != "terabox") || u.Host != "share_detail" || (u.Path != "" && u.Path != "/") {
		return nil, "unsupported_route", nil
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, "", errors.New("returned share-detail query is invalid")
	}
	for _, key := range []string{"shareid", "uk", "surl", "randsk", "source"} {
		if len(query[key]) > 1 || (len(query[key]) == 1 && !attributionStringValid(query[key][0])) {
			return nil, "", errors.New("returned share-detail identity contains a duplicate or invalid field")
		}
	}
	shareID, shareErr := strconv.ParseInt(query.Get("shareid"), 10, 64)
	ownerUK, ownerErr := strconv.ParseInt(query.Get("uk"), 10, 64)
	surl := query.Get("surl")
	if shareErr != nil || ownerErr != nil || shareID <= 0 || ownerUK <= 0 {
		return nil, "", errors.New("returned share-detail identity is incomplete")
	}
	if surl == "" {
		return nil, "insufficient_metadata", nil
	}
	if validateShareKey(surl) != nil {
		return nil, "", errors.New("returned share-detail short URL is invalid")
	}
	if expected == nil || expected.ShareID <= 0 || expected.WebmasterUK <= 0 {
		return nil, "insufficient_metadata", nil
	}
	urlSURL, err := ParseShareURL(expected.ShareURL)
	if err != nil || urlSURL != expected.ShareFromSURL || validateWebmasterShareLinkMetadata(expected) != nil || validateReferralSource(expected.Source) != nil {
		return nil, "", errors.New("expected first-launch share metadata is invalid")
	}
	if shareID != expected.ShareID || ownerUK != expected.WebmasterUK || surl != expected.ShareFromSURL {
		return nil, "", errors.New("returned first-launch share identity conflicts with resolved public share metadata")
	}
	if expected.Randsk == "" && query.Get("randsk") != "" {
		return nil, "insufficient_metadata", nil
	}
	expectedRandsk, err := url.QueryUnescape(expected.Randsk)
	if err != nil || query.Get("randsk") != expectedRandsk {
		return nil, "", errors.New("returned first-launch share access key conflicts with resolved public share metadata")
	}
	return &AndroidResolvedShareEntry{ShareID: shareID, OwnerUK: ownerUK, SURL: surl,
		Randsk: query.Get("randsk"), Source: query.Get("source"), ShareURL: expected.ShareURL}, "", nil
}

func validateAndroidShareOriginalInputs(capture AndroidAttributionCapture, resolved *AndroidResolvedShareEntry) error {
	if resolved == nil {
		return nil
	}
	var links []string
	if capture.Click != nil {
		links = append(links, capture.Click.DeepLink)
	}
	if capture.InstallReferrer != nil {
		raw := *capture.InstallReferrer
		query, err := url.ParseQuery(raw)
		if err != nil || !query.Has("af_dp") {
			// Play's observed outer value is encodeURIComponent(inner query).
			// PathUnescape preserves literal '+' in this opaque outer layer.
			decoded, decodeErr := url.PathUnescape(raw)
			if decodeErr == nil {
				query, err = url.ParseQuery(decoded)
			}
		}
		if err == nil && query.Has("af_dp") {
			if len(query["af_dp"]) != 1 {
				return errors.New("captured install referrer repeats its share deeplink")
			}
			links = append(links, query.Get("af_dp"))
		}
	}
	for _, link := range links {
		parsed, err := url.Parse(link)
		if err != nil {
			return errors.New("captured share deeplink is invalid")
		}
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return errors.New("captured share deeplink query is invalid")
		}
		for key, want := range map[string]string{"uk": strconv.FormatInt(resolved.OwnerUK, 10),
			"shareid": strconv.FormatInt(resolved.ShareID, 10), "surl": resolved.SURL, "randsk": resolved.Randsk} {
			if len(query[key]) > 1 || (query.Has(key) && query.Get(key) != want) {
				return errors.New("returned first-launch route conflicts with its original captured share identity")
			}
		}
	}
	return nil
}

func validateAndroidShareEntry(state *AndroidAttributionState, profile AndroidAppProfile) error {
	entry := state.ShareEntry
	if entry == nil {
		return nil // Older installation/session snapshots remain valid.
	}
	if entry.DeviceID != profile.DeviceID || entry.Provenance != state.Capture.Provenance || entry.CaptureSHA256 != androidShareCaptureDigest(state.Capture) ||
		!state.ReferrerReport.Succeeded || state.Referrer == nil || state.Referrer.DeepLink == nil || entry.DeepLink != *state.Referrer.DeepLink ||
		state.Capture.Install == nil || !state.Capture.Install.IsFirstLaunch || strings.TrimSpace(entry.DeepLink) == "" {
		return errors.New("saved share entry must belong to its confirmed first-launch capture")
	}
	resolved, skip, err := resolveAndroidShareEntry(entry.DeepLink, &entry.Expected)
	if err != nil {
		return err
	}
	if err := validateAndroidShareOriginalInputs(state.Capture, resolved); err != nil {
		return err
	}
	if entry.SkipReason != skip || (skip != "" && (entry.Pending || entry.Jumped || entry.Resolved != nil || entry.Authenticated != nil)) ||
		(skip == "" && (entry.Pending == entry.Jumped || !reflect.DeepEqual(resolved, entry.Resolved))) {
		return errors.New("saved first-launch share dispatch has inconsistent pending/jump state")
	}
	auth := entry.Authenticated
	if auth == nil {
		return nil
	}
	if !entry.Jumped || auth.AccountUK <= 0 || auth.AccountUID == "" || auth.AccountUID != profile.UID {
		return errors.New("saved authenticated share entry is missing its own account identity")
	}
	if digest, err := hex.DecodeString(auth.NDUSSHA256); err != nil || len(digest) != sha256.Size {
		return errors.New("saved authenticated share entry has an invalid session binding")
	}
	wantSkip := androidAuthenticatedShareSkip(entry.Resolved, auth.AccountUK, auth.FromHive, auth.FromReceivedList)
	if auth.SkipReason != wantSkip || (wantSkip != "" && auth.Report.Attempted) {
		return errors.New("saved authenticated share exclusion conflicts with its new-entry inputs")
	}
	report := auth.Report
	if (report.Succeeded && (!report.Attempted || report.HTTPStatus != http.StatusOK || report.Errno == nil || *report.Errno != 0 || len(report.RawResponse) == 0)) ||
		(!report.Attempted && (report.HTTPStatus != 0 || report.Errno != nil || report.RequestID != "" || len(report.RawBody) != 0 || len(report.RawResponse) != 0)) ||
		report.HTTPStatus < 0 || report.HTTPStatus > 599 || (report.HTTPStatus > 0 && report.HTTPStatus < 100) ||
		len(report.RawBody) > androidAttributionResponseLimit || len(report.RawResponse) > androidAttributionResponseLimit {
		return errors.New("saved authenticated share report has inconsistent attempt/result state")
	}
	if len(report.RawResponse) != 0 {
		var response ShareViewReportResponse
		if json.Unmarshal(report.RawResponse, &response) != nil || report.Errno == nil || response.Errno != *report.Errno || string(response.RequestID) != report.RequestID {
			return errors.New("saved authenticated share report does not match its actual response")
		}
		if len(report.RawBody) != 0 {
			var raw, wire any
			decode := func(body []byte, target *any) error {
				decoder := json.NewDecoder(bytes.NewReader(body))
				decoder.UseNumber()
				return decoder.Decode(target)
			}
			if !json.Valid(report.RawBody) || decode(report.RawResponse, &raw) != nil || decode(report.RawBody, &wire) != nil || !reflect.DeepEqual(raw, wire) {
				return errors.New("saved authenticated share JSON differs from its original wire bytes")
			}
		}
	} else if report.Errno != nil || report.RequestID != "" || report.Succeeded {
		return errors.New("unparsed authenticated share response cannot have confirmed envelope metadata")
	}
	return nil
}

func validateAndroidShareEntrySession(state *AndroidAttributionState, ndus string) error {
	if state != nil && state.ShareEntry != nil && state.ShareEntry.Authenticated != nil {
		if ndus == "" || state.ShareEntry.Authenticated.NDUSSHA256 != androidShareEntryDigest([]byte(ndus)) {
			return errors.New("saved authenticated share entry does not belong to its own session cookie")
		}
	}
	return nil
}

// StageAndroidFirstLaunchShareEntry saves the server-returned first-launch
// deeplink as pending after matching the independently resolved share identity.
// Unsupported routes are recorded without dispatch or HTTP. Missing/empty or
// non-first-launch deeplinks have no pending event. This operation is local.
func (c *Client) StageAndroidFirstLaunchShareEntry(expected *WebmasterReferral) (*AndroidShareEntryState, error) {
	const op = "stageAndroidFirstLaunchShareEntry"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	state := c.AndroidAttribution()
	if state == nil || !state.ReferrerReport.Succeeded || state.Referrer == nil {
		return nil, wrapErr(op, errors.New("confirmed native referrer response is required before first-launch dispatch"))
	}
	if state.ShareEntry != nil {
		if expected != nil && !reflect.DeepEqual(state.ShareEntry.Expected, androidShareEntryExpected(expected)) {
			return nil, wrapErr(op, errors.New("first-launch share entry is already bound to different share metadata"))
		}
		return state.ShareEntry, nil
	}
	if state.Capture.Install == nil || !state.Capture.Install.IsFirstLaunch || state.Referrer.DeepLink == nil || strings.TrimSpace(*state.Referrer.DeepLink) == "" {
		return nil, nil
	}
	resolved, skip, err := resolveAndroidShareEntry(*state.Referrer.DeepLink, expected)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if err := validateAndroidShareOriginalInputs(state.Capture, resolved); err != nil {
		return nil, wrapErr(op, err)
	}
	entry := &AndroidShareEntryState{DeviceID: state.Capture.DeviceID, Provenance: state.Capture.Provenance,
		CaptureSHA256: androidShareCaptureDigest(state.Capture), DeepLink: *state.Referrer.DeepLink,
		Pending: skip == "", SkipReason: skip, Resolved: resolved}
	if expected != nil {
		entry.Expected = androidShareEntryExpected(expected)
	}
	c.mu.Lock()
	c.androidAttribution.ShareEntry = entry
	c.mu.Unlock()
	return c.AndroidAttribution().ShareEntry, nil
}

// DispatchAndroidFirstLaunchShareEntry consumes the pending share_detail route
// exactly once and saves deep_value_jumped. Returning an existing resolved
// entry does not dispatch it again or send a network request.
func (c *Client) DispatchAndroidFirstLaunchShareEntry() (*AndroidResolvedShareEntry, error) {
	const op = "dispatchAndroidFirstLaunchShareEntry"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	state := c.AndroidAttribution()
	if state == nil || state.ShareEntry == nil {
		return nil, wrapErr(op, errors.New("stage the first-launch share entry before dispatch"))
	}
	if state.ShareEntry.SkipReason != "" || state.ShareEntry.Jumped {
		return state.ShareEntry.Resolved, nil
	}
	c.mu.Lock()
	c.androidAttribution.ShareEntry.Pending = false
	c.androidAttribution.ShareEntry.Jumped = true
	c.mu.Unlock()
	return c.AndroidAttribution().ShareEntry.Resolved, nil
}

func androidAuthenticatedShareSkip(entry *AndroidResolvedShareEntry, ownUK int64, hive, received bool) string {
	if hive {
		return "hive"
	}
	if received {
		return "received_list"
	}
	if entry.OwnerUK == ownUK {
		return "self_share"
	}
	return ""
}

func androidShareResponseFromReport(report AndroidAttributionReport) (*ShareViewReportResponse, error) {
	if len(report.RawResponse) == 0 {
		return nil, errors.New("authenticated share entry was attempted without a confirmed response; implicit replay is prohibited")
	}
	var response ShareViewReportResponse
	if err := json.Unmarshal(report.RawResponse, &response); err != nil {
		return nil, err
	}
	response.HTTPStatus = report.HTTPStatus
	response.Raw, response.RawBody = append(json.RawMessage(nil), report.RawResponse...), append([]byte(nil), report.RawBody...)
	return &response, nil
}

// ReportAndroidAuthenticatedShareEntry opens one new authenticated shared
// screen after the local first-launch dispatch. It uses ReportShareView's
// actual native endpoint and exclusions. It never replays the earlier guest
// report or repeats a successful, failed, or uncertain new-entry attempt.
func (c *Client) ReportAndroidAuthenticatedShareEntry(ctx context.Context, opts *AndroidAuthenticatedShareEntryOptions) (*ShareViewReportResponse, error) {
	const op = "reportAndroidAuthenticatedShareEntry"
	if err := c.requireAndroidApp(); err != nil {
		return nil, wrapErr(op, err)
	}
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	state := c.AndroidAttribution()
	if state == nil || state.ShareEntry == nil {
		return nil, wrapErr(op, errors.New("stage and dispatch the returned first-launch share entry before authenticated entry"))
	}
	entry := state.ShareEntry
	if entry.SkipReason != "" {
		return nil, nil
	}
	if !entry.Jumped || entry.Resolved == nil {
		return nil, wrapErr(op, errors.New("first-launch share entry has not been dispatched"))
	}
	ndus, _ := c.CookieValue("ndus")
	profile, verifiedUK := c.AndroidAppProfile(), c.Account().ID
	if opts == nil || opts.AccountUK <= 0 || opts.AccountUK != verifiedUK || ndus == "" || profile.UID == "" {
		return nil, wrapErr(op, errors.New("authenticated share entry requires own native UID, NDUS and this client's CheckLogin-verified account UK"))
	}
	prepared := &AndroidAuthenticatedShareEntryState{AccountUK: verifiedUK, AccountUID: profile.UID,
		NDUSSHA256: androidShareEntryDigest([]byte(ndus)), FromHive: opts.FromHive, FromReceivedList: opts.FromReceivedList}
	prepared.SkipReason = androidAuthenticatedShareSkip(entry.Resolved, verifiedUK, opts.FromHive, opts.FromReceivedList)
	if prior := entry.Authenticated; prior != nil {
		if prior.AccountUK != prepared.AccountUK || prior.AccountUID != prepared.AccountUID || prior.NDUSSHA256 != prepared.NDUSSHA256 ||
			prior.FromHive != prepared.FromHive || prior.FromReceivedList != prepared.FromReceivedList {
			return nil, wrapErr(op, errors.New("authenticated share entry is already bound to different own-account or screen inputs"))
		}
		if prior.SkipReason != "" {
			return &ShareViewReportResponse{Skipped: true, SkipReason: prior.SkipReason}, nil
		}
		if prior.Report.Succeeded {
			response, err := androidShareResponseFromReport(prior.Report)
			return response, wrapErr(op, err)
		}
		if prior.Report.Attempted {
			return nil, wrapErr(op, errors.New("authenticated share entry was already attempted; implicit replay is prohibited"))
		}
	}
	if prepared.SkipReason == "" {
		prepared.Report.Attempted = true
	}
	c.mu.Lock()
	c.androidAttribution.ShareEntry.Authenticated = prepared
	c.mu.Unlock()
	if prepared.SkipReason != "" {
		return &ShareViewReportResponse{Skipped: true, SkipReason: prepared.SkipReason}, nil
	}
	if opts.BeforeSend != nil {
		if err := opts.BeforeSend(c.WebmasterRegistrationSession()); err != nil {
			return nil, wrapErr(op, err)
		}
	}
	response, requestErr := c.ReportShareView(ctx, &ShareViewOptions{OwnerUK: entry.Resolved.OwnerUK, AccountUK: verifiedUK,
		ShareURL: entry.Resolved.ShareURL, ChainSURL: entry.Resolved.SURL})
	report := AndroidAttributionReport{Attempted: true}
	if response != nil {
		report.HTTPStatus = response.HTTPStatus
		report.RawBody = append([]byte(nil), response.RawBody...)
		if len(report.RawBody) > androidAttributionResponseLimit {
			report.RawBody = report.RawBody[:androidAttributionResponseLimit]
		} else if len(response.Raw) != 0 && json.Valid(response.Raw) {
			var actual ShareViewReportResponse
			if json.Unmarshal(response.Raw, &actual) == nil {
				report.RawResponse = append(json.RawMessage(nil), response.Raw...)
				errno := actual.Errno
				report.Errno, report.RequestID = &errno, string(actual.RequestID)
				report.Succeeded = requestErr == nil && response.HTTPStatus == http.StatusOK && actual.Errno == 0
			}
		}
	}
	c.mu.Lock()
	c.androidAttribution.ShareEntry.Authenticated.Report = report
	c.mu.Unlock()
	if requestErr == nil && response != nil && response.Errno != 0 {
		requestErr = &APIError{Code: response.Errno, Message: response.ErrMsg}
	}
	if requestErr == nil && !report.Succeeded {
		requestErr = errors.New("authenticated share entry did not retain a complete successful response")
	}
	return response, wrapErr(op, requestErr)
}
