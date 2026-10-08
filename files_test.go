package terabox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type filesRoundTripFunc func(*http.Request) (*http.Response, error)

func (f filesRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func filesJSONResponse(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func filesCursor(c *Client) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.params.cursor
}

func TestFileDiffMergesPagesAndCommitsCursor(t *testing.T) {
	bodies := []string{
		`{"errno":0,"cursor":"c1","has_more":true,"reset":true,"request_id":1,"entries":{"first":{"fs_id":1},"same":{"fs_id":2}}}`,
		`{"errno":0,"cursor":"c2","has_more":true,"reset":false,"request_id":[2,3],"entries":{"same":{"fs_id":3}}}`,
		`{"errno":0,"cursor":"c3","has_more":false,"request_id":4,"entries":{"last":{"fs_id":4}}}`,
	}
	var requested []string
	var c *Client
	c = NewClient("", WithHTTPClient(&http.Client{Transport: filesRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.ParseForm(); err != nil {
			return nil, err
		}
		if got := filesCursor(c); got != "start" {
			t.Errorf("cursor committed before all pages succeeded: %q", got)
		}
		requested = append(requested, req.PostForm.Get("cursor"))
		if len(requested) > len(bodies) {
			return nil, errors.New("unexpected extra page")
		}
		return filesJSONResponse(req, bodies[len(requested)-1]), nil
	})}))
	c.updateParams(func(p *accountParams) { p.cursor = "start" })

	res, err := c.FileDiff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"start", "c1", "c2"}; !reflect.DeepEqual(requested, want) {
		t.Errorf("requested cursors = %v, want %v", requested, want)
	}
	if res.Cursor != "c3" || res.HasMore || !res.Reset || filesCursor(c) != "c3" {
		t.Errorf("unexpected final metadata: %+v, stored cursor %q", res, filesCursor(c))
	}
	if want := (requestIDs{1, 2, 3, 4}); !reflect.DeepEqual(res.RequestIDs, want) {
		t.Errorf("request IDs = %v, want %v", res.RequestIDs, want)
	}
	if len(res.Entries) != 3 || res.Entries["same"].FSID != 3 || res.Entries["last"].FSID != 4 {
		t.Errorf("unexpected merged entries: %+v", res.Entries)
	}
}

func TestFileDiffFailuresResetCursor(t *testing.T) {
	transportFailure := errors.New("connection interrupted")
	tests := []struct {
		name      string
		bodies    []string
		failAfter int
		wantCode  int
		wantErr   string
	}{
		{name: "first API failure", bodies: []string{`{"errno":12}`}, wantCode: 12},
		{name: "later API failure", bodies: []string{`{"errno":0,"cursor":"c1","has_more":true}`, `{"errno":12}`}, wantCode: 12, wantErr: "API"},
		{name: "transport failure", bodies: []string{`{"errno":0,"cursor":"c1","has_more":true}`}, failAfter: 1, wantErr: "transport"},
		{name: "malformed JSON", bodies: []string{`{"errno":0,"cursor":"c1","has_more":true}`, `{"errno":`}, wantErr: "JSON"},
		{name: "missing cursor", bodies: []string{`{"errno":0}`}, wantErr: "missing cursor"},
		{name: "stalled cursor", bodies: []string{`{"errno":0,"cursor":"start","has_more":true}`}, wantErr: "did not advance"},
		{name: "cursor cycle", bodies: []string{`{"errno":0,"cursor":"c1","has_more":true}`, `{"errno":0,"cursor":"start","has_more":true}`}, wantErr: "did not advance"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			c := NewClient("", WithHTTPClient(&http.Client{Transport: filesRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if test.failAfter > 0 && calls > test.failAfter {
					return nil, transportFailure
				}
				if calls > len(test.bodies) {
					return nil, errors.New("unexpected extra page")
				}
				return filesJSONResponse(req, test.bodies[calls-1]), nil
			})}))
			c.updateParams(func(p *accountParams) { p.cursor = "start" })

			res, err := c.FileDiff(context.Background())
			if test.wantErr == "" {
				if err != nil || res == nil || res.Errno != test.wantCode {
					t.Fatalf("first-page API failure = (%+v, %v), want errno %d and nil error", res, err, test.wantCode)
				}
			} else {
				if err == nil || res != nil {
					t.Fatalf("failure = (%+v, %v), want nil response and an error", res, err)
				}
				switch test.wantErr {
				case "API":
					var apiErr *APIError
					if !errors.As(err, &apiErr) || apiErr.Code != test.wantCode {
						t.Errorf("error = %v, want APIError with code %d", err, test.wantCode)
					}
				case "transport":
					if !errors.Is(err, transportFailure) {
						t.Errorf("transport error was not preserved: %v", err)
					}
				case "JSON":
					if !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Errorf("JSON error was not preserved: %v", err)
					}
				default:
					if !strings.Contains(err.Error(), test.wantErr) {
						t.Errorf("error = %v, want substring %q", err, test.wantErr)
					}
				}
			}
			if got := filesCursor(c); got != "null" {
				t.Errorf("cursor after failure = %q, want null", got)
			}
		})
	}
}

func TestFileDiffPageLimit(t *testing.T) {
	calls := 0
	c := NewClient("", WithHTTPClient(&http.Client{Transport: filesRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return filesJSONResponse(req, fmt.Sprintf(`{"errno":0,"cursor":"c%d","has_more":true}`, calls)), nil
	})}))
	res, err := c.FileDiff(context.Background())
	if err == nil || res != nil || !strings.Contains(err.Error(), "pagination limit") {
		t.Fatalf("result = (%+v, %v), want a pagination limit error", res, err)
	}
	if calls != 101 || filesCursor(c) != "null" {
		t.Errorf("calls = %d, cursor = %q, want 101 and null", calls, filesCursor(c))
	}
}

func TestFileDiffNoChangesAllowsUnchangedFinalCursor(t *testing.T) {
	c := NewClient("", WithHTTPClient(&http.Client{Transport: filesRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return filesJSONResponse(req, `{"errno":0,"cursor":"start","has_more":false}`), nil
	})}))
	c.updateParams(func(p *accountParams) { p.cursor = "start" })
	res, err := c.FileDiff(context.Background())
	if err != nil || res == nil || res.Cursor != "start" || filesCursor(c) != "start" {
		t.Fatalf("no-change result = (%+v, %v), cursor = %q", res, err, filesCursor(c))
	}
}

func TestFileDiffFailureRestartsFullSync(t *testing.T) {
	calls := 0
	c := NewClient("", WithHTTPClient(&http.Client{Transport: filesRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.ParseForm(); err != nil {
			return nil, err
		}
		calls++
		switch calls {
		case 1:
			return filesJSONResponse(req, `{"errno":0,"cursor":"c1","has_more":true}`), nil
		case 2:
			return filesJSONResponse(req, `{"errno":12}`), nil
		default:
			if req.PostForm.Get("cursor") != "null" || req.PostForm.Get("c") != "full" {
				t.Errorf("recovery request did not start a full sync: %v", req.PostForm)
			}
			return filesJSONResponse(req, `{"errno":0,"cursor":"recovered","has_more":false}`), nil
		}
	})}))
	c.updateParams(func(p *accountParams) { p.cursor = "start" })
	if _, err := c.FileDiff(context.Background()); err == nil {
		t.Fatal("first call should fail on its second page")
	}
	if _, err := c.FileDiff(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || filesCursor(c) != "recovered" {
		t.Errorf("recovery calls = %d, cursor = %q", calls, filesCursor(c))
	}
}

func TestFileDiffConcurrentCallsSerialized(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	defer release()
	var active atomic.Int32
	var overlap atomic.Bool
	var mu sync.Mutex
	var requested []string
	c := NewClient("", WithHTTPClient(&http.Client{Transport: filesRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if active.Add(1) > 1 {
			overlap.Store(true)
		}
		defer active.Add(-1)
		if err := req.ParseForm(); err != nil {
			return nil, err
		}
		mu.Lock()
		requested = append(requested, req.PostForm.Get("cursor"))
		call := len(requested)
		mu.Unlock()
		switch call {
		case 1:
			close(firstStarted)
			select {
			case <-releaseFirst:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
			return filesJSONResponse(req, `{"errno":0,"cursor":"c1","has_more":true}`), nil
		case 2:
			return filesJSONResponse(req, `{"errno":0,"cursor":"c2","has_more":false}`), nil
		default:
			return filesJSONResponse(req, `{"errno":0,"cursor":"c3","has_more":false}`), nil
		}
	})}))
	c.updateParams(func(p *accountParams) { p.cursor = "start" })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() { _, err := c.FileDiff(ctx); results <- err }()
	select {
	case <-firstStarted:
	case <-ctx.Done():
		t.Fatal("first request did not start")
	}
	secondStarted := make(chan struct{})
	go func() { close(secondStarted); _, err := c.FileDiff(ctx); results <- err }()
	<-secondStarted
	select {
	case err := <-results:
		t.Fatalf("a call completed before the blocked request was released: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	release()
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("serialized requests did not finish")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"start", "c1", "c2"}; overlap.Load() || !reflect.DeepEqual(requested, want) {
		t.Errorf("overlap = %v, cursors = %v, want no overlap and %v", overlap.Load(), requested, want)
	}
	if got := filesCursor(c); got != "c3" {
		t.Errorf("stored cursor = %q, want c3", got)
	}
}

func TestFileDiffCanceledBeforeRequestPreservesCursor(t *testing.T) {
	c := NewClient("", WithHTTPClient(&http.Client{Transport: filesRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("canceled FileDiff sent a request")
		return nil, errors.New("unexpected request")
	})}))
	c.updateParams(func(p *accountParams) { p.cursor = "start" })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := c.FileDiff(ctx)
	if res != nil || !errors.Is(err, context.Canceled) || filesCursor(c) != "start" {
		t.Errorf("canceled call = (%+v, %v), cursor = %q", res, err, filesCursor(c))
	}
}

func TestGetRecentUploadsRetainsUnverifiedPaginationContract(t *testing.T) {
	calls := 0
	c := NewClient("", WithHTTPClient(&http.Client{Transport: filesRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodGet || req.URL.Path != "/rest/recent/listall" {
			t.Errorf("unexpected recent uploads request: %s %s", req.Method, req.URL.Path)
		}
		query := req.URL.Query()
		if query.Has("page") || query.Get("version") != verAndroid {
			t.Errorf("unexpected query parameters: %v", query)
		}
		return filesJSONResponse(req, `{"errno":0,"list":[]}`), nil
	})}))
	for _, page := range []int{0, 1, 2} {
		if _, err := c.GetRecentUploads(context.Background(), page); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Errorf("requests = %d, want 3", calls)
	}
}
