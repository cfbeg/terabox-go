package terabox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RequestObservation contains only transport metadata. Query strings, fragments,
// headers, cookies, bodies, identities and transport error text are excluded.
// Unknown/dynamic paths are replaced, including the private key in /s/<key>.
type RequestObservation struct {
	ID         string    `json:"id"`
	Phase      string    `json:"phase"` // before or after
	At         time.Time `json:"at"`    // UTC
	Stage      string    `json:"stage,omitempty"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	Route      string    `json:"route"`
	HTTPStatus int       `json:"http_status,omitempty"`
	Errno      *int      `json:"errno,omitempty"`
	Code       *int      `json:"code,omitempty"`
	// RequestID is a SHA-256 hex digest of the returned request ID. Arbitrary
	// server-controlled strings are never reflected into the journal.
	RequestID        string `json:"request_id_sha256,omitempty"`
	ResponseComplete bool   `json:"response_complete,omitempty"`
	Outcome          string `json:"outcome,omitempty"`
}

// RequestObserver appends an observation to the caller's durable journal.
// Calls are serialized across this client's native, Hy and asset/browser
// requests, including copies of its HTTP client. Before errors prevent network
// transmission. After errors fail the response read/close; callers must retain
// an uncertain outcome, not retry a side effect. Do not make SDK requests from
// the callback. It receives no payload or credentials.
type RequestObserver func(context.Context, RequestObservation) error

// RequestObservationError means the journal callback failed. Sent distinguishes
// a failed pre-send journal from an already attempted exchange. The callback's
// error is deliberately not exposed because it can contain private data.
type RequestObservationError struct{ Sent bool }

func (e *RequestObservationError) Error() string {
	if e.Sent {
		return "request was attempted but its observation could not be persisted"
	}
	return "request observation could not be persisted before transmission"
}

// WithRequestObserver installs a synchronous metadata journal hook. Nil disables
// it. The supplied http.Client is still copied and its transport is unchanged.
func WithRequestObserver(observer RequestObserver) Option {
	return func(c *Client) {
		c.SetRequestObserver(observer)
	}
}

// SetRequestObserver replaces the hook for future exchanges. An exchange that
// has already emitted before retains the same hook for its after record.
func (c *Client) SetRequestObserver(observer RequestObserver) {
	if c == nil || c.requestObserver == nil {
		return
	}
	c.requestObserver.mu.Lock()
	c.requestObserver.callback = observer
	c.requestObserver.mu.Unlock()
}

type observationStageKey struct{}
type observationRouteKey struct{}

func withObservedAPIRoute(req *http.Request, operation string, forceLegacy bool) *http.Request {
	route := "native"
	p := req.URL.Path
	if strings.HasPrefix(p, "/passport/") {
		route = "hy_passport"
		if operation == "androidAppPSign" {
			route = "native_psign"
		}
	} else if forceLegacy || p == "/api/shorturlinfo" || p == "/api/report/user" || p == "/api/account/uinfo" {
		route = "native_legacy"
	}
	return req.WithContext(context.WithValue(req.Context(), observationRouteKey{}, route))
}

// WithRequestObservationStage labels observations for one operation. Stage must
// be a fixed, nonsecret label (letters, digits, _, -, . only); invalid labels are
// omitted. The context value never changes a request's wire parameters.
func WithRequestObservationStage(ctx context.Context, stage string) context.Context {
	if len(stage) > 64 || strings.IndexFunc(stage, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.')
	}) >= 0 {
		stage = ""
	}
	return context.WithValue(ctx, observationStageKey{}, stage)
}

type requestObservationState struct {
	mu       sync.Mutex
	emitMu   sync.Mutex
	callback RequestObserver
	prefix   string
	sequence uint64
}

func (s *requestObservationState) before(req *http.Request) (RequestObservation, RequestObserver, error) {
	s.mu.Lock()
	callback := s.callback
	if callback == nil {
		s.mu.Unlock()
		return RequestObservation{}, nil, nil
	}
	s.sequence++
	id := fmt.Sprintf("%s-%d", s.prefix, s.sequence)
	s.mu.Unlock()
	path, route := observedPathRoute(req.URL)
	if explicit, ok := req.Context().Value(observationRouteKey{}).(string); ok {
		route = explicit
	} else if req.Header.Get("X-Requested-With") == "XMLHttpRequest" && strings.HasPrefix(req.URL.Path, "/rest/1.0/") {
		route = "h5"
	}
	stage, _ := req.Context().Value(observationStageKey{}).(string)
	o := RequestObservation{ID: id, Phase: "before", At: time.Now().UTC(),
		Stage: stage, Method: req.Method, Host: strings.ToLower(req.URL.Host), Path: path, Route: route}
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	if err := callback(req.Context(), o); err != nil {
		return o, callback, &RequestObservationError{}
	}
	return o, callback, nil
}

func (s *requestObservationState) after(ctx context.Context, callback RequestObserver, o RequestObservation) error {
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	o.Phase, o.At = "after", time.Now().UTC()
	// Persist even when the request timed out; the value-only context retains
	// its operation stage while removing the canceled network deadline.
	if err := callback(context.WithoutCancel(ctx), o); err != nil {
		return &RequestObservationError{Sent: true}
	}
	return nil
}

func observedPathRoute(u *url.URL) (string, string) {
	p := u.Path
	switch {
	case strings.HasPrefix(p, "/passport/"):
		if apkRequestPath(p) {
			return p, "hy_passport"
		}
	case p == "/wap/hylogin" || strings.HasPrefix(p, "/wap/hylogin/"):
		// Router path suffixes may be supplied by a remote redirect. Keep only
		// the verified fixed screens, never arbitrary trailing identifiers.
		switch p {
		case "/wap/hylogin", "/wap/hylogin/emailRegister", "/wap/hylogin/emailVerfify", "/wap/hylogin/login":
			return p, "hy_page"
		}
		return "/wap/hylogin/[redacted]", "hy_page"
	case p == "/statistics":
		return p, "statistics"
	case p == "/api/srn/ck":
		return p, "share_click"
	case p == "/api/shorturlinfo" || p == "/share/transfer" || p == "/api/report/user" || p == "/api/account/uinfo" || p == "/api/list" || p == "/api/taskquery" || p == "/api/analytics" || p == "/api/report/device":
		return p, "native_legacy"
	case apkRequestPath(p):
		return p, "native"
	case p == "/wap/share/filelist" || p == "/sharing/link":
		return p, "share_page"
	case strings.HasPrefix(p, "/s/"):
		return "/s/[redacted]", "share_page"
	}
	// Asset paths and unfamiliar redirect paths can carry opaque private data.
	return "/[redacted]", "asset_or_page"
}

type observedTransport struct {
	base  http.RoundTripper
	state *requestObservationState
}

func (t *observedTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *observedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	o, callback, err := t.state.before(req)
	if err != nil {
		return nil, err
	}
	if callback == nil {
		return t.base.RoundTrip(req)
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		o.Outcome = "transport_error"
		if journalErr := t.state.after(req.Context(), callback, o); journalErr != nil {
			return nil, errors.Join(err, journalErr)
		}
		return nil, err
	}
	if resp == nil {
		o.Outcome = "transport_error"
		return nil, errors.Join(errors.New("transport returned no response"), t.state.after(req.Context(), callback, o))
	}
	o.HTTPStatus = resp.StatusCode
	if resp.Body == nil || resp.Body == http.NoBody {
		o.Outcome, o.ResponseComplete = "response", true
		if err := t.state.after(req.Context(), callback, o); err != nil {
			return nil, err
		}
	} else {
		resp.Body = &observedResponseBody{ReadCloser: resp.Body, state: t.state, callback: callback, ctx: req.Context(), observation: o}
	}
	return resp, nil
}

const observationBodyLimit = 64 << 10

type observedResponseBody struct {
	io.ReadCloser
	state       *requestObservationState
	callback    RequestObserver
	ctx         context.Context
	observation RequestObservation
	prefix      []byte
	overflow    bool
	once        sync.Once
	journalErr  error
}

func (b *observedResponseBody) finish(complete bool) error {
	b.once.Do(func() {
		b.observation.ResponseComplete = complete
		b.observation.Outcome = "response_incomplete"
		if complete {
			b.observation.Outcome = "response"
			if !b.overflow {
				parseObservationMetadata(&b.observation, b.prefix)
			}
		}
		b.prefix = nil
		b.journalErr = b.state.after(b.ctx, b.callback, b.observation)
	})
	return b.journalErr
}

func (b *observedResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if !b.overflow {
		if len(b.prefix)+n > observationBodyLimit {
			b.prefix, b.overflow = nil, true
		} else {
			b.prefix = append(b.prefix, p[:n]...)
		}
	}
	if err != nil {
		journalErr := b.finish(err == io.EOF)
		if journalErr != nil {
			return n, journalErr
		}
	}
	return n, err
}

func (b *observedResponseBody) Close() error {
	err := b.ReadCloser.Close()
	return errors.Join(err, b.finish(false))
}

func parseObservationMetadata(o *RequestObservation, body []byte) {
	var data map[string]json.RawMessage
	if json.Unmarshal(body, &data) != nil {
		return
	}
	for _, field := range []struct {
		key string
		out **int
	}{{"errno", &o.Errno}, {"code", &o.Code}} {
		var value *int
		if json.Unmarshal(data[field.key], &value) == nil && value != nil {
			*field.out = value
		}
	}
	for _, key := range []string{"request_id_string", "request_id"} {
		var value string
		if json.Unmarshal(data[key], &value) != nil {
			var number json.Number
			if json.Unmarshal(data[key], &number) == nil {
				value = string(number)
			}
		}
		if len(value) > 0 && len(value) <= 4096 {
			o.RequestID = fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
			break
		}
	}
}
