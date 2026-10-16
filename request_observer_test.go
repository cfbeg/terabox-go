package terabox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRequestObserverRedactsPersistsAndPreservesBody(t *testing.T) {
	var observations []RequestObservation
	transportCalls := 0
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithRequestObserver(func(ctx context.Context, o RequestObservation) error {
		observations = append(observations, o)
		if o.Phase == "before" && transportCalls != 0 {
			t.Fatal("before journal ran after transport")
		}
		return nil
	}), WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		transportCalls++
		return clientResponse(req, 200, `{"errno":0,"code":7,"request_id_string":"private-reflection","data":{"ndus":"private-body"}}`), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestObservationStage(context.Background(), "registration.finish")
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://www.terabox.com/passport/register_v4/finish?token=private-query", strings.NewReader("pwd=private-form"))
	req.Header.Set("Cookie", "ndus=private-cookie")
	response, err := client.doHTTP(req, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || !strings.Contains(string(body), "private-body") {
		t.Fatal("observer changed response bytes", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if len(observations) != 2 || observations[0].Phase != "before" || observations[1].Phase != "after" || observations[0].ID != observations[1].ID {
		t.Fatalf("missing correlated observations: %#v", observations)
	}
	after := observations[1]
	if after.At.Location().String() != "UTC" || !after.ResponseComplete || after.HTTPStatus != 200 || after.Errno == nil || *after.Errno != 0 || after.Code == nil || *after.Code != 7 || after.Stage != "registration.finish" || after.Route != "hy_passport" || after.RequestID != fmt.Sprintf("%x", sha256.Sum256([]byte("private-reflection"))) {
		t.Fatal("incorrect transport metadata", after)
	}
	serialized, _ := json.Marshal(observations)
	if strings.Contains(string(serialized), "private-") || strings.Contains(string(serialized), "?") || strings.Contains(string(serialized), "pwd") || strings.Contains(string(serialized), "ndus") {
		t.Fatal("observer leaked credentials or payload", string(serialized))
	}
}

func TestRequestObserverBeforeAndAfterFailures(t *testing.T) {
	for _, failPhase := range []string{"before", "after"} {
		t.Run(failPhase, func(t *testing.T) {
			calls := 0
			client, _ := NewAndroidAppClient(androidFixtureProfile(), WithRequestObserver(func(_ context.Context, o RequestObservation) error {
				if o.Phase == failPhase {
					return errors.New("private callback detail")
				}
				return nil
			}), WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return clientResponse(req, 200, `{"errno":0}`), nil
			})}))
			var out map[string]any
			err := client.doJSON(context.Background(), "observe", &requestOpts{method: "GET", path: "/share/list"}, &out)
			if err == nil || strings.Contains(err.Error(), "private callback") {
				t.Fatal("failed observer was accepted or exposed its error", err)
			}
			if (failPhase == "before" && calls != 0) || (failPhase == "after" && calls != 1) {
				t.Fatal("incorrect transmit count", calls)
			}
		})
	}
}

func TestRequestObserverTransportErrorsEarlyCloseAndCopies(t *testing.T) {
	var events []RequestObservation
	client, _ := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/list" {
			return nil, errors.New("private transport error")
		}
		return clientResponse(req, 200, `{"errno":0,"token":"private"}`), nil
	})}))
	client.SetRequestObserver(func(ctx context.Context, o RequestObservation) error {
		events = append(events, o)
		return nil
	})
	// Both direct asset fetching and the independent share browser copy the
	// configured HTTP transport, rather than going through Client.doHTTP.
	for _, address := range []string{"https://www.terabox.com/s/private-share-key?secret=one", "https://s5.teraboxcdn.com/private-asset?token=two"} {
		copy := *client.httpClient
		req, _ := http.NewRequest("GET", address, nil)
		response, err := copy.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
	}
	req, _ := http.NewRequest("GET", "https://www.terabox.com/api/list?dir=private", nil)
	_, _ = client.doHTTP(req, 0)
	if len(events) != 6 || events[1].Outcome != "response_incomplete" || events[3].ResponseComplete || events[5].Outcome != "transport_error" {
		t.Fatal("partial/error metadata missing", events)
	}
	data, _ := json.Marshal(events)
	if strings.Contains(string(data), "private") {
		t.Fatal("dynamic path or transport error was reflected", string(data))
	}
	client.SetRequestObserver(nil)
	req, _ = http.NewRequest("GET", "https://www.terabox.com/share/list", nil)
	response, _ := client.doHTTP(req, 0)
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if len(events) != 6 {
		t.Fatal("disabled observer still ran")
	}
}

func TestRequestObserverBoundedResponseAndPreservedInflightHook(t *testing.T) {
	var first, second []RequestObservation
	client, _ := NewAndroidAppClient(androidFixtureProfile(), WithRequestObserver(func(_ context.Context, o RequestObservation) error {
		first = append(first, o)
		return nil
	}), WithHTTPClient(&http.Client{Transport: clientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return clientResponse(req, 200, `{"errno":0,"payload":"`+strings.Repeat("x", observationBodyLimit)+`"}`), nil
	})}))
	req, _ := http.NewRequest("GET", "https://www.terabox.com/share/list", nil)
	response, _ := client.doHTTP(req, 0)
	client.SetRequestObserver(func(_ context.Context, o RequestObservation) error { second = append(second, o); return nil })
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if len(first) != 2 || len(second) != 0 || first[1].Errno != nil || !first[1].ResponseComplete {
		t.Fatal("capture exceeded bound or inflight hook changed")
	}
}

func TestRequestObserverDoesNotTurnNullMetadataIntoZero(t *testing.T) {
	for _, raw := range []string{`{}`, `{"errno":null,"code":null}`, `{"errno":"0","code":false}`, `not-json`} {
		var observation RequestObservation
		parseObservationMetadata(&observation, []byte(raw))
		if observation.Errno != nil || observation.Code != nil {
			t.Fatal("absent/null/noninteger metadata became success", raw)
		}
	}
}
