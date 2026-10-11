package terabox

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const minerStatusFixture = `{"errno":0,"data":{"free_times_left":"2","buy_times_left":5,"price":"100"}}`

func TestMinerRequestsMatchOfficialH5Contract(t *testing.T) {
	paths := []string{"/rest/1.0/imact/miner/pull", "/rest/1.0/inte/system/getrecord",
		"/rest/1.0/imact/miner/start", "/rest/1.0/imact/miner/getitem", "/rest/1.0/imact/miner/finishgame"}
	next := 0
	profile := androidFixtureProfile()
	profile.NativeParams = map[string]string{"app_name": "must-not-leak", "logid": "must-not-leak"}
	profile.CKData = map[string]string{"ck_tk": "must-not-leak"}
	client, err := NewAndroidAppClient(profile, WithCookies("ndus=fixture-session"),
		WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if next >= len(paths) || req.URL.Path != paths[next] {
				t.Fatalf("unexpected path at request %d: %s", next, req.URL.Path)
			}
			step := next
			next++
			if req.Method != http.MethodGet || req.Header.Get("User-Agent") != profile.UserAgent ||
				req.Header.Get("X-Requested-With") != "XMLHttpRequest" ||
				req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
				req.Header.Get("Referer") != "https://www.terabox.com/wap/glodminer?show_type=3" ||
				!strings.Contains(req.Header.Get("Cookie"), "ndus=fixture-session") {
				t.Fatal("Gold Miner lost its WebView transport identity")
			}
			query := req.URL.Query()
			if step < 3 && len(query) != 0 {
				t.Fatalf("empty-argument H5 call acquired parameters: %v", query)
			}
			switch step {
			case 0:
				response := shareJSONResponse(req, minerStatusFixture)
				response.Header.Add("Set-Cookie", "miner_visitor=fixture-visitor; Path=/")
				return response, nil
			case 1:
				if !strings.Contains(req.Header.Get("Cookie"), "miner_visitor=fixture-visitor") {
					t.Fatal("lost game response cookie")
				}
				return shareJSONResponse(req, `{"code":0,"data":{"can_used_cnt":"9007199254740993"}}`), nil
			case 2:
				return shareJSONResponse(req, `{"error_code":0,"data":{"game_id":9007199254740993,"map_id":"18446744073709551615","map_info":{"items":[{"object_type":"5","x":100,"y":"200.5","rotation":"-12.5","multiplier":"1.5"},{"object_type":0,"x":0,"y":0,"rotation":0,"multiplier":1}]}}}`), nil
			case 3:
				want := url.Values{"game_id": {"9007199254740993"}, "object_type": {"5"}, "report_id": {"1700000000123"}}
				if !reflect.DeepEqual(query, want) {
					t.Fatalf("getitem parameters=%v, want=%v", query, want)
				}
				return shareJSONResponse(req, `{"errno":0,"data":{"result":{"reward_kind":"9","size":"9007199254740993","origin":"7","expire_day":0,"reason_code":"11"}}}`), nil
			case 4:
				want := url.Values{"game_id": {"9007199254740993"}, "devuid": {profile.DeviceID}, "cuid": {profile.DeviceID},
					"version": {"4.26.5"}, "clienttype": {"1"}, "lang": {"ja"}, "channel": {profile.UserAgent},
					"time": {"1700000000123"}, "rand": {"0"}, "zid": {""}}
				if !reflect.DeepEqual(query, want) {
					t.Fatalf("finish parameters=%v, want=%v", query, want)
				}
				return shareJSONResponse(req, minerStatusFixture), nil
			default:
				t.Fatal("unexpected fixture step")
				return nil, errors.New("unexpected fixture step")
			}
		})}))
	if err != nil {
		t.Fatal(err)
	}
	client.androidApp.now = func() time.Time { return time.UnixMilli(1700000000123) }
	status, err := client.MinerPull(context.Background())
	if err != nil || *status != (MinerPullResponse{FreeTimesLeft: 2, BuyTimesLeft: 5, Price: 100}) {
		t.Fatalf("pull=%+v error=%v", status, err)
	}
	gold, err := client.GoldRecord(context.Background())
	if err != nil || gold.CanUsedCnt != 9007199254740993 {
		t.Fatalf("gold=%+v error=%v", gold, err)
	}
	game, err := client.MinerStart(context.Background())
	if err != nil || game.GameID != "9007199254740993" || game.MapID != "18446744073709551615" ||
		len(game.Items) != 2 || game.Items[0] != (MinerMapItem{ObjectType: 5, X: 100, Y: 200.5, Rotation: -12.5, Multiplier: 1.5}) {
		t.Fatalf("start=%+v error=%v", game, err)
	}
	item, err := client.MinerGetItem(context.Background(), game.GameID, 5, "1700000000123")
	if err != nil || item.Reward == nil || item.Reward.Kind != 9 || item.Reward.Size != 9007199254740993 ||
		item.Reward.Origin == nil || *item.Reward.Origin != 7 || item.Reward.ReasonCode == nil || *item.Reward.ReasonCode != 11 {
		t.Fatalf("item=%+v error=%v", item, err)
	}
	finish, err := client.MinerFinish(context.Background(), game.GameID)
	if err != nil || finish.FreeTimesLeft != 2 || next != len(paths) {
		t.Fatalf("finish=%+v requests=%d error=%v", finish, next, err)
	}
}

func TestMinerFinishUsesNativeAPKSigner(t *testing.T) {
	profile := androidFixtureProfile()
	fixtures := androidSignatureLoadFixtures(t).Vectors
	fixture := fixtures[0]
	for _, vector := range fixtures {
		if vector.Algorithm == "legacy" && vector.Name == "ascii" {
			fixture = vector
			break
		}
	}
	if fixture.Algorithm != "legacy" {
		t.Fatal("missing APK URLHandler oracle fixture")
	}
	profile.DeviceID, profile.Version = fixture.DeviceID, fixture.Version
	profile.UID, profile.EncodedSK = fixture.UID, fixture.EncodedSK
	client, err := NewAndroidAppClient(profile, WithCookies("ndus="+fixture.NDUS),
		WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Query().Get("rand") != fixture.ExpectedRand || req.URL.Query().Get("time") != fixture.Time {
				t.Fatal("finish signature does not match the actual APK oracle")
			}
			return shareJSONResponse(req, minerStatusFixture), nil
		})}))
	if err != nil {
		t.Fatal(err)
	}
	ms, err := minerInteger([]byte(fixture.Time))
	if err != nil {
		t.Fatal(err)
	}
	client.androidApp.now = func() time.Time { return time.UnixMilli(ms) }
	if _, err := client.MinerFinish(context.Background(), "fixture-game"); err != nil {
		t.Fatal(err)
	}
}

func TestMinerRejectsMalformedResponseWithoutEchoingContents(t *testing.T) {
	for _, body := range []string{
		`{"data":{"free_times_left":1,"buy_times_left":1,"price":1}}`,
		`{"errno":null,"data":{}}`, `{"errno":false,"data":{}}`,
		`{"errno":0,"code":3,"data":{}}`, `{"errno":0.1,"data":{}}`,
		`{"errno":0}`, `{"errno":0,"data":null}`, `{"errno":0,"data":[]}`,
		`{"errno":0,"data":{"free_times_left":1,"buy_times_left":1}}`,
		`{"errno":0,"data":{"free_times_left":-1,"buy_times_left":1,"price":1}}`,
		`{"errno":0,"data":{"free_times_left":"private-session-value","buy_times_left":1,"price":1}}`,
		`{"errno":0,"data":{"free_times_left":9223372036854775808,"buy_times_left":1,"price":1}}`,
		`{"errno":0,"data":{"free_times_left":1,"buy_times_left":1,"price":1}} {"ndus":"private-session-value"}`,
	} {
		t.Run(body, func(t *testing.T) {
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				return shareJSONResponse(req, body), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.MinerPull(context.Background()); err == nil || strings.Contains(err.Error(), "private-session-value") {
				t.Fatalf("malformed response accepted or leaked: %v", err)
			}
		})
	}
}

func TestMinerMutationsNeverRetryAndPreserveServerCode(t *testing.T) {
	for _, operation := range []string{"start", "getitem", "finish"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return shareJSONResponse(req, `{"errno":460030,"errmsg":"ndus=private-session-value"}`), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "start":
				_, err = client.MinerStart(context.Background())
			case "getitem":
				_, err = client.MinerGetItem(context.Background(), "fixture-game", 5, "1700000000123")
			case "finish":
				_, err = client.MinerFinish(context.Background(), "fixture-game")
			}
			var api *APIError
			if !errors.As(err, &api) || api.Code != 460030 || calls != 1 || strings.Contains(err.Error(), "private-session-value") {
				t.Fatalf("mutation code/retry/redaction failure: calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestMinerTransportErrorsDoNotLeakSignedURLsOrRetry(t *testing.T) {
	for _, operation := range []string{"start", "getitem", "finish"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return nil, &url.Error{Op: "Get", URL: "https://www.terabox.com/?ndus=private-session-value", Err: context.DeadlineExceeded}
			})}))
			if err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "start":
				_, err = client.MinerStart(context.Background())
			case "getitem":
				_, err = client.MinerGetItem(context.Background(), "fixture-game", 5, "1700000000123")
			case "finish":
				_, err = client.MinerFinish(context.Background(), "fixture-game")
			}
			if !errors.Is(err, context.DeadlineExceeded) || calls != 1 || strings.Contains(err.Error(), "private-session-value") {
				t.Fatalf("uncertain mutation lost its timeout, retried or leaked a URL: calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestMinerItemResultsAndMalformedData(t *testing.T) {
	for _, test := range []struct {
		data string
		ok   bool
	}{
		{`{"result":null}`, true},
		{`{"result":{"reward_kind":100,"object_id":1}}`, true},
		{`{"result":{"reward_kind":10,"object_id":6}}`, true},
		{`{"result":{"reward_kind":3,"size":1048576,"object_id":0,"origin":null}}`, true},
		{`{}`, false}, {`{"result":[]}`, false},
		{`{"result":{"size":1}}`, false},
		{`{"result":{"reward_kind":9}}`, false},
		{`{"result":{"reward_kind":100,"size":1}}`, false},
		{`{"result":{"reward_kind":9,"size":-1}}`, false},
		{`{"result":{"reward_kind":9,"size":1,"origin":"ndus=private"}}`, false},
	} {
		_, err := decodeMinerReward([]byte(test.data))
		if (err == nil) != test.ok {
			t.Errorf("reward fixture %s: error=%v, want ok=%v", test.data, err, test.ok)
		}
	}
	for _, data := range []string{
		`{"game_id":1,"map_id":2}`, `{"game_id":null,"map_id":2,"map_info":{"items":[]}}`,
		`{"game_id":1.5,"map_id":2,"map_info":{"items":[]}}`,
		`{"game_id":1,"map_id":2,"map_info":{"items":null}}`,
		`{"game_id":1,"map_id":2,"map_info":{"items":[{"object_type":5,"x":0,"y":0,"rotation":"NaN","multiplier":1}]}}`,
		`{"game_id":1,"map_id":2,"map_info":{"items":[{"object_type":5,"x":0,"y":0,"rotation":0,"multiplier":"Infinity"}]}}`,
	} {
		if _, err := decodeMinerStart([]byte(data)); err == nil {
			t.Errorf("accepted invalid start fixture %s", data)
		}
	}
}

func TestMinerRejectsInvalidInputsWithoutHTTP(t *testing.T) {
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached HTTP")
		return nil, errors.New("invalid input reached HTTP")
	})}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		game   string
		object int
		report string
	}{{"", 5, "123"}, {"secret&ndus=value", 5, "123"}, {"game", 0, "123"}, {"game", 5, ""}, {"game", 5, "1e3"}} {
		if _, err := client.MinerGetItem(context.Background(), test.game, test.object, test.report); err == nil {
			t.Fatal("accepted invalid item parameters")
		}
	}
	if _, err := client.MinerFinish(context.Background(), ""); err == nil {
		t.Fatal("accepted empty game ID")
	}
	var missing *Client
	if _, err := missing.MinerPull(context.Background()); err == nil {
		t.Fatal("nil client accepted")
	}
}

func TestMinerQueryVideoUsesOnlyOfficialPollFields(t *testing.T) {
	toolID := 2
	for _, test := range []struct {
		video  int
		object *int
		data   string
	}{{0, &toolID, `{"tool":true}`}, {1, nil, `true`}, {2, nil, `{"reward_kind":9,"size":9007199254740993}`}, {2, nil, `null`}} {
		calls := 0
		client, err := NewAndroidAppClient(androidFixtureProfile(), WithCookies("ndus=fixture-session"),
			WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				want := url.Values{"game_id": {"9007199254740993"}, "video_type": {string(rune('0' + test.video))}}
				if test.object != nil {
					want.Set("object_id", "2")
				}
				if req.Method != http.MethodGet || req.URL.Path != "/rest/1.0/imact/miner/queryvideo" ||
					!reflect.DeepEqual(req.URL.Query(), want) || req.Header.Get("User-Agent") != androidFixtureProfile().UserAgent ||
					!strings.Contains(req.Header.Get("Cookie"), "ndus=fixture-session") {
					t.Fatal("video poll differs from the official H5 transport or query")
				}
				return shareJSONResponse(req, `{"errno":0,"data":`+test.data+`}`), nil
			})}))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.MinerQueryVideo(context.Background(), "9007199254740993", test.video, test.object)
		if err != nil || calls != 1 || string(response.Data) != test.data {
			t.Fatalf("video type=%d data=%v calls=%d error=%v", test.video, response, calls, err)
		}
	}
}

func TestMinerPuzzleQueryPreservesAvailabilityAndRawData(t *testing.T) {
	for _, test := range []struct {
		availability string
		want         bool
	}{{"true", true}, {"false", false}, {"1", true}, {"0", false}, {`"1"`, true}} {
		data := `{"can_receive":` + test.availability + `,"puzzles":[{"count":9007199254740993,"img":"https://s5.teraboxcdn.com/fixture.png"}],"end_time":1700000000,"reward":{"size":100}}`
		calls := 0
		client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.Method != http.MethodGet || req.URL.Path != "/rest/1.0/imact/puzzle/query" || len(req.URL.Query()) != 0 ||
				req.Header.Get("Referer") != "https://www.terabox.com/wap/glodminer?show_type=3" {
				t.Fatal("puzzle query differs from the official H5 request")
			}
			return shareJSONResponse(req, `{"errno":0,"data":`+data+`}`), nil
		})}))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.MinerPuzzleQuery(context.Background())
		if err != nil || calls != 1 || response.CanReceive != test.want || string(response.Data) != data {
			t.Fatalf("puzzle availability=%s response=%v calls=%d error=%v", test.availability, response, calls, err)
		}
	}
}

func TestMinerAdditionalQueriesRejectMalformedResponsesWithoutRetry(t *testing.T) {
	for _, test := range []struct {
		puzzle bool
		body   string
		code   int
	}{
		{false, `{"errno":0}`, 0}, {false, `{"data":null}`, 0},
		{false, `{"errno":99,"errmsg":"ndus=private-session-value"}`, 99},
		{true, `{"errno":0,"data":{}}`, 0},
		{true, `{"errno":0,"data":{"can_receive":null}}`, 0},
		{true, `{"errno":0,"data":{"can_receive":2}}`, 0},
		{true, `{"errno":0,"data":{"can_receive":"private-session-value"}}`, 0},
		{true, `{"errno":99,"errmsg":"ndus=private-session-value"}`, 99},
	} {
		calls := 0
		client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return shareJSONResponse(req, test.body), nil
		})}))
		if err != nil {
			t.Fatal(err)
		}
		if test.puzzle {
			_, err = client.MinerPuzzleQuery(context.Background())
		} else {
			_, err = client.MinerQueryVideo(context.Background(), "game", 2, nil)
		}
		if err == nil || calls != 1 || strings.Contains(err.Error(), "private-session-value") {
			t.Fatalf("bad poll accepted, repeated or leaked: calls=%d error=%v", calls, err)
		}
		if test.code != 0 {
			var api *APIError
			if !errors.As(err, &api) || api.Code != test.code {
				t.Fatalf("poll lost its server error code: %v", err)
			}
		}
	}
}

func TestMinerQueryVideoRejectsInvalidInputsWithoutHTTP(t *testing.T) {
	toolID := 2
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithHTTPClient(&http.Client{Transport: shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("invalid video input reached HTTP")
		return nil, errors.New("invalid video input reached HTTP")
	})}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		game   string
		video  int
		object *int
	}{{"", 1, nil}, {"game", -1, nil}, {"game", 3, nil}, {"game", 0, nil}, {"game", 1, &toolID}, {"game", 2, &toolID}} {
		if _, err := client.MinerQueryVideo(context.Background(), test.game, test.video, test.object); err == nil {
			t.Fatal("accepted invalid video parameters")
		}
	}
}
