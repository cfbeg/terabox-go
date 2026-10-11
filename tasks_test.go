package terabox

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func taskFixtureClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	client, err := NewAndroidAppClient(androidFixtureProfile(), WithCookies("ndus=fixture-session"), WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatal(err)
	}
	client.androidApp.now = func() time.Time { return time.UnixMilli(1791680000123) }
	return client
}

func TestTaskQueriesUseITaskApiAndPreserveIdentifiers(t *testing.T) {
	requests := 0
	client := taskFixtureClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		query := req.URL.Query()
		if req.Method != http.MethodGet || query.Get("clienttype") != "1" || query.Get("channel") != androidFixtureProfile().NativeChannel || !strings.HasSuffix(req.URL.RawQuery, "&rand") {
			t.Fatalf("not a native task query: %s %s", req.Method, req.URL)
		}
		for _, key := range []string{"app_id", "web", "bdstoken", "pcftoken", "psign", "client", "clientfrom", "pass_version", "check_rand"} {
			if query.Has(key) {
				t.Errorf("non-native task field %s", key)
			}
		}
		if req.Header.Get("X-Requested-With") != "" || req.Header.Get("Referer") != "https://terabox.com/" {
			t.Fatal("task request inherited H5 headers")
		}
		if requests == 1 {
			if req.URL.Path != "/rest/1.0/task/new/act/querybyname" || query.Get("act_name") != "goldwall_task" {
				t.Fatal("goldwall query lost its name")
			}
		} else if req.URL.Path != "/rest/1.0/task/common/querystart" || query.Has("act_name") {
			t.Fatal("start query added endpoint parameters")
		}
		return shareJSONResponse(req, `{"errno":0,"request_id":"9007199254740999","data":{"group":[{"task_id":"9007199254740993","task_config_id":"9007199254740995","task_kind":"120","query_status":2,"has_rec_cnt":"3","max_rec_cnt":5,"cur_val":"17","target_val":300,"text":{"title":"Watch videos","sub_title":"Actual progress"},"reward_kind":"9","reward_info":"{\"reward_kind\":9,\"size\":\"9007199254740997\"}"}]}}`), nil
	}))
	want := []TaskItem{{TaskID: 9007199254740993, TaskConfigID: 9007199254740995, TaskKind: 120, QueryStatus: 2, HasRecCnt: 3, MaxRecCnt: 5, CurVal: 17, TargetVal: 300, Title: "Watch videos", SubTitle: "Actual progress", RewardKind: 9, Size: 9007199254740997}}
	for _, query := range []func(context.Context) ([]TaskItem, error){client.QueryGoldwall, client.QueryStartTasks} {
		got, err := query(context.Background())
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("task query lost data or precision: %+v, %v", got, err)
		}
	}
	if requests != 2 {
		t.Fatal("dashboard query performed extra actions")
	}
}

func TestTaskActionsSendOnlySuppliedProgressAndNativeReportSignature(t *testing.T) {
	requests := 0
	client := taskFixtureClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		query := req.URL.Query()
		switch requests {
		case 1:
			if req.Method != http.MethodGet || req.URL.Path != "/rest/1.0/task/common/reportstart" || query.Get("task_id") != "9007199254740993" || query.Get("task_config_id") != "123" || query.Has("task_kind") {
				t.Fatal("reportstart differs from ITaskApi annotation")
			}
		case 2:
			if req.Method != http.MethodPost || req.URL.Path != "/rest/1.0/task/common/report" {
				t.Fatal("report used wrong native endpoint")
			}
			if err := req.ParseForm(); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"task_config_id": "123", "task_id": "9007199254740993", "task_kind": "120", "report_id": "Android_120_1791680000123", "bdstoken": fmt.Sprintf("%x", md5.Sum([]byte("fixture-session"))), "report_time": "1791680000123", "sign": "YmRjZTYzMWRiZDg2YTFmNzg1YjEzNzEzOWJmNGJkMzc=", "cnt": "7"}
			if len(req.PostForm) != len(want) {
				t.Fatalf("report form has invented fields: %v", req.PostForm)
			}
			for key, value := range want {
				if req.PostForm.Get(key) != value {
					t.Errorf("report %s=%q, want %q", key, req.PostForm.Get(key), value)
				}
			}
			for _, key := range []string{"task_id", "task_config_id", "task_kind", "report_time", "cnt", "bdstoken"} {
				if query.Has(key) {
					t.Errorf("report form field %s was duplicated in query", key)
				}
			}
		case 3:
			if req.Method != http.MethodGet || req.URL.Path != "/rest/1.0/task/common/receive" || query.Get("task_id") != "456" || query.Get("task_config_id") != "123" || query.Has("task_kind") || query.Has("ev") || query.Has("aid") {
				t.Fatal("receive differs from ITaskApi int IDs")
			}
		default:
			t.Fatal("task API automatically repeated or added an operation")
		}
		return shareJSONResponse(req, `{"errno":0,"request_id":"9007199254740999","data":null}`), nil
	}))
	task := TaskItem{TaskID: 9007199254740993, TaskConfigID: 123, TaskKind: 120, TargetVal: 1000000}
	if _, err := client.ReportTaskStart(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if response, err := client.ReportTask(context.Background(), task, 7); err != nil || response.RequestID != "9007199254740999" {
		t.Fatalf("report response: %+v, %v", response, err)
	}
	task.TaskID = 456
	if _, err := client.ReceiveTask(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if requests != 3 {
		t.Fatal("actions were not one request per explicit call")
	}
}

func TestTaskReportRetainsCallerOperationIDAndZeroProgress(t *testing.T) {
	client := taskFixtureClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		_ = req.ParseForm()
		if req.PostForm.Get("report_id") != "Android_39_1791680000000" || req.PostForm.Get("cnt") != "0" {
			t.Fatal("caller report ID or progress was replaced")
		}
		return shareJSONResponse(req, `{"errno":0}`), nil
	}))
	if _, err := client.ReportTask(context.Background(), TaskItem{TaskID: 1, TaskConfigID: 2, TaskKind: 39, TargetVal: 999, ReportID: "Android_39_1791680000000"}, 0); err != nil {
		t.Fatal(err)
	}
}

func TestTaskRequestRejectsMalformedResponsesAndRetainsServerCode(t *testing.T) {
	for _, body := range []string{`{}`, `{"errno":null}`, `{"code":0,"data":{"group":[]}}`, `{"errno":0}`, `{"errno":0,"data":{"group":null}}`, `{"errno":0,"data":{"group":[{"task_id":"not-numeric"}]}}`, `{"errno":9,"errmsg":"rejected fixture-session"}`} {
		t.Run(body, func(t *testing.T) {
			requests := 0
			client := taskFixtureClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) { requests++; return shareJSONResponse(req, body), nil }))
			if _, err := client.QueryGoldwall(context.Background()); err == nil || strings.Contains(err.Error(), "fixture-session") {
				t.Fatalf("invalid result accepted or account leaked: %v", err)
			} else if strings.Contains(body, `"errno":9`) {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Code != 9 {
					t.Fatalf("server code lost: %v", err)
				}
			}
			if requests != 1 {
				t.Fatal("task errors triggered a retry")
			}
		})
	}
	client := taskFixtureClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return shareJSONResponse(req, `{"errno":0,"data":{"group":[]}}`), nil
	}))
	if tasks, err := client.QueryStartTasks(context.Background()); err != nil || tasks == nil || len(tasks) != 0 {
		t.Fatalf("valid empty task list rejected: %v", err)
	}
}

func TestTaskMutationValidatesAPKIntegerWidthsBeforeRequest(t *testing.T) {
	client := taskFixtureClient(t, shareRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("invalid task action sent HTTP")
		return nil, nil
	}))
	for _, task := range []TaskItem{{TaskID: 1}, {TaskID: 1, TaskConfigID: math.MaxInt32 + 1}, {TaskID: -1, TaskConfigID: 1}} {
		if _, err := client.ReportTaskStart(context.Background(), task); err == nil {
			t.Fatal("invalid report-start IDs accepted")
		}
	}
	if _, err := client.ReceiveTask(context.Background(), TaskItem{TaskID: math.MaxInt32 + 1, TaskConfigID: 1}); err == nil {
		t.Fatal("native int receive ID overflow accepted")
	}
	for _, cnt := range []int64{-1, math.MaxInt32 + 1} {
		if _, err := client.ReportTask(context.Background(), TaskItem{TaskID: 1, TaskConfigID: 2, TaskKind: 120}, cnt); err == nil {
			t.Fatal("native count overflow accepted")
		}
	}
	if _, err := client.ReportTask(context.Background(), TaskItem{TaskID: 1, TaskConfigID: 2, TaskKind: 0}, 1); err == nil {
		t.Fatal("missing task kind accepted")
	}
	guest, _ := NewAndroidAppClient(androidFixtureProfile())
	if _, err := guest.ReceiveTask(context.Background(), TaskItem{TaskID: 1, TaskConfigID: 2}); err == nil {
		t.Fatal("guest sent authenticated task action")
	}
}

func TestTaskModelUsesAPKRewardFallbackAndRejectsInvalidNumbers(t *testing.T) {
	var item TaskItem
	if err := json.Unmarshal([]byte(`{"reward_kind":9,"reward_info":"bad-json","extra_info":{"prize_size":"123"}}`), &item); err != nil || item.Size != 123 {
		t.Fatalf("APK prize-size fallback lost: %+v %v", item, err)
	}
	if err := json.Unmarshal([]byte(`{"reward_kind":1,"reward_info":"{\"reward_kind\":9,\"size\":123}"}`), &item); err != nil || item.Size != 0 {
		t.Fatal("non-gold reward became gold")
	}
	for _, body := range []string{`{"task_id":"9223372036854775808"}`, `{"cur_val":1.5}`, `{"task_kind":"2147483648"}`} {
		if err := json.Unmarshal([]byte(body), &item); err == nil {
			t.Fatalf("invalid task integer accepted: %s", body)
		}
	}
}
