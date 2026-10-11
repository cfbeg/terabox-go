package terabox

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// TaskItem is a task-center item returned by the APK's ITaskApi. Counters and
// identifiers retain integer precision when the server uses numeric strings.
type TaskItem struct {
	TaskID       int64  `json:"task_id"`
	TaskConfigID int64  `json:"task_config_id"`
	TaskKind     int    `json:"task_kind"`
	QueryStatus  int    `json:"query_status"`
	HasRecCnt    int64  `json:"has_rec_cnt"`
	MaxRecCnt    int64  `json:"max_rec_cnt"`
	CurVal       int64  `json:"cur_val"`
	TargetVal    int64  `json:"target_val"`
	Title        string `json:"title"`
	SubTitle     string `json:"sub_title"`
	RewardKind   int    `json:"reward_kind"`
	Size         int64  `json:"size"`
	// ReportID can retain the app's existing operation ID across retries.
	// Empty creates Android_<taskKind>_<milliseconds> for this report call.
	ReportID string `json:"report_id,omitempty"`
}

type taskInteger int64

func (value *taskInteger) UnmarshalJSON(body []byte) error {
	text := strings.TrimSpace(string(body))
	if text == "null" {
		return nil
	}
	if strings.HasPrefix(text, `"`) {
		if err := json.Unmarshal(body, &text); err != nil {
			return err
		}
	}
	number, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return errors.New("task field is not a valid int64 integer")
	}
	*value = taskInteger(number)
	return nil
}

func (item *TaskItem) UnmarshalJSON(body []byte) error {
	// Explicit tags keep the public representation independent of the model
	// used to normalize the server's mixed integer/string response fields.
	var wire struct {
		TaskID       taskInteger     `json:"task_id"`
		TaskConfigID taskInteger     `json:"task_config_id"`
		TaskKind     taskInteger     `json:"task_kind"`
		QueryStatus  taskInteger     `json:"query_status"`
		RewardKind   taskInteger     `json:"reward_kind"`
		HasRecCnt    taskInteger     `json:"has_rec_cnt"`
		MaxRecCnt    taskInteger     `json:"max_rec_cnt"`
		CurVal       taskInteger     `json:"cur_val"`
		TargetVal    taskInteger     `json:"target_val"`
		Size         taskInteger     `json:"size"`
		Title        string          `json:"title"`
		SubTitle     string          `json:"sub_title"`
		ReportID     string          `json:"report_id"`
		RewardInfo   json.RawMessage `json:"reward_info"`
		RewardExtra  json.RawMessage `json:"reward_extra"`
		Text         struct {
			Title    string `json:"title"`
			SubTitle string `json:"sub_title"`
		} `json:"text"`
		ExtraInfo struct {
			PrizeSize taskInteger `json:"prize_size"`
		} `json:"extra_info"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return err
	}
	for _, value := range []taskInteger{wire.TaskKind, wire.QueryStatus, wire.RewardKind} {
		if value < math.MinInt32 || value > math.MaxInt32 {
			return errors.New("task enum exceeds the APK's integer range")
		}
	}
	result := TaskItem{TaskID: int64(wire.TaskID), TaskConfigID: int64(wire.TaskConfigID),
		TaskKind: int(wire.TaskKind), QueryStatus: int(wire.QueryStatus), RewardKind: int(wire.RewardKind),
		HasRecCnt: int64(wire.HasRecCnt), MaxRecCnt: int64(wire.MaxRecCnt), CurVal: int64(wire.CurVal), TargetVal: int64(wire.TargetVal),
		Title: wire.Title, SubTitle: wire.SubTitle, ReportID: wire.ReportID, Size: int64(wire.Size)}
	if result.Title == "" {
		result.Title = wire.Text.Title
	}
	if result.SubTitle == "" {
		result.SubTitle = wire.Text.SubTitle
	}
	if result.RewardKind == 9 {
		for _, raw := range []json.RawMessage{wire.RewardInfo, wire.RewardExtra} {
			var encoded string
			if json.Unmarshal(raw, &encoded) == nil {
				raw = json.RawMessage(encoded)
			}
			var reward struct {
				RewardKind taskInteger `json:"reward_kind"`
				Size       taskInteger `json:"size"`
			}
			if json.Unmarshal(raw, &reward) == nil && reward.RewardKind == 9 && reward.Size > 0 {
				result.Size = int64(reward.Size)
				break
			}
		}
		if result.Size <= 0 && wire.ExtraInfo.PrizeSize > 0 {
			result.Size = int64(wire.ExtraInfo.PrizeSize)
		}
	}
	*item = result
	return nil
}

// TaskActionResponse retains the server acknowledgement and its optional data.
// Success acknowledges this request; it does not certify an action occurred.
type TaskActionResponse struct {
	Errno      int             `json:"errno"`
	RequestID  json.Number     `json:"request_id,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	ReportID   string          `json:"report_id,omitempty"`
	ReportTime int64           `json:"report_time,omitempty"`
}

type taskResponse struct {
	Errno     *int            `json:"errno"`
	Code      *int            `json:"code"`
	ErrMsg    string          `json:"errmsg"`
	Msg       string          `json:"msg"`
	ErrorMsg  string          `json:"error_msg"`
	RequestID json.Number     `json:"request_id"`
	Data      json.RawMessage `json:"data"`
}

func (c *Client) taskRequest(ctx context.Context, operation, path, method string, query url.Values, form *formValues) (*TaskActionResponse, error) {
	var response taskResponse
	if err := c.doJSON(ctx, operation, &requestOpts{method: method, path: path, query: query, form: form}, &response); err != nil {
		return nil, err
	}
	if response.Errno == nil {
		return nil, wrapErr(operation, errors.New("task response is missing errno"))
	}
	result := &TaskActionResponse{Errno: *response.Errno, RequestID: response.RequestID, Data: response.Data}
	code := *response.Errno
	if response.Code != nil && *response.Code != 0 {
		code = *response.Code
	}
	if code != 0 {
		message := response.ErrMsg
		if message == "" {
			message = response.Msg
		}
		if message == "" {
			message = response.ErrorMsg
		}
		return result, wrapErr(operation, &APIError{Code: code, Message: c.taskErrorMessage(message)})
	}
	return result, nil
}

func (c *Client) taskErrorMessage(message string) string {
	var sensitive []string
	c.mu.RLock()
	for key, value := range c.cookies {
		if value != "" {
			sensitive = append(sensitive, value)
			if key == "ndus" {
				sensitive = append(sensitive, fmt.Sprintf("%x", md5.Sum([]byte(value))))
			}
		}
	}
	if c.androidApp != nil {
		profile := c.androidApp.profile
		sensitive = append(sensitive, profile.EncodedSK, profile.PSign)
		for _, values := range []map[string]string{profile.CKData, profile.NativeCKData} {
			for _, value := range values {
				if value != "" {
					sensitive = append(sensitive, value)
				}
			}
		}
	}
	c.mu.RUnlock()
	for _, value := range sensitive {
		if value != "" {
			message = strings.ReplaceAll(message, value, "[redacted]")
			message = strings.ReplaceAll(message, url.QueryEscape(value), "[redacted]")
		}
	}
	return message
}

func (c *Client) queryTasks(ctx context.Context, operation, path string, query url.Values) ([]TaskItem, error) {
	response, err := c.taskRequest(ctx, operation, path, http.MethodGet, query, nil)
	if err != nil {
		return nil, err
	}
	var data struct {
		Group *[]TaskItem `json:"group"`
	}
	if err := json.Unmarshal(response.Data, &data); err != nil {
		return nil, wrapErr(operation, errors.New("invalid task list data"))
	}
	if data.Group == nil {
		return nil, wrapErr(operation, errors.New("task list is missing group"))
	}
	return *data.Group, nil
}

// QueryGoldwall retrieves the named goldwall campaign through native ITaskApi.
func (c *Client) QueryGoldwall(ctx context.Context) ([]TaskItem, error) {
	return c.queryTasks(ctx, "queryGoldwall", "/rest/1.0/task/new/act/querybyname", url.Values{"act_name": {"goldwall_task"}})
}

// QueryStartTasks retrieves currently started tasks without reporting progress.
func (c *Client) QueryStartTasks(ctx context.Context) ([]TaskItem, error) {
	return c.queryTasks(ctx, "queryStartTasks", "/rest/1.0/task/common/querystart", nil)
}

func validateTaskIDs(task TaskItem, receive bool) error {
	if task.TaskConfigID <= 0 || task.TaskConfigID > math.MaxInt32 || task.TaskID <= 0 {
		return errors.New("positive task IDs and an APK int32 task config ID are required")
	}
	if receive && task.TaskID > math.MaxInt32 {
		return errors.New("task receive ID exceeds the APK's int32 parameter")
	}
	return nil
}

func (c *Client) requireTaskAccount() error {
	if err := c.requireAndroidApp(); err != nil {
		return err
	}
	if ndus, _ := c.CookieValue("ndus"); ndus == "" {
		return errors.New("authenticated task account required")
	}
	return nil
}

// ReportTaskStart sends the caller's selected operation start through ITaskApi.
func (c *Client) ReportTaskStart(ctx context.Context, task TaskItem) (*TaskActionResponse, error) {
	const op = "reportTaskStart"
	if err := validateTaskIDs(task, false); err != nil {
		return nil, wrapErr(op, err)
	}
	if err := c.requireTaskAccount(); err != nil {
		return nil, wrapErr(op, err)
	}
	return c.taskRequest(ctx, op, "/rest/1.0/task/common/reportstart", http.MethodGet, url.Values{
		"task_config_id": {strconv.FormatInt(task.TaskConfigID, 10)}, "task_id": {strconv.FormatInt(task.TaskID, 10)}}, nil)
}

// ReportTask reports actual caller-supplied progress. It never derives a count
// from TargetVal or runs advertisements/actions. Requests are not auto-retried.
func (c *Client) ReportTask(ctx context.Context, task TaskItem, cnt int64) (*TaskActionResponse, error) {
	const op = "reportTask"
	if err := validateTaskIDs(task, false); err != nil {
		return nil, wrapErr(op, err)
	}
	if task.TaskKind <= 0 || int64(task.TaskKind) > math.MaxInt32 || cnt < 0 || cnt > math.MaxInt32 {
		return nil, wrapErr(op, errors.New("task kind and supplied progress must fit APK int32 fields"))
	}
	if err := c.requireTaskAccount(); err != nil {
		return nil, wrapErr(op, err)
	}
	ndus, _ := c.CookieValue("ndus")
	timestamp := c.androidAppTime()
	reportID := task.ReportID
	if reportID == "" {
		reportID = fmt.Sprintf("Android_%d_%d", task.TaskKind, timestamp)
	}
	operationTime, parseErr := strconv.ParseInt(strings.TrimPrefix(reportID, fmt.Sprintf("Android_%d_", task.TaskKind)), 10, 64)
	if !strings.HasPrefix(reportID, fmt.Sprintf("Android_%d_", task.TaskKind)) || parseErr != nil || operationTime <= 0 {
		return nil, wrapErr(op, errors.New("invalid task report ID"))
	}
	bdstoken := fmt.Sprintf("%x", md5.Sum([]byte(ndus)))
	raw := bdstoken + strconv.FormatInt(task.TaskConfigID, 10) + strconv.FormatInt(task.TaskID, 10) + strconv.Itoa(task.TaskKind) + strconv.FormatInt(timestamp, 10) + reportID
	digest := fmt.Sprintf("%x", md5.Sum([]byte(raw)))
	form := newForm()
	for _, pair := range [][2]string{{"task_config_id", strconv.FormatInt(task.TaskConfigID, 10)}, {"task_id", strconv.FormatInt(task.TaskID, 10)},
		{"task_kind", strconv.Itoa(task.TaskKind)}, {"report_id", reportID}, {"bdstoken", bdstoken}, {"report_time", strconv.FormatInt(timestamp, 10)},
		{"sign", base64.StdEncoding.EncodeToString([]byte(digest))}, {"cnt", strconv.FormatInt(cnt, 10)}} {
		form.Append(pair[0], pair[1])
	}
	response, err := c.taskRequest(ctx, op, "/rest/1.0/task/common/report", http.MethodPost, nil, form)
	if response != nil {
		response.ReportID, response.ReportTime = reportID, timestamp
	}
	return response, err
}

// ReceiveTask submits a reward-receive request for the selected task.
func (c *Client) ReceiveTask(ctx context.Context, task TaskItem) (*TaskActionResponse, error) {
	const op = "receiveTask"
	if err := validateTaskIDs(task, true); err != nil {
		return nil, wrapErr(op, err)
	}
	if err := c.requireTaskAccount(); err != nil {
		return nil, wrapErr(op, err)
	}
	return c.taskRequest(ctx, op, "/rest/1.0/task/common/receive", http.MethodGet, url.Values{
		"task_config_id": {strconv.FormatInt(task.TaskConfigID, 10)}, "task_id": {strconv.FormatInt(task.TaskID, 10)}}, nil)
}
