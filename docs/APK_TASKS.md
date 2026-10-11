# APK native task-center requests

The task APIs use the Android APK 4.26.5 `ITaskApi` Retrofit interface, rather
than copying the previous TypeScript client's Hy passport query fields.
The APK SHA-256 is
`73340b723c45cca9bb44289b1ca3ea2e5e207f4af406a6970bb2ef1badf7f696`.

## Exact interface

`classes13.dex`, `Lcom/dubox/drive/task/server/ITaskApi;`, annotation directory
`0x60878c`, declares the following methods. `ServerKt` uses the native
`network/request` factory with base `/rest/1.0/task/`.

| Go method | APK request | Endpoint-specific fields | Annotation offset |
| --- | --- | --- | --- |
| QueryGoldwall | GET new/act/querybyname | query act_name=goldwall_task | 0x571a01 |
| QueryStartTasks | GET common/querystart | none | 0x55875f |
| ReportTaskStart | GET common/reportstart | query task_config_id(int), task_id(String) | 0x54334e |
| ReportTask | POST common/report, FormUrlEncoded | task_config_id(int), task_id(String), task_kind(String), report_id, bdstoken, report_time(long), sign, cnt(int) | 0x52bd08 |
| ReceiveTask | GET common/receive | query task_config_id(int), task_id(int) | 0x51b63e |

The original miner client selects the campaign name `goldwall_task`. The
inspected APK defines a caller-supplied `act_name` String; this particular
campaign label was not found as a literal in its DEX or bundled H5 assets.
`QueryGoldwall` retains the existing client's selected label through that
verified native query-by-name method.

Native common fields, cookie, User-Agent, signing, and nullable guest rand use
the client's captured app profile. These requests do not add H5 client,
clientfrom, pass_version, PCF, psign, membership_version, or check_rand fields.
No task call bootstraps a browser page or performs another task operation.

## Response and model

Native responses use explicit errno and `data.group`. `TaskListResponse` has
`@SerializedName("group")` and a list of `TaskInfo`. Missing errno/group is an
error; a real empty group is returned as an empty slice. API result codes remain
available with `errors.As(err, *APIError)`.

`TaskItem` exposes integer IDs, kind/status, received/progress counters, title,
subtitle, reward kind, and size. JSON integer numbers and numeric strings are
decoded without float conversion, including identifiers above 2^53. Enum
overflow and malformed integer values are rejected.

`TaskInfo.getGoldRewardSize()` confirms that reward kind 9 reads JSON
`reward_info.reward_kind=9` and its positive size, falling back to positive
`extra_info.prize_size`. Malformed optional reward JSON falls back as the APK
does. Text labels are retained when provided by the response.

## Native report signature

The APK's CommonReportJob is obfuscated as `Lq40/______;` (fast variant
`Lq40/b;`). The receiver callback at `0xdf6f80` gets currentTimeMillis and
derives the token by MD5 hex of the account's actual NDUS. Method `k` at
`0xdf7380` builds:

```text
bdstoken = lowercase MD5hex(UTF-8 NDUS)
report_id = Android_<task_kind>_<operation timestamp in milliseconds>
preimage = bdstoken + task_config_id + task_id + task_kind
           + report_time + report_id
sign = standard Base64(UTF-8 lowercase MD5hex(preimage))
```

`ActivityTaskManager.n`, `0xcbf75c`, generates that report ID when none exists;
task-operation code may persist and reuse an existing ID. The report digest
calls `hv.___._____` (MD5 hex) and `hv._.b`, `0xdd9b2c`, the padded Base64
encoder. This signature is separate from URLHandler's native URL rand.

The caller must supply actual progress to `ReportTask(ctx, task, cnt)`.
The SDK does not derive cnt from target_val, run advertisements, fabricate
progress, or automatically report/receive queried tasks. The APK's int fields
are bounded to signed int32 at mutation boundaries. Report/reportstart task IDs
remain decimal strings; ReceiveTask IDs must fit the interface's int32 fields.

`TaskItem.ReportID` may retain the actual operation ID across explicit retries.
`TaskActionResponse.ReportID` and ReportTime preserve the submitted report
identity when a server response exists. Mutating requests are issued once;
transport failure is not automatically retried. Server acknowledgement alone
does not prove that an action was performed or a reward became available.

## Reproduction and verification

Offline analysis artifacts are under
`C:\Projects\gemini\analysis\android-registration`:

- `auth_task_annotations.json`: raw Retrofit annotations and offsets.
- `auth_task_dex13.jsonl`: task interface/callers/models disassembly.
- `auth_task_reports.jsonl` and `auth_task_sign.jsonl`: report job call and digest.
- `auth_TaskInfo.java`, `auth_TaskListResponse.java`, `auth_TaskExtraInfo.java`:
  readable model annotations, with DEX as the primary evidence.
- `auth_task_base64.jsonl`: actual encoder implementation.
- `auth_task_assets.py` / `auth_task_h5_evidence.json`: offline bundled-H5 search.

Reproduce the native interface from the supplied APK:

```powershell
py -3.14 analysis/android-registration/bootstrap_share_annotations.py --apk materials/TeraBox_Android_web_v4.26.5.apk --class 'Lcom/dubox/drive/task/server/ITaskApi;' --out analysis/android-registration/auth_task_annotations.json
py -3.14 analysis/android-registration/bootstrap_scan.py --apk materials/TeraBox_Android_web_v4.26.5.apk --dex classes13.dex --class 'Lq40/______;' --class 'Lq40/b;' --pattern '^$' --out analysis/android-registration/auth_task_sign.jsonl
```

`tasks_test.go` checks both query request shapes, precise IDs/counters,
int32 mutation boundaries, a fixed report-signature vector, supplied counts,
existing operation IDs, strict envelopes, account-secret redaction, and the
absence of automatic retries or extra actions. Tests use mock transports;
they do not call live reporting, claiming, or advertisement endpoints.
