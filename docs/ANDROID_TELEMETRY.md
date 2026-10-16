# Request observations and Android telemetry

These APIs separate an HTTP response, a native SDK invocation, and acquisition
credit. They do not infer Webmaster approval from a registration or event.

## Redacted network journal

Install `WithRequestObserver` at construction, or call `SetRequestObserver` on
an existing SDK client. The hook is synchronous and serialized across requests.
The SDK wraps the configured HTTP transport once, including the transport
copied by the independent share browser and Hy/CDN asset fetchers.

```go
client, err := terabox.NewAndroidAppClient(profile,
    terabox.WithRequestObserver(func(ctx context.Context, entry terabox.RequestObservation) error {
        // Append one JSONL entry, flush and fsync before returning nil.
        return journal.AppendAndSync(entry)
    }),
)
ctx = terabox.WithRequestObservationStage(ctx, "registration.finish")
```

Each exchange emits `before`, then `after` with a shared `id`. A `before`
persistence error prevents the HTTP transport from running. A failed `after`
callback fails the response read or close; the operation must remain uncertain.
An `after` observation is emitted at EOF, a read error, or early close. It is
not available while a caller leaves a response body unconsumed and unclosed.
SDK operations always close their response bodies. A response read through a
limit without EOF has `response_complete=false`, even if its retained prefix
resembles successful JSON. Request cancellation does not cancel the final
persistence callback. Callbacks must be bounded and must not make SDK requests.

Metadata includes UTC time, fixed stage, method, resolved host, redacted path,
route, HTTP status, integer `errno`/`code`, and a **SHA-256 digest** of the returned
request ID (`RequestID`, JSON `request_id_sha256`). Parsing is limited to complete
JSON responses of at most 64 KiB. An absent metadata field does not mean zero.
There are no cookies, headers, raw response bodies, query values, credentials,
URL fragments, or transport error strings. `/s/<private-key>` is replaced by
`/s/[redacted]`; unfamiliar asset/redirect paths become `/[redacted]`.

Routes describe the selected SDK transport, not a server acquisition result.
They distinguish native, legacy native, Hy passport/page, native psign,
statistics, share click/page and H5. Unknown direct asset routes are explicit.
Replacing the observer affects future exchanges; an in-flight exchange keeps
its original hook. A nil observer disables future observations.

The caller owns journal storage, permissions, append-only policy, and operation
state. No journal file is created implicitly. Fixed stage labels should contain
no user identifiers. The observer does not change redirect/cookie policy,
request bytes, response bytes, or the original transport's idle cleanup.

## Captured statistics batches

`NewAndroidStatisticsBatch` accepts **already serialized event batch bytes**,
their captured statistics query and the filename selected by the APK config.
The SDK does not synthesize events or guess event schemas, filenames or flush
timing. The query is the dedicated statistics URL builder's output; it is not
the general native common query. Unexpected query fields are rejected.

```go
batch, err := terabox.NewAndroidStatisticsBatch(terabox.AndroidStatisticsCapture{
    DeviceID: profile.DeviceID,
    Filename: observedStatsFilename,
    Query: observedStatisticsQuery,
    EventBytes: observedSerializedBatch,
})
if err != nil { return err }
err = client.UploadAndroidStatistics(ctx, batch, func(state *terabox.AndroidStatisticsBatch) error {
    // Atomically save this private JSON snapshot and fsync it.
    return stateStore.Save(state)
})
```

`UploadAndroidStatistics` checks installation identity/channel/version, binds the
capture to its digest, persists `Attempted=true` before sending, then makes one
real POST to the client's current `/statistics` origin. It sets only captured
statistics query values, the profile UA, and the account's NDUS cookie when
present. It does **not** append Retrofit/legacy API `rand`, `time`, `cuid` or a
browser token. The transport observer still covers this request.

The framing reproduces APK `n40._.c`:

```text
Content-Encoding: gzip
Content-Type: multipart/form-data; boundary=*****

--*****\r\n
Content-Disposition: form-data; name="userfile"; filename="<captured-config-filename>"\r\n
Content-Type: application/octet-stream\r\n
\r\n
<gzip bytes of the captured serialized batch>
\r\n--*****--\r\n
```

Despite the `Content-Encoding` header, only the `userfile` payload is gzip; the
multipart envelope itself is ordinary bytes. Compression preserves event bytes
and uses Java GZIPOutputStream's OS header byte 0. Deflate byte-for-byte equality
with a particular Android zlib build is not claimed. No event-level batching or
deduplication schema is fabricated.

Only complete HTTP 200 with JSON `errno=0` confirms upload. Event bytes are then
removed from the saved batch, leaving a receipt/digest tombstone. Failed,
malformed, interrupted, oversized or uncertain results keep their bytes and
Attempted marker. Restored attempted batches are never automatically resent;
confirmed tombstones are not transmitted again. The caller must retain the
state on any error, including persistence failure, and inspect it before an
explicit recovery. The SDK does not recreate HTTP/HTTPS fallback or HTTP DNS
from the Android networking layer.

## Actual AppsFlyer / Firebase execution adapter

The verified Hy success branch calls `appsflyerReport` with
`{key:"wap_email_register",isReportFb:true}`. Native `DevAction.j` treats true as
AppsFlyer **and FirebaseAnalytics**, not Facebook. True sends empty parameters
to both; false calls AppsFlyer with null parameters. The interface never guesses
vendor endpoints, SDK registration secrets or HTTP payloads.

```go
dispatch, err := terabox.NewAndroidAnalyticsDispatch(
    stableRegistrationOperationID, profile.DeviceID,
    terabox.AndroidAnalyticsEvent{Key: "wap_email_register", IsReportFb: true},
)
if err != nil { return err }
bridge := terabox.ExecutableAndroidAnalyticsBridge{
    Command: absolutePythonExecutable,
    Args: []string{absoluteSDKToolsDir + "/android_analytics_bridge.py",
        "--pid", alreadyRunningPID, "--remote", "127.0.0.1:27042"},
}
err = terabox.ExecuteAndroidAnalytics(ctx, dispatch, bridge,
    func(state *terabox.AndroidAnalyticsDispatch) error { return stateStore.Save(state) })
```

The executable adapter sends one JSON stdin request and requires one correlated
JSON stdout receipt. It invokes an absolute executable directly without a
shell, bounds runtime/output, rejects mismatched proof and suppresses runtime
error/output text. The shipped Python/JS helper attaches to the explicitly
selected, already running APK process. It verifies package, version 4.26.5,
versionCode 699, installed base APK SHA-256 (see evidence below), and the same
raw `wu._.______` CUID **before** calling the actual
installed AppsFlyer/Firebase SDKs. It requires Frida, frida-tools and an existing
reachable Frida server; it does not spawn the app or configure a device/server.

The caller must choose a real event/operation, preserve the dispatch, and keep
runtime lifecycle/account context aligned. Device equality alone does not
establish account login or SDK customer-ID configuration. A generated virtual
Go installation cannot be silently substituted for the attached device.

Execution persists Attempted before invoking the adapter. A receipt means the
specified SDK calls returned, not that vendor servers accepted the event or
Webmaster credited it. Partial SDK execution, timeout, missing proof and lost
response stay attempted without a receipt and cannot be implicitly replayed.

## Evidence and scope

APK 4.26.5 versionCode 699, analyzed base SHA-256
`c82a4429bee57e59f45709d358314950e2220191c2c9d774a443242df13cdad8`:

- `n40._.java:427-443,539-560,600-650`: UA, NDUS, gzip header, fixed boundary,
  userfile filename/payload and HTTP 200 plus errno success condition.
- `com.dubox.drive.stats._.java:172-179,232-249`: batch success/delete and
  compress-before-upload boundary; filename comes from stats config.
- `ek.____.java:153-162,292-293`: dedicated statistics URL/query construction.
- `com.dubox.drive.bus.action.DevAction.java:664-677` and `g40.q.java:39-73`:
  actual AppsFlyer/Firebase routing and empty parameter behavior.
- Packaged `emailRegister.bfe46f32.js`: success `Be()` invokes
  `appsflyerReport({key:"wap_email_register",isReportFb:true})`.

Offline tests validate framing, captured byte preservation, persistence gates,
response handling, no implicit replay, redaction, copied transports and
subprocess correlation. They do not send live telemetry or execute Android.
`/api/report/device` signing remains delegated to native KeyMaker, as described
in the explicit lifecycle methods below. No inferred reporting sequence is
added to registration.

## Explicit guest installation lifecycle

`NewAndroidInstallationLifecycleState` accepts an observation from the same
guest process: DeviceID, IsGuest, Language, explicit IANA TimeZone, DatePattern,
ObservedToday, LastUnloginDay, DeviceActivated and ActivatedTimeSeconds. Neither
the machine's local zone nor an absent native activation flag is guessed.

`ReportAndroidUnloginActive(ctx, state, observedToday, persist)` sends legacy
GET `/api/analytics?type=unloginactive` only for that guest client, after durable
Attempted state. The supplied native current-day string must match the captured
zone/pattern and current SDK time. Only confirmed HTTP 200 / errno=0 advances
the saved last-day value. A response with missing/null errno is not success.
An uncertain same-day request cannot be replayed after restoration.

The current APK's `gv.a0._()` selects the date pattern using the observed
language (literal `cn`, not an inferred alias for `zh`):

| Language | DatePattern |
|---|---|
| th, vi, ru, ar, es, hi, in, pt | dd/MM/yyyy |
| en | MM-dd-yyyy |
| ja, ko, cn | MM/dd/yyyy |
| otherwise | yyyy.MM.dd |

`gv.____.b()` uses Locale.ENGLISH with the device's local time zone. The original
deduplication is **lexicographic string comparison**, not chronological date
comparison. This API preserves it: for example English `01-01-2026` does not
compare greater than stored `12-31-2025`. The previous raw date is retained even
after a locale change. This is separate from report/user's calendar-day policy.

`ReportAndroidDeviceActivation(ctx, state, options, persist)` performs legacy
GET `/api/report/device?timestamp=<ms>&sign=<native signature>` once, only while
the observed activation flag is false. `AndroidDeviceActivationOptions` requires
exactly one source: an `ObservedSignature` bound to DeviceID/channel/clienttype/
timestamp, or an `AndroidDeviceActivationSigner`. Only complete errno=0 updates
DeviceActivated and ActivatedTimeSeconds (current response time in seconds).
Unknown attempts retain the signature and journal and cannot be implicitly
replayed. Both lifecycle methods reject clients with native UID/SK or NDUS.
They are explicit APIs and are never run automatically after registration.

```go
signer := terabox.ExecutableAndroidDeviceActivationSigner{
    Command: absolutePythonExecutable,
    Args: []string{absoluteSDKToolsDir + "/android_device_activation_signer.py",
        "--pid", alreadyRunningGuestPID, "--remote", "127.0.0.1:27042"},
}
result, err := client.ReportAndroidDeviceActivation(ctx, lifecycle,
    terabox.AndroidDeviceActivationOptions{Signer: signer},
    func(s *terabox.AndroidInstallationLifecycleState) error { return stateStore.Save(s) })
```

The signer calls **actual** `hv.______.__` in the selected guest process. It
checks package/build/base hash, native account guest state, CUID/channel/type,
and independently recomputes `clienttype + channel + devuid + timestamp` before
native signing. The KeyMaker key never leaves the process. It returns a private
signature capture to the SDK; the helper itself makes no HTTP request. As with
the analytics helper, missing runtime support fails rather than inventing data.

Additional evidence: `h40._.java:25-39,97-103`, `h40._____.java:47-56`,
`h40.a.java:40-56`; selected DEX parser exports `lifecycle-parser11.json`
(mj.__), `lifecycle-parser13.json` (i40.__), `lifecycle-date12.json`
(gv.____), `lifecycle-date-pattern12.json` (gv.a0). The two response parsers
accept errno=0, otherwise throw. These helpers were verified with offline
protocol and syntax checks; no live Android signature or event was requested.
