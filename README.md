# terabox-go

Go client for the HTTP protocols used by TeraBox Android APK 4.26.5. It implements
the app's Hy email registration/login, Gold Miner WebView, and native account,
sharing, taskcenter and post-login configuration requests. Construct every client from a captured
`AndroidAppProfile`. `NewAndroidGuestProfile` can explicitly generate an APK-format
virtual installation from captured build constants; save it before first use.

```sh
go get github.com/cfbeg/terabox-go@latest
```

```go
package main

import (
	"encoding/json"
	"log"
	"os"

	terabox "github.com/cfbeg/terabox-go"
)

func main() {
	raw, err := os.ReadFile("android-profile.json")
	if err != nil {
		log.Fatal(err)
	}
	var profile terabox.AndroidAppProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		log.Fatal("invalid Android app profile")
	}
	client, err := terabox.NewAndroidAppClient(profile)
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}
```

The profile retains the app's CUID, version, UA, native and Hy channels,
language, actual Hy page URL, and captured native common query maps. Guest
UID/SK may be empty. To reuse an existing account, supply its privately stored
cookie string with `WithCookies`; native UID is retained separately and is
never inferred from the share owner's UK or an account-check UK.
Registration follows the APK's active Hy document through its verification
and password screens, recomputing channel/Referer while preserving bridge
identity and PCF/cookies. Successful native account results also update the
validated regional API origin without changing the captured Hy URL.

## Registration from a shared link

For accounts without device state, `NewAndroidGuestProfile(template)` generates
a Cesium CUID, virtual model, app UA and matching native/Hy channels. It copies
runtime maps and clears old account credentials, psign and inspection tokens.
The factory is local and uses the verified APK CUID algorithm. Account UID/SK
must still come from that account's authentication. Reuse saved identities on
subsequent runs rather than calling the factory again.

Create one guest app client per registration and keep that client throughout:

```go
client, err := terabox.NewAndroidAppClient(profile)
if err != nil {
	return err
}
referral, err := client.PrepareWebmasterReferral(ctx, shareURL)
if err != nil {
	return err
}
sent, err := client.RegisterSendCode(ctx, email)
if err != nil {
	return err
}
if sent.Code != 0 || sent.Errno != 0 || sent.Token == "" {
	return fmt.Errorf("send code failed: code=%d errno=%d", sent.Code, sent.Errno)
}
// Save client.WebmasterRegistrationSession() before waiting for the email.
verified, err := client.RegisterVerify(ctx, sent.Token, verificationCode)
if err != nil {
	return err
}
if verified.Code != 0 || verified.Errno != 0 {
	return fmt.Errorf("verification failed: code=%d errno=%d", verified.Code, verified.Errno)
}
// Persist a Finish-in-progress record before making this request.
finished, err := client.RegisterFinish(ctx, sent.Token, password)
// Persist both the returned result and session before handling an error.
saved := client.WebmasterRegistrationSession()
_ = saved
if err != nil {
	return err
}
if finished.Code != 0 || finished.Errno != 0 || finished.NDUS == "" {
	return fmt.Errorf("registration was not confirmed")
}
_ = referral // Inspect referral.Files and select transfer files explicitly.
```

The APK source is `share`. The Hy flow fetches the captured `/wap/hylogin`
page for PCF/cookies, sends Android passport forms with native psign, and
encrypts the password using the app's RSA scheme. Its password policy is
8–20 characters and at least three character kinds. The mail-code screen uses
four digits. Finish confirms native `data.ndus` and `data.userid` and retains
the same account session on the client.

After saving the account, `RefreshAndroidAppConfig(ctx)` performs the app's
separate native ReportUser request using captured `ReportParams`. It validates
and stores the account's encoded signing key. Refresh failure leaves the
registered account intact and can be retried independently.

Use `TransferWebmasterReferral` to submit a selected native shared-file
transfer. `RegisterFinishWithReferral` is a convenience combination that
returns registration/session state even when the later transfer fails.
Transfer acknowledgement, file-save completion, and Webmaster acquisition
accounting are separate outcomes. The SDK does not assert acquisition credit.
See the [Japanese operational runbook](docs/WEBMASTER_REGISTRATION_RUNBOOK_JA.md).

## Session recovery

JSON-serialize `WebmasterRegistrationSession()` privately. It includes the app
profile, cookies, registration token, native UID/SK, and finish state, including
registrations without a shared link. Restore it onto a fresh client created
with the same captured identity through `RestoreWebmasterRegistrationSession`.
Snapshots without an Android profile are rejected.

A completed or ambiguous Finish attempt blocks repeating registration. Check
the account state and retry only subsequent configuration or transfer work.
A transfer response loss may conceal an accepted task; check the destination
before repeating a `newcopy` transfer. Captcha errors preserve the request ID
and captured Hy page; complete the app's verification with the same session.

## Gold Miner and taskcenter

`MinerPull`, `GoldRecord`, `MinerStart`, `MinerGetItem`, and `MinerFinish`
implement the Gold Miner page opened by the APK. The game's H5 calls use its
actual cookie session and app UA; native Retrofit parameters are not added to
these requests. With a saved SK, finish obtains its `rand` from the verified
native bridge. NDUS-only sessions use the minimal finish query restored from
the working source client and verified on the service, retaining Android
clienttype 1 and the captured app UA.
Game IDs and reward values retain integer precision. Start, item and finish
send one request each, with no alternate parameter combinations or retries.
`MinerQueryVideo` preserves a single video-result poll's data after external
native ad completion; `MinerPuzzleQuery` reads puzzle availability and state.

`QueryGoldwall` and `QueryStartTasks` read taskcenter state through native
`ITaskApi`. `ReportTaskStart`, `ReportTask` and `ReceiveTask` implement the
APK's native operation contracts. A progress report takes an explicit caller
count and uses the APK's `Android_<kind>_<milliseconds>` report ID and MD5/Base64
signature. No task target or advertisement completion is generated by the SDK.

The [Gold Miner request contract](docs/APK_GOLDMINER.md) and
[native task contract](docs/APK_TASKS.md) record the primary protocol evidence.

## HTTP and verification

Result codes must be checked even when a Go error is nil. Prerequisite failures
retain their `APIError.Code`. Caller deadlines and per-request timeouts use the
earlier deadline. API origins are validated before sending credentials;
`WithAPIHost` can explicitly trust a local test server. `WithHTTPClient` copies
client settings while the SDK manages redirects/cookies itself. App transport
errors omit request URLs that might contain captured bridge tokens.

`go test ./...` and `go vet ./...` verify the checked-in APK request replay,
native signing vectors, JSON precision, recovery, and HTTP boundary behavior.
Tests use local/mock transports and do not create live accounts.

The [app request contract](docs/ANDROID_APP.md),
[API evidence](docs/API_NOTES.md), and
[native signing formulas](docs/ANDROID_SIGNING.md) record the inspected
DEX/classes and APK scripts. Both older native and Retrofit request families
remain because this APK uses both.
