# Android app protocol

`NewAndroidAppClient(AndroidAppProfile, ...Option)` is the SDK constructor.
It implements the Android APK 4.26.5 hybrid email flow and native account/share
request families from the app's captured runtime identity.

Required profile fields are `device_id`, `version`, `user_agent`,
`native_channel`, `language`, `client_type` (1), and an HTTPS TeraBox Hy
`page_url`. Hy `channel` uses the page URL's channel or the captured UA.
Guest UID and encoded SK may be empty. The constructor uses the supplied
identity. The separate `NewAndroidGuestProfile` factory creates a virtual
installation profile; it does not create an actual Play installation/referrer
or infer a native account UID.

`native_params` contains the captured Retrofit common query map;
`legacy_native_params` contains the older native map used by shorturlinfo,
native public-key bootstrap and ReportUser. Both are actual APK request
families. Per-request identity/time are refreshed from the profile. The native
builders obtain `startDevTime` from currentTimeMillis for every request;
`firstlaunchtime` remains the installation's cached first-launch seconds. Native
log IDs are raw standard Base64 of
`timeMillis,capturedNonLoopbackIP,random0..999998`.
Hy `ck_data` and transfer `native_ck_data` belong to separate native providers.

Observed shared-page click and Android installation/referrer attribution can
be imported or explicitly reported with the [capture APIs](ANDROID_ATTRIBUTION.md).
They retain the actual installation identity and preserve server responses in
sessions. Stored attribution and the effective native process media cache are
preserved separately; a returned media value does not immediately overwrite
an already initialized native common value.

## Hy registration and login

`AccountWebViewActivity.getWebUrl()` (classes10.dex `0xbc1d98`) opens
`/wap/hylogin/emailRegister?type=1`. The embedded APK screen imports the
API from `login.409326c5.js`. Its `ua`/`Dr`/`Qr`/`en`/`ge` builders supply:

| Request | Additional form fields |
| --- | --- |
| POST `/passport/register_v4/sendcode` | email, op_type=1, choose_email=0, g_identity; shared entry adds reg_source=share |
| POST `/passport/register_v4/verify` | token, code, skip_code=0, support_unify=1, g_identity |
| POST `/passport/register_v4/finish` | token, pwd, g_identity, access_token |

Common form fields are client=android, pass_version=2.8, clientfrom=h5,
PCF token, psign, version, device ID/CUID and language. Common query uses
the active page's channel or UA, native client type, app_id=250528, millisecond time, empty
zid, page jsToken and explicit Hy rand. Only SendCode carries source=share;
Finish does not copy it. Hy Axios explicitly sets
`X-Requested-With: XMLHttpRequest` and URL-encoded form content type.

The UI changes the active document after a successful SendCode to
`/wap/hylogin/emailVerfify`, retaining only an existing `from` query. After
successful Verify it opens `/wap/hylogin/emailRegister?type=2&showDoublePwd=1`,
retaining an existing redirectUrl. The initial channel/device/logId/wapFrom
query is not copied to these router pushes. The bridge still supplies the same
CUID/version/language; `channel` is recomputed from each active URL or the UA.
The SDK follows these transitions for query channel and Referer while keeping
the same PCF/cookie state. It does not fetch another Hy page on navigation.

PCF follows the APK's `wa()` selection: nonempty `__INITIAL_STATE__.pcftoken`
precedes `templateData.pcftoken`, regardless of their assignment order. Hy
`jsToken` follows `Dr()` and comes from the actual `window.jsToken` global,
including an observed top-level `var jsToken` literal; a similarly named field
inside either state object is not its source. Simple literals use the bounded
static decoder. Dynamic globals and FSEC bootstrap use the Go `goja` runtime
to execute the observed synchronous bootstrap sources. Runtime source and
random/time/entropy inputs are saved in `hy_runtime` for identity-bound replay.
Redirect cookies replace/delete previous names in a
request-local copy; cookies and bootstrap state are committed together after a
valid final page. The saved `hy_js_token` retains the actual global token;
older sessions without that field keep the empty default.

When the actual page defines `window.fsec.encrypt`, the runtime executes the
APK branch `fsec.encrypt(email).slice(8)`. With no FSEC object, the verified
plaintext branch remains active. Referenced FSEC assets are fetched only from
HTTPS `terabox.com` or `teraboxcdn.com` and their subdomains, with source-size and execution
bounds. The runtime supports synchronous bootstrap globals and the observed
encryptor, and rejects unobserved browser dependencies such as network APIs,
timers, DOM fingerprinting and native bridges. It does not execute the full
application or CAPTCHA UI. The SDK uses its pinned Go `goja` dependency; no
external browser or Node process is required. Synthetic runtime tests cover
dynamic tokens/FSEC and restoration. FSEC-active registration has not been
observed in the live account test.

Native psign retrieval uses POST `/passport/getpubkey`, passport version 2.0.
It computes `MD5hex(MD5hex(CUID+"android"+pp3)+pp3)`; missing/failed pp3 uses
the APK fallback `dubox`. Hy RSA public-key retrieval is POST with version
2.8. Password encryption is RSA PKCS#1 v1.5 of `MD5hex(password)+"32"`, using
the AES-decoded pp1/pp2 public key. The actual UI policy requires 8–20 printable
ASCII characters (`!` through `~`) including all three kinds: letters, digits,
and symbols. Uppercase/lowercase letters belong to one kind. Spaces, controls,
and non-ASCII characters fail the UI policy. The verification screen uses four
digits.

Hy password login uses the native `loginInfoEncrypt` bridge. Dispatcher
`Lww/b0.______` calls `e0` at `0xc0c918`; `e0` (`0xc0b3e8`) returns MD5 hex of
`seval-email-encryptedPwd-random-timestamp-devuid-android`.

## Account and recovery

Finish's `data.ndus` and `data.userid` are passed to native `sendLoginResults`.
`Lww/b0.A0` (`0xc09c08`) requires both and persists them through `Account.T`.
The SDK stores NDUS as a cookie, checks any returned cookie for consistency,
and stores the native UID separately. A share/account UK is never converted
into native UID.

The successful native callback also applies `region_domain_prefix` through
`ek.____.T(null,prefix)`: `www` selects `https://terabox.com`, other region
labels select `https://<prefix>.terabox.com`. The SDK applies validated labels
after preserving the account, and retains the resulting API origin in the
session. Captured Hy URLs and explicit custom fixture origins remain intact.
Invalid optional region metadata cannot undo a confirmed account.

`WebmasterRegistrationSession.AndroidApp` retains the profile, cookies,
registration token, native identity and finish state even without a referral.
Restore it on a fresh `NewAndroidAppClient` with the same captured identity.
A session lacking an app profile is rejected. A completed or ambiguous Finish
cannot be repeated; retry only subsequent configuration or transfer work.
Captcha results retain RequestID and the captured Hy page for the app's
verification UI and the same session. `SetAndroidChallengeIdentity` accepts
an actually completed identity matching that request; it does not generate a
challenge token. Runtime snapshots and challenge state also survive restore.

## Post-login configuration and sharing

After persisting the successful account, `RefreshAndroidAppConfig(ctx)` sends
the separate native GET `/api/report/user` using that account's UID/NDUS and
captured `report_params`. The foreground action is ANDROID_ACTIVE_FRONTDESK.
Notification/backup/FCM state is captured; the `backup_on ` key retains its
trailing space. Request timestamp is refreshed. Explicit errno=0 and nonempty
flat uinfo are required; the encoded key is checked under the native UID.
Failure leaves account/session/previous configuration intact.

The older authenticated native base derives bdstoken as lowercase MD5 of NDUS:
GET carries it in the query, POST in the endpoint form. `TransferShare` supports
the Retrofit MultiShareList branch and the explicit `share_detail_legacy`
route, whose file-ID array contains strings and whose common transport differs.
Its query uses shareid/from/bot_uk and observed optional sekey; the form carries
path/async/fsidlist/ondup plus the relevant native checks. `ReportShareView`
reproduces `POST /rest/receive/report` with its received-link JSON body and
skips actual Hive/history/self entries. Task acknowledgement remains distinct
from saved-file existence and Webmaster acquisition accounting.

`ReportAndroidPostLoginAttribution` sends invite code only from a confirmed
nonempty referrer result, and material fields only from an actually observed
first-launch scene. Own UID/NDUS/SK and saved per-report outcomes bind those
requests to the account. Media storage is separate from
`RequestCommonParams.c()`'s process cache; the extracted getter was replayed
offline. See [attribution state](ANDROID_ATTRIBUTION.md) for the exact fields.

The Hy SendCode source follows the active page's `from=share`, independently of
locally saved shared-link metadata. Callers may explicitly select that known UI
entry branch. The native producer of this exact route has not been identified;
a shared owner, `upload_log` and Play InstallReferrer are separate inputs.

## Three APK rand families

- Hy passport: missing native rand is removed by JSONObject.put; JS defaults
  it to zero and emits rand=0.
- New Retrofit: a nullable rand becomes a bare query name without an equals sign.
- Older guest native: the wrapper skips signing and emits no rand.

Configured native UID/SK use the verified URLHandler digest. The checked-in
`testdata/android_h5_wire.json` was generated by executing the actual APK
JavaScript builders with local bridge/HTTP fixtures. Tests cover exact shapes,
native signing, integer precision, and account recovery without live signup.
