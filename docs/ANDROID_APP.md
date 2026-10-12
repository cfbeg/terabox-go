# Android app protocol

`NewAndroidAppClient(AndroidAppProfile, ...Option)` is the SDK constructor.
It implements the Android APK 4.26.5 hybrid email flow and native account/share
request families from the app's captured runtime identity.

Required profile fields are `device_id`, `version`, `user_agent`,
`native_channel`, `language`, `client_type` (1), and an HTTPS TeraBox Hy
`page_url`. Hy `channel` uses the page URL's channel or the captured UA.
Guest UID and encoded SK may be empty. No device ID, installation source,
country or native UID is generated or inferred.

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
They retain the actual installation identity, preserve server responses in saved
sessions, and apply only confirmed first-launch media to native requests.

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

PCF and cookies come from the captured Hy page's `templateData` or
`__INITIAL_STATE__`. The inspected runtime had no `window.fsec`, whose
plaintext email branch is explicitly supported in the APK. An initializing
fsec page is rejected until its runtime encryptor has been captured.

Native psign retrieval uses POST `/passport/getpubkey`, passport version 2.0.
It computes `MD5hex(MD5hex(CUID+"android"+pp3)+pp3)`; missing/failed pp3 uses
the APK fallback `dubox`. Hy RSA public-key retrieval is POST with version
2.8. Password encryption is RSA PKCS#1 v1.5 of `MD5hex(password)+"32"`, using
the AES-decoded pp1/pp2 public key. The app policy is 8–20 characters and three
character kinds; the verification screen uses four digits.

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
verification UI and the same session.

## Post-login configuration and sharing

After persisting the successful account, `RefreshAndroidAppConfig(ctx)` sends
the separate native GET `/api/report/user` using that account's UID/NDUS and
captured `report_params`. The foreground action is ANDROID_ACTIVE_FRONTDESK.
Notification/backup/FCM state is captured; the `backup_on ` key retains its
trailing space. Request timestamp is refreshed. Explicit errno=0 and nonempty
flat uinfo are required; the encoded key is checked under the native UID.
Failure leaves account/session/previous configuration intact.

The older authenticated native base derives bdstoken as lowercase MD5 of NDUS.
Retrofit sharing uses its own common fields and form conventions. Native
transfer query is shareid/from/bot_uk; its form is path/async/fsidlist/ondup
plus native CK fields. Task acceptance remains distinct from saved-file
completion and Webmaster acquisition accounting.

## Three APK rand families

- Hy passport: missing native rand is removed by JSONObject.put; JS defaults
  it to zero and emits rand=0.
- New Retrofit: a nullable rand becomes a bare query name without an equals sign.
- Older guest native: the wrapper skips signing and emits no rand.

Configured native UID/SK use the verified URLHandler digest. The checked-in
`testdata/android_h5_wire.json` was generated by executing the actual APK
JavaScript builders with local bridge/HTTP fixtures. Tests cover exact shapes,
native signing, integer precision, and account recovery without live signup.
