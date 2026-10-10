# Android app registration and sharing

`NewAndroidAppClient(AndroidAppProfile, ...Option)` is separate from the default
Web client and the existing opt-in `WithAndroidSigner`. It implements the
Android APK 4.26.5 hybrid email flow and native share request families.

The profile must come from the app runtime. Required fields are `device_id`,
`version`, `user_agent`, `native_channel`, `language`, `client_type` (1), and
`page_url` (an HTTPS TeraBox `/wap/hylogin` URL). Hy `channel` uses the page URL
query's channel, falling back to the captured app User-Agent, as the APK does.
No device ID, country, installation source, or native UID is inferred.

`native_params` contains the complete captured new Retrofit common query map;
`legacy_native_params` contains the older native map used by shorturlinfo and
native psign public-key bootstrap. Device identity and request time are updated
from the profile. Native log IDs are regenerated in the APK's format:
raw standard Base64 of `timeMillis,capturedNonLoopbackIP,random0..999998`.
`ck_data` belongs to Hy query, while `native_ck_data` belongs to native transfer
form fields. These providers are separate even when both maps are empty.

## Registration

The app's `AccountWebViewActivity.getWebUrl()` (classes10.dex code item
`0xbc1d98`) opens `/wap/hylogin/emailRegister?type=1`. The embedded APK screen
`emailRegister.bfe46f32.js` imports its API from `login.409326c5.js`.
That script's `ua`/`Dr`/`Qr`/`en`/`ge` functions produce:

| Stage | Endpoint and additional form fields |
| --- | --- |
| Send | POST `/passport/register_v4/sendcode`: email, op_type=1, choose_email=0, g_identity; prepared referral adds reg_source=share |
| Verify | POST `/passport/register_v4/verify`: token, code, skip_code=0, support_unify=1, g_identity |
| Finish | POST `/passport/register_v4/finish`: token, pwd, g_identity, access_token |

Common form fields include `client=android`, `pass_version=2.8`,
`clientfrom=h5`, PCF token, psign, version, device ID/CUID, and language.
The query preserves app profile parameters, millisecond time, empty zid, and
the explicit Hy rand. Finish does not mechanically copy Web `koltype`,
`first_referer`, or `reg_source`. The Hy Axios defaults explicitly set
`X-Requested-With: XMLHttpRequest`; native share transport does not.

Native psign bootstrap uses POST `/passport/getpubkey` with native passport
version 2.0. It computes
`MD5hex(MD5hex(CUID + "android" + pp3) + pp3)`; the APK's failed/missing pp3
fallback is `dubox`. The captured nonempty cached psign is reused. Hy RSA-key
retrieval is POST with passport version 2.8; existing AES pp1/pp2 decryption
and RSA PKCS#1 v1.5 of `MD5hex(password) + "32"` are reused.

The app password policy is 8–20 characters and at least three character kinds.
The code-entry screen uses four digits. The SDK does not apply the old Web
password rule to the app path.

PCF and cookies come from the captured Hy page. Both `templateData` and
`__INITIAL_STATE__` JSON assignments are parsed. The inspected runtime branch
had no `window.fsec`; its plaintext email branch is supported by the APK.
A detected fsec-initializing page is rejected before sending an email because
its runtime encryption must be captured rather than guessed.

## Native session and recovery

The Hy finish screen copies `response.data.userid` into the `uid` passed to
native `sendLoginResults`. Native `Lww/b0.A0` (classes10.dex `0xc09c08`)
requires nonblank JSON NDUS and UID. The client preserves this NDUS as a cookie
and native UID as profile state. A conflicting response cookie is an error.
Web `CheckLogin.UK` is never converted into the native UID.

`WebmasterRegistrationSession.AndroidApp` preserves the profile and native
identity, including app-only registrations without a share. Save snapshots
after the verification code is sent and before sending Finish, and save the
returned account/session even if later transfer work fails. A fresh ordinary
client can restore the app snapshot with `RestoreWebmasterRegistrationSession`;
the restored client retains the app protocol and cannot repeat an ambiguous or
completed Finish attempt. A Web snapshot cannot be restored onto an app client.

## Three rand families

After first saving the confirmed registration/session, call
`RefreshAndroidAppConfig(ctx)` with captured `report_params`. It sends native
GET `/api/report/user` using the same account's actual UID/NDUS and legacy
common parameters. The captured foreground action is
`ANDROID_ACTIVE_FRONTDESK`; endpoint fields include notification/backup/FCM
state, and the literal `backup_on ` key retains its trailing space. The
timestamp is regenerated for each request. No such preference values are
invented when `report_params` is absent.

An explicit successful errno and nonempty flat `uinfo` provide the account's
encoded SK. The client validates it with `DecodeAndroidSK(nativeUID,uinfo)` and
updates the profile only after validation. Refresh failure preserves the
successful account and its previous configuration. Registration must not be
repeated to obtain a key. This models the APK's separate asynchronous
post-login activation/configuration request.

- Hy passport: missing native SK causes a null Java rand; `JSONObject.put`
  removes the key and JavaScript's `{rand=0}` default emits `rand=0`.
- New native Retrofit: the same unavailable rand is added as a nullable query
  parameter; OkHttp emits a bare `rand` name without an equals sign.
- Old guest shorturlinfo: the legacy wrapper skips signing and emits no rand.

A populated native UID and encoded SK use the existing URLHandler signer.
No empty-secret digest is invented. Native share transfer uses the APK's
query shareid/from/bot_uk and form path/async/fsidlist/ondup; it does not fetch
`/main` or use Web jsToken/bdstoken. Old authenticated native metadata derives
its bdstoken as MD5 hex of NDUS without a Web HTML refresh.

The checked-in `testdata/android_h5_wire.json` was generated by executing the
APK's actual Hy request builders with local bridge and HTTP fixtures. It checks
full query/form shapes with placeholder credentials; ordinary tests make no
live registration calls. Request-shape equivalence, registration success,
transfer acceptance, saved files, and Webmaster acquisition accounting remain
separate results.
