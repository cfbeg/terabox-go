# Android APK API evidence

The SDK implements the request families found in the supplied
`TeraBox_Android_web_v4.26.5.apk`, SHA-256
`73340b723c45cca9bb44289b1ca3ea2e5e207f4af406a6970bb2ef1badf7f696`.
Its manifest version is 4.26.5, code 699. The primary evidence is DEX/native
instructions and the JavaScript embedded in this APK.

## Registration and login

`classes10.dex`, `AccountWebViewActivity.getWebUrl`, code item `0xbc1d98`,
opens `/wap/hylogin/emailRegister?type=1`. The embedded screen imports the
API from `assets/offlineh5/login32/fe-static/fe-v5-wap-login/js/login.409326c5.js`.
Its `ua`/`Dr`/`Qr`/`en`/`ge` request builders supply native bridge identity,
millisecond time, PCF, psign, and Android passport forms.

| Operation | APK request |
| --- | --- |
| Hy sendcode | POST `/passport/register_v4/sendcode`, email, op_type=1, choose_email, g_identity; shared-entry source=share in form |
| Hy verify | POST `/passport/register_v4/verify`, token, code, skip_code=0, support_unify=1, g_identity |
| Hy finish | POST `/passport/register_v4/finish`, token, RSA pwd, g_identity, access_token |
| Native psign bootstrap | POST `/passport/getpubkey`, client=android/pass_version=2.0/devuid/psign; response pp3 |
| Hy RSA public key | POST `/passport/getpubkey`, Android passport version 2.8 plus Hy common query/form |
| Password prelogin/login | POST `/passport/prelogin` and `/passport/login`, app bridge prand and encrypted password |

The Hy email API sends plaintext email when `window.fsec` is absent. When it
exists, the APK uses `fsec.encrypt(value).slice(8)` and `fs-ex-st:1`.
An initializing fsec page is rejected until that runtime encryptor is known.
PCF comes from the actual Hy page's `templateData` or `__INITIAL_STATE__`.

Hy login `loginInfoEncrypt` is dispatched by `Lww/b0.______` at `0xc0c918`
to `e0`, code item `0xc0b3e8`. It returns
`MD5hex(seval-email-encryptedPwd-random-timestamp-devuid-android)`.
Password RSA encrypts `MD5hex(password)+"32"` with PKCS#1 v1.5.

`Lww/b0.A0`, `0xc09c08`, consumes finish JSON NDUS and native UID;
`p0`, `0xc0beb4`, persists the native account. The introducing share owner's
UK and account-check UK are not native UID sources.

## Shared files

| Operation | APK request |
| --- | --- |
| Old native shorturlinfo | GET `/api/shorturlinfo`, type=0, root=1, shorturl=1+normalizedKey, bot_uk |
| Native root list | GET `/share/list`, normalized shorturl, zero-based page, num=100, root=1, dir, timestamp(seconds), scene, bot_uk |
| Native transfer | POST `/share/transfer`; query shareid/from/bot_uk; form path/async/fsidlist/ondup/native CK FieldMap |

Shorturlinfo evidence: `classes13.dex L l30/_.h`, `0xdc9498`.
Retrofit list/transfer annotation evidence: `IApi.k/m`, `0x5483aa`, and
`IApi.d`, `0x52f341`. Initial root-list caller
`MultiShareListViewModel.y`, `0xc2fa7c`, uses page 0, num 100, root 1,
empty dir/scene. Transfers use Java `List.toString()` serialization for FSIDs.

Native UA and request headers come from the app. Native metadata/transfer
do not request a browser main page or depend on its JavaScript token.
Share response identifiers and FileEntry numeric fields accept JSON numbers
or numeric strings without float conversion.

## Post-login configuration

After persisting the successful account, `sendLoginResults` triggers
`h40.__.e`, `0xdb020c`, with `ANDROID_ACTIVE_FRONTDESK`. It schedules a
separate GET `/api/report/user`, constructed by `h40._.h`, `0xdafc10`.
Captured endpoint fields include timestamp, action, optional attribution/FCM,
notification state, and the literal `backup_on ` field with a trailing space.
Flat response `uinfo` is the account's encoded SK, decoded under its native UID.
Failure leaves the successful registration intact.

The older authenticated native base derives bdstoken as lowercase MD5 of
UTF-8 NDUS (`Llj/_.<init>`, `0xd5e6b4`). Retrofit transfer does not use that
parameter. Older native and new Retrofit common query maps are captured
separately; the SDK preserves their distinct app_id/AB/header conventions.

## Signing families and reproduction

Hy passport emits rand=0 when the native getter returns no rand. Older guest
native requests omit rand. New Retrofit retains OkHttp's nullable bare rand
parameter. With a configured native UID/SK, URLHandler computes the verified
native digest. See [Android signing](ANDROID_SIGNING.md).

`testdata/android_h5_wire.json` comes from running the APK's actual JavaScript
request builders with local bridge/HTTP fixtures. The upstream Go tests assert
those full request shapes and registration recovery boundaries. See
[Android app protocol](ANDROID_APP.md) for configuration and lifecycle details.
