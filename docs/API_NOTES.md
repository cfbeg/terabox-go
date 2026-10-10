# API verification notes

## Sources and scope

The Android analysis report `terabox_apk_analysis_report.md` and its sample
`TeraBox_Android_web_v4.26.5.apk` were checked against bytecode, embedded H5
JavaScript, the current public Web application, and this Go client's existing
Web requests. The APK manifest declares version `4.26.5` (code `699`).

Current first-party Web sources:

- [Share API wrapper](https://s5.teraboxcdn.com/fe-static/fe-v5-web-share/js/share.mhw2uil5.js)
- [Shared-link page](https://s5.teraboxcdn.com/fe-static/fe-v5-web-share/js/shareLink.kax0xevo.js)
- [Passport and registration wrapper](https://s5.teraboxcdn.com/fe-static/fe-v5-web-share/js/index.ck9924y1.js)
- [Shared-page login dialog](https://s5.teraboxcdn.com/fe-static/fe-v5-web-share/js/index.lhdcm7oe.js)

These assets are observations of a private Web protocol, not an Open Platform
stability contract. Their hash-named URLs identify the implementation inspected.
Account creation and actual file transfers were tested with mock transports;
no live registration or transfer was performed for this change.

## Shared links and registration

| Operation | Observed Web contract used by this client |
| --- | --- |
| Parse link | `/s/1<key>` strips one leading `1`; `/sharing/link?surl=<key>` already contains a normalized key. |
| Metadata | `GET /api/shorturlinfo`, `shorturl=1<key>`, `root=1`, `scene=`. |
| Root file list | `GET /share/list`, `shorturl=<key>`, `root=1`, `page`, `num`, `by`, `order`. No authenticated token is required by the client for a public read. |
| Owner/share identifiers | `shareid` or `share_id`, and `uk` or `uk_str`; string identifiers retain integer precision. |
| Registration source | The shared-page dialog defaults to `from=share`. Sendcode and finish carry `reg_source=share` in both query and form; `first_referer` is a hostname in the form. |
| Conditional source | `PrepareWebmasterReferralWithOptions` can select `web_share`: sendcode maps `reg_source` to `share` with `koltype=1`; finish uses `reg_source=web_share` without `koltype`. `web_share_videoplay` maps sendcode to `share` with `koltype=0` and retains its source for finish. The default source is `share`, with sendcode `koltype=0`. |
| Transfer | `POST /share/transfer`; query has `shareid`, `from`, `ondup`, `async=1`; form has `fsidlist` as JSON and `path`. |
| Transfer acknowledgement | Positive `task_id` represents an asynchronous task; `extra.list` can represent a direct result. Neither proves webmaster credit. |

Anonymous GET checks of the report's example showed `shorturlinfo` returning
`errno=400210` (`need verify_v2`) while `share/list` returned share identifiers
and a file list. `PrepareWebmasterReferral` uses that public-list fallback only
for code `400210`; other API failures retain their original code.

The report's `/share/info?surl=...` did not resolve a normal file share: a public
Web GET returned an HTML error page. In the APK, `classes14.dex`,
`com.dubux.drive.listennote.server.IApi`, the `GET("share/info")` annotation has
`shareuk` and `speechid` parameters and belongs to an AI transcription feature.
The adjacent `GET("share/transfer")` uses `shareuk`, `speechid`, `is_demo`, and
a query map. Those are separate from normal file-share APIs.

The APK's normal share flow is visible in
`assets/offlineh5/agent/fe-static/fe-v5-wap-ai-index/js/history-result.d963648e.js`.
It obtains normal files through `/share/list` and transfers them through the
normal POST `/share/transfer`. Its `scene=purchased_list` belongs to that AI
purchase-list workflow and is not copied into the general referral transfer.

`extra_params_key_share_from_surl` and `extra_params_key_webmaster_uk` occur in
`classes13.dex` in `NewFileListInfoFragment.extraParams_delegate$lambda$18`.
They are consumed by video/advertising code, including
`VideoPlayerCActivity.initExtraParams` in `classes14.dex`. They do not establish
passport form or Cookie field names. This client preserves their conceptual
values locally and uses the registration fields observed in the Web client.

The report's acquisition-count timing was not independently confirmed. The
implemented workflow prepares attribution, creates an account through the
existing email steps, and submits the caller-selected transfer; it exposes
server responses without claiming a count was credited.

## Existing authentication and upload APIs

The existing client uses the Web/desktop protocol. The APK's native Android
transport is a separate surface:

- Embedded H5 authentication still uses passport version `2.8`, RSA PKCS#1 v1.5
  with the MD5 password preprocessing, and the `pp1`/`pp2` AES public-key scheme.
  These match this client's existing crypto handling.
- H5 obtains `psign` through a native bridge with a `0` fallback, chooses a
  client label according to its UA, and optionally encrypts email when
  `window.fsec` is available. It also explicitly supports plain email. These
  observations do not establish that the existing `client=web` flow was removed.
- Android `app_id=16892322` with `is_hidden=1` is conditional on backup/hidden
  operations. It is not a replacement for regular `app_id=250528` requests.
- Native precreate/rapidupload uses `/rest/2.0/pcs/file` and native chunk uploads
  can use `partoffset` and `type=tmpfile`. This does not invalidate Web
  `/api/precreate`, `/api/rapidupload`, or the `uploadid`/`partseq` chunk flow.
- The report's native URL-signature model does not contain a fully verified
  secret-key derivation. It is not applied to Web requests as an invented
  signature implementation. Native RC4 block-list handling is also not imposed
  on the existing Web precreate method.
- The APK version alone does not establish the `version` parameter accepted by
  `/rest/recent/listall`. Its existing value is retained; the desktop UA is
  independent of that query parameter.

No authenticated Web endpoint deprecation or breaking contract change was
confirmed from the Android analysis. The applied additions therefore use the
verified current share and registration-source contracts while preserving
ordinary authentication and upload behavior.
