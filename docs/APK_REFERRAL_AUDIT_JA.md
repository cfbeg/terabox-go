# 4.26.5 共有リンク経由の登録・帰属・登録後通信

2026-10-16 の静的解析に対応した追加機能。今回の検体は split APK を含む
`TeraBox 4.26.5.apk+`。base APK SHA-256 は
`c82a4429bee57e59f45709d358314950e2220191c2c9d774a443242df13cdad8`、
package `com.dubox.drive`、versionCode 699。以前の単体 APK と難読化後の
メソッド位置が異なるため、現在の DEX と同梱 JS を確認している。

## コードで確認した経路

| 段階 | API / 通知 | 主な値・条件 |
|---|---|---|
| 導入帰属 | POST `/api/srn/ins`・`/api/srn/ref` | 空 clipboard、端末・国・言語、導入/初回時刻、実 Play の `referer_data` |
| 共有解決 | GET `/api/shorturlinfo`、必要時 `/share/list` | 共有 ID、共有主 UK、surl、アクセス key |
| 共有履歴 | POST `/rest/receive/report` | `optype=4,scene=2,unikey=surl,origin=0` |
| Hy 登録 | POST `register_v4/sendcode → verify → finish` | `from=share` のとき sendcode に `reg_source=share` |
| 登録成功イベント | `appsflyerReport` → `DevAction.j` | `key=wap_email_register,isReportFb=true` は AppsFlyer + FirebaseAnalytics |
| native account | `sendLoginResults` → `ww.b0.A0` | state、NDUS、UID、region prefix を保持 |
| activation | GET `/api/report/user` | foreground action、timestamp、起動状態、isnew、uinfo/SK |
| 招待・素材 | GET `reportinvite`、POST `userattribute` | 実際の返却 code / 初回起動 + 非空 material scene |
| 自社統計 | POST `/statistics` | gzip userfile を持つ通常の multipart batch |
| 保存 | POST `/share/transfer` → `/api/taskquery`、GET `/api/list` | 受付、task 完了、宛先ファイル存在は別状態 |

共有主 UK、登録者の native UID、自分の account UK、招待 code は異なる値。
`isnew=1`、SK 取得、共有履歴通知、転存完了のいずれも、紹介元の獲得承認を
直接示す値ではない。地域 host はページ origin と返された prefix に従う。

## 追加した SDK 機能

- `WithRequestObserver` / `SetRequestObserver`：native、Hy、共有ページ、資産取得を
  含む transport の before/after 記録。送信前の永続化失敗は送信を停止し、
  送信後の保存失敗は不明結果として返す。認証値・query・本文は記録しない。
- `NewAndroidStatisticsBatch` / `UploadAndroidStatistics`：実際に直列化された
  event batch を、確認した gzip/multipart 形式で送信。送信前・結果の永続化、
  不明結果の自動再送防止、確認成功時の payload 除去に対応。
- `NewAndroidAnalyticsDispatch` / `ExecuteAndroidAnalytics`：同一端末の
  AppsFlyer/Firebase 実 SDK にイベントを渡す。実行器は shell を介さず呼び、
  request ID と端末 ID を照合する。SDK 呼出しとサーバー受理を区別する。
- `ParseAndroidShareClickObservation`：実 browser/WebView のクリック通知を
  query/form/UA/cookie のまま入力へ変換する。Node の CDP 観測器を同梱。
- Android capture exporter：既存 guest process の実 Play referrer、PackageInfo、
  first-launch、CUID、locale/model、native cache、自然発火 CK 値を取り込む。
- `ReportAndroidUnloginActive` / `ReportAndroidDeviceActivation`：実観測した
  guest lifecycle、locale 日付文字列の比較、初回端末 flag を用いた明示 API。
  device 署名は同一 APK process の native 実装で取得し、鍵を推測しない。

詳細と実行例：
[telemetry](ANDROID_TELEMETRY.md)、
[Android capture](ANDROID_RUNTIME_CAPTURE.md)、
[browser observation](ANDROID_BROWSER_CAPTURE.md)。

既存の生成 referrer と実 Play 観測は別 provenance のまま保持する。
外部 SDK の HTTP endpoint、未観測のイベント schema や Webmaster 集計 API は
推測して実装していない。実機での wire と紹介元側の集計照合は別途記録する。

## ローカル creator 側

creator には受付後の read-only task/list 照合、pending の明示、資格情報保持、
登録確認時刻、通信 JSONL、inspect、集計の前後比較を追加した。
creator 本体・保存 session・アカウント一覧・APK・raw 解析物はこの SDK
リポジトリへ公開しない。個別 credit は明示的な承認証拠なしに確定しない。
