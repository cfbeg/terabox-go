# アプリ共有リンク経由の登録と計上確認

紹介元 A の共有リンクから新規利用者 B がアプリで登録し、A の対象リンクの
New Users 計上までを確認する手順。登録成功、転存受付、保存完了、計上を
それぞれ記録する。

## 紹介元の準備

1. A の [Webmaster センター](https://www.terabox.com/webmaster/index) で、選択中の
   New Users プラン、B の対象地域、当日の料金表を確認する。
2. ファイル共有機能から完全な共有 URL を取得する。照合には専用リンクを使い、
   ドメインや追加パラメーターを手作業で削らない。
3. Sharing history で同じリンク・プラン・集計日の現在値 N0 と確認日時を記録する。
   Reward history の対象日も記録する。
4. 共有 ID・共有主 UK・保存対象のファイル名とサイズを照合する。匿名状態で
   開けないリンクは、A 側で状態を確認してから進む。

公式の [報酬計算説明](https://www.terabox.app/wap/help-center-questions-answer?id=160)
に示されたアプリ導入・新規登録経路を使う。対象地域や金額は A の当日画面で確認する。

## B のアプリ経路

1. A の完全な共有 URL を開き、アプリ導入・アプリで開く導線から対象共有画面へ進む。
2. 初回起動で対象画面へ戻らなかった場合は、登録前に同じ共有 URL を再度アプリで開く。
3. 表示された共有主とファイルを A の記録と照合し、この共有画面から登録する。
4. メール確認や追加確認は同じ登録セッションで完了する。
5. B としてログインできたこと、登録日時、アプリ版、端末種別、登録方法を記録する。

A の NDUS を B に渡さない。パスワード、OTP、NDUS、署名設定値は計上表から分けて
保存する。

## Go SDK で同じ APK の通信を実行する場合

SDK は APK 4.26.5 が使う Hy WebView 登録と native 共有 API を実装する。
捕捉した `AndroidAppProfile` から `NewAndroidAppClient` を作り、同じ Client を使う。
`Source` は `share`。アプリの CUID・UA・版・チャネル・Hy page URL・native 共通値は
実環境で取得したものを使用する。

| 順序 | 操作 | 次へ進む条件 |
| --- | --- | --- |
| 1 | `NewAndroidAppClient(profile)` | B 専用の捕捉済みプロフィール、初期 Session 保存 |
| 2 | `PrepareWebmasterReferral(ctx,url)` | Go エラーなし、共有 ID・共有主・対象ファイルの一致 |
| 3 | メール inbox 準備 | サービスから確認メールを送る前に受信先を準備 |
| 4 | `RegisterSendCode` | Go エラーなし、Code=0、Errno=0、非空 Token、Session 保存 |
| 5 | OTP 待ち→`RegisterVerify` | 同じ Client/Token、Code=0、Errno=0 |
| 6 | Finish 送出前の永続記録 | 「Finish 実行中」をディスクへ保存してから送出 |
| 7 | `RegisterFinish` | 返却結果と Session をエラー処理より先に保存 |
| 8 | `RefreshAndroidAppConfig` | 登録済み成果を保持し、取得成功または未取得状態を保存 |
| 9 | 任意の `TransferWebmasterReferral` | 明示選択 FSID、受付結果と Session を保存 |
| 10 | 保存と A の計上の確認 | 下記の各結果を別々に確認 |

Hy page の PCF・cookie、Android passport form、native psign、RSA password、
native response の NDUS と UID を維持する。UID を共有主 UK や別の確認 API の UK から
推測しない。登録後の鍵取得や転存の失敗で、成功済みアカウントを捨てない。

確認コードの待ち時間を一つの短いネットワーク期限へまとめない。各通信に期限を設け、
OTP 待ちはその専用期限を使う。captcha 応答の RequestID と捕捉済み Hy page を保存し、
同じアプリフローで確認を続ける。

## 保存・復旧

`WebmasterRegistrationSession` はプロフィール、cookie、登録 Token、native UID/SK、
Finish 状態を含む。捕捉した同じ identity の fresh な `NewAndroidAppClient` に
`RestoreWebmasterRegistrationSession` で復元する。

| 保存状態 | 復旧方針 |
| --- | --- |
| Token あり・Finish 未実行 | 保存 Session を復元して確認／Finish へ進む |
| 登録確認済み | 必要な設定取得や転存だけを実行する |
| Finish 実行済み・結果不明 | 同じメールのアカウント状態を確認し、登録を再送しない |
| 転存受付・結果不明 | 保存先と既存処理を確認してから再送を判断する |

`newcopy` の再送は別コピーを作る可能性がある。SDK の task_id は受付を表す。
保存完了は B のアプリのファイル一覧で対象ファイル・サイズ・保存先を確認する。
保存数を New Users の代わりに数えない。

## A 側の計上確認

公式の [更新時間説明](https://www.terabox.app/wap/help-center-questions-answer?id=160)
は前日 GMT+8 の 24:00 までを集計し、13:00～17:00 GMT+8 に報酬データを更新する。
日本時間では 14:00～18:00。登録日時を GMT+8 に換算して集計日を選ぶ。

1. 該当する集計更新後に A の同じ共有リンク・プラン・集計日の New Users 値 N1 を記録する。
2. 比較する N0 と N1 は累計同士か同じ集計日の数値同士とする。
3. 専用リンクの単独流入なら N1−N0>=1 と B の操作日時を照合する。他流入が混ざる場合は
   B 個別の計上を断定しない。
4. Reward history の対象日・プランの状態も確認する。未更新、審査中、対象外はそのまま記録する。

完了は、対象リンク・New Users 指標・集計日・プラン・B の操作記録が対応し、
増加を確認できた時点。収益対象の獲得を目的にする場合は報酬履歴も対象として扱われたことを確認する。

## 記録項目

```text
検証 ID / 紹介元 A / 選択プラン:
共有 URL / 共有 ID / 共有主 UK:
対象地域・当日の料金表:
アプリ版・端末種別・登録方法:
B の共有画面・登録・保存日時と TZ:
GMT+8 集計日:
保存対象・保存先・完了確認:
API 受付 request_id / task_id:
Sharing history 対象リンク・指標:
N0 / N1 / 確認日時・画面更新日時:
Reward history 対象日・プラン・状態:
判定: 計上確認済み / 更新待ち / 対象外 / 未確認
```

通信再現のテスト通過や登録成功を計上結果として記録しない。SDK の具体的な
APK 証拠は [Android app contract](ANDROID_APP.md) と [API notes](API_NOTES.md) にある。
