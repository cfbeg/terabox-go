# APK Gold Miner H5 contract

The APK's Gold Miner is an online H5 game. Its JavaScript is served separately
from the APK; no miner API implementation or `glodminer` page URL is bundled in
the supplied APK's DEX/assets. The SDK uses that official game's request
contract with the captured Android WebView User-Agent and account cookies.

## Primary evidence

The read-only public page fetch used
`https://www.terabox.com/wap/glodminer?show_type=3`. It loaded
`https://s5.teraboxcdn.com/fe-static/wap-goldminer/js/index.7e123511.js`, which
imports `./index.23eaf58e.js` containing the game and API implementation.

| Saved artifact | Bytes | SHA-256 |
|---|---:|---|
| `miner_page.html` | 14264 | `fc9c1e1b1e7020917075723e0651ff01c6126ee9ae79f649b9ab3d01c1e29910` |
| `miner_index.7e123511.js` | 496602 | `a0e1de3e3710667253ec6cd8f321f705ca1a4b2590211d48ea42dc65ab9e261f` |
| `miner_game.index.23eaf58e.js` | 912390 | `4ca6f4a4bcfa8e3ad39a8cce899a724b1c7b9666feff70938880137cd5e3d028` |

Local analysis artifacts and excerpts are in
`C:/Projects/gemini/analysis/coin-miner/h5_contract_evidence.json`. Character
offsets below refer to the UTF-8-decoded game bundle above. Native bridge/signing
evidence comes from `TeraBox_Android_web_v4.26.5.apk` and the SDK's existing
`testdata/android_signature_vectors.json`; see also [ANDROID_APP.md](ANDROID_APP.md).

## Requests and results

Every game endpoint uses GET. Axios sets
`Content-Type: application/x-www-form-urlencoded` and
`X-Requested-With: XMLHttpRequest`. Its request interceptor does not add common
parameters; only calls with `checkRand` receive native bridge values.

| SDK method | Path | Endpoint query | Data fields |
|---|---|---|---|
| `MinerPull` | `/rest/1.0/imact/miner/pull` | none | `free_times_left`, `buy_times_left`, `price` |
| `GoldRecord` | `/rest/1.0/inte/system/getrecord` | none | `can_used_cnt` |
| `MinerStart` | `/rest/1.0/imact/miner/start` | none | `game_id`, `map_id`, `map_info.items` |
| `MinerGetItem` | `/rest/1.0/imact/miner/getitem` | `game_id`, `object_type`, `report_id` | `result` |
| `MinerFinish` | `/rest/1.0/imact/miner/finishgame` | `game_id` plus bridge fields below | `free_times_left`, `buy_times_left`, `price` |
| `MinerQueryVideo` | `/rest/1.0/imact/miner/queryvideo` | `game_id`, `video_type`, and `object_id` for type 0 | raw poll `data` |
| `MinerPuzzleQuery` | `/rest/1.0/imact/puzzle/query` | none | `can_receive` and complete raw puzzle data |

Endpoint wrappers occur at offset 632666 and the home wrappers at 790571. Home
initialization at 791877 calls `HI()` and `GI()` with no arguments. Game start at
805204 calls `e2()` with no arguments. The item call at 801931 sends exactly
three fields and sets `report_id=Date.now()`; plain stones skip this call. The
finish call at 816194 explicitly updates all three allowance/price fields.

The SDK's five methods use a separate H5 transport. The native Retrofit wrapper
would add a different parameter set and does not describe these requests. The
game calls do not use Hy-login tokens, `psign`, `jsToken`, `app_id`, `web`, CK
fields, coordinates or guessed fallback query combinations. The SDK preserves
the captured account cookie session and uses the miner page as its Referer.
No additional page bootstrap is necessary for these five endpoint contracts.

### Finish bridge

At offset 630930, `$3` obtains `getCuid`, `getClientVersion`, `getLang`, then
uses `Date.now()` for `time` and invokes `getRand({timestamp})` and
`getZtoken({eventId:3333})`.

The Android fields are:

```text
game_id=<returned game ID>
devuid=<captured device ID>
cuid=<same captured device ID>
version=<captured bridge version>
clienttype=1
lang=<captured language>
channel=<WebView User-Agent>
time=<decimal Unix milliseconds>
rand=<APK URLHandler signature, or 0 without native SK>
zid=
```

The game's channel builder reads the miner page's `channel` query argument and
otherwise uses `navigator.userAgent`. The SDK's miner page has no such argument,
so it uses the captured WebView UA. A Hy-login profile's channel is a different
page setting and is not used. `getZtoken` returns an empty token in the analyzed
APK. Authenticated `rand` uses the existing URLHandler signing implementation,
captured device/UID/SK/version, account NDUS and the exact request timestamp;
its test compares against a native APK oracle vector.

## Decoding and failure behavior

The H5 wrapper at offset 631886 checks explicit outer `errno`, `code` or
`error_code`. Axios's response `.data` is the HTTP body, not another nested wire
envelope. The SDK requires an explicit integral code and the successful body's
`data`. All methods except the video poll require that data to be an object.
Missing or conflicting codes and malformed/missing required data return
errors. Nonzero codes become `APIError`, whose numeric code remains available
through `errors.As`; untrusted response messages are omitted because they can
echo signed URLs or cookies. Numeric-string integer fields are accepted without
floating-point conversion.

Game/map IDs are preserved as strings, including JSON numeric IDs above 2^53.
Status, gold and reward amounts use checked `int64` conversion. Map objects at
offset 774909 contain `object_type`, `x`, `y`, `rotation`, `multiplier`; the
last two are parsed as finite numeric values even when supplied as strings.

The official reward processor at 799811 reads `data.result.reward_kind`.
Space/gold/VIP/supply quantities use `size`; tool and debris rewards use
`object_id`, and may omit size. Known reward kinds are space 3, supply card 6,
VIP 8, gold 9, debris 10 and tool 100. Tool IDs are bomb 1, extra time 2,
speed 3, protection card 4 and puzzle piece 6. A null result means no reward;
optional integer metadata (`origin`, `expire_day`, `reason_code`) is preserved
when present, without assuming that the game bundle consumes those fields.

Start, getitem and finish send one request each. They do not retry either server
errors or uncertain transport outcomes, and never replay with alternate query
parameters. Callers must retain the game ID when resolving an uncertain result.

## Rewarded ads

At offset 632981,
`pd` invokes native `showSignInRewardAd` with `placement` and `custom_data`,
checks `isSuccess`, and only then polls `queryvideo`. Queryvideo itself is not
proof that an ad completed. The SDK does not implement that native ad operation
or automatic puzzle redemption.

`MinerQueryVideo(ctx, gameID, videoType, objectID)` performs one poll with the
H5's exact query fields. The verified calls use type 0 with a positive tool ID
at 797436, type 1 without an object ID at 817526, and type 2 without an object
ID at 809068. Type 0/1 callers only check data truthiness; type 2 reads
`reward_kind` and `size`. `MinerQueryVideoResponse.Data` therefore preserves
the raw JSON value, including `null` while pending, without imposing an
unverified schema or inferring completion. Missing data still fails. There is
no automatic polling, native callback simulation or ad report in this method.

`MinerPuzzleQuery(ctx)` sends an empty query. The home call at 792402 consumes
`can_receive`; the puzzle popup at 869801 also consumes `puzzles[].count`,
`puzzles[].img`, `end_time` and `reward.size`. Its result exposes checked
`CanReceive` (boolean or numeric 0/1) and raw `Data`, preserving all other
fields and integer precision. It does not invoke `/imact/puzzle/receive`.

## Validation

`goldminer_test.go` uses local HTTP fixtures for all seven requests, exact empty
and three-field queries, captured cookies/UA, bridge fields/signature, numeric
and numeric-string IDs above 2^53, finite map values, optional tool quantity,
malformed/missing data, error-code preservation, response redaction and absence
of mutation retries. Additional fixtures cover the three video types, null poll
data, raw reward precision, puzzle availability and invalid query inputs.
Fixtures do not execute games, tasks or ads on the service.

```sh
go test ./...
go vet ./...
```
