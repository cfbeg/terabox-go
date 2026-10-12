# Android shared-screen operations

These APIs reproduce verified paths in TeraBox Android 4.26.5. They distinguish
the ordinary `share_detail` screen's legacy native implementation from the
Retrofit implementation used by other APK share screens. Neither an API
acknowledgement nor a completed file copy establishes referral credit or rewards.

## Report the observed shared-screen entry

`ReportShareView(ctx, &ShareViewOptions{OwnerUK: owner, ShareURL: actualURL,
ChainSURL: normalizedKey})` sends the received-link history operation to
`POST /rest/receive/report` with this native JSON body:

```json
{"list":[{"optype":4,"scene":2,"unikey":"<actual normalized key>"}],"origin":0}
```

It skips entries explicitly marked `FromHive` or `FromReceivedList`, and excludes
self shares by comparing the owner UK to an observed account UK. The native
signing UID is a different value and is never used for that comparison. Guests
use account UK zero. Authenticated callers must supply `AccountUK` from actual
account metadata or explicitly call `CheckLogin` first to cache a verified UK.
The reporting method does not perform account checks or login on its own.

`ChainSURL` is already normalized. A leading `1` in that value belongs to the
key and is retained. If only `ShareURL` is supplied, `ParseShareURL` obtains the
key. When both fields are supplied, they must identify the same share. Response
fields preserve HTTP status, server result and raw JSON; excluded entries have
`Skipped` and a `SkipReason`. No ambiguous side effect is automatically retried.

## Save from the ordinary shared screen

```go
result, err := client.TransferShare(ctx, shareID, ownerUK, selectedFSIDs, "/", &terabox.ShareTransferOptions{
    Route: terabox.ShareTransferRouteShareDetailLegacy,
    OnDup: "newcopy",
})
```

That route follows `ln.__.B`: a string JSON array for `fsidlist`, legacy common
parameters, observed native check fields, and an NDUS hash in the POST form.
An optional `SEKey` is an observed native share access key, decoded and encoded
the same way as the native caller. The normal external entry has an empty
`bot_uk`; Webmaster owner UK is not substituted for it. No `wm_token` is sent.

The empty route keeps the existing APK Retrofit contract for compatibility:
`List<Long>.toString()` selection and the new native common request builder.
Both routes are APK implementations. `taskid` and `task_id` are normalized to
`TaskID`; their conflicting simultaneous values are rejected. Synchronous legacy
`info[]` results are preserved and their first per-file error is surfaced.

## Verify asynchronous completion

`QueryShareTransferTask(ctx, taskID)` makes one ordinary native status request:
`POST /api/taskquery?taskid=...`, with `filelist=[{}]` and a native POST NDUS hash.
The empty object comes from the APK callback's null optional retry arguments,
not from a fabricated file selection. `Completed()` requires `status=success`,
no task or per-file error, and a nonempty result list. `pending` and `running`
are not completion.

`ListFiles(ctx, directory, options)` reads `/api/list` through the legacy native
GET path. Listing options include zero-based `Start`, `Limit`, `Order`,
`Descending`, `Preset` and an observed `SecretToken`. SDK defaults are a
100-entry name-ordered page. Compare returned destination paths, file IDs and
metadata with the expected copied files. Neither helper logs in or obtains new
credentials. Both require an existing NDUS.

## APK evidence

The wire fixture `testdata/android_share_detail_wire.json` names each source
class and code item. The inspected APK SHA-256 is
`73340b723c45cca9bb44289b1ca3ea2e5e207f4af406a6970bb2ef1badf7f696`.

- Received-link entry: `ChainInfoViewModel.h` -> `h30.t1` -> server `_.l0`;
  body defaults are `optype=4`, `scene=2`, `origin=0`.
- Self-share identity: `Account.B` -> `hf._.h` -> `AccountInfo.uk`, distinct
  from `AccountInfo.uid`.
- Save: `NewFileListInfoFragment.saveCloudFiles` -> `ShareFileOpPresenter` ->
  `cloudfile.service.b0.q` -> `ln.__.B` (`classes12.dex`, `0xdf8800`).
- Poll: `b0.b` (`0xabfd48`, six null arguments at `+0x134..+0x13e`) ->
  `service.___.h` -> `g` -> `ln.__.u` (`0xdf9708`).
- Results: `mn.e` uses `ManageResponse.taskid`, with Gson alternate `task_id`,
  and per-file `info[]`; `mn.b` parses `FileManagerTaskResponse`.
- Listing: `ln.__.p` (`classes12.dex`, `0xdf920c`).
