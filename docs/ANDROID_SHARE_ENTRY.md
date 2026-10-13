# First-launch shared entry and authenticated revisit

After a confirmed `/api/srn/ref` response, call
`StageAndroidFirstLaunchShareEntry(expectedReferral)` to validate the returned
share-detail identifiers and randsk against the prepared share. Persist the
session, then call `DispatchAndroidFirstLaunchShareEntry()` and persist again.
The pending event is consumed once and `deep_value_jumped` is retained. Neither
method sends HTTP. Unsupported routes and incomplete legacy metadata are
recorded without dispatch; they do not invent missing share inputs.

Once registration and native signing configuration succeed, `CheckLogin`
obtains the account's own UK. This UK is distinct from the native signing UID
and the share owner's UK. Use it with `ReportAndroidAuthenticatedShareEntry`
to open a separate authenticated entry. Its `BeforeSend` callback receives the
attempted session and must durably save it before the notification is sent.

The authenticated entry calls the existing `/rest/receive/report` contract.
It preserves any earlier guest notification and records its own outcome under
`AndroidAttribution.ShareEntry.Authenticated`. Captures, installation CUID,
account UID/UK and NDUS digest bind this journal to its original inputs.
Successes return their saved response; failed or uncertain attempts prohibit
implicit replay after restoration. Hive, received-history and self-share
entries are excluded.

This is a new authenticated shared-screen event. It does not claim that the
APK automatically retries a guest notification after login. The first-launch
pending/dispatch contract was extracted from the real Play APK 4.26.5:
`aw.b.t`, `pu._`, and `MergeWapAndAFLaunch`. Received-link reporting is separate
from registration and from Webmaster acquisition-credit confirmation.
