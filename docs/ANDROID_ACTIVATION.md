# Android ReportUser state

`RefreshAndroidAppConfig(ctx)` is an explicit configuration/SK refresh. It
always requests `/api/report/user` with the captured foreground parameters,
even when an activation has already succeeded that day. Persist the registered
account before this request.

`SendAndroidAppActivation(ctx, policy)` applies the APK's scheduled activation
guard. It returns `Attempted` for an HTTP attempt or `Skipped` when the same
account and action already succeeded on the device's current calendar day.
`policy.Action` can select one of the observed foreground/background actions;
omitting it retains the profile's captured action. It never generates lifecycle
suffixes or UI events.

```go
result, err := client.SendAndroidAppActivation(ctx, &terabox.AndroidActivationPolicy{
    TimeZone: "Asia/Tokyo", // The actual device's zone.
})
```

`ConfigValue` is the captured `start_config` preferences value `c`. The APK's
default is 6. Values >= 5 use millisecond timestamp storage; lower values use
`yyMMdd` date storage. Both guards compare calendar days in the device's time
zone. Timestamp mode does not mean a rolling 24-hour interval. With no explicit
value the client keeps the restored storage mode, or defaults to the APK's 6
for a new account session. Supply `TimeZone` when the device's time zone differs
from the Go process; an omitted value preserves the restored zone or uses
`time.Local`.

Only a successful response with a valid nonempty `uinfo` is committed. The
consumer saves SK and updates `isnew=0` to old-user state (`needrookie` omitted
on subsequent requests); `isnew=1` requests `needrookie=1`. Absent, null, -1,
and other values preserve the previous state. It then removes the one-use
`source`, `msg_id`, and private push-message timestamp while retaining
`channel_id` and `bind_uid`. `mediainfo` is saved when its `videourl` is nonempty,
as in the APK; Go stores the data without Android UI broadcasts.

`AndroidAppProfile.Activation` is private, native-UID-bound state. Profile and
registration-session snapshots deep-copy it; JSON round trips retain the
calendar guard. A state belonging to a different UID is rejected. Fresh guest
profiles remove it together with old account credentials. Invalid responses do
not partially update the profile, SK, pending fields, or activation records.

The source is the installed Google Play 4.26.5 APK (code 699):

- `i40._.__`, `classes13.dex`, code item `0x51f204`: `isnew`, per-action records,
  successful parser state, logout exclusion.
- `h40.______.b`, `classes13.dex`, `0x51bd88`: SK and pending-field cleanup,
  `mediainfo` consumer.
- `gv.z.u0`, `classes12.dex`, `0x50b054`: same year and day-of-year comparison.
- `gv.z.B`, `classes12.dex`, `0x50b46c`: `yyMMdd` formatting.
- `com.dubox.drive.util.wh.d`, `classes14.dex`, `0x3b5bd4`: config threshold 5.
- `com.dubox.drive.util.wh._____`, `classes14.dex`, `0x3b5c54`: `start_config/c`
  and default value 6.

These state transitions use the existing ReportUser request. They are not an
additional referral-reporting endpoint or evidence of dashboard credit.
