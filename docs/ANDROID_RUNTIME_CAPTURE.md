# Capture an existing Android installation

`tools/capture_android_attribution.py` reads one already running guest TeraBox
4.26.5 process (versionCode 699, base SHA-256
`c82a4429bee57e59f45709d358314950e2220191c2c9d774a443242df13cdad8`). It exports the `installations` input accepted
by the local account creator and a separate observation sidecar. It requires
an existing accessible Frida server, Python `frida` and `frida-tools` with the
Java bridge. It neither installs nor starts the application.

```text
python tools/capture_android_attribution.py --help
python tools/capture_android_attribution.py --pid PID --remote 127.0.0.1:27042 --read-play --output PRIVATE_DIRECTORY/installations.json
```

Open the actual guest Hy page before capture. If no WebView remains, supply
its observed URL using `--page-url`; its provenance is recorded as
`operator_observed`. An ambiguous live page selection is not guessed.

The snapshot reads PackageInfo installation time, the existing CUID, native
UA/channel, app locale/model, the cached first-launch decision, and the native
media cache before its getter initializes it. It checks guest account state
before and after collection. Native and legacy common parameter builders are
invoked on inert local requests; no HTTP exchange is made by those builders.
The sidecar names this source `inert_local_request_builder`, rather than
claiming that those query values were observed on a transmitted packet.

`--read-play` queries the actual Play Install Referrer binder service inside
the target process. A returned empty string remains an observed empty string.
An unavailable, disconnected or timed-out service remains absent and receives
no `play_observed` marker. Installation times are milliseconds; native
`firstlaunchtime` remains seconds. Neither is replaced by account creation time.

The sidecar's `installation_lifecycle` is a direct observation for
`NewAndroidInstallationLifecycleState`: guest state, device ID, language, device
time-zone ID, native date pattern/current date, stored logout-report day and
the existing device-activation flag. Optional activation time is not inferred.
The lifecycle SDK requires an explicitly supported IANA zone; an unsupported
raw Android zone is not replaced with the host computer's zone. The capture
does not send either lifecycle report or change either native success flag.

CK getter calls may produce their own app statistics. The collector therefore
does not call them to obtain a value. To capture their natural return values:

```text
python tools/capture_android_attribution.py --pid PID --read-play --observe-ck-seconds 30 --require-ck --output PRIVATE_DIRECTORY/installations-with-ck.json
```

During that bounded observation interval, perform the ordinary app action that
naturally obtains H5/native CK values. `--require-ck` rejects a missing map;
without it, unobserved maps are omitted and the sidecar records the omission.
An actually returned empty map remains distinct from a missing observation.
The collector does not infer a material scene or generate one from the share
owner. The input validator checks profile/build/CUID/cache/time consistency.

Output files are created exclusively, flushed and synced. They contain private
installation state and belong with local session evidence. The console emits
field-status summaries only. Existing files are not replaced. On systems where
mode bits are enforced, files use `0600`; on Windows use a private directory
with the intended account ACL. Captured files are not SDK fixtures and should
not be committed.

The exporter does not prove an install was new, submit an attribution report,
or confirm Webmaster acquisition. A matching runtime capture does not authorize
replaying an HTTP request already performed by the app. Keep its report state
and original result with the same installation when restoring a session.

For a full browser/WebView share-page path, use the separate
[observed browser click adapter](ANDROID_BROWSER_CAPTURE.md). For native
AppsFlyer/Firebase dispatch, use the
[runtime analytics bridge](ANDROID_TELEMETRY.md).

Offline checks:

```text
python -m unittest discover -s tools -p test_capture_android_attribution.py
node --check tools/android_attribution_capture.js
```

The collector's APIs were checked against the supplied APK and its validation
tests run offline. An actual attach on the operator's current device remains
a separate runtime check; the script reports unavailable methods rather than
substituting an unrelated version's profile.
