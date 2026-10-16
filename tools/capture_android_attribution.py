"""Collect an existing APK 4.26.5 guest installation through Frida.

Writes a private creator-compatible installation pool and an observation
sidecar. --read-play queries the Play binder service inside the target process;
it does not register an account or send TeraBox attribution reports.
"""
import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus, urlparse

REVIEWED_BASE_SHA256 = "c82a4429bee57e59f45709d358314950e2220191c2c9d774a443242df13cdad8"

class CaptureError(Exception):
    pass


def _object(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise CaptureError("invalid capture object fields")


def _valid_strings(value):
    if isinstance(value, str):
        return not any(ord(ch) < 32 or ord(ch) == 127 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _valid_strings(k) and _valid_strings(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_valid_strings(v) for v in value)
    return value is None or type(value) in (bool, int)


def validate_snapshot(raw, require_ck=False):
    """Fail closed before labelling a process snapshot as an installation."""
    if not isinstance(raw, dict) or set(raw) != {"android_profile", "capture", "observation"}:
        raise CaptureError("invalid capture schema")
    if not _valid_strings(raw):
        raise CaptureError("capture contains invalid control characters or types")
    if len(json.dumps(raw, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 8 << 20:
        raise CaptureError("capture is too large")
    profile, capture, observation = raw["android_profile"], raw["capture"], raw["observation"]
    _object(profile, {"device_id", "version", "client_type", "user_agent", "native_channel", "language",
                      "page_url", "native_params", "legacy_native_params", "psign", "ck_data", "native_ck_data"},
            {"device_id", "version", "client_type", "user_agent", "native_channel", "language", "page_url", "native_params", "legacy_native_params"})
    _object(capture, {"device_id", "provenance", "install_referrer", "install", "native_media_cache", "stored_media_source"},
            {"device_id", "install", "native_media_cache"})
    _object(observation, {"package_name", "version", "version_code", "base_apk_sha256", "observed_at_ms", "first_launch_seconds",
                          "native_params_source", "native_media_cache_source", "play_referrer_status", "page_url_source",
                          "first_launch_state_source", "native_null_query_keys", "legacy_null_query_keys",
                          "ck_data_status", "native_ck_data_status", "ck_data_observed_at_ms", "native_ck_data_observed_at_ms", "completed_at_ms", "installation_lifecycle"},
            {"package_name", "version", "version_code", "base_apk_sha256", "observed_at_ms", "first_launch_seconds",
             "native_params_source", "native_media_cache_source", "play_referrer_status", "page_url_source",
             "first_launch_state_source", "native_null_query_keys", "legacy_null_query_keys", "ck_data_status", "native_ck_data_status", "completed_at_ms"})
    identity = profile.get("device_id")
    if not isinstance(identity, str) or not identity or identity != capture.get("device_id"):
        raise CaptureError("installation identity mismatch")
    if "installation_lifecycle" in observation:
        lifecycle = observation["installation_lifecycle"]
        fields = {"device_id", "is_guest", "language", "time_zone", "date_pattern", "observed_today", "last_unlogin_day", "device_activated"}
        _object(lifecycle, fields, fields)
        if (lifecycle["device_id"] != identity or lifecycle["is_guest"] is not True
                or type(lifecycle["device_activated"]) is not bool
                or any(not isinstance(lifecycle[k], str) for k in fields - {"is_guest", "device_activated"})
                or any(not lifecycle[k] for k in ("language", "time_zone", "date_pattern", "observed_today"))):
            raise CaptureError("invalid installation lifecycle observation")
    if (profile.get("version") != "4.26.5" or type(profile.get("client_type")) is not int or profile["client_type"] != 1
            or observation["version"] != profile["version"] or type(observation["version_code"]) is not int
            or observation["version_code"] != 699 or observation["package_name"] != "com.dubox.drive"
            or observation["base_apk_sha256"] != REVIEWED_BASE_SHA256):
        raise CaptureError("unsupported APK build")
    for field in ("user_agent", "native_channel", "language", "page_url"):
        if not isinstance(profile[field], str) or not profile[field].strip():
            raise CaptureError("missing captured native profile field")
    try:
        page = urlparse(profile["page_url"])
        port = page.port
    except (ValueError, TypeError):
        raise CaptureError("invalid observed Hy page") from None
    if (page.scheme != "https" or page.username or page.password or page.fragment
            or port not in (None, 443) or not page.hostname
            or not (page.hostname == "terabox.com" or page.hostname.endswith(".terabox.com"))
            or not (page.path == "/wap/hylogin" or page.path.startswith("/wap/hylogin/"))):
        raise CaptureError("invalid observed Hy page")
    ua = profile.get("user_agent", "").split(";")
    if len(ua) != 9 or ua[0] != "dubox" or ua[1] != "4.26.5" or ua[3] != "android-android":
        raise CaptureError("invalid native User-Agent")
    install = capture.get("install")
    install_fields = {"device", "os_version", "clipboard", "install_time", "first_launch_time", "is_first_launch", "device_country", "device_lang"}
    _object(install, install_fields, install_fields)
    if any(not isinstance(install[key], str) for key in ("device", "os_version", "clipboard", "device_country", "device_lang")):
        raise CaptureError("invalid installation string field")
    if install.get("device") != unquote_plus(ua[2]) or install.get("os_version") != unquote_plus(ua[4]):
        raise CaptureError("build and installation state disagree")
    for key in ("first_launch_time", "install_time"):
        if type(install.get(key)) is not int or not (0 <= install[key] <= 9007199254740991):
            raise CaptureError("invalid installation time")
    if (install["first_launch_time"] <= 0 or install["first_launch_time"] % 1000
            or type(observation["first_launch_seconds"]) is not int
            or observation["first_launch_seconds"] * 1000 != install["first_launch_time"]
            or type(observation["observed_at_ms"]) is not int or not 0 < observation["observed_at_ms"] <= 9007199254740991):
        raise CaptureError("invalid observed first-launch units or timestamp")
    if type(observation["completed_at_ms"]) is not int or not observation["observed_at_ms"] <= observation["completed_at_ms"] <= 9007199254740991:
        raise CaptureError("invalid capture completion timestamp")
    if type(install.get("is_first_launch")) is not bool or install.get("clipboard") != "":
        raise CaptureError("invalid first-launch state")
    secrets = {"ndus", "uid", "userid", "sk", "encoded_sk", "secret_token", "access_token",
               "bdstoken", "cookie", "authorization", "password", "passwd"}
    page_query = parse_qs(page.query, keep_blank_values=True)
    if any(len(values) != 1 for values in page_query.values()):
        raise CaptureError("observed page contains ambiguous query values")
    maps = [profile["native_params"], profile["legacy_native_params"], {key: value[0] for key, value in page_query.items()}]
    for params in maps:
        if not isinstance(params, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in params.items()):
            raise CaptureError("invalid native parameters")
        for key, value in params.items():
            if key.strip().lower() in secrets and value.strip():
                raise CaptureError("guest parameters contain account credentials")
            if key in ("cuid", "devuid") and value and value != identity:
                raise CaptureError("native parameters belong to another installation")
        if "firstlaunchtime" in params:
            try:
                seconds = int(params["firstlaunchtime"])
            except (ValueError, TypeError):
                raise CaptureError("invalid native first-launch time") from None
            if seconds * 1000 != install["first_launch_time"]:
                raise CaptureError("first-launch units disagree")
    for params in maps[:2]:
        for key, value in {"devuid": identity, "version": "4.26.5", "versioncode": "699", "clienttype": "1",
                           "channel": profile["native_channel"], "lang": profile["language"],
                           "firstlaunchtime": str(observation["first_launch_seconds"])}.items():
            if params.get(key) != value:
                raise CaptureError("native common query and profile disagree")
    if profile["native_params"].get("cuid") != identity:
        raise CaptureError("native common query lacks its captured installation identity")
    for key in ("native_null_query_keys", "legacy_null_query_keys"):
        if observation[key] not in ([], ["rand"]):
            raise CaptureError("unsupported nullable query observation")
        family = "native_params" if key == "native_null_query_keys" else "legacy_native_params"
        if observation[key] and "rand" in profile[family]:
            raise CaptureError("nullable common query was converted into a string")
    cache = capture.get("native_media_cache")
    _object(cache, {"initialized", "value"}, {"initialized"})
    if type(cache.get("initialized")) is not bool:
        raise CaptureError("missing native cache observation")
    if cache["initialized"] != isinstance(cache.get("value"), str):
        raise CaptureError("inconsistent native cache observation")
    if "stored_media_source" in capture and not isinstance(capture["stored_media_source"], str):
        raise CaptureError("invalid stored media observation")
    expected_media = cache.get("value") if cache["initialized"] else capture.get("stored_media_source", "Undefined")
    if any(params.get("af_media_source") != expected_media for params in maps[:2]):
        raise CaptureError("native media getter and pre-builder cache observation disagree")
    if (observation["native_params_source"] != "inert_local_request_builder"
            or observation["native_media_cache_source"] != "static_field_before_builder"
            or observation["first_launch_state_source"] != "q5_cached_lazy"
            or observation["page_url_source"] not in ("live_webview", "operator_observed")):
        raise CaptureError("invalid observation source")
    for field, state_field in (("ck_data", "ck_data_status"), ("native_ck_data", "native_ck_data_status")):
        state = observation[state_field]
        if state not in ("observed", "not_observed", "unavailable", "invalid_observation"):
            raise CaptureError("invalid CK observation state")
        if state == "observed":
            values = profile.get(field)
            if not isinstance(values, dict) or set(values) - {"ck_st", "ck_val", "ck_own", "ck_tk"} or any(not isinstance(v, str) for v in values.values()):
                raise CaptureError("invalid observed CK fields")
            at = observation.get(field + "_observed_at_ms")
            if type(at) is not int or not observation["observed_at_ms"] <= at <= observation["completed_at_ms"]:
                raise CaptureError("missing dated CK observation")
        elif field in profile or require_ck:
            raise CaptureError("CK values require natural observed calls in both protocol families")
        elif field + "_observed_at_ms" in observation:
            raise CaptureError("CK observation time without observed values")
    status = observation["play_referrer_status"]
    if status == "observed":
        if capture.get("provenance") != "play_observed" or not isinstance(capture.get("install_referrer"), str):
            raise CaptureError("missing observed Play result")
    elif status not in ("not_requested", "unavailable", "disconnected", "timeout", "service_code_-1", "service_code_1", "service_code_2", "service_code_3", "service_code_4"):
        raise CaptureError("invalid Play observation state")
    elif capture.get("provenance") or "install_referrer" in capture:
        raise CaptureError("unobserved referrer cannot have Play provenance")
    return {"installations": [{"android_profile": profile, "capture": capture}]}


def private_json(path, value):
    path = Path(path)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int, help="PID of the already running guest app")
    parser.add_argument("--remote", default="127.0.0.1:27042", help="existing Frida server endpoint")
    parser.add_argument("--page-url", help="actual observed Hy page URL when no live WebView remains")
    parser.add_argument("--read-play", action="store_true", help="read the actual Play Install Referrer service")
    parser.add_argument("--observe-ck-seconds", type=int, default=0, help="observe natural CK getter/bridge calls for 0 to 120 seconds, without invoking them")
    parser.add_argument("--require-ck", action="store_true", help="fail unless both H5 and native CK maps were naturally observed")
    parser.add_argument("--output", type=Path, required=True, help="new private installation pool file")
    args = parser.parse_args(argv)
    session = None
    try:
        if args.pid <= 0:
            raise CaptureError("PID must be positive")
        if not 0 <= args.observe_ck_seconds <= 120 or args.require_ck and args.observe_ck_seconds == 0:
            raise CaptureError("CK observation requires 1 to 120 seconds when --require-ck is set")
        sidecar = args.output.with_suffix(args.output.suffix + ".observation.json")
        if args.output.exists() or sidecar.exists():
            raise CaptureError("output paths must be new files")
        import frida
        import frida_tools
        bridge_path = Path(frida_tools.__file__).parent / "bridges" / "java.js"
        bridge = bridge_path.read_text(encoding="utf-8")
        source = bridge + "\nglobalThis.Java = bridge;\n" + Path(__file__).with_name(
            "android_attribution_capture.js").read_text(encoding="utf-8")
        device = frida.get_device_manager().add_remote_device(args.remote)
        session = device.attach(args.pid)
        script = session.create_script(source)
        script.load()
        raw = script.exports_sync.collect({"read_play": args.read_play, "page_url": args.page_url,
                                           "observe_ck_ms": args.observe_ck_seconds * 1000, "require_ck": args.require_ck})
        pool = validate_snapshot(raw, require_ck=args.require_ck)
        private_json(args.output, pool)
        private_json(sidecar, raw["observation"])
        print(json.dumps({"installations": 1, "play_referrer_status": raw["observation"]["play_referrer_status"],
                          "native_params_source": raw["observation"]["native_params_source"],
                          "ck_data_status": raw["observation"]["ck_data_status"],
                          "native_ck_data_status": raw["observation"]["native_ck_data_status"]}))
        return 0
    except CaptureError as error:
        print("capture: " + str(error), file=sys.stderr)
        return 1
    except Exception:
        print("capture: could not read the guest process; check Frida, APK version and runtime access", file=sys.stderr)
        return 1
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
