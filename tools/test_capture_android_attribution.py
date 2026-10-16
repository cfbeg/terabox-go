import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("capture", Path(__file__).with_name("capture_android_attribution.py"))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class CaptureValidation(unittest.TestCase):
    def fixture(self):
        return {
            "android_profile": {
                "device_id": "fixture-cuid", "version": "4.26.5", "client_type": 1,
                "user_agent": "dubox;4.26.5;Pixel+8;android-android;15;JSbridge;0;0;",
                "native_channel": "fixture-channel", "language": "en",
                "page_url": "https://www.terabox.com/wap/hylogin/emailRegister?from=share",
                "native_params": {"devuid": "fixture-cuid", "cuid": "fixture-cuid", "firstlaunchtime": "1000",
                                  "version": "4.26.5", "versioncode": "699", "clienttype": "1", "channel": "fixture-channel", "lang": "en", "af_media_source": "Undefined"},
                "legacy_native_params": {"devuid": "fixture-cuid", "firstlaunchtime": "1000",
                                         "version": "4.26.5", "versioncode": "699", "clienttype": "1", "channel": "fixture-channel", "lang": "en", "af_media_source": "Undefined"},
            },
            "capture": {
                "device_id": "fixture-cuid", "provenance": "play_observed", "install_referrer": "",
                "install": {"device": "Pixel 8", "os_version": "15", "clipboard": "",
                            "install_time": 999000, "first_launch_time": 1000000, "is_first_launch": True,
                            "device_country": "US", "device_lang": "en"},
                "native_media_cache": {"initialized": False},
            },
            "observation": {"play_referrer_status": "observed", "package_name": "com.dubox.drive", "version": "4.26.5",
                            "version_code": 699, "observed_at_ms": 1010000, "completed_at_ms": 1010001,
                            "base_apk_sha256": capture.REVIEWED_BASE_SHA256,
                            "first_launch_seconds": 1000, "native_params_source": "inert_local_request_builder",
                            "native_media_cache_source": "static_field_before_builder", "first_launch_state_source": "q5_cached_lazy",
                            "native_null_query_keys": ["rand"], "legacy_null_query_keys": [], "page_url_source": "live_webview",
                            "ck_data_status": "not_observed", "native_ck_data_status": "not_observed"},
        }

    def test_empty_and_unavailable_referrer_remain_distinct(self):
        raw = self.fixture()
        self.assertEqual(capture.validate_snapshot(raw)["installations"][0]["capture"]["install_referrer"], "")
        raw["capture"].pop("install_referrer")
        raw["capture"].pop("provenance")
        raw["observation"]["play_referrer_status"] = "unavailable"
        self.assertNotIn("install_referrer", capture.validate_snapshot(raw)["installations"][0]["capture"])

    def test_identity_units_and_guest_constraints(self):
        cases = [
            ("capture", "device_id", "another"),
            ("android_profile", "uid", "account-id"),
            ("android_profile", "page_url", "https://evil.test/wap/hylogin"),
            ("android_profile", "native_params", {"cuid": "fixture-cuid", "ndus": "secret"}),
        ]
        for section, key, value in cases:
            raw = self.fixture()
            raw[section][key] = value
            with self.subTest(key=key), self.assertRaises(capture.CaptureError):
                capture.validate_snapshot(raw)
        raw = self.fixture()
        raw["capture"]["install"]["first_launch_time"] = 1000
        with self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)

    def test_cache_and_provenance_are_not_invented(self):
        for cache in [{"initialized": True}, {"initialized": False, "value": "Undefined"}]:
            raw = self.fixture()
            raw["capture"]["native_media_cache"] = cache
            with self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)
        raw = self.fixture()
        raw["observation"]["play_referrer_status"] = "unavailable"
        with self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)

    def test_private_output_never_overwrites_an_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "capture.json"
            capture.private_json(file, {"observed": True})
            with self.assertRaises(FileExistsError): capture.private_json(file, {"observed": False})
            self.assertIn("true", file.read_text())

    def test_ck_absence_empty_and_observed_maps_remain_distinct(self):
        raw = self.fixture()
        pool = capture.validate_snapshot(raw)
        self.assertNotIn("ck_data", pool["installations"][0]["android_profile"])
        with self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw, require_ck=True)
        for key in ("ck_data", "native_ck_data"):
            raw["android_profile"][key] = {}
            raw["observation"][key + "_status"] = "observed"
            raw["observation"][key + "_observed_at_ms"] = 1010000
        pool = capture.validate_snapshot(raw, require_ck=True)
        self.assertEqual(pool["installations"][0]["android_profile"]["native_ck_data"], {})
        raw["android_profile"]["ck_data"] = {"ck_st": "", "ck_val": "fixture-value", "ck_own": "", "ck_tk": "fixture-tk"}
        self.assertEqual(capture.validate_snapshot(raw)["installations"][0]["android_profile"]["ck_data"], raw["android_profile"]["ck_data"])
        for key, val in (("unknown", "x"), ("ck_val", None), ("ck_val", 42)):
            changed = copy.deepcopy(raw)
            changed["android_profile"]["ck_data"][key] = val
            with self.assertRaises(capture.CaptureError): capture.validate_snapshot(changed)
        changed = copy.deepcopy(raw)
        changed["observation"]["ck_data_status"] = "not_observed"
        with self.assertRaises(capture.CaptureError): capture.validate_snapshot(changed)
        changed = copy.deepcopy(raw)
        changed["observation"]["ck_data_observed_at_ms"] = 900000
        with self.assertRaises(capture.CaptureError): capture.validate_snapshot(changed)

    def test_profile_build_language_and_null_fields_are_not_invented(self):
        for section, key, value in (("android_profile", "language", ""), ("android_profile", "native_channel", ""),
                                    ("observation", "version_code", 698), ("capture", "stored_media_source", None),
                                    ("observation", "base_apk_sha256", "0" * 64),
                                    ("observation", "first_launch_state_source", "preference")):
            raw = self.fixture(); raw[section][key] = value
            with self.subTest(key=key), self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)
        for family, key, value in (("native_params", "lang", "ja"), ("legacy_native_params", "version", "4.26.4"),
                                   ("native_params", "rand", None), ("native_params", "rand", "null"),
                                   ("native_params", "af_media_source", "invented"), ("legacy_native_params", "lang", None)):
            raw = self.fixture(); raw["android_profile"][family][key] = value
            with self.subTest(family=family, key=key), self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)
        raw = self.fixture(); raw["android_profile"]["user_agent"] = raw["android_profile"]["user_agent"].replace("Pixel+8", "Pixel+9")
        with self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)

    def test_cached_first_launch_and_media_values_are_preserved(self):
        raw = self.fixture()
        raw["capture"]["install"]["is_first_launch"] = False
        raw["capture"]["native_media_cache"] = {"initialized": True, "value": ""}
        raw["capture"]["stored_media_source"] = "later-stored-source"
        for family in ("native_params", "legacy_native_params"):
            raw["android_profile"][family]["af_media_source"] = ""
        pool = capture.validate_snapshot(raw)
        observed = pool["installations"][0]["capture"]
        self.assertFalse(observed["install"]["is_first_launch"])
        self.assertEqual(observed["native_media_cache"]["value"], "")
        self.assertEqual(observed["stored_media_source"], "later-stored-source")

    def test_unknown_private_fields_and_invalid_types_fail_without_echo(self):
        for section in ("android_profile", "capture", "observation"):
            raw = self.fixture(); raw[section]["private"] = "DO-NOT-ECHO"
            with self.subTest(section=section), self.assertRaises(capture.CaptureError) as error:
                capture.validate_snapshot(raw)
            self.assertNotIn("DO-NOT-ECHO", str(error.exception))
        for value in (None, [], "string"):
            raw = self.fixture(); raw["observation"] = value
            with self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)
        for page in ("https://www.terabox.com:bad/wap/hylogin", "https://terabox.com/wap/hylogin?devuid=other&devuid=fixture-cuid"):
            raw = self.fixture(); raw["android_profile"]["page_url"] = page
            with self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)
        raw = self.fixture(); raw["capture"]["install_referrer"] = "bad\x00value"
        with self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)
        raw = self.fixture(); raw["capture"]["install_referrer"] = "x" * (8 << 20)
        with self.assertRaises(capture.CaptureError): capture.validate_snapshot(raw)

    def test_cli_invalid_interval_fails_before_importing_runtime_tools(self):
        import contextlib
        import io
        for args in (("--observe-ck-seconds", "121"), ("--require-ck",)):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(capture.main(["--pid", "1", "--output", "not-created.json", *args]), 1)
            self.assertIn("CK observation", err.getvalue())


if __name__ == "__main__":
    unittest.main()
