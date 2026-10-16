"""Offline protocol checks; this module never imports Frida or attaches a PID."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("analytics_bridge", Path(__file__).with_name("android_analytics_bridge.py"))
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class AnalyticsProtocolTests(unittest.TestCase):
    def request(self):
        return {"version": 1, "operation": "appsflyerReport", "request_id": "a" * 64,
                "device_id": "offline-fixture-cuid", "event": {"key": "wap_email_register", "isReportFb": True}}

    def test_request_and_receipt(self):
        request = self.request()
        self.assertEqual(bridge.validate_request(request), request)
        receipt = {"version": 1, "request_id": request["request_id"], "key": "wap_email_register",
                   "appsflyer_called": True, "firebase_called": True,
                   "environment": "android-frida-com.dubox.drive-4.26.5-699"}
        self.assertEqual(bridge.validate_receipt(request, receipt), receipt)
        for key, bad in (("request_id", "b" * 64), ("firebase_called", False), ("appsflyer_called", 1), ("environment", "unknown")):
            other = dict(receipt, **{key: bad})
            with self.assertRaises(ValueError):
                bridge.validate_receipt(request, other)

    def test_rejects_unbound_or_injected_input(self):
        for change in ({"device_id": ""}, {"request_id": "raw-private-request"}, {"operation": "unknown"},
                       {"version": True}, {"extra": "not allowed"}):
            request = dict(self.request(), **change)
            with self.assertRaises(ValueError):
                bridge.validate_request(request)

    def test_native_signing_contract_is_bound_to_exact_message(self):
        signer_spec = importlib.util.spec_from_file_location("device_signer", Path(__file__).with_name("android_device_activation_signer.py"))
        signer = importlib.util.module_from_spec(signer_spec)
        signer_spec.loader.exec_module(signer)
        request = {"device_id": "fixture-cuid", "channel": "fixture-channel", "clienttype": 1,
                   "timestamp_ms": 1700000001000, "message": "1fixture-channelfixture-cuid1700000001000"}
        self.assertEqual(signer.validate_request(request), request)
        for key, invalid in (("device_id", "different"), ("timestamp_ms", 1700000001001),
                             ("clienttype", True), ("message", "invented-signing-input")):
            with self.assertRaises(ValueError):
                signer.validate_request(dict(request, **{key: invalid}))
        for key in ("", "event\r\nprivate", "x" * 129):
            request = copy.deepcopy(self.request())
            request["event"]["key"] = key
            with self.assertRaises(ValueError):
                bridge.validate_request(request)


if __name__ == "__main__":
    unittest.main()
