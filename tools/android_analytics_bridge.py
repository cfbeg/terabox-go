"""Execute one correlated AppsFlyer/Firebase event in an existing APK process.

Single JSON request on stdin; single correlated execution receipt on stdout.
The caller must persist an attempt before invoking this adapter. No spawning,
registration or automatic replay is performed. Runtime logs are suppressed.
"""
import argparse
import json
import re
import sys
from pathlib import Path


def validate_request(value):
    if (not isinstance(value, dict)
            or set(value) != {"version", "operation", "request_id", "device_id", "event"}
            or type(value["version"]) is not int or value["version"] != 1
            or value["operation"] != "appsflyerReport"
            or not isinstance(value["request_id"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", value["request_id"])
            or not isinstance(value["device_id"], str) or not 1 <= len(value["device_id"]) <= 1024
            or any(ord(c) < 32 for c in value["device_id"])):
        raise ValueError("invalid analytics request")
    event = value["event"]
    if (not isinstance(event, dict) or set(event) != {"key", "isReportFb"}
            or not isinstance(event["key"], str) or not 1 <= len(event["key"]) <= 128
            or any(ord(c) < 32 for c in event["key"])
            or type(event["isReportFb"]) is not bool):
        raise ValueError("invalid analytics event")
    return value


def validate_receipt(request, receipt):
    if (not isinstance(receipt, dict)
            or set(receipt) != {"version", "request_id", "key", "appsflyer_called", "firebase_called", "environment"}
            or receipt["version"] != 1 or receipt["request_id"] != request["request_id"]
            or receipt["key"] != request["event"]["key"]
            or receipt["appsflyer_called"] is not True
            or receipt["firebase_called"] is not request["event"]["isReportFb"]
            or receipt["environment"] != "android-frida-com.dubox.drive-4.26.5-699"):
        raise ValueError("invalid runtime execution receipt")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True, help="already running com.dubox.drive PID")
    parser.add_argument("--remote", default="127.0.0.1:27042", help="existing Frida server endpoint")
    args = parser.parse_args(argv)
    session = None
    try:
        if args.pid <= 0:
            raise ValueError("invalid target PID")
        raw = sys.stdin.buffer.read((16 << 10) + 1)
        if len(raw) > 16 << 10:
            raise ValueError("request exceeds its size limit")
        request = validate_request(json.loads(raw.decode("utf-8")))
        import frida
        import frida_tools
        java_bridge = Path(frida_tools.__file__).parent / "bridges" / "java.js"
        source = (java_bridge.read_text(encoding="utf-8") + "\nglobalThis.Java = bridge;\n"
                  + Path(__file__).with_suffix(".js").read_text(encoding="utf-8"))
        device = frida.get_device_manager().add_remote_device(args.remote)
        session = device.attach(args.pid)
        script = session.create_script(source)
        script.set_log_handler(lambda *_: None)
        script.load()
        receipt = validate_receipt(request, script.exports_sync.execute(request))
        sys.stdout.write(json.dumps(receipt, ensure_ascii=True, separators=(",", ":")) + "\n")
        return 0
    except Exception:
        # Frida/Java exception text can contain runtime tokens and user data.
        print("analytics execution failed or is uncertain; inspect the target before replay", file=sys.stderr)
        return 1
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
