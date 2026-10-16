"""Obtain report/device's signature from the selected running guest APK.

One bound signing request on stdin; one signature capture on stdout. No HTTP,
registration, app spawning, credential copying or KeyMaker emulation occurs.
The signature output is private and must not be written to a general log.
"""
import argparse
import json
import sys
from pathlib import Path


def validate_request(value):
    required = {"device_id", "channel", "clienttype", "timestamp_ms", "message"}
    if (not isinstance(value, dict) or set(value) != required
            or type(value["clienttype"]) is not int or value["clienttype"] != 1
            or type(value["timestamp_ms"]) is not int or not 0 < value["timestamp_ms"] < 2**53
            or any(not isinstance(value[k], str) or not value[k] or len(value[k]) > 4096
                   or any(ord(c) < 32 for c in value[k]) for k in ("device_id", "channel", "message"))
            or value["message"] != str(value["clienttype"]) + value["channel"] + value["device_id"] + str(value["timestamp_ms"])):
        raise ValueError("invalid native signing input")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--remote", default="127.0.0.1:27042")
    args = parser.parse_args(argv)
    session = None
    try:
        if args.pid <= 0:
            raise ValueError("invalid PID")
        raw = sys.stdin.buffer.read((16 << 10) + 1)
        if len(raw) > 16 << 10:
            raise ValueError("request too large")
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
        result = script.exports_sync.sign(request)
        if (not isinstance(result, dict) or set(result) != {"device_id", "channel", "clienttype", "timestamp_ms", "signature"}
                or any(result[k] != request[k] for k in ("device_id", "channel", "clienttype", "timestamp_ms"))
                or not isinstance(result["signature"], str) or not 0 < len(result["signature"]) <= 4096
                or any(ord(c) < 32 for c in result["signature"])):
            raise ValueError("invalid native signature response")
        sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n")
        return 0
    except Exception:
        print("native device signing failed; inspect target build and installation", file=sys.stderr)
        return 1
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
