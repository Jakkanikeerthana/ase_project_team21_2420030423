"""Stops a running Adaptive Honeypot instance (used by the Start-menu shortcut and the uninstaller)."""
import json
import os
import signal
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from honeypot import config  # noqa: E402


def main():
    try:
        with open(config.CONTROL_FILE) as f:
            c = json.load(f)
    except (OSError, ValueError):
        print("Adaptive Honeypot is not running.")
        return
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{c['port']}/api/system/shutdown",
                                     data=json.dumps({"control_token": c["token"]}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5).read()
        time.sleep(2)
    except Exception:
        pass
    # Fallback: terminate the recorded process only if the console is still answering
    still_up = False
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{c['port']}/api/health", timeout=2).read()
        still_up = True
    except Exception:
        pass
    pid = c.get("pid")
    if still_up and pid and pid != os.getpid():
        try:
            os.kill(int(pid), signal.SIGTERM)
        except OSError:
            pass
    try:
        os.remove(config.CONTROL_FILE)
    except OSError:
        pass
    print("Adaptive Honeypot stopped.")


if __name__ == "__main__":
    main()
