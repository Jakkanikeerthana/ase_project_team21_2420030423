"""Adaptive Honeypot launcher - starts the console + sensors and opens the browser.
Usage:  python run.py [--no-browser] [--port 8765]"""
import json
import logging
import os
import sys
import threading
import time
import urllib.request
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from honeypot import config  # noqa: E402


def already_running():
    try:
        with open(config.CONTROL_FILE) as f:
            port = json.load(f)["port"]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1.5) as r:
            return port if r.status == 200 else None
    except Exception:
        return None


def main():
    args = sys.argv[1:]
    if "--port" in args:
        os.environ["AHP_PORT"] = args[args.index("--port") + 1]
        config.UI_PORT = int(os.environ["AHP_PORT"])
    no_browser = "--no-browser" in args
    port = already_running()
    if port:
        if not no_browser:
            webbrowser.open(f"http://127.0.0.1:{port}/")
        return
    handlers = [logging.FileHandler(config.LOG_PATH, encoding="utf-8")]
    if sys.stdout is not None and not sys.executable.lower().endswith("pythonw.exe"):
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", handlers=handlers)
    from honeypot.server import App
    app = App()
    httpd = app.start(config.UI_HOST, config.UI_PORT)
    url = f"http://{config.UI_HOST}:{config.UI_PORT}/"
    logging.info("%s v%s running at %s (data: %s)", config.APP_NAME, config.VERSION, url, config.DATA_DIR)
    if not no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.sensors.stop_all()
        try:
            os.remove(config.CONTROL_FILE)
        except OSError:
            pass
        time.sleep(0.3)


if __name__ == "__main__":
    main()
