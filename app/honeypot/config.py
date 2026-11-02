"""Paths, defaults and constants for Adaptive Honeypot."""
import os

APP_NAME = "Adaptive Honeypot"
APP_ID = "AdaptiveHoneypot"
VERSION = "1.0.0"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../app
WEB_DIR = os.path.join(BASE_DIR, "web")


def _data_dir():
    env = os.environ.get("AHP_DATA_DIR")
    if env:
        d = env
    elif os.name == "nt":
        d = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), APP_ID)
    else:
        d = os.path.join(os.path.expanduser("~"), ".adaptive-honeypot")
    os.makedirs(d, exist_ok=True)
    return d


DATA_DIR = _data_dir()
DB_PATH = os.path.join(DATA_DIR, "honeypot.db")
LOG_PATH = os.path.join(DATA_DIR, "honeypot.log")
CONTROL_FILE = os.path.join(DATA_DIR, "control.json")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

UI_HOST = "127.0.0.1"
UI_PORT = int(os.environ.get("AHP_PORT", "8765"))

# Default runtime settings (editable from the UI, stored in SQLite)
DEFAULT_SETTINGS = {
    # Area 1 - Scope
    "scope_surfaces": ["ssh", "telnet", "http", "ftp", "modbus"],
    "scope_deployment": "lab",            # lab | internal | internet
    "scope_consumers": ["SOC", "CSIRT feed", "Research"],
    "org_name": "My Organisation",
    # Area 2 - Infrastructure
    "bind_host": "127.0.0.1",
    "ports": {"ssh": 2222, "telnet": 2323, "http": 8081, "ftp": 2121, "modbus": 5020},
    # Area 3 - Sensors
    "sensors_enabled": {"ssh": True, "telnet": True, "http": True, "ftp": True, "modbus": True},
    # Area 4 - Adaptive engine
    "adaptive_enabled": True,
    "morph_interval_min": 30,
    "bandit_c": 1.2,
    "llm_enabled": False,
    "ollama_url": "http://127.0.0.1:11434",
    "ollama_model": "llama3.2",
    "llm_timeout_s": 6,
    # Area 5 - Pipeline / enrichment
    "abuseipdb_key": "",
    "virustotal_key": "",
    # Area 6 - Threat intel
    "misp_url": "",
    "misp_key": "",
    "webhook_url": "",
    "syslog_host": "",
    "syslog_port": 514,
    "alert_threshold": 70,
    # Area 7 - Containment
    "lab_mode": True,
    "max_conn_per_min": 40,
    "max_session_secs": 300,
    "max_concurrent_per_sensor": 50,
    "kill_switch": False,
    # Area 8 - Governance
    "retention_days": 30,
    "anonymize_ips": False,
    "allow_signup": True,
    "legal_ack": False,
    "legal_ack_by": "",
    "legal_ack_at": "",
}

SECRET_KEYS = {"abuseipdb_key", "virustotal_key", "misp_key", "webhook_url"}
