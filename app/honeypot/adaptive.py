"""Adaptive engine: attacker profiling, UCB1 strategy bandit, persona morphing,
per-attacker consistency store and optional local-LLM response generation."""
import json
import math
import random
import re
import statistics
import threading
import time

# --------------------------------------------------------------------------------------
# Personas (morphing) - fictional identities the decoys rotate through
# --------------------------------------------------------------------------------------
PERSONAS = [
    {"key": "ubuntu-web", "label": "Ubuntu web server", "hostname": "web-prod-01",
     "os": "Ubuntu 22.04.4 LTS", "kernel": "5.15.0-105-generic", "user": "deploy",
     "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "http_server": "nginx/1.18.0 (Ubuntu)",
     "ftp_banner": "220 (vsFTPd 3.0.5)", "plc": "RoseTech PLC-500 v2.1", "portal": "Rosewood Hosting Panel"},
    {"key": "centos-db", "label": "CentOS database host", "hostname": "db-backup-02",
     "os": "CentOS Linux 7 (Core)", "kernel": "3.10.0-1160.el7.x86_64", "user": "dbadmin",
     "ssh_banner": "SSH-2.0-OpenSSH_7.4", "http_server": "Apache/2.4.6 (CentOS) PHP/7.2.24",
     "ftp_banner": "220 ProFTPD 1.3.5 Server (backup)", "plc": "RoseTech PLC-300 v1.8", "portal": "DB Backup Console"},
    {"key": "iot-camera", "label": "IoT camera (BusyBox)", "hostname": "ipcam-7f3a",
     "os": "BusyBox v1.31.1 (embedded Linux)", "kernel": "4.9.37", "user": "admin",
     "ssh_banner": "SSH-2.0-dropbear_2019.78", "http_server": "lighttpd/1.4.55",
     "ftp_banner": "220 BusyBox FTP server ready", "plc": "RoseTech RTU-10 v0.9", "portal": "NetCam Viewer"},
    {"key": "debian-dev", "label": "Debian CI runner", "hostname": "dev-ci-03",
     "os": "Debian GNU/Linux 12 (bookworm)", "kernel": "6.1.0-21-amd64", "user": "jenkins",
     "ssh_banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", "http_server": "Apache/2.4.62 (Debian)",
     "ftp_banner": "220 Welcome to Pure-FTPd", "plc": "RoseTech PLC-500 v2.3", "portal": "BuildBox CI"},
]


class Morph:
    """Rotates the active persona on a schedule (or on demand)."""

    def __init__(self, db):
        self.db = db
        self.index = 0
        self.last_rotation = time.time()
        self.history = []

    def current(self):
        interval = max(1, int(self.db.get("morph_interval_min", 30))) * 60
        if self.db.get("adaptive_enabled", True) and time.time() - self.last_rotation > interval:
            self.rotate("schedule")
        return PERSONAS[self.index]

    def rotate(self, reason="manual"):
        self.index = (self.index + 1) % len(PERSONAS)
        self.last_rotation = time.time()
        self.history.append({"ts": self.last_rotation, "persona": PERSONAS[self.index]["key"], "reason": reason})
        self.history = self.history[-50:]
        return PERSONAS[self.index]


# --------------------------------------------------------------------------------------
# Profiler - explainable rule/feature based attacker classification
# --------------------------------------------------------------------------------------
PROFILES = ["scanner", "bot", "script_kiddie", "skilled", "unknown"]
PROFILE_LABEL = {"scanner": "Scanner", "bot": "Automated bot", "script_kiddie": "Script kiddie",
                 "skilled": "Skilled attacker", "unknown": "Unknown"}

BOT_SIGS = re.compile(r"/bin/busybox|enable\s*;?\s*system|\bshell\b\s*;?\s*sh|echo -e ['\"]\\\\x|mirai|ECCHI|\.nippon|tftp -g", re.I)
SKILL_SIGS = re.compile(r"sudo -l|history -c|unset HISTFILE|authorized_keys|base64 -d|python3? -c|/proc/1/cgroup|"
                        r"ss -tulpn|find / -perm|getcap|\.aws/credentials|systemctl|journalctl", re.I)
KIDDIE_SIGS = re.compile(r"xmrig|minerd|stratum|\.sh\b.*\|\s*sh|chmod 777|perl .*\.pl|kdevtmpfsi", re.I)
HP_CHECK = re.compile(r"cowrie|honeypot|kippo|/proc/1/cgroup|dmesg.*hyper|systemd-detect-virt|cat /proc/cpuinfo.*grep", re.I)


def profile_session(f):
    """f: features dict -> (profile, confidence, reasons)."""
    cmds = f.get("cmds", [])
    times = f.get("times", [])
    n = len(cmds)
    joined = "\n".join(cmds)
    gaps = [b - a for a, b in zip(times, times[1:])] if len(times) > 1 else []
    mean_gap = statistics.mean(gaps) if gaps else None
    reasons = []
    sensor = f.get("sensor")

    if sensor == "http":
        paths, ua = f.get("paths", 0), f.get("ua", "")
        if f.get("scanner_ua") or (paths >= 6 and (mean_gap or 1) < 0.5):
            reasons.append("scanner user-agent or rapid path enumeration")
            return "scanner", 0.85, reasons
        if f.get("exploits", 0) >= 1 and f.get("breadcrumbs", 0) == 0:
            reasons.append(f"{f['exploits']} exploit payload(s) from public kits")
            return "script_kiddie", 0.7, reasons
        if f.get("breadcrumbs", 0) or f.get("canary_used"):
            reasons.append("followed breadcrumbs / reused leaked credentials")
            return "skilled", 0.75, reasons
        if paths >= 3 and (mean_gap or 0) >= 0.8:
            return "skilled", 0.55, [f"manual, human-paced exploration of {paths} paths"]
        return ("scanner" if paths <= 2 else "unknown"), 0.5, ["few HTTP requests"]

    if sensor == "modbus":
        if f.get("writes", 0):
            return "skilled", 0.7, ["issued ICS write commands"]
        return "scanner", 0.7, ["read-only ICS polling"]

    if sensor == "ssh":
        return "scanner", 0.9, ["banner grab / version probe only"]

    if n == 0:
        if sensor == "lab":
            return "unknown", 0.3, ["waiting for commands"]
        if f.get("logins", 0) >= 3 and (f.get("login_gap") or 1) < 0.5:
            return "bot", 0.8, ["rapid credential brute force"]
        return "scanner", 0.6, ["connected without issuing commands"]

    score = {"bot": 0.0, "script_kiddie": 0.0, "skilled": 0.0}
    if BOT_SIGS.search(joined):
        score["bot"] += 2; reasons.append("botnet command signature")
    if mean_gap is not None and mean_gap < 0.35 and n >= 3:
        score["bot"] += 2; reasons.append(f"machine-speed typing (avg gap {mean_gap:.2f}s)")
    if f.get("logins", 0) >= 3 and (f.get("login_gap") or 1) < 0.5:
        score["bot"] += 1; reasons.append("rapid brute-force before login")
    if KIDDIE_SIGS.search(joined):
        score["script_kiddie"] += 2; reasons.append("commodity miner/dropper commands")
    if f.get("unknown", 0) >= 2:
        score["script_kiddie"] += 1; reasons.append("several invalid commands / typos")
    if SKILL_SIGS.search(joined):
        score["skilled"] += 2; reasons.append("stealth / privilege-escalation tradecraft")
    if f.get("breadcrumbs", 0):
        score["skilled"] += 1.5; reasons.append("read planted breadcrumb files")
    if mean_gap is not None and mean_gap >= 0.8 and n >= 4:
        score["skilled"] += 1; score["script_kiddie"] += 0.5; reasons.append(f"human pacing (avg gap {mean_gap:.1f}s)")
    if len(set(f.get("tactics", []))) >= 4:
        score["skilled"] += 1; reasons.append("activity spans 4+ ATT&CK tactics")
    best = max(score, key=score.get)
    total = sum(score.values())
    if total == 0:
        return "unknown", 0.4, ["insufficient signal"]
    return best, round(min(0.95, 0.45 + score[best] / (total + 2)), 2), reasons


# --------------------------------------------------------------------------------------
# UCB1 contextual bandit over response strategies
# --------------------------------------------------------------------------------------
ARMS = {
    "static": "Classic static honeypot (baseline for comparison)",
    "breadcrumbs": "Plants fake credentials & files (canary tokens) to lure deeper",
    "tarpit": "Adds human-like latency to slow automated tools",
    "rich": "High-interaction: rich outputs, accepts sudo, LLM for unknown commands",
}


class Bandit:
    def __init__(self, db):
        self.db = db
        self.lock = threading.Lock()

    def stats(self, profile=None):
        rows = self.db.query("SELECT * FROM bandit" + (" WHERE profile=?" if profile else ""),
                             (profile,) if profile else ())
        return rows

    def select(self, profile):
        if not self.db.get("adaptive_enabled", True):
            return "static", "adaptive engine disabled"
        c = float(self.db.get("bandit_c", 1.2))
        with self.lock:
            rows = {r["arm"]: r for r in self.stats(profile)}
            untried = [a for a in ARMS if rows.get(a, {}).get("pulls", 0) == 0]
            if untried:
                arm = random.choice(untried)
                return arm, "exploring untried strategy"
            total = sum(r["pulls"] for r in rows.values())
            best, best_v = None, -1
            for a in ARMS:
                r = rows[a]
                mean = r["reward"] / r["pulls"]
                ucb = mean + c * math.sqrt(math.log(total) / r["pulls"])
                if ucb > best_v:
                    best, best_v = a, ucb
            return best, f"UCB1 score {best_v:.2f}"

    def update(self, profile, arm, reward):
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO bandit(profile, arm, pulls, reward) VALUES(?,?,0,0)", (profile, arm))
            self.db.execute("UPDATE bandit SET pulls=pulls+1, reward=reward+? WHERE profile=? AND arm=?",
                            (float(reward), profile, arm))

    def reset(self):
        self.db.execute("DELETE FROM bandit")


def engagement_reward(commands, duration, bonus=0.0):
    r = 0.6 * min(1.0, commands / 15.0) + 0.4 * min(1.0, duration / 120.0) + bonus
    return round(min(1.0, r), 4)


# --------------------------------------------------------------------------------------
# Consistency store - per-attacker virtual filesystem overlay persisted in SQLite
# --------------------------------------------------------------------------------------
class ConsistencyStore:
    def __init__(self, db):
        self.db = db

    def load(self, ip):
        row = self.db.one("SELECT state FROM vfs_state WHERE ip=?", (ip,))
        if row:
            try:
                return json.loads(row["state"])
            except Exception:
                pass
        return {"files": {}, "dirs": [], "deleted": [], "cwd": None, "history": [], "visits": 0}

    def save(self, ip, state):
        state["history"] = state.get("history", [])[-200:]
        self.db.execute("INSERT OR REPLACE INTO vfs_state(ip, state, updated) VALUES(?,?,?)",
                        (ip, json.dumps(state), time.time()))

    def reset(self):
        self.db.execute("DELETE FROM vfs_state")

    def count(self):
        return self.db.scalar("SELECT COUNT(*) FROM vfs_state")


# --------------------------------------------------------------------------------------
# Optional local LLM (Ollama) for realistic responses to unknown commands
# --------------------------------------------------------------------------------------
class LLM:
    def __init__(self, db, egress):
        self.db = db
        self.egress = egress
        self.cache = {}
        self.last_error = ""
        self.calls = 0

    def enabled(self):
        return bool(self.db.get("llm_enabled", False))

    def generate(self, cmd, persona, cwd):
        key = (persona["key"], cmd.strip())
        if key in self.cache:
            return self.cache[key]
        prompt = (f"You are emulating a Linux terminal on host '{persona['hostname']}' running {persona['os']} "
                  f"kernel {persona['kernel']}. Current directory: {cwd}. Reply ONLY with the exact raw terminal "
                  f"output for this command, no explanations, no markdown, max 25 lines. If the command would not "
                  f"exist, print the bash 'command not found' error.\nCommand: {cmd}")
        url = self.db.get("ollama_url", "http://127.0.0.1:11434").rstrip("/") + "/api/generate"
        body = {"model": self.db.get("ollama_model", "llama3.2"), "prompt": prompt, "stream": False,
                "options": {"temperature": 0.2, "num_predict": 300}}
        try:
            data = self.egress.request_json(url, body, timeout=float(self.db.get("llm_timeout_s", 6)))
            text = (data.get("response") or "").strip()
            text = re.sub(r"^```\w*\n?|```$", "", text).strip()
            self.calls += 1
            self.cache[key] = text
            if len(self.cache) > 500:
                self.cache.pop(next(iter(self.cache)))
            return text
        except Exception as e:  # graceful fallback to rule-based output
            self.last_error = str(e)[:200]
            return None
