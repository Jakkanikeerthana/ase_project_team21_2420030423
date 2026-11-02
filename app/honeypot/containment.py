"""Containment & safety: egress allow-listing, per-IP rate limiting, IP anonymisation."""
import json
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict, deque


class EgressBlocked(Exception):
    pass


class EgressGuard:
    """Every outbound request the application makes goes through here.
    Only hosts of integrations the admin configured are reachable. Honeypot sensors never
    make outbound connections at all (wget/curl inside the decoy are simulated)."""

    def __init__(self, db):
        self.db = db
        self.blocked = deque(maxlen=100)
        self.allowed_count = 0

    def allowlist(self):
        s = self.db.settings()
        hosts = set()
        for k in ("ollama_url", "misp_url", "webhook_url"):
            if s.get(k):
                h = urllib.parse.urlparse(s[k]).hostname
                if h:
                    hosts.add(h.lower())
        if s.get("abuseipdb_key"):
            hosts.add("api.abuseipdb.com")
        if s.get("virustotal_key"):
            hosts.add("www.virustotal.com")
        return sorted(hosts)

    def check(self, url):
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host not in self.allowlist():
            self.blocked.append({"ts": time.time(), "host": host})
            self.db.audit("system", "egress_blocked", "containment", f"Outbound request to {host} blocked")
            raise EgressBlocked(f"Egress to '{host}' is not on the allow-list")
        self.allowed_count += 1

    def request(self, url, data=None, headers=None, method=None, timeout=8):
        self.check(url)
        body = None
        hdrs = dict(headers or {})
        if data is not None:
            body = json.dumps(data).encode() if not isinstance(data, (bytes, str)) else (
                data.encode() if isinstance(data, str) else data)
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method or ("POST" if body else "GET"))
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()

    def request_json(self, url, data=None, headers=None, method=None, timeout=8):
        status, raw = self.request(url, data, headers, method, timeout)
        return json.loads(raw.decode() or "{}")


class RateLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()
        self.dropped = 0

    def allow(self, ip, limit_per_min):
        now = time.time()
        with self.lock:
            q = self.hits[ip]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= limit_per_min:
                self.dropped += 1
                return False
            q.append(now)
            return True


def anonymize(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["x"])
    return ip
