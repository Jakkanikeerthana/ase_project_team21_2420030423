"""Web console + REST API (standard library http.server)."""
import json
import logging
import mimetypes
import os
import platform
import re
import secrets
import sys
import threading
import time
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import intel, metrics, reports
from .adaptive import ARMS, PERSONAS, PROFILE_LABEL
from .auth import ROLES, Auth
from .config import APP_NAME, CONTROL_FILE, DATA_DIR, DB_PATH, SECRET_KEYS, UI_HOST, UI_PORT, VERSION, WEB_DIR
from .core import Core
from .db import Database
from .fakeshell import FakeShell
from .sensors import SensorManager
from .simulator import SCENARIOS, Simulator

log = logging.getLogger("honeypot.web")
ROUTES = []
PUBLIC_PAGES = {"/", "/index.html", "/about.html", "/login.html", "/games.html"}


def route(method, pattern, role=None):
    """role None = public, 'viewer'/'analyst'/'admin' = minimum role."""
    def deco(fn):
        ROUTES.append((method, re.compile("^" + pattern + "$"), role, fn))
        return fn
    return deco


ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


class App:
    def __init__(self):
        self.db = Database()
        self.auth = Auth(self.db)
        self.core = Core(self.db)
        self.sensors = SensorManager(self.core)
        self.sim = Simulator(self.core)
        self.lab_sessions = {}
        self.control_token = secrets.token_urlsafe(24)
        self.httpd = None
        self.started = time.time()

    def start(self, host=UI_HOST, port=UI_PORT):
        app = self

        class Handler(RequestHandler):
            pass
        Handler.app = app

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = os.name != "nt"
        self.httpd = Server((host, port), Handler)
        with open(CONTROL_FILE, "w") as f:
            json.dump({"port": port, "token": self.control_token, "pid": os.getpid()}, f)
        self.sensors.start_enabled()
        self.db.audit("system", "application_started", "system", f"v{VERSION} on {host}:{port}")
        return self.httpd

    def shutdown(self):
        self.db.audit("system", "application_stopped", "system", "")
        self.sim.set_campaign(False)
        self.sensors.stop_all()
        threading.Thread(target=self.httpd.shutdown, daemon=True).start()


class RequestHandler(BaseHTTPRequestHandler):
    app: App = None
    server_version = "AdaptiveHoneypot/" + VERSION

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    # ------------------------------------------------------------------ helpers
    @property
    def db(self):
        return self.app.db

    def token(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        if "ahp_token" in c:
            return c["ahp_token"].value
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else None

    def user(self):
        if not hasattr(self, "_user"):
            self._user = self.app.auth.user_for_token(self.token())
        return self._user

    def body(self):
        n = min(int(self.headers.get("Content-Length") or 0), 1_000_000)
        if not n:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode() or "{}")
        except ValueError:
            return dict(urllib.parse.parse_qsl(raw.decode()))

    def send(self, status=200, data=None, ctype="application/json", headers=None):
        if isinstance(data, (dict, list)):
            payload = json.dumps(data, default=str).encode()
        elif isinstance(data, str):
            payload = data.encode()
        else:
            payload = data or b""
        self.send_response(status)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith(("text", "application/json")) else ""))
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def ok(self, data=None, **kw):
        self.send(200, data if data is not None else {"ok": True}, **kw)

    def err(self, status, msg):
        self.send(status, {"error": msg})

    def audit(self, action, category, detail=""):
        u = self.user()
        self.db.audit(u["username"] if u else "anonymous", action, category, detail, self.client_address[0])

    def qs(self):
        return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).items()}

    # ------------------------------------------------------------------ dispatch
    def dispatch(self, method):
        path = urllib.parse.urlparse(self.path).path
        if not path.startswith("/api/"):
            return self.static(path)
        if method == "POST":
            origin = self.headers.get("Origin")
            if origin and urllib.parse.urlparse(origin).hostname not in ("127.0.0.1", "localhost", None):
                return self.err(403, "Cross-origin request blocked")
        for m, rx, role, fn in ROUTES:
            if m != method:
                continue
            mt = rx.match(path)
            if not mt:
                continue
            if role:
                u = self.user()
                if not u:
                    return self.err(401, "Please sign in")
                if ROLE_RANK.get(u["role"], 0) < ROLE_RANK[role]:
                    return self.err(403, f"Requires {role} role")
            try:
                return fn(self, *mt.groups())
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as e:
                log.exception("API error")
                return self.err(500, f"{type(e).__name__}: {e}")
        return self.err(404, "Not found")

    def do_GET(self):
        self.dispatch("GET")

    def do_HEAD(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def static(self, path):
        if path == "/":
            path = "/index.html"
        full = os.path.normpath(os.path.join(WEB_DIR, path.lstrip("/")))
        if not full.startswith(os.path.normpath(WEB_DIR)) or not os.path.isfile(full):
            full = os.path.join(WEB_DIR, "404.html")
            status = 404
        else:
            status = 200
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if full.endswith(".js"):
            ctype = "application/javascript"
        with open(full, "rb") as f:
            self.send(status, f.read(), ctype)


# ======================================================================================
# Public & auth
# ======================================================================================
@route("GET", "/api/health")
def health(h):
    h.ok({"status": "ok", "version": VERSION, "uptime": time.time() - h.app.started})


@route("GET", "/api/public/info")
def public_info(h):
    h.ok({"app": APP_NAME, "version": VERSION, "has_users": h.app.auth.user_count() > 0,
          "allow_signup": bool(h.db.get("allow_signup", True)) or h.app.auth.user_count() == 0,
          "sensors": [{"name": s["name"], "running": s["running"]} for s in h.app.sensors.status()]})


def _cookie(token, maxage):
    return f"ahp_token={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={maxage}"


@route("POST", "/api/auth/signup")
def signup(h):
    b = h.body()
    first = h.app.auth.user_count() == 0
    if not first and not h.db.get("allow_signup", True):
        return h.err(403, "Self sign-up is disabled by the administrator.")
    u, e = h.app.auth.signup(b.get("username", "").strip(), b.get("password", ""), b.get("email", "").strip())
    if e:
        return h.err(400, e)
    h.db.audit(u["username"], "account_created", "auth", f"role={u['role']}", h.client_address[0])
    sess, _ = h.app.auth.login(u["username"], b.get("password", ""), h.client_address[0])
    h.send(200, {"ok": True, "user": u, "first_admin": first}, headers={"Set-Cookie": _cookie(sess["token"], 43200)})


@route("POST", "/api/auth/login")
def login(h):
    b = h.body()
    s, e = h.app.auth.login(b.get("username", "").strip(), b.get("password", ""), h.client_address[0])
    if e:
        h.db.audit(b.get("username", "?"), "login_failed", "auth", "", h.client_address[0])
        return h.err(401, e)
    h.db.audit(s["username"], "login", "auth", "", h.client_address[0])
    h.send(200, {"ok": True, "username": s["username"], "role": s["role"]},
           headers={"Set-Cookie": _cookie(s["token"], 43200)})


@route("POST", "/api/auth/logout")
def logout(h):
    if h.user():
        h.audit("logout", "auth")
    h.app.auth.logout(h.token())
    h.send(200, {"ok": True}, headers={"Set-Cookie": _cookie("", 0)})


@route("GET", "/api/me", "viewer")
def me(h):
    u = dict(h.user())
    u["legal_ack"] = h.db.get("legal_ack")
    h.ok(u)


@route("GET", "/api/whoami")
def whoami(h):
    u = h.user()
    if u:
        u = dict(u)
        u["legal_ack"] = h.db.get("legal_ack")
    h.ok({"user": u})


@route("POST", "/api/me/password", "viewer")
def change_pw(h):
    b = h.body()
    e = h.app.auth.change_password(h.user()["id"], b.get("old", ""), b.get("new", ""))
    if e:
        return h.err(400, e)
    h.audit("password_changed", "auth")
    h.ok()


@route("POST", "/api/track", "viewer")
def track(h):
    b = h.body()
    page = re.sub(r"[^a-z0-9_-]", "", str(b.get("page", ""))[:30])
    secs = max(0.0, min(float(b.get("seconds", 0) or 0), 3600))
    if page:
        h.db.execute("INSERT INTO pageviews(ts, username, page, seconds) VALUES(?,?,?,?)",
                     (time.time(), h.user()["username"], page, secs))
    h.ok()


# ======================================================================================
# Dashboard & live data
# ======================================================================================
@route("GET", "/api/dashboard", "viewer")
def dashboard(h):
    q = h.qs()
    m = metrics.compute(h.db, q.get("range", "24h"), q.get("sim", "1") == "1")
    m["sensors_status"] = h.app.sensors.status()
    m["active"] = [{"id": s.id, "sensor": s.sensor, "ip": s.ip, "profile": s.profile, "threat": s.threat,
                    "strategy": s.arm, "persona": s.persona["key"], "commands": len(s.features["cmds"]),
                    "age": round(time.time() - s.started)} for s in list(h.app.core.active.values())]
    m["persona"] = h.app.core.morph.current()
    m["alerts_recent"] = h.db.query("SELECT * FROM alerts ORDER BY ts DESC LIMIT 8")
    m["kill_switch"] = h.db.get("kill_switch")
    m["campaign"] = h.app.sim.campaign
    h.ok(m)


@route("GET", "/api/live", "viewer")
def live(h):
    since = int(h.qs().get("since", 0) or 0)
    items = h.app.core.live_since(since)
    h.ok({"seq": h.app.core.live_seq, "items": items[-200:]})


@route("GET", "/api/sessions", "viewer")
def sessions(h):
    q = h.qs()
    where, params = ["1=1"], []
    for k in ("profile", "sensor", "strategy"):
        if q.get(k):
            where.append(f"{k}=?")
            params.append(q[k])
    if q.get("q"):
        where.append("(src_ip LIKE ? OR id LIKE ?)")
        params += [f"%{q['q']}%"] * 2
    if q.get("min_threat"):
        where.append("threat >= ?")
        params.append(int(q["min_threat"]))
    limit = min(int(q.get("limit", 100)), 1000)
    h.ok(h.db.query(f"SELECT * FROM hp_sessions WHERE {' AND '.join(where)} ORDER BY started DESC LIMIT {limit}", params))


@route("GET", "/api/sessions/([a-f0-9]+)", "viewer")
def session_detail(h, sid):
    s = h.db.one("SELECT * FROM hp_sessions WHERE id=?", (sid,))
    if not s:
        return h.err(404, "Session not found")
    s["events"] = h.db.query("SELECT * FROM events WHERE session_id=? ORDER BY ts", (sid,))
    for e in s["events"]:
        e["techniques"] = json.loads(e["techniques"]) if e["techniques"] else []
    s["creds"] = h.db.query("SELECT * FROM creds WHERE src_ip=? ORDER BY ts DESC LIMIT 20", (s["src_ip"],))
    act = h.app.core.active.get(sid)
    s["decisions"] = act.decisions if act else []
    s["reasons"] = act.reasons if act else []
    h.audit("session_viewed", "investigation", sid)
    h.ok(s)


@route("GET", "/api/iocs", "viewer")
def iocs(h):
    t = h.qs().get("type")
    if t:
        h.ok(h.db.query("SELECT * FROM iocs WHERE type=? ORDER BY last_seen DESC LIMIT 500", (t,)))
    else:
        h.ok(h.db.query("SELECT * FROM iocs ORDER BY last_seen DESC LIMIT 500"))


@route("GET", "/api/creds", "viewer")
def creds(h):
    h.ok(h.db.query("SELECT * FROM creds ORDER BY ts DESC LIMIT 300"))


@route("GET", "/api/alerts", "viewer")
def alerts(h):
    h.ok(h.db.query("SELECT * FROM alerts ORDER BY ts DESC LIMIT 300"))


@route("POST", "/api/alerts/(\\d+)/ack", "analyst")
def ack_alert(h, aid):
    h.db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (int(aid),))
    h.audit("alert_acknowledged", "investigation", aid)
    h.ok()


@route("POST", "/api/alerts/ack-all", "analyst")
def ack_all(h):
    h.db.execute("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0")
    h.audit("alerts_acknowledged_all", "investigation")
    h.ok()


@route("GET", "/api/metrics", "viewer")
def get_metrics(h):
    h.ok(metrics.compute(h.db, h.qs().get("range", "24h")))


# ======================================================================================
# The nine areas
# ======================================================================================
@route("GET", "/api/areas", "viewer")
def areas(h):
    s = h.db.settings()
    core = h.app.core
    m = metrics.compute(h.db, "24h")
    sens = h.app.sensors.status()
    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    out = {
        "scope": {"surfaces": s["scope_surfaces"], "deployment": s["scope_deployment"],
                  "consumers": s["scope_consumers"], "org_name": s["org_name"]},
        "infrastructure": {"host": platform.node(), "os": f"{platform.system()} {platform.release()}",
                           "python": sys.version.split()[0], "bind_host": s["bind_host"], "ui": f"{UI_HOST}:{UI_PORT}",
                           "data_dir": DATA_DIR, "db_size_kb": round(db_size / 1024, 1),
                           "threads": threading.active_count(), "uptime": round(time.time() - h.app.started),
                           "ports": s["ports"]},
        "sensors": sens,
        "adaptive": {"enabled": s["adaptive_enabled"], "persona": core.morph.current(), "personas": PERSONAS,
                     "morph_interval_min": s["morph_interval_min"], "morph_history": core.morph.history[-10:],
                     "next_morph_in": max(0, round(core.morph.last_rotation + int(s["morph_interval_min"]) * 60 - time.time())),
                     "arms": ARMS, "bandit": m["bandit"], "llm_enabled": s["llm_enabled"], "llm_calls": core.llm.calls,
                     "llm_error": core.llm.last_error, "consistency_profiles": core.consistency.count(),
                     "profiles": PROFILE_LABEL, "bandit_c": s["bandit_c"]},
        "pipeline": {"events": h.db.scalar("SELECT COUNT(*) FROM events"), "iocs": h.db.scalar("SELECT COUNT(*) FROM iocs"),
                     "enrich_queue": core.enrich_q.qsize(), "enriched": len(core.enrich_cache),
                     "abuseipdb": bool(s["abuseipdb_key"]), "virustotal": bool(s["virustotal_key"]),
                     "ioc_types": h.db.query("SELECT type, COUNT(*) c FROM iocs GROUP BY type"),
                     "live_seq": core.live_seq},
        "intel": {"misp": bool(s["misp_url"] and s["misp_key"]), "webhook": bool(s["webhook_url"]),
                  "syslog": bool(s["syslog_host"]), "alert_threshold": s["alert_threshold"],
                  "alerts": h.db.scalar("SELECT COUNT(*) FROM alerts"),
                  "delivered": h.db.scalar("SELECT COUNT(*) FROM alerts WHERE delivered != ''"),
                  "stix_objects": h.db.scalar("SELECT COUNT(*) FROM iocs")},
        "containment": {"kill_switch": s["kill_switch"], "lab_mode": s["lab_mode"], "bind_host": s["bind_host"],
                        "exposed": s["bind_host"] not in ("127.0.0.1", "localhost"),
                        "egress_allowlist": core.egress.allowlist(), "egress_blocked": list(core.egress.blocked)[-10:],
                        "rate_limited": core.ratelimit.dropped, "max_conn_per_min": s["max_conn_per_min"],
                        "max_session_secs": s["max_session_secs"], "max_concurrent_per_sensor": s["max_concurrent_per_sensor"],
                        "outbound_from_decoys": "never (wget/curl/ssh inside decoys are simulated)"},
        "governance": {"retention_days": s["retention_days"], "anonymize_ips": s["anonymize_ips"],
                       "allow_signup": s["allow_signup"], "legal_ack": s["legal_ack"], "legal_ack_by": s["legal_ack_by"],
                       "legal_ack_at": s["legal_ack_at"], "users": h.db.query("SELECT id, username, email, role, created_at, last_login FROM users"),
                       "audit_entries": h.db.scalar("SELECT COUNT(*) FROM audit")},
        "metrics": {"kpis": m["kpis"], "uplift": m["uplift"], "arms": m["arms"]},
    }
    h.ok(out)


def _masked_settings(db):
    s = db.settings()
    for k in SECRET_KEYS:
        if s.get(k):
            v = str(s[k])
            s[k] = "•" * 8 + v[-4:]
            s[k + "_set"] = True
        else:
            s[k + "_set"] = False
    return s


@route("GET", "/api/settings", "viewer")
def get_settings(h):
    h.ok(_masked_settings(h.db))


@route("POST", "/api/settings", "admin")
def post_settings(h):
    b = h.body()
    updates = {}
    for k, v in b.items():
        if k in SECRET_KEYS and isinstance(v, str) and v.startswith("•"):
            continue  # unchanged masked secret
        updates[k] = v
    if "ports" in updates:
        ports = {k: int(v) for k, v in updates["ports"].items()}
        if len(set(ports.values())) != len(ports) or any(not (1024 <= p <= 65535) for p in ports.values()):
            return h.err(400, "Ports must be unique and between 1024 and 65535.")
        if UI_PORT in ports.values():
            return h.err(400, f"Port {UI_PORT} is used by the console.")
        updates["ports"] = ports
    old = h.db.settings()
    h.db.set_settings(updates)
    changed = [k for k in updates if old.get(k) != h.db.get(k)]
    h.audit("settings_changed", "configuration", ", ".join(changed) or "no change")
    if any(k in changed for k in ("ports", "bind_host", "sensors_enabled")):
        h.app.sensors.restart_all()
    h.ok(_masked_settings(h.db))


@route("POST", "/api/sensors/(\\w+)/(start|stop)", "analyst")
def sensor_ctl(h, name, action):
    if name not in h.app.sensors.sensors:
        return h.err(404, "Unknown sensor")
    en = dict(h.db.get("sensors_enabled"))
    if action == "start":
        ok = h.app.sensors.start(name)
        en[name] = True
    else:
        h.app.sensors.stop(name)
        ok = True
        en[name] = False
    h.db.set_settings({"sensors_enabled": en})
    h.audit(f"sensor_{action}", "operations", name)
    h.ok({"ok": ok, "status": h.app.sensors.status()})


@route("POST", "/api/containment/killswitch", "analyst")
def killswitch(h):
    on = bool(h.body().get("on"))
    h.db.set_settings({"kill_switch": on})
    if on:
        for s in list(h.app.core.active.values()):
            s.close()
        h.app.sim.set_campaign(False)
    h.audit("kill_switch_" + ("on" if on else "off"), "containment")
    h.ok({"kill_switch": on})


@route("POST", "/api/containment/reset-decoys", "analyst")
def reset_decoys(h):
    h.app.core.consistency.reset()
    h.audit("decoys_reset", "containment", "virtual filesystem state wiped")
    h.ok()


@route("POST", "/api/engine/morph", "analyst")
def morph(h):
    p = h.app.core.morph.rotate("manual")
    h.audit("persona_rotated", "adaptive", p["key"])
    h.ok(p)


@route("POST", "/api/engine/reset-bandit", "admin")
def reset_bandit(h):
    h.app.core.bandit.reset()
    h.audit("bandit_reset", "adaptive")
    h.ok()


@route("POST", "/api/llm/test", "analyst")
def llm_test(h):
    was = h.db.get("llm_enabled")
    out = h.app.core.llm.generate("cat /etc/motd", h.app.core.morph.current(), "/root")
    h.audit("llm_tested", "adaptive", "ok" if out else h.app.core.llm.last_error)
    if out is None:
        return h.err(502, "LLM not reachable: " + h.app.core.llm.last_error +
                     (" (LLM is disabled in settings)" if not was else ""))
    h.ok({"output": out})


@route("POST", "/api/intel/test-webhook", "analyst")
def test_webhook(h):
    try:
        ok = intel.send_webhook(h.db, h.app.core.egress, {"severity": "low", "title": "Test alert from console",
                                                          "session_id": "test"})
        h.audit("webhook_tested", "intel", str(ok))
        h.ok({"sent": ok}) if ok else h.err(400, "Webhook URL is not configured")
    except Exception as e:
        h.err(502, str(e))


@route("POST", "/api/intel/test-syslog", "analyst")
def test_syslog(h):
    try:
        ok = intel.send_syslog(h.db, {"severity": "low", "title": "Test alert from console", "session_id": "test"})
        h.audit("syslog_tested", "intel", str(ok))
        h.ok({"sent": ok}) if ok else h.err(400, "Syslog host is not configured")
    except Exception as e:
        h.err(502, str(e))


@route("POST", "/api/intel/misp-push", "analyst")
def misp(h):
    try:
        r = intel.misp_push(h.db, h.app.core.egress)
        h.audit("misp_push", "intel", "ok")
        h.ok({"result": r})
    except Exception as e:
        h.audit("misp_push", "intel", f"failed: {e}")
        h.err(502, str(e))


@route("GET", "/api/intel/stix", "viewer")
def stix(h):
    h.audit("stix_exported", "reports")
    h.send(200, json.dumps(intel.stix_bundle(h.db, h.db.get("org_name")), indent=2), "application/json",
           headers={"Content-Disposition": f"attachment; filename=honeypot-stix-{time.strftime('%Y%m%d-%H%M')}.json"})


@route("POST", "/api/governance/purge", "admin")
def purge(h):
    days = h.body().get("days")
    counts = h.app.core.purge(days)
    h.audit("data_purged", "governance", json.dumps(counts))
    h.ok(counts)


@route("POST", "/api/governance/ack", "admin")
def legal_ack(h):
    u = h.user()
    h.db.set_settings({"legal_ack": True, "legal_ack_by": u["username"], "legal_ack_at": time.strftime("%Y-%m-%d %H:%M:%S")})
    h.audit("legal_acknowledged", "governance")
    h.ok()


@route("GET", "/api/users", "admin")
def users(h):
    h.ok(h.db.query("SELECT id, username, email, role, created_at, last_login FROM users"))


@route("POST", "/api/users/(\\d+)/role", "admin")
def user_role(h, uid):
    role = h.body().get("role")
    if role not in ROLES:
        return h.err(400, "Invalid role")
    if int(uid) == h.user()["id"] and role != "admin":
        return h.err(400, "You cannot demote yourself")
    h.db.execute("UPDATE users SET role=? WHERE id=?", (role, int(uid)))
    h.audit("role_changed", "governance", f"user {uid} -> {role}")
    h.ok()


# ======================================================================================
# Lab: simulator & web terminal
# ======================================================================================
@route("GET", "/api/sim/status", "viewer")
def sim_status(h):
    h.ok(h.app.sim.status())


@route("POST", "/api/sim/run", "analyst")
def sim_run(h):
    if h.db.get("kill_switch"):
        return h.err(409, "Kill switch is engaged - disable it in Containment first")
    sc = h.body().get("scenario", "random")
    try:
        r = h.app.sim.run(sc)
    except ValueError as e:
        return h.err(400, str(e))
    h.audit("simulation_run", "operations", r["scenario"])
    h.ok(r)


@route("POST", "/api/sim/campaign", "analyst")
def sim_campaign(h):
    b = h.body()
    if b.get("on") and h.db.get("kill_switch"):
        return h.err(409, "Kill switch is engaged")
    h.app.sim.set_campaign(bool(b.get("on")), b.get("rate"))
    h.audit("campaign_" + ("started" if b.get("on") else "stopped"), "operations", f"rate={h.app.sim.campaign_rate}/min")
    h.ok(h.app.sim.status())


@route("POST", "/api/lab/shell", "analyst")
def lab_shell(h):
    b = h.body()
    sid = b.get("sid")
    cmd = str(b.get("cmd", ""))[:500]
    entry = h.app.lab_sessions.get(sid)
    if not entry or entry[0].closed:
        sess = h.app.core.open_session("lab", "127.0.0.1", 0, True, "web-terminal")
        shell = FakeShell(sess.persona, sess.state, sess.arm, h.app.core.llm, "root")
        sess.login("root", "(web lab)", True)
        entry = (sess, shell)
        h.app.lab_sessions[sess.id] = entry
        h.audit("lab_terminal_opened", "operations", sess.id)
        if not cmd:
            return h.ok({"sid": sess.id, "prompt": shell.prompt, "output": f"Connected to decoy '{sess.persona['hostname']}' "
                         f"({sess.persona['os']}). Strategy: {sess.arm}.", "strategy": sess.arm,
                         "profile": sess.profile, "threat": sess.threat})
    sess, shell = entry
    out, meta = shell.handle(cmd)
    new_arm = sess.command(cmd.strip(), out, meta) if cmd.strip() else None
    if new_arm:
        shell.set_arm(new_arm)
    if meta["exit"]:
        sess.close()
    h.ok({"sid": sess.id, "prompt": shell.prompt, "output": out, "strategy": sess.arm, "profile": sess.profile,
          "threat": sess.threat, "reasons": sess.reasons, "closed": sess.closed, "adapted": bool(new_arm),
          "techniques": [t["id"] + " " + t["name"] for t in sess.techniques.values()]})


# ======================================================================================
# History / audit
# ======================================================================================
@route("GET", "/api/audit", "viewer")
def audit(h):
    q = h.qs()
    where, params = ["1=1"], []
    if q.get("category"):
        where.append("category=?")
        params.append(q["category"])
    if q.get("user"):
        where.append("username=?")
        params.append(q["user"])
    if q.get("q"):
        where.append("(action LIKE ? OR detail LIKE ?)")
        params += [f"%{q['q']}%"] * 2
    limit = min(int(q.get("limit", 200)), 2000)
    rows = h.db.query(f"SELECT * FROM audit WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT {limit}", params)
    cats = [r["category"] for r in h.db.query("SELECT DISTINCT category FROM audit")]
    h.ok({"rows": rows, "categories": cats})


@route("GET", "/api/audit.csv", "analyst")
def audit_csv(h):
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "user", "category", "action", "detail", "ip"])
    for r in h.db.query("SELECT * FROM audit ORDER BY ts DESC LIMIT 20000"):
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), r["username"], r["category"],
                    r["action"], r["detail"], r["ip"]])
    h.audit("audit_exported", "reports")
    h.send(200, buf.getvalue(), "text/csv", headers={"Content-Disposition": "attachment; filename=audit-log.csv"})


# ======================================================================================
# Reports
# ======================================================================================
@route("GET", "/api/reports/analysis", "viewer")
def report_analysis(h):
    q = h.qs()
    fmt, rng = q.get("format", "html"), q.get("range", "24h")
    stamp = time.strftime("%Y%m%d-%H%M")
    h.audit("report_downloaded", "reports", f"analysis {fmt} {rng}")
    if fmt == "csv":
        return h.send(200, reports.sessions_csv(h.db, rng), "text/csv",
                      headers={"Content-Disposition": f"attachment; filename=sessions-{stamp}.csv"})
    if fmt == "iocs":
        return h.send(200, reports.iocs_csv(h.db), "text/csv",
                      headers={"Content-Disposition": f"attachment; filename=iocs-{stamp}.csv"})
    if fmt == "json":
        return h.send(200, reports.analysis_json(h.db, rng), "application/json",
                      headers={"Content-Disposition": f"attachment; filename=analysis-{stamp}.json"})
    disp = "inline" if q.get("view") else "attachment"
    h.send(200, reports.analysis_html(h.db, rng, h.user()["username"]), "text/html",
           headers={"Content-Disposition": f"{disp}; filename=analysis-report-{stamp}.html"})


@route("GET", "/api/reports/adaptive", "viewer")
def report_adaptive(h):
    q = h.qs()
    scope = None if (q.get("all") and h.user()["role"] == "admin") else h.user()["username"]
    h.ok(metrics.user_activity(h.db, scope))


@route("GET", "/api/reports/adaptive.html", "viewer")
def report_adaptive_html(h):
    h.audit("report_downloaded", "reports", "adaptive analysis")
    disp = "inline" if h.qs().get("view") else "attachment"
    h.send(200, reports.adaptive_html(h.db, h.user()["username"]), "text/html",
           headers={"Content-Disposition": f"{disp}; filename=adaptive-analysis-{time.strftime('%Y%m%d-%H%M')}.html"})


# ======================================================================================
# Toolkit
# ======================================================================================
@route("GET", "/api/toolkit", "viewer")
def toolkit(h):
    s = h.db.settings()
    h.ok({
        "apis": [
            {"name": "AbuseIPDB", "key": "abuseipdb_key", "set": bool(s["abuseipdb_key"]), "required": False,
             "purpose": "IP reputation, country and ISP enrichment for real attacker IPs",
             "get": "https://www.abuseipdb.com/account/api"},
            {"name": "VirusTotal", "key": "virustotal_key", "set": bool(s["virustotal_key"]), "required": False,
             "purpose": "Reputation of malware download URLs captured from attackers",
             "get": "https://www.virustotal.com/gui/my-apikey"},
            {"name": "MISP", "key": "misp_key", "set": bool(s["misp_url"] and s["misp_key"]), "required": False,
             "purpose": "Push IOCs as a MISP event to your threat-intel platform", "get": "Your MISP instance > My Profile > Auth keys"},
            {"name": "Webhook (Slack / Teams / Discord)", "key": "webhook_url", "set": bool(s["webhook_url"]), "required": False,
             "purpose": "Real-time alert notifications", "get": "Incoming-webhook URL from your chat tool"},
            {"name": "Ollama (local LLM)", "key": "ollama_url", "set": bool(s["llm_enabled"]), "required": False,
             "purpose": "Generates realistic output for unknown shell commands (rich strategy)",
             "get": "https://ollama.com - run 'ollama pull llama3.2'"},
            {"name": "Syslog / SIEM", "key": "syslog_host", "set": bool(s["syslog_host"]), "required": False,
             "purpose": "CEF alerts over UDP to Wazuh, Splunk, QRadar, Sentinel collector", "get": "Your SIEM collector address"},
        ],
        "scenarios": SCENARIOS, "personas": PERSONAS, "arms": ARMS, "profiles": PROFILE_LABEL,
        "sensors": h.app.sensors.status(),
    })


@route("POST", "/api/system/shutdown")
def shutdown(h):
    u = h.user()
    tok = h.body().get("control_token")
    if not ((u and u["role"] == "admin") or (tok and secrets.compare_digest(tok, h.app.control_token))):
        return h.err(403, "Not allowed")
    h.ok({"stopping": True})
    h.app.shutdown()
