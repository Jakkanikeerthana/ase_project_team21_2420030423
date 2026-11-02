"""Core orchestration: honeypot session lifecycle, data pipeline (tagging, IOC extraction,
enrichment), adaptive decisions, alerting, governance jobs and the live event stream."""
import base64
import json
import logging
import queue
import threading
import time
import uuid
from collections import deque

from . import attack, intel
from .adaptive import (ARMS, Bandit, ConsistencyStore, LLM, Morph, PROFILE_LABEL, HP_CHECK,
                       engagement_reward, profile_session)
from .containment import EgressGuard, RateLimiter, anonymize

log = logging.getLogger("honeypot")

# Lab geo table for the simulator's reserved benchmarking range 198.18.0.0/15
LAB_GEO = [("CN", "China", "AS4134"), ("RU", "Russia", "AS12389"), ("US", "United States", "AS14061"),
           ("BR", "Brazil", "AS28573"), ("NL", "Netherlands", "AS49981"), ("VN", "Vietnam", "AS45899"),
           ("IN", "India", "AS9829"), ("DE", "Germany", "AS24940"), ("KR", "South Korea", "AS4766"),
           ("IR", "Iran", "AS58224"), ("ID", "Indonesia", "AS7713"), ("UA", "Ukraine", "AS15895")]
COUNTRY_NAMES = {c: n for c, n, _ in LAB_GEO}


class HPSession:
    def __init__(self, core, sensor, ip, port, simulated=False, client=""):
        self.core = core
        self.id = uuid.uuid4().hex[:12]
        self.sensor = sensor
        self.raw_ip = ip
        self.ip = anonymize(ip) if core.db.get("anonymize_ips") else ip
        self.port = port
        self.simulated = simulated
        self.started = time.time()
        self.persona = core.morph.current()
        self.state = core.consistency.load(ip)
        self.state["visits"] = self.state.get("visits", 0) + 1
        self.features = {"sensor": sensor, "cmds": [], "times": [], "unknown": 0, "breadcrumbs": 0,
                         "logins": 0, "login_times": [], "tactics": [], "paths": 0, "exploits": 0,
                         "scanner_ua": False, "writes": 0, "canary_used": False, "ua": ""}
        self.techniques = {}
        self.threat = 0
        self.profile = "unknown"
        self.confidence = 0.0
        self.reasons = []
        self.arm, why = core.bandit.select(self.predicted_profile())
        self.decisions = [{"ts": self.started, "arm": self.arm, "profile": "unknown", "why": why}]
        self.iocs = 0
        self.alerted = False
        self.login_ok = False
        self.detected = False
        self.closed = False
        self.last_activity = self.started
        country, cname, asn = core.geo(ip)
        self.country, self.asn = country, asn
        core.db.execute(
            "INSERT INTO hp_sessions(id, sensor, src_ip, src_port, country, asn, started, persona, strategy, simulated, client)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (self.id, sensor, self.ip, port, country, asn, self.started, self.persona["key"], self.arm,
             int(simulated), client[:200]))
        core.active[self.id] = self
        core.push_live({"kind": "session_open", "session": self.id, "sensor": sensor, "ip": self.ip,
                        "country": country, "persona": self.persona["key"], "strategy": self.arm,
                        "simulated": simulated})
        core.enqueue_enrichment("ip", ip, self.id)
        if attack.is_public(ip) or ip.startswith("198.1"):
            core.add_ioc("ip", self.ip, self)

    def predicted_profile(self):
        prev = self.core.db.one("SELECT profile FROM hp_sessions WHERE src_ip=? AND profile!='unknown' "
                                "ORDER BY started DESC LIMIT 1", (self.raw_ip,))
        return prev["profile"] if prev else "unknown"

    # ------------------------------------------------------------------ events
    def event(self, etype, data="", response="", techniques=None, ioc_text=None):
        now = time.time()
        self.last_activity = now
        techniques = list(techniques or [])
        for t in techniques:
            if t["id"] not in self.techniques:
                self.techniques[t["id"]] = t
                self.features["tactics"].append(t["tactic"])
        self.core.db.execute(
            "INSERT INTO events(ts, session_id, sensor, src_ip, type, data, response, techniques) VALUES(?,?,?,?,?,?,?,?)",
            (now, self.id, self.sensor, self.ip, etype, str(data)[:4000], str(response)[:4000],
             json.dumps(techniques) if techniques else ""))
        for itype, val in attack.extract_iocs(ioc_text if ioc_text is not None else str(data)):
            self.core.add_ioc(itype, val, self)
            self.iocs += 1
            if itype == "url":
                self.core.enqueue_enrichment("url", val, self.id)
        self.recompute()
        self.core.push_live({"kind": "event", "session": self.id, "sensor": self.sensor, "ip": self.ip,
                             "type": etype, "data": str(data)[:200], "profile": self.profile,
                             "threat": self.threat, "strategy": self.arm,
                             "techniques": [t["id"] for t in techniques]})

    def command(self, cmd, response, meta=None):
        meta = meta or {}
        self.features["cmds"].append(cmd)
        self.features["times"].append(time.time())
        self.features["unknown"] += meta.get("unknown", 0)
        if meta.get("breadcrumb"):
            self.features["breadcrumbs"] += 1
        techs = attack.tag_shell(cmd)
        if not any(t["id"] == "T1059.004" for t in techs):
            techs.append(attack.tech("T1059.004"))
        if HP_CHECK.search(cmd):
            self.detected = True
        self.event("command", cmd, response, techs)
        if meta.get("breadcrumb"):
            self.core.raise_alert(self, "high", f"Canary breadcrumb file read on {self.sensor} ({cmd[:60]})", "breadcrumb")
        # Adaptive re-decision after the 3rd command, once a profile is known
        if len(self.features["cmds"]) == 3 and self.core.db.get("adaptive_enabled", True):
            new_arm, why = self.core.bandit.select(self.profile)
            if new_arm != self.arm:
                self.decisions.append({"ts": time.time(), "arm": new_arm, "profile": self.profile, "why": why})
                self.arm = new_arm
                self.core.db.execute("UPDATE hp_sessions SET strategy=? WHERE id=?", (new_arm, self.id))
                self.core.push_live({"kind": "adapt", "session": self.id, "ip": self.ip, "profile": self.profile,
                                     "strategy": new_arm, "why": why})
                return new_arm
        return None

    def login(self, username, password, success):
        self.features["logins"] += 1
        self.features["login_times"].append(time.time())
        lt = self.features["login_times"]
        if len(lt) > 1:
            self.features["login_gap"] = (lt[-1] - lt[0]) / (len(lt) - 1)
        self.core.db.execute("INSERT INTO creds(ts, sensor, src_ip, username, password, success) VALUES(?,?,?,?,?,?)",
                             (time.time(), self.sensor, self.ip, username[:100], password[:100], int(success)))
        techs = [attack.tech("T1110.001")]
        if success:
            techs.append(attack.tech("T1078"))
            self.login_ok = True
        if password and "Canary" in password:
            self.features["canary_used"] = True
            self.core.raise_alert(self, "critical", f"Leaked canary credential re-used on {self.sensor}", "canary")
        self.event("login_success" if success else "login_failed", f"{username}:{password}", "", techs, ioc_text="")

    def recompute(self):
        old = self.profile
        self.profile, self.confidence, self.reasons = profile_session(self.features)
        score = sum(t["severity"] for t in self.techniques.values())
        score += 10 * self.features["breadcrumbs"] + (15 if self.login_ok else 0) + 3 * min(self.iocs, 5)
        if self.features["canary_used"]:
            score += 30
        self.threat = int(min(100, score))
        self.core.db.execute(
            "UPDATE hp_sessions SET profile=?, threat=?, commands=?, duration=?, detected=?, login_ok=?, interaction=? WHERE id=?",
            (self.profile, self.threat, len(self.features["cmds"]), time.time() - self.started, int(self.detected),
             int(self.login_ok), self.interaction(), self.id))
        if old != self.profile and old != "unknown":
            self.core.push_live({"kind": "profile", "session": self.id, "ip": self.ip, "profile": self.profile,
                                 "reasons": self.reasons})
        if self.threat >= int(self.core.db.get("alert_threshold", 70)) and not self.alerted:
            self.core.raise_alert(self, "high" if self.threat < 90 else "critical",
                                  f"{PROFILE_LABEL.get(self.profile, self.profile)} reached threat {self.threat} on {self.sensor}",
                                  "threat")

    def interaction(self):
        return {"static": "low", "tarpit": "medium", "breadcrumbs": "medium", "rich": "high"}.get(self.arm, "low")

    def close(self):
        if self.closed:
            return
        self.closed = True
        dur = time.time() - self.started
        n = len(self.features["cmds"])
        unknown_tail = self.features["unknown"] >= 2 and n <= 6
        if unknown_tail:
            self.detected = True
        self.recompute()
        bonus = 0.1 if (self.features["breadcrumbs"] or self.iocs) else 0.0
        reward = engagement_reward(n if self.sensor not in ("http", "modbus") else len(self.features["times"]), dur, bonus)
        if self.sensor in ("telnet", "lab", "http", "modbus", "ftp"):
            self.core.bandit.update(self.profile, self.arm, reward)
        self.core.db.execute("UPDATE hp_sessions SET ended=?, duration=?, detected=? WHERE id=?",
                             (time.time(), dur, int(self.detected), self.id))
        self.core.consistency.save(self.raw_ip, self.state)
        self.core.active.pop(self.id, None)
        self.core.push_live({"kind": "session_close", "session": self.id, "ip": self.ip, "profile": self.profile,
                             "threat": self.threat, "duration": round(dur, 1), "commands": n, "reward": reward,
                             "strategy": self.arm})


class Core:
    def __init__(self, db):
        self.db = db
        self.egress = EgressGuard(db)
        self.ratelimit = RateLimiter()
        self.morph = Morph(db)
        self.bandit = Bandit(db)
        self.consistency = ConsistencyStore(db)
        self.llm = LLM(db, self.egress)
        self.active = {}
        self.live = deque(maxlen=500)
        self.live_seq = 0
        self.live_lock = threading.Lock()
        self.enrich_q = queue.Queue(maxsize=2000)
        self.enrich_cache = {}
        self.started = time.time()
        self.stop_flag = threading.Event()
        threading.Thread(target=self._enrich_worker, daemon=True, name="enrich").start()
        threading.Thread(target=self._housekeeping, daemon=True, name="housekeeping").start()

    # ------------------------------------------------------------------ live stream
    def push_live(self, item):
        with self.live_lock:
            self.live_seq += 1
            item["seq"] = self.live_seq
            item["ts"] = time.time()
            self.live.append(item)

    def live_since(self, seq):
        with self.live_lock:
            return [x for x in self.live if x["seq"] > seq]

    # ------------------------------------------------------------------ sessions
    def open_session(self, sensor, ip, port, simulated=False, client=""):
        return HPSession(self, sensor, ip, port, simulated, client)

    def geo(self, ip):
        if ip.startswith("198.18.") or ip.startswith("198.19."):
            idx = int(ip.split(".")[2]) % len(LAB_GEO)
            c, n, asn = LAB_GEO[idx]
            return c, n, asn + " (lab)"
        if ip.startswith("127.") or not attack.is_public(ip):
            return "LAN", "Local / private network", "-"
        cached = self.enrich_cache.get(("ip", ip))
        if cached:
            return cached.get("countryCode", "??"), cached.get("countryCode", "Unknown"), cached.get("isp", "")
        return "??", "Unknown", ""

    def add_ioc(self, itype, value, sess):
        now = time.time()
        self.db.execute(
            "INSERT INTO iocs(type, value, session_id, sensor, first_seen, last_seen, count) VALUES(?,?,?,?,?,?,1) "
            "ON CONFLICT(type, value) DO UPDATE SET last_seen=excluded.last_seen, count=count+1",
            (itype, value[:500], sess.id, sess.sensor, now, now))

    # ------------------------------------------------------------------ alerts
    def raise_alert(self, sess, severity, title, atype="alert"):
        if atype == "threat":
            sess.alerted = True
            self.db.execute("UPDATE hp_sessions SET alerted=1 WHERE id=?", (sess.id,))
        mttd = time.time() - sess.started
        alert = {"severity": severity, "title": title, "session_id": sess.id, "src_ip": sess.ip, "type": atype,
                 "threat": sess.threat, "profile": sess.profile}
        aid = self.db.execute("INSERT INTO alerts(ts, severity, title, session_id, detail, mttd) VALUES(?,?,?,?,?,?)",
                              (time.time(), severity, title, sess.id, json.dumps(alert), mttd))
        self.push_live({"kind": "alert", "severity": severity, "title": title, "session": sess.id, "ip": sess.ip})
        threading.Thread(target=self._deliver_alert, args=(aid, alert), daemon=True).start()

    def _deliver_alert(self, aid, alert):
        delivered = []
        for name, fn in (("webhook", lambda: intel.send_webhook(self.db, self.egress, alert)),
                         ("syslog", lambda: intel.send_syslog(self.db, alert))):
            try:
                if fn():
                    delivered.append(name)
            except Exception as e:
                delivered.append(f"{name}:error")
                log.warning("alert delivery %s failed: %s", name, e)
        if delivered:
            self.db.execute("UPDATE alerts SET delivered=? WHERE id=?", (",".join(delivered), aid))

    # ------------------------------------------------------------------ enrichment
    def enqueue_enrichment(self, kind, value, sid):
        if kind == "ip" and not attack.is_public(value):
            return
        if (kind, value) in self.enrich_cache:
            return
        try:
            self.enrich_q.put_nowait((kind, value, sid))
        except queue.Full:
            pass

    def _enrich_worker(self):
        while not self.stop_flag.is_set():
            try:
                kind, value, sid = self.enrich_q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                if kind == "ip" and self.db.get("abuseipdb_key"):
                    d = self.egress.request_json(
                        f"https://api.abuseipdb.com/api/v2/check?ipAddress={value}&maxAgeInDays=90",
                        headers={"Key": self.db.get("abuseipdb_key"), "Accept": "application/json"}).get("data", {})
                    self.enrich_cache[(kind, value)] = d
                    self.db.execute("UPDATE hp_sessions SET country=?, asn=?, abuse_score=? WHERE src_ip=?",
                                    (d.get("countryCode", "??"), d.get("isp", ""), d.get("abuseConfidenceScore", -1), value))
                    self.db.execute("UPDATE iocs SET enrichment=? WHERE type='ip' AND value=?",
                                    (json.dumps({"abuse_score": d.get("abuseConfidenceScore"), "isp": d.get("isp"),
                                                 "country": d.get("countryCode")}), value))
                elif kind == "url" and self.db.get("virustotal_key"):
                    uid = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
                    d = self.egress.request_json(f"https://www.virustotal.com/api/v3/urls/{uid}",
                                                 headers={"x-apikey": self.db.get("virustotal_key")})
                    stats = d.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    self.enrich_cache[(kind, value)] = stats
                    self.db.execute("UPDATE iocs SET enrichment=? WHERE type='url' AND value=?",
                                    (json.dumps({"virustotal": stats}), value))
            except Exception as e:
                self.enrich_cache[(kind, value)] = {"error": str(e)[:120]}

    # ------------------------------------------------------------------ housekeeping
    def _housekeeping(self):
        last_purge = 0
        while not self.stop_flag.is_set():
            time.sleep(2)
            now = time.time()
            idle_limit = 60
            max_secs = int(self.db.get("max_session_secs", 300))
            for s in list(self.active.values()):
                if s.sensor in ("http", "lab") and now - s.last_activity > idle_limit:
                    s.close()
                elif now - s.started > max_secs + 30:
                    s.close()
            if now - last_purge > 3600:
                last_purge = now
                try:
                    self.purge()
                except Exception as e:
                    log.warning("purge failed: %s", e)

    def purge(self, days=None):
        days = int(days if days is not None else self.db.get("retention_days", 30))
        cutoff = time.time() - days * 86400
        counts = {}
        for table, col in (("events", "ts"), ("hp_sessions", "started"), ("creds", "ts"), ("alerts", "ts"),
                           ("iocs", "last_seen"), ("pageviews", "ts")):
            counts[table] = self.db.scalar(f"SELECT COUNT(*) FROM {table} WHERE {col} < ?", (cutoff,))
            self.db.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
        self.db.execute("DELETE FROM audit WHERE ts < ?", (time.time() - 365 * 86400,))
        self.db.execute("DELETE FROM auth_sessions WHERE expires < ?", (time.time(),))
        return counts
