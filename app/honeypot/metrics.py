"""Success metrics & analytics queries (Area 9)."""
import json
import time
from collections import Counter

from .adaptive import ARMS, PROFILE_LABEL


def _since(range_key):
    return {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}.get(range_key, None)


def compute(db, range_key="24h", include_sim=True):
    span = _since(range_key)
    since = time.time() - span if span else 0
    sim = "" if include_sim else " AND simulated=0"
    S = f"FROM hp_sessions WHERE started >= ?{sim}"
    p = (since,)
    total = db.scalar(f"SELECT COUNT(*) {S}", p)
    k = {
        "sessions": total,
        "unique_ips": db.scalar(f"SELECT COUNT(DISTINCT src_ip) {S}", p),
        "events": db.scalar("SELECT COUNT(*) FROM events WHERE ts >= ?", p),
        "iocs": db.scalar("SELECT COUNT(*) FROM iocs WHERE last_seen >= ?", p),
        "alerts": db.scalar("SELECT COUNT(*) FROM alerts WHERE ts >= ?", p),
        "open_alerts": db.scalar("SELECT COUNT(*) FROM alerts WHERE acknowledged=0"),
        "creds": db.scalar("SELECT COUNT(*) FROM creds WHERE ts >= ?", p),
        "avg_duration": round(db.scalar(f"SELECT AVG(duration) {S}", p, 0) or 0, 1),
        "avg_commands": round(db.scalar(f"SELECT AVG(commands) {S} AND sensor IN ('telnet','lab')", p, 0) or 0, 1),
        "high_threat": db.scalar(f"SELECT COUNT(*) {S} AND threat >= 70", p),
        "detected": db.scalar(f"SELECT COUNT(*) {S} AND detected=1", p),
        "mttd": round(db.scalar("SELECT AVG(mttd) FROM alerts WHERE ts >= ?", p, 0) or 0, 1),
    }
    k["detection_rate"] = round(100.0 * k["detected"] / total, 1) if total else 0.0

    # time series: per-minute for 1h, hourly otherwise
    bucket = 60 if range_key == "1h" else (3600 if range_key in ("24h", None, "all") else 86400)
    nb = 60 if range_key == "1h" else (24 if range_key == "24h" else (7 if range_key == "7d" else 30))
    now = time.time()
    start = now - bucket * nb
    rows = db.query(f"SELECT CAST((started - ?)/? AS INTEGER) b, COUNT(*) c, AVG(threat) t FROM hp_sessions "
                    f"WHERE started >= ?{sim} GROUP BY b", (start, bucket, start))
    series = [{"t": start + i * bucket, "sessions": 0, "threat": 0} for i in range(nb)]
    for r in rows:
        if 0 <= r["b"] < nb:
            series[r["b"]]["sessions"] = r["c"]
            series[r["b"]]["threat"] = round(r["t"] or 0, 1)

    profiles = {r["profile"]: r["c"] for r in db.query(f"SELECT profile, COUNT(*) c {S} GROUP BY profile", p)}
    sensors = {r["sensor"]: r["c"] for r in db.query(f"SELECT sensor, COUNT(*) c {S} GROUP BY sensor", p)}
    countries = db.query(f"SELECT country, COUNT(*) c {S} GROUP BY country ORDER BY c DESC LIMIT 10", p)
    top_ips = db.query(f"SELECT src_ip, country, COUNT(*) c, MAX(threat) threat, MAX(profile) profile {S} "
                       "GROUP BY src_ip ORDER BY threat DESC, c DESC LIMIT 10", p)

    tech, tactics = Counter(), Counter()
    names = {}
    for r in db.query("SELECT techniques FROM events WHERE ts >= ? AND techniques != ''", p):
        for t in json.loads(r["techniques"]):
            tech[t["id"]] += 1
            tactics[t["tactic"]] += 1
            names[t["id"]] = t["name"]
    techniques = [{"id": t, "name": names[t], "count": c} for t, c in tech.most_common(12)]

    creds = db.query("SELECT username, password, COUNT(*) c FROM creds WHERE ts >= ? GROUP BY username, password "
                     "ORDER BY c DESC LIMIT 10", p)
    commands = db.query("SELECT data cmd, COUNT(*) c FROM events WHERE ts >= ? AND type='command' GROUP BY data "
                        "ORDER BY c DESC LIMIT 10", p)

    # adaptive vs static comparison
    arms = []
    for a in ARMS:
        r = db.one(f"SELECT COUNT(*) n, AVG(duration) d, AVG(commands) c, AVG(threat) t, SUM(detected) det {S} "
                   "AND strategy=? AND ended IS NOT NULL", (since, a))
        arms.append({"arm": a, "desc": ARMS[a], "sessions": r["n"] or 0, "avg_duration": round(r["d"] or 0, 1),
                     "avg_commands": round(r["c"] or 0, 1), "avg_threat": round(r["t"] or 0, 1),
                     "detected": r["det"] or 0})
    base = next(x for x in arms if x["arm"] == "static")
    adaptive = [x for x in arms if x["arm"] != "static" and x["sessions"]]
    if adaptive and base["sessions"]:
        ad_dur = sum(x["avg_duration"] * x["sessions"] for x in adaptive) / sum(x["sessions"] for x in adaptive)
        ad_cmd = sum(x["avg_commands"] * x["sessions"] for x in adaptive) / sum(x["sessions"] for x in adaptive)
        uplift = {"duration_pct": round(100 * (ad_dur - base["avg_duration"]) / base["avg_duration"], 1) if base["avg_duration"] else None,
                  "commands_pct": round(100 * (ad_cmd - base["avg_commands"]) / base["avg_commands"], 1) if base["avg_commands"] else None}
    else:
        uplift = {"duration_pct": None, "commands_pct": None}
    bandit = db.query("SELECT profile, arm, pulls, ROUND(reward / MAX(pulls,1), 3) mean FROM bandit ORDER BY profile, arm")

    return {"range": range_key, "kpis": k, "series": series, "bucket": bucket, "profiles": profiles,
            "profile_labels": PROFILE_LABEL, "sensors": sensors, "countries": countries, "top_ips": top_ips,
            "techniques": techniques, "tactics": dict(tactics.most_common()), "creds": creds, "commands": commands,
            "arms": arms, "uplift": uplift, "bandit": bandit}


def user_activity(db, username=None, days=30):
    """Adaptive analysis of the *operator's* own behaviour in the console."""
    since = time.time() - days * 86400
    w = " AND username=?" if username else ""
    p = (since, username) if username else (since,)
    pages = db.query(f"SELECT page, COUNT(*) views, SUM(seconds) secs FROM pageviews WHERE ts>=?{w} GROUP BY page "
                     "ORDER BY secs DESC", p)
    cats = db.query(f"SELECT category, COUNT(*) c FROM audit WHERE ts>=?{w} GROUP BY category ORDER BY c DESC", p)
    actions = db.query(f"SELECT action, COUNT(*) c FROM audit WHERE ts>=?{w} GROUP BY action ORDER BY c DESC LIMIT 12", p)
    hours = Counter()
    for r in db.query(f"SELECT ts FROM pageviews WHERE ts>=?{w}", p):
        hours[time.localtime(r["ts"]).tm_hour] += 1
    groups = {"Monitoring": ["dashboard", "areas"], "Investigation": ["history", "reports", "sessions"],
              "Operations": ["lab", "toolkit", "settings"], "Learning": ["about", "games"]}
    total_secs = sum((r["secs"] or 0) for r in pages) or 0
    by_group = {}
    for g, keys in groups.items():
        by_group[g] = round(sum((r["secs"] or 0) for r in pages if r["page"] in keys), 1)
    ratios = {g: (round(100 * v / total_secs, 1) if total_secs else 0) for g, v in by_group.items()}
    insights = []
    if total_secs == 0:
        insights.append("No activity recorded yet - browse the console and this analysis will adapt to you.")
    else:
        top = max(ratios, key=ratios.get)
        insights.append(f"Your focus is {top} ({ratios[top]}% of active time).")
        if ratios.get("Investigation", 0) < 15:
            insights.append("Investigation time is low - review History and download the analysis report to turn data into intel.")
        if ratios.get("Monitoring", 0) > 60:
            insights.append("Most time is spent watching dashboards - enable webhook/syslog alerts so you can step away safely.")
        if ratios.get("Operations", 0) < 10:
            insights.append("Try the Lab: run simulated attacks or the web terminal to see the adaptive engine react.")
        if ratios.get("Learning", 0) > 40:
            insights.append("Heavy use of learning pages - great for onboarding; next step is running a campaign in the Lab.")
    hp = compute(db, "30d")
    prof = hp["profiles"]
    tot = sum(prof.values()) or 1
    attack_ratios = {PROFILE_LABEL.get(k, k): round(100 * v / tot, 1) for k, v in prof.items()}
    bots = prof.get("bot", 0) + prof.get("scanner", 0)
    humans = prof.get("script_kiddie", 0) + prof.get("skilled", 0)
    return {"pages": pages, "categories": cats, "actions": actions, "hours": [hours.get(h, 0) for h in range(24)],
            "groups": by_group, "ratios": ratios, "insights": insights, "total_secs": round(total_secs, 1),
            "attack_ratios": attack_ratios,
            "automation_ratio": f"{bots}:{humans}" if humans else f"{bots}:0",
            "kpis": hp["kpis"]}
