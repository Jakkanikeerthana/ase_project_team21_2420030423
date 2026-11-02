"""Downloadable reports: analysis report (HTML/CSV/JSON) and adaptive user-activity report."""
import csv
import html
import io
import json
import time

from . import metrics
from .config import APP_NAME, VERSION

CSS = """body{font-family:Segoe UI,Arial,sans-serif;color:#2b1b23;background:#fff;margin:0;padding:32px;max-width:1000px;margin:auto}
h1{color:#b8326a;margin:0}h2{color:#b8326a;border-bottom:2px solid #fbd3e2;padding-bottom:4px;margin-top:32px}
.meta{color:#7a5866;font-size:13px}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}
.k{background:#fff4f8;border:1px solid #fbd3e2;border-radius:10px;padding:12px}.k b{display:block;font-size:22px;color:#2b1b23}
.k span{font-size:12px;color:#7a5866}table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #f6dbe6}th{background:#fff4f8}
.note{background:#fff4f8;border-left:4px solid #e05a8a;padding:10px 14px;border-radius:6px;margin:8px 0}
code{background:#fbe7ef;padding:1px 4px;border-radius:4px}@media print{body{padding:0}.noprint{display:none}}
button{background:#e05a8a;color:#fff;border:0;border-radius:8px;padding:8px 14px;cursor:pointer}"""


def _bars(items, label_key, value_key, width=620):
    items = [i for i in items if i.get(value_key)]
    if not items:
        return "<p class='meta'>No data in this period.</p>"
    mx = max(i[value_key] for i in items) or 1
    h = 26 * len(items) + 10
    rows = []
    for n, i in enumerate(items):
        w = int((width - 260) * i[value_key] / mx)
        y = 8 + n * 26
        rows.append(f"<text x='0' y='{y + 13}' font-size='12' fill='#2b1b23'>{html.escape(str(i[label_key]))[:34]}</text>"
                    f"<rect x='240' y='{y}' width='{max(w, 2)}' height='16' rx='4' fill='#e05a8a'/>"
                    f"<text x='{246 + w}' y='{y + 13}' font-size='12' fill='#7a5866'>{i[value_key]}</text>")
    return f"<svg width='{width}' height='{h}' role='img'>{''.join(rows)}</svg>"


def _table(rows, cols):
    if not rows:
        return "<p class='meta'>No records.</p>"
    head = "".join(f"<th>{html.escape(c[1])}</th>" for c in cols)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(r.get(c[0], '')))}</td>" for c in cols) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def analysis_html(db, range_key="24h", user="analyst"):
    m = metrics.compute(db, range_key)
    k = m["kpis"]
    org = db.get("org_name", "")
    prof = [{"p": m["profile_labels"].get(a, a), "c": b} for a, b in m["profiles"].items()]
    sens = [{"s": a, "c": b} for a, b in m["sensors"].items()]
    tact = [{"t": a, "c": b} for a, b in m["tactics"].items()]
    alerts = db.query("SELECT ts, severity, title, session_id FROM alerts ORDER BY ts DESC LIMIT 15")
    for a in alerts:
        a["ts"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["ts"]))
    iocs = db.query("SELECT type, value, sensor, count FROM iocs ORDER BY count DESC, last_seen DESC LIMIT 25")
    up = m["uplift"]
    uplift_txt = ("Not enough data yet to compare adaptive strategies against the static baseline."
                  if up["duration_pct"] is None else
                  f"Adaptive strategies kept attackers engaged <b>{up['duration_pct']:+}%</b> longer and drew "
                  f"<b>{(up['commands_pct'] or 0):+}%</b> more commands than the static baseline.")
    recs = []
    if k["high_threat"]:
        recs.append(f"{k['high_threat']} high-threat session(s): block the source IPs at the perimeter and share IOCs via STIX/MISP.")
    if any(t["id"].startswith("T08") for t in m["techniques"]):
        recs.append("ICS techniques observed: review Modbus exposure of real PLCs and enforce write-protection.")
    if any(t["id"] == "T1110.001" for t in m["techniques"]):
        recs.append("Credential brute force observed: ensure real services use key-based auth / MFA and lockout.")
    if any(t["id"] == "T1496" for t in m["techniques"]):
        recs.append("Crypto-mining activity: monitor outbound connections to mining pools (stratum) on real hosts.")
    if k["detection_rate"] > 20:
        recs.append("Detection rate above 20%: enable 'rich' strategy / local LLM to improve realism.")
    if not recs:
        recs.append("No critical findings in this period. Keep the sensors running to build a baseline.")
    period = {"1h": "last hour", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days"}.get(range_key, "all time")
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{APP_NAME} - Analysis Report</title>
<style>{CSS}</style></head><body>
<div class='noprint' style='text-align:right'><button onclick='window.print()'>Save as PDF / Print</button></div>
<h1>{APP_NAME} &mdash; Threat Analysis Report</h1>
<p class='meta'>{html.escape(org)} &middot; Period: {period} &middot; Generated {time.strftime('%Y-%m-%d %H:%M:%S')} by {html.escape(user)} &middot; v{VERSION}</p>
<h2>1. Executive summary</h2>
<div class='kpis'>
<div class='k'><b>{k['sessions']}</b><span>Attacker sessions</span></div>
<div class='k'><b>{k['unique_ips']}</b><span>Unique source IPs</span></div>
<div class='k'><b>{k['high_threat']}</b><span>High-threat sessions</span></div>
<div class='k'><b>{k['iocs']}</b><span>Indicators of compromise</span></div>
<div class='k'><b>{k['avg_duration']}s</b><span>Avg engagement time</span></div>
<div class='k'><b>{k['avg_commands']}</b><span>Avg commands / shell session</span></div>
<div class='k'><b>{k['detection_rate']}%</b><span>Suspected honeypot detection</span></div>
<div class='k'><b>{k['mttd']}s</b><span>Mean time to detect (alert)</span></div></div>
<div class='note'>{uplift_txt}</div>
<h2>2. Who attacked (attacker profiles)</h2>{_bars(prof, 'p', 'c')}
<h2>3. Where (sensors &amp; origin)</h2>{_bars(sens, 's', 'c')}{_bars(m['countries'], 'country', 'c')}
<h2>4. How (MITRE ATT&amp;CK)</h2>{_bars(m['techniques'], 'name', 'count')}
<h3>Tactics</h3>{_bars(tact, 't', 'c')}
<h2>5. Adaptive engine performance</h2>
{_table(m['arms'], [('arm', 'Strategy'), ('desc', 'Description'), ('sessions', 'Sessions'), ('avg_duration', 'Avg duration (s)'), ('avg_commands', 'Avg commands'), ('detected', 'Suspected detections')])}
<h2>6. Top attackers</h2>{_table(m['top_ips'], [('src_ip', 'Source IP'), ('country', 'Country'), ('c', 'Sessions'), ('threat', 'Max threat'), ('profile', 'Profile')])}
<h2>7. Credentials tried</h2>{_table(m['creds'], [('username', 'Username'), ('password', 'Password'), ('c', 'Attempts')])}
<h2>8. Top commands</h2>{_table(m['commands'], [('cmd', 'Command'), ('c', 'Count')])}
<h2>9. Indicators of compromise</h2>{_table(iocs, [('type', 'Type'), ('value', 'Value'), ('sensor', 'Sensor'), ('count', 'Sightings')])}
<h2>10. Alerts</h2>{_table(alerts, [('ts', 'Time'), ('severity', 'Severity'), ('title', 'Alert'), ('session_id', 'Session')])}
<h2>11. Recommendations</h2><ul>{''.join(f'<li>{r}</li>' for r in recs)}</ul>
<p class='meta'>Simulated lab traffic uses the reserved 198.18.0.0/15 range. Canary credentials in this report are decoys and grant no access.</p>
</body></html>"""


def sessions_csv(db, range_key="24h"):
    span = metrics._since(range_key)
    since = time.time() - span if span else 0
    rows = db.query("SELECT * FROM hp_sessions WHERE started >= ? ORDER BY started DESC", (since,))
    buf = io.StringIO()
    cols = ["id", "sensor", "src_ip", "country", "asn", "started", "duration", "commands", "profile", "threat",
            "strategy", "persona", "interaction", "detected", "simulated", "login_ok", "client"]
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        r["started"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["started"]))
        r["duration"] = round(r["duration"] or 0, 1)
        w.writerow([r.get(c, "") for c in cols])
    return buf.getvalue()


def iocs_csv(db):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "sensor", "count", "first_seen", "last_seen", "enrichment"])
    for r in db.query("SELECT * FROM iocs ORDER BY last_seen DESC"):
        w.writerow([r["type"], r["value"], r["sensor"], r["count"],
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["first_seen"])),
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["last_seen"])), r["enrichment"]])
    return buf.getvalue()


def analysis_json(db, range_key="24h"):
    m = metrics.compute(db, range_key)
    m["generated"] = time.time()
    return json.dumps(m, indent=2, default=str)


def adaptive_html(db, username):
    a = metrics.user_activity(db, username)
    pages = [{"p": r["page"], "s": round(r["secs"] or 0)} for r in a["pages"]]
    groups = [{"g": f"{g} ({a['ratios'][g]}%)", "s": round(v)} for g, v in a["groups"].items()]
    att = [{"a": f"{k} ({v}%)", "v": v} for k, v in a["attack_ratios"].items()]
    hours = [{"h": f"{h:02d}:00", "c": c} for h, c in enumerate(a["hours"]) if c]
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{APP_NAME} - Adaptive Analysis</title>
<style>{CSS}</style></head><body>
<div class='noprint' style='text-align:right'><button onclick='window.print()'>Save as PDF / Print</button></div>
<h1>Adaptive Analysis Report</h1>
<p class='meta'>Operator: {html.escape(username)} &middot; Last 30 days &middot; Generated {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<h2>Insights</h2><ul>{''.join(f'<li>{html.escape(i)}</li>' for i in a['insights'])}</ul>
<h2>How you split your time</h2>{_bars(groups, 'g', 's')}
<h2>Time per page (seconds)</h2>{_bars(pages, 'p', 's')}
<h2>When you work</h2>{_bars(hours, 'h', 'c')}
<h2>Your actions</h2>{_table(a['actions'], [('action', 'Action'), ('c', 'Count')])}
<h2>What you are defending against</h2>{_bars(att, 'a', 'v')}
<p class='note'>Automated : human attacker ratio = <b>{a['automation_ratio']}</b></p>
</body></html>"""
