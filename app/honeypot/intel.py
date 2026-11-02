"""Threat-intelligence outputs: STIX 2.1 bundles, MISP push, webhook and syslog (CEF) alerts."""
import datetime as dt
import json
import socket
import uuid

from .config import APP_NAME, VERSION


def _ts(t=None):
    d = dt.datetime.fromtimestamp(t, dt.timezone.utc) if t else dt.datetime.now(dt.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sid(kind, value):
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, kind + ':' + value)}"


STIX_PATTERN = {
    "ip": "[ipv4-addr:value = '{v}']",
    "url": "[url:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "hash": "[file:hashes.'SHA-256' = '{v}']",
}


def stix_bundle(db, org="Adaptive Honeypot"):
    identity = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", org), "created": _ts(),
                "modified": _ts(), "name": org, "identity_class": "organization"}
    objs = [identity]
    tech_rows = db.query("SELECT techniques FROM events WHERE techniques != '' AND techniques IS NOT NULL")
    techs = {}
    for r in tech_rows:
        for t in json.loads(r["techniques"] or "[]"):
            techs[t["id"]] = t
    ap_ids = {}
    for tid, t in techs.items():
        ap = {"type": "attack-pattern", "spec_version": "2.1", "id": _sid("attack-pattern", tid), "created": _ts(),
              "modified": _ts(), "name": t["name"], "created_by_ref": identity["id"],
              "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                       "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}]}
        ap_ids[tid] = ap["id"]
        objs.append(ap)
    for i in db.query("SELECT * FROM iocs ORDER BY last_seen DESC LIMIT 1000"):
        pat = STIX_PATTERN.get(i["type"])
        if not pat:
            continue
        v = i["value"].replace("'", "\\'")
        if i["type"] == "hash" and len(i["value"]) != 64:
            pat = "[file:hashes.'MD5' = '{v}']" if len(i["value"]) == 32 else "[file:hashes.'SHA-1' = '{v}']"
        ind = {"type": "indicator", "spec_version": "2.1", "id": _sid("indicator", i["type"] + i["value"]),
               "created": _ts(i["first_seen"]), "modified": _ts(i["last_seen"]), "name": f"Honeypot {i['type']}: {i['value']}",
               "pattern": pat.format(v=v), "pattern_type": "stix", "valid_from": _ts(i["first_seen"]),
               "indicator_types": ["malicious-activity"], "created_by_ref": identity["id"],
               "labels": [f"sensor:{i['sensor']}", f"sightings:{i['count']}"]}
        objs.append(ind)
        sess_techs = db.query("SELECT techniques FROM events WHERE session_id=? AND techniques != ''", (i["session_id"],))
        linked = set()
        for r in sess_techs:
            for t in json.loads(r["techniques"] or "[]"):
                linked.add(t["id"])
        for tid in list(linked)[:5]:
            if tid in ap_ids:
                objs.append({"type": "relationship", "spec_version": "2.1",
                             "id": _sid("relationship", ind["id"] + tid), "created": _ts(), "modified": _ts(),
                             "relationship_type": "indicates", "source_ref": ind["id"], "target_ref": ap_ids[tid]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


MISP_TYPES = {"ip": ("ip-src", "Network activity"), "url": ("url", "Network activity"),
              "domain": ("domain", "Network activity"), "hash": ("sha256", "Payload delivery")}


def misp_push(db, egress, limit=200):
    url, key = db.get("misp_url"), db.get("misp_key")
    if not url or not key:
        raise ValueError("MISP URL and API key must be configured in Toolkit > API keys")
    attrs = []
    for i in db.query("SELECT * FROM iocs ORDER BY last_seen DESC LIMIT ?", (limit,)):
        t, cat = MISP_TYPES.get(i["type"], (None, None))
        if not t:
            continue
        if i["type"] == "hash":
            t = {32: "md5", 40: "sha1"}.get(len(i["value"]), "sha256")
        attrs.append({"type": t, "category": cat, "value": i["value"], "to_ids": True,
                      "comment": f"{APP_NAME} sensor={i['sensor']} sightings={i['count']}"})
    event = {"Event": {"info": f"{APP_NAME} export {_ts()}", "distribution": 0, "threat_level_id": 2,
                       "analysis": 1, "Attribute": attrs}}
    return egress.request_json(url.rstrip("/") + "/events", event,
                               headers={"Authorization": key, "Accept": "application/json"}, timeout=15)


def send_webhook(db, egress, alert):
    url = db.get("webhook_url")
    if not url:
        return False
    text = f"[{APP_NAME}] {alert['severity'].upper()}: {alert['title']} (session {alert.get('session_id', '-')})"
    egress.request(url, {"text": text, "content": text, "alert": alert}, timeout=8)
    return True


def send_syslog(db, alert):
    host = db.get("syslog_host")
    if not host:
        return False
    sev = {"low": 3, "medium": 6, "high": 8, "critical": 10}.get(alert["severity"], 5)
    cef = (f"CEF:0|{APP_NAME.replace(' ', '')}|AdaptiveHoneypot|{VERSION}|{alert.get('type', 'alert')}|"
           f"{alert['title'].replace('|', '/')}|{sev}|src={alert.get('src_ip', '')} cs1Label=session cs1={alert.get('session_id', '')}")
    msg = f"<{8 * 1 + 4}>{cef}".encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(msg, (host, int(db.get("syslog_port", 514))))
    finally:
        s.close()
    return True
