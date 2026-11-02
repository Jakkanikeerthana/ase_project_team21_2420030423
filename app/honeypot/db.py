"""SQLite storage layer (thread-safe, single connection guarded by a lock)."""
import json
import sqlite3
import threading
import time

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT,
  pw_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst',
  created_at REAL, last_login REAL);
CREATE TABLE IF NOT EXISTS auth_sessions(
  token TEXT PRIMARY KEY, user_id INTEGER, created REAL, expires REAL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, username TEXT, action TEXT,
  category TEXT, detail TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS pageviews(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, username TEXT, page TEXT, seconds REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS hp_sessions(
  id TEXT PRIMARY KEY, sensor TEXT, src_ip TEXT, src_port INTEGER, country TEXT, asn TEXT,
  started REAL, ended REAL, duration REAL DEFAULT 0, commands INTEGER DEFAULT 0,
  profile TEXT DEFAULT 'unknown', threat INTEGER DEFAULT 0, strategy TEXT DEFAULT '',
  persona TEXT DEFAULT '', interaction TEXT DEFAULT 'low', detected INTEGER DEFAULT 0,
  simulated INTEGER DEFAULT 0, alerted INTEGER DEFAULT 0, client TEXT DEFAULT '',
  login_ok INTEGER DEFAULT 0, abuse_score INTEGER DEFAULT -1);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, session_id TEXT, sensor TEXT, src_ip TEXT,
  type TEXT, data TEXT, response TEXT, techniques TEXT);
CREATE TABLE IF NOT EXISTS iocs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, value TEXT, session_id TEXT, sensor TEXT,
  first_seen REAL, last_seen REAL, count INTEGER DEFAULT 1, enrichment TEXT DEFAULT '',
  UNIQUE(type, value));
CREATE TABLE IF NOT EXISTS creds(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, sensor TEXT, src_ip TEXT, username TEXT,
  password TEXT, success INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS bandit(
  profile TEXT, arm TEXT, pulls INTEGER DEFAULT 0, reward REAL DEFAULT 0,
  PRIMARY KEY(profile, arm));
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, severity TEXT, title TEXT, session_id TEXT,
  detail TEXT, delivered TEXT DEFAULT '', mttd REAL DEFAULT 0, acknowledged INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS vfs_state(ip TEXT PRIMARY KEY, state TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_sess ON events(session_id);
CREATE INDEX IF NOT EXISTS ix_sess_started ON hp_sessions(started);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
"""


class Database:
    def __init__(self, path=None):
        self.path = path or config.DB_PATH
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        self._settings_cache = None

    # ---- generic helpers -------------------------------------------------
    def execute(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.lastrowid

    def executemany(self, sql, rows):
        with self.lock:
            self.conn.executemany(sql, rows)
            self.conn.commit()

    def query(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        with self.lock:
            r = self.conn.execute(sql, params).fetchone()
            return dict(r) if r else None

    def scalar(self, sql, params=(), default=0):
        with self.lock:
            r = self.conn.execute(sql, params).fetchone()
            if not r or r[0] is None:
                return default
            return r[0]

    # ---- settings ----------------------------------------------------------
    def settings(self):
        if self._settings_cache is None:
            s = dict(config.DEFAULT_SETTINGS)
            for row in self.query("SELECT key, value FROM settings"):
                try:
                    s[row["key"]] = json.loads(row["value"])
                except Exception:
                    pass
            # merge nested dict defaults
            for k in ("ports", "sensors_enabled"):
                merged = dict(config.DEFAULT_SETTINGS[k])
                merged.update(s.get(k) or {})
                s[k] = merged
            self._settings_cache = s
        return dict(self._settings_cache)

    def get(self, key, default=None):
        return self.settings().get(key, default)

    def set_settings(self, updates):
        with self.lock:
            for k, v in updates.items():
                if k not in config.DEFAULT_SETTINGS:
                    continue
                self.conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)",
                                  (k, json.dumps(v)))
            self.conn.commit()
            self._settings_cache = None

    # ---- audit -------------------------------------------------------------
    def audit(self, username, action, category="system", detail="", ip=""):
        if not isinstance(detail, str):
            detail = json.dumps(detail)
        self.execute("INSERT INTO audit(ts, username, action, category, detail, ip) VALUES(?,?,?,?,?,?)",
                     (time.time(), username or "system", action, category, detail[:2000], ip))
