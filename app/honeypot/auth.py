"""User accounts, password hashing (PBKDF2-SHA256) and login sessions."""
import hashlib
import hmac
import re
import secrets
import time

SESSION_TTL = 12 * 3600
ITERATIONS = 200_000
ROLES = ("admin", "analyst", "viewer")
_fail = {}  # ip -> [timestamps] for login rate limiting


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), ITERATIONS).hex()
    return h, salt


class Auth:
    def __init__(self, db):
        self.db = db

    def user_count(self):
        return self.db.scalar("SELECT COUNT(*) FROM users")

    def validate(self, username, password, email=""):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username or ""):
            return "Username must be 3-32 characters (letters, digits, _ . -)."
        if len(password or "") < 8:
            return "Password must be at least 8 characters."
        if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
            return "Password must contain letters and digits."
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return "Email address looks invalid."
        return None

    def signup(self, username, password, email="", role=None):
        err = self.validate(username, password, email)
        if err:
            return None, err
        if self.db.one("SELECT id FROM users WHERE lower(username)=lower(?)", (username,)):
            return None, "That username is already taken."
        first = self.user_count() == 0
        role = "admin" if first else (role if role in ROLES else "analyst")
        h, salt = hash_password(password)
        uid = self.db.execute(
            "INSERT INTO users(username, email, pw_hash, salt, role, created_at) VALUES(?,?,?,?,?,?)",
            (username, email, h, salt, role, time.time()))
        return {"id": uid, "username": username, "role": role}, None

    def rate_limited(self, ip):
        now = time.time()
        lst = [t for t in _fail.get(ip, []) if now - t < 300]
        _fail[ip] = lst
        return len(lst) >= 8

    def login(self, username, password, ip=""):
        if self.rate_limited(ip):
            return None, "Too many failed attempts. Try again in 5 minutes."
        u = self.db.one("SELECT * FROM users WHERE lower(username)=lower(?)", (username or "",))
        if u:
            h, _ = hash_password(password or "", u["salt"])
            if hmac.compare_digest(h, u["pw_hash"]):
                token = secrets.token_urlsafe(32)
                now = time.time()
                self.db.execute("INSERT INTO auth_sessions(token, user_id, created, expires) VALUES(?,?,?,?)",
                                (token, u["id"], now, now + SESSION_TTL))
                self.db.execute("UPDATE users SET last_login=? WHERE id=?", (now, u["id"]))
                _fail.pop(ip, None)
                return {"token": token, "username": u["username"], "role": u["role"]}, None
        _fail.setdefault(ip, []).append(time.time())
        return None, "Invalid username or password."

    def user_for_token(self, token):
        if not token:
            return None
        row = self.db.one(
            "SELECT u.id, u.username, u.email, u.role, u.created_at, u.last_login, s.expires "
            "FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (token,))
        if not row or row["expires"] < time.time():
            return None
        return row

    def logout(self, token):
        self.db.execute("DELETE FROM auth_sessions WHERE token=?", (token,))

    def change_password(self, user_id, old, new):
        u = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        h, _ = hash_password(old, u["salt"])
        if not hmac.compare_digest(h, u["pw_hash"]):
            return "Current password is incorrect."
        err = self.validate(u["username"], new)
        if err:
            return err
        h, salt = hash_password(new)
        self.db.execute("UPDATE users SET pw_hash=?, salt=? WHERE id=?", (h, salt, user_id))
        return None
