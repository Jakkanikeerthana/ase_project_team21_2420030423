"""Network sensors (decoys). All are emulations written with the Python standard library:
  ssh    - banner/version honeypot (low interaction: records client version + key-exchange probe)
  telnet - interactive emulated shell with login prompt (medium/high interaction, adaptive)
  http   - fake admin portal with breadcrumbs, exploit detection (adaptive)
  ftp    - FTP control channel: credential capture, fake listings (no data channel - contained)
  modbus - Modbus/TCP PLC emulation (reads return synthetic process values; writes are logged)
"""
import html
import os
import logging
import random
import socket
import socketserver
import struct
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import attack
from .fakeshell import CANARY_PASSWORD, FakeShell

log = logging.getLogger("honeypot.sensors")

COMMON_CREDS = {("root", "root"), ("admin", "admin"), ("root", "123456"), ("admin", "password"), ("root", "toor"),
                ("pi", "raspberry"), ("ubnt", "ubnt"), ("root", "admin"), ("user", "user"), ("support", "support"),
                ("root", "vizxv"), ("root", "xc3511"), ("admin", "1234"), ("root", "password")}


# ======================================================================================
# helpers
# ======================================================================================
def read_proxy_header(sock, peer_ip, core):
    """Lab mode: the built-in attack simulator prefixes connections with a PROXY v1 header so
    simulated attackers appear with their own source IP. Only trusted from localhost."""
    if not (core.db.get("lab_mode", True) and peer_ip.startswith("127.")):
        return None, False
    try:
        sock.settimeout(0.35)
        peek = sock.recv(16, socket.MSG_PEEK)
    except (socket.timeout, OSError):
        return None, False
    finally:
        sock.settimeout(None)
    if not peek.startswith(b"PROXY "):
        return None, False
    line = b""
    while not line.endswith(b"\r\n") and len(line) < 120:
        ch = sock.recv(1)
        if not ch:
            break
        line += ch
    parts = line.decode(errors="ignore").split()
    if len(parts) >= 3:
        return parts[2], True
    return None, False


def recv_line(sock, limit=1024, timeout=120):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < limit:
        ch = sock.recv(1)
        if not ch:
            return None
        if ch == b"\xff":  # telnet IAC negotiation - skip command bytes
            nxt = sock.recv(2)
            if nxt[:1] in (b"\xfa",):
                while True:
                    c = sock.recv(1)
                    if not c or c == b"\xf0":
                        break
            continue
        if ch == b"\n":
            break
        if ch in (b"\r", b"\x00"):
            continue
        buf += ch
    return buf.decode("utf-8", errors="replace")


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = os.name != "nt"
    daemon_threads = True


class BaseSensor:
    name = "base"
    description = ""
    interaction = "low"

    def __init__(self, core):
        self.core = core
        self.server = None
        self.thread = None
        self.error = ""
        self.started_at = None
        self.connections = 0
        self.lock = threading.Lock()

    @property
    def port(self):
        return int(self.core.db.get("ports")[self.name])

    def running(self):
        return self.server is not None

    def active(self):
        return sum(1 for s in self.core.active.values() if s.sensor == self.name)

    def gate(self, ip):
        """Containment checks applied before a connection is served."""
        db = self.core.db
        if db.get("kill_switch"):
            return "kill switch engaged"
        if not self.core.ratelimit.allow(ip, int(db.get("max_conn_per_min", 40))):
            return "rate limited"
        if self.active() >= int(db.get("max_concurrent_per_sensor", 50)):
            return "concurrency limit"
        return None

    def make_server(self, host):
        sensor = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                peer_ip, peer_port = self.client_address[0], self.client_address[1]
                ip, simulated = read_proxy_header(self.request, peer_ip, sensor.core)
                ip = ip or peer_ip
                reason = sensor.gate(ip)
                if reason:
                    sensor.core.db.audit("system", "connection_dropped", "containment", f"{sensor.name} {ip}: {reason}")
                    return
                sensor.connections += 1
                sess = sensor.core.open_session(sensor.name, ip, peer_port, simulated)
                try:
                    self.request.settimeout(int(sensor.core.db.get("max_session_secs", 300)))
                    sensor.serve(self.request, sess)
                except (ConnectionError, socket.timeout, OSError):
                    pass
                except Exception as e:
                    log.exception("sensor %s error: %s", sensor.name, e)
                finally:
                    sess.close()
        return _TCPServer((host, self.port), Handler)

    def start(self):
        if self.server:
            return True
        host = self.core.db.get("bind_host", "127.0.0.1")
        try:
            self.server = self.make_server(host)
        except OSError as e:
            self.error = f"Port {self.port} unavailable: {e}"
            self.server = None
            return False
        self.error = ""
        self.started_at = time.time()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name=f"sensor-{self.name}")
        self.thread.start()
        return True

    def stop(self):
        if self.server:
            srv = self.server
            self.server = None
            threading.Thread(target=lambda: (srv.shutdown(), srv.server_close()), daemon=True).start()
        self.started_at = None

    def status(self):
        return {"name": self.name, "port": self.port, "running": self.running(), "error": self.error,
                "connections": self.connections, "active": self.active(), "interaction": self.interaction,
                "description": self.description, "enabled": self.core.db.get("sensors_enabled").get(self.name, True),
                "uptime": time.time() - self.started_at if self.started_at else 0}


# ======================================================================================
# SSH banner sensor
# ======================================================================================
class SSHSensor(BaseSensor):
    name = "ssh"
    description = "SSH version/banner honeypot: records client software and key-exchange probes"
    interaction = "low"

    def serve(self, sock, sess):
        persona = sess.persona
        sock.sendall((persona["ssh_banner"] + "\r\n").encode())
        sock.settimeout(15)
        data = b""
        try:
            while b"\n" not in data and len(data) < 512:
                chunk = sock.recv(256)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        client = data.split(b"\n")[0].decode(errors="replace").strip()
        sess.features["times"].append(time.time())
        sess.event("ssh_client_version", client or "(no banner)", persona["ssh_banner"], [attack.tech("T1046")],
                   ioc_text="")
        if client:
            sess.core.db.execute("UPDATE hp_sessions SET client=? WHERE id=?", (client[:200], sess.id))
            sess.core.add_ioc("ssh-client", client[:200], sess)
        try:
            kex = sock.recv(2048)
            if kex:
                sess.event("ssh_kex_init", f"{len(kex)} bytes key-exchange init received", "connection closed", ioc_text="")
        except socket.timeout:
            pass


# ======================================================================================
# Telnet interactive shell sensor (adaptive)
# ======================================================================================
class TelnetSensor(BaseSensor):
    name = "telnet"
    description = "Interactive emulated Linux shell with login prompt; adapts strategy per attacker"
    interaction = "adaptive"

    def serve(self, sock, sess):
        p = sess.persona
        send = lambda s: sock.sendall(s.replace("\n", "\r\n").encode("utf-8", errors="replace"))
        send(f"\n{p['os']}\n{p['hostname']} login: ")
        user, attempts = None, 0
        while attempts < 6:
            u = recv_line(sock)
            if u is None:
                return
            send("Password: ")
            pw = recv_line(sock)
            if pw is None:
                return
            attempts += 1
            # Adaptive acceptance: common creds accepted; otherwise accept after the 3rd try
            ok = (u, pw) in COMMON_CREDS or attempts >= 3 or "Canary" in pw
            sess.login(u, pw, ok)
            if ok:
                user = u
                break
            time.sleep(0.2 if sess.arm != "tarpit" else 1.0)
            send(f"\nLogin incorrect\n{p['hostname']} login: ")
        if not user:
            return
        shell = FakeShell(p, sess.state, sess.arm, sess.core.llm, user)
        send(f"\nWelcome to {p['os']} (GNU/Linux {p['kernel']} x86_64)\n\nLast login: Mon Oct 28 09:14:11 2026 "
             f"from 10.0.4.2\n")
        while True:
            send(shell.prompt)
            line = recv_line(sock, 4096)
            if line is None:
                return
            if not line.strip():
                continue
            out, meta = shell.handle(line)
            new_arm = sess.command(line.strip(), out, meta)
            if new_arm:
                shell.set_arm(new_arm)
            if meta["delay"]:
                time.sleep(meta["delay"])
            if out:
                send(out + "\n")
            if meta["exit"]:
                return


# ======================================================================================
# FTP sensor
# ======================================================================================
class FTPSensor(BaseSensor):
    name = "ftp"
    description = "FTP control-channel honeypot: credential capture, fake listings, upload attempts logged"
    interaction = "medium"

    def serve(self, sock, sess):
        p = sess.persona
        send = lambda s: sock.sendall((s + "\r\n").encode())
        send(p["ftp_banner"])
        user, authed, fails = "", False, 0
        while True:
            line = recv_line(sock, 512)
            if line is None:
                return
            cmd, _, arg = line.strip().partition(" ")
            cmd = cmd.upper()
            sess.features["times"].append(time.time())
            if cmd == "USER":
                user = arg
                send(f"331 Please specify the password.")
            elif cmd == "PASS":
                ok = (user, arg) in COMMON_CREDS or user.lower() == "anonymous" or fails >= 2 or "Canary" in arg
                sess.login(user, arg, ok)
                if ok:
                    authed = True
                    send("230 Login successful.")
                else:
                    fails += 1
                    send("530 Login incorrect.")
            elif cmd in ("QUIT", "BYE"):
                send("221 Goodbye.")
                return
            elif not authed:
                send("530 Please login with USER and PASS.")
            elif cmd in ("LIST", "NLST", "MLSD"):
                sess.event("ftp_command", line, "listing", [attack.tech("T1005")], ioc_text="")
                send("150 Here comes the directory listing.")
                send("-rw-r--r--    1 0  0   48211 Oct 27 22:10 backup_2026-10-27.sql.gz")
                send("-rw-r--r--    1 0  0    1290 Oct 21 09:03 vpn-config.ovpn")
                send("drwxr-xr-x    2 0  0    4096 Oct 01 00:00 www")
                send("226 Directory send OK.")
            elif cmd == "RETR":
                sess.event("ftp_download", arg, "425", [attack.tech("T1005")], ioc_text="")
                send("425 Failed to establish connection.")
            elif cmd in ("STOR", "APPE"):
                sess.event("ftp_upload", arg, "425", [attack.tech("T1105")], ioc_text=arg)
                send("425 Failed to establish connection.")
            elif cmd in ("PASV", "EPSV", "PORT"):
                send("227 Entering Passive Mode (10,0,4,17,195,80).")
            elif cmd == "SYST":
                send("215 UNIX Type: L8")
            elif cmd == "PWD":
                send('257 "/" is the current directory')
            elif cmd in ("CWD", "TYPE", "MODE", "NOOP", "FEAT", "OPTS"):
                sess.event("ftp_command", line, "200", ioc_text="")
                send("200 OK.")
            else:
                sess.event("ftp_command", line, "502", ioc_text="")
                send("502 Command not implemented.")


# ======================================================================================
# Modbus/TCP ICS sensor
# ======================================================================================
class ModbusSensor(BaseSensor):
    name = "modbus"
    description = "Modbus/TCP PLC emulation: synthetic tank/pump values, write attempts flagged (ICS ATT&CK)"
    interaction = "medium"

    def serve(self, sock, sess):
        registers = [random.randint(200, 900) for _ in range(64)]
        coils = [random.random() > 0.5 for _ in range(64)]
        sock.settimeout(30)
        while True:
            hdr = b""
            while len(hdr) < 7:
                chunk = sock.recv(7 - len(hdr))
                if not chunk:
                    return
                hdr += chunk
            tid, pid, length, uid = struct.unpack(">HHHB", hdr)
            if length < 2 or length > 260:
                return
            pdu = b""
            while len(pdu) < length - 1:
                chunk = sock.recv(length - 1 - len(pdu))
                if not chunk:
                    return
                pdu += chunk
            fc = pdu[0]
            sess.features["times"].append(time.time())
            resp = None
            if fc in (1, 2, 3, 4) and len(pdu) >= 5:
                addr, qty = struct.unpack(">HH", pdu[1:5])
                qty = max(1, min(qty, 60))
                if fc in (3, 4):
                    vals = [registers[(addr + i) % 64] + random.randint(-3, 3) for i in range(qty)]
                    resp = bytes([fc, qty * 2]) + b"".join(struct.pack(">H", max(0, v)) for v in vals)
                else:
                    bits = 0
                    for i in range(min(qty, 8)):
                        bits |= (1 if coils[(addr + i) % 64] else 0) << i
                    resp = bytes([fc, 1, bits])
                sess.event("modbus_read", f"FC{fc} addr={addr} qty={qty}", f"{qty} values", [attack.tech("T0801")],
                           ioc_text="")
            elif fc in (5, 6, 15, 16) and len(pdu) >= 5:
                addr, val = struct.unpack(">HH", pdu[1:5])
                sess.features["writes"] += 1
                t = attack.tech("T0836") if fc in (6, 16) else attack.tech("T0855")
                sess.event("modbus_write", f"FC{fc} addr={addr} value={val}", "acknowledged (simulated)",
                           [t, attack.tech("T0855")], ioc_text="")
                if sess.features["writes"] == 1:
                    sess.core.raise_alert(sess, "critical", f"ICS write command (FC{fc}) to PLC decoy", "ics")
                resp = pdu[:5]
            elif fc == 43:
                vendor = sess.persona["plc"]
                sess.event("modbus_device_id", "FC43 read device identification", vendor, [attack.tech("T0888")],
                           ioc_text="")
                obj = vendor.encode()[:60]
                resp = bytes([43, 14, 1, 1, 0, 0, 1, 0, len(obj)]) + obj
            else:
                resp = bytes([fc | 0x80, 1])
                sess.event("modbus_unknown", f"FC{fc}", "illegal function", ioc_text="")
            sock.sendall(struct.pack(">HHHB", tid, 0, len(resp) + 1, uid) + resp)


# ======================================================================================
# HTTP sensor (adaptive web decoy)
# ======================================================================================
class HTTPSensor(BaseSensor):
    name = "http"
    description = "Fake admin portal: detects SQLi/XSS/traversal/Log4Shell/scanners, serves adaptive breadcrumbs"
    interaction = "adaptive"

    def __init__(self, core):
        super().__init__(core)
        self.sessions = {}

    def session_for(self, ip, simulated, ua):
        s = self.sessions.get(ip)
        if s is None or s.closed:
            s = self.core.open_session("http", ip, 0, simulated, ua)
            self.sessions[ip] = s
            self.connections += 1
        return s

    def make_server(self, host):
        sensor = self

        class H(BaseHTTPRequestHandler):
            server_version = "nginx"
            sys_version = ""

            def log_message(self, *a):
                pass

            def version_string(self):
                return sensor.core.morph.current()["http_server"]

            def _handle(self):
                peer = self.client_address[0]
                ip, simulated = peer, False
                sim_src = self.headers.get("X-Sim-Source")
                if sim_src and peer.startswith("127.") and sensor.core.db.get("lab_mode", True):
                    ip, simulated = sim_src.strip(), True
                reason = sensor.gate(ip)
                if reason:
                    self.send_response(503)
                    self.end_headers()
                    return
                length = min(int(self.headers.get("Content-Length") or 0), 65536)
                body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
                ua = self.headers.get("User-Agent", "")
                sess = sensor.session_for(ip, simulated, ua)
                sensor.respond(self, sess, body, ua)

            do_GET = do_POST = do_HEAD = do_PUT = do_OPTIONS = _handle

        class S(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = os.name != "nt"
        return S((host, self.port), H)

    def respond(self, req, sess, body, ua):
        p = sess.persona
        path = req.path
        decoded = urllib.parse.unquote_plus(path + " " + body)
        f = sess.features
        f["times"].append(time.time())
        f["paths"] += 1
        f["ua"] = ua
        techs = attack.tag_http(decoded)
        if attack.SCANNER_UA.search(ua):
            f["scanner_ua"] = True
            techs.append(attack.tech("T1595.002"))
            sess.core.add_ioc("user-agent", ua[:200], sess)
        f["exploits"] += sum(1 for t in techs if t["id"] in ("T1190", "T1059"))
        rich = sess.arm in ("breadcrumbs", "rich")
        route = urllib.parse.urlparse(path).path.rstrip("/") or "/"
        status, ctype, content = 200, "text/html", ""

        if route == "/robots.txt":
            content = "User-agent: *\nDisallow: /admin\n" + ("Disallow: /backup/\nDisallow: /.env\n" if rich else "")
            ctype = "text/plain"
        elif route in ("/.env", "/.git/config", "/wp-config.php.bak", "/config.php.bak"):
            if rich:
                f["breadcrumbs"] += 1
                content = (f"APP_ENV=production\nDB_HOST=10.0.4.12\nDB_USER=app_rw\nDB_PASSWORD={CANARY_PASSWORD}\n"
                           "ADMIN_USER=admin\n")
                ctype = "text/plain"
                sess.core.raise_alert(sess, "high", f"Canary breadcrumb {route} fetched over HTTP", "breadcrumb")
            else:
                status, content = 404, "<h1>404 Not Found</h1>"
        elif route.startswith("/backup"):
            if rich:
                f["breadcrumbs"] += 1
                content = ("<h1>Index of /backup/</h1><pre><a href='/backup/db_2026-10-27.sql.gz'>db_2026-10-27.sql.gz</a>"
                           "   27-Oct-2026 22:10   48M\n<a href='/backup/users.csv'>users.csv</a>   21-Oct-2026 09:03   12K</pre>")
            else:
                status, content = 403, "<h1>403 Forbidden</h1>"
        elif route in ("/login", "/admin/login", "/wp-login.php", "/admin") and req.command == "POST":
            form = urllib.parse.parse_qs(body)
            u = (form.get("username") or form.get("log") or form.get("user") or [""])[0]
            pw = (form.get("password") or form.get("pwd") or form.get("pass") or [""])[0]
            ok = CANARY_PASSWORD in pw
            sess.login(u, pw, ok)
            if ok:
                content = f"<h1>{html.escape(p['portal'])}</h1><p>Welcome back, {html.escape(u)}. Session expired - please retry.</p>"
            else:
                status, content = 401, self.login_page(p, "Invalid credentials")
        elif route in ("/", "/login", "/admin", "/index.html", "/wp-login.php", "/phpmyadmin", "/manager/html"):
            content = self.login_page(p)
        elif route == "/api/v1/status":
            ctype, content = "application/json", ('{"status":"ok","version":"4.2.1","node":"%s"}' % p["hostname"])
        else:
            status, content = 404, f"<html><body><h1>404 Not Found</h1><hr>{html.escape(p['http_server'])}</body></html>"

        sess.event("http_request", f"{req.command} {path} UA={ua[:120]}" + (f" BODY={body[:300]}" if body else ""),
                   f"{status}", techs, ioc_text=decoded)
        delay = random.uniform(0.3, 1.0) if sess.arm == "tarpit" else 0
        if delay:
            time.sleep(delay)
        data = content.encode()
        req.send_response(status)
        req.send_header("Content-Type", ctype + "; charset=utf-8")
        req.send_header("Content-Length", str(len(data)))
        req.send_header("X-Powered-By", "PHP/7.4.33" if p["key"] != "iot-camera" else "")
        req.end_headers()
        if req.command != "HEAD":
            req.wfile.write(data)

    @staticmethod
    def login_page(p, err=""):
        e = f"<p style='color:#c0392b'>{html.escape(err)}</p>" if err else ""
        return (f"<!doctype html><html><head><title>{html.escape(p['portal'])} - Sign in</title></head>"
                "<body style='font-family:sans-serif;background:#f4f4f4'><div style='max-width:320px;margin:80px auto;"
                "background:#fff;padding:24px;border-radius:6px'>"
                f"<h2>{html.escape(p['portal'])}</h2>{e}<form method='post' action='/login'>"
                "<input name='username' placeholder='Username' style='width:100%;margin:6px 0'><br>"
                "<input name='password' type='password' placeholder='Password' style='width:100%;margin:6px 0'><br>"
                "<button>Sign in</button></form></div></body></html>")

    def start(self):
        ok = super().start()
        return ok


SENSOR_CLASSES = [SSHSensor, TelnetSensor, HTTPSensor, FTPSensor, ModbusSensor]


class SensorManager:
    def __init__(self, core):
        self.core = core
        self.sensors = {cls.name: cls(core) for cls in SENSOR_CLASSES}

    def start_enabled(self):
        enabled = self.core.db.get("sensors_enabled")
        for name, s in self.sensors.items():
            if enabled.get(name, True):
                s.start()

    def start(self, name):
        return self.sensors[name].start()

    def stop(self, name):
        self.sensors[name].stop()

    def stop_all(self):
        for s in self.sensors.values():
            s.stop()

    def restart_all(self):
        self.stop_all()
        time.sleep(0.5)
        self.start_enabled()

    def status(self):
        return [s.status() for s in self.sensors.values()]
