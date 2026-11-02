"""Emulated Linux shell used by the Telnet sensor and the web Lab terminal.
Nothing is ever executed on the host - every response is synthesised."""
import hashlib
import posixpath
import random
import re
import shlex
import time

CANARY_PASSWORD = "Rose#Canary2026!"
CANARY_AWS = "AKIAHONEYCANARY7ROSE"


def base_fs(p):
    u = p["user"]
    passwd = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
              "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
              f"{u}:x:1000:1000:{u}:/home/{u}:/bin/bash\nmysql:x:112:117:MySQL Server:/nonexistent:/bin/false\n")
    fs = {
        "/": None, "/root": None, "/home": None, f"/home/{u}": None, "/etc": None, "/tmp": None, "/var": None,
        "/var/www": None, "/var/www/html": None, "/var/log": None, "/proc": None, "/usr": None, "/usr/bin": None,
        "/bin": None, "/opt": None, "/dev": None, "/root/.ssh": None,
        "/etc/passwd": passwd,
        "/etc/shadow": None if False else "cat: /etc/shadow: Permission denied",
        "/etc/hostname": p["hostname"] + "\n",
        "/etc/os-release": f'PRETTY_NAME="{p["os"]}"\nNAME="{p["os"].split()[0]}"\nID={p["os"].split()[0].lower()}\n',
        "/etc/issue": p["os"] + " \\n \\l\n",
        "/proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
                         "cpu MHz\t\t: 2399.998\ncache size\t: 35840 KB\ncpu cores\t: 4\n\n" * 1,
        "/proc/version": f"Linux version {p['kernel']} (buildd@lcy02) (gcc 11.4.0) #115-Ubuntu SMP\n",
        "/var/www/html/index.html": f"<html><body><h1>{p['portal']}</h1></body></html>\n",
        "/var/log/auth.log": "Permission denied\n",
        f"/home/{u}/.bash_history": "ls -la\ncd /var/www/html\nsudo systemctl restart nginx\nexit\n",
        "/root/.ssh/authorized_keys": "",
    }
    return fs


def breadcrumb_fs(p):
    u = p["user"]
    return {
        "/var/www/html/.env": f"APP_ENV=production\nDB_HOST=10.0.4.12\nDB_USER=app_rw\nDB_PASSWORD={CANARY_PASSWORD}\n"
                              f"AWS_ACCESS_KEY_ID={CANARY_AWS}\n",
        "/root/.aws": None,
        "/root/.aws/credentials": f"[default]\naws_access_key_id = {CANARY_AWS}\naws_secret_access_key = "
                                  "rOsE/hOnEyToKeN/Do+Not+Use/0000000000\nregion = ap-south-1\n",
        f"/home/{u}/backup.sql": "-- MySQL dump 10.13  Distrib 8.0.36\n-- Host: localhost    Database: billing\n"
                                 "INSERT INTO users VALUES (1,'admin','$2y$10$Canary.Hash.Only.For.Detection');\n",
        "/root/notes.txt": f"TODO: rotate vpn creds -> vpn.internal:443  user {u} / {CANARY_PASSWORD}\n",
    }


BREADCRUMB_PATHS = {"/var/www/html/.env", "/root/.aws/credentials", "/root/notes.txt"}


class FakeShell:
    def __init__(self, persona, state, arm, llm=None, username="root"):
        self.p = persona
        self.state = state
        self.arm = arm
        self.llm = llm
        self.user = username if username in ("root", persona["user"]) else "root"
        self.fs = base_fs(persona)
        self.set_arm(arm)
        if not state.get("cwd"):
            state["cwd"] = "/root" if self.user == "root" else f"/home/{self.user}"
        self.sudo_ok = False

    def set_arm(self, arm):
        self.arm = arm
        if arm in ("breadcrumbs", "rich"):
            self.fs.update(breadcrumb_fs(self.p))

    # ------------------------------------------------------------------ VFS helpers
    @property
    def cwd(self):
        return self.state["cwd"]

    def path(self, p):
        if not p:
            return self.cwd
        p = p.replace("~", "/root" if self.user == "root" else f"/home/{self.user}")
        return posixpath.normpath(p if p.startswith("/") else posixpath.join(self.cwd, p))

    def exists(self, p):
        if p in self.state["deleted"]:
            return False
        return p in self.fs or p in self.state["files"] or p in self.state["dirs"]

    def is_dir(self, p):
        return (p in self.fs and self.fs[p] is None) or p in self.state["dirs"]

    def read(self, p):
        if p in self.state["files"]:
            return self.state["files"][p]
        return self.fs.get(p)

    def listdir(self, d):
        names = set()
        for src in (list(self.fs.keys()), list(self.state["files"].keys()), self.state["dirs"]):
            for k in src:
                if k != d and posixpath.dirname(k) == d and k not in self.state["deleted"]:
                    names.add(posixpath.basename(k))
        return sorted(names)

    @property
    def prompt(self):
        sym = "#" if self.user == "root" else "$"
        cwd = self.cwd.replace("/root", "~") if self.user == "root" else self.cwd
        return f"{self.user}@{self.p['hostname']}:{cwd}{sym} "

    # ------------------------------------------------------------------ main entry
    def handle(self, line):
        """Returns (output, meta). meta: unknown(int), breadcrumb(bool), exit(bool), delay(float)."""
        meta = {"unknown": 0, "breadcrumb": False, "exit": False, "delay": 0.0, "llm": False}
        line = line.strip()
        if not line:
            return "", meta
        self.state["history"].append(line)
        outputs = []
        for part in re.split(r"\s*(?:;|&&|\|\|)\s*", line):
            if not part:
                continue
            seg = part.split("|")[0].strip()  # pipes: emulate left-most command
            out = self.run(seg, meta)
            grep = re.search(r"\|\s*grep\s+(-\w+\s+)?['\"]?([^'\"|]+)", part)
            if grep and out:
                pat = grep.group(2).strip().lower()
                out = "\n".join(l for l in out.split("\n") if pat in l.lower())
            if out:
                outputs.append(out)
            if meta["exit"]:
                break
        if self.arm == "tarpit":
            meta["delay"] = random.uniform(0.4, 1.4)
        return "\n".join(outputs), meta

    def run(self, cmd, meta):
        redirect = None
        m = re.match(r"(.*?)\s*(>>?)\s*(\S+)\s*$", cmd)
        if m and not cmd.startswith(("wget", "curl")):
            cmd, redirect = m.group(1), (m.group(2), self.path(m.group(3)))
        try:
            argv = shlex.split(cmd)
        except ValueError:
            argv = cmd.split()
        if not argv:
            return ""
        name, args = argv[0], argv[1:]
        name = posixpath.basename(name) if name.startswith("/bin/") or name.startswith("/usr/bin/") else name
        fn = getattr(self, "c_" + name.replace("-", "_").replace(".", "_"), None)
        if name.startswith("./") or (name.startswith("/") and not fn):
            out = self.exec_file(name)
        elif fn:
            out = fn(args, meta)
        else:
            out = None
            if self.arm == "rich" and self.llm and self.llm.enabled():
                out = self.llm.generate(cmd, self.p, self.cwd)
                meta["llm"] = out is not None
            if out is None:
                meta["unknown"] += 1
                out = f"-bash: {name}: command not found"
        if redirect:
            mode, target = redirect
            prev = (self.read(target) or "") if mode == ">>" else ""
            self.state["files"][target] = prev + (out or "") + "\n"
            if target in self.state["deleted"]:
                self.state["deleted"].remove(target)
            return ""
        return out

    # ------------------------------------------------------------------ commands
    def c_exit(self, a, meta):
        meta["exit"] = True
        return "logout"
    c_logout = c_exit

    def c_pwd(self, a, m): return self.cwd
    def c_whoami(self, a, m): return self.user

    def c_id(self, a, m):
        return "uid=0(root) gid=0(root) groups=0(root)" if self.user == "root" else \
            f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user}),27(sudo)"

    def c_hostname(self, a, m): return self.p["hostname"]

    def c_uname(self, a, m):
        if "-a" in a:
            return f"Linux {self.p['hostname']} {self.p['kernel']} #115-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux"
        if "-r" in a:
            return self.p["kernel"]
        if "-m" in a:
            return "x86_64"
        return "Linux"

    def c_cd(self, a, m):
        target = self.path(a[0] if a else "~")
        if self.exists(target) and self.is_dir(target):
            self.state["cwd"] = target
            return ""
        return f"-bash: cd: {a[0] if a else ''}: No such file or directory"

    def c_ls(self, a, m):
        targets = [x for x in a if not x.startswith("-")] or [self.cwd]
        long = any(x.startswith("-") and "l" in x for x in a)
        out = []
        for t in targets:
            p = self.path(t)
            if not self.exists(p):
                out.append(f"ls: cannot access '{t}': No such file or directory")
                continue
            names = self.listdir(p) if self.is_dir(p) else [posixpath.basename(p)]
            if not any(x.startswith("-") and "a" in x for x in a):
                names = [n for n in names if not n.startswith(".")]
            if long:
                lines = [f"total {len(names) * 4}"]
                for n in names:
                    fp = posixpath.join(p, n) if self.is_dir(p) else p
                    d = self.is_dir(fp)
                    size = 4096 if d else len(self.read(fp) or "") or 220
                    perm = "drwxr-xr-x" if d else "-rw-r--r--"
                    lines.append(f"{perm} 1 root root {size:>6} Oct 28 09:14 {n}")
                out.append("\n".join(lines))
            else:
                out.append("  ".join(names))
        return "\n".join(out)
    c_ll = lambda self, a, m: self.c_ls(["-la"] + a, m)
    c_dir = c_ls

    def c_cat(self, a, m):
        out = []
        for f in a:
            if f.startswith("-"):
                continue
            p = self.path(f)
            if not self.exists(p):
                out.append(f"cat: {f}: No such file or directory")
            elif self.is_dir(p):
                out.append(f"cat: {f}: Is a directory")
            else:
                if p in BREADCRUMB_PATHS:
                    m["breadcrumb"] = True
                c = self.read(p) or ""
                if p == "/etc/shadow" and self.user != "root":
                    c = "cat: /etc/shadow: Permission denied"
                elif p == "/etc/shadow":
                    c = "root:$6$rOsE$canaryhashcanaryhash:19700:0:99999:7:::\n" + f"{self.p['user']}:!:19700:0:99999:7:::"
                out.append(c.rstrip("\n"))
        return "\n".join(out)
    c_more = c_less = c_head = c_tail = c_cat

    def c_echo(self, a, m):
        return " ".join(x for x in a if x not in ("-e", "-n"))

    def c_touch(self, a, m):
        for f in a:
            p = self.path(f)
            self.state["files"].setdefault(p, "")
            if p in self.state["deleted"]:
                self.state["deleted"].remove(p)
        return ""

    def c_mkdir(self, a, m):
        for f in a:
            if not f.startswith("-"):
                self.state["dirs"].append(self.path(f))
        return ""

    def c_rm(self, a, m):
        for f in a:
            if f.startswith("-"):
                continue
            p = self.path(f)
            if self.exists(p):
                self.state["deleted"].append(p)
                self.state["files"].pop(p, None)
        return ""

    def c_cp(self, a, m):
        a = [x for x in a if not x.startswith("-")]
        if len(a) == 2 and self.exists(self.path(a[0])):
            self.state["files"][self.path(a[1])] = self.read(self.path(a[0])) or ""
            return ""
        return "cp: missing file operand"

    def c_mv(self, a, m):
        out = self.c_cp(a, m)
        if not out:
            self.c_rm(a[:1], m)
        return out

    def c_chmod(self, a, m):
        return "" if len(a) >= 2 else "chmod: missing operand"
    c_chown = c_chmod

    def c_ps(self, a, m):
        rows = ["  PID TTY          TIME CMD", "    1 ?        00:00:04 systemd", "  612 ?        00:00:01 sshd",
                "  845 ?        00:00:12 cron"]
        if self.arm == "rich" or "aux" in "".join(a):
            rows = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
                    "root           1  0.0  0.2 167744 11872 ?        Ss   Oct28   0:04 /sbin/init",
                    "root         612  0.0  0.1  15432  9120 ?        Ss   Oct28   0:01 sshd: /usr/sbin/sshd -D",
                    "mysql        733  0.4  9.8 2342140 398112 ?      Ssl  Oct28  11:02 /usr/sbin/mysqld",
                    "www-data     801  0.0  0.3 203440 14212 ?        S    Oct28   0:03 nginx: worker process",
                    "root         845  0.0  0.0   6896  2980 ?        Ss   Oct28   0:12 /usr/sbin/cron -f",
                    f"{self.p['user']:<10}  1290  0.1  1.2 724112 48120 ?        Sl   Oct28   2:15 node /opt/app/server.js",
                    "root        2231  0.0  0.1  10044  4160 pts/0    Ss   09:14   0:00 -bash"]
        return "\n".join(rows)

    def c_w(self, a, m):
        return (f" {time.strftime('%H:%M:%S')} up 12 days,  3:41,  1 user,  load average: 0.08, 0.11, 0.09\n"
                "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"{self.user:<8} pts/0    10.0.4.2         09:14    0.00s  0.02s  0.00s w")

    def c_uptime(self, a, m):
        return f" {time.strftime('%H:%M:%S')} up 12 days,  3:41,  1 user,  load average: 0.08, 0.11, 0.09"

    def c_free(self, a, m):
        return ("               total        used        free      shared  buff/cache   available\n"
                "Mem:         4024320     1638212      612004       12840     1774104     2120884\n"
                "Swap:        2097148           0     2097148")

    def c_df(self, a, m):
        return ("Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       41152736 9876544  "
                "29163448  26% /\ntmpfs            2012160       0   2012160   0% /dev/shm")

    def c_nproc(self, a, m): return "4"

    def c_lscpu(self, a, m):
        return "Architecture:        x86_64\nCPU(s):              4\nModel name:          Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"

    def c_ifconfig(self, a, m):
        return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.4.17  netmask "
                "255.255.255.0  broadcast 10.0.4.255\n        ether 52:54:00:3a:7f:21  txqueuelen 1000  (Ethernet)")

    def c_ip(self, a, m):
        return ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                "    inet 10.0.4.17/24 brd 10.0.4.255 scope global eth0")

    def c_netstat(self, a, m):
        return ("Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address  Foreign Address State\n"
                "tcp        0      0 0.0.0.0:22     0.0.0.0:*       LISTEN\ntcp        0      0 0.0.0.0:80     0.0.0.0:*       LISTEN\n"
                "tcp        0      0 127.0.0.1:3306 0.0.0.0:*       LISTEN")
    c_ss = c_netstat

    def c_history(self, a, m):
        if "-c" in a:
            self.state["history"] = []
            return ""
        return "\n".join(f"{i + 1:>5}  {h}" for i, h in enumerate(self.state["history"][-30:]))

    def _download(self, a, tool):
        url = next((x for x in a if "://" in x or re.match(r"\d+\.\d+\.\d+\.\d+", x)), None)
        if not url:
            return f"{tool}: missing URL"
        fname = posixpath.basename(url.split("?")[0]) or "index.html"
        outp = None
        for i, x in enumerate(a):
            if x in ("-O", "-o") and i + 1 < len(a):
                outp = a[i + 1]
        target = self.path(outp or fname)
        size = 100000 + int(hashlib.md5(url.encode()).hexdigest()[:4], 16) * 13
        # Containment: nothing is downloaded. We only record the URL as an IOC.
        self.state["files"][target] = f"#!/bin/sh\n# placeholder for {url} (not fetched - contained)\n"
        if tool == "curl" and not outp and "-O" not in a:
            return "<html><head><title>403 Forbidden</title></head><body>403</body></html>" if self.arm == "static" else \
                f"#!/bin/sh\ncd /tmp || cd /var/run; wget {url}; chmod +x {fname}; ./{fname}"
        return (f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\nResolving host... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\nLength: {size} ({size // 1024}K) [application/octet-stream]\n"
                f"Saving to: '{posixpath.basename(target)}'\n\n{posixpath.basename(target)}  100%[====================>] "
                f"{size // 1024}K  1.2MB/s    in 0.1s\n")

    def c_wget(self, a, m): return self._download(a, "wget")
    def c_curl(self, a, m): return self._download(a, "curl")
    def c_tftp(self, a, m): return self._download(a, "tftp")

    def exec_file(self, name):
        p = self.path(name)
        if not self.exists(p):
            return f"-bash: {name}: No such file or directory"
        return random.choice(["Segmentation fault (core dumped)", "-bash: " + name + ": cannot execute binary file: Exec format error",
                              "Illegal instruction"])

    def c_sh(self, a, m):
        if a and not a[0].startswith("-"):
            return self.exec_file(a[0])
        return ""
    c_bash = c_sh

    def c_sudo(self, a, m):
        if "-l" in a:
            return (f"Matching Defaults entries for {self.user} on {self.p['hostname']}:\n    env_reset, secure_path=/usr/sbin\n\n"
                    f"User {self.user} may run the following commands on {self.p['hostname']}:\n    (ALL : ALL) ALL")
        a = [x for x in a if not x.startswith("-")]
        if self.user == "root" or self.arm == "rich":
            return self.run(" ".join(a), m) if a else ""
        return f"[sudo] password for {self.user}: \nSorry, try again.\nsudo: 3 incorrect password attempts"

    def c_su(self, a, m): return "Password: \nsu: Authentication failure"

    def c_passwd(self, a, m):
        return "Changing password for root.\nNew password: \npasswd: Authentication token manipulation error"

    def c_crontab(self, a, m):
        if "-l" in a:
            return self.state.get("crontab", "no crontab for root")
        self.state["crontab"] = "* * * * * /tmp/.x/update >/dev/null 2>&1"
        return ""

    def c_export(self, a, m): return ""
    c_unset = c_alias = c_set = c_source = c_nohup = c_kill = c_pkill = c_killall = c_export

    def c_env(self, a, m):
        return f"SHELL=/bin/bash\nPWD={self.cwd}\nLOGNAME={self.user}\nHOME=/root\nLANG=C.UTF-8\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    def c_busybox(self, a, m):
        if self.p["key"] == "iot-camera":
            if a and a[0] not in ("ECCHI", "MIRAI"):
                return self.run(" ".join(a), m)
            return f"{a[0] if a else 'busybox'}: applet not found"
        return "-bash: busybox: command not found"

    def c_apt(self, a, m):
        return "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 3121 (unattended-upgr)"
    c_apt_get = c_yum = c_dnf = c_apt

    def c_ping(self, a, m):
        host = a[-1] if a else ""
        return f"PING {host} 56(84) bytes of data.\n\n--- {host} ping statistics ---\n4 packets transmitted, 0 received, 100% packet loss"

    def c_ssh(self, a, m):
        host = a[-1] if a else ""
        return f"ssh: connect to host {host.split('@')[-1]} port 22: Connection timed out"
    c_scp = c_ssh

    def c_python(self, a, m): return "" if a else "Python 3.10.12 (main) [GCC 11.4.0] on linux"
    c_python3 = c_perl = c_python

    def c_base64(self, a, m): return ""

    def c_which(self, a, m): return "\n".join(f"/usr/bin/{x}" for x in a)

    def c_clear(self, a, m): return "\x1b[2J\x1b[H"

    def c_help(self, a, m):
        return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\nThese shell commands are defined internally."

    def c_systemctl(self, a, m):
        return "Failed to connect to bus: Operation not permitted" if self.arm == "static" else \
            "  UNIT              LOAD   ACTIVE SUB     DESCRIPTION\n  mysql.service     loaded active running MySQL Community Server\n  nginx.service     loaded active running A high performance web server"

    def c_find(self, a, m):
        if self.arm in ("breadcrumbs", "rich"):
            return "\n".join(sorted(BREADCRUMB_PATHS | {f"/home/{self.p['user']}/backup.sql"}))
        return ""

    def c_last(self, a, m):
        return f"{self.p['user']}   pts/0        10.0.4.2         Mon Oct 28 09:14   still logged in\n\nwtmp begins Tue Oct  1 00:00:01 2026"
