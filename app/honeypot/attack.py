"""MITRE ATT&CK tagging and IOC extraction (pure, rule-based, explainable)."""
import ipaddress
import re

# (regex, technique_id, name, tactic, severity) - applied to shell/ftp commands
SHELL_RULES = [
    (r"\b(wget|curl|tftp|ftpget)\b", "T1105", "Ingress Tool Transfer", "command-and-control", 15),
    (r"\b(uname|lscpu|nproc|hostnamectl)\b|/proc/cpuinfo|\bfree\b|\bdf\b", "T1082", "System Information Discovery", "discovery", 5),
    (r"^\s*(ls|find|locate)\b", "T1083", "File and Directory Discovery", "discovery", 3),
    (r"/etc/(passwd|shadow)", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "credential-access", 20),
    (r"^\s*(whoami|id|w|who|last)\b", "T1033", "System Owner/User Discovery", "discovery", 5),
    (r"^\s*(ps|top|htop)\b", "T1057", "Process Discovery", "discovery", 4),
    (r"\b(netstat|ss|ifconfig|arp|route)\b|\bip (a|addr|r|route)\b", "T1016", "System Network Configuration Discovery", "discovery", 6),
    (r"crontab|/etc/cron", "T1053.003", "Scheduled Task/Job: Cron", "persistence", 20),
    (r"authorized_keys", "T1098.004", "Account Manipulation: SSH Authorized Keys", "persistence", 25),
    (r"history -c|unset HISTFILE|\.bash_history|\bshred\b", "T1070.003", "Indicator Removal: Clear Command History", "defense-evasion", 15),
    (r"chmod (\+x|[0-7]?7[0-7]{2})", "T1222.002", "Linux File and Directory Permissions Modification", "defense-evasion", 8),
    (r"xmrig|minerd|stratum\+tcp|cryptonight|kdevtmpfsi", "T1496", "Resource Hijacking", "impact", 25),
    (r"^\s*(sudo|su)\b", "T1548.003", "Abuse Elevation Control: Sudo and Sudo Caching", "privilege-escalation", 15),
    (r"base64 (-d|--decode)|\\x[0-9a-fA-F]{2}", "T1140", "Deobfuscate/Decode Files or Information", "defense-evasion", 12),
    (r"\bssh\b\s+\S*@|\bscp\b", "T1021.004", "Remote Services: SSH", "lateral-movement", 20),
    (r"\b(nmap|masscan|zmap)\b", "T1046", "Network Service Discovery", "discovery", 10),
    (r"\b(useradd|adduser|passwd)\b", "T1136.001", "Create Account: Local Account", "persistence", 20),
    (r"rm -rf /(\s|$)|\bmkfs\b|\bdd if=", "T1485", "Data Destruction", "impact", 30),
    (r"\bpython[23]? -c\b|\bperl -e\b", "T1059.006", "Command and Scripting Interpreter: Python", "execution", 10),
    (r"\bbusybox\b|/bin/sh|\bsh -c\b|\bbash -c\b", "T1059.004", "Command and Scripting Interpreter: Unix Shell", "execution", 8),
    (r"\.aws/credentials|\.env\b|id_rsa|\.git/config", "T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access", 15),
]

HTTP_RULES = [
    (r"union(\s|\+|%20)+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d+\)|information_schema", "T1190", "Exploit Public-Facing Application (SQLi)", "initial-access", 25),
    (r"<script|javascript:|onerror=|%3Cscript", "T1190", "Exploit Public-Facing Application (XSS)", "initial-access", 15),
    (r"\.\./|%2e%2e%2f|/etc/passwd", "T1190", "Exploit Public-Facing Application (Path traversal)", "initial-access", 20),
    (r"\$\{jndi:", "T1190", "Exploit Public-Facing Application (Log4Shell)", "initial-access", 30),
    (r";\s*(id|cat|wget|curl|uname)\b|\|\s*(id|sh)\b|`[^`]+`|\$\([^)]+\)", "T1059", "Command Injection", "execution", 25),
    (r"/\.env|/\.git/|/wp-config|/config\.php|/backup", "T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access", 15),
    (r"/wp-login|/phpmyadmin|/admin|/manager/html|/login", "T1595.003", "Active Scanning: Wordlist Scanning", "reconnaissance", 6),
]

SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|wpscan|python-requests|go-http-client|curl/|wget/|libwww|httpclient|scanner", re.I)

TECH = {  # extra techniques used by sensors directly
    "T1110.001": ("Brute Force: Password Guessing", "credential-access", 10),
    "T1078": ("Valid Accounts", "initial-access", 15),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "reconnaissance", 8),
    "T1046": ("Network Service Discovery", "discovery", 3),
    "T0801": ("ICS: Monitor Process State", "collection", 8),
    "T0855": ("ICS: Unauthorized Command Message", "impair-process-control", 35),
    "T0836": ("ICS: Modify Parameter", "impair-process-control", 30),
    "T0888": ("ICS: Remote System Information Discovery", "discovery", 6),
    "T1005": ("Data from Local System", "collection", 10),
    "T1105": ("Ingress Tool Transfer", "command-and-control", 15),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "execution", 2),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "credential-access", 15),
}

_shell_c = [(re.compile(r, re.I), t, n, ta, s) for r, t, n, ta, s in SHELL_RULES]
_http_c = [(re.compile(r, re.I), t, n, ta, s) for r, t, n, ta, s in HTTP_RULES]


def tag_shell(cmd):
    out = []
    for rx, t, n, ta, s in _shell_c:
        if rx.search(cmd):
            out.append({"id": t, "name": n, "tactic": ta, "severity": s})
    return out


def tag_http(text):
    out, seen = [], set()
    for rx, t, n, ta, s in _http_c:
        if rx.search(text) and (t, n) not in seen:
            seen.add((t, n))
            out.append({"id": t, "name": n, "tactic": ta, "severity": s})
    return out


def tech(tid):
    n, ta, s = TECH[tid]
    return {"id": tid, "name": n, "tactic": ta, "severity": s}


URL_RX = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>;|`]+", re.I)
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RX = re.compile(r"\b([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
DOMAIN_RX = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|cn|xyz|top|io|info|biz|in|cc|tk|su)\b", re.I)


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved or a.is_multicast or a.is_link_local)
    except ValueError:
        return False


def extract_iocs(text):
    iocs = []
    for u in URL_RX.findall(text or ""):
        iocs.append(("url", u.rstrip(".,)")))
        m = re.match(r"\w+://([^/:]+)", u)
        if m and not IP_RX.fullmatch(m.group(1)):
            iocs.append(("domain", m.group(1).lower()))
    for ip in IP_RX.findall(text or ""):
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts) and (is_public(ip) or ip.startswith("198.18.") or ip.startswith("198.19.")):
            iocs.append(("ip", ip))
    for h in HASH_RX.findall(text or ""):
        iocs.append(("hash", h.lower()))
    for d in DOMAIN_RX.findall(text or ""):
        iocs.append(("domain", d.lower()))
    seen, out = set(), []
    for i in iocs:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out
