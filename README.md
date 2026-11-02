# Adaptive Cybersecurity Honeypot

A deception platform that runs **five decoy services**, profiles every attacker who touches them, and **adapts its behaviour** with a learning engine to keep each type of attacker engaged longer. It turns what they do into MITRE ATT&CK-tagged threat intelligence.

It ships as a **one-click Windows installer** with its own Python runtime, a **multi-page web console** (light, dark and system themes in rose pink), and a built-in **attack simulator**, so the whole system can be evaluated safely on one PC with no internet connection.

> Version 1.0.0 · MIT License · Python standard library only (no pip dependencies)

---

## Contents

1. [Quick start (Windows installer)](#1-quick-start-windows-installer)
2. [Uninstall](#2-uninstall)
3. [What's inside the console](#3-whats-inside-the-console)
4. [Architecture (linked-list view)](#4-architecture-linked-list-view)
5. [The nine areas](#5-the-nine-areas)
6. [Algorithms](#6-algorithms)
7. [API keys (all optional)](#7-api-keys-all-optional)
8. [Run from source (any OS)](#8-run-from-source-any-os)
9. [Build the installer yourself](#9-build-the-installer-yourself)
10. [REST API](#10-rest-api)
11. [Project layout](#11-project-layout)
12. [Safety, legal and limitations](#12-safety-legal-and-limitations)

---

## 1. Quick start (Windows installer)

1. Run **`release/AdaptiveHoneypot-Setup-1.0.0.exe`** (about 11 MB).
   - Windows SmartScreen may say *"Windows protected your PC"* because the installer is not code-signed. Click **More info → Run anyway**.
   - The installer is per-user: it needs no administrator rights and installs to `%LOCALAPPDATA%\Programs\AdaptiveHoneypot`.
2. Leave **Launch Adaptive Honeypot** ticked and click **Finish**. Your browser opens at **http://127.0.0.1:8765**.
3. **Create the first account.** It automatically becomes the **admin**.
4. On the dashboard, click **I acknowledge** on the governance check.
5. Open **Attack Lab** and click **Run all once**, or **Start campaign**, then go back to the **Dashboard** to watch it live.

| Shortcut (Start menu / desktop) | What it does |
|---|---|
| **Adaptive Honeypot** | Starts the server and sensors in the background (no console window) and opens the browser. If it's already running, it just opens the browser. |
| **Stop Adaptive Honeypot** | Shuts the server and all decoys down cleanly. |
| **Uninstall Adaptive Honeypot** | Removes the app. |

Your data (database, logs, reports) is stored in `%LOCALAPPDATA%\AdaptiveHoneypot`.

## 2. Uninstall

Use any of these:

- **Settings → Apps → Installed apps → Adaptive Honeypot → Uninstall**
- **Control Panel → Programs and Features**
- **Revo Uninstaller** (it finds the standard registry entry; the *QuietUninstallString* is `Uninstall.exe /S`)
- Start menu → **Uninstall Adaptive Honeypot**

The uninstaller stops the app, removes all program files, shortcuts and registry keys, then **asks** whether to delete your data folder too. In silent mode (`/S`) the data folder is kept.

## 3. What's inside the console

| Page | Purpose |
|---|---|
| **About** (public) | What the project is, the architecture as a linked list, algorithm definitions, the nine areas, a getting-started guide |
| **Sign in / Create account** | PBKDF2-SHA256 passwords, HttpOnly + SameSite cookies, brute-force lockout, roles (admin / analyst / viewer) |
| **Dashboard** | KPIs, attack timeline, attacker profiles, live event feed, active sessions, alerts, ATT&CK techniques and tactics, sensors, origin countries, adaptive vs. static comparison, top attackers, credentials and commands, recent sessions with full timeline drawer |
| **Nine Areas** | One tab per project area, each live and configurable (see §5) |
| **Attack Lab** | 8 simulated attacker scenarios, a continuous campaign mode, and a **web terminal** where you play the attacker and see the engine profile and adapt to you in real time |
| **Toolkit & APIs** | Processing flow, how the project was analysed, component inventory, API key configuration, requirements, REST reference, personas and scenarios |
| **History** | Audit log of every user action (filters + CSV export), attacker session history, alerts, captured credentials |
| **Reports** | Threat analysis report (HTML → Save as PDF), sessions/IOC CSV, JSON, STIX 2.1, audit CSV, plus the **Adaptive Analysis Report**: ratios of where *you* spend time and what you do, compared with the attacker mix |
| **Learn & Play** (public) | 5 games: Honeypot Basics Quiz, Build the Chain (linked list), Be the Adaptive Engine, Packet Catcher, ATT&CK Match |

Theme switcher (top right): **Light · Dark · System**.

## 4. Architecture (linked-list view)

Each node holds *data* (its job) and a *next* pointer to the stage that receives its output:

```
[1 Attacker] -> [2 Sensor layer] -> [3 Containment gate] -> [4 Session + consistency store]
   -> [5 Adaptive engine] -> [6 Response generator] -> [7 Data pipeline] -> [8 Storage]
   -> [9 Alerting + threat intel] -> [10 Console + reports] -> NULL

back-pointer: 6 --(engagement reward)--> 5      (this feedback edge is what makes it adaptive)
```

| # | Node | Implementation |
|---|---|---|
| 1 | Attacker | Real traffic, or the simulator (PROXY v1 header with a 198.18.0.0/15 source, trusted only from localhost in lab mode) |
| 2 | Sensors | SSH banner :2222 · Telnet shell :2323 · HTTP portal :8081 · FTP :2121 · Modbus/TCP PLC :5020 |
| 3 | Containment | Kill switch, per-IP rate limit, concurrency cap, session timeout |
| 4 | Session store | Persona assignment, per-IP virtual filesystem persisted in SQLite |
| 5 | Adaptive engine | Explainable profiler, UCB1 bandit per profile, persona morphing |
| 6 | Responder | Emulated shell (60+ commands), fake web pages, FTP listings, PLC registers, optional local LLM |
| 7 | Pipeline | ATT&CK tagging (~30 techniques incl. ICS), IOC extraction, AbuseIPDB / VirusTotal enrichment, threat score |
| 8 | Storage | SQLite (WAL) with retention purge |
| 9 | Intel | Alerts → webhook / syslog CEF; STIX 2.1 bundle; MISP push |
| 10 | Console | This web app + reports |

A longer write-up is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## 5. The nine areas

| # | Area | What's live in the app |
|---|---|---|
| 1 | **Scope** | Surfaces to imitate (synced to sensors), deployment mode (lab / internal / internet), output consumers, organisation name |
| 2 | **Infrastructure** | Host and runtime info, data folder, DB size, threads, uptime; bind address and all five ports (apply = hot restart) |
| 3 | **Honeypot sensors** | Start/stop each decoy, status, connections, interaction level, how to connect yourself |
| 4 | **Adaptive engine** | On/off (A/B), UCB1 constant, live bandit table, persona rotation, local LLM (Ollama) config and test, consistency store |
| 5 | **Data pipeline** | Event/IOC counts, enrichment queue, IOC table with filters, exports |
| 6 | **Threat intel** | STIX download, MISP URL/key and push, webhook and syslog with test buttons, alert threshold |
| 7 | **Containment** | Kill switch, exposure status, lab mode, rate/session limits, egress allow-list and blocked log, decoy reset |
| 8 | **Governance** | Legal acknowledgement and SOP, retention and purge, IP anonymisation, self sign-up toggle, user roles, audit trail |
| 9 | **Success metrics** | Engagement time, commands/session, adaptive uplift vs. static, detection rate, IOCs, MTTD, per-strategy table |

## 6. Algorithms

**Attacker profiling (explainable rules):** features per session are command count, average inter-command gap, tool signatures, invalid commands, breadcrumbs read, ATT&CK tactics covered, HTTP scanner user-agents and payloads, and Modbus writes. The result is one of `scanner`, `bot`, `script_kiddie`, `skilled` or `unknown`, with a confidence and human-readable reasons.

**Strategy selection: UCB1 contextual bandit.** There is one bandit per profile, with four arms:

| Arm | Behaviour |
|---|---|
| `static` | Classic honeypot. Kept as the **control group** to measure uplift |
| `breadcrumbs` | Plants canary credentials and files (`.env`, `.aws/credentials`, notes, backups) |
| `tarpit` | Adds 0.4–1.4 s latency to slow automated tools |
| `rich` | High interaction: richer output, accepts `sudo`, local LLM for unknown commands |

```
if any arm untried: choose it
else choose argmax_a  mean_reward(a) + c * sqrt( ln N / n(a) )      (c = 1.2 by default)
```

The strategy is chosen at connect time (using the IP's previous profile) and re-chosen after the 3rd command.

**Engagement reward** (fed back when a session closes):
`reward = 0.6·min(1, commands/15) + 0.4·min(1, duration/120 s) + 0.1 if breadcrumbs or IOCs captured` (capped at 1).

**Threat score (0–100):** the sum of unique technique severities, plus 10 × breadcrumbs, plus 15 if login succeeded, plus 3 × IOCs (max 5), plus 30 if a canary credential is reused. An alert fires at ≥ 70 (configurable), and always on canary access, canary reuse or ICS writes.

**Persona morphing:** rotates hostname, OS, kernel, SSH/HTTP/FTP banners and PLC vendor among 4 fictional personas every *N* minutes or on demand.

**Consistency store:** a per-IP virtual filesystem overlay (created/deleted files, cwd, history, crontab), so a returning attacker finds the world as they left it.

**Honeypot-detection heuristic:** a session is flagged when it runs honeypot checks (`cowrie`, `/proc/1/cgroup`, `systemd-detect-virt`, …) or leaves within 6 commands after ≥ 2 invalid ones.

## 7. API keys (all optional)

The app works fully offline. Configure keys in **Toolkit & APIs → API keys** (admin). Each configured integration is added to the egress allow-list automatically; every other outbound host is blocked and audited.

| Integration | Used for | Where to get it |
|---|---|---|
| AbuseIPDB | Country, ISP and abuse score for real attacker IPs | abuseipdb.com → Account → API |
| VirusTotal | Reputation of malware URLs attackers try to download | virustotal.com → profile → API key |
| MISP | Push IOCs as a MISP event | Your MISP → My Profile → Auth keys |
| Webhook | Real-time alerts to Slack / Teams / Discord / any JSON endpoint | Incoming-webhook URL |
| Ollama | Local LLM for realistic unknown-command output (`rich` strategy) | ollama.com → `ollama pull llama3.2` |
| Syslog | CEF alerts over UDP to Wazuh, Splunk, QRadar, Sentinel collector | Your SIEM collector |

## 8. Run from source (any OS)

Needs Python 3.10+ and nothing else.

```bash
cd app
python run.py                 # opens http://127.0.0.1:8765
python run.py --no-browser --port 9000
python stop.py                # stop a running instance
```

Data goes to `~/.adaptive-honeypot` (Linux/macOS), or set `AHP_DATA_DIR`.

Try the decoys by hand:

```bash
telnet 127.0.0.1 2323          # any login works after 3 tries; common default creds work at once
curl http://127.0.0.1:8081/.env
ftp 127.0.0.1 2121
```

## 9. Build the installer yourself

The installer bundles a portable CPython 3.12 (from conda-forge) and is built with NSIS.

```bash
pip install zstandard
# Linux/macOS (apt install nsis / brew install makensis)
./installer/build_installer.sh
# Windows (NSIS 3 on PATH)
installer\build_installer.bat
```

Output: `installer/build/AdaptiveHoneypot-Setup-1.0.0.exe`. On GitHub, pushing a tag like `v1.0.0` runs `.github/workflows/build-installer.yml` and uploads the installer as a build artifact.

## 10. REST API

All under `http://127.0.0.1:8765`. JSON, cookie (or `Authorization: Bearer <token>`) auth.

| Method | Endpoint | Role |
|---|---|---|
| GET | `/api/health`, `/api/public/info`, `/api/whoami` | public |
| POST | `/api/auth/signup`, `/api/auth/login`, `/api/auth/logout` | public |
| GET | `/api/dashboard?range=1h\|24h\|7d\|30d`, `/api/live?since=`, `/api/metrics` | viewer |
| GET | `/api/sessions`, `/api/sessions/{id}`, `/api/iocs`, `/api/creds`, `/api/alerts`, `/api/areas` | viewer |
| GET/POST | `/api/settings` | viewer / admin |
| POST | `/api/sensors/{name}/start\|stop`, `/api/containment/killswitch`, `/api/containment/reset-decoys` | analyst |
| POST | `/api/engine/morph`, `/api/engine/reset-bandit`, `/api/llm/test` | analyst / admin |
| POST | `/api/sim/run`, `/api/sim/campaign`, `/api/lab/shell` | analyst |
| GET/POST | `/api/intel/stix`, `/api/intel/misp-push`, `/api/intel/test-webhook`, `/api/intel/test-syslog` | viewer / analyst |
| GET | `/api/reports/analysis?format=html\|csv\|iocs\|json`, `/api/reports/adaptive`, `/api/reports/adaptive.html` | viewer |
| GET | `/api/audit`, `/api/audit.csv` | viewer / analyst |
| POST | `/api/governance/purge`, `/api/governance/ack`, `/api/users/{id}/role` | admin |

## 11. Project layout

```
AdaptiveHoneypot/
├─ app/
│  ├─ run.py / stop.py          launcher and clean shutdown
│  ├─ honeypot/
│  │  ├─ config.py              paths, defaults
│  │  ├─ db.py                  SQLite schema, settings, audit
│  │  ├─ auth.py                accounts, PBKDF2, sessions, roles
│  │  ├─ sensors.py             SSH / Telnet / HTTP / FTP / Modbus decoys
│  │  ├─ fakeshell.py           emulated Linux shell + virtual filesystem
│  │  ├─ adaptive.py            profiler, UCB1 bandit, morphing, consistency, LLM
│  │  ├─ attack.py              ATT&CK rules, IOC extraction
│  │  ├─ core.py                session lifecycle, pipeline, enrichment, alerts, retention
│  │  ├─ containment.py         egress guard, rate limiter, anonymisation
│  │  ├─ intel.py               STIX 2.1, MISP, webhook, syslog CEF
│  │  ├─ metrics.py             KPIs, adaptive uplift, user-activity analysis
│  │  ├─ reports.py             HTML/CSV/JSON reports
│  │  ├─ simulator.py           8 attacker scenarios + campaign mode
│  │  └─ server.py              web server + REST API
│  └─ web/                      multi-page console (HTML/CSS/JS, offline)
├─ installer/                   NSIS scripts, icon, portable-Python fetcher, build scripts
├─ docs/ARCHITECTURE.md
├─ .github/workflows/build-installer.yml
├─ LICENSE
└─ README.md
```

## 12. Safety, legal and limitations

- **Emulation only.** Attacker commands are never executed. `wget`/`curl`/`ssh` inside decoys are simulated, and URLs are logged as IOCs, never fetched.
- **Local by default.** Decoys bind to `127.0.0.1`. Switching to `0.0.0.0` (Nine Areas → Infrastructure) exposes them, and Windows Firewall will ask for permission. Expose them to the internet only from a **dedicated, isolated VM** after a risk review, with port forwards 22→2222, 23→2323, 80→8081, 21→2121, 502→5020.
- **Governance.** Get written authorisation, follow your data-protection obligations (e.g. India's DPDP Act 2023 and IT Act 2000), keep retention short, and never retaliate against sources. This is not legal advice.
- **Limitations (v1.0):** the SSH sensor is low-interaction (banner and key-exchange capture, no full SSH protocol); FTP has no data channel; the profiler is rule-based (the bandit learns strategy, not profiles); lab geo for simulated IPs is synthetic; enrichment needs API keys and internet access.
- Canary credentials shown by the decoys (e.g. `Rose#Canary2026!`, `AKIAHONEYCANARY7ROSE`) are fake detection tokens.
