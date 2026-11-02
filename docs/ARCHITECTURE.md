# Architecture

## Process model

A single process (`app/run.py`) hosts:

- the **web console + REST API** (`http.server.ThreadingHTTPServer` on 127.0.0.1:8765)
- **five sensor servers** (`socketserver.ThreadingTCPServer` / `ThreadingHTTPServer`), one thread per connection
- an **enrichment worker** thread (queue → AbuseIPDB / VirusTotal through the egress guard)
- a **housekeeping** thread (idle-session reaper, hourly retention purge)
- the **simulator** threads when scenarios or campaigns run

All state lives in one SQLite database (WAL mode) behind a re-entrant lock.

## Data flow (linked list)

```
Attacker ─▶ Sensor ─▶ Containment gate ─▶ HPSession(open)
                                            │  persona = Morph.current()
                                            │  state   = ConsistencyStore.load(ip)
                                            │  arm     = Bandit.select(predicted_profile)
                                            ▼
                                     interaction loop
                                            │  FakeShell.handle / HTTP respond / FTP / Modbus
                                            │  HPSession.event()
                                            │     ├─ attack.tag_*  → techniques
                                            │     ├─ attack.extract_iocs → iocs table + enrichment queue
                                            │     ├─ recompute(): profile_session(), threat score
                                            │     ├─ alerts (threshold / canary / ICS) → webhook, syslog
                                            │     └─ live stream (ring buffer, polled by the dashboard)
                                            │  after 3rd command: Bandit.select(profile) → maybe switch arm
                                            ▼
                                     HPSession.close()
                                            │  reward = engagement_reward(cmds, duration, bonus)
                                            └─ Bandit.update(profile, arm, reward)   ◀── feedback edge
```

## Tables

| Table | Contents |
|---|---|
| `users`, `auth_sessions` | Accounts (PBKDF2-SHA256, 200k iterations), session tokens (12 h) |
| `audit` | Every console action: who, what, category, detail, IP |
| `pageviews` | Active seconds per page per user (feeds the Adaptive Analysis Report) |
| `hp_sessions` | One row per attacker session: sensor, IP, geo, profile, threat, strategy, persona, duration, flags |
| `events` | Every login, command, request and PLC call, with the decoy response and ATT&CK techniques |
| `iocs` | Unique (type, value) with sightings and enrichment |
| `creds` | Credentials tried, and whether the decoy accepted them |
| `alerts` | Severity, title, MTTD, delivery channels, acknowledgement |
| `bandit` | (profile, arm) → pulls, cumulative reward |
| `vfs_state` | Per-IP virtual filesystem JSON |
| `settings` | JSON key/value configuration |

## Security of the console itself

- Binds to 127.0.0.1 only; cross-origin POSTs are rejected.
- HttpOnly + SameSite=Strict cookies; `X-Frame-Options: DENY`, `nosniff`, `no-store`.
- Login throttling (8 failures per IP in 5 minutes).
- Role checks on every API route; secrets are masked in API responses.
- The shutdown endpoint requires an admin session or a per-run control token written to the data folder.

## Extending

- **New sensor:** subclass `BaseSensor`, implement `serve(sock, sess)`, add it to `SENSOR_CLASSES` and give it a port in `config.DEFAULT_SETTINGS`.
- **New strategy (arm):** add it to `adaptive.ARMS` and branch on `sess.arm` / `shell.arm` in the responders.
- **New ATT&CK rule:** append to `SHELL_RULES` or `HTTP_RULES` in `attack.py`.
- **New simulator scenario:** add to `SCENARIOS` and implement `_<name>(self, ip)` in `simulator.py`.
