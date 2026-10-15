# Socky Logger

**A read-only, multi-log SOC monitoring dashboard for Linux — built for security students, homelab users and defenders of their own machines.**

Socky Logger accepts Apache/Nginx access logs, auth.log, syslog, kern.log,
dpkg.log, cron logs, web error logs and database logs. It parses each line,
runs detection rules and per-IP behavior windows, then writes a readable text
report (with optional JSON Lines). It is designed for security learners,
homelab owners and SOC-style defenders monitoring systems they own.

It turns hours of manually reading `grep` output into a live dashboard that
surfaces attacks in seconds.

## Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Reference](#reference)
- [Architecture](#architecture)
- [Testing](#testing)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Overview

**The problem:** reviewing Apache, SSH and system logs by hand means running
separate `grep`, `awk` and `tail` commands for each log, then correlating
repeated hits from the same IP yourself. On a busy server this takes minutes
per incident and is easy to miss.

**What Socky Logger does:**
1. Ingests multiple log files at once, following them live like `tail -f`.
2. Parses Combined/Common access logs, syslog-style auth events and plain-text system logs.
3. Runs compiled regex rules plus per-IP sliding-window behavior checks.
4. Explains every finding in plain English with a severity and a recommended action.
5. Exports a grouped text report and optional JSON Lines.

## Features

- **Multi-log dashboard:** one pane per log file, up to 24 sources, with paging and a maximize view.
- **Web attack detection:** SQL injection, XSS, path traversal/LFI/RFI, command injection, scanner user agents, sensitive file probes and known exploit patterns (Shellshock, Log4Shell, Struts, ThinkPHP).
- **Behavior detection:** brute force (10 login POSTs / 60 s), directory enumeration (20 404s / 60 s), request floods (100 requests / 10 s), auth failure bursts and login-after-failures.
- **Auth monitoring:** SSH brute force, root logins, new users, sudo misuse and suspicious cron commands.
- **Health escalation:** with `--health`, brute force, scan and DoS findings become CRITICAL when CPU is at/above 50% or RAM at/above 80%.
- **Optional IP blocker:** asks Yes/No before blocking with UFW; blocks expire automatically (1, 3, 7, 30 days, then 1 year).
- **Standard library only:** no `pip install` required; Python 3.6+.

## Installation

Requires Python 3.6 or newer on Linux (Debian/Ubuntu/Kali).

```bash
git clone [https://github.com/nullbyte-sec/socky-logger.git](https://github.com/nullbyte-sec/socky-logger.git)
cd socky-logger
```

No pip packages are needed. For the optional IP blocker and desktop popup:

```bash
bash install.sh
```

`install.sh` installs `ufw` and `zenity`, allows SSH (22), HTTP (80) and
HTTPS (443), and enables UFW. Review the script before running it.

## Configuration

Most settings live in a config block at the top of each module, so you can
edit thresholds without touching the logic.

| Setting | File | Default | Purpose |
|---|---|---|---|
| `FLOOD_COUNT / FLOOD_WINDOW` | `soc_analyst.py` | 100 / 10 s | Request flood threshold |
| `BRUTE_FORCE_POSTS / WINDOW` | `soc_analyst.py` | 10 / 60 s | Login brute force threshold |
| `NOT_FOUND_COUNT / WINDOW` | `soc_analyst.py` | 20 / 60 s | Directory enumeration threshold |
| `SSH_BRUTE_COUNT / WINDOW` | `soc_auth.py` | 5 / 60 s | SSH brute force threshold |
| `BLOCK_LADDER_DAYS` | `soc_blocker.py` | 1, 3, 7, 30, 365 | Block duration per repeat |
| `HIGH_REPEAT_COUNT / WINDOW` | `soc_blocker.py` | 3 / 300 s | HIGH hits before a block prompt |
| `HEALTH_CPU_PCT / HEALTH_RAM_PCT` | `soc_analyst.py` | 50% / 80% | Health escalation limits |

Whitelisted IPs are skipped entirely (default: `127.0.0.1`). The blocker
additionally refuses to block loopback, the machine's own IPs, the default
gateway, DNS servers and active SSH session IPs.

## Usage

### Live dashboard (all discovered logs)

```bash
sudo python3 soc_live.py --out report.txt --whitelist none
```

Example output:

```text
 SOCKY LOGGER - LIVE MONITOR  (authorized lab)
Report: report.txt | Uptime 00:05:12 | 12.3 lines/s | page 1/3
access.log:2  auth.log:1  syslog:0  kern.log:0[1][2][3][4]
> [1] apache2/access.log (access) | Lines 1204 | Bad 0 | Rot 0
  14:32:01 [CRIT] SQL Injection | 203.0.113.7 | GET /?id=1' UNION SELECT
```

### One-time scan of an existing log

```bash
sudo python3 soc_analyst.py --log /var/log/apache2/access.log --mode once --out report.txt
```

### IP blocker

```bash
# Dry run first: shows UFW commands without running them
sudo python3 soc_live.py --out report.txt --whitelist none --blocker --blocker-dry-run

# Real blocking (asks Yes/No for each attacking IP)
sudo python3 soc_live.py --out report.txt --whitelist none --blocker

# Manage blocks
sudo python3 soc_live.py --list-blocks
sudo python3 soc_live.py --unblock 203.0.113.7
sudo python3 soc_live.py --blocker-cleanup
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--logs PATH[:KIND]` | auto-discover | Logs to monitor; kinds: access, auth, syslog, kern, cron, dpkg, weberror, mysql, postgres, generic |
| `--all` | off | Also monitor every other readable `*.log` in `/var/log` |
| `--list` | off | Show what would be monitored, then exit |
| `--out FILE` | asked interactively | Report file name |
| `--json` | off | Also write JSON Lines next to the report |
| `--whitelist` | `127.0.0.1` | IPs/CIDRs to ignore, or `none` |
| `--history` | off | Read existing log content first, then keep watching |
| `--health` | off | Escalate findings to CRITICAL under CPU/RAM load |
| `--blocker` | off | Enable the Yes/No IP blocker |
| `--firewall` | `ufw` | `ufw` or `iptables` |
| `--prompt` | `auto` | `gui` (zenity popup), `terminal` (y/n box), or `auto` |
| `--protect IP...` | none | Extra IPs that must never be blocked |
| `--blocker-dry-run` | off | Show firewall commands without running them |

### Exit codes

| Result | Code |
|---|---|
| Success | 0 |
| Error (no logs, permission, bad arguments) | 1 |

## Reference

### Inputs / data sources

| Name | Supported types | Auth | Purpose |
|---|---|---|---|
| Apache/Nginx access log | Combined, Common | File read | Web attack detection |
| auth.log | syslog text | File read | SSH, sudo, su, user changes |
| syslog / kern.log | syslog text | File read | Service, kernel and firewall events |
| dpkg.log / cron.log | plain text | File read | Package and cron activity |
| Web error logs | Apache/Nginx error text | File read | Malformed requests, scan bursts |
| MySQL / PostgreSQL logs | plain text | File read | Database brute force and errors |

### Severity model

| Component | Severity | Rule |
|---|---|---|
| Shellshock / Log4Shell / Struts | CRITICAL | Always |
| SQLi, traversal, command injection, sensitive files, webshell | HIGH, CRITICAL if 2xx | `escalate=True` |
| Scanner UA, brute force, flood, login-after-failures | HIGH | Fixed |
| Directory scan, admin probes, error bursts | MEDIUM | Fixed |
| Odd UA, quiet hours, malformed lines | LOW | Fixed |
| Health escalation | +1 level | CPU ≥ 50% or RAM ≥ 80% |

### Storage

Block state is saved to `/var/lib/socky-logger/blocks.json` (or a local
fallback if that path is not writable). It records each IP's block count,
expiry time and history, so blocks survive a restart.

## Architecture

```text
soc_live.py        entrypoint: log discovery, grid dashboard, key handling
soc_analyst.py     access-log parsing, web rules, sliding windows, report writer
soc_auth.py        auth.log rules (SSH, sudo, su, users)
soc_generic.py     rules for syslog, kern, dpkg, cron, DB and generic logs
soc_blocker.py     optional UFW/iptables blocker with Yes/No prompt and expiry
```

## Testing

```bash
python3 soc_live.py --list
sudo python3 soc_live.py --out report.txt --whitelist none --blocker --blocker-dry-run
```

Manual test commands (run from a second machine against your own server):

```bash
curl -s -o /dev/null "http://TARGET/?id=1%27%20UNION%20SELECT%201,2--"   # SQLi
curl -s -o /dev/null -A "sqlmap/1.7" "http://TARGET/"                     # scanner UA
for i in $(seq 1 30); do curl -s -o /dev/null "http://TARGET/nope$i"; done # 404 burst
```

## Known Limitations

- Only sees what appears in log files: plain Nmap port scans and POST bodies are invisible.
- Regex rules can produce false positives on legitimate traffic containing keywords like `select` or `error`.
- A 2xx status does not prove an attack succeeded; verify CRITICAL findings manually.
- GUI popups need a desktop session; over SSH use `--prompt terminal`.
- Logs other than access/auth are timestamped with the read time, not the original log time.

## Roadmap

| Iteration | Scope | Status |
|---|---|---|
| 1 | Access log analysis, report, live dashboard | Done |
| 2 | auth.log monitoring, two-pane dashboard | Done |
| 3 | Multi-log grid, generic log rules | Done |
| 4 | Optional UFW blocker with escalating expiry | Done |
| 5 | Web dashboard, email/webhook alerts, fail2ban integration | Planned |

## Contributing

To add a new detection rule:

1. Open the relevant module (`soc_analyst.py`, `soc_auth.py` or `soc_generic.py`).
2. Add a rule dict to `PATTERN_RULES` or `RULES` with `name`, `sev`, `pattern`, `why` and `action`.
3. For behavior rules, add a sliding-window check in `run_rules()` or `analyze()`.
4. Test with a crafted log line and confirm the finding appears in the report.

## License

Released under the [MIT License](LICENSE).
