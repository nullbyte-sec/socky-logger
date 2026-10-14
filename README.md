# Socky Logger

A lightweight, read-only SOC log monitoring tool for Linux. It watches multiple
log files at once in a live terminal dashboard, detects suspicious activity,
and writes everything to a report file.

Built for defensive monitoring of your OWN machine or authorized lab only.

## What it does

- Watches Apache/Nginx access logs, auth.log, syslog, kern.log, dpkg.log,
  cron.log, web error logs, MySQL/MariaDB and PostgreSQL logs
- Detects SQL injection, XSS, path traversal, command injection, scanner
  user agents, sensitive file probing, brute force, directory scanning
  and request floods
- Monitors SSH brute force, root logins, new users, sudo misuse and
  suspicious cron jobs
- Optional CPU/RAM health check that raises brute force, scan and DoS
  findings to CRITICAL when the server is under load
- Live multi-pane terminal dashboard with alerts, per-log stats and a
  full detail view for each finding
- Saves a readable text report, with an optional JSON Lines output

## Files

| File | Purpose |
|---|---|
| `soc_analyst.py` | Web access log rules, report writer, CLI |
| `soc_auth.py` | auth.log rules (SSH, sudo, su, user changes) |
| `soc_generic.py` | Rules for syslog, kern, dpkg, cron, DB and other logs |
| `soc_live.py` | Live multi-pane terminal dashboard |

## Requirements

- Linux (Debian/Ubuntu/Kali)
- Python 3.6+ (standard library only, no pip installs)
- Read access to the log files (run with sudo, or add your user to the `adm` group)

## Quick start

```bash
# See which logs it will monitor
sudo python3 soc_live.py --list

# Start the live dashboard
sudo python3 soc_live.py --out report.txt --whitelist none

# Monitor specific logs
sudo python3 soc_live.py --logs /var/log/auth.log /var/log/syslog /var/log/kern.log

# Include every other readable *.log in /var/log
sudo python3 soc_live.py --all --out report.txt

# Enable CPU/RAM health escalation
sudo python3 soc_live.py --health --cpu-limit 50 --ram-limit 80
```

## Dashboard keys

| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | Next / previous pane |
| `1`-`9` | Jump to a pane |
| `[` / `]` | Previous / next page |
| `m` | Maximize / restore focused pane |
| `Up` / `Down` | Select an alert |
| `Enter` / `d` | Inspect the selected alert |
| `Esc` | Close the detail view |
| `p` | Pause / resume screen |
| `q` | Quit and save the summary |

## Severity levels

| Level | Meaning |
|---|---|
| CRITICAL | Likely exploit or confirmed impact (Shellshock, Log4Shell, successful login after failures) |
| HIGH | Clear attack intent (SQLi, XSS, scanner tools, brute force) |
| MEDIUM | Suspicious behavior (directory scanning, admin probing, error bursts) |
| LOW | Worth noting (odd user agents, malformed requests, quiet-hour activity) |

## Safety

This tool is **read-only**. It never modifies, deletes or rotates log files,
and it never blocks IPs or changes the server. Detection and response stay
separate: review the report, then decide what to do.

Use it only on systems you own or have explicit permission to monitor.

## Author

Built by [nullbyte-sec](https://github.com/nullbyte-sec)
