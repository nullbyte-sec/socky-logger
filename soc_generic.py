#!/usr/bin/env python3
"""
soc_generic.py - Read-only rules for other /var/log files (syslog, kern.log, dpkg.log,
cron, web error logs, MySQL/MariaDB, PostgreSQL and a generic keyword fallback).
Used by soc_live.py. Standard library only. Never modifies any log.
Note: these logs have many different timestamp formats, so findings are stamped
with the time the line was READ (fine for live monitoring).
"""
import re
import time
from collections import deque
from datetime import datetime

IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def R(name, sev, pattern, why, action, burst=None):
    """Rule: burst=(count, window_seconds, extra_rule_name, extra_severity) or None."""
    return dict(name=name, sev=sev, rx=re.compile(pattern, re.I), why=why, action=action, burst=burst)


# =====================================================================
# CONFIG SECTION - edit rules here. For each log type the FIRST matching rule wins,
# so keep the most serious rules at the top.
# =====================================================================
RULES = {
    "kern": [
        R("Promiscuous Mode", "HIGH", r"entered promiscuous mode",
          "A network interface entered promiscuous mode. Sniffers (tcpdump, Wireshark, ettercap) do this.",
          "Confirm you started a sniffer; otherwise investigate."),
        R("Out of Memory Kill", "HIGH", r"out of memory: kill|oom-kill",
          "The kernel killed a process because RAM ran out. A flood or leak may be happening.",
          "Check which process was killed and what caused the memory spike."),
        R("SYN Flood Warning", "HIGH", r"possible SYN flooding",
          "The kernel reports a possible SYN flood (DoS) against a listening port.",
          "Check the source IPs with 'ss -tn' and consider firewall rate limits."),
        R("Program Crash (segfault)", "MEDIUM", r"segfault at|general protection fault",
          "A program crashed with a memory error. Exploit attempts can cause this.",
          "Check which program crashed and whether a service was being attacked."),
        R("Disk / I-O Error", "MEDIUM", r"i/o error|ext4-fs error|buffer i/o",
          "The kernel reported a disk error.", "Check disk health with smartctl."),
        R("Firewall Block", "LOW", r"UFW BLOCK|\bIN=\S* OUT=\S* .*SRC=",
          "The firewall dropped a packet.", "Watch the source IP.",
          burst=(20, 60, "Port Scan / Firewall Block Flood", "HIGH")),
        R("USB Device Connected", "LOW", r"usb \S+: new (?:\w+-speed )?usb device",
          "A USB device was plugged in.", "Confirm it was you."),
    ],
    "syslog": [
        R("Security Service Stopped", "HIGH", r"(?:Stopped|Stopping) .*(?:fail2ban|ufw|apparmor|auditd|firewall)",
          "A security service was stopped. Attackers stop these to hide.",
          "Confirm you stopped it; restart it if not."),
        R("Crontab Modified", "MEDIUM", r"crontab\[\d+\]: \(\S+\) (?:BEGIN EDIT|REPLACE)",
          "A crontab was edited. Cron is a common way to stay on a machine.",
          "Run 'crontab -l' for each user and review."),
        R("Service Crash / Failure", "MEDIUM",
          r"segfault|core dumped|failed with result|main process exited, code=(?:killed|dumped)",
          "A service crashed or failed.", "Check 'journalctl -u <service>' for details."),
        R("Error Keyword", "LOW", r"\b(?:error|failed|failure|denied|refused|fatal|panic|critical)\b",
          "The line contains an error or failure word.", "Review if unexpected."),
    ],
    "cron": [
        R("Suspicious Cron Command", "HIGH",
          r"CMD \(.*(?:(?:wget|curl)[^)]*\|\s*(?:ba)?sh|nc\s+-e|/dev/tcp/|base64\s+-d|mkfifo|/tmp/\S+)",
          "A cron job runs a command with download-and-run, reverse shell or /tmp patterns.",
          "Inspect the crontab and the script it runs."),
        R("Crontab Modified", "MEDIUM", r"\(\S+\) (?:BEGIN EDIT|REPLACE)",
          "A crontab was edited.", "Run 'crontab -l' for each user and review."),
        R("Cron Error", "LOW", r"\b(?:error|bad command|failed)\b", "Cron reported an error.", "Review the job."),
    ],
    "dpkg": [
        R("Security Package Removed", "HIGH",
          r" (?:remove|purge) (?:fail2ban|ufw|apparmor|auditd|rsyslog|openssh-server|iptables|nftables|clamav)[:\s]",
          "A security-related package was removed.", "Confirm it was you; reinstall if not."),
        R("Package Removed", "LOW", r" (?:remove|purge) \S+ ", "A package was removed.", "Review if unexpected."),
        R("Package Installed", "LOW", r" install \S+ ", "A package was installed.", "Review if unexpected."),
    ],
    "weberror": [
        R("Invalid / Malformed Request", "MEDIUM",
          r"Invalid URI in request|request failed: (?:URI too long|error reading)|client sent invalid|AH0\d+: .*invalid",
          "The web server rejected a malformed request, typical of scanners and exploit attempts.",
          "Check the access log for the same IP."),
        R("PHP Error", "MEDIUM", r"PHP (?:Fatal error|Parse error|Warning:.*(?:include|require|file_get_contents))",
          "A PHP error occurred, possibly caused by bad input.", "Check the script and the request that caused it."),
        R("Access Denied by Server", "LOW", r"client denied by server configuration|Directory index forbidden|ModSecurity",
          "A request was denied by server rules.", "Watch the source IP.",
          burst=(10, 60, "Repeated Denied Requests", "MEDIUM")),
        R("File Not Found (probe)", "LOW",
          r"File does not exist|script '.*' not found|open\(\) \".*\" failed \(2:|No such file",
          "A requested file does not exist.", "Watch the IP; many of these means scanning.",
          burst=(20, 60, "Scan: Many Missing Files", "MEDIUM")),
    ],
    "mysql": [
        R("Access Denied", "LOW", r"Access denied for user",
          "A database login failed.", "Check the source IP and user.",
          burst=(5, 60, "Database Brute Force", "HIGH")),
        R("Database Error", "LOW", r"\[ERROR\]", "The database reported an error.", "Review the message."),
    ],
    "postgres": [
        R("Authentication Failure", "LOW", r"password authentication failed|no pg_hba\.conf entry",
          "A PostgreSQL login failed.", "Check the user and source.",
          burst=(5, 60, "Database Brute Force", "HIGH")),
        R("Fatal / Panic", "MEDIUM", r"\b(?:FATAL|PANIC)\b", "PostgreSQL reported a serious error.", "Review the message."),
    ],
    "generic": [
        R("Critical Keyword", "MEDIUM",
          r"\b(?:panic|fatal|critical|segfault|exploit|attack|intrusion|unauthori[sz]ed)\b",
          "The line contains a serious warning word.", "Review the line."),
        R("Error Keyword", "LOW", r"\b(?:error|failed|failure|denied|refused)\b",
          "The line contains an error word.", "Review if unexpected."),
    ],
}


def _valid_ip(text):
    return all(int(p) <= 255 for p in text.split("."))


def _init(st):
    if not hasattr(st, "gw"):
        st.gw = {}       # (kind, rule, ip) -> deque of times
        st.gcool = {}


def cleanup_generic(st, now):
    if not hasattr(st, "gw"):
        return
    for k in list(st.gw):
        dq = st.gw[k]
        while dq and now - dq[0] > 300:
            dq.popleft()
        if not dq:
            del st.gw[k]
    for k in [k for k, t in st.gcool.items() if now - t > 3600]:
        del st.gcool[k]


def process_generic_line(kind, line, st, rep, nets, record, is_white, post=None):
    """Match one log line against the rules for its kind and record any finding."""
    _init(st)
    st.lines += 1
    line = line.rstrip("\r\n")
    if not line.strip():
        return
    rule = None
    for r in RULES.get(kind, RULES["generic"]):
        if r["rx"].search(line):
            rule = r
            break
    if rule is None:
        return
    m = IP_RE.search(line)
    ip = m.group(0) if m and _valid_ip(m.group(0)) else "local"
    if ip != "local" and is_white(ip, nets):
        st.whitelisted += 1
        return
    now = time.time()
    rec = dict(ip=ip, ts=datetime.now().astimezone(), epoch=now, method=kind.upper(), url=line[:300],
               status=0, size=0, ref="-", ua="-", malformed=False)
    prefix = kind.upper() + ": "
    findings = [dict(rule=prefix + rule["name"], severity=rule["sev"], why=rule["why"], action=rule["action"])]
    if rule["burst"]:
        count, window, bname, bsev = rule["burst"]
        key = (kind, rule["name"], ip)
        dq = st.gw.setdefault(key, deque(maxlen=2000))
        dq.append(now)
        while dq and now - dq[0] > window:
            dq.popleft()
        last = st.gcool.get(key)
        if len(dq) >= count and (last is None or now - last >= window):
            st.gcool[key] = now
            findings.append(dict(rule=prefix + bname, severity=bsev,
                                 why="%d matching lines in %d seconds from the same source." % (len(dq), window),
                                 action="Investigate the source and consider blocking it."))
    st.latest = max(getattr(st, "latest", 0.0), now)
    if post:
        post(findings, rec)
    for f in findings:
        record(st, rep, rec, f)
