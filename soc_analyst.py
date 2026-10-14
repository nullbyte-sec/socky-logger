#!/usr/bin/env python3
"""
soc_analyst.py - Read-only SOC-style monitor for the Apache access log.
For defensive use on your OWN machine / authorized lab only.
It never modifies, deletes or rotates the log and never blocks or changes anything.
Standard library only (Python 3.6+).
"""

import argparse
import html
import ipaddress
import pwd
import subprocess
import json
import os
import re
import sys
import time
from collections import Counter, deque
from datetime import datetime
from urllib.parse import unquote_plus

# =====================================================================
# CONFIG SECTION - edit thresholds and patterns here
# =====================================================================
DEFAULT_LOG = "/var/log/apache2/access.log"
DEFAULT_WHITELIST = "127.0.0.1"          # comma separated IPs or CIDRs

BRUTE_FORCE_POSTS, BRUTE_FORCE_WINDOW = 10, 60      # POSTs to login pages
NOT_FOUND_COUNT, NOT_FOUND_WINDOW = 40, 60          # 404s (dir enumeration)
FLOOD_COUNT, FLOOD_WINDOW = 100, 10                 # requests (DoS)
AUTH_FAIL_COUNT, AUTH_FAIL_WINDOW = 10, 60          # 401/403 burst
ERROR_500_COUNT, ERROR_500_WINDOW = 5, 60           # 500 burst
FAIL_THEN_OK_COUNT, FAIL_THEN_OK_WINDOW = 5, 300    # 200 after many failures
LONG_URL_LENGTH = 2000
LARGE_RESPONSE_BYTES = 10 * 1024 * 1024             # 10 MB
QUIET_HOURS = range(0, 5)                           # 00:00-04:59 = unusual
UA_CHANGE_WINDOW = 600                              # seconds
MAX_DECODE_PASSES = 5                               # handles double encoding
CLEANUP_EVERY_LINES = 5000
LIVE_POLL_SECONDS = 0.5
REPEAT_MILESTONES = {10, 100, 1000, 10000, 100000}  # repeat-hit notes
MAX_URL_IN_REPORT = 4000
BAD_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}

LOGIN_PATH_RE = re.compile(
    r"(?:wp-login\.php|xmlrpc\.php|/login|/signin|/log-in|/auth|/admin|"
    r"/user/login|/account/login|/session)", re.I)

# Each rule: name, severity, target (url|path|ua|all), regex, why, action
# escalate=True raises HIGH -> CRITICAL if the server answered with 2xx.
# group: only the first matching rule of a group is reported.
PATTERN_RULES = [
    dict(name="SQL Injection", sev="HIGH", target="url", group="sqli", escalate=True,
         pattern=(r"union\s+(?:all\s+)?select|'\s*or\s+['\d]|\bor\s+1\s*=\s*1|"
                  r"\band\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema|"
                  r"waitfor\s+delay|load_file\s*\(|into\s+outfile|extractvalue\s*\(|"
                  r"updatexml\s*\(|;\s*drop\s+table|['\"]\s*(?:--|#)"),
         why="The URL contains SQL keywords or tricks used to read or change database data.",
         action="Review and patch the vulnerable parameter (use prepared statements); consider blocking the IP."),
    dict(name="SQLi Probe (quote/comment)", sev="LOW", target="url", group="sqli", escalate=False,
         pattern=r"'|--\s|--$",
         why="A single quote or SQL comment appeared in the request, often the first step of SQL injection testing.",
         action="Watch this IP; check whether the parameter is validated."),
    dict(name="Cross-Site Scripting (XSS)", sev="HIGH", target="url", group="xss", escalate=False,
         pattern=(r"<\s*/?\s*script|\bon(?:error|load|click|mouseover|focus|toggle)\s*=|"
                  r"javascript\s*:|<\s*(?:iframe|svg|img|body)[^>]*>|document\.cookie|"
                  r"alert\s*\(|fromcharcode"),
         why="The request contains script or HTML event code that tries to run in a visitor's browser.",
         action="Encode output and validate input on the affected parameter; review page for reflected content."),
    dict(name="Path Traversal / LFI / RFI", sev="HIGH", target="url", group="lfi", escalate=True,
         pattern=(r"\.\./|\.\.\\|/etc/(?:passwd|shadow|hosts)|/proc/self|win\.ini|boot\.ini|"
                  r"php://|data://|expect://|file://|[?&=]\s*(?:https?|ftp)://"),
         why="The request tries to read local files or include a remote file through a parameter.",
         action="Block the IP, check the parameter handling, and make sure no file include uses user input."),
    dict(name="Command Injection", sev="HIGH", target="url", group="cmdi", escalate=True,
         pattern=(r"(?:;|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|ping|echo|rm|chmod|python|perl)\b|"
                  r"\bnc\s+-e|/bin/(?:ba)?sh|\bwhoami\b|\bwget\s|\bcurl\s"),
         why="The request contains shell commands or operators that try to run commands on the server.",
         action="Block the IP and review any code that passes parameters to a shell."),
    dict(name="Command Injection Parameter", sev="MEDIUM", target="url", group="cmdi", escalate=False,
         pattern=r"(?:^|[?&])(?:cmd|exec|command|execute|shell)=",
         why="A parameter with a command-style name (cmd/exec) was used. Common in webshell and RCE probes.",
         action="Check whether the application has such a parameter; watch the IP."),
    dict(name="Scanner / Attack Tool", sev="HIGH", target="ua", group="ua", escalate=False,
         pattern=(r"sqlmap|nikto|nmap|dirbuster|\bdirb\b|gobuster|wfuzz|ffuf|hydra|masscan|"
                  r"burp|zgrab|acunetix|nessus|openvas|wpscan|whatweb|nuclei|havij|metasploit|feroxbuster"),
         why="The user agent matches a known scanning or attack tool.",
         action="Block the IP in the firewall and review what else it requested."),
    dict(name="Scripted Client", sev="LOW", target="ua", group="ua", escalate=False,
         pattern=r"python-requests|python-urllib|go-http-client|libwww-perl|okhttp|java/|scrapy|httpclient",
         why="The request came from a scripting library, not a normal browser.",
         action="Check whether this automation is expected."),
    dict(name="Sensitive Files (.env/.git)", sev="HIGH", target="path", group="path", escalate=True,
         pattern=r"(?:^|/)(?:\.env|\.git|\.svn|\.htpasswd|\.htaccess|\.ssh|id_rsa)(?:[/.?]|$)|\.(?:bak|old|sql|swp)$|backup[^/]*\.(?:zip|tar|gz|sql)$",
         why="The request targets secret, config or backup files that must never be public.",
         action="Make sure these files are not web-accessible; rotate any exposed secrets."),
    dict(name="Webshell / Upload Probe", sev="HIGH", target="path", group="path", escalate=True,
         pattern=r"/(?:uploads?|files|images|media|tmp|assets)/[^?]*\.(?:php\d?|phtml|jsp|aspx?)(?:$|[/?])",
         why="A script file was requested inside an upload-type folder, a typical webshell pattern.",
         action="Inspect the folder for unknown scripts and disable script execution in upload directories."),
    dict(name="Sensitive Path Probe", sev="MEDIUM", target="path", group="path", escalate=False,
         pattern=(r"(?:^|/)(?:admin|administrator|wp-login\.php|wp-admin|phpmyadmin|pma|config|"
                  r"backup|server-status|server-info|cgi-bin|manager/html|xmlrpc\.php)(?:[/.?]|$)"),
         why="The request targets an admin, config or management path that attackers commonly probe.",
         action="Restrict this path by IP or password and review the IP's other requests."),
    dict(name="Shellshock", sev="CRITICAL", target="all", group="exploit", escalate=False,
         pattern=r"\(\)\s*\{\s*[^}]*\}\s*;",
         why="The request has the Shellshock pattern used to run commands through CGI/Bash.",
         action="Block the IP now, patch Bash, and check /cgi-bin for compromise."),
    dict(name="Log4Shell (JNDI)", sev="CRITICAL", target="all", group="exploit", escalate=False,
         pattern=r"\$\{\s*jndi\s*:|\$\{[^}]{0,40}(?:lower|upper|::-)[^}]{0,40}\}.{0,40}(?:ldap|rmi|dns)",
         why="The request has a Log4Shell JNDI lookup string that can trigger remote code execution in Java apps.",
         action="Block the IP and verify no Java app logs this input with a vulnerable Log4j."),
    dict(name="Struts / OGNL Exploit", sev="CRITICAL", target="all", group="exploit", escalate=False,
         pattern=r"\(#_memberAccess|#_memberAccess|ognl:|\$\{#|\(#context|%\{#",
         why="The request contains OGNL expressions used in Apache Struts remote code execution exploits.",
         action="Block the IP and patch Struts if you run it."),
    dict(name="ThinkPHP / PHPUnit Exploit", sev="HIGH", target="url", group="exploit", escalate=True,
         pattern=r"invokefunction|call_user_func_array|think\\app|s=/?index/\\think|eval-stdin\.php",
         why="The request matches known ThinkPHP or PHPUnit remote code execution probes.",
         action="Block the IP and make sure these frameworks are patched or not exposed."),
]

# =====================================================================
# Helpers
# =====================================================================
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
COLORS = {"HIGH": "\033[91m", "CRITICAL": "\033[1;97;41m"}
RESET = "\033[0m"

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<size>\d+|-)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')
REQ_RE = re.compile(r"^([A-Za-z]+) (.*?)(?: (HTTP/[\d.]+))?$")
HEX_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
COMMENT_RE = re.compile(r"/\*.*?\*/")
CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def compile_rules():
    """Compile every regex once at start-up."""
    rules = []
    for r in PATTERN_RULES:
        r = dict(r)
        r["rx"] = re.compile(r["pattern"], re.I)
        rules.append(r)
    return rules


RULES = compile_rules()


def clean(text, limit=None):
    """Remove control characters so log data cannot mess up the terminal/report."""
    text = CTRL_RE.sub("?", str(text))
    if limit and len(text) > limit:
        text = text[:limit] + "...[truncated]"
    return text


def bump(sev):
    return SEVERITIES[min(SEVERITIES.index(sev) + 1, len(SEVERITIES) - 1)]


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =====================================================================
# parse_line / decode
# =====================================================================
def parse_line(line):
    """Parse a Combined or Common log line. Returns a dict, or None if unusable."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    m = LOG_RE.match(line)
    if not m:
        m2 = re.match(r"^([0-9A-Fa-f:.]+) ", line)   # malformed: salvage the IP if possible
        if not m2:
            return None
        return dict(ip=m2.group(1), ts=datetime.now().astimezone(), method="",
                    url=line[:300], proto="", status=0, size=0, ref="", ua="",
                    malformed=True, raw=line)
    try:
        ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        ts = datetime.now().astimezone()
    req = HEX_RE.sub(lambda x: chr(int(x.group(1), 16)), m.group("req"))
    rm = REQ_RE.match(req)
    if rm:
        method, url, proto = rm.group(1).upper(), rm.group(2), rm.group(3) or ""
        malformed = False
    else:
        method, url, proto, malformed = "", req, "", True
    status = int(m.group("status")) if m.group("status") != "-" else 0
    size = int(m.group("size")) if m.group("size") != "-" else 0
    return dict(ip=m.group("ip"), ts=ts, method=method, url=url, proto=proto,
                status=status, size=size, ref=m.group("ref") or "-",
                ua=m.group("ua") if m.group("ua") is not None else "-",
                malformed=malformed, raw=line)


def decode(text):
    """URL-decode repeatedly (double/triple encoding), unescape HTML, strip SQL comments."""
    if not text:
        return ""
    cur = HEX_RE.sub(lambda x: chr(int(x.group(1), 16)), text)
    for _ in range(MAX_DECODE_PASSES):
        prev = cur
        cur = html.unescape(unquote_plus(cur))
        if cur == prev:
            break
    cur = cur.replace("\x00", "")
    return COMMENT_RE.sub(" ", cur)


# =====================================================================
# State and sliding windows
# =====================================================================
class State:
    def __init__(self):
        self.win = {k: {} for k in ("flood", "404", "post", "authfail", "500")}
        self.cool = {}          # (ip, rule) -> last fired epoch
        self.last_ua = {}       # ip -> (ua, epoch)
        self.groups = {}        # (ip, rule) -> repeat summary
        self.sev = Counter()
        self.ip_hits = Counter()
        self.rule_hits = Counter()
        self.timeline = Counter()
        self.lines = 0
        self.malformed = 0
        self.whitelisted = 0
        self.latest = 0.0
        self.started = now_str()


def window_count(store, ip, now, span, add=True):
    """Add a hit (optional), drop old ones, return how many remain in the window."""
    dq = store.get(ip)
    if dq is None:
        dq = store[ip] = deque(maxlen=5000)
    if add:
        dq.append(now)
    while dq and now - dq[0] > span:
        dq.popleft()
    return len(dq)


def should_fire(st, ip, rule, now, span):
    """Cooldown so a threshold rule fires once per window, not on every request."""
    last = st.cool.get((ip, rule))
    if last is not None and 0 <= now - last < span:
        return False
    st.cool[(ip, rule)] = now
    return True


def cleanup(st, now):
    """Free memory: drop idle IPs from all windows and old cooldown entries."""
    for store in st.win.values():
        for ip in list(store):
            dq = store[ip]
            while dq and now - dq[0] > 300:
                dq.popleft()
            if not dq:
                del store[ip]
    for k in [k for k, t in st.cool.items() if now - t > 3600]:
        del st.cool[k]
    for ip in [i for i, (_, t) in st.last_ua.items() if now - t > 3600]:
        del st.last_ua[ip]


# =====================================================================
# run_rules
# =====================================================================
def run_rules(rec, st):
    """Return a list of findings: dict(rule, severity, why, action)."""
    out = []

    def add(rule, sev, why, action):
        out.append(dict(rule=rule, severity=sev, why=why, action=action))

    ip, now, status, method = rec["ip"], rec["epoch"], rec["status"], rec["method"]
    dec = rec["dec_url"]
    path = dec.split("?", 1)[0]
    targets = {"url": dec, "path": path, "ua": rec["dec_ua"],
               "all": " ".join((dec, rec["dec_ua"], rec["dec_ref"]))}

    # ---- 1. Pattern rules (compiled regexes) ----
    seen = set()
    for r in RULES:
        if r["group"] in seen:
            continue
        if r["rx"].search(targets[r["target"]]):
            seen.add(r["group"])
            sev, why = r["sev"], r["why"]
            if r["escalate"] and 200 <= status < 300 and sev == "HIGH":
                sev = bump(sev)
                why += " The server answered 2xx, so verify the attack did not work."
            add(r["name"], sev, why, r["action"])

    # ---- 2. Request-level checks ----
    if rec["malformed"]:
        add("Malformed / Non-HTTP Request", "LOW",
            "The request line is not valid HTTP. Port scanners and TLS-to-HTTP probes do this.",
            "Check this IP for scanning activity.")
    if method in BAD_METHODS:
        sev = "HIGH" if method in ("PUT", "DELETE") and 200 <= status < 300 else "MEDIUM"
        add("Suspicious HTTP Method", sev,
            "Method %s is rarely used on normal websites and can upload or delete content." % method,
            "Disable unneeded methods (Apache: TraceEnable off, LimitExcept).")
    if len(rec["url"]) > LONG_URL_LENGTH:
        add("Very Long URL", "MEDIUM",
            "The URL is %d characters long, which may be a buffer overflow or payload attempt." % len(rec["url"]),
            "Review the request; consider LimitRequestLine in Apache.")
    ua = rec["ua"].strip()
    if not rec["malformed"]:
        if ua in ("", "-"):
            add("Empty User Agent", "LOW", "The client sent no user agent, which is common for scripts and scanners.",
                "Watch this IP.")
        elif len(ua) < 10:
            add("Odd User Agent", "LOW", "The user agent is very short or unusual: '%s'." % clean(ua, 40),
                "Watch this IP.")
    if status == 200 and rec["size"] >= LARGE_RESPONSE_BYTES:
        add("Large Response (Possible Exfiltration)", "MEDIUM",
            "The response was %.1f MB. Large downloads can mean data theft." % (rec["size"] / 1048576.0),
            "Confirm this download is expected for that file.")
    if rec["ts"].hour in QUIET_HOURS and should_fire(st, ip, "Unusual Hour", now, 3600):
        add("Unusual Hour Activity", "LOW",
            "Activity at %02d:%02d falls in the configured quiet hours." % (rec["ts"].hour, rec["ts"].minute),
            "Check if this access is expected.")

    # ---- 3. Behaviour rules (sliding windows per IP) ----
    n = window_count(st.win["flood"], ip, now, FLOOD_WINDOW)
    if n >= FLOOD_COUNT and should_fire(st, ip, "Request Flood", now, FLOOD_WINDOW):
        add("Request Flood / DoS", "HIGH",
            "%d requests in %d seconds from one IP." % (n, FLOOD_WINDOW),
            "Rate-limit or block the IP (mod_evasive, mod_qos, firewall).")
    if status == 404:
        n = window_count(st.win["404"], ip, now, NOT_FOUND_WINDOW)
        if n >= NOT_FOUND_COUNT and should_fire(st, ip, "Directory Enumeration", now, NOT_FOUND_WINDOW):
            add("Directory Enumeration / Scan", "MEDIUM",
                "%d 'Not Found' errors in %d seconds, typical of gobuster/dirb style scanning." % (n, NOT_FOUND_WINDOW),
                "Block the IP and review which paths it guessed.")
    is_login_post = method == "POST" and LOGIN_PATH_RE.search(dec.split("?", 1)[0])
    if is_login_post:
        n = window_count(st.win["post"], ip, now, BRUTE_FORCE_WINDOW)
        if n >= BRUTE_FORCE_POSTS and should_fire(st, ip, "Brute Force Login", now, BRUTE_FORCE_WINDOW):
            add("Brute Force Login", "HIGH",
                "%d POST requests to a login page in %d seconds." % (n, BRUTE_FORCE_WINDOW),
                "Review the login page, add rate limiting or lockout, and block the IP.")
    if status in (401, 403):
        window_count(st.win["authfail"], ip, now, FAIL_THEN_OK_WINDOW)
        recent = sum(1 for t in st.win["authfail"][ip] if now - t <= AUTH_FAIL_WINDOW)
        if recent >= AUTH_FAIL_COUNT and should_fire(st, ip, "Auth Failure Burst", now, AUTH_FAIL_WINDOW):
            add("Auth Failure Burst (401/403)", "MEDIUM",
                "%d denied requests in %d seconds from one IP." % (recent, AUTH_FAIL_WINDOW),
                "Check for password guessing and consider blocking the IP.")
    elif status == 500:
        n = window_count(st.win["500"], ip, now, ERROR_500_WINDOW)
        if n >= ERROR_500_COUNT and should_fire(st, ip, "Server Error Burst", now, ERROR_500_WINDOW):
            add("Server Error Burst (500)", "MEDIUM",
                "%d server errors in %d seconds; the IP may be breaking the application with bad input." % (n, ERROR_500_WINDOW),
                "Check the Apache error log and fix the failing code path.")
    elif status in (200, 302) and is_login_post and ip in st.win["authfail"]:
        fails = window_count(st.win["authfail"], ip, now, FAIL_THEN_OK_WINDOW, add=False)
        if fails >= FAIL_THEN_OK_COUNT:
            add("Possible Successful Login After Failures", "HIGH",
                "A login POST succeeded right after %d denied requests from the same IP." % fails,
                "Verify that account, force a password reset, and check its recent activity.")
            st.win["authfail"][ip].clear()

    prev = st.last_ua.get(ip)
    if (prev and prev[0] != rec["ua"] and now - prev[1] <= UA_CHANGE_WINDOW
            and rec["ua"] not in ("", "-")
            and should_fire(st, ip, "User-Agent Change", now, UA_CHANGE_WINDOW)):
        add("User-Agent Change", "LOW",
            "The same IP switched user agent within %d seconds, which can hide a scanner." % UA_CHANGE_WINDOW,
            "Compare both user agents and check the IP's other requests.")
    st.last_ua[ip] = (rec["ua"], now)
    return out


# =====================================================================
# Reporting
# =====================================================================
class Reporter:
    def __init__(self, path, mode, json_on):
        self.path = path
        self.fh = open(path, mode, encoding="utf-8", errors="replace")
        self.jpath = os.path.splitext(path)[0] + ".jsonl" if json_on else None
        self.jfh = open(self.jpath, mode, encoding="utf-8", errors="replace") if json_on else None
        self.color = sys.stdout.isatty()

    def text(self, s):
        self.fh.write(s + "\n")
        self.fh.flush()

    def json(self, obj):
        if self.jfh:
            self.jfh.write(json.dumps(obj, default=str) + "\n")
            self.jfh.flush()

    def close(self):
        for h in (self.fh, self.jfh):
            if h:
                try:
                    h.close()
                except OSError:
                    pass


def write_report(rep, entry):
    """Write one finding (full entry or repeat note) to the text file and JSONL."""
    if entry["type"] == "finding":
        rep.text("=" * 72)
        rep.text("[%s] %s | %s" % (entry["severity"], entry["rule"], entry["source_ip"]))
        rep.text("Detected at : %s" % entry["detected_at"])
        rep.text("Log time    : %s" % entry["log_time"])
        rep.text("Source IP   : %s" % entry["source_ip"])
        rep.text("Request     : %s %s" % (entry["method"], clean(entry["url"], MAX_URL_IN_REPORT)))
        rep.text("Status/Size : %s / %s bytes" % (entry["status"], entry["size"]))
        rep.text("User-Agent  : %s" % clean(entry["user_agent"], 300))
        rep.text("Why         : %s" % entry["why"])
        rep.text("Action      : %s" % entry["action"])
    else:
        rep.text("-- REPEAT [%s] %s from %s: %d hits so far (last log time %s)" % (
            entry["severity"], entry["rule"], entry["source_ip"], entry["count"], entry["log_time"]))
    rep.json(entry)


POPUP_ENABLED = False
POPUP_MIN_GAP = 10          # seconds between popups (avoids popup spam)
_last_popup = 0.0


def popup(title, message, severity):
    """Desktop notification via notify-send. Works even when started with sudo."""
    global _last_popup
    if not POPUP_ENABLED or time.time() - _last_popup < POPUP_MIN_GAP:
        return
    _last_popup = time.time()
    urgency = "critical" if severity == "CRITICAL" else "normal"
    cmd = ["notify-send", "-u", urgency, title, message]
    user = os.environ.get("SUDO_USER")
    if user and os.geteuid() == 0:
        try:
            uid = pwd.getpwnam(user).pw_uid
            cmd = ["sudo", "-u", user, "env", "DISPLAY=:0",
                   "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus" % uid] + cmd
        except KeyError:
            pass
    try:
        subprocess.run(cmd, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        pass
def terminal_alert(rep, entry):
    """Short colored alert, HIGH and CRITICAL only."""
    if entry["severity"] not in COLORS:
        return
    tag = "[%s]" % entry["severity"]
    if rep.color:
        tag = COLORS[entry["severity"]] + tag + RESET
    extra = "" if entry["type"] == "finding" else " (x%d)" % entry["count"]
    print("%s %s%s  ip=%s  %s %s" % (tag, entry["rule"], extra, entry["source_ip"],
                                    entry["method"], clean(entry["url"], 80)))
    popup("SOC Alert: %s" % entry["severity"],
          "%s from %s" % (entry["rule"], entry["source_ip"]), entry["severity"])

def record_finding(st, rep, rec, f):
    """Count the finding; write the first hit fully and group later repeats."""
    ip, rule, sev = rec["ip"], f["rule"], f["severity"]
    st.sev[sev] += 1
    st.ip_hits[ip] += 1
    st.rule_hits[rule] += 1
    st.timeline[rec["ts"].strftime("%Y-%m-%d %H:00")] += 1
    base = dict(severity=sev, rule=rule, source_ip=ip, method=rec["method"], url=rec["url"],
                status=rec["status"], size=rec["size"], user_agent=rec["ua"],
                log_time=rec["ts"].strftime("%Y-%m-%d %H:%M:%S %z"), detected_at=now_str())
    key = (ip, rule)
    g = st.groups.get(key)
    if g is None:
        st.groups[key] = dict(count=1, first=base["log_time"], last=base["log_time"],
                              sev=sev, sample=rec["url"][:200])
        entry = dict(base, type="finding", why=f["why"], action=f["action"])
        write_report(rep, entry)
        terminal_alert(rep, entry)
    else:
        g["count"] += 1
        g["last"] = base["log_time"]
        if SEVERITIES.index(sev) > SEVERITIES.index(g["sev"]):
            g["sev"] = sev
        if g["count"] in REPEAT_MILESTONES:
            entry = dict(base, type="repeat", count=g["count"])
            write_report(rep, entry)
            terminal_alert(rep, entry)


def write_summary(rep, st):
    """Final summary: totals, top IPs, top attack types, grouped repeats, timeline."""
    total = sum(st.sev.values())
    rep.text("")
    rep.text("#" * 72)
    rep.text("SUMMARY  (started %s, finished %s)" % (st.started, now_str()))
    rep.text("#" * 72)
    rep.text("Lines analyzed      : %d" % st.lines)
    rep.text("Malformed lines     : %d" % st.malformed)
    rep.text("Whitelisted skipped : %d" % st.whitelisted)
    rep.text("Total findings      : %d" % total)
    for s in reversed(SEVERITIES):
        rep.text("  %-9s: %d" % (s, st.sev.get(s, 0)))
    rep.text("")
    rep.text("Top 10 attacker IPs:")
    for ip, c in st.ip_hits.most_common(10) or [("none", 0)]:
        rep.text("  %-40s %d findings" % (ip, c))
    rep.text("")
    rep.text("Top attack types:")
    for r, c in st.rule_hits.most_common(10) or [("none", 0)]:
        rep.text("  %-45s %d" % (r, c))
    rep.text("")
    rep.text("Grouped repeat hits (same IP + same rule, 2+ hits):")
    reps = sorted(((k, g) for k, g in st.groups.items() if g["count"] > 1),
                  key=lambda kg: kg[1]["count"], reverse=True)
    if not reps:
        rep.text("  none")
    for (ip, rule), g in reps[:50]:
        rep.text("  [%s] %s from %s: %d hits, %s -> %s" % (g["sev"], rule, ip, g["count"], g["first"], g["last"]))
        rep.text("      sample: %s" % clean(g["sample"], 120))
    rep.text("")
    rep.text("Timeline (findings per hour):")
    for hour in sorted(st.timeline)[-200:]:
        rep.text("  %s  %-6d %s" % (hour, st.timeline[hour], "#" * min(40, st.timeline[hour])))
    if not st.timeline:
        rep.text("  no findings")
    rep.json(dict(type="summary", lines=st.lines, malformed=st.malformed, findings=total,
                  by_severity=dict(st.sev), top_ips=st.ip_hits.most_common(10),
                  top_rules=st.rule_hits.most_common(10), timeline=dict(st.timeline),
                  finished=now_str()))


# =====================================================================
# Processing
# =====================================================================
def parse_whitelist(text):
    nets = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part or part.lower() == "none":
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            print("Warning: ignoring invalid whitelist entry '%s'" % part)
    return nets


def is_whitelisted(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def process_line(line, st, rep, nets):
    """Parse, filter, analyze one log line and record findings."""
    st.lines += 1
    rec = parse_line(line)
    if rec is None:
        if line.strip():
            st.malformed += 1
        return
    if rec["malformed"]:
        st.malformed += 1
    if is_whitelisted(rec["ip"], nets):
        st.whitelisted += 1
        return
    rec["epoch"] = rec["ts"].timestamp()
    rec["dec_url"] = decode(rec["url"])
    rec["dec_ua"] = decode(rec["ua"])
    rec["dec_ref"] = decode(rec["ref"])
    st.latest = max(st.latest, rec["epoch"])
    for f in run_rules(rec, st):
        record_finding(st, rep, rec, f)
    if st.lines % CLEANUP_EVERY_LINES == 0:
        cleanup(st, st.latest)


def analyze_once(path, st, rep, nets):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            process_line(line, st, rep, nets)
    if st.lines == 0:
        print("The log file is empty. Nothing to analyze.")


def monitor_live(path, st, rep, nets):
    """Like tail -f. Reopens the file if it is rotated (new inode) or truncated."""
    print("Live monitoring started. Press Ctrl+C to stop and write the summary.")
    fh = open(path, "r", encoding="utf-8", errors="replace")
    fh.seek(0, os.SEEK_END)
    inode = os.fstat(fh.fileno()).st_ino
    buf, last_clean = "", time.time()
    try:
        while True:
            line = fh.readline()
            if line:
                buf += line
                if buf.endswith("\n"):
                    process_line(buf, st, rep, nets)
                    buf = ""
                continue
            time.sleep(LIVE_POLL_SECONDS)
            if time.time() - last_clean > 60:
                cleanup(st, max(st.latest, time.time()))
                last_clean = time.time()
            try:
                s = os.stat(path)
            except OSError:
                continue                     # file briefly missing during rotation
            if s.st_ino != inode or s.st_size < fh.tell():
                fh.close()
                try:
                    fh = open(path, "r", encoding="utf-8", errors="replace")
                except OSError:
                    continue
                inode = os.fstat(fh.fileno()).st_ino
                buf = ""
                print("Log rotation detected - reopened %s" % path)
    finally:
        fh.close()


# =====================================================================
# Interactive startup
# =====================================================================
def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def choose_output(args):
    """Ask for the report file; handle default name and existing files."""
    name = args.out if args.out else ask("Enter the output file name to save the report: ")
    while True:
        if not name:
            name = "soc_report_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S")
        if not os.path.exists(name):
            return name, "w"
        c = ask("'%s' already exists. [a]ppend, [o]verwrite or [n]ew name? " % name).lower()
        if c.startswith("a"):
            return name, "a"
        if c.startswith("o"):
            return name, "w"
        name = ask("Enter a new output file name: ")


def check_log(path):
    if not os.path.exists(path):
        return "Log file not found: %s\n  Fix: check the path, or use --log /path/to/access.log" % path
    if os.path.isdir(path):
        return "%s is a directory, not a file." % path
    if not os.access(path, os.R_OK):
        return ("Permission denied reading %s\n  Fix: run with sudo, or add your user to the adm group:\n"
                "       sudo usermod -aG adm $USER   (then log out and back in)" % path)
    try:
        with open(path, "r"):
            pass
    except OSError as e:
        return "Cannot open %s: %s" % (path, e)
    return None


def choose_mode(args):
    if args.mode:
        return args.mode
    while True:
        c = ask("Choose: (a) analyze existing log once, (b) monitor live [a/b]: ").lower()
        if c in ("a", "once"):
            return "once"
        if c in ("b", "live"):
            return "live"
        print("Please type a or b.")


def banner():
    print("=" * 60)
    print("  SOC Analyst - Apache Access Log Monitor (read-only)")
    print("  Defensive use on your own authorized lab only")
    print("=" * 60)


def main():
    ap = argparse.ArgumentParser(description="Read-only SOC-style Apache access log analyzer.")
    ap.add_argument("--log", default=DEFAULT_LOG, help="path to access log (default %(default)s)")
    ap.add_argument("--out", help="report file name (skips the question)")
    ap.add_argument("--mode", choices=["once", "live"], help="analyze once or monitor live")
    ap.add_argument("--json", action="store_true", help="also write JSON Lines (.jsonl) next to the report")
    ap.add_argument("--whitelist", default=DEFAULT_WHITELIST,
                    help="comma separated IPs/CIDRs to ignore; 'none' for no whitelist (default %(default)s)")
    ap.add_argument("--popup", action="store_true", help="show desktop popups for HIGH/CRITICAL")
    args = ap.parse_args()
    global POPUP_ENABLED
    POPUP_ENABLED = args.popup

    banner()
    out_path, out_mode = choose_output(args)
    err = check_log(args.log)
    if err:
        print("ERROR: " + err)
        return 1
    mode = choose_mode(args)
    nets = parse_whitelist(args.whitelist)

    try:
        rep = Reporter(out_path, out_mode, args.json)
    except OSError as e:
        print("ERROR: cannot write report file '%s': %s" % (out_path, e))
        return 1
    rep.text("SOC ANALYST REPORT - log: %s - mode: %s - started: %s" % (args.log, mode, now_str()))
    print("Report file: %s%s" % (out_path, " (+ %s)" % rep.jpath if rep.jpath else ""))

    st = State()
    try:
        if mode == "once":
            analyze_once(args.log, st, rep, nets)
        else:
            monitor_live(args.log, st, rep, nets)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except PermissionError:
        print("ERROR: lost permission to read the log. Try running with sudo.")
    except OSError as e:
        print("ERROR: %s" % e)
    finally:
        write_summary(rep, st)
        rep.close()
        total = sum(st.sev.values())
        print("Done. Lines: %d | Findings: %d (CRITICAL %d, HIGH %d, MEDIUM %d, LOW %d)" % (
            st.lines, total, st.sev["CRITICAL"], st.sev["HIGH"], st.sev["MEDIUM"], st.sev["LOW"]))
        print("Report saved to %s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
