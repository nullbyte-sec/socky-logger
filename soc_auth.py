#!/usr/bin/env python3
"""
soc_auth.py - Read-only rules for /var/log/auth.log (SSH, sudo, su, user changes).
Used by soc_live.py. Standard library only. Never modifies any log.
"""
import re
from collections import deque
from datetime import datetime, timedelta

# =====================================================================
# CONFIG SECTION - edit thresholds here
# =====================================================================
SSH_BRUTE_COUNT, SSH_BRUTE_WINDOW = 50, 60        # failed SSH logins from one IP
SSH_SPRAY_USERS, SSH_SPRAY_WINDOW = 50, 60        # different usernames from one IP
SUCCESS_AFTER_FAILS, SUCCESS_WINDOW = 3, 300     # login OK after N failures
LOG_ALL_SUDO = False                             # True = also report normal sudo commands
ADMIN_GROUPS = {"sudo", "wheel", "admin", "root"}

SHELL_RE = re.compile(r"(?:^|/)(?:bash|sh|zsh|dash|ksh|su)(?:\s|$)", re.I)

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?) "
    r"(?P<host>\S+) (?P<proc>[^\s\[:]+)(?:\[\d+\])?: (?P<msg>.*)$")

FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+")
INVALID_RE = re.compile(r"Invalid user (?P<user>.*?) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
SCAN_RES = [re.compile(r"Did not receive identification string from (?P<ip>\S+)"),
            re.compile(r"Unable to negotiate with (?P<ip>\S+)"),
            re.compile(r"Connection from (?P<ip>\S+) port \d+.*invalid format")]
SUDO_CMD_RE = re.compile(r"^\s*(?P<user>\S+)\s*: (?:TTY=\S+ ; )?PWD=\S+ ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")
SUDO_FAIL_RE = re.compile(r"(?P<user>\S+)\s*: (?P<n>\d+) incorrect password attempts?")
SUDO_DENY_RE = re.compile(r"(?P<user>\S+)\s*: user NOT in sudoers")
SU_FAIL_RE = re.compile(r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+)")
NEWUSER_RE = re.compile(r"new user: name=(?P<user>[^,\s]+)")
GROUP_RES = [re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<grp>[^']+)'"),
             re.compile(r"user '?(?P<user>[^'\s]+)'? added by \S+ to group '?(?P<grp>[^'\s]+)'?")]
PASSWD_RE = re.compile(r"password changed for (?P<user>\S+)")


# =====================================================================
# Parsing
# =====================================================================
def _parse_ts(raw):
    """Handle classic syslog (no year) and ISO-8601 timestamps. Returns aware datetime."""
    try:
        if raw[:4].isdigit():
            raw = re.sub(r"\.\d+", "", raw).replace("Z", "+00:00")
            dt = datetime.fromisoformat(raw)
            return dt if dt.tzinfo else dt.astimezone()
        now = datetime.now()
        dt = datetime.strptime("%d %s" % (now.year, " ".join(raw.split())), "%Y %b %d %H:%M:%S")
        if dt > now + timedelta(days=1):            # December log read in January
            dt = dt.replace(year=now.year - 1)
        return dt.astimezone()
    except ValueError:
        return None


def parse_auth_line(line):
    """Return dict(ts, host, proc, msg) or None if the line is not usable."""
    m = SYSLOG_RE.match(line.rstrip("\r\n"))
    if not m:
        return None
    ts = _parse_ts(m.group("ts"))
    if ts is None:
        return None
    return dict(ts=ts, host=m.group("host"), proc=m.group("proc"), msg=m.group("msg"))


# =====================================================================
# Sliding windows (kept on the State object so memory stays low)
# =====================================================================
def _init(st):
    if not hasattr(st, "aw"):
        st.aw = {"fail": {}, "users": {}}
        st.acool = {}


def _win(store, key, now, span, item=None, add=True):
    dq = store.setdefault(key, deque(maxlen=2000))
    if add:
        dq.append((now, item))
    while dq and now - dq[0][0] > span:
        dq.popleft()
    return dq


def _fire(st, key, now, span):
    last = st.acool.get(key)
    if last is not None and 0 <= now - last < span:
        return False
    st.acool[key] = now
    return True


def cleanup_auth(st, now):
    """Drop idle IPs and old cooldowns."""
    if not hasattr(st, "aw"):
        return
    for store in st.aw.values():
        for k in list(store):
            dq = store[k]
            while dq and now - dq[0][0] > 300:
                dq.popleft()
            if not dq:
                del store[k]
    for k in [k for k, t in st.acool.items() if now - t > 3600]:
        del st.acool[k]


def _rec(ev, ip, method, detail, user="-"):
    """Build a record shaped like the access-log record so reporting code can be reused."""
    return dict(ip=ip, ts=ev["ts"], epoch=ev["ts"].timestamp(), method=method,
                url=detail[:300], status=0, size=0, ref="-", ua="user=%s" % user, malformed=False)


# =====================================================================
# Rules
# =====================================================================
def analyze(ev, st):
    """Return (rec, findings) for one parsed auth event, or None if nothing to report."""
    _init(st)
    proc, msg, now = ev["proc"], ev["msg"], ev["ts"].timestamp()
    out, rec = [], None

    def add(rule, sev, why, action):
        out.append(dict(rule="AUTH: " + rule, severity=sev, why=why, action=action))

    def track_user(ip, user):
        ud = _win(st.aw["users"], ip, now, SSH_SPRAY_WINDOW, item=user)
        distinct = len({u for _, u in ud})
        if distinct >= SSH_SPRAY_USERS and _fire(st, (ip, "spray"), now, SSH_SPRAY_WINDOW):
            add("SSH User Enumeration / Spray", "HIGH",
                "%d different usernames tried from one IP in %d seconds." % (distinct, SSH_SPRAY_WINDOW),
                "Block the IP, disable password login for SSH, and use key-based login.")

    if proc.startswith("sshd"):
        m = FAILED_RE.search(msg)
        if m:
            user, ip = m.group("user"), m.group("ip")
            rec = _rec(ev, ip, "SSH", msg, user)
            dq = _win(st.aw["fail"], ip, now, SUCCESS_WINDOW)
            recent = sum(1 for t, _ in dq if now - t <= SSH_BRUTE_WINDOW)
            add("SSH Failed Login", "LOW", "A failed SSH login for user '%s'." % user,
                "Watch this IP; use key-based login and fail2ban.")
            if recent >= SSH_BRUTE_COUNT and _fire(st, (ip, "brute"), now, SSH_BRUTE_WINDOW):
                add("SSH Brute Force", "HIGH",
                    "%d failed SSH logins in %d seconds from one IP." % (recent, SSH_BRUTE_WINDOW),
                    "Block the IP in the firewall, disable password login, install fail2ban.")
            if user == "root":
                add("Root Login Attempt", "MEDIUM", "Someone tried to log in as root over SSH.",
                    "Set PermitRootLogin no in /etc/ssh/sshd_config.")
            track_user(ip, user)
        else:
            m = INVALID_RE.search(msg)
            if m:
                ip, user = m.group("ip"), m.group("user")
                rec = _rec(ev, ip, "SSH", msg, user)
                add("SSH Invalid User", "LOW", "Login attempt for a user that does not exist: '%s'." % user,
                    "Watch this IP for user guessing.")
                track_user(ip, user)
            else:
                m = ACCEPTED_RE.search(msg)
                if m:
                    user, ip = m.group("user"), m.group("ip")
                    rec = _rec(ev, ip, "SSH", msg, user)
                    dq = _win(st.aw["fail"], ip, now, SUCCESS_WINDOW, add=False)
                    if len(dq) >= SUCCESS_AFTER_FAILS:
                        add("SSH Login After Failures", "CRITICAL",
                            "A login for '%s' succeeded right after %d failures from the same IP - possible compromise."
                            % (user, len(dq)),
                            "Check that account now: run 'last', 'w', change its password, review ~/.ssh/authorized_keys.")
                        dq.clear()
                    if user == "root":
                        add("Root SSH Login", "HIGH", "Root logged in directly over SSH.",
                            "Disable root SSH login and use sudo from a normal user.")
                else:
                    for rx in SCAN_RES:
                        m = rx.search(msg)
                        if m:
                            rec = _rec(ev, m.group("ip"), "SSH", msg)
                            add("SSH Scan / Odd Connection", "LOW",
                                "A client connected to SSH but did not speak normal SSH, typical of port scanners.",
                                "Check this IP for scanning; restrict SSH by firewall.")
                            break
    elif proc == "sudo":
        m = SUDO_DENY_RE.search(msg)
        if m:
            rec = _rec(ev, "local", "SUDO", msg, m.group("user"))
            add("Sudo Without Permission", "HIGH", "User '%s' tried sudo but is not allowed." % m.group("user"),
                "Check whether that user should have access; review who is logged in.")
        else:
            m = SUDO_FAIL_RE.search(msg)
            if m:
                rec = _rec(ev, "local", "SUDO", msg, m.group("user"))
                add("Sudo Password Failures", "MEDIUM",
                    "%s wrong sudo passwords by '%s'." % (m.group("n"), m.group("user")),
                    "Confirm it was you; otherwise check for an intruder session.")
            else:
                m = SUDO_CMD_RE.search(msg)
                if m:
                    rec = _rec(ev, "local", "SUDO", "%s -> %s: %s" % (m.group("user"), m.group("target"), m.group("cmd")),
                               m.group("user"))
                    if SHELL_RE.search(m.group("cmd")):
                        add("Root Shell via Sudo", "MEDIUM", "A root shell was opened with sudo.",
                            "Confirm it was expected.")
                    elif LOG_ALL_SUDO:
                        add("Sudo Command", "LOW", "A command was run with sudo.", "Review if unexpected.")
    elif proc == "su":
        m = SU_FAIL_RE.search(msg)
        if m:
            rec = _rec(ev, "local", "SU", msg, m.group("user"))
            add("Failed su", "MEDIUM", "Failed switch to '%s' by '%s'." % (m.group("target"), m.group("user")),
                "Confirm it was you.")
    elif proc in ("useradd", "adduser"):
        m = NEWUSER_RE.search(msg)
        if m:
            rec = _rec(ev, "local", "USER", msg, m.group("user"))
            add("New User Created", "HIGH", "A new account '%s' was created." % m.group("user"),
                "Confirm you created it; attackers add users for persistence.")
    elif proc in ("usermod", "gpasswd", "groupadd"):
        for rx in GROUP_RES:
            m = rx.search(msg)
            if m and m.group("grp") in ADMIN_GROUPS:
                rec = _rec(ev, "local", "USER", msg, m.group("user"))
                add("User Added to Admin Group", "HIGH",
                    "'%s' was added to the '%s' group." % (m.group("user"), m.group("grp")),
                    "Confirm this was intended; remove if not.")
                break
    elif proc in ("passwd", "chpasswd"):
        m = PASSWD_RE.search(msg)
        if m:
            rec = _rec(ev, "local", "USER", msg, m.group("user"))
            add("Password Changed", "MEDIUM", "Password changed for '%s'." % m.group("user"),
                "Confirm it was you.")
    return (rec, out) if rec and out else None


def process_auth_line(line, st, rep, nets, record, is_white, post=None):
    """Parse one auth.log line and record any findings.
    record  = function(st, rep, rec, finding)  (soc_analyst.record_finding)
    is_white = function(ip, nets)              (soc_analyst.is_whitelisted)
    post    = optional function(findings, rec) (soc_analyst.apply_health)"""
    st.lines += 1
    ev = parse_auth_line(line)
    if ev is None:
        if line.strip():
            st.malformed += 1
        return
    res = analyze(ev, st)
    if res is None:
        return
    rec, findings = res
    if rec["ip"] != "local" and is_white(rec["ip"], nets):
        st.whitelisted += 1
        return
    st.latest = max(getattr(st, "latest", 0.0), rec["epoch"])
    if post:
        post(findings, rec)
    for f in findings:
        record(st, rep, rec, f)
