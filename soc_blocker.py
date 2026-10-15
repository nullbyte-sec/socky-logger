#!/usr/bin/env python3
"""
soc_blocker.py - Optional IP blocking for Socky Logger (UFW recommended, iptables also supported).

OFF unless you start soc_live.py with --blocker.
It NEVER blocks on its own: you are asked Yes/No for each IP.
Blocks remove themselves: 1st block = 1 day, then 3 days, 7 days, 30 days, and 1 year from the 5th block on.
Needs root (run with sudo). Standard library only.
"""
import html
import ipaddress
import json
import os
import pwd
import queue
import shutil
import subprocess
import threading
import time
from collections import deque
from datetime import datetime

# =====================================================================
# CONFIG SECTION
# =====================================================================
BLOCK_LADDER_DAYS = [1, 3, 7, 30, 365]    # 1st, 2nd, 3rd, 4th, 5th+ block (365 = 1 year)
HIGH_REPEAT_COUNT, HIGH_REPEAT_WINDOW = 3, 300   # HIGH findings needed from one IP (seconds window)
# CRITICAL findings ask immediately.
NO_COOLDOWN = 1800            # after you click "No", do not ask about that IP again for 30 min
TIMEOUT_COOLDOWN = 600        # popup ignored for POPUP_TIMEOUT seconds -> ask again after 10 min
POPUP_TIMEOUT = 120
EXPIRY_CHECK_SECONDS = 30
DEFAULT_STATE = "/var/lib/socky-logger/blocks.json"
RULE_COMMENT = "socky-logger"


def days_label(d):
    return "1 year" if d >= 365 else "%d day%s" % (d, "" if d == 1 else "s")


def ordinal(n):
    return {1: "1st", 2: "2nd", 3: "3rd"}.get(n, "%dth" % n)


def norm_ip(ip):
    ip = str(ip).strip().strip("[]")
    if ip.lower().startswith("::ffff:") and "." in ip:
        ip = ip[7:]
    return ip


class Blocker:
    def __init__(self, firewall="ufw", state_path=DEFAULT_STATE, prompt="auto", nets=None,
                 protect=(), dry_run=False, log=None, runner=None):
        self.fw = firewall
        self.dry = dry_run
        self.nets = nets or []
        self.extra_protect = {norm_ip(p) for p in protect}
        self.log_cb = log or (lambda m: None)
        self.events = deque(maxlen=50)
        self.runner = runner
        self.enabled, self.disabled_reason = True, ""
        self.state_path = self._pick_state_path(state_path)
        self.state = self._load()
        self.high_hits, self.no_until, self.reasons = {}, {}, {}
        self.queued = set()
        self.pending = deque()        # (ip, text) waiting for a terminal y/n answer
        self.waiting = deque()        # (ip, text) waiting for a GUI popup
        self.answers = queue.Queue()
        self.gui_busy = False
        self.last_expiry = 0.0
        self._prot = (0.0, set())
        self.mode = self._pick_mode(prompt)
        self._check_firewall()

    # ---------------- helpers ----------------
    def _log(self, msg):
        self.events.append((time.strftime("%H:%M:%S"), msg))
        self.log_cb("[BLOCKER] " + msg)

    def _run(self, cmd, mutate=False):
        """Run a command. With dry_run, commands that change the firewall are only logged."""
        if mutate and self.dry:
            self._log("[dry-run] " + " ".join(cmd))
            return 0, ""
        if self.runner:
            return self.runner(cmd)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except FileNotFoundError:
            return 127, "command not found: %s" % cmd[0]
        except subprocess.TimeoutExpired:
            return 124, "timeout"

    def _pick_state_path(self, path):
        if self.dry:
            path += ".dryrun"
        folder = os.path.dirname(path) or "."
        try:
            os.makedirs(folder, exist_ok=True)
            if os.access(folder, os.W_OK):
                return path
        except OSError:
            pass
        fallback = os.path.join(os.getcwd(), "socky_blocks.json" + (".dryrun" if self.dry else ""))
        self._log("cannot write %s, using %s instead" % (path, fallback))
        return fallback

    def _load(self):
        try:
            with open(self.state_path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self):
        tmp = self.state_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(self.state, f, indent=1)
            os.replace(tmp, self.state_path)
        except OSError as e:
            self._log("WARNING: cannot save block state: %s" % e)

    def _pick_mode(self, prompt):
        have_gui = bool(shutil.which("zenity")) and bool(os.environ.get("DISPLAY") or os.environ.get("SUDO_USER"))
        if prompt == "gui" and not shutil.which("zenity"):
            self._log("zenity not installed (sudo apt install zenity); using terminal prompts")
            return "terminal"
        if prompt in ("gui", "terminal"):
            return prompt
        return "gui" if have_gui else "terminal"

    def _check_firewall(self):
        if self.dry:
            return
        if os.geteuid() != 0 and self.runner is None:
            self.enabled, self.disabled_reason = False, "needs root (run with sudo)"
            return
        tool = "ufw" if self.fw == "ufw" else "iptables"
        if self.runner is None and not shutil.which(tool):
            self.enabled, self.disabled_reason = False, "%s is not installed" % tool
            return
        if self.fw == "ufw":
            rc, out = self._run(["ufw", "status"])
            if "inactive" in out.lower():
                self.enabled = False
                self.disabled_reason = "ufw is inactive (allow SSH first: sudo ufw allow 22/tcp; then sudo ufw enable)"

    # ---------------- protection ----------------
    def protected_ips(self):
        """IPs that must never be blocked: this machine, gateway, DNS, current SSH sessions."""
        t, s = self._prot
        if s and time.time() - t < 60:
            return s
        ips = set(self.extra_protect) | {"127.0.0.1", "::1"}
        rc, out = self._run(["hostname", "-I"])
        if rc == 0:
            ips |= {norm_ip(x) for x in out.split()}
        rc, out = self._run(["ip", "route", "show", "default"])
        if rc == 0:
            for line in out.splitlines():
                tok = line.split()
                if "via" in tok and tok.index("via") + 1 < len(tok):
                    ips.add(norm_ip(tok[tok.index("via") + 1]))
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        ips.add(norm_ip(parts[1]))
        except OSError:
            pass
        rc, out = self._run(["ss", "-tnH"])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3].rsplit(":", 1)[-1] == "22":
                    ips.add(norm_ip(parts[4].rsplit(":", 1)[0]))
        for env in ("SSH_CONNECTION", "SSH_CLIENT"):
            if os.environ.get(env):
                ips.add(norm_ip(os.environ[env].split()[0]))
        self._prot = (time.time(), ips)
        return ips

    def is_protected(self, ip):
        try:
            a = ipaddress.ip_address(norm_ip(ip))
        except ValueError:
            return True                       # not a real IP (for example "local")
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            return True
        if any(a in n for n in self.nets):
            return True
        return norm_ip(ip) in self.protected_ips()

    # ---------------- deciding and asking ----------------
    def observe(self, rec, finding):
        """Call for every finding. Decides whether to ask you about blocking this IP."""
        if not self.enabled:
            return
        sev = finding["severity"]
        if sev not in ("HIGH", "CRITICAL"):
            return
        ip = norm_ip(rec["ip"])
        now = time.time()
        if ip in self.queued or self.no_until.get(ip, 0) > now:
            return
        if self.state.get(ip, {}).get("blocked_until", 0) > now:
            return
        if self.is_protected(ip):
            return
        if sev == "HIGH":
            dq = self.high_hits.setdefault(ip, deque(maxlen=50))
            dq.append(now)
            while dq and now - dq[0] > HIGH_REPEAT_WINDOW:
                dq.popleft()
            if len(dq) < HIGH_REPEAT_COUNT:
                return
        count = self.state.get(ip, {}).get("count", 0)
        days = BLOCK_LADDER_DAYS[min(count, len(BLOCK_LADDER_DAYS) - 1)]
        text = ("IP %s is malicious or attacking your device.\nReason: %s - %s\n\n"
                "Do you want to block this IP for %s (%s time it is blocked)?"
                % (ip, sev, finding["rule"], days_label(days), ordinal(count + 1)))
        self.queued.add(ip)
        self.reasons[ip] = "%s: %s" % (sev, finding["rule"])
        (self.pending if self.mode == "terminal" else self.waiting).append((ip, text))

    def answer(self, yes):
        """Answer the oldest terminal prompt."""
        if self.pending:
            ip, _ = self.pending.popleft()
            self._apply(ip, bool(yes))

    def _apply(self, ip, ans):
        self.queued.discard(ip)
        reason = self.reasons.pop(ip, "")
        if ans is True:
            self.block(ip, reason)
        else:
            self.no_until[ip] = time.time() + (TIMEOUT_COOLDOWN if ans == "timeout" else NO_COOLDOWN)
            self._log("not blocking %s (%s)" % (ip, "no answer" if ans == "timeout" else "you chose No"))

    def tick(self, now=None):
        """Call often: handles expiry, finished popups and starts the next popup."""
        now = now or time.time()
        if now - self.last_expiry >= EXPIRY_CHECK_SECONDS:
            self.last_expiry = now
            self.cleanup_expired(now)
        while not self.answers.empty():
            ip, ans, text = self.answers.get_nowait()
            self.gui_busy = False
            if ans == "error":
                self._log("popup failed (no desktop session?), asking in the terminal instead")
                self.pending.append((ip, text))
            else:
                self._apply(ip, ans)
        if self.mode == "gui" and not self.gui_busy and self.waiting:
            ip, text = self.waiting.popleft()
            self.gui_busy = True
            threading.Thread(target=self._gui_worker, args=(ip, text), daemon=True).start()

    def _gui_worker(self, ip, text):
        cmd = ["zenity", "--question", "--title=Socky Logger - malicious IP", "--text=" + html.escape(text),
               "--ok-label=Block IP", "--cancel-label=Do not block", "--width=460",
               "--timeout=%d" % POPUP_TIMEOUT]
        user = os.environ.get("SUDO_USER")
        if os.geteuid() == 0 and user and user != "root":
            try:
                home = pwd.getpwnam(user).pw_dir
                cmd = ["sudo", "-u", user, "env", "DISPLAY=" + os.environ.get("DISPLAY", ":0"),
                       "XAUTHORITY=" + os.path.join(home, ".Xauthority")] + cmd
            except KeyError:
                pass
        try:
            rc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=POPUP_TIMEOUT + 15).returncode
        except (OSError, subprocess.SubprocessError):
            rc = -1
        ans = True if rc == 0 else False if rc == 1 else "timeout" if rc == 5 else "error"
        self.answers.put((ip, ans, text))

    # ---------------- firewall actions ----------------
    def _fw_block(self, ip):
        v6 = ":" in ip
        if self.fw == "ufw":
            if v6:
                cmd = ["ufw", "prepend", "deny", "from", ip, "to", "any", "comment", RULE_COMMENT]
            else:
                cmd = ["ufw", "insert", "1", "deny", "from", ip, "to", "any", "comment", RULE_COMMENT]
            rc, out = self._run(cmd, True)
            if rc != 0 and ("position" in out.lower() or "invalid" in out.lower()):
                rc, out = self._run(["ufw", "deny", "from", ip, "to", "any", "comment", RULE_COMMENT], True)
            return rc == 0, out.strip()
        ipt = "ip6tables" if v6 else "iptables"
        rc, _ = self._run([ipt, "-C", "INPUT", "-s", ip, "-j", "DROP"])
        if rc == 0:
            return True, "already present"
        rc, out = self._run([ipt, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], True)
        return rc == 0, out.strip()

    def _fw_unblock(self, ip):
        if self.fw == "ufw":
            rc, out = self._run(["ufw", "--force", "delete", "deny", "from", ip, "to", "any"], True)
        else:
            ipt = "ip6tables" if ":" in ip else "iptables"
            rc, out = self._run([ipt, "-D", "INPUT", "-s", ip, "-j", "DROP"], True)
        return rc == 0 or "non-existent" in out.lower() or "no chain/target/match" in out.lower(), out.strip()

    def block(self, ip, reason=""):
        ip = norm_ip(ip)
        if self.is_protected(ip):
            self._log("refused to block protected IP %s" % ip)
            return False
        now = time.time()
        ent = self.state.setdefault(ip, dict(count=0, blocked_until=0, first=now, history=[]))
        if ent.get("blocked_until", 0) > now:
            self._log("%s is already blocked" % ip)
            return True
        days = BLOCK_LADDER_DAYS[min(ent["count"], len(BLOCK_LADDER_DAYS) - 1)]
        until = now + days * 86400
        ok, msg = self._fw_block(ip)
        if not ok:
            self._log("FAILED to block %s: %s" % (ip, msg))
            return False
        ent["count"] += 1
        ent["blocked_until"], ent["last"] = until, now
        ent["history"] = (ent["history"] + [dict(at=now, days=days, reason=reason)])[-20:]
        self._save()
        self._log("BLOCKED %s for %s (%s time) until %s. %s" % (
            ip, days_label(days), ordinal(ent["count"]),
            datetime.fromtimestamp(until).strftime("%Y-%m-%d %H:%M"), reason))
        return True

    def unblock(self, ip, why="manual"):
        ip = norm_ip(ip)
        ok, msg = self._fw_unblock(ip)
        ent = self.state.setdefault(ip, dict(count=0, blocked_until=0, first=time.time(), history=[]))
        if ok:
            ent["blocked_until"] = 0
            ent.pop("retry_after", None)
            self._save()
            self._log("UNBLOCKED %s (%s)" % (ip, why))
        else:
            ent["retry_after"] = time.time() + 300
            self._save()
            self._log("FAILED to unblock %s: %s (will retry in 5 minutes)" % (ip, msg))
        return ok

    def cleanup_expired(self, now=None):
        """Remove every block whose time is over. Also run at start-up and by --blocker-cleanup."""
        now = now or time.time()
        n = 0
        for ip, ent in list(self.state.items()):
            until = ent.get("blocked_until", 0)
            if until and until <= now and ent.get("retry_after", 0) <= now:
                n += 1 if self.unblock(ip, "block expired") else 0
        return n

    # ---------------- info ----------------
    def active_blocks(self):
        now = time.time()
        return {ip: e for ip, e in self.state.items() if e.get("blocked_until", 0) > now}

    def list_blocks(self):
        lines = []
        for ip, e in sorted(self.state.items()):
            until = e.get("blocked_until", 0)
            status = ("blocked until " + datetime.fromtimestamp(until).strftime("%Y-%m-%d %H:%M")
                      if until > time.time() else "not blocked")
            lines.append("%-40s blocked %d time(s) | %s" % (ip, e.get("count", 0), status))
        return lines

    def status_line(self):
        if not self.enabled:
            return "Blocker DISABLED: %s" % self.disabled_reason, False
        last = ("  | last: [%s] %s" % self.events[-1]) if self.events else ""
        return "Blocker: %s%s | %s prompts | blocked now: %d | waiting: %d%s" % (
            self.fw.upper(), " (DRY-RUN)" if self.dry else "", self.mode, len(self.active_blocks()),
            len(self.pending) + len(self.waiting), last), True
