#!/usr/bin/env python3
"""
soc_live.py - Live multi-log SOC dashboard (read-only). One pane per log file, shown as a grid.
Needs soc_analyst.py, soc_auth.py, soc_generic.py in the SAME folder.
Everything is saved to one report file (+ optional JSONL).

Examples:
  sudo python3 soc_live.py --list                      show which logs it would monitor
  sudo python3 soc_live.py --out report.txt            monitor the default set
  sudo python3 soc_live.py --all --out report.txt      every readable *.log in /var/log
  sudo python3 soc_live.py --logs /var/log/auth.log /var/log/syslog /var/log/kern.log:kern

Keys:
  Tab / Shift-Tab  next / previous pane      1-9  jump to pane N
  [  ]             previous / next page      m    maximize / restore focused pane
  Up / Down        select an alert (PgUp/PgDn = 10, n/Home = newest)
  Enter / d        inspect the selected alert in full (Esc closes)
  p                pause screen refresh      q    quit and save summary
"""
import argparse
import curses
import glob
import math
import os
import re
import sys
import textwrap
import time
from collections import deque

import soc_analyst as sa
import soc_auth
import soc_generic

LOG_DIR = "/var/log"
REFRESH_SECONDS = 0.5
MAX_LINES_PER_TICK = 2000
MAX_SOURCES = 24
KINDS = {"access", "auth", "syslog", "kern", "cron", "dpkg", "weberror", "mysql", "postgres", "generic"}

# Default set: (path relative to /var/log, kind). Globs allowed. Missing files are skipped.
DEFAULT_SOURCES = [
    ("apache2/access.log", "access"), ("nginx/access.log", "access"),
    ("apache2/other_vhosts_access.log", "access"),
    ("auth.log", "auth"), ("syslog", "syslog"), ("kern.log", "kern"),
    ("apache2/error.log", "weberror"), ("nginx/error.log", "weberror"),
    ("dpkg.log", "dpkg"), ("cron.log", "cron"),
    ("mysql/error.log", "mysql"), ("mariadb/mariadb.log", "mysql"), ("postgresql/*.log", "postgres"),
    ("redis/redis-server.log", "generic"), ("mosquitto/mosquitto.log", "generic"),
    ("openvpn/*.log", "generic"), ("lightdm/lightdm.log", "generic"),
]
# Skipped by --all because they are noisy or not security relevant (you can still pass them with --logs)
NOISY_RE = re.compile(r"vmware|boot\.log|Xorg|alternatives|fontconfig|macchanger|sysstat|speech|cups|bootstrap")
ROTATED_RE = re.compile(r"(?:\.\d+(?:\.gz)?|\.gz|\.old|\.xz|\.bz2)$")

CTX = {"src": None}


class Source:
    """One monitored log file = one pane."""

    def __init__(self, idx, path, kind):
        self.idx, self.path, self.kind = idx, path, kind
        parent = os.path.basename(os.path.dirname(path))
        self.name = ("%s/%s" % (parent, os.path.basename(path))) if parent and parent != "log" else os.path.basename(path)
        self.short = os.path.basename(path).replace(".log", "")[:10]
        self.st = sa.State()
        self.recent = deque(maxlen=200)
        self.sel = 0
        self.tail = None
        self.note = ""


def capture_alert(rep, entry):
    """Replaces sa.terminal_alert: store the full alert in the pane that produced it."""
    src = CTX["src"]
    item = dict(entry)
    item["t"] = time.strftime("%H:%M:%S")
    src.recent.append(item)
    if src.sel > 0:                              # keep a selected older alert in place
        src.sel = min(src.sel + 1, len(src.recent) - 1)
    popup = getattr(sa, "popup", None)           # exists only if you added the popup patch
    if popup and entry["severity"] in ("HIGH", "CRITICAL"):
        popup("SOC Alert: %s" % entry["severity"],
              "%s from %s" % (entry["rule"], entry["source_ip"]), entry["severity"])


sa.terminal_alert = capture_alert


class Tail:
    """Read-only tail -f that survives log rotation and truncation."""

    def __init__(self, path, from_end=True):
        self.path = path
        self.fh = open(path, "r", encoding="utf-8", errors="replace")
        if from_end:
            self.fh.seek(0, os.SEEK_END)
        self.inode = os.fstat(self.fh.fileno()).st_ino
        self.buf = ""
        self.rotations = 0

    def poll(self, maxlines=MAX_LINES_PER_TICK):
        out = []
        for _ in range(maxlines):
            line = self.fh.readline()
            if not line:
                break
            self.buf += line
            if self.buf.endswith("\n"):
                out.append(self.buf)
                self.buf = ""
        if not out:
            self.check_rotation()
        return out

    def check_rotation(self):
        try:
            s = os.stat(self.path)
        except OSError:
            return
        if s.st_ino != self.inode or s.st_size < self.fh.tell():
            try:
                new = open(self.path, "r", encoding="utf-8", errors="replace")
            except OSError:
                return
            self.fh.close()
            self.fh = new
            self.inode = os.fstat(new.fileno()).st_ino
            self.buf = ""
            self.rotations += 1

    def close(self):
        self.fh.close()


# =====================================================================
# Discovery
# =====================================================================
def guess_kind(path):
    p, name = path.lower(), os.path.basename(path).lower()
    if name.endswith(".log") and "access" in name:
        return "access"
    if name == "auth.log":
        return "auth"
    if name in ("syslog", "messages"):
        return "syslog"
    if name == "kern.log":
        return "kern"
    if name == "error.log" and ("apache" in p or "nginx" in p):
        return "weberror"
    if "dpkg" in name:
        return "dpkg"
    if "cron" in name:
        return "cron"
    if "mysql" in p or "mariadb" in p:
        return "mysql"
    if "postgres" in p:
        return "postgres"
    return "generic"


def discover(args):
    """Return a list of (path, kind) to monitor."""
    found, seen = [], set()

    def add(path, kind):
        real = os.path.realpath(path)
        if real in seen or not os.path.isfile(path):
            return
        seen.add(real)
        found.append((path, kind if kind in KINDS else "generic"))

    if args.logs:
        for item in args.logs:
            path, _, kind = item.partition(":")
            if os.path.exists(path):
                add(path, kind or guess_kind(path))
            else:
                print("Warning: %s does not exist, skipping." % path)
    else:
        for rel, kind in DEFAULT_SOURCES:
            for path in sorted(glob.glob(os.path.join(LOG_DIR, rel))):
                if not ROTATED_RE.search(path):
                    add(path, kind)
        if args.all:
            for pattern in ("*.log", "*/*.log"):
                for path in sorted(glob.glob(os.path.join(LOG_DIR, pattern))):
                    if not ROTATED_RE.search(path) and not NOISY_RE.search(path):
                        add(path, guess_kind(path))
    return found[:MAX_SOURCES]


# =====================================================================
# Drawing
# =====================================================================
def init_colors():
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    curses.init_pair(1, curses.COLOR_RED, bg)
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_RED)
    curses.init_pair(3, curses.COLOR_YELLOW, bg)
    curses.init_pair(4, curses.COLOR_CYAN, bg)
    curses.init_pair(5, curses.COLOR_GREEN, bg)
    return {"CRITICAL": curses.color_pair(2) | curses.A_BOLD,
            "HIGH": curses.color_pair(1) | curses.A_BOLD,
            "MEDIUM": curses.color_pair(3),
            "LOW": curses.color_pair(4),
            "OK": curses.color_pair(5)}


def make_put(scr):
    h, w = scr.getmaxyx()

    def put(y, x, text, attr=0):
        if 0 <= y < h and 0 <= x < w - 1:
            try:
                scr.addnstr(y, x, sa.clean(text), max(0, w - x - 1), attr)
            except curses.error:
                pass
    return put


def draw_pane(put, col, y0, x0, height, width, src, focused):
    """One pane: title, status, counters, top lists and a selectable alert list."""
    if height < 3 or width < 20:
        return

    def p(y, x, text, attr=0):
        put(y, x0 + x, str(text)[:max(0, width - x - 1)], attr)

    head = (" %s[%d] %s (%s) " % ("> " if focused else "  ", src.idx + 1, src.name, src.kind)).ljust(width - 1)
    p(y0, 0, head, curses.A_REVERSE | (curses.A_BOLD if focused else 0))
    if src.tail is None:
        for i, part in enumerate(textwrap.wrap(src.note, max(20, width - 2))[:max(1, height - 1)]):
            p(y0 + 1 + i, 0, part, col["MEDIUM"])
        return
    st = src.st
    p(y0 + 1, 0, "Lines %d | Bad %d | Rot %d" % (st.lines, st.malformed, src.tail.rotations), col["OK"])
    x = 0
    for s in reversed(sa.SEVERITIES):
        label = "%s %d" % (s[:4] if width < 60 else s, st.sev.get(s, 0))
        p(y0 + 2, x, label, col[s])
        x += len(label) + 2
    ips = ", ".join("%s(%d)" % kv for kv in st.ip_hits.most_common(2)) or "-"
    rules = ", ".join("%s(%d)" % kv for kv in st.rule_hits.most_common(1)) or "-"
    p(y0 + 3, 0, "IPs: %s | Top: %s" % (ips, rules))
    top, rows = y0 + 4, height - 4
    items = list(src.recent)[::-1]
    if not items:
        p(top, 0, "No findings yet - watching...", col["OK"])
        return
    start = max(0, src.sel - rows + 1)
    for i, e in enumerate(items[start:start + rows]):
        idx = start + i
        cnt = " x%d" % e["count"] if e.get("count", 1) > 1 else ""
        line = "%s [%-4s] %s%s | %s | %s" % (e["t"], e["severity"][:4], e["rule"], cnt, e["source_ip"], e["url"])
        attr = col[e["severity"]]
        sel = focused and idx == src.sel
        if sel:
            attr |= curses.A_REVERSE
        p(top + i, 0, line.ljust(width - 1) if sel else line, attr)


def draw_tabs(put, col, ctx):
    """Row of all sources with their finding counts, so activity on other pages is visible."""
    x = 0
    for s in ctx["sources"]:
        total = sum(s.st.sev.values())
        worst = next((v for v in reversed(sa.SEVERITIES) if s.st.sev.get(v, 0)), None)
        label = "[%d]%s:%d" % (s.idx + 1, s.short, total)
        attr = col[worst] if worst else col["OK"]
        if s.tail is None:
            attr = curses.A_DIM
        if s.idx == ctx["focus"]:
            attr |= curses.A_UNDERLINE | curses.A_BOLD
        put(2, x, label, attr)
        x += len(label) + 2


def draw_detail(scr, col, e):
    """Full-screen view of one alert."""
    scr.erase()
    h, w = scr.getmaxyx()
    put = make_put(scr)
    put(0, 0, " ALERT DETAIL ".ljust(w), curses.A_REVERSE)
    rows = [("Severity", e.get("severity", "")), ("Rule", e.get("rule", "")),
            ("Source IP", e.get("source_ip", "")), ("Log time", e.get("log_time") or e.get("t", "")),
            ("Request", "%s %s" % (e.get("method", ""), e.get("url", ""))),
            ("Status/Size", "%s / %s bytes" % (e.get("status", "-"), e.get("size", "-"))),
            ("User/Agent", e.get("user_agent", "-")), ("Hits", e.get("count", 1)),
            ("Why", e.get("why") or "(repeat note - see the first entry for this IP and rule in the report)"),
            ("Action", e.get("action") or "-")]
    y = 2
    for label, val in rows:
        for i, part in enumerate(textwrap.wrap(sa.clean(val, 3000), max(10, w - 16)) or [""]):
            if y >= h - 2:
                break
            attr = col.get(str(val), 0) if label == "Severity" else 0
            put(y, 0, label + ":" if i == 0 else "", curses.A_BOLD)
            put(y, 14, part, attr)
            y += 1
        y += 1
    put(h - 1, 0, " Esc / Enter / d = back ".ljust(w - 1), curses.A_REVERSE)
    scr.refresh()


def grid_dims(w, body_h, n, per_page):
    cols = 3 if w >= 210 else (2 if w >= 100 else 1)
    rows = max(1, min(2, body_h // 9))
    pp = per_page if per_page > 0 else cols * rows
    cols = min(cols, pp)
    return cols, math.ceil(pp / cols), max(1, min(pp, n))


def draw(scr, col, ctx):
    if ctx["detail"]:
        draw_detail(scr, col, ctx["detail"])
        return
    scr.erase()
    h, w = scr.getmaxyx()
    put = make_put(scr)
    srcs = ctx["sources"]
    by, bh = 3, h - 4
    cols, rows, pp = grid_dims(w, bh, len(srcs), ctx["per_page"])
    ctx["pp"] = pp
    if ctx["max"]:
        visible, pages = [srcs[ctx["focus"]]], 1
        ctx["page"] = 0
    else:
        pages = math.ceil(len(srcs) / pp)
        ctx["page"] = min(ctx["page"], pages - 1)
        if not (ctx["page"] * pp <= ctx["focus"] < (ctx["page"] + 1) * pp):
            ctx["page"] = ctx["focus"] // pp
        visible = srcs[ctx["page"] * pp:(ctx["page"] + 1) * pp]
    up = int(time.time() - ctx["started"])
    put(0, 0, " SOC LIVE MONITOR  (read-only, authorized lab)".ljust(w), curses.A_REVERSE)
    line = "Report: %s | Uptime %02d:%02d:%02d | %.1f lines/s | page %d/%d%s%s" % (
        ctx["out_path"], up // 3600, up % 3600 // 60, up % 60, ctx["lps"], ctx["page"] + 1, pages,
        " | MAXIMIZED" if ctx["max"] else "", " | [PAUSED]" if ctx["paused"] else "")
    put(1, 0, line, col["OK"])
    hl = sa.get_health() if getattr(sa, "HEALTH_ENABLED", False) and hasattr(sa, "get_health") else None
    if hl:
        hot = hl["cpu"] >= sa.HEALTH_CPU_PCT or hl["ram"] >= sa.HEALTH_RAM_PCT
        put(1, min(len(line) + 3, max(0, w - 45)), "CPU %.0f%% (%.1f/%d) RAM %.0f%%%s" % (
            hl["cpu"], hl["busy"], hl["cores"], hl["ram"], " STRESSED" if hot else ""),
            col["CRITICAL"] if hot else col["OK"])
    draw_tabs(put, col, ctx)

    ncols = min(cols, len(visible))
    nrows = math.ceil(len(visible) / ncols)
    rh, cw = bh // nrows, w // ncols
    for i, src in enumerate(visible):
        r, c = divmod(i, ncols)
        x0 = c * cw
        width = cw - 1 if c < ncols - 1 else w - x0
        height = rh if r < nrows - 1 else bh - rh * (nrows - 1)
        if c < ncols - 1:
            for y in range(by + r * rh, by + r * rh + height):
                put(y, x0 + cw - 1, "|")
        draw_pane(put, col, by + r * rh, x0, height, width, src, src.idx == ctx["focus"])
    put(h - 1, 0, " q quit | Tab pane | 1-9 jump | [ ] page | m maximize | Up/Down select | Enter inspect | p pause ".ljust(w - 1),
        curses.A_REVERSE)
    scr.refresh()


# =====================================================================
# Keys and main loop
# =====================================================================
def set_focus(ctx, idx):
    ctx["focus"] = idx % len(ctx["sources"])
    ctx["page"] = ctx["focus"] // max(1, ctx.get("pp", 1))


def change_page(ctx, delta):
    pp = max(1, ctx.get("pp", 1))
    pages = math.ceil(len(ctx["sources"]) / pp)
    ctx["page"] = (ctx["page"] + delta) % pages
    ctx["focus"] = min(ctx["page"] * pp, len(ctx["sources"]) - 1)


def handle_key(key, ctx):
    """Return True if the screen should redraw immediately."""
    if ctx["detail"]:
        if key in (27, 10, 13, curses.KEY_ENTER, ord("d"), ord("D"), ord("q"), ord("Q")):
            ctx["detail"] = None
            return True
        return False
    srcs = ctx["sources"]
    src = srcs[ctx["focus"]]
    n = len(src.recent)
    if key in (ord("p"), ord("P")):
        ctx["paused"] = not ctx["paused"]
    elif key == 9:
        set_focus(ctx, ctx["focus"] + 1)
    elif key == curses.KEY_BTAB:
        set_focus(ctx, ctx["focus"] - 1)
    elif ord("1") <= key <= ord("9"):
        if key - ord("1") < len(srcs):
            set_focus(ctx, key - ord("1"))
    elif key == ord("]"):
        change_page(ctx, 1)
    elif key == ord("["):
        change_page(ctx, -1)
    elif key in (ord("m"), ord("M")):
        ctx["max"] = not ctx["max"]
    elif key == curses.KEY_DOWN:
        src.sel = min(src.sel + 1, max(0, n - 1))
    elif key == curses.KEY_UP:
        src.sel = max(src.sel - 1, 0)
    elif key == curses.KEY_NPAGE:
        src.sel = min(src.sel + 10, max(0, n - 1))
    elif key == curses.KEY_PPAGE:
        src.sel = max(src.sel - 10, 0)
    elif key in (curses.KEY_HOME, ord("n")):
        src.sel = 0
    elif key in (10, 13, curses.KEY_ENTER, ord("d"), ord("D")):
        if n:
            ctx["detail"] = list(src.recent)[::-1][min(src.sel, n - 1)]
    else:
        return False
    return True


def process(src, line, rep, nets, post):
    """Send one line to the right analyzer for this source."""
    if src.kind == "access":
        sa.process_line(line, src.st, rep, nets)
    elif src.kind == "auth":
        soc_auth.process_auth_line(line, src.st, rep, nets, sa.record_finding, sa.is_whitelisted, post)
    else:
        soc_generic.process_generic_line(src.kind, line, src.st, rep, nets, sa.record_finding,
                                         sa.is_whitelisted, post)


def run(scr, args, ctx, rep, nets):
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    scr.nodelay(True)
    scr.keypad(True)
    col = init_colors()
    post = getattr(sa, "apply_health", None)
    if hasattr(sa, "HEALTH_RULES"):
        sa.HEALTH_RULES.update({"AUTH: SSH Brute Force", "MYSQL: Database Brute Force",
                                "POSTGRES: Database Brute Force"})
    last_draw, last_clean, last_lines = 0.0, time.time(), 0
    while True:
        busy = False
        for src in ctx["sources"]:
            if src.tail is None:
                continue
            lines = src.tail.poll()
            CTX["src"] = src
            for line in lines:
                process(src, line, rep, nets, post)
            busy = busy or bool(lines)
        key = scr.getch()
        if key in (ord("q"), ord("Q")) and not ctx["detail"]:
            return
        redraw = key != -1 and handle_key(key, ctx)
        now = time.time()
        if now - last_clean > 60:
            for src in ctx["sources"]:
                sa.cleanup(src.st, max(src.st.latest, now))
                soc_auth.cleanup_auth(src.st, now)
                soc_generic.cleanup_generic(src.st, now)
            last_clean = now
        if redraw or (now - last_draw >= REFRESH_SECONDS and not ctx["paused"]):
            total = sum(s.st.lines for s in ctx["sources"])
            if now - last_draw >= REFRESH_SECONDS:
                ctx["lps"] = (total - last_lines) / max(now - last_draw, 0.001) if last_draw else 0.0
                last_lines, last_draw = total, now
            draw(scr, col, ctx)
        if not busy and key == -1:
            time.sleep(0.05)


def main():
    ap = argparse.ArgumentParser(description="Live multi-log SOC dashboard (read-only).")
    ap.add_argument("--logs", nargs="*", metavar="PATH[:KIND]",
                    help="logs to monitor (kinds: %s). Default: auto-discover in /var/log" % ", ".join(sorted(KINDS)))
    ap.add_argument("--all", action="store_true", help="also add every other readable *.log in /var/log")
    ap.add_argument("--list", action="store_true", help="show what would be monitored, then exit")
    ap.add_argument("--per-page", type=int, default=0, help="panes per page (default: automatic)")
    ap.add_argument("--out", help="report file name (skips the question)")
    ap.add_argument("--json", action="store_true", help="also write JSON Lines")
    ap.add_argument("--whitelist", default=sa.DEFAULT_WHITELIST, help="IPs/CIDRs to ignore, or 'none'")
    ap.add_argument("--history", action="store_true", help="read existing logs first, then keep watching")
    ap.add_argument("--popup", action="store_true", help="desktop popups (needs popup patch)")
    ap.add_argument("--health", action="store_true", help="CRITICAL on brute force/scan/DoS when CPU/RAM is high")
    ap.add_argument("--cpu-limit", type=float, default=getattr(sa, "HEALTH_CPU_PCT", 50.0))
    ap.add_argument("--ram-limit", type=float, default=getattr(sa, "HEALTH_RAM_PCT", 80.0))
    args = ap.parse_args()

    found = discover(args)
    if args.list:
        for i, (path, kind) in enumerate(found, 1):
            ok = "readable" if os.access(path, os.R_OK) else "NOT readable (use sudo)"
            print("%2d. %-45s %-9s %s" % (i, path, kind, ok))
        print("%d log(s) found." % len(found))
        return 0
    if not found:
        print("ERROR: no logs found. Use --logs /path/to/file[:kind] or --all.")
        return 1
    if not sys.stdout.isatty():
        print("ERROR: the dashboard needs a real terminal.")
        return 1

    os.environ.setdefault("ESCDELAY", "25")
    sa.HEALTH_ENABLED, sa.HEALTH_CPU_PCT, sa.HEALTH_RAM_PCT = args.health, args.cpu_limit, args.ram_limit
    sa.banner()
    out_path, out_mode = sa.choose_output(args)
    sources = [Source(i, p, k) for i, (p, k) in enumerate(found)]
    for s in sources:
        err = sa.check_log(s.path)
        if err:
            s.note = err.splitlines()[0] + "  (try: sudo, or sudo usermod -aG adm $USER)"
            continue
        try:
            s.tail = Tail(s.path, not args.history)
        except OSError as e:
            s.note = "cannot open: %s" % e
    if not any(s.tail for s in sources):
        print("ERROR: none of the logs can be read. Run with sudo.")
        for s in sources:
            print("  %s: %s" % (s.path, s.note))
        return 1
    if args.popup and hasattr(sa, "POPUP_ENABLED"):
        sa.POPUP_ENABLED = True
    nets = sa.parse_whitelist(args.whitelist)
    try:
        rep = sa.Reporter(out_path, out_mode, args.json)
    except OSError as e:
        print("ERROR: cannot write report file '%s': %s" % (out_path, e))
        return 1
    rep.color = False
    rep.text("SOC LIVE REPORT - started: %s" % sa.now_str())
    for s in sources:
        rep.text("  source %d: %s (%s)%s" % (s.idx + 1, s.path, s.kind, "" if s.tail else " - UNAVAILABLE"))

    first = next(s.idx for s in sources if s.tail)
    ctx = dict(sources=sources, out_path=out_path, started=time.time(), lps=0.0, paused=False,
               focus=first, page=0, pp=1, max=False, per_page=args.per_page, detail=None)
    try:
        curses.wrapper(run, args, ctx, rep, nets)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("ERROR: lost permission to read a log. Try sudo.")
    finally:
        for s in sources:
            if s.tail:
                s.tail.close()
            rep.text("")
            rep.text("=" * 72)
            rep.text("SUMMARY: [%d] %s (%s)" % (s.idx + 1, s.path, s.kind))
            sa.write_summary(rep, s.st)
        rep.close()
        total = sum(sum(s.st.sev.values()) for s in sources)
        print("Stopped. %d source(s), %d findings in total." % (len(sources), total))
        for s in sources:
            print("  [%d] %-32s lines %-7d findings %d" % (s.idx + 1, s.name, s.st.lines, sum(s.st.sev.values())))
        print("Report saved to %s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
