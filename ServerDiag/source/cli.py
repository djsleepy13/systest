"""
ServerDiag command line.

  sudo python3 serverdiag.pyz                    interactive terminal UI for this server
  sudo python3 serverdiag.pyz --report           no UI: print summary + save HTML/TXT/JSON report
  sudo python3 serverdiag.pyz --json             JSON to stdout (used by fleet mode)
  python3 serverdiag.pyz fleet hosts.txt         scan many hosts over SSH (Linux + Windows)
"""
import argparse
import json
import os
import sys

from .common import VERSION, sort_findings, all_findings

DEFAULT_OUT = "serverdiag-reports"


def _eprint(*a):
    sys.stderr.write(" ".join(str(x) for x in a) + "\n")
    sys.stderr.flush()


def _color(txt, code):
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        return "\033[%sm%s\033[0m" % (code, txt)
    return txt


def print_summary(r):
    col = {"CRITICAL": "1;41;97", "WARNING": "1;43;30", "INFO": "1;44;97", "OK": "1;42;30"}
    sc = "1;32" if r["score"] >= 85 else ("1;33" if r["score"] >= 60 else "1;31")
    print("\n%s  %s  (%s)" % (_color(" ServerDiag %s " % VERSION, "1;44;97"), r["host"], r.get("os", "")))
    print("Health score: %s   %d critical, %d warnings\n" % (_color("%d/100" % r["score"], sc), r["critical"], r["warnings"]))
    for f in sort_findings(all_findings(r)):
        if f.get("Status") == "OK":
            continue
        print("%s %-14s %s" % (_color(" %-8s " % f["Status"], col.get(f["Status"], "0")), (f.get("Area") or "")[:14], f.get("Finding")))
        if f.get("Advice"):
            print("%s -> %s" % (" " * 26, f["Advice"]))
    a = r.get("analysis") or {}
    if a.get("problems"):
        print("\n%s" % _color("Likely causes from the logs:", "1;36"))
        for p in a["problems"]:
            print("  %s %s" % (_color(" %-6s " % p["likelihood"], col.get({"HIGH": "CRITICAL", "MEDIUM": "WARNING"}.get(p["likelihood"], "INFO"))), p["name"]))
            for e in p["evidence"][:3]:
                print("         - " + e)
    for ins in a.get("insights", []):
        print("  * " + ins)
    print("")


def print_fleet(results):
    print("\n%-30s %-32s %6s %5s %5s  %s" % ("HOST", "OS", "SCORE", "CRIT", "WARN", "TOP ISSUE"))
    for r in sorted(results, key=lambda r: r["score"]):
        fs = [f for f in sort_findings(all_findings(r)) if f.get("Status") in ("CRITICAL", "WARNING")]
        issue = r.get("error") or (fs[0]["Finding"] if fs else "-")
        sc = "1;32" if r["score"] >= 85 else ("1;33" if r["score"] >= 60 else "1;31")
        print("%-30s %-32s %s %5d %5d  %s" % (r["host"][:30], (r.get("os") or "")[:32], _color("%6s" % ("ERR" if r.get("error") else r["score"]), sc), r["critical"], r["warnings"], issue[:70]))
    print("")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "fleet":
        return fleet_main(argv[1:])
    ap = argparse.ArgumentParser(prog="serverdiag", description="ServerDiag %s - server health check + log analyzer" % VERSION)
    ap.add_argument("--days", type=int, default=7, help="days of logs to analyse (default 7)")
    ap.add_argument("--report", action="store_true", help="no UI: print summary and save reports")
    ap.add_argument("--json", action="store_true", help="print JSON result to stdout")
    ap.add_argument("--out", default=DEFAULT_OUT, help="report folder (default ./%s)" % DEFAULT_OUT)
    ap.add_argument("--version", action="version", version="ServerDiag %s" % VERSION)
    args = ap.parse_args(argv)

    if os.name == "nt":
        _eprint("ServerDiag's local mode is for Linux. For Windows use WinDiag, or scan Windows servers with: serverdiag fleet hosts.txt")
        return 2
    from .results import build_linux_result, dumps
    from . import report

    if args.json:
        r = build_linux_result(args.days, progress=lambda m: None)
        sys.stdout.write(dumps(r))
        return 0
    if args.report or not sys.stdout.isatty():
        if os.geteuid() != 0:
            _eprint("Note: not running as root - SMART, firewall, SSH config and full logs need sudo.")
        r = build_linux_result(args.days, progress=lambda m: _eprint("  " + m))
        print_summary(r)
        path = report.save([r], args.out)
        print("Reports saved to %s/ (report.html, report.txt, report.json)" % path)
        return 0 if r["critical"] == 0 else 1

    import curses
    from . import tui
    os.environ.setdefault("ESCDELAY", "50")

    def app(scr):
        while True:
            r = tui.loading(scr, "checking this server" + ("" if os.geteuid() == 0 else " (not root - limited)"),
                            lambda prog: build_linux_result(args.days, progress=prog))
            if r is None:
                return
            v = tui.Viewer(scr, [r], rerun=True, save=lambda: "Saved: %s" % report.save([r], args.out))
            if v.host(r) != "rerun":
                return
    curses.wrapper(app)
    return 0


def fleet_main(argv):
    ap = argparse.ArgumentParser(prog="serverdiag fleet", description="Scan many servers over SSH (key-based auth).")
    ap.add_argument("hosts", help="file with one host per line: [user@]host [port=N]; prefix Windows hosts with win:")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--parallel", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=600, help="per-host timeout in seconds")
    ap.add_argument("--ssh-option", "-o", action="append", default=[], help="extra ssh -o option (repeatable), e.g. -o IdentityFile=~/.ssh/ops")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--no-tui", action="store_true", help="print a table and save reports instead of the UI")
    args = ap.parse_args(argv)
    from .fleet import parse_hosts, scan_fleet
    from . import report
    hosts = parse_hosts(args.hosts)
    if not hosts:
        _eprint("No hosts in %s" % args.hosts)
        return 2

    def work(prog):
        return scan_fleet(hosts, args.days, args.parallel, args.ssh_option, args.timeout, progress=prog)

    use_tui = not args.no_tui and sys.stdout.isatty()
    if use_tui:
        try:
            import curses
        except ImportError:
            use_tui = False
    if not use_tui:
        res = work(lambda d, t, r: _eprint("  [%d/%d] %-30s score %s %s" % (d, t, r["host"], r["score"], ("ERROR " + r["error"][:80]) if r.get("error") else "")))
        print_fleet(res)
        print("Fleet report saved to %s/" % report.save(res, args.out))
        return 0
    from . import tui
    os.environ.setdefault("ESCDELAY", "50")
    holder = {}

    def app(scr):
        res = tui.loading(scr, "scanning %d hosts" % len(hosts), work)
        if res is None:
            return
        holder["res"] = res
        path = report.save(res, args.out)
        v = tui.Viewer(scr, res, save=lambda: "Saved: %s" % report.save(res, args.out), fleet=True)
        v.msg = "Report saved: %s" % path
        v.fleet_view()
    curses.wrapper(app)
    if holder.get("res"):
        print_fleet(holder["res"])
    return 0
