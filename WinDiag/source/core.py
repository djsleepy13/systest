"""WinDiag core: paths, admin, PowerShell runner, repairs, findings."""
import ctypes
import json
import os
import re
import subprocess
import sys
import tempfile
import threading as _threading
import uuid
from datetime import datetime

from ps_collector import SCRIPT as COLLECTOR_PS

APP_NAME = "WinDiag"
APP_VERSION = "4.0"

CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_CONSOLE = 0x00000010

POWERSHELL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
if not os.path.exists(POWERSHELL):
    POWERSHELL = "powershell.exe"


def sys32(exe):
    """Full path to a Windows tool (never picks up a same-named file from the USB folder / PATH)."""
    p = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", exe if exe.lower().endswith(".exe") else exe + ".exe")
    return p if os.path.exists(p) else exe


# ---------------------------------------------------------------------------------
#  Error log (the exe has no console, so tracebacks would otherwise vanish)
# ---------------------------------------------------------------------------------
_log_lock = None


def log_error(where, exc=None):
    """Append a traceback to Reports/windiag_errors.log (max ~1 MB). Never raises."""
    global _log_lock
    import threading as _t
    import traceback as _tb
    if _log_lock is None:
        _log_lock = _t.Lock()
    try:
        text = "".join(_tb.format_exception(type(exc), exc, exc.__traceback__)) if exc is not None else _tb.format_exc()
        base = os.path.join(app_dir(), "Reports")
        os.makedirs(base, exist_ok=True)
        path = os.path.join(base, "windiag_errors.log")
        with _log_lock:
            if os.path.exists(path) and os.path.getsize(path) > 1000000:
                os.replace(path, path + ".old")
            with open(path, "a", encoding="utf-8") as f:
                f.write("=== %s  %s  v%s\n%s\n" % (datetime.now().isoformat(timespec="seconds"), where, APP_VERSION, text))
    except Exception:
        pass


def friendly_error(exc):
    """Short text for the UI; the details go to the error log."""
    return "couldn't read this (details in Reports\\windiag_errors.log)"


# ---------------------------------------------------------------------------------
#  Paths / admin
# ---------------------------------------------------------------------------------
def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(extra_args=()):
    """Relaunch self elevated. Returns True if the elevated copy was started."""
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
            args = list(sys.argv[1:]) + list(extra_args)
        else:
            exe = sys.executable
            args = [os.path.abspath(sys.argv[0])] + list(sys.argv[1:]) + list(extra_args)
        params = " ".join('"%s"' % a for a in args)
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return r > 32
    except Exception:
        return False


def _open_reports_acl(base):
    """Reports created while elevated are owned by Administrators; let normal users delete them too.
    Runs icacls in a background thread (a big Reports tree with /T can take many seconds)."""
    if os.name != "nt" or not is_admin():
        return

    def work():
        try:
            subprocess.run([sys32("icacls"), base, "/grant", "*S-1-5-11:(OI)(CI)M", "/T", "/C", "/Q"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW, timeout=120)
        except Exception:
            pass
    _threading.Thread(target=work, daemon=True).start()


def make_report_dir():
    name = "%s_%s" % (os.environ.get("COMPUTERNAME", "PC"), datetime.now().strftime("%Y-%m-%d_%H%M"))
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    for base in (os.path.join(app_dir(), "Reports"), os.path.join(desktop, "WinDiag_Reports"),
                 os.path.join(tempfile.gettempdir(), "WinDiag_Reports")):
        path = os.path.join(base, name)
        try:
            os.makedirs(path, exist_ok=True)
            probe = os.path.join(path, ".write_test")
            with open(probe, "w") as f:
                f.write("ok")
            os.remove(probe)
            _open_reports_acl(base)
            return path
        except Exception:
            continue
    return tempfile.mkdtemp(prefix="WinDiag_")


# ---------------------------------------------------------------------------------
#  PowerShell collector
# ---------------------------------------------------------------------------------
_work = tempfile.mkdtemp(prefix="windiag_")

# ---------------------------------------------------------------------------------
#  Abort support: every PowerShell / helper process is tracked so "Stop" can kill it
# ---------------------------------------------------------------------------------
ACTIVE = {}                     # pid -> (Popen, label)
_active_lock = _threading.Lock()
ABORT = _threading.Event()


class Aborted(Exception):
    pass


def busy():
    with _active_lock:
        return [lbl for (_p, lbl) in ACTIVE.values()]


def _kill_tree(p):
    try:
        if os.name == "nt":
            subprocess.run([sys32("taskkill"), "/T", "/F", "/PID", str(p.pid)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW, timeout=15)
        else:
            p.kill()
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def abort_all():
    """Kill every tracked (read-only) background process. Repairs/wipes run in their own consoles and are NOT touched."""
    ABORT.set()
    with _active_lock:
        procs = [p for (p, _l) in ACTIVE.values()]
    for p in procs:
        _kill_tree(p)
    return len(procs)


def reset_abort():
    ABORT.clear()


def tracked_run(args, timeout, label="task", track=True):
    """subprocess.run replacement: returns (returncode, stdout bytes, stderr bytes); raises Aborted / TimeoutExpired.
    track=False: not stopped by the Stop button / Esc (used for repairs and fixes, which must not be cut off half-way)."""
    if track and ABORT.is_set():
        raise Aborted()
    p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0)
    if track:
        with _active_lock:
            ACTIVE[p.pid] = (p, label)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(p)
        p.communicate()
        raise
    finally:
        with _active_lock:
            ACTIVE.pop(p.pid, None)
    if track and ABORT.is_set() and p.returncode not in (0,):
        raise Aborted()
    return p.returncode, out, err
_collector_path = os.path.join(_work, "collector.ps1")
with open(_collector_path, "w", encoding="utf-8-sig") as _f:
    _f.write(COLLECTOR_PS)


# ---------------------------------------------------------------------------------
#  How PowerShell is started. Group Policy "AllSigned" / "scripts disabled" beats
#  -ExecutionPolicy Bypass for -File, so if a script file is refused we run the same
#  file's text through -Command ([scriptblock]::Create), which execution policy does not cover.
#  The mode that worked is remembered for the rest of the session.
# ---------------------------------------------------------------------------------
_PS_MODE = {"mode": None}        # None = not known yet, "file" or "command"
# PSSecurityException and the about_Execution_Policies link are not translated, so this also works on non-English Windows.
# (Not a bare "UnauthorizedAccess": a check that merely hits an access-denied registry key must not look like a policy block.)
_POLICY_RX = re.compile(r"PSSecurityException|about_Execution_Policies|running scripts is disabled|is not digitally signed", re.I)
_AMSI_RX = re.compile(r"ScriptContainedMaliciousContent|contains malicious content|blocked by your antivirus", re.I)
CLM_MSG = "PowerShell is locked to Constrained Language Mode by policy - WinDiag can't run its checks"
AMSI_MSG = ("Your antivirus blocked this WinDiag check (it flagged the PowerShell script). Nothing was changed. "
            "If you trust WinDiag, allow it in the antivirus and try again.")
POLICY_MSG = "A Windows policy on this PC blocks PowerShell scripts, so WinDiag couldn't run this check."
_notices = {"pending": [], "shown": set()}
_notice_lock = _threading.Lock()


def _note(kind, msg):
    """Remember a one-time notice (CLM / AMSI) for the UI to show once. Thread-safe (checks run in parallel)."""
    with _notice_lock:
        if kind not in _notices["shown"]:
            _notices["shown"].add(kind)
            _notices["pending"].append(msg)


def pop_notices():
    """One-time policy notices (Constrained Language Mode, antivirus block) not yet shown to the user.
    Call from the UI thread (e.g. the main queue poll) and show each text once."""
    with _notice_lock:
        out, _notices["pending"] = _notices["pending"], []
    return out


def _psq(s):
    return str(s).replace("'", "''")


def ps_cmd(path, args=(), mode=None, extra=("-NonInteractive",)):
    """Command line that runs a .ps1 file (with -Name value args) in the given / remembered mode."""
    mode = mode or _PS_MODE["mode"] or "file"
    base = [POWERSHELL, "-NoProfile"] + list(extra) + ["-ExecutionPolicy", "Bypass"]
    if mode == "command":
        tail = " ".join(a if re.match(r"^-[A-Za-z]\w*$", str(a)) else "'%s'" % _psq(a) for a in args)
        return base + ["-Command", "& ([scriptblock]::Create((Get-Content -Raw -LiteralPath '%s'))) %s" % (_psq(path), tail)]
    return base + ["-File", path] + [str(a) for a in args]


def blocked_kind(text):
    """'amsi' / 'policy' / None for PowerShell error output of a run that produced no result."""
    if not text:
        return None
    if _AMSI_RX.search(text):
        return "amsi"
    if _POLICY_RX.search(text):
        return "policy"
    return None


def _run_ps_file(path, args, timeout, label, track, produced):
    """tracked_run a .ps1 file; retry via -Command when execution policy refuses the file.
    produced(stdout_bytes) -> True when the run gave a result. Returns (rc, out, err, kind)."""
    mode = _PS_MODE["mode"] or "file"
    rc, out, err = tracked_run(ps_cmd(path, args, mode), timeout, label, track)
    if produced(out):
        _PS_MODE["mode"] = mode
        return rc, out, err, None
    kind = blocked_kind((out or b"").decode("utf-8", "replace") + (err or b"").decode("utf-8", "replace"))
    if kind == "policy" and mode == "file":
        rc, out, err = tracked_run(ps_cmd(path, args, "command"), timeout, label, track)
        if produced(out):
            _PS_MODE["mode"] = "command"
            return rc, out, err, None
        kind = blocked_kind((out or b"").decode("utf-8", "replace") + (err or b"").decode("utf-8", "replace"))
    if kind == "amsi":
        _note("amsi", AMSI_MSG)
    return rc, out, err, kind


def ps_mode():
    """Launch mode for a PowerShell window (repairs): probes once with a tiny script if not known yet."""
    if _PS_MODE["mode"]:
        return _PS_MODE["mode"]
    tmp = os.path.join(_work, "probe_%s.ps1" % uuid.uuid4().hex[:8])
    try:
        with open(tmp, "w", encoding="utf-8-sig") as f:
            f.write("'WDPROBE'\n")
        _run_ps_file(tmp, (), 30, "PowerShell probe", False, lambda o: b"WDPROBE" in (o or b""))
    except Exception:
        pass
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass
    return _PS_MODE["mode"] or "file"


def _fail(msg, **kw):
    d = {"sections": [], "findings": [], "events": [], "error": msg}
    d.update(kw)
    return d


def run_check(check, days=30, timeout=420):
    """Run one check via PowerShell. Returns dict(sections, findings, events, error)."""
    out = os.path.join(_work, "%s_%s.json" % (check, uuid.uuid4().hex[:8]))
    args = ["-Check", check, "-Out", out, "-Days", str(days)]
    try:
        rc, pout, perr, kind = _run_ps_file(_collector_path, args, timeout, "Check: %s" % check, True,
                                            lambda _o: os.path.exists(out))
    except Aborted:
        return _fail("Stopped by user", aborted=True)
    except subprocess.TimeoutExpired:
        return _fail("Timed out after %d s" % timeout)
    except Exception as e:
        log_error("run_check " + check, e)
        return _fail("Could not start PowerShell: %s" % e)
    if not os.path.exists(out):
        if kind == "amsi":
            return _fail(AMSI_MSG, blocked="amsi")
        if kind == "policy":
            return _fail(POLICY_MSG, blocked="policy")
        err = (perr or b"").decode("utf-8", "replace").strip()[:500]
        return _fail("No output from PowerShell. %s" % err)
    try:
        with open(out, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except Exception as e:
        return _fail("Bad output: %s" % e)
    finally:
        try:
            os.remove(out)
        except Exception:
            pass
    if isinstance(data, dict) and data.get("clm"):
        _note("clm", CLM_MSG)
        return _fail(CLM_MSG, blocked="clm")
    return normalize_result(data)


def _as_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        # un-nest [[...]] produced by some PowerShell versions
        if len(x) == 1 and isinstance(x[0], list):
            return x[0]
        return x
    if isinstance(x, dict) and "value" in x and isinstance(x["value"], list):
        return x["value"]
    return [x]


def normalize_result(data):
    secs = []
    for s in _as_list(data.get("sections")):
        if not isinstance(s, dict):
            continue
        secs.append({"title": s.get("title") or "", "note": s.get("note") or "", "list": bool(s.get("list")),
                     "data": _as_list(s.get("data"))})
    finds = [f for f in _as_list(data.get("findings")) if isinstance(f, dict)]
    evs = [e for e in _as_list(data.get("events")) if isinstance(e, dict)]
    return {"sections": secs, "findings": finds, "events": evs, "error": data.get("error")}


# ---------------------------------------------------------------------------------
#  Findings helpers
# ---------------------------------------------------------------------------------
ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2, "OK": 3}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (ORDER.get(f.get("Status"), 9), f.get("Area") or ""))


def health_score(findings):
    """(score 0-100, critical count, warning count).
    - "Check could not run" items are not counted against the PC (that's a WinDiag/permissions problem, not a PC problem).
    - The same finding reported by two checks counts once.
    - Diminishing penalty: each critical x0.78, each warning x0.94 - one problem can't take a PC to 0, many still pull it down."""
    seen, c, w = set(), 0, 0
    for f in findings:
        st = f.get("Status")
        if st not in ("CRITICAL", "WARNING") or f.get("CheckError"):
            continue
        key = (st, str(f.get("Area") or ""), re.sub(r"\W+", " ", str(f.get("Finding") or "")).strip().lower()[:80])
        if key in seen:
            continue
        seen.add(key)
        if st == "CRITICAL":
            c += 1
        else:
            w += 1
    score = int(round(100 * (0.78 ** c) * (0.94 ** w)))
    if c:
        score = min(score, 59)                  # any critical problem = red, never "amber"
    return max(5 if (c or w) else 0, min(100, score)) if (c or w) else 100, c, w


# ---------------------------------------------------------------------------------
#  Text formatting of sections
# ---------------------------------------------------------------------------------
def cell(v, maxlen=70):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, list):
        v = ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        v = json.dumps(v)
    s = str(v).replace("\r", " ").replace("\n", " ")
    if maxlen and len(s) > maxlen:
        s = s[: maxlen - 3] + "..."
    return s


def section_text(sec, maxlen=70):
    data = sec["data"]
    if not data:
        return "  (nothing found)\n"
    if all(isinstance(d, str) for d in data):
        return "\n".join("  " + d for d in data) + "\n"
    rows = [d for d in data if isinstance(d, dict)]
    if not rows:
        return "\n".join("  " + cell(d, 0) for d in data) + "\n"
    if sec.get("list"):
        out = []
        for r in rows:
            w = max(len(k) for k in r) if r else 0
            for k, v in r.items():
                out.append("  %s : %s" % (k.ljust(w), cell(v, 0)))
            out.append("")
        return "\n".join(out).rstrip() + "\n"
    cols = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    table = [[cell(r.get(c), maxlen) for c in cols] for r in rows]
    widths = [max(len(c), *(len(t[i]) for t in table)) for i, c in enumerate(cols)]
    line = lambda vals: "  " + "  ".join(v.ljust(widths[i]) for i, v in enumerate(vals))
    out = [line(cols), "  " + "  ".join("-" * w for w in widths)]
    out += [line(t) for t in table]
    return "\n".join(o.rstrip() for o in out) + "\n"


# ---------------------------------------------------------------------------------
#  Repairs
# ---------------------------------------------------------------------------------
REPAIRS = [
    dict(group="Before you repair", name="Create restore point", admin=True,
         desc="Snapshot of system settings so repairs can be undone (System Restore).",
         body=r"""Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
Checkpoint-Computer -Description 'WinDiag - before repairs' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
Write-Host 'Restore point requested (Windows allows one per 24h; a recent one is kept).' -ForegroundColor Green"""),
    dict(group="System files", name="Full system repair (DISM + SFC)", admin=True,
         desc="Repairs the Windows image, then scans/fixes system files. 15-45 min, needs internet.",
         confirm="This runs DISM /RestoreHealth then SFC /scannow. It can take 15-45 minutes. Continue?",
         body=r"""Write-Host 'Step 1/2: DISM RestoreHealth - may sit at 20% or 62% for a while, that is normal.' -ForegroundColor Yellow
DISM /Online /Cleanup-Image /RestoreHealth
$dismExit = $LASTEXITCODE
Write-Host "DISM exit code: $dismExit  (0 = OK)"
Write-Host ''
Write-Host 'Step 2/2: System File Checker' -ForegroundColor Yellow
sfc /scannow
$WDStatus = @{ dism = $dismExit; sfc = $LASTEXITCODE; exit = $dismExit }
Write-Host "SFC exit code: $LASTEXITCODE"
findstr /c:"[SR]" "$env:windir\Logs\CBS\CBS.log" | Out-File -FilePath (Join-Path $ReportDir 'sfc_details.txt') -Encoding UTF8
Write-Host "SFC details saved to $ReportDir\sfc_details.txt"
Write-Host 'Restart the PC when finished.' -ForegroundColor Green"""),
    dict(group="System files", name="Quick system file check (SFC)", admin=True,
         desc="Scans protected Windows files and replaces corrupted ones. ~10 min.",
         body=r"""sfc /scannow
Write-Host "SFC exit code: $LASTEXITCODE"
findstr /c:"[SR]" "$env:windir\Logs\CBS\CBS.log" | Out-File -FilePath (Join-Path $ReportDir 'sfc_details.txt') -Encoding UTF8
Write-Host "Details saved to $ReportDir\sfc_details.txt"
"""),
    dict(group="Disk", name="CHKDSK scan (online)", admin=True,
         desc="Checks the system drive for file-system errors without restarting.",
         body=r"""chkdsk $env:SystemDrive /scan
$WDStatus = @{ exit = $LASTEXITCODE }
Write-Host "CHKDSK exit code: $LASTEXITCODE  (0 = no errors found)"
"""),
    dict(group="Disk", name="CHKDSK full repair at next restart", admin=True,
         desc="Schedules chkdsk /f /r on the next boot. Can take HOURS on big drives.",
         confirm="This schedules a full disk check/repair (chkdsk /f /r) on the next restart. It can take several hours and must not be interrupted. Continue?",
         body=r"""cmd.exe /c "echo Y| chkdsk %SystemDrive% /f /r"
Write-Host 'Scheduled. Restart the PC to run it - do not power off during the check.' -ForegroundColor Yellow"""),
    dict(group="Disk", name="Clear temp files", admin=True,
         desc="Deletes temp files for all users + Windows temp. Safe; in-use files are skipped.",
         body=r"""$targets = @("$env:SystemRoot\Temp")
$targets += Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' } | Where-Object { Test-Path $_ }
$total = 0
foreach ($t in $targets) {
    $before = [double](Get-ChildItem $t -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Get-ChildItem $t -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'windiag_*' -and $_.Name -notlike '_MEI*' } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $after = [double](Get-ChildItem $t -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    $freed = $before - $after; $total += $freed
    Write-Host ('{0,-60} freed {1,10:N1} MB' -f $t, ($freed / 1MB))
}
Write-Host ''
Write-Host ('Total freed: {0:N1} MB' -f ($total / 1MB)) -ForegroundColor Green"""),
    dict(group="Network", name="Flush DNS cache", admin=False,
         desc="Fixes websites not loading after DNS/IP changes. Instant and harmless.",
         body=r"""ipconfig /flushdns
Clear-DnsClientCache -ErrorAction SilentlyContinue
Write-Host 'DNS cache cleared.' -ForegroundColor Green"""),
    dict(group="Network", name="Full network reset", admin=True,
         desc="Resets Winsock + TCP/IP and renews the IP. Fixes most 'connected, no internet'. Restart needed.",
         confirm="This resets Winsock and TCP/IP and briefly disconnects the network. Static IP settings may need re-entering. A restart is needed afterwards. Continue?",
         body=r"""ipconfig /flushdns
ipconfig /release
ipconfig /renew
netsh winsock reset
netsh int ip reset
Write-Host ''
Write-Host 'Done. RESTART the PC to finish the network reset.' -ForegroundColor Yellow"""),
    dict(group="Windows Update", name="Reset Windows Update", admin=True,
         desc="Stops update services, renames the update cache, restarts services. Fixes stuck/failing updates.",
         confirm="This resets the Windows Update cache (folders are renamed, not deleted). Update history in Settings will look empty afterwards. Continue?",
         body=r"""$svcs = 'wuauserv', 'bits', 'cryptsvc', 'msiserver'
foreach ($s in $svcs) { Write-Host "Stopping $s"; Stop-Service $s -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
foreach ($p in "$env:SystemRoot\SoftwareDistribution", "$env:SystemRoot\System32\catroot2") {
    if (Test-Path $p) {
        try { Rename-Item $p ((Split-Path $p -Leaf) + ".bak$stamp") -ErrorAction Stop; Write-Host "Renamed $p" -ForegroundColor Green }
        catch { Write-Host "Could not rename $p : $($_.Exception.Message)" -ForegroundColor Red }
    }
}
foreach ($s in $svcs) { Write-Host "Starting $s"; Start-Service $s -ErrorAction SilentlyContinue }
$WDStatus = @{ exit = 0 }
Write-Host 'Done. Now open Settings > Windows Update and check for updates.' -ForegroundColor Green"""),
    dict(group="Security", name="Update Defender definitions", admin=True,
         desc="Downloads the latest Microsoft Defender virus definitions.",
         body=r"""Update-MpSignature -ErrorAction Stop
Write-Host ('Definitions now dated: {0}' -f (Get-MpComputerStatus).AntivirusSignatureLastUpdated) -ForegroundColor Green"""),
    dict(group="Security", name="Defender quick scan", admin=True,
         desc="Runs a Microsoft Defender quick malware scan (~5-15 min).",
         body=r"""Write-Host 'Scanning... this window updates when finished.' -ForegroundColor Yellow
Start-MpScan -ScanType QuickScan -ErrorAction Stop
$t = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddHours(-1) })
Write-Host ("Scan finished. Threats found in the last hour: {0}" -f $t.Count) -ForegroundColor Green"""),
    dict(group="Security", name="Defender full scan", admin=True,
         desc="Microsoft Defender full scan of every file (can take 1 hour or more).",
         body=r"""Write-Host 'Full scan running - this can take an hour or more. This window updates when finished.' -ForegroundColor Yellow
$t0 = Get-Date
Start-MpScan -ScanType FullScan -ErrorAction Stop
$t = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $t0 })
Write-Host ("Full scan finished. Threats found: {0}" -f $t.Count) -ForegroundColor $(if ($t.Count) { 'Red' } else { 'Green' })
$WDStatus = @{ exit = 0; threats = $t.Count }"""),
    dict(group="Hardware", name="Memory (RAM) test", admin=True, launch=["mdsched.exe"],
         desc="Windows Memory Diagnostic - restarts and tests RAM. Result appears in the Event Analyzer afterwards."),
    dict(group="Hardware", name="Battery report", admin=False,
         desc="Detailed battery history & capacity (laptops). Saved to the report folder.",
         body=r"""$f = Join-Path $ReportDir 'battery-report.html'
powercfg /batteryreport /output "$f"
if (Test-Path $f) { Start-Process $f }"""),
    dict(group="Hardware", name="Power / energy report", admin=True,
         desc="Observes the PC for 60 s and lists power / sleep problems.",
         body=r"""$f = Join-Path $ReportDir 'energy-report.html'
Write-Host 'Observing for 60 seconds, leave the PC idle...' -ForegroundColor Yellow
powercfg /energy /output "$f" /duration 60
if (Test-Path $f) { Start-Process $f }"""),
]

TOOLS = [
    ("Device Manager", ["mmc.exe", "devmgmt.msc"]), ("Event Viewer", ["mmc.exe", "eventvwr.msc"]),
    ("Reliability Monitor", ["perfmon.exe", "/rel"]), ("Resource Monitor", ["resmon.exe"]),
    ("Task Manager", ["taskmgr.exe"]), ("System Information", ["msinfo32.exe"]),
    ("Disk Management", ["mmc.exe", "diskmgmt.msc"]), ("Services", ["mmc.exe", "services.msc"]),
    ("Disk Cleanup", ["cleanmgr.exe"]), ("Windows Security", "windowsdefender:"),
    ("Windows Update", "ms-settings:windowsupdate"), ("Apps & features", "ms-settings:appsfeatures"),
    ("Startup apps", "ms-settings:startupapps"), ("System Restore", ["rstrui.exe"]),
]


def start_repair(rep, report_dir, status_path=None):
    if rep.get("launch"):
        cmd = list(rep["launch"])
        if cmd and not os.path.dirname(cmd[0]):
            cmd[0] = sys32(cmd[0])
        subprocess.Popen(cmd)
        if status_path:
            with open(status_path, "w") as f:
                json.dump({"finished": datetime.now().isoformat(timespec="seconds"), "exit": 0, "extra": {"launched": True}}, f)
        return
    safe = "".join(ch if ch.isalnum() else "_" for ch in rep["name"]).strip("_")
    log = os.path.join(report_dir, "repair_%s_%s.log" % (safe, datetime.now().strftime("%H%M%S")))
    tmp = os.path.join(tempfile.gettempdir(), "windiag_%s.ps1" % uuid.uuid4().hex)
    q = lambda s: s.replace("'", "''")
    script = (
        "$ErrorActionPreference = 'Continue'\n"
        "$Host.UI.RawUI.WindowTitle = 'WinDiag - %s'\n"
        "$ReportDir = '%s'\n"
        "Start-Transcript -Path '%s' | Out-Null\n"
        "Write-Host '==== %s ====' -ForegroundColor Cyan\n"
        "Write-Host ('Started: ' + (Get-Date))\nWrite-Host ''\n"
        "$WDStatus = $null\n"
        "try {\n%s\n} catch { Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red; $WDStatus = @{ exit = -1; error = $_.Exception.Message } }\n"
        "$WDExit = $LASTEXITCODE\n"
        "Write-Host ''\nWrite-Host ('Finished: ' + (Get-Date)) -ForegroundColor Green\n"
        "Stop-Transcript | Out-Null\n"
        "$WDStatusFile = '%s'\n"
        "if ($WDStatusFile) { $ex = if ($WDStatus -and $WDStatus.ContainsKey('exit')) { $WDStatus.exit } else { $WDExit }\n"
        "  @{ finished = (Get-Date).ToString('s'); exit = $ex; extra = $WDStatus } | ConvertTo-Json -Depth 4 | Set-Content -Path $WDStatusFile -Encoding UTF8 }\n"
        "Remove-Item -LiteralPath '%s' -Force -ErrorAction SilentlyContinue\n"
        "Read-Host 'Press Enter to close this window'\n"
    ) % (q(rep["name"]), q(report_dir), q(log), q(rep["name"]), rep["body"], q(status_path or ""), q(tmp))
    with open(tmp, "w", encoding="utf-8-sig") as f:
        f.write(script)
    subprocess.Popen(ps_cmd(tmp, (), ps_mode(), extra=()), creationflags=CREATE_NEW_CONSOLE)


def open_tool(target):
    if isinstance(target, str):
        os.startfile(target)
    else:
        target = list(target)
        if target and not os.path.dirname(target[0]):
            target[0] = sys32(target[0])
        subprocess.Popen(target)


# ---------------------------------------------------------------------------------
#  Guided Fix helpers
# ---------------------------------------------------------------------------------
import guided as _guided
REPAIRS.extend(_guided.EXTRA_REPAIRS)
import updates as _updates  # noqa: E402
REPAIRS.append(dict(group="Windows Update", name="Install available Windows updates", admin=True,
                    desc="Downloads and installs the important updates Windows Update offers for this PC (same as Settings).",
                    confirm="Download and install all important Windows updates now? This can take a while and may need a restart.",
                    body=_updates.INSTALL_BODY))
REPAIR_BY_NAME = {r["name"]: r for r in REPAIRS}


# The snippet runs first (dot-sourced, output captured); only then is the console switched to UTF-8 and the
# captured JSON written. Switching first would garble native tools (netsh, powercfg, w32tm...) on non-English
# Windows. Streaming into a list also keeps whatever was printed before a stray `exit`.
PS_JSON_HEAD = r"""if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    '{"status":"error","clm":true,"detail":"%s"}'
    return
}
# PS 5.1 serialises arrays as {"value":[...],"Count":n} unless this type data is removed
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
# en-US formatting culture: Gregorian dates and '.' decimals for Python to parse (Thai / Persian / Arabic calendars,
# German decimals), and event .Message is not left empty on mixed-locale systems. Native tools are not affected.
try { [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US' } catch {}
$__wdbuf = New-Object System.Collections.ArrayList
try { . {
""" % _psq(CLM_MSG)
PS_JSON_TAIL = r"""
} | ForEach-Object { [void]$__wdbuf.Add($_) } } finally {
    try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
    foreach ($__wdl in $__wdbuf) { [Console]::Out.WriteLine([string]$__wdl) }
}
"""


def _is_json(text):
    try:
        json.loads(text)
        return True
    except ValueError:
        return False


def wrap_ps_json(script):
    return PS_JSON_HEAD + script + PS_JSON_TAIL


def run_ps_json(script, timeout=180, label="PowerShell task", track=True):
    """Run a PowerShell snippet that prints one JSON object; return it as dict."""
    tmp = os.path.join(_work, "v_%s.ps1" % uuid.uuid4().hex[:8])
    with open(tmp, "w", encoding="utf-8-sig") as f:
        f.write(wrap_ps_json(script))
    try:
        rc, pout, perr, kind = _run_ps_file(tmp, (), timeout, label, track, lambda o: b"{" in (o or b""))
        out = pout.decode("utf-8", "replace")
        i = out.find("{")
        if i < 0:
            if kind == "amsi":
                return {"status": "error", "detail": AMSI_MSG, "blocked": "amsi"}
            if kind == "policy":
                return {"status": "error", "detail": POLICY_MSG, "blocked": "policy"}
            return {"status": "error", "detail": "No result. " + perr.decode("utf-8", "replace")[:300]}
        try:
            res = json.loads(out[i:out.rfind("}") + 1])
        except ValueError:
            # stray text with braces before the JSON (e.g. a GUID printed by a native tool): use the last JSON line
            res = next((json.loads(ln) for ln in reversed(out.strip().splitlines()) if ln.strip().startswith("{") and _is_json(ln)), None)
            if res is None:
                raise
        if isinstance(res, dict) and res.get("clm"):
            _note("clm", CLM_MSG)
            res["blocked"] = "clm"
        return res
    except Aborted:
        return {"status": "error", "detail": "Stopped by user", "aborted": True}
    except subprocess.TimeoutExpired:
        return {"status": "error", "detail": "Check timed out after %d s" % timeout}
    except Exception as e:
        log_error("run_ps_json " + str(label), e)
        return {"status": "error", "detail": "Check failed: %s" % e}
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass


FIND_CDB_PS = r"""
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$c = @()
$g = Get-Command cdb.exe -ErrorAction SilentlyContinue; if ($g) { $c += $g.Source }
$c += "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe"
$c += "$env:ProgramFiles\Windows Kits\10\Debuggers\x64\cdb.exe"
foreach ($p in @(Get-AppxPackage -Name Microsoft.WinDbg -ErrorAction SilentlyContinue) + @(Get-AppxPackage -AllUsers -Name Microsoft.WinDbg -ErrorAction SilentlyContinue)) {
    if ($p.InstallLocation) { $c += Join-Path $p.InstallLocation 'amd64\cdb.exe' }
}
$found = $c | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
$dumps = @(Get-ChildItem "$env:SystemRoot\Minidump" -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object { @{ path = $_.FullName; time = $_.LastWriteTime.ToString('s'); size = $_.Length } })
$full = Get-Item "$env:SystemRoot\MEMORY.DMP" -ErrorAction SilentlyContinue
@{ cdb = $found; dumps = $dumps; memory_dmp = $(if ($full) { @{ path = $full.FullName; time = $full.LastWriteTime.ToString('s'); size = $full.Length } } else { $null }) } | ConvertTo-Json -Compress -Depth 4
"""


def analyze_dumps(max_dumps=3, timeout=420, progress=None):
    """Run Microsoft's cdb '!analyze -v' on the newest minidumps. Returns dict."""
    info = run_ps_json(FIND_CDB_PS, 60)
    dumps = info.get("dumps") or []
    if isinstance(dumps, dict):
        dumps = [dumps]
    if not dumps and info.get("memory_dmp"):
        dumps = [info["memory_dmp"]]
    res = {"cdb": info.get("cdb"), "dumps": dumps, "results": [], "error": None}
    if not dumps:
        res["error"] = "No crash dump files found in C:\\Windows\\Minidump. Make sure dumps are enabled (previous step) - the next blue screen will create one."
        return res
    if not info.get("cdb"):
        res["error"] = "Microsoft's debugger (WinDbg / cdb.exe) is not installed. Click 'Install WinDbg' and run this step again."
        return res
    sym = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "WinDiag", "symbols")
    os.makedirs(sym, exist_ok=True)
    for i, d in enumerate(dumps[:max_dumps]):
        if progress:
            progress("Analysing dump %d of %d (first run downloads Microsoft symbols, can take a few minutes)..." % (i + 1, min(len(dumps), max_dumps)))
        try:
            rc, pout, perr = tracked_run([info["cdb"], "-z", d["path"], "-y", "srv*%s*https://msdl.microsoft.com/download/symbols" % sym,
                                          "-c", "!analyze -v; q"], timeout, "Crash dump analysis")
            text = (pout + perr).decode("utf-8", "replace")
        except Aborted:
            res["aborted"] = True
            break
        except subprocess.TimeoutExpired:
            text = ""
        r = _guided.parse_analyze(text)
        r.update({"file": os.path.basename(d["path"]), "time": d.get("time", ""), "raw": text[-6000:]})
        res["results"].append(r)
    return res
