"""
Before / after measurements. A snapshot records numbers Windows itself measures, so a fix can be
shown to have made a difference (not just "the command ran").
Snapshots are kept in Reports\\baseline_<PC>.json (newest last, max 30).
"""
import core
import json
import os
import threading
import uuid
from datetime import datetime

SNAP_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$R = [ordered]@{ time = (Get-Date).ToString('s') }
# boot time (Windows' own measurement, Diagnostics-Performance event 100, needs admin)
$boots = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } -MaxEvents 3 | ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    [ordered]@{ time = $_.TimeCreated.ToString('s'); total = [int]$d['BootTime']; main = [int]$d['MainPathBootTime']; post = [int]$d['BootPostBootTime'] } })
$R.boot = $boots
# CPU at idle-ish (5 s average) - language independent perf classes
$cpu = @(); for ($i = 0; $i -lt 5; $i++) { $cpu += (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime; Start-Sleep -Milliseconds 900 }
$R.cpu = [math]::Round(($cpu | Measure-Object -Average).Average, 1)
# disk response time (raw counters, 3 s window)
$a = Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"; Start-Sleep -Seconds 3
$b = Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
$dn = [double]$b.AvgDisksecPerTransfer - [double]$a.AvgDisksecPerTransfer; $db = [double]$b.AvgDisksecPerTransfer_Base - [double]$a.AvgDisksecPerTransfer_Base
$R.disk_ms = $(if ($db -gt 0 -and $b.Frequency_PerfTime -gt 0) { [math]::Round(($dn / $b.Frequency_PerfTime) / $db * 1000, 2) } else { $null })
$R.disk_io = $db
$os = Get-CimInstance Win32_OperatingSystem
$R.ram_pct = [math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
$R.processes = @(Get-Process).Count
$R.services = @(Get-Service | Where-Object { $_.Status -eq 'Running' }).Count
$c = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
$R.free_gb = [math]::Round($c.FreeSpace / 1GB, 1); $R.free_pct = [math]::Round($c.FreeSpace / $c.Size * 100, 1)
$t = 0; foreach ($p in $env:TEMP, "$env:windir\Temp") { $t += (Get-ChildItem $p -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum }
$R.temp_gb = [math]::Round($t / 1GB, 2)
$since = (Get-Date).AddDays(-7)
$R.errors_7d = @(Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; Level = 1, 2; StartTime = $since } -MaxEvents 5000).Count
$R.crashes_7d = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41, 1001, 6008; StartTime = $since } -MaxEvents 500).Count
# startup apps that are enabled
$en = 0
foreach ($k in 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
    $it = Get-Item $k; if (-not $it) { continue }
    $ap = if ($k -like 'HKCU*') { 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' } elseif ($k -like '*WOW6432*') { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' } else { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    foreach ($v in $it.GetValueNames()) { if (-not $v) { continue }; $b0 = (Get-ItemProperty $ap).$v; if (-not $b0 -or ($b0[0] % 2) -eq 0) { $en++ } }
}
foreach ($f in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {
    $ap = if ($f -like "$env:APPDATA*") { 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' } else { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
    foreach ($x in Get-ChildItem $f -File -Force | Where-Object { $_.Name -ne 'desktop.ini' }) { $b0 = (Get-ItemProperty $ap).($x.Name); if (-not $b0 -or ($b0[0] % 2) -eq 0) { $en++ } }
}
$R.startup = $en
$R | ConvertTo-Json -Depth 4 -Compress
"""

# (key, label, unit, lower_is_better, relative threshold, minimum absolute change) - a change must pass BOTH
# before it counts as better/worse (idle CPU 0.8% -> 1.9% is noise, not "worse").
METRICS = [
    ("boot_s", "Boot time (Windows' own measurement)", "s", True, 0.08, 2.0),
    ("startup", "Apps starting with Windows", "", True, 0.0, 1),
    ("disk_ms", "Disk response time", "ms", True, 0.25, 1.0),
    ("cpu", "CPU use while idle", "%", True, 0.3, 3.0),
    ("ram_pct", "Memory in use", "%", True, 0.1, 3.0),
    ("processes", "Running processes", "", True, 0.1, 10),
    ("free_gb", "Free space on the system drive", "GB", False, 0.03, 1.0),
    ("temp_gb", "Temporary files", "GB", True, 0.2, 0.2),
    ("errors_7d", "Errors in the event log (7 days)", "", True, 0.2, 5),
    ("crashes_7d", "Crashes / unexpected shutdowns (7 days)", "", True, 0.0, 1),
    ("updates_missing", "Missing Windows updates", "", True, 0.0, 1),
]


def normalise(raw, updates_missing=None):
    raw = raw if isinstance(raw, dict) else {}
    s = dict(raw)
    boots = raw.get("boot") or []
    if isinstance(boots, dict) and isinstance(boots.get("value"), list):
        boots = boots["value"]
    boots = [b for b in (boots if isinstance(boots, list) else [boots]) if isinstance(b, dict)]
    try:
        s["boot_s"] = round(float(boots[0]["total"]) / 1000.0, 1) if boots and boots[0].get("total") else None
    except (TypeError, ValueError):
        s["boot_s"] = None
    s["boot_time"] = boots[0].get("time") if boots else None
    if updates_missing is not None:
        s["updates_missing"] = updates_missing
    return s


class Store(object):
    """Measurements on disk. add() may run in a worker thread (scan / Guided Fix) while the page reads .items."""
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.items = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.items = json.load(f)
        except Exception:
            self.items = []
        if not isinstance(self.items, list):
            self.items = []
        self.items = [x for x in self.items if isinstance(x, dict) and x.get("id")]

    def add(self, snap, label):
        snap = dict(snap)
        snap["id"] = uuid.uuid4().hex[:8]
        snap["label"] = label
        snap.setdefault("time", datetime.now().isoformat(timespec="seconds"))
        with self.lock:
            self.items = (self.items + [snap])[-30:]     # new list: readers iterating the old one are unaffected
            self.save()
        return snap

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.items, f, indent=1, default=str)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def get(self, sid):
        return next((x for x in self.items if x.get("id") == sid), None)


def compare(before, after):
    """Rows: (label, before_text, after_text, verdict 'better'|'worse'|'same'|'n/a', note)."""
    rows = []
    for key, label, unit, lower, thr, min_abs in METRICS:
        a, b = before.get(key), after.get(key)
        fa = lambda v: "--" if v is None else ("%s %s" % (v, unit)).strip()
        if a is None or b is None:
            rows.append((label, fa(a), fa(b), "n/a", ""))
            continue
        try:
            a, b = float(a), float(b)
        except (TypeError, ValueError):
            rows.append((label, fa(a), fa(b), "n/a", ""))
            continue
        diff = b - a
        rel = abs(diff) / max(abs(a), 1e-9) if a else (1.0 if diff else 0.0)
        if diff == 0 or (rel <= thr and thr > 0) or abs(diff) < min_abs:
            v = "same"
        else:
            v = "better" if (diff < 0) == lower else "worse"
        note = ""
        if diff and v != "same":
            note = "%s%g %s" % ("+" if diff > 0 else "", round(diff, 2), unit)
        rows.append((label, fa(before.get(key)), fa(after.get(key)), v, note.strip()))
    if before.get("boot_time") and before.get("boot_time") == after.get("boot_time"):
        rows[0] = (rows[0][0], rows[0][1], rows[0][2], "n/a", "no restart since - restart to measure")
    return rows


def summary_lines(before, after):
    out = []
    for label, a, b, v, note in compare(before, after):
        if v in ("better", "worse"):
            out.append("%s: %s -> %s (%s)" % (label, a, b, v))
    return out or ["No measurable change yet (some values need a restart or a few days)."]


def take_snapshot(app, label):
    """Blocking (run in a thread; thread-safe). Returns the stored snapshot, or None. Never raises."""
    try:
        raw = core.run_ps_json(SNAP_PS, 180, "Measurement")
        if raw.get("status") == "error" and "time" not in raw:
            return None
        upd = getattr(app, "update_result", None)
        missing = upd["counts"]["missing"] if isinstance(upd, dict) and upd.get("ok") and isinstance(upd.get("counts"), dict) else None
        snap = normalise(raw, missing)
        return app.baselines.add(snap, label)
    except Exception as e:
        core.log_error("take_snapshot", e)
        return None


def snap_name(s):
    """'Full scan 2026-10-09 14:02' already carries its date - don't print it twice."""
    label, t = s.get("label") or "Measurement", (s.get("time") or "")[:16].replace("T", " ")
    return label if (not t or t[:10] in label) else "%s  (%s)" % (label, t)
