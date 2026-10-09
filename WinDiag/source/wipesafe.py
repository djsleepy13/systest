"""
Drive-wipe safety layers (3.2).

  1. Hard blocks      - Windows/boot, WinDiag's own drive, the Reports drive, page file, hibernation file, crash-dump
                        location, Windows Recovery (WinRE), Hyper-V VM disks, attached VHDs, Storage Spaces pools,
                        dynamic (software RAID) disks, hardware RAID volumes, cluster disks, drives with running programs,
                        read-only disks, laptops running on battery.
  2. Identity lock    - the drive is pinned by serial + size + model; re-checked right before the wipe starts and again
                        by the wipe script itself (if the disk number now points at another drive, nothing is erased).
  3. Contents preview - top folders, most recent files, Windows user folders, data size - so you SEE what you're erasing.
  4. Confirmations    - two tick boxes, type the last 4 characters of the serial, 10-second locked button, final summary,
                        optional USB unplug / re-plug check, 10-second countdown with Cancel, technician PIN.
  5. Afterwards       - random-sample check that the drive now reads back zeros, wipe log, HTML erasure certificate.
Everything in this module is read-only except runner_script()/partition_script(), which are only launched by the wizard.
"""
import hashlib
import html
import json
import os
import random
import re
import time
from datetime import datetime

import core

WIPE_CHECK_PS = r"""
# WINDIAG_WIPE_CHECK
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$N = __N__
$sw = [Diagnostics.Stopwatch]::StartNew()
$R = [ordered]@{ number = $N }
$pd = Get-PhysicalDisk | Where-Object { "$($_.DeviceId)" -eq "$N" } | Select-Object -First 1
$d = Get-Disk -Number $N
if (-not $pd -or -not $d) { $R.missing = $true; $R | ConvertTo-Json -Compress; exit }
$R.model = "$($pd.FriendlyName)".Trim(); $R.serial = "$($pd.SerialNumber)".Trim(); $R.size = [int64]$pd.Size
$R.bus = "$($pd.BusType)"; $R.media = "$($pd.MediaType)"; $R.unique_id = "$($d.UniqueId)"; $R.health = "$($pd.HealthStatus)"
$R.is_boot = [bool]$d.IsBoot; $R.is_system = [bool]$d.IsSystem; $R.clustered = [bool]$d.IsClustered
$R.readonly = [bool]$d.IsReadOnly; $R.offline = [bool]$d.IsOffline; $R.style = "$($d.PartitionStyle)"
$R.pools = @(Get-StoragePool -IsPrimordial $false | Where-Object { @($_ | Get-PhysicalDisk | ForEach-Object { "$($_.DeviceId)" }) -contains "$N" } | ForEach-Object { $_.FriendlyName })
if ("$($pd.CannotPoolReason)" -match 'In a Pool' -and -not $R.pools.Count) { $R.pools = @('(storage pool)') }
$R.dynamic = [bool](Get-CimInstance Win32_DiskPartition -Filter "DiskIndex=$N" | Where-Object { $_.Type -match 'Logical Disk Manager' })
$parts = @(Get-Partition -DiskNumber $N)
$letters = @($parts | Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter)".Trim([char]0).Trim() } | Where-Object { $_ })
$R.letters = $letters
$R.recovery_parts = @($parts | Where-Object { "$($_.GptType)" -eq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' -or $_.MbrType -eq 39 } | ForEach-Object { $_.PartitionNumber })
$re = (reagentc /info 2>$null) -join "`n"
if ($re -match '(?i)harddisk(\d+)\\partition(\d+)') { $R.winre_disk = [int]$Matches[1]; $R.winre_part = [int]$Matches[2] }
$R.pagefile = @(Get-CimInstance Win32_PageFileUsage | ForEach-Object { $_.Name } | Where-Object { $letters -contains $_.Substring(0, 1) })
$R.hiberfil = @(foreach ($l in $letters) { if (Test-Path -LiteralPath "$($l):\hiberfil.sys") { "$($l):\hiberfil.sys" } })
$cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$R.dump = @(foreach ($p in @($cc.DumpFile, $cc.DedicatedDumpFile, $cc.MinidumpDir)) { if ($p) { $e = [Environment]::ExpandEnvironmentVariables("$p"); if ($letters -contains $e.Substring(0, 1)) { $e } } })
$R.vhd_hosted = @(Get-Disk | Where-Object { $_.Location -and $letters -contains "$($_.Location)".Substring(0, 1) -and "$($_.Location)" -match '^[A-Za-z]:\\' } | ForEach-Object { "$($_.Location)" })
$R.hyperv = @()
if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
    foreach ($vm in @(Get-VM)) {
        foreach ($hd in @($vm | Get-VMHardDiskDrive)) {
            if ($hd.DiskNumber -eq $N) { $R.hyperv += "$($vm.Name) (pass-through disk)" }
            elseif ($hd.Path -and $letters -contains "$($hd.Path)".Substring(0, 1)) { $R.hyperv += "$($vm.Name): $($hd.Path)" }
        }
        if ($vm.Path -and $letters -contains "$($vm.Path)".Substring(0, 1)) { $R.hyperv += "$($vm.Name): configuration in $($vm.Path)" }
    }
}
$R.procs = @(Get-Process | Where-Object { $_.Path -and $letters -contains $_.Path.Substring(0, 1) } | Select-Object -First 15 | ForEach-Object { "$($_.ProcessName) ($($_.Path))" })
$R.services = @(Get-CimInstance Win32_Service -Filter "State='Running'" | Where-Object { $p = "$($_.PathName)".Trim('"', ' '); $p.Length -gt 2 -and $p[1] -eq ':' -and $letters -contains $p.Substring(0, 1) } | Select-Object -First 10 | ForEach-Object { $_.Name })
$R.bitlocker = @(foreach ($l in $letters) { $b = Get-BitLockerVolume -MountPoint "$($l):"; if ($b -and "$($b.VolumeStatus)" -ne 'FullyDecrypted') { "$($l): $($b.VolumeStatus)" } })
$budget = [math]::Max(3, 14 / [math]::Max(1, $letters.Count))
$R.contents = @(foreach ($l in $letters) {
    $root = "$($l):\"
    $v = Get-Volume -DriveLetter $l
    $top = @(Get-ChildItem -LiteralPath $root -Force | Where-Object { $_.Name -notin 'System Volume Information', '$RECYCLE.BIN' } |
             Sort-Object LastWriteTime -Descending | Select-Object -First 14 | ForEach-Object {
                 [ordered]@{ name = $_.Name; dir = [bool]$_.PSIsContainer; time = $_.LastWriteTime.ToString('yyyy-MM-dd'); size = $(if ($_.PSIsContainer) { $null } else { [int64]$_.Length }) } })
    $users = @(if (Test-Path -LiteralPath "$($root)Users") { Get-ChildItem -LiteralPath "$($root)Users" -Directory -Force | Where-Object { $_.Name -notin 'Public', 'Default', 'Default User', 'All Users', 'defaultuser0' } | ForEach-Object { $_.Name } })
    $t0 = $sw.Elapsed.TotalSeconds; $files = 0; $partial = $false
    $q = New-Object System.Collections.Queue; $q.Enqueue([IO.DirectoryInfo]$root)
    $best = New-Object System.Collections.Generic.List[object]
    while ($q.Count) {
        if ($sw.Elapsed.TotalSeconds - $t0 -gt $budget) { $partial = $true; break }
        $dir = $q.Dequeue()
        try { $items = $dir.GetFileSystemInfos() } catch { continue }
        foreach ($it in $items) {
            if ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($it -is [IO.DirectoryInfo]) { if ($it.Name -notin 'System Volume Information', '$RECYCLE.BIN') { $q.Enqueue($it) } }
            else {
                $files++; $best.Add($it)
                if ($best.Count -gt 300) { $keep = @($best | Sort-Object LastWriteTime -Descending | Select-Object -First 12); $best.Clear(); foreach ($k in $keep) { $best.Add($k) } }
            }
        }
    }
    $recent = @($best | Sort-Object LastWriteTime -Descending | Select-Object -First 12 | ForEach-Object { [ordered]@{ path = $_.FullName; time = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'); size = [int64]$_.Length } })
    [ordered]@{ letter = $l; label = "$($v.FileSystemLabel)"; fs = "$($v.FileSystem)"; size = [int64]$v.Size; used = [int64]($v.Size - $v.SizeRemaining)
                windows = [bool](Test-Path -LiteralPath "$($root)Windows\System32"); users = $users; top = $top; recent = $recent; files = $files; partial = $partial }
})
$R | ConvertTo-Json -Depth 6 -Compress
"""

IDENTITY_PS = r"""
# WINDIAG_WIPE_IDENTITY
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$R = [ordered]@{ disks = @(Get-PhysicalDisk | ForEach-Object {
    $n = "$($_.DeviceId)"; $d = Get-Disk -Number $n
    [ordered]@{ number = [int]$n; model = "$($_.FriendlyName)".Trim(); serial = "$($_.SerialNumber)".Trim(); size = [int64]$_.Size; is_boot = [bool]$d.IsBoot; is_system = [bool]$d.IsSystem } }) }
$R | ConvertTo-Json -Depth 4 -Compress
"""


def _l(x):
    # PS 5.1 without Remove-TypeData: {"value": [...], "Count": n}
    if isinstance(x, dict) and "value" in x and set(x) <= {"value", "Count", "Length"}:
        x = x["value"]
    return [i for i in x if i is not None] if isinstance(x, list) else ([] if x in (None, "", {}) else [x])


def _s(x):
    """Plain text (PS 5.1 can wrap strings as {'value': ..., 'PSPath': ...})."""
    if isinstance(x, dict):
        x = x.get("value", "")
    if x is None:
        return ""
    if isinstance(x, list):
        return ", ".join(_s(i) for i in x if i is not None)
    return x if isinstance(x, str) else str(x)


def _ls(x):
    return [t for t in (_s(i) for i in _l(x)) if t]


def _i(x, default=0):
    try:
        return int(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else int(float(_s(x).replace(",", ".")))
    except (TypeError, ValueError, OverflowError):
        return default


def fmt_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "--"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or u == "TB":
            return ("%.0f %s" if u == "B" else "%.1f %s") % (n, u)
        n /= 1000.0


def norm(s):
    return re.sub(r"[^A-Za-z0-9]", "", str(s or "")).upper()


def fingerprint(x):
    return (norm(_s(x.get("model"))), norm(_s(x.get("serial"))), _i(x.get("size")))


def same_drive(a, b):
    fa, fb = fingerprint(a), fingerprint(b)
    return fa[2] == fb[2] and fa[2] > 0 and fa[0] == fb[0] and fa[1] == fb[1]


def serial_code(x):
    """What the user must type: last 4 letters/digits of the serial (or the size in GB if there is no serial)."""
    s = norm(_s(x.get("serial")))
    if len(s) >= 4:
        return s[-4:], "the last 4 characters of the serial number"
    return str(int(round(_i(x.get("size")) / 1e9))), "the drive size in GB"


def check(number):
    r = core.run_ps_json(WIPE_CHECK_PS.replace("__N__", str(int(number))), 120, "Wipe safety check")
    return normalize_check(r)


def normalize_check(r):
    """Type-safe WIPE_CHECK_PS result (PS 5.1 quirks, missing cmdlets on Server/LTSC)."""
    r = r if isinstance(r, dict) else {"status": "error", "detail": "no data"}
    for k in ("letters", "pagefile", "hiberfil", "dump", "vhd_hosted", "hyperv", "procs", "services", "bitlocker", "pools"):
        r[k] = _ls(r.get(k))
    r["recovery_parts"] = [_i(x) for x in _l(r.get("recovery_parts"))]
    for k in ("model", "serial", "bus", "media", "style", "health", "unique_id"):
        if k in r:
            r[k] = _s(r.get(k))
    if "winre_disk" in r:
        r["winre_disk"] = _i(r.get("winre_disk"), None)
    r["contents"] = [c for c in _l(r.get("contents")) if isinstance(c, dict)]
    for c in r["contents"]:
        c["letter"], c["label"], c["fs"] = _s(c.get("letter")), _s(c.get("label")), _s(c.get("fs"))
        c["users"] = _ls(c.get("users"))
        c["top"] = [x for x in _l(c.get("top")) if isinstance(x, dict)]
        c["recent"] = [x for x in _l(c.get("recent")) if isinstance(x, dict)]
        for x in c["top"] + c["recent"]:
            for k in ("name", "path", "time"):
                if k in x:
                    x[k] = _s(x.get(k))
    return r


def identity(number):
    """Current identity of disk <number> right now (None if gone)."""
    r = core.run_ps_json(IDENTITY_PS, 60, "Drive identity check")
    for x in _l(r.get("disks")):
        if isinstance(x, dict) and _i(x.get("number"), -1) == int(number):
            return x
    return None


def present_serials():
    r = core.run_ps_json(IDENTITY_PS, 60, "Drive identity check")
    if r.get("status") == "error":
        return None
    return {norm(_s(x.get("serial"))) + ":%s" % _i(x.get("size")) for x in _l(r.get("disks")) if isinstance(x, dict)}


def power_state():
    """(has_battery, on_ac).  Desktop -> (False, True)."""
    try:
        import battery
        st = battery.live_status()
    except Exception:
        st = None
    if not st:
        return False, True
    ac, pct, left, flag = st
    no_batt = bool(flag & 128) or flag == 255
    return (not no_batt), (ac or no_batt)


def blockers(d, chk, windiag_disk=None, reports_disk=None, power=None):
    """Hard blocks -> list of (title, detail). Any entry means the wipe can't start."""
    B = []
    d = d if isinstance(d, dict) else {}
    chk = normalize_check(dict(chk) if isinstance(chk, dict) else None)
    n = d.get("number")
    if chk.get("missing"):
        return [("Drive not found", "Disk %s is no longer attached. Refresh the drive list." % n)]
    if chk.get("status") == "error" and not chk.get("model"):
        return [("Safety check failed", "Couldn't run the safety check (%s). Wiping is blocked until it runs." % (_s(chk.get("detail")) or "unknown error")[:120])]
    if d.get("model") and chk.get("model") and not same_drive(d, chk):
        B.append(("Drive changed", "Disk %s is now a different drive than the one shown (serial/size/model don't match). Refresh the list." % n))
    if d.get("is_system") or d.get("is_boot") or chk.get("is_system") or chk.get("is_boot"):
        B.append(("Windows is on this drive", "It holds Windows or the boot files."))
    sysl = (os.environ.get("SystemDrive", "C:")[:1]).upper()
    if sysl in [x.upper() for x in chk.get("letters", [])]:
        B.append(("System drive", "It contains %s: (the Windows drive)." % sysl))
    if windiag_disk is not None and n == windiag_disk:
        B.append(("WinDiag runs from it", "Copy WinDiag to another drive first."))
    if reports_disk is not None and n == reports_disk:
        B.append(("WinDiag's Reports folder is on it", "The wipe log and certificate must be saved to a different drive."))
    if chk.get("pagefile"):
        B.append(("Page file", "Windows' page file is on it: %s." % ", ".join(chk["pagefile"])))
    if chk.get("hiberfil"):
        B.append(("Hibernation file", "%s is on it." % ", ".join(chk["hiberfil"])))
    if chk.get("dump"):
        B.append(("Crash-dump location", "Windows writes crash dumps here: %s." % ", ".join(chk["dump"][:2])))
    if chk.get("winre_disk") == n:
        B.append(("Windows Recovery", "Windows' recovery environment (WinRE) is on this drive."))
    if chk.get("hyperv"):
        B.append(("Hyper-V virtual machines", "; ".join(chk["hyperv"][:4])))
    if chk.get("vhd_hosted"):
        B.append(("Virtual disks attached", "Attached VHD(X) files live on it: %s." % ", ".join(chk["vhd_hosted"][:3])))
    if chk.get("pools"):
        B.append(("Storage Spaces", "Member of storage pool %s. Remove it from the pool in Storage Spaces first." % ", ".join(chk["pools"])))
    if chk.get("dynamic"):
        B.append(("Dynamic disk / software RAID", "Part of a Windows dynamic volume (mirror / span / RAID-5). Break the volume in Disk Management first."))
    if (_s(chk.get("bus")) or _s(d.get("bus"))).upper() == "RAID":
        B.append(("Hardware RAID volume", "This is a RAID array, not one drive. Use the RAID controller's tools."))
    if chk.get("clustered"):
        B.append(("Cluster disk", "The disk belongs to a failover cluster."))
    if chk.get("procs") or chk.get("services"):
        B.append(("In use", "Running from it: %s. Close them first." % ", ".join((chk.get("procs") or [])[:3] + (chk.get("services") or [])[:3])))
    if chk.get("readonly"):
        B.append(("Read-only", "The disk is write-protected (switch on the drive/adapter, or policy)."))
    if power is not None:
        has_batt, on_ac = power
        if has_batt and not on_ac:
            B.append(("On battery", "Plug in the charger - a laptop dying mid-wipe leaves the drive half-erased."))
    return B


def warnings(d, chk):
    W = []
    d = d if isinstance(d, dict) else {}
    chk = normalize_check(dict(chk) if isinstance(chk, dict) else None)
    v = d.get("verdict") if isinstance(d.get("verdict"), dict) else {}
    if v.get("status") == "CRITICAL":
        W.append(("Failing drive", "The wipe may stop at bad sectors and can take much longer. For disposal of a failing drive, physical destruction is the safe option."))
    kind = _s(v.get("kind"))
    if "SSD" in kind or (chk.get("media") or "").upper() == "SSD":
        W.append(("SSD", "A zero-fill makes the data unreadable through normal means. The maker's Secure Erase / Sanitize (Samsung Magician, WD Dashboard, "
                         "Crucial Storage Executive...) also clears spare flash areas."))
    for c in chk.get("contents", []):
        if c.get("windows"):
            W.append(("Windows installation found", "%s: has a Windows folder - maybe another PC's system drive." % c["letter"]))
        if c.get("users"):
            W.append(("User folders", "%s:\\Users has profiles: %s" % (c["letter"], ", ".join(c["users"][:6]))))
    for b in chk.get("bitlocker", []):
        W.append(("BitLocker", "%s - the wipe removes it too." % b))
    return W


def used_bytes(chk):
    chk = chk if isinstance(chk, dict) else {}
    return sum(_i(c.get("used")) for c in _l(chk.get("contents")) if isinstance(c, dict))


def estimate_seconds(size, bus, media):
    b, m = (bus or "").upper(), (media or "").upper()
    mbps = 35 if b == "USB" else 900 if b == "NVME" else 400 if m == "SSD" else 140
    return int((size or 0) / (mbps * 1e6))


def fmt_dur(s):
    s = int(max(0, s))
    h, m = divmod(s // 60, 60)
    return "%dh %02dm" % (h, m) if h else "%dm %02ds" % (m, s % 60)


def _q(s):
    return "'" + str(s).replace("'", "''") + "'"


def diskpart_clean(number):
    return "select disk %d\nattributes disk clear readonly\nonline disk noerr\nclean all\n" % int(number)


def diskpart_partition(number, label="Wiped"):
    return 'select disk %d\nconvert gpt noerr\ncreate partition primary\nformat fs=ntfs quick label="%s"\nassign\n' % (int(number), label)


def runner_script(chk, status_path, log_path, dp_path):
    """Visible PowerShell window. Re-checks identity itself, then runs diskpart clean all. Writes JSON status."""
    n = int(chk["number"])
    return r"""
$ErrorActionPreference = 'Continue'
try { $Host.UI.RawUI.WindowTitle = 'WinDiag - wiping disk %(n)d' } catch {}
$status = %(st)s; $log = %(log)s; $dp = %(dp)s
function Put($h) { $h.time = (Get-Date).ToString('o'); ($h | ConvertTo-Json -Compress) | Set-Content -LiteralPath $status -Encoding UTF8 }
Write-Host ''
Write-Host '  WinDiag drive wipe' -ForegroundColor Cyan
Write-Host ('  Disk %(n)d  -  ' + %(model)s + '  -  serial ' + %(serial)s)
Put @{ state = 'verifying' }
$pd = Get-PhysicalDisk | Where-Object { "$($_.DeviceId)" -eq '%(n)d' } | Select-Object -First 1
$d = Get-Disk -Number %(n)d
$norm = { param($s) ("$s" -replace '[^A-Za-z0-9]', '').ToUpper() }
$ok = $pd -and $d -and ((& $norm $pd.SerialNumber) -eq (& $norm %(serial)s)) -and ([int64]$pd.Size -eq %(size)d) -and ((& $norm $pd.FriendlyName) -eq (& $norm %(model)s)) -and -not $d.IsBoot -and -not $d.IsSystem
if (-not $ok) {
    Put @{ state = 'aborted'; reason = 'Disk %(n)d is not the drive you confirmed any more (serial / size / model changed, or it now holds Windows). Nothing was erased.' }
    Write-Host '  STOPPED: disk %(n)d is not the drive you confirmed. Nothing was erased.' -ForegroundColor Red
    Read-Host '  Press Enter to close'
    exit 2
}
Write-Host '  Identity confirmed. Erasing - do NOT unplug the drive or close this window.' -ForegroundColor Yellow
$start = Get-Date
Put @{ state = 'wiping'; start = $start.ToString('o') }
('=== WinDiag wipe  disk %(n)d  ' + %(model)s + '  serial ' + %(serial)s + '  started ' + $start.ToString('o')) | Out-File -LiteralPath $log -Encoding UTF8
& %(diskpart)s /s $dp 2>&1 | Tee-Object -FilePath $log -Append
$rc = $LASTEXITCODE
$end = Get-Date
('=== diskpart exit code ' + $rc + '  finished ' + $end.ToString('o')) | Out-File -LiteralPath $log -Encoding UTF8 -Append
Put @{ state = $(if ($rc -eq 0) { 'cleaned' } else { 'failed' }); rc = $rc; start = $start.ToString('o'); end = $end.ToString('o') }
if ($rc -eq 0) { Write-Host '  Erase finished. WinDiag is now checking the drive reads back zeros.' -ForegroundColor Green; Start-Sleep 4 }
else { Write-Host ('  diskpart reported an error (code ' + $rc + '). See the log: ' + $log) -ForegroundColor Red; Read-Host '  Press Enter to close' }
""" % {"n": n, "st": _q(status_path), "log": _q(log_path), "dp": _q(dp_path), "model": _q(chk.get("model") or ""), "serial": _q(chk.get("serial") or ""),
       "size": _i(chk.get("size")), "diskpart": _q(core.sys32("diskpart"))}


def read_status(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.loads(f.read() or "{}")
    except (OSError, ValueError):
        return {}


def verify_zeros(reader, size, samples=768, block=65536, progress=None, cancel=None):
    """Read random blocks across the whole drive; every byte must be 0. Returns dict(checked, nonzero=[offsets], errors=[offsets])."""
    rnd = random.SystemRandom()
    size = size - size % 4096
    top = max(0, size - block)
    offs = {0, top - top % 4096}
    while len(offs) < min(samples, max(1, top // block)):
        o = rnd.randrange(0, max(1, top))
        offs.add(o - o % 4096)
    offs = sorted(offs)
    res = {"checked": 0, "nonzero": [], "errors": [], "bytes": 0}
    for i, o in enumerate(offs):
        if cancel is not None and cancel.is_set():
            break
        data = reader.read_bytes(o, block)
        if data is None:
            res["errors"].append(o)
        elif data.count(0) != len(data):
            res["nonzero"].append(o)
        res["checked"] += 1
        res["bytes"] += block
        if progress and i % 16 == 0:
            progress(i + 1, len(offs))
    if progress:
        progress(len(offs), len(offs))
    return res


def cert_id(rec):
    blob = json.dumps({k: rec.get(k) for k in ("model", "serial", "size", "start", "end", "result", "checked", "pc")}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:20].upper()


def certificate_html(rec):
    e = lambda x: html.escape(str(x if x not in (None, "") else "--"))
    ok = rec.get("result") == "PASSED"
    col = "#16a34a" if ok else "#dc2626"
    rows = [("Drive model", rec.get("model")), ("Serial number", rec.get("serial")), ("Capacity", fmt_bytes(rec.get("size"))),
            ("Interface / type", "%s / %s" % (rec.get("bus") or "--", rec.get("media") or "--")), ("Disk number at time of wipe", rec.get("number")),
            ("Method", "Microsoft diskpart 'clean all' - every sector overwritten once with zeros (single pass). "
                       "Comparable to NIST SP 800-88 'Clear' for hard drives."),
            ("Started", rec.get("start")), ("Finished", rec.get("end")), ("Duration", rec.get("duration")),
            ("Verification", "%s random samples (%s) across the whole drive read back as zeros%s" % (
                rec.get("checked"), fmt_bytes(rec.get("vbytes")), "" if ok else " - FAILED: %s non-zero, %s unreadable" % (rec.get("nonzero"), rec.get("errors")))),
            ("After the wipe", rec.get("after") or "Left empty (uninitialised)"),
            ("Computer", rec.get("pc")), ("Operator (Windows account)", rec.get("user")), ("Software", "WinDiag %s" % core.APP_VERSION)]
    note = ("SSD / flash note: a zero-fill makes the data unreadable through the drive's normal interface. Spare / remapped flash blocks are managed by the "
            "drive's controller and are not reachable from Windows; for the highest assurance on SSDs also use the maker's Secure Erase / Sanitize, "
            "or physically destroy the drive.") if (rec.get("media") or "").upper() == "SSD" or (rec.get("bus") or "").upper() == "NVME" else ""
    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (e(k), e(v)) for k, v in rows)
    return """<!doctype html><html><head><meta charset="utf-8"><title>Data erasure certificate - %(serial)s</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;background:#f3f4f6;color:#111827;margin:0;padding:32px}
.c{max-width:820px;margin:auto;background:#fff;border:1px solid #d1d5db;border-radius:10px;padding:36px 44px}
h1{margin:0 0 4px;font-size:26px}.sub{color:#6b7280;margin-bottom:22px}.badge{display:inline-block;padding:6px 14px;border-radius:999px;color:#fff;background:%(col)s;font-weight:600}
table{width:100%%;border-collapse:collapse;margin:22px 0}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top;font-size:14px}
th{width:34%%;color:#374151;font-weight:600}.note{font-size:12.5px;color:#4b5563;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 14px}
.sig{display:flex;gap:40px;margin-top:40px}.sig div{flex:1;border-top:1px solid #9ca3af;padding-top:6px;font-size:12px;color:#6b7280}
.id{font-family:Consolas,monospace;font-size:12px;color:#6b7280;margin-top:18px}@media print{body{background:#fff;padding:0}.c{border:none}}</style></head>
<body><div class="c"><h1>Data erasure certificate</h1><div class="sub">Issued by WinDiag on %(date)s</div>
<span class="badge">%(res)s</span><table>%(body)s</table>%(note)s
<div class="sig"><div>Technician name &amp; signature</div><div>Date</div></div>
<div class="id">Certificate ID %(id)s &nbsp;·&nbsp; log: %(log)s</div></div></body></html>""" % {
        "serial": e(rec.get("serial")), "col": col, "date": e(rec.get("end") or datetime.now().strftime("%Y-%m-%d %H:%M")),
        "res": "ERASED AND VERIFIED" if ok else "ERASE NOT VERIFIED", "body": body, "note": ('<div class="note">%s</div>' % e(note)) if note else "",
        "id": e(rec.get("id")), "log": e(os.path.basename(rec.get("log") or ""))}


def save_certificate(report_dir, rec):
    rec["id"] = cert_id(rec)
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", "%s_%s" % (rec.get("model") or "drive", rec.get("serial") or ""))[:60]
    stamp = time.strftime("%Y%m%d_%H%M")
    path = os.path.join(report_dir, "Erasure-Certificate_%s_%s.html" % (safe, stamp))
    with open(path, "w", encoding="utf-8") as f:
        f.write(certificate_html(rec))
    with open(os.path.join(report_dir, "Erasure-Record_%s_%s.json" % (safe, stamp)), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, default=str)
    return path
