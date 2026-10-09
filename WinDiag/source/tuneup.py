"""
Tune-up: only safe, reversible, measurable changes.
  - Pending Windows updates        (online check - see updates.py)
  - Startup apps                   (enable/disable exactly like Task Manager: StartupApproved registry flags)
  - Power plan                     (powercfg)
  - Low disk space                 (temp size, Storage Sense, Disk Cleanup, Recycle Bin)
  - TRIM for SSDs                  (fsutil DisableDeleteNotify + Optimize-Volume -ReTrim)
  - Fast Startup                   (HiberbootEnabled - off helps when drivers/updates misbehave after "Shut down")
No registry "cleaning", no RAM "boosters", no service tweaking - those don't help and can break things.
"""
TUNE_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$R = [ordered]@{}
# power plans
$act = (powercfg /getactivescheme) -join ' '
$R.power_active = $(if ($act -match '([0-9a-f-]{36})\s+\((.+)\)') { [ordered]@{ guid = $matches[1]; name = $matches[2] } } else { $null })
$R.power_plans = @((powercfg /list) | ForEach-Object { if ($_ -match '([0-9a-f-]{36})\s+\((.+?)\)') { [ordered]@{ guid = $matches[1]; name = $matches[2] } } })
$R.battery = [bool](Get-CimInstance Win32_Battery)
$R.modern_standby = [bool]((powercfg /a) -join ' ' -match 'S0 Low Power Idle')
# TRIM
$q = (fsutil behavior query DisableDeleteNotify) -join ' '
$R.trim_ntfs = $(if ($q -match 'NTFS DisableDeleteNotify\s*=\s*(\d)') { [int]$matches[1] } elseif ($q -match 'DisableDeleteNotify\s*=\s*(\d)') { [int]$matches[1] } else { $null })
$R.ssd = [bool](Get-PhysicalDisk | Where-Object { $_.MediaType -eq 'SSD' -or $_.BusType -eq 'NVMe' })
$t = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag'
$R.optimize_task = "$($t.State)"
$ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Microsoft-Windows-Defrag' } -MaxEvents 1
$R.last_optimize = $(if ($ev) { $ev.TimeCreated.ToString('s') } else { '' })
# fast startup
$R.fast_startup = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled
$R.hibernate = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power').HibernateEnabled
$R.kp41_30d = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 50).Count
# disk space
$c = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
$R.free_gb = [math]::Round($c.FreeSpace / 1GB, 1); $R.size_gb = [math]::Round($c.Size / 1GB, 1)
$tt = 0; foreach ($p in $env:TEMP, "$env:windir\Temp") { $tt += (Get-ChildItem $p -Recurse -Force -File | Measure-Object Length -Sum).Sum }
$R.temp_gb = [math]::Round($tt / 1GB, 2)
$rb = 0; foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3') { $rb += (Get-ChildItem (Join-Path ($d.DeviceID + '\') '$Recycle.Bin') -Recurse -Force -File | Measure-Object Length -Sum).Sum }
$R.recycle_gb = [math]::Round($rb / 1GB, 2)
$R.storage_sense = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy').'01'
# startup apps
$items = @()
$map = @(
  @{ k = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; a = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; scope = 'Current user' },
  @{ k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; a = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; scope = 'All users' },
  @{ k = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; a = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'; scope = 'All users (32-bit)' })
foreach ($m in $map) {
    $it = Get-Item $m.k; if (-not $it) { continue }
    foreach ($v in $it.GetValueNames()) {
        if (-not $v) { continue }
        $b0 = (Get-ItemProperty $m.a).$v
        $items += [ordered]@{ name = $v; command = "$($it.GetValue($v))"; scope = $m.scope; approved = $m.a; value = $v; enabled = (-not $b0 -or ($b0[0] % 2) -eq 0) }
    }
}
foreach ($f in @(@{ p = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; a = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; scope = 'Current user (folder)' },
                 @{ p = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; a = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; scope = 'All users (folder)' })) {
    foreach ($x in Get-ChildItem $f.p -File -Force | Where-Object { $_.Name -ne 'desktop.ini' }) {
        $b0 = (Get-ItemProperty $f.a).($x.Name)
        $items += [ordered]@{ name = $x.BaseName; command = $x.FullName; scope = $f.scope; approved = $f.a; value = $x.Name; enabled = (-not $b0 -or ($b0[0] % 2) -eq 0) }
    }
}
$R.startup = $items
$R | ConvertTo-Json -Depth 4 -Compress
"""

PS_ARGS = "$ErrorActionPreference = 'Stop'\n$A = Get-Content -Raw -LiteralPath '{args}' | ConvertFrom-Json\n"

SET_STARTUP_PS = PS_ARGS + r"""
try {
    if (-not (Test-Path $A.approved)) { New-Item -Path $A.approved -Force | Out-Null }
    if ($A.enable) { $b = [byte[]](2,0,0,0,0,0,0,0,0,0,0,0) } else { $b = [byte[]](3,0,0,0) + [BitConverter]::GetBytes([DateTime]::Now.ToFileTime()) }
    New-ItemProperty -Path $A.approved -Name $A.value -Value $b -PropertyType Binary -Force | Out-Null
    @{ ok = $true } | ConvertTo-Json -Compress
} catch { @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress }
"""

SET_POWER_PS = PS_ARGS + r"""
$o = powercfg /setactive $A.guid 2>&1
@{ ok = ($LASTEXITCODE -eq 0); detail = "$o" } | ConvertTo-Json -Compress
"""

SET_FASTSTART_PS = PS_ARGS + r"""
try {
    if ($A.enable) { powercfg /hibernate on | Out-Null }
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -Value $(if ($A.enable) { 1 } else { 0 }) -Type DWord
    @{ ok = $true } | ConvertTo-Json -Compress
} catch { @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress }
"""

TRIM_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
fsutil behavior set DisableDeleteNotify 0 | Out-Null
$done = @()
$pds = @(Get-PhysicalDisk)
foreach ($v in Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystem -eq 'NTFS' }) {
    # Get-Disk | Get-PhysicalDisk does not bind on many systems - match the disk number to the physical disk's DeviceId
    $n = (Get-Partition -DriveLetter $v.DriveLetter | Select-Object -First 1).DiskNumber
    $pd = $pds | Where-Object { "$($_.DeviceId)" -eq "$n" } | Select-Object -First 1
    if ($pd.MediaType -eq 'SSD' -or $pd.BusType -eq 'NVMe') { Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim; $done += "$($v.DriveLetter):" }
}
Enable-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' | Out-Null
@{ ok = $true; trimmed = $done } | ConvertTo-Json -Compress
"""

EMPTY_RECYCLE_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
Clear-RecycleBin -Force
@{ ok = $true } | ConvertTo-Json -Compress
"""

SCHEMES = {"381b4222-f694-41f0-9685-ff5bb260df2e": "Balanced", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": "High performance",
           "a1841308-3541-4fab-bc81-f71556f20b4a": "Power saver", "e9a42b02-d5df-448d-aa00-03f14749eb61": "Ultimate Performance"}


def _l(x):
    if isinstance(x, dict) and isinstance(x.get("value"), list):     # PS 5.1 System.Array wrapper
        x = x["value"]
    return x if isinstance(x, list) else ([] if x is None or x == "" else [x])


def _s(x):
    if isinstance(x, dict):
        x = x.get("value")
    return "" if x is None or isinstance(x, (dict, list)) else str(x)


def _num(x, default=0.0):
    try:
        return float(_s(x).replace(",", ".")) if not isinstance(x, (int, float)) else float(x)
    except ValueError:
        return default


def low_space(free, size):
    """Low only when it really is: under 20 GB free, or under 10% AND under 100 GB (12% of a 2 TB drive is plenty)."""
    pct = free * 100.0 / size if size else 0
    return free < 20 or (pct < 10 and free < 100)


def assess(raw, upd=None):
    """Return list of items: id, title, status (OK/WARNING/INFO), value, why, actions [(label, action_id)]."""
    items = []
    raw = raw if isinstance(raw, dict) else {}
    # updates
    if upd:
        c = upd["counts"]
        st = "OK" if upd.get("ok") and not c["missing"] and not upd.get("reboot") else ("WARNING" if upd.get("ok") else "INFO")
        val = ("%d missing (%d security), %d driver update(s)%s" % (c["missing"], c["security"], c["drivers"], ", restart pending" if upd.get("reboot") else "")) if upd.get("ok") else "Could not check online"
    else:
        st, val = "INFO", "Not checked yet"
    items.append({"id": "updates", "title": "Windows updates", "status": st, "value": val,
                  "why": "Missing updates are the most common cause of security holes and many bugs. Checked online against Windows Update.",
                  "actions": [("Open Updates & Drivers", "page_updates")]})
    # startup
    su = [x for x in _l(raw.get("startup")) if isinstance(x, dict)]
    en = [s for s in su if s.get("enabled")]
    items.append({"id": "startup", "title": "Startup apps", "status": "WARNING" if len(en) >= 12 else ("INFO" if len(en) >= 7 else "OK"),
                  "value": "%d of %d enabled" % (len(en), len(su)),
                  "why": "Every app that starts with Windows slows the boot and uses memory. Disabling is reversible and exactly what Task Manager does.",
                  "actions": [("Manage below", "scroll_startup")]})
    # power
    pa = raw.get("power_active") or {}
    pa = pa[0] if isinstance(pa, list) and pa else pa
    pa = pa if isinstance(pa, dict) else {}
    name = _s(pa.get("name")) or "?"
    guid = _s(pa.get("guid")).lower()
    is_saver = guid == "a1841308-3541-4fab-bc81-f71556f20b4a"
    items.append({"id": "power", "title": "Power plan", "status": "WARNING" if is_saver and not raw.get("battery") else "OK",
                  "value": name + (" (modern standby device - Windows manages this)" if raw.get("modern_standby") and len(_l(raw.get("power_plans"))) <= 1 else ""),
                  "why": "Balanced is Microsoft's recommendation and boosts when needed. 'Power saver' on a desktop makes it slow; High performance only helps some desktops and uses more power.",
                  "actions": [("Choose plan", "power")]})
    # disk space
    free, size = _num(raw.get("free_gb")), _num(raw.get("size_gb"), 1.0) or 1.0
    pct = free * 100.0 / size if size else 0
    items.append({"id": "space", "title": "Free disk space (%s)" % "system drive", "status": "WARNING" if low_space(free, size) else "OK",
                  "value": "%.1f GB free of %.0f GB (%.0f%%)  ·  temp files %.2f GB  ·  Recycle Bin %.2f GB" % (free, size, pct, _num(raw.get("temp_gb")), _num(raw.get("recycle_gb"))),
                  "why": "Windows and updates need room to work: keep at least 20 GB free (more on small drives). Low space causes slowdowns and failed updates.",
                  "actions": [("Clear temp files", "clear_temp"), ("Empty Recycle Bin", "recycle"), ("Storage Sense", "storagesense")]})
    # TRIM
    if raw.get("ssd"):
        ok = raw.get("trim_ntfs") == 0 and raw.get("optimize_task") not in ("Disabled",)
        items.append({"id": "trim", "title": "TRIM for SSDs", "status": "OK" if ok else "WARNING",
                      "value": "TRIM %s, weekly optimisation %s, last run %s" % ("on" if raw.get("trim_ntfs") == 0 else "OFF", (_s(raw.get("optimize_task")) or "?").lower(),
                                                                                (_s(raw.get("last_optimize")) or "never")[:10]),
                      "why": "TRIM tells the SSD which blocks are free so it stays fast. Windows does it weekly - unless it has been switched off.",
                      "actions": [("Turn on + run TRIM now", "trim")]})
    # fast startup
    fs = raw.get("fast_startup")
    kp = int(_num(raw.get("kp41_30d")))
    items.append({"id": "faststart", "title": "Fast Startup", "status": "INFO" if fs == 1 and kp else "OK",
                  "value": ("On" if fs == 1 else "Off") + ("  ·  %d unexpected shutdown(s) in 30 days" % kp if kp else ""),
                  "why": "With Fast Startup, 'Shut down' doesn't fully restart Windows - drivers and some updates aren't reloaded. Turning it off is a common fix for "
                         "sleep/shutdown problems and devices that stop working; boot is a few seconds slower.",
                  "actions": [("Turn off" if fs == 1 else "Turn on", "faststart_off" if fs == 1 else "faststart_on")]})
    return items
