"""
WinDiag file tools
------------------
Quarantine  - reversible removal: the file is neutralised (XOR-encoded, can't run), its metadata
              (hash, ACL, timestamps, attributes) and whatever launched it (Run value, scheduled task,
              service, IFEO, WMI subscription, root certificate) are saved, then removed/disabled.
              Restore puts everything back. Defender's own quarantine is listed/restored too.
Recover     - Recycle Bin (all users, parsed from $I files), shadow copies (Previous Versions),
              File History, OneDrive recycle bin, Microsoft's Windows File Recovery (winfr).
Secure del  - overwrite + delete (honest about SSD limits), free-space wipe (cipher /w), TRIM.
"""
import json
import os
import shutil
import tempfile
import time
import uuid
from datetime import datetime

QROOT = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "WinDiag", "Quarantine")
SNAPROOT = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "WinDiag", "Snapshots")
WINFR_STORE = "ms-windows-store://pdp/?productid=9n26s50ln705"
WINFR_ID = "9N26S50LN705"

PS_ARGS = "$ErrorActionPreference = 'SilentlyContinue'\ntry { Remove-TypeData System.Array -ErrorAction Stop } catch {}\n$A = Get-Content -Raw -LiteralPath '{args}' | ConvertFrom-Json\n"

PS_COMMON = r"""
function Test-Protected([string]$p) {
    if (-not $p) { return 'no path' }
    $full = [IO.Path]::GetFullPath($p)
    if ($full -like "$env:windir\*" -and $full -notlike "$env:windir\Temp\*") { return 'inside the Windows folder' }
    if ($full -match '^[a-zA-Z]:\\?$') { return 'a whole drive' }
    if (Test-Path -LiteralPath $full -PathType Leaf) {
        $s = Get-AuthenticodeSignature -LiteralPath $full
        if ($s.IsOSBinary) { return 'a Windows system file' }
        if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'O=Microsoft Corporation') { return 'signed by Microsoft' }
    }
    return ''
}
Add-Type -Namespace WD -Name K32 -MemberDefinition '[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool MoveFileEx(string a, string b, int f);' -ErrorAction SilentlyContinue
"""

QUARANTINE_PS = PS_ARGS + PS_COMMON + r"""
$root = $A.root; $id = $A.id
$dir = Join-Path $root $id
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$m = [ordered]@{ id = $id; time = (Get-Date).ToString('s'); reason = $A.reason; title = $A.title; state = 'quarantined'; items = @(); errors = @(); pending_reboot = $false }
if ($A.restore_point) { try { Checkpoint-Computer -Description 'WinDiag - before quarantine' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop } catch {} }

function Q-File([string]$p, [bool]$killProc) {
    $why = Test-Protected $p
    if ($why) { $script:m.errors += "Refused to quarantine $p ($why)."; return }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { $script:m.errors += "File not found: $p"; return }
    if ($killProc) { Get-Process | Where-Object { $_.Path -eq $p } | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 800 }
    $fi = Get-Item -LiteralPath $p -Force
    $it = [ordered]@{ type = 'file'; path = $p; size = $fi.Length; sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
                      attrs = [int]$fi.Attributes; created = $fi.CreationTimeUtc.ToString('o'); modified = $fi.LastWriteTimeUtc.ToString('o')
                      sddl = (Get-Acl -LiteralPath $p).Sddl; payload = ('f{0}.bin' -f $script:m.items.Count); deleted = $false }
    try {
        $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite, Delete'); $buf = New-Object byte[] $fs.Length; [void]$fs.Read($buf, 0, $buf.Length); $fs.Close()
        for ($i = 0; $i -lt $buf.Length; $i++) { $buf[$i] = $buf[$i] -bxor 0xA5 }
        [IO.File]::WriteAllBytes((Join-Path $dir $it.payload), $buf)
    } catch { $script:m.errors += "Could not read $p : $($_.Exception.Message)"; return }
    try { [IO.File]::SetAttributes($p, 'Normal'); Remove-Item -LiteralPath $p -Force -ErrorAction Stop; $it.deleted = $true }
    catch {
        if ([WD.K32]::MoveFileEx($p, $null, 4)) { $it.deleted = 'at-reboot'; $script:m.pending_reboot = $true }
        else { $script:m.errors += "Could not delete $p (in use)." }
    }
    $script:m.items += $it
}

$e = $A.entry
if ($A.kind -eq 'entry' -and $e) {
    switch ($e.type) {
        'run' {
            $val = (Get-ItemProperty -LiteralPath $e.key).($e.value)
            $script:m.items += [ordered]@{ type = 'run'; key = $e.key; value = $e.value; data = "$val" }
            Remove-ItemProperty -LiteralPath $e.key -Name $e.value -Force
        }
        'task' {
            $xml = Export-ScheduledTask -TaskName $e.name -TaskPath $e.taskpath
            $xf = Join-Path $dir ('task{0}.xml' -f $script:m.items.Count); $xml | Set-Content -LiteralPath $xf -Encoding Unicode
            $script:m.items += [ordered]@{ type = 'task'; name = $e.name; taskpath = $e.taskpath; xml = (Split-Path $xf -Leaf) }
            Disable-ScheduledTask -TaskName $e.name -TaskPath $e.taskpath | Out-Null
        }
        'service' {
            $s = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $e.name)
            $script:m.items += [ordered]@{ type = 'service'; name = $e.name; startmode = $s.StartMode; state = $s.State }
            Stop-Service -Name $e.name -Force; Set-Service -Name $e.name -StartupType Disabled
        }
        'startup' { Q-File $e.file $false }
    }
    $prog = if ($e.target -and $e.target.path) { $e.target.path } else { $e.path }
    if ($A.include_file -and $prog -and -not (Test-Protected $prog)) { Q-File $prog $true }
}
elseif ($A.kind -eq 'file') { Q-File $A.path $true }
elseif ($A.kind -eq 'ifeo') {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + $A.ifeo.image
    $script:m.items += [ordered]@{ type = 'ifeo'; key = $k; data = $A.ifeo.debugger }
    Remove-ItemProperty -LiteralPath $k -Name Debugger -Force
}
elseif ($A.kind -eq 'wmi') {
    $c = Get-CimInstance -Namespace root\subscription -ClassName $A.wmi.class | Where-Object { $_.Name -eq $A.wmi.name } | Select-Object -First 1
    if ($c) {
        $cp = [ordered]@{}; foreach ($n in 'Name', 'CommandLineTemplate', 'ExecutablePath', 'WorkingDirectory', 'ScriptText', 'ScriptingEngine', 'ScriptFileName') { if ($c.$n) { $cp[$n] = $c.$n } }
        $filters = @()
        foreach ($b in Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Where-Object { $_.Consumer.Name -eq $c.Name }) {
            $f = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Where-Object { $_.Name -eq $b.Filter.Name } | Select-Object -First 1
            if ($f) { $filters += [ordered]@{ Name = $f.Name; Query = $f.Query; QueryLanguage = $f.QueryLanguage; EventNamespace = $f.EventNamespace }; Remove-CimInstance -InputObject $f }
            Remove-CimInstance -InputObject $b
        }
        $script:m.items += [ordered]@{ type = 'wmi'; class = $A.wmi.class; consumer = $cp; filters = $filters }
        Remove-CimInstance -InputObject $c
    } else { $script:m.errors += 'WMI consumer not found' }
}
elseif ($A.kind -eq 'cert') {
    $store = $A.cert.store; $cp = Join-Path $store $A.cert.thumb
    $c = Get-Item -LiteralPath $cp
    if ($c) {
        $cf = Join-Path $dir ('cert{0}.cer' -f $script:m.items.Count)
        [IO.File]::WriteAllBytes($cf, $c.Export('Cert'))
        $script:m.items += [ordered]@{ type = 'cert'; store = $store; thumb = $A.cert.thumb; subject = $c.Subject; file = (Split-Path $cf -Leaf); had_private_key = $c.HasPrivateKey }
        Remove-Item -LiteralPath $cp -Force -DeleteKey
    } else { $script:m.errors += 'Certificate not found' }
}
$m | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $dir 'manifest.json') -Encoding UTF8
@{ ok = ($m.items.Count -gt 0); id = $id; items = $m.items.Count; errors = $m.errors; pending_reboot = $m.pending_reboot } | ConvertTo-Json -Compress -Depth 4
"""

RESTORE_PS = PS_ARGS + r"""
$dir = Join-Path $A.root $A.id
$mf = Join-Path $dir 'manifest.json'
$m = Get-Content -Raw -LiteralPath $mf | ConvertFrom-Json
$errs = @(); $done = 0
foreach ($it in @($m.items)[(@($m.items).Count - 1)..0]) {
    try {
        switch ($it.type) {
            'file' {
                $buf = [IO.File]::ReadAllBytes((Join-Path $dir $it.payload)); for ($i = 0; $i -lt $buf.Length; $i++) { $buf[$i] = $buf[$i] -bxor 0xA5 }
                $target = $it.path
                if (Test-Path -LiteralPath $target) { $target = $target + '.restored' }
                New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
                [IO.File]::WriteAllBytes($target, $buf)
                if ($it.sddl) { $acl = Get-Acl -LiteralPath $target; $acl.SetSecurityDescriptorSddlForm($it.sddl); Set-Acl -LiteralPath $target -AclObject $acl }
                [IO.File]::SetCreationTimeUtc($target, [datetime]::Parse($it.created).ToUniversalTime()); [IO.File]::SetLastWriteTimeUtc($target, [datetime]::Parse($it.modified).ToUniversalTime())
                [IO.File]::SetAttributes($target, [IO.FileAttributes][int]$it.attrs)
            }
            'run' { if (-not (Test-Path -LiteralPath $it.key)) { New-Item -Path $it.key -Force | Out-Null }; New-ItemProperty -LiteralPath $it.key -Name $it.value -Value $it.data -PropertyType String -Force | Out-Null }
            'task' {
                if (Get-ScheduledTask -TaskName $it.name -TaskPath $it.taskpath) { Enable-ScheduledTask -TaskName $it.name -TaskPath $it.taskpath | Out-Null }
                else { Register-ScheduledTask -TaskName $it.name -TaskPath $it.taskpath -Xml (Get-Content -Raw -LiteralPath (Join-Path $dir $it.xml)) | Out-Null }
            }
            'service' {
                $mode = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }[$it.startmode]; if (-not $mode) { $mode = 'Manual' }
                Set-Service -Name $it.name -StartupType $mode; if ($it.state -eq 'Running') { Start-Service -Name $it.name }
            }
            'ifeo' { New-ItemProperty -LiteralPath $it.key -Name Debugger -Value $it.data -PropertyType String -Force | Out-Null }
            'wmi' {
                $props = @{}; $it.consumer.PSObject.Properties | ForEach-Object { $props[$_.Name] = $_.Value }
                $c = New-CimInstance -Namespace root\subscription -ClassName $it.class -Property $props
                foreach ($f in @($it.filters)) {
                    $fp = @{}; $f.PSObject.Properties | ForEach-Object { $fp[$_.Name] = $_.Value }
                    $fi = New-CimInstance -Namespace root\subscription -ClassName __EventFilter -Property $fp
                    New-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -Property @{ Filter = [ref]$fi; Consumer = [ref]$c } | Out-Null
                }
            }
            'cert' { Import-Certificate -FilePath (Join-Path $dir $it.file) -CertStoreLocation ($it.store -replace '^Cert:\\', 'Cert:\') | Out-Null }
        }
        $done++
    } catch { $errs += "$($it.type): $($_.Exception.Message)" }
}
$m.state = 'restored'; $m | Add-Member -NotePropertyName restored -NotePropertyValue (Get-Date).ToString('s') -Force
$m | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $mf -Encoding UTF8
@{ ok = ($errs.Count -eq 0); restored = $done; errors = $errs } | ConvertTo-Json -Compress
"""

DEFENDER_Q_PS = r"""
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$ErrorActionPreference = 'SilentlyContinue'
$mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
$out = @(& $mp -Restore -ListAll 2>&1)
$items = @(); $cur = $null
foreach ($l in $out) {
    if ($l -match 'ThreatName\s*=\s*(.+)$') { $cur = [ordered]@{ threat = $matches[1].Trim(); files = @() }; $items += $cur }
    elseif ($cur -and $l -match '(file|containerfile):\s*(.+?)\s+quarantined at\s+(.+)$') { $cur.files += ("{0}  (quarantined {1})" -f $matches[2], $matches[3]) }
    elseif ($cur -and $l -match '(file|containerfile|regkey|process|service):\s*(.+)$') { $cur.files += $matches[2].Trim() }
}
$pref = Get-MpPreference
@{ items = $items; active = @(Get-MpThreat | Where-Object { $_.IsActive } | ForEach-Object { $_.ThreatName }); purge_days = $pref.QuarantinePurgeItemsAfterDelay } | ConvertTo-Json -Compress -Depth 4
"""

DEFENDER_REMOVE_ACTIVE_PS = r"""
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$ErrorActionPreference = 'Stop'
try {
    $before = @(Get-MpThreat | Where-Object { $_.IsActive } | ForEach-Object { $_.ThreatName })
    Remove-MpThreat
    Start-Sleep 3
    $after = @(Get-MpThreat | Where-Object { $_.IsActive } | ForEach-Object { $_.ThreatName })
    @{ ok = $true; before = $before; after = $after } | ConvertTo-Json -Compress
} catch { @{ ok = $false; detail = "$($_.Exception.Message)" } | ConvertTo-Json -Compress }
"""

DEFENDER_PURGE_PS = PS_ARGS + r"""
try {
    Set-MpPreference -QuarantinePurgeItemsAfterDelay ([int]$A.days) -ErrorAction Stop
    $now = (Get-MpPreference).QuarantinePurgeItemsAfterDelay
    @{ ok = ($now -eq [int]$A.days); now = $now; detail = $(if ($now -ne [int]$A.days) { 'Windows kept the old value - a policy (Group Policy / Intune) or Tamper Protection controls this setting.' } else { '' }) } | ConvertTo-Json -Compress
} catch { @{ ok = $false; detail = "$($_.Exception.Message)" } | ConvertTo-Json -Compress }
"""

DEFENDER_RESTORE_PS = PS_ARGS + r"""
$mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
$o = (& $mp -Restore -Name $A.threat 2>&1) -join ' '
@{ ok = ($LASTEXITCODE -eq 0); detail = $o } | ConvertTo-Json -Compress
"""

RECYCLE_LIST_PS = r"""
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$ErrorActionPreference = 'SilentlyContinue'
$out = New-Object System.Collections.ArrayList
foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3 OR DriveType=2') {
    $rb = Join-Path ($d.DeviceID + '\') '$Recycle.Bin'
    foreach ($sidDir in Get-ChildItem -LiteralPath $rb -Directory -Force) {
        $user = $sidDir.Name
        try { $user = (New-Object Security.Principal.SecurityIdentifier($sidDir.Name)).Translate([Security.Principal.NTAccount]).Value } catch {}
        foreach ($i in Get-ChildItem -LiteralPath $sidDir.FullName -Filter '$I*' -Force) {
            try {
                $b = [IO.File]::ReadAllBytes($i.FullName)
                $ver = [BitConverter]::ToInt64($b, 0); $size = [BitConverter]::ToInt64($b, 8); $ft = [BitConverter]::ToInt64($b, 16)
                if ($ver -ge 2) { $len = [BitConverter]::ToInt32($b, 24); $name = [Text.Encoding]::Unicode.GetString($b, 28, [math]::Max(0, ($len - 1) * 2)) }
                else { $name = [Text.Encoding]::Unicode.GetString($b, 24, 520).TrimEnd([char]0) }
                $r = Join-Path $sidDir.FullName ('$R' + $i.Name.Substring(2))
                if (Test-Path -LiteralPath $r) {
                    [void]$out.Add([ordered]@{ user = $user; original = $name; size = $size; deleted = [DateTime]::FromFileTime($ft).ToString('s'); ipath = $i.FullName; rpath = $r; folder = (Test-Path -LiteralPath $r -PathType Container) })
                }
            } catch {}
        }
    }
}
@{ items = @($out | Sort-Object deleted -Descending | Select-Object -First 3000) } | ConvertTo-Json -Compress -Depth 4
"""

RECYCLE_RESTORE_PS = PS_ARGS + r"""
$ok = 0; $errs = @(); $where = @()
foreach ($it in @($A.items)) {
    try {
        $t = $it.original
        if (Test-Path -LiteralPath $t) { $n = 1; do { $t = [IO.Path]::Combine([IO.Path]::GetDirectoryName($it.original), [IO.Path]::GetFileNameWithoutExtension($it.original) + " (restored $n)" + [IO.Path]::GetExtension($it.original)); $n++ } while (Test-Path -LiteralPath $t) }
        New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($t)) -Force | Out-Null
        Move-Item -LiteralPath $it.rpath -Destination $t -Force -ErrorAction Stop
        Remove-Item -LiteralPath $it.ipath -Force
        $ok++; $where += $t
    } catch { $errs += "$($it.original): $($_.Exception.Message)" }
}
@{ ok = $ok; errors = $errs; restored_to = $where } | ConvertTo-Json -Compress
"""

SHADOW_LIST_PS = r"""
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$ErrorActionPreference = 'SilentlyContinue'
$vols = @{}; foreach ($v in Get-CimInstance Win32_Volume) { $vols[$v.DeviceID] = $v.DriveLetter }
$s = @(Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending | ForEach-Object {
    [ordered]@{ id = $_.ID; time = $_.InstallDate.ToString('s'); drive = $vols[$_.VolumeName]; device = $_.DeviceObject } })
$fh = Test-Path "$env:windir\System32\FileHistory.exe"
$cfg = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\FileHistory\Configuration" -Filter 'Config*.xml' -ErrorAction SilentlyContinue | Select-Object -First 1
$winfr = [bool](Get-Command winfr -ErrorAction SilentlyContinue)
@{ shadows = $s; filehistory_app = $fh; filehistory_configured = [bool]$cfg; winfr = $winfr; winget = [bool](Get-Command winget -ErrorAction SilentlyContinue) } | ConvertTo-Json -Compress -Depth 4
"""

SHADOW_FIND_PS = PS_ARGS + r"""
$rel = $A.path -replace '^[a-zA-Z]:', ''
$hits = @()
foreach ($s in @($A.shadows)) {
    if ($s.drive -and $A.path.Substring(0, 2) -ne $s.drive) { continue }
    $p = $s.device + $rel
    $info = cmd /c "dir /-c `"$p`"" 2>$null
    if ($LASTEXITCODE -eq 0 -and ($info -join "`n") -notmatch 'File Not Found') {
        $line = $info | Where-Object { $_ -match '^\d' -and $_ -notmatch '<DIR>' } | Select-Object -First 1
        $hits += [ordered]@{ snapshot = $s.time; device = $s.device; source = $p; listing = "$line".Trim() }
    }
}
@{ hits = $hits } | ConvertTo-Json -Compress -Depth 4
"""

SHADOW_COPY_PS = PS_ARGS + r"""
New-Item -ItemType Directory -Path $A.dest -Force | Out-Null
$name = Split-Path $A.source -Leaf
$target = Join-Path $A.dest ($A.stamp + '_' + $name)
$o = cmd /c "copy /y `"$($A.source)`" `"$target`"" 2>&1
@{ ok = (Test-Path -LiteralPath $target); target = $target; detail = ($o -join ' ') } | ConvertTo-Json -Compress
"""

SHADOW_MOUNT_PS = PS_ARGS + r"""
New-Item -ItemType Directory -Path $A.root -Force | Out-Null
$link = Join-Path $A.root $A.name
if (-not (Test-Path -LiteralPath $link)) { $o = cmd /c "mklink /d `"$link`" `"$($A.device)\`"" 2>&1 }
@{ ok = (Test-Path -LiteralPath $link); link = $link; detail = ($o -join ' ') } | ConvertTo-Json -Compress
"""

SHADOW_UNMOUNT_PS = PS_ARGS + r"""
$n = 0; foreach ($l in Get-ChildItem -LiteralPath $A.root -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { cmd /c "rmdir `"$($l.FullName)`"" | Out-Null; $n++ }
@{ ok = $true; removed = $n } | ConvertTo-Json -Compress
"""

MEDIA_PS = PS_ARGS + r"""
$dl = $A.drive.Substring(0, 1)
# Get-Disk | Get-PhysicalDisk does not bind on many systems - match the disk number to the physical disk's DeviceId
$n = (Get-Partition -DriveLetter $dl | Select-Object -First 1).DiskNumber
$pd = @(Get-PhysicalDisk) | Where-Object { "$($_.DeviceId)" -eq "$n" } | Select-Object -First 1
$t = "$($pd.MediaType)"; if ($pd.BusType -eq 'NVMe') { $t = 'SSD' }
@{ media = $t; bus = "$($pd.BusType)"; model = $pd.FriendlyName } | ConvertTo-Json -Compress
"""

SECDEL_PS = PS_ARGS + r"""
function Test-Protected([string]$p) {
    $full = [IO.Path]::GetFullPath($p)
    if ($full -like "$env:windir*" -or $full -like "$env:ProgramFiles*" -or $full -like "${env:ProgramFiles(x86)}*") { return $true }
    if ($full -match '^[a-zA-Z]:\\?$') { return $true }
    if ($full -match '^[a-zA-Z]:\\Users\\[^\\]+\\?$') { return $true }
    return $false
}
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$done = 0; $errs = @(); $drives = @{}
foreach ($p in @($A.paths)) {
    if (Test-Protected $p) { $errs += "Refused (protected location): $p"; continue }
    $files = if (Test-Path -LiteralPath $p -PathType Container) { @(Get-ChildItem -LiteralPath $p -Recurse -File -Force) } else { @(Get-Item -LiteralPath $p -Force) }
    foreach ($f in $files) {
        try {
            [IO.File]::SetAttributes($f.FullName, 'Normal')
            $len = $f.Length; $fs = [IO.File]::Open($f.FullName, 'Open', 'Write', 'None')
            $buf = New-Object byte[] 1048576
            for ($pass = 0; $pass -lt [int]$A.passes; $pass++) {
                [void]$fs.Seek(0, 'Begin'); $left = $len
                while ($left -gt 0) { $n = [int][math]::Min($buf.Length, $left); $rng.GetBytes($buf); $fs.Write($buf, 0, $n); $left -= $n }
                $fs.Flush($true)
            }
            $fs.SetLength(0); $fs.Close()
            $rn = Join-Path $f.DirectoryName ([Guid]::NewGuid().ToString('N'))
            Rename-Item -LiteralPath $f.FullName -NewName (Split-Path $rn -Leaf)
            Remove-Item -LiteralPath $rn -Force -ErrorAction Stop
            $done++; $drives[$f.FullName.Substring(0, 1)] = 1
        } catch { $errs += "$($f.FullName): $($_.Exception.Message)" }
    }
    if (Test-Path -LiteralPath $p -PathType Container) { Remove-Item -LiteralPath $p -Recurse -Force }
}
foreach ($d in $drives.Keys) { Optimize-Volume -DriveLetter $d -ReTrim -ErrorAction SilentlyContinue | Out-Null }
@{ ok = ($errs.Count -eq 0); files = $done; errors = $errs } | ConvertTo-Json -Compress
"""


# ---------------------------------------------------------------------------------
#  Python side
# ---------------------------------------------------------------------------------
def run_with_args(script, args, timeout=600, track=True):
    """track=False for changes (quarantine, restore, settings): the Stop button must not cut them off half-way."""
    import core
    fd, path = tempfile.mkstemp(prefix="wd_args_", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(args, f, default=str)
    try:
        return core.run_ps_json(script.replace("{args}", path.replace("'", "''")), timeout, "File tools", track)
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def quarantine(kind, title, reason, restore_point=True, include_file=True, **payload):
    args = {"root": QROOT, "id": datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6], "kind": kind,
            "title": title, "reason": reason, "restore_point": restore_point, "include_file": include_file}
    args.update(payload)
    return run_with_args(QUARANTINE_PS, args, 300, track=False)


def restore(qid):
    return run_with_args(RESTORE_PS, {"root": QROOT, "id": qid}, 300, track=False)


def list_quarantine():
    out = []
    if not os.path.isdir(QROOT):
        return out
    for d in sorted(os.listdir(QROOT), reverse=True):
        mf = os.path.join(QROOT, d, "manifest.json")
        try:
            with open(mf, "r", encoding="utf-8-sig") as f:
                m = json.load(f)
            if not isinstance(m, dict):
                continue
            m["_dir"] = os.path.join(QROOT, d)
            out.append(m)
        except Exception:
            continue
    return out


def purge(days=30):
    n = 0
    cutoff = time.time() - days * 86400
    for m in list_quarantine():
        try:
            t = datetime.strptime(m.get("time", "")[:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        except ValueError:
            continue
        if t < cutoff:
            shutil.rmtree(m["_dir"], ignore_errors=True)
            n += 1
    return n


def item_summary(m):
    parts = []
    for it in m.get("items", []) if isinstance(m.get("items"), list) else [m.get("items")]:
        if not it:
            continue
        t = it.get("type")
        parts.append({"file": "File: %s" % it.get("path"), "run": "Run value: %s" % it.get("value"), "task": "Task: %s%s" % (it.get("taskpath", ""), it.get("name", "")),
                      "service": "Service: %s" % it.get("name"), "ifeo": "IFEO debugger: %s" % it.get("key", "").rsplit("\\", 1)[-1],
                      "wmi": "WMI subscription: %s" % (it.get("consumer") or {}).get("Name", ""), "cert": "Certificate: %s" % it.get("subject", "")}.get(t, t))
    return parts


def fmt_size(b):
    try:
        b = float(b)
    except (TypeError, ValueError):
        return ""
    for u, d in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if b >= d:
            return "%.1f %s" % (b / d, u)
    return "%d B" % b


def parse_i_file(data):
    """Parse a Recycle Bin $I file (Vista+ v1 and Win10+ v2). Pure Python for tests / offline use."""
    import struct
    ver, size, ft = struct.unpack_from("<qqq", data, 0)
    if ver >= 2:
        (n,) = struct.unpack_from("<i", data, 24)
        name = data[28:28 + max(0, n - 1) * 2].decode("utf-16-le", "replace")
    else:
        name = data[24:24 + 520].decode("utf-16-le", "replace").rstrip("\x00")
    deleted = datetime(1601, 1, 1) + __import__("datetime").timedelta(microseconds=ft // 10) if ft else None
    return {"version": ver, "size": size, "original": name, "deleted": deleted}


def winfr_command(src, dest, mode, pattern):
    src = src.rstrip("\\/")[:2].upper()
    if dest[:2].upper() == src:
        raise ValueError("The destination must be on a DIFFERENT drive than the source (Microsoft requirement).")
    cmd = 'winfr %s "%s" /%s' % (src, dest, "extensive" if mode == "extensive" else "regular")
    if pattern:
        cmd += ' /n "%s"' % pattern
    return cmd


def open_console(cmd, title="WinDiag"):
    """Run a command in its own visible console window that stays open."""
    import subprocess
    import core
    subprocess.Popen([core.sys32("cmd"), "/k", "title %s & %s" % (title, cmd)], creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10))


def drives():
    import string
    return ["%s:" % d for d in string.ascii_uppercase if os.path.exists("%s:\\" % d)]


def winfr_install_cmd():
    return "winget install --id %s --source msstore --accept-package-agreements --accept-source-agreements" % WINFR_ID
