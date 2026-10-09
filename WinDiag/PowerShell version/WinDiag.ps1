<#
    WinDiag - Portable Windows Diagnostic Toolkit
    Runs straight from a USB stick. No install. Windows 10 / 11 (PowerShell 5.1+).

    Start it with "Start WinDiag.bat" (it asks for admin rights automatically).
    Reports are saved to the "Reports" folder next to this script.
#>
param([switch]$NoElevate)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$AppName    = 'WinDiag'
$AppVersion = '1.0'

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# ----------------------------------------------------------------------------------
#  Elevation
# ----------------------------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$script:IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Start-Elevated {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -ErrorAction Stop `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
}

if (-not $script:IsAdmin -and -not $NoElevate) {
    try { Start-Elevated; exit } catch { <# UAC declined - continue in limited mode #> }
}

# ----------------------------------------------------------------------------------
#  Paths (reports go on the USB stick; fall back to Desktop if the stick is read-only)
# ----------------------------------------------------------------------------------
$script:ToolRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$folderName = '{0}_{1}' -f $env:COMPUTERNAME, $stamp
$candidates = @(
    (Join-Path $script:ToolRoot "Reports\$folderName"),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) "WinDiag_Reports\$folderName"),
    (Join-Path $env:TEMP "WinDiag_Reports\$folderName")
)
$script:ReportDir = $null
foreach ($c in $candidates) {
    try {
        New-Item -ItemType Directory -Path $c -Force -ErrorAction Stop | Out-Null
        $probe = Join-Path $c '.write_test'
        Set-Content -Path $probe -Value 'ok' -ErrorAction Stop
        Remove-Item $probe -Force
        $script:ReportDir = $c
        break
    } catch {}
}

# ----------------------------------------------------------------------------------
#  Result model + helpers
# ----------------------------------------------------------------------------------
$script:Findings = New-Object System.Collections.ArrayList
$script:Results  = @{}

function Add-Finding([string]$Status, [string]$Area, [string]$Finding, [string]$Advice = '') {
    [void]$script:Findings.Add([pscustomobject]@{ Status = $Status; Area = $Area; Finding = $Finding; Advice = $Advice })
}

function New-Section([string]$Title, $Data, [switch]$List, [string]$Note = '') {
    [pscustomobject]@{
        Title  = $Title
        Data   = @($Data | Where-Object { $null -ne $_ })
        AsList = [bool]$List
        Note   = $Note
    }
}

function Format-Size($Bytes) {
    $b = [double]$Bytes
    if ($b -ge 1TB) { '{0:N2} TB' -f ($b / 1TB) }
    elseif ($b -ge 1GB) { '{0:N1} GB' -f ($b / 1GB) }
    elseif ($b -ge 1MB) { '{0:N0} MB' -f ($b / 1MB) }
    else { '{0:N0} KB' -f ($b / 1KB) }
}

function Get-FirstLine([string]$Text, [int]$Max = 150) {
    if (-not $Text) { return '' }
    $line = $Text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1
    if (-not $line) { return '' }
    $line = $line.Trim()
    if ($line.Length -gt $Max) { return $line.Substring(0, $Max) + '...' }
    return $line
}

function Get-EventsSafe([hashtable]$Filter, [int]$Max = 500) {
    try { Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop } catch { }
}

function ConvertTo-EventRows($Events, [int]$Max = 25) {
    $Events | Select-Object -First $Max | ForEach-Object {
        [pscustomobject]@{
            Time    = '{0:yyyy-MM-dd HH:mm}' -f $_.TimeCreated
            Source  = $_.ProviderName
            ID      = $_.Id
            Level   = $_.LevelDisplayName
            Message = Get-FirstLine $_.Message 130
        }
    }
}

function ConvertTo-EventSummary($Events, [int]$Top = 20) {
    $Events | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object {
        $g = $_.Group
        [pscustomobject]@{
            Count       = $_.Count
            Source      = $g[0].ProviderName
            ID          = $g[0].Id
            'Last seen' = '{0:yyyy-MM-dd HH:mm}' -f $g[0].TimeCreated
            Message     = Get-FirstLine $g[0].Message 110
        }
    }
}

# ==================================================================================
#  CHECK 1: System & hardware
# ==================================================================================
function Get-SystemInfo {
    $out  = New-Object System.Collections.ArrayList
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $bb   = Get-CimInstance Win32_BaseBoard
    $cpus = @(Get-CimInstance Win32_Processor)
    $cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $uptime   = (Get-Date) - $os.LastBootUpTime
    $totalRam = [double]$os.TotalVisibleMemorySize * 1KB
    $freeRam  = [double]$os.FreePhysicalMemory * 1KB
    $ramPct   = 0
    if ($totalRam -gt 0) { $ramPct = [math]::Round((($totalRam - $freeRam) / $totalRam) * 100) }
    $cpuLoad  = [math]::Round((($cpus | Measure-Object LoadPercentage -Average).Average))

    $secureBoot = 'Unknown'
    try { if (Confirm-SecureBootUEFI -ErrorAction Stop) { $secureBoot = 'On' } else { $secureBoot = 'Off' } }
    catch { if ($script:IsAdmin) { $secureBoot = 'Not supported (Legacy BIOS)' } else { $secureBoot = 'Unknown (needs admin)' } }

    $tpmText = 'Unknown (needs admin)'
    $tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm
    if ($tpm) {
        $ver = ("$($tpm.SpecVersion)" -split ',')[0].Trim()
        $tpmText = "Present, version $ver, enabled=$($tpm.IsEnabled_InitialValue)"
    } elseif ($script:IsAdmin) { $tpmText = 'Not found / disabled in BIOS' }

    $activation = 'Unknown'
    $lic = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" | Select-Object -First 1
    $licMap = @{ 0 = 'Unlicensed'; 1 = 'Licensed (activated)'; 2 = 'Grace period'; 3 = 'Grace period'; 4 = 'Non-genuine grace'; 5 = 'Not activated (notification mode)'; 6 = 'Extended grace' }
    if ($lic) { $activation = $licMap[[int]$lic.LicenseStatus] }

    $firmware = $env:firmware_type
    if (-not $firmware) { $firmware = 'Unknown' }

    $cores   = ($cpus | Measure-Object NumberOfCores -Sum).Sum
    $threads = ($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum

    $overview = [pscustomobject]@{
        'Computer name'   = $env:COMPUTERNAME
        'Signed-in user'  = "$env:USERDOMAIN\$env:USERNAME"
        'Windows'         = "$($os.Caption) $($cv.DisplayVersion)".Trim()
        'Build'           = "$($os.Version).$($cv.UBR)"
        'Architecture'    = $os.OSArchitecture
        'Installed on'    = '{0:yyyy-MM-dd}' -f $os.InstallDate
        'Last boot'       = '{0:yyyy-MM-dd HH:mm}' -f $os.LastBootUpTime
        'Uptime'          = '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
        'Activation'      = $activation
        'Manufacturer'    = $cs.Manufacturer
        'Model'           = $cs.Model
        'Serial number'   = $bios.SerialNumber
        'Motherboard'     = "$($bb.Manufacturer) $($bb.Product)".Trim()
        'BIOS version'    = '{0} ({1:yyyy-MM-dd})' -f $bios.SMBIOSBIOSVersion, $bios.ReleaseDate
        'Firmware mode'   = $firmware
        'Secure Boot'     = $secureBoot
        'TPM'             = $tpmText
        'CPU'             = ($cpus | ForEach-Object { "$($_.Name)".Trim() }) -join ' | '
        'Cores / threads' = "$cores / $threads"
        'CPU load now'    = "$cpuLoad %"
        'RAM'             = '{0} total, {1} in use ({2}%)' -f (Format-Size $totalRam), (Format-Size ($totalRam - $freeRam)), $ramPct
    }
    [void]$out.Add((New-Section 'Overview' $overview -List))

    # Memory modules
    $mods = Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
        [pscustomobject]@{
            Slot         = $_.DeviceLocator
            Size         = Format-Size $_.Capacity
            'Speed MHz'  = $_.Speed
            'Running at' = $_.ConfiguredClockSpeed
            Manufacturer = "$($_.Manufacturer)".Trim()
            'Part no.'   = "$($_.PartNumber)".Trim()
        }
    }
    [void]$out.Add((New-Section 'Memory modules (RAM sticks)' $mods))

    # GPU
    $gpus = Get-CimInstance Win32_VideoController | ForEach-Object {
        [pscustomobject]@{
            GPU             = $_.Name
            'Driver version'= $_.DriverVersion
            'Driver date'   = '{0:yyyy-MM-dd}' -f $_.DriverDate
            Resolution      = if ($_.CurrentHorizontalResolution) { "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution) @ $($_.CurrentRefreshRate)Hz" } else { '-' }
            Status          = $_.Status
        }
    }
    [void]$out.Add((New-Section 'Graphics' $gpus -Note 'Microsoft Basic Display Adapter = no proper GPU driver installed.'))
    foreach ($g in @($gpus)) {
        if ($g.GPU -match 'Basic Display|Basic Render') {
            Add-Finding 'WARNING' 'Graphics' 'No proper graphics driver installed (using Microsoft Basic Display Adapter)' 'Install the driver from NVIDIA / AMD / Intel or the PC maker''s website.'
        }
    }

    # Device Manager problems
    $codeMap = @{ 1 = 'Not configured correctly'; 3 = 'Driver may be corrupted'; 10 = 'Device cannot start'; 12 = 'Not enough resources'
                  14 = 'Restart required'; 18 = 'Reinstall the drivers'; 19 = 'Registry problem'; 22 = 'Disabled'; 24 = 'Not present / not working'
                  28 = 'Drivers not installed'; 31 = 'Not working properly'; 32 = 'Driver disabled'; 37 = 'Driver failed to initialise'
                  39 = 'Driver missing or corrupted'; 43 = 'Stopped - reported a problem (Code 43)'; 45 = 'Not connected'; 52 = 'Unsigned driver blocked' }
    $bad = @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' | ForEach-Object {
        $code = [int]$_.ConfigManagerErrorCode
        $desc = $codeMap[$code]; if (-not $desc) { $desc = 'Problem' }
        [pscustomobject]@{ Device = $(if ($_.Name) { $_.Name } else { $_.PNPDeviceID }); Code = $code; Problem = $desc; Class = $_.PNPClass }
    })
    [void]$out.Add((New-Section 'Device Manager problems' $bad -Note 'Devices with a yellow "!" in Device Manager.'))
    $realBad = @($bad | Where-Object { $_.Code -notin 22, 45 })
    if ($realBad.Count -gt 0) {
        Add-Finding 'WARNING' 'Drivers' ("{0} device(s) have driver problems: {1}" -f $realBad.Count, (($realBad | Select-Object -First 3 | ForEach-Object { $_.Device }) -join ', ')) 'Open Device Manager (Repairs & Tools tab) and update or reinstall those drivers.'
    } else { Add-Finding 'OK' 'Drivers' 'No device driver problems found' }

    # Findings
    if ($uptime.TotalDays -ge 14) { Add-Finding 'WARNING' 'System' ("PC has not been restarted for {0} days" -f [int]$uptime.TotalDays) 'Restart the PC (Fast Startup means "Shut down" does not count as a restart).' }
    if ($ramPct -ge 90) { Add-Finding 'WARNING' 'Memory' "RAM is $ramPct% full right now" 'Close heavy apps / browser tabs; see Top processes in the Startup & Processes tab.' }
    if ($totalRam -gt 0 -and $totalRam -lt 7.5GB) { Add-Finding 'INFO' 'Memory' ("Only {0} of RAM installed" -f (Format-Size $totalRam)) '8 GB or more is recommended for Windows 10/11.' }
    if ($cpuLoad -ge 85) { Add-Finding 'WARNING' 'CPU' "CPU is at $cpuLoad% load" 'Check Top processes for what is using the CPU.' }
    if ($lic -and [int]$lic.LicenseStatus -ne 1) { Add-Finding 'WARNING' 'Windows' "Windows is not activated ($activation)" 'Activate Windows in Settings > System > Activation.' }
    if ($secureBoot -eq 'Off') { Add-Finding 'INFO' 'Security' 'Secure Boot is turned off' 'Can be enabled in BIOS/UEFI settings (required for Windows 11).' }

    $out
}

# ==================================================================================
#  CHECK 2: Disks
# ==================================================================================
function Get-DiskInfo {
    $out = New-Object System.Collections.ArrayList

    $pds = @(Get-PhysicalDisk | Sort-Object { [int]$_.DeviceId })
    if ($pds.Count -gt 0) {
        $rows = foreach ($d in $pds) {
            $r = $null
            try { $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
            $health = "$($d.HealthStatus)"
            $label  = "Disk $($d.DeviceId) ($($d.FriendlyName))"
            if ($health -and $health -ne 'Healthy') {
                Add-Finding 'CRITICAL' 'Disks' "$label health status: $health" 'Back up your files NOW and plan to replace this drive.'
            } elseif ($health -eq 'Healthy') { Add-Finding 'OK' 'Disks' "$label reports Healthy" }

            $temp = 'n/a'; $wear = 'n/a'; $hours = 'n/a'; $errs = 'n/a'
            if ($r) {
                if ($r.Temperature -gt 0) { $temp = $r.Temperature }
                if ($null -ne $r.Wear)    { $wear = $r.Wear }
                if ($r.PowerOnHours)      { $hours = $r.PowerOnHours }
                $unc = [int64]$r.ReadErrorsUncorrected + [int64]$r.WriteErrorsUncorrected
                $errs = $unc
                if ($r.Wear -ge 90) { Add-Finding 'CRITICAL' 'Disks' "$label is $($r.Wear)% worn out" 'SSD is near end of life - back up and replace it.' }
                elseif ($r.Wear -ge 70) { Add-Finding 'WARNING' 'Disks' "$label is $($r.Wear)% worn" 'Keep backups current; plan a replacement.' }
                if ($r.Temperature -ge 65) { Add-Finding 'WARNING' 'Disks' "$label is hot ($($r.Temperature) C)" 'Check airflow / heatsink; sustained heat shortens drive life.' }
                if ($unc -gt 0) { Add-Finding 'CRITICAL' 'Disks' "$label has $unc uncorrected read/write errors" 'Drive is failing to read/write data - back up now and run CHKDSK.' }
            }
            [pscustomobject]@{
                Disk        = $d.DeviceId
                Model       = $d.FriendlyName
                Type        = "$($d.MediaType)"
                Bus         = "$($d.BusType)"
                Size        = Format-Size $d.Size
                Health      = $health
                'Temp C'    = $temp
                'Wear %'    = $wear
                'Power-on h'= $hours
                'Uncorr. errors' = $errs
            }
        }
        $note = 'Temperature / wear / errors need admin rights and a drive that reports them.'
        [void]$out.Add((New-Section 'Physical drives' $rows -Note $note))
    } else {
        $rows = Get-CimInstance Win32_DiskDrive | ForEach-Object {
            [pscustomobject]@{ Model = $_.Model; Interface = $_.InterfaceType; Size = Format-Size $_.Size; Status = $_.Status }
        }
        [void]$out.Add((New-Section 'Physical drives' $rows))
    }

    # SMART predict-failure flag
    $smart = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus | ForEach-Object {
        if ($_.PredictFailure) { Add-Finding 'CRITICAL' 'Disks' "SMART predicts failure for $($_.InstanceName)" 'Back up immediately and replace the drive.' }
        [pscustomobject]@{ Drive = $_.InstanceName; 'Predicts failure' = $_.PredictFailure; Reason = $_.Reason }
    })
    [void]$out.Add((New-Section 'SMART failure prediction' $smart -Note 'Many NVMe drives do not appear here - that is normal.'))

    # Volumes
    $vols = @(Get-Volume | Where-Object { $_.DriveLetter } | Sort-Object DriveLetter)
    $vrows = foreach ($v in $vols) {
        $pct = $null
        if ($v.Size -gt 0) { $pct = [math]::Round(($v.SizeRemaining / $v.Size) * 100, 1) }
        if ("$($v.DriveType)" -eq 'Fixed' -and $null -ne $pct) {
            if ($pct -lt 10) { Add-Finding 'CRITICAL' 'Storage' ("Drive {0}: only {1} free ({2}%)" -f $v.DriveLetter, (Format-Size $v.SizeRemaining), $pct) 'Free up space: "Clear temp files" repair, Disk Cleanup, uninstall unused apps, move videos/photos off.' }
            elseif ($pct -lt 15) { Add-Finding 'WARNING' 'Storage' ("Drive {0}: getting full - {1} free ({2}%)" -f $v.DriveLetter, (Format-Size $v.SizeRemaining), $pct) 'Windows runs best with 15-20% free space.' }
        }
        if ("$($v.HealthStatus)" -and "$($v.HealthStatus)" -ne 'Healthy') {
            Add-Finding 'WARNING' 'Storage' "Volume $($v.DriveLetter): health is $($v.HealthStatus)" 'Run the CHKDSK scan in the Repairs tab.'
        }
        [pscustomobject]@{
            Drive    = "$($v.DriveLetter):"
            Label    = $v.FileSystemLabel
            Type     = "$($v.DriveType)"
            FS       = $v.FileSystem
            Size     = Format-Size $v.Size
            Free     = Format-Size $v.SizeRemaining
            'Free %' = $pct
            Health   = "$($v.HealthStatus)"
        }
    }
    if (-not $vrows) {
        $vrows = Get-CimInstance Win32_LogicalDisk | ForEach-Object {
            [pscustomobject]@{ Drive = $_.DeviceID; Label = $_.VolumeName; FS = $_.FileSystem; Size = Format-Size $_.Size; Free = Format-Size $_.FreeSpace }
        }
    }
    [void]$out.Add((New-Section 'Drive letters / free space' $vrows))

    $out
}

# ==================================================================================
#  CHECK 3: Errors & crashes
# ==================================================================================
function Get-ErrorInfo {
    $out = New-Object System.Collections.ArrayList
    $since7  = (Get-Date).AddDays(-7)
    $since30 = (Get-Date).AddDays(-30)

    # Blue screens
    $bsod = @()
    $bsod += @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $since30 } 50)
    $bsod += @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'BugCheck'; Id = 1001; StartTime = $since30 } 50)
    $bsod = @($bsod | Where-Object { $_ } | Sort-Object TimeCreated -Descending)
    [void]$out.Add((New-Section 'Blue screens (BSOD) - last 30 days' (ConvertTo-EventRows $bsod 20) -Note 'The message contains the bugcheck (stop) code - search it online to see the likely cause.'))
    if ($bsod.Count -gt 0) {
        Add-Finding 'CRITICAL' 'Crashes' "$($bsod.Count) blue screen crash(es) in the last 30 days" 'Update GPU / chipset / storage drivers and BIOS, run the memory test, then DISM + SFC.'
    }

    # Minidumps
    $dumps = @(Get-ChildItem "$env:SystemRoot\Minidump" -Filter *.dmp -Force | Sort-Object LastWriteTime -Descending | ForEach-Object {
        [pscustomobject]@{ File = $_.Name; Date = '{0:yyyy-MM-dd HH:mm}' -f $_.LastWriteTime; Size = Format-Size $_.Length }
    })
    $full = Get-Item "$env:SystemRoot\MEMORY.DMP" -Force
    if ($full) { $dumps += [pscustomobject]@{ File = 'MEMORY.DMP (full dump)'; Date = '{0:yyyy-MM-dd HH:mm}' -f $full.LastWriteTime; Size = Format-Size $full.Length } }
    [void]$out.Add((New-Section 'Crash dump files' $dumps -Note "Located in $env:SystemRoot\Minidump. Open them with WinDbg or BlueScreenView for details."))

    # Unexpected shutdowns
    $kp = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since30 } 100)
    [void]$out.Add((New-Section 'Unexpected shutdowns / power loss (Kernel-Power 41) - last 30 days' (ConvertTo-EventRows $kp 15)))
    if ($kp.Count -gt 0) {
        Add-Finding 'WARNING' 'Crashes' "$($kp.Count) unexpected shutdown(s) / restarts in the last 30 days" 'Caused by crashes, freezes, power cuts, holding the power button, overheating or a weak PSU/battery.'
    }

    # WHEA hardware errors
    $wheaErr  = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Level = 1, 2; StartTime = $since30 } 100)
    $wheaWarn = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Level = 3; StartTime = $since30 } 200)
    [void]$out.Add((New-Section 'Hardware errors (WHEA) - last 30 days' (ConvertTo-EventRows (@($wheaErr) + @($wheaWarn) | Sort-Object TimeCreated -Descending) 20) -Note 'Reported by the CPU, RAM or PCIe devices themselves.'))
    if ($wheaErr.Count -gt 0) {
        Add-Finding 'CRITICAL' 'Hardware' "$($wheaErr.Count) fatal hardware error(s) reported (WHEA)" 'Check CPU/GPU temperatures, remove overclocks/XMP, reseat RAM, run the memory test.'
    } elseif ($wheaWarn.Count -ge 10) {
        Add-Finding 'WARNING' 'Hardware' "$($wheaWarn.Count) corrected hardware errors (WHEA)" 'Often a PCIe link or unstable overclock - update chipset drivers / BIOS.'
    }

    # Disk / file-system errors
    $diskEv = @()
    foreach ($p in 'disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'stornvme', 'storahci', 'iaStorA', 'iaStorAC', 'iaStorAVC') {
        $diskEv += @(Get-EventsSafe @{ LogName = 'System'; ProviderName = $p; Level = 1, 2, 3; StartTime = $since30 } 100)
    }
    $diskEv = @($diskEv | Where-Object { $_ } | Sort-Object TimeCreated -Descending)
    [void]$out.Add((New-Section 'Disk / file-system errors - last 30 days' (ConvertTo-EventRows $diskEv 20) -Note 'IDs 7, 11, 51, 55, 129, 153 usually mean a failing drive, bad cable, or file-system corruption.'))
    if ($diskEv.Count -gt 0) {
        Add-Finding 'WARNING' 'Disks' "$($diskEv.Count) disk / file-system error events in the last 30 days" 'Back up, run the CHKDSK scan, check SATA/NVMe cables. (Events from a USB stick can be ignored.)'
    }

    # App crashes
    $appCr = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $since30 } 500)
    $appHg = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002; StartTime = $since30 } 500)
    $appRows = @()
    $appRows += $appCr | Group-Object { "$($_.Properties[0].Value)" } | ForEach-Object {
        [pscustomobject]@{ App = $_.Name; Type = 'Crash'; Count = $_.Count; 'Last seen' = '{0:yyyy-MM-dd HH:mm}' -f $_.Group[0].TimeCreated; 'Faulting module' = "$($_.Group[0].Properties[3].Value)" }
    }
    $appRows += $appHg | Group-Object { "$($_.Properties[0].Value)" } | ForEach-Object {
        [pscustomobject]@{ App = $_.Name; Type = 'Hang'; Count = $_.Count; 'Last seen' = '{0:yyyy-MM-dd HH:mm}' -f $_.Group[0].TimeCreated; 'Faulting module' = '-' }
    }
    $appRows = @($appRows | Where-Object { $_ } | Sort-Object Count -Descending)
    [void]$out.Add((New-Section 'Crashing / freezing apps - last 30 days' $appRows))
    foreach ($a in ($appRows | Where-Object { $_.Count -ge 3 } | Select-Object -First 3)) {
        Add-Finding 'WARNING' 'Apps' "$($a.App) had $($a.Count) $($a.Type.ToLower())es in 30 days" 'Update or reinstall that app. If the faulting module is a system DLL, run DISM + SFC.'
    }

    # Top recurring errors, last 7 days
    $sys = @(Get-EventsSafe @{ LogName = 'System'; Level = 1, 2; StartTime = $since7 } 3000)
    $app = @(Get-EventsSafe @{ LogName = 'Application'; Level = 1, 2; StartTime = $since7 } 3000)
    [void]$out.Add((New-Section "Most frequent System log errors - last 7 days ($($sys.Count) total)" (ConvertTo-EventSummary $sys 20) -Note 'Some errors are normal on every PC; look for high counts or ones matching your symptoms.'))
    [void]$out.Add((New-Section "Most frequent Application log errors - last 7 days ($($app.Count) total)" (ConvertTo-EventSummary $app 20)))

    if ($bsod.Count -eq 0 -and $wheaErr.Count -eq 0 -and $kp.Count -eq 0) {
        Add-Finding 'OK' 'Crashes' 'No blue screens, hardware errors or unexpected shutdowns in the last 30 days'
    }
    $out
}

# ==================================================================================
#  CHECK 4: Network
# ==================================================================================
function Get-NetworkInfo {
    $out = New-Object System.Collections.ArrayList

    $adapters = @(Get-NetAdapter | Sort-Object Status, Name | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Description = $_.InterfaceDescription; Status = "$($_.Status)"; Speed = $_.LinkSpeed; MAC = $_.MacAddress }
    })
    [void]$out.Add((New-Section 'Network adapters' $adapters))

    $cfg = @(Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' })
    $ipRows = foreach ($c in $cfg) {
        [pscustomobject]@{
            Interface = $c.InterfaceAlias
            IPv4      = ($c.IPv4Address.IPAddress) -join ', '
            Gateway   = ($c.IPv4DefaultGateway.NextHop) -join ', '
            DNS       = (($c.DNSServer | Where-Object { $_.AddressFamily -eq 2 }).ServerAddresses) -join ', '
        }
    }
    [void]$out.Add((New-Section 'IP configuration (connected adapters)' $ipRows))

    # Connectivity tests
    $tests = New-Object System.Collections.ArrayList
    $gw = @($cfg | ForEach-Object { $_.IPv4DefaultGateway.NextHop } | Where-Object { $_ }) | Select-Object -First 1
    $gwOk = $false
    if ($gw) {
        $p = @(Test-Connection -ComputerName $gw -Count 2 -ErrorAction SilentlyContinue)
        $gwOk = $p.Count -gt 0
        [void]$tests.Add([pscustomobject]@{ Test = "Ping router ($gw)"; Result = $(if ($gwOk) { 'OK' } else { 'FAILED' }); Detail = $(if ($gwOk) { '{0:N0} ms' -f ($p | Measure-Object ResponseTime -Average).Average } else { 'no reply (some routers block ping)' }) })
    } else {
        [void]$tests.Add([pscustomobject]@{ Test = 'Default gateway'; Result = 'FAILED'; Detail = 'No gateway - not connected to a network' })
    }

    $p = @(Test-Connection -ComputerName 1.1.1.1 -Count 3 -ErrorAction SilentlyContinue)
    $avg = $null; if ($p.Count -gt 0) { $avg = [math]::Round(($p | Measure-Object ResponseTime -Average).Average) }
    [void]$tests.Add([pscustomobject]@{ Test = 'Ping internet (1.1.1.1)'; Result = $(if ($p.Count -gt 0) { 'OK' } else { 'FAILED' }); Detail = $(if ($avg -ne $null) { "$avg ms average, $($p.Count)/3 replies" } else { 'no reply' }) })

    $dnsOk = $false
    try { $r = Resolve-DnsName 'www.microsoft.com' -DnsOnly -QuickTimeout -ErrorAction Stop; $dnsOk = $true } catch {}
    [void]$tests.Add([pscustomobject]@{ Test = 'DNS lookup (www.microsoft.com)'; Result = $(if ($dnsOk) { 'OK' } else { 'FAILED' }); Detail = '' })

    $webOk = $false
    try {
        $w = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        $webOk = ($w.Content -match 'Microsoft Connect Test')
    } catch {}
    [void]$tests.Add([pscustomobject]@{ Test = 'Internet (Microsoft connect test)'; Result = $(if ($webOk) { 'OK' } else { 'FAILED' }); Detail = $(if ($webOk) { '' } else { 'no response or captive portal / proxy' }) })
    [void]$out.Add((New-Section 'Connectivity tests' $tests))

    # Wi-Fi
    $wlan = @(netsh wlan show interfaces 2>$null | Where-Object { $_.Trim() })
    $signal = $null
    $sigLine = $wlan | Select-String '(\d{1,3})\s*%' | Select-Object -First 1
    if ($sigLine) { $signal = [int]$sigLine.Matches[0].Groups[1].Value }
    if ($wlan.Count -gt 3) { [void]$out.Add((New-Section 'Wi-Fi' ($wlan | ForEach-Object { $_.Trim() }))) }

    # Proxy + hosts
    $inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $hosts = @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*(#|$)' })
    $misc = [pscustomobject]@{
        'Proxy enabled'         = $(if ($inet.ProxyEnable -eq 1) { "Yes ($($inet.ProxyServer))" } else { 'No' })
        'Auto-config script'    = $(if ($inet.AutoConfigURL) { $inet.AutoConfigURL } else { 'None' })
        'Custom hosts entries'  = $hosts.Count
    }
    [void]$out.Add((New-Section 'Proxy & hosts file' $misc -List))
    if ($hosts.Count -gt 0) { [void]$out.Add((New-Section 'Hosts file entries' $hosts -Note 'Unknown entries here can redirect or block websites (sometimes adware).')) }

    # Findings
    $up = @($adapters | Where-Object { $_.Status -eq 'Up' })
    if ($up.Count -eq 0) { Add-Finding 'CRITICAL' 'Network' 'No network adapter is connected' 'Check the cable / Wi-Fi switch, and the Network adapters list for missing drivers.' }
    elseif ($webOk) { Add-Finding 'OK' 'Network' ("Internet connection works{0}" -f $(if ($avg) { " ($avg ms)" } else { '' })) }
    elseif (-not $dnsOk -and ($p.Count -gt 0)) { Add-Finding 'CRITICAL' 'Network' 'Internet reachable by IP but DNS lookups fail' 'Run "Flush DNS" or set DNS to 1.1.1.1 / 8.8.8.8; try the network reset repair.' }
    else { Add-Finding 'CRITICAL' 'Network' 'No internet access' 'Restart router, try another network, then run the network reset repair.' }
    if ($avg -and $avg -gt 120) { Add-Finding 'WARNING' 'Network' "High internet latency ($avg ms)" 'Weak Wi-Fi, busy network or ISP issue.' }
    if ($signal -and $signal -lt 50) { Add-Finding 'WARNING' 'Network' "Weak Wi-Fi signal ($signal%)" 'Move closer to the router or use a cable.' }
    if ($inet.ProxyEnable -eq 1) { Add-Finding 'INFO' 'Network' "A proxy is set: $($inet.ProxyServer)" 'If you did not set this, it may be adware - disable in Settings > Network > Proxy.' }
    if ($hosts.Count -gt 0) { Add-Finding 'INFO' 'Network' "$($hosts.Count) custom entries in the hosts file" 'Review them in the Network tab.' }

    $out
}

# ==================================================================================
#  CHECK 5: Startup, services, processes
# ==================================================================================
function Get-StartupInfo {
    $out = New-Object System.Collections.ArrayList

    $st = @(Get-CimInstance Win32_StartupCommand | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Command = $_.Command; Location = $_.Location; User = $_.User }
    })
    [void]$out.Add((New-Section "Startup programs ($($st.Count))" $st -Note 'Disable unneeded ones in Task Manager > Startup apps. Items disabled there may still be listed.'))
    if ($st.Count -ge 15) { Add-Finding 'WARNING' 'Startup' "$($st.Count) programs start with Windows" 'Disable the ones you do not need in Task Manager > Startup apps for faster boot.' }

    $tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and "$($_.State)" -ne 'Disabled' } | ForEach-Object {
        [pscustomobject]@{ Task = $_.TaskName; Folder = $_.TaskPath; State = "$($_.State)"; Runs = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ; ') }
    })
    [void]$out.Add((New-Section "Non-Microsoft scheduled tasks ($($tasks.Count))" $tasks -Note 'Updaters are normal here. Unknown tasks running scripts from AppData/Temp can be malware.'))

    $important = 'WinDefend', 'mpssvc', 'BFE', 'Dhcp', 'Dnscache', 'EventLog', 'Winmgmt', 'AudioSrv', 'wscsvc', 'CryptSvc', 'LanmanWorkstation', 'nsi', 'Power', 'ProfSvc', 'Schedule', 'Themes', 'RpcSs', 'PlugPlay'
    $stopped = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ Service = $_.Name; 'Display name' = $_.DisplayName; State = $_.State; Important = $(if ($_.Name -in $important) { 'YES' } else { '' }) }
    })
    [void]$out.Add((New-Section 'Automatic services that are not running' $stopped -Note 'Many of these are normal (they start on demand). Pay attention to rows marked Important.'))
    foreach ($s in ($stopped | Where-Object { $_.Important -eq 'YES' })) {
        Add-Finding 'WARNING' 'Services' "Important service stopped: $($s.'Display name')" 'Open Services and start it; if it will not start, run DISM + SFC or scan for malware.'
    }

    $procs = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 | ForEach-Object {
        [pscustomobject]@{ Process = $_.ProcessName; PID = $_.Id; 'RAM' = Format-Size $_.WorkingSet64; 'CPU time (s)' = [math]::Round($_.CPU, 0); Path = $_.Path }
    }
    [void]$out.Add((New-Section 'Top processes by memory' $procs))

    $cpuTop = Get-Process | Where-Object { $_.CPU } | Sort-Object CPU -Descending | Select-Object -First 10 | ForEach-Object {
        [pscustomobject]@{ Process = $_.ProcessName; PID = $_.Id; 'CPU time (s)' = [math]::Round($_.CPU, 0); RAM = Format-Size $_.WorkingSet64 }
    }
    [void]$out.Add((New-Section 'Top processes by total CPU time' $cpuTop))

    $out
}

# ==================================================================================
#  CHECK 6: Security, updates, battery
# ==================================================================================
function Get-SecurityInfo {
    $out = New-Object System.Collections.ArrayList

    # Antivirus (Security Center)
    $avList = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
        $hex = '{0:x6}' -f [int]$_.productState
        [pscustomobject]@{
            Antivirus   = $_.displayName
            Enabled     = $(if ($hex.Substring(2, 2) -in '10', '11') { 'Yes' } else { 'No' })
            'Up to date'= $(if ($hex.Substring(4, 2) -eq '00') { 'Yes' } else { 'No' })
        }
    })
    [void]$out.Add((New-Section 'Antivirus products' $avList))
    $activeAv = @($avList | Where-Object { $_.Enabled -eq 'Yes' })
    if ($avList.Count -gt 0 -and $activeAv.Count -eq 0) { Add-Finding 'CRITICAL' 'Security' 'No antivirus is turned on' 'Turn on Microsoft Defender in Windows Security or fix your antivirus.' }
    foreach ($a in ($activeAv | Where-Object { $_.'Up to date' -eq 'No' })) { Add-Finding 'WARNING' 'Security' "$($a.Antivirus) is out of date" 'Update virus definitions (Repairs tab > Update Defender).' }
    if ($activeAv.Count -gt 1) { Add-Finding 'INFO' 'Security' ("{0} antivirus products active: {1}" -f $activeAv.Count, (($activeAv.Antivirus) -join ', ')) 'Running two real-time antiviruses can slow the PC.' }

    # Defender
    $mp = Get-MpComputerStatus
    if ($mp) {
        $sigAge = 0; if ($mp.AntivirusSignatureLastUpdated) { $sigAge = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days }
        $def = [pscustomobject]@{
            'Defender service running' = $mp.AMServiceEnabled
            'Real-time protection'     = $mp.RealTimeProtectionEnabled
            'Tamper protection'        = $mp.IsTamperProtected
            'Definitions updated'      = '{0:yyyy-MM-dd} ({1} days ago)' -f $mp.AntivirusSignatureLastUpdated, $sigAge
            'Last quick scan'          = $(if ($mp.QuickScanEndTime) { '{0:yyyy-MM-dd}' -f $mp.QuickScanEndTime } else { 'Never' })
            'Last full scan'           = $(if ($mp.FullScanEndTime) { '{0:yyyy-MM-dd}' -f $mp.FullScanEndTime } else { 'Never' })
        }
        [void]$out.Add((New-Section 'Microsoft Defender' $def -List))
        $thirdParty = @($activeAv | Where-Object { $_.Antivirus -notmatch 'Defender' })
        if ($mp.AMServiceEnabled -and -not $mp.RealTimeProtectionEnabled -and $thirdParty.Count -eq 0) {
            Add-Finding 'CRITICAL' 'Security' 'Defender real-time protection is OFF' 'Turn it on in Windows Security > Virus & threat protection.'
        } elseif ($mp.RealTimeProtectionEnabled) {
            Add-Finding 'OK' 'Security' 'Microsoft Defender real-time protection is on'
            if ($sigAge -gt 7) { Add-Finding 'WARNING' 'Security' "Defender definitions are $sigAge days old" 'Run "Update Defender definitions" in the Repairs tab.' }
        }
    }

    # Recent detections
    $threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 15 | ForEach-Object {
        $name = (Get-MpThreat -ThreatID $_.ThreatID).ThreatName
        [pscustomobject]@{ Detected = '{0:yyyy-MM-dd HH:mm}' -f $_.InitialDetectionTime; Threat = $name; Action = $_.ActionSuccess; Resources = (($_.Resources | Select-Object -First 2) -join '; ') }
    })
    [void]$out.Add((New-Section 'Recent Defender detections' $threats))
    if ($threats.Count -gt 0) { Add-Finding 'INFO' 'Security' "Defender detected $($threats.Count) threat(s) recently" 'Review the list in Security & Updates; run a full scan if unsure.' }

    # Firewall
    $fw = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Profile = $_.Name; Enabled = "$($_.Enabled)" } })
    [void]$out.Add((New-Section 'Firewall' $fw))
    foreach ($f in ($fw | Where-Object { $_.Enabled -ne 'True' })) {
        Add-Finding 'WARNING' 'Security' "Windows Firewall is OFF for the $($f.Profile) profile" 'Turn it on in Windows Security > Firewall (unless another firewall is installed).'
    }

    # UAC / BitLocker
    $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
    if ($uac -eq 0) { Add-Finding 'WARNING' 'Security' 'User Account Control (UAC) is disabled' 'Re-enable UAC - it blocks silent admin changes by malware.' }
    $bl = @()
    try {
        $bl = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Drive = $_.MountPoint; Status = "$($_.VolumeStatus)"; Protection = "$($_.ProtectionStatus)"; 'Encrypted %' = $_.EncryptionPercentage }
        })
    } catch {}
    [void]$out.Add((New-Section 'BitLocker drive encryption' $bl -Note 'If BitLocker protection is On, have the recovery key (aka.ms/myrecoverykey) BEFORE changing BIOS settings or hardware.'))
    if (@($bl | Where-Object { $_.Protection -eq 'On' }).Count -gt 0) {
        Add-Finding 'INFO' 'Security' 'BitLocker encryption is ON' 'Make sure the recovery key is saved before BIOS updates or hardware changes.'
    }
    [void]$out.Add((New-Section 'Other' ([pscustomobject]@{ 'UAC enabled' = $(if ($uac -eq 0) { 'No' } else { 'Yes' }) }) -List))

    # Windows Update history
    $hist = @()
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $n = $searcher.GetTotalHistoryCount()
        if ($n -gt 0) { $hist = @($searcher.QueryHistory(0, [math]::Min(60, $n))) }
    } catch {}
    $resMap = @{ 0 = 'Not started'; 1 = 'In progress'; 2 = 'Succeeded'; 3 = 'Succeeded w/ errors'; 4 = 'FAILED'; 5 = 'Aborted' }
    $histRows = $hist | Where-Object { $_.Title } | Select-Object -First 25 | ForEach-Object {
        [pscustomobject]@{ Date = '{0:yyyy-MM-dd}' -f $_.Date; Result = $resMap[[int]$_.ResultCode]; Update = Get-FirstLine $_.Title 110 }
    }
    [void]$out.Add((New-Section 'Windows Update - recent history' $histRows))

    $osUpd = @($hist | Where-Object { $_.Title -and [int]$_.ResultCode -eq 2 -and $_.Title -notmatch 'KB2267602|KB4052623|KB890830|Defender|Intelligence' } | Sort-Object Date -Descending)
    if ($osUpd.Count -gt 0) {
        $age = [int]((Get-Date) - $osUpd[0].Date).TotalDays
        if ($age -gt 45) { Add-Finding 'WARNING' 'Updates' "Last successful Windows update was $age days ago" 'Run Windows Update. If it keeps failing, use "Reset Windows Update" in Repairs.' }
        else { Add-Finding 'OK' 'Updates' "Windows updates are recent (last one $age days ago)" }
    } else {
        $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf) {
            $age = [int]((Get-Date) - $hf.InstalledOn).TotalDays
            if ($age -gt 45) { Add-Finding 'WARNING' 'Updates' "Last Windows update was installed $age days ago" 'Run Windows Update.' }
        }
    }
    $failed = @($hist | Where-Object { [int]$_.ResultCode -eq 4 -and $_.Date -gt (Get-Date).AddDays(-30) })
    if ($failed.Count -ge 2) { Add-Finding 'WARNING' 'Updates' "$($failed.Count) Windows updates failed in the last 30 days" 'Try "Reset Windows Update" then DISM + SFC in the Repairs tab.' }

    $wu = Get-Service wuauserv
    if ($wu -and "$($wu.StartType)" -eq 'Disabled') { Add-Finding 'WARNING' 'Updates' 'The Windows Update service is disabled' 'Set "Windows Update" service to Manual in Services.' }

    # Pending reboot
    $pending = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'Component servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'Windows Update' }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations) { $pending += 'Pending file operations' }
    [void]$out.Add((New-Section 'Pending restart' $(if ($pending.Count) { "Restart pending because of: $($pending -join ', ')" } else { 'No restart pending' })))
    if ($pending -contains 'Windows Update' -or $pending -contains 'Component servicing') {
        Add-Finding 'WARNING' 'Updates' 'A restart is pending to finish installing updates' 'Restart the PC.'
    }

    # Battery
    $bat = @(Get-CimInstance Win32_Battery)
    if ($bat.Count -gt 0) {
        $design = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData)
        $fullc  = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity)
        $rows = for ($i = 0; $i -lt $bat.Count; $i++) {
            $d = $null; $f = $null; $h = 'n/a'
            if ($i -lt $design.Count) { $d = $design[$i].DesignedCapacity }
            if ($i -lt $fullc.Count)  { $f = $fullc[$i].FullChargedCapacity }
            if ($d -gt 0 -and $f -gt 0) {
                $hp = [math]::Round(($f / $d) * 100)
                $h = "$hp %"
                if ($hp -lt 50) { Add-Finding 'CRITICAL' 'Battery' "Battery health is only $hp% of original capacity" 'Replace the battery - it will run out fast and may cause sudden shutdowns.' }
                elseif ($hp -lt 75) { Add-Finding 'WARNING' 'Battery' "Battery health is $hp% of original capacity" 'Battery is worn; consider a replacement.' }
                else { Add-Finding 'OK' 'Battery' "Battery health is $hp%" }
            }
            [pscustomobject]@{
                Battery = $bat[$i].Name
                'Charge now' = "$($bat[$i].EstimatedChargeRemaining) %"
                'Design capacity (mWh)' = $d
                'Full charge capacity (mWh)' = $f
                Health = $h
            }
        }
        [void]$out.Add((New-Section 'Battery' $rows -Note 'Use "Battery report" in Repairs & Tools for full history.'))
    }

    $out
}

# ==================================================================================
#  Repairs & tools
# ==================================================================================
$script:Repairs = @(
    @{ Group = 'Before you repair'; Name = 'Create restore point'; Admin = $true
       Desc = 'Snapshot of system settings so repairs can be undone (System Restore).'
       Body = @'
Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
Checkpoint-Computer -Description 'WinDiag - before repairs' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
Write-Host 'Restore point requested. (Windows only allows one every 24h - if a recent one exists, it is kept.)' -ForegroundColor Green
'@ }

    @{ Group = 'System files'; Name = 'Full system repair (DISM + SFC)'; Admin = $true
       Desc = 'Repairs the Windows image, then scans and fixes system files. 15-45 min. Needs internet.'
       Confirm = 'This runs DISM /RestoreHealth then SFC /scannow. It can take 15-45 minutes. Continue?'
       Body = @'
Write-Host 'Step 1/2: DISM RestoreHealth - may sit at 20% or 62% for a while, that is normal.' -ForegroundColor Yellow
DISM /Online /Cleanup-Image /RestoreHealth
Write-Host "DISM exit code: $LASTEXITCODE  (0 = OK)"
Write-Host ''
Write-Host 'Step 2/2: System File Checker' -ForegroundColor Yellow
sfc /scannow
Write-Host "SFC exit code: $LASTEXITCODE"
findstr /c:"[SR]" "$env:windir\Logs\CBS\CBS.log" | Out-File -FilePath (Join-Path $ReportDir 'sfc_details.txt') -Encoding UTF8
Write-Host "SFC details saved to $ReportDir\sfc_details.txt"
Write-Host 'Restart the PC when finished.' -ForegroundColor Green
'@ }

    @{ Group = 'System files'; Name = 'Quick system file check (SFC)'; Admin = $true
       Desc = 'Scans protected Windows files and replaces corrupted ones. ~10 min.'
       Body = @'
sfc /scannow
Write-Host "SFC exit code: $LASTEXITCODE"
findstr /c:"[SR]" "$env:windir\Logs\CBS\CBS.log" | Out-File -FilePath (Join-Path $ReportDir 'sfc_details.txt') -Encoding UTF8
Write-Host "Details saved to $ReportDir\sfc_details.txt"
'@ }

    @{ Group = 'Disk'; Name = 'CHKDSK scan (online)'; Admin = $true
       Desc = 'Checks the system drive for file-system errors without restarting.'
       Body = @'
chkdsk $env:SystemDrive /scan
Write-Host "CHKDSK exit code: $LASTEXITCODE  (0 = no errors found)"
'@ }

    @{ Group = 'Disk'; Name = 'CHKDSK full repair at next restart'; Admin = $true
       Desc = 'Schedules chkdsk /f /r on the next boot. Can take HOURS on large drives.'
       Confirm = 'This schedules a full disk check/repair (chkdsk /f /r) on the next restart. It can take several hours and must not be interrupted. Continue?'
       Body = @'
cmd.exe /c "echo Y| chkdsk %SystemDrive% /f /r"
Write-Host 'Scheduled. Restart the PC to run it - do not turn it off during the check.' -ForegroundColor Yellow
'@ }

    @{ Group = 'Disk'; Name = 'Clear temp files'; Admin = $true
       Desc = 'Deletes temporary files for all users and Windows temp. Safe; in-use files are skipped.'
       Body = @'
$targets = @("$env:SystemRoot\Temp")
$targets += Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' } | Where-Object { Test-Path $_ }
$total = 0
foreach ($t in $targets) {
    $before = [double](Get-ChildItem $t -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Get-ChildItem $t -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $after = [double](Get-ChildItem $t -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    $freed = $before - $after
    $total += $freed
    Write-Host ('{0,-60} freed {1,10:N1} MB' -f $t, ($freed / 1MB))
}
Write-Host ''
Write-Host ('Total freed: {0:N1} MB' -f ($total / 1MB)) -ForegroundColor Green
'@ }

    @{ Group = 'Network'; Name = 'Flush DNS cache'; Admin = $false
       Desc = 'Fixes websites not loading after DNS/IP changes. Instant, harmless.'
       Body = @'
ipconfig /flushdns
Clear-DnsClientCache -ErrorAction SilentlyContinue
Write-Host 'DNS cache cleared.' -ForegroundColor Green
'@ }

    @{ Group = 'Network'; Name = 'Full network reset'; Admin = $true
       Desc = 'Resets Winsock + TCP/IP, renews IP. Fixes most "connected but no internet" problems. Restart needed.'
       Confirm = 'This resets Winsock and TCP/IP settings and briefly disconnects the network. Static IP settings may need to be re-entered. A restart is needed afterwards. Continue?'
       Body = @'
ipconfig /flushdns
ipconfig /release
ipconfig /renew
netsh winsock reset
netsh int ip reset
Write-Host ''
Write-Host 'Done. RESTART the PC to finish the network reset.' -ForegroundColor Yellow
'@ }

    @{ Group = 'Windows Update'; Name = 'Reset Windows Update'; Admin = $true
       Desc = 'Stops update services, renames the update cache folders, restarts services. Fixes stuck/failing updates.'
       Confirm = 'This resets the Windows Update cache (SoftwareDistribution and catroot2 are renamed, not deleted). Update history in Settings will look empty afterwards. Continue?'
       Body = @'
$svcs = 'wuauserv', 'bits', 'cryptsvc', 'msiserver'
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
Write-Host 'Done. Now open Settings > Windows Update and check for updates.' -ForegroundColor Green
'@ }

    @{ Group = 'Security'; Name = 'Update Defender definitions'; Admin = $true
       Desc = 'Downloads the latest Microsoft Defender virus definitions.'
       Body = @'
Update-MpSignature -ErrorAction Stop
Write-Host ('Definitions now dated: {0}' -f (Get-MpComputerStatus).AntivirusSignatureLastUpdated) -ForegroundColor Green
'@ }

    @{ Group = 'Security'; Name = 'Defender quick scan'; Admin = $true
       Desc = 'Runs a Microsoft Defender quick malware scan (~5-15 min).'
       Body = @'
Write-Host 'Scanning... this window will update when finished.' -ForegroundColor Yellow
Start-MpScan -ScanType QuickScan -ErrorAction Stop
$t = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddHours(-1) })
Write-Host ("Scan finished. Threats found in the last hour: {0}" -f $t.Count) -ForegroundColor Green
'@ }

    @{ Group = 'Hardware'; Name = 'Memory (RAM) test'; Admin = $true; Launch = 'mdsched.exe'
       Desc = 'Windows Memory Diagnostic - restarts the PC and tests RAM. Results show after login.' }

    @{ Group = 'Hardware'; Name = 'Battery report'; Admin = $false
       Desc = 'Detailed battery history & capacity (laptops). Saved to the report folder.'
       Body = @'
$f = Join-Path $ReportDir 'battery-report.html'
powercfg /batteryreport /output "$f"
if (Test-Path $f) { Start-Process $f }
'@ }

    @{ Group = 'Hardware'; Name = 'Power / energy report'; Admin = $true
       Desc = 'Observes the system for 60 s and lists power & sleep problems.'
       Body = @'
$f = Join-Path $ReportDir 'energy-report.html'
Write-Host 'Observing for 60 seconds, leave the PC idle...' -ForegroundColor Yellow
powercfg /energy /output "$f" /duration 60
if (Test-Path $f) { Start-Process $f }
'@ }
)

$script:Tools = @(
    @{ Name = 'Device Manager';      Cmd = 'devmgmt.msc' }
    @{ Name = 'Event Viewer';        Cmd = 'eventvwr.msc' }
    @{ Name = 'Reliability Monitor'; Cmd = 'perfmon.exe'; Args = '/rel' }
    @{ Name = 'Resource Monitor';    Cmd = 'resmon.exe' }
    @{ Name = 'Task Manager';        Cmd = 'taskmgr.exe' }
    @{ Name = 'System Information';  Cmd = 'msinfo32.exe' }
    @{ Name = 'Disk Management';     Cmd = 'diskmgmt.msc' }
    @{ Name = 'Services';            Cmd = 'services.msc' }
    @{ Name = 'Disk Cleanup';        Cmd = 'cleanmgr.exe' }
    @{ Name = 'Windows Security';    Cmd = 'windowsdefender:' }
    @{ Name = 'Windows Update';      Cmd = 'ms-settings:windowsupdate' }
    @{ Name = 'Apps & features';     Cmd = 'ms-settings:appsfeatures' }
    @{ Name = 'Startup apps';        Cmd = 'ms-settings:startupapps' }
    @{ Name = 'System Restore';      Cmd = 'rstrui.exe' }
)

function Start-RepairWindow([string]$Name, [string]$Body) {
    $safe = ($Name -replace '[^A-Za-z0-9]+', '_').Trim('_')
    $log  = Join-Path $script:ReportDir ('repair_{0}_{1}.log' -f $safe, (Get-Date -Format 'HHmmss'))
    $tmp  = Join-Path $env:TEMP ('WinDiag_{0}.ps1' -f [guid]::NewGuid().ToString('N'))
    $q    = { param($s) $s -replace "'", "''" }
    $header = @"
`$ErrorActionPreference = 'Continue'
`$Host.UI.RawUI.WindowTitle = 'WinDiag - $(& $q $Name)'
`$ReportDir = '$(& $q $script:ReportDir)'
Start-Transcript -Path '$(& $q $log)' | Out-Null
Write-Host '==== $(& $q $Name) ====' -ForegroundColor Cyan
Write-Host ('Started: ' + (Get-Date))
Write-Host ''
try {
"@
    $footer = @'

} catch { Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red }
Write-Host ''
Write-Host ('Finished: ' + (Get-Date)) -ForegroundColor Green
Stop-Transcript | Out-Null
Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
Read-Host 'Press Enter to close this window'
'@
    Set-Content -Path $tmp -Value ($header + "`r`n" + $Body + $footer) -Encoding UTF8
    Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$tmp`"")
}

# ==================================================================================
#  Reports (HTML + TXT)
# ==================================================================================
function Get-HealthScore {
    $c = @($script:Findings | Where-Object { $_.Status -eq 'CRITICAL' }).Count
    $w = @($script:Findings | Where-Object { $_.Status -eq 'WARNING' }).Count
    [pscustomobject]@{ Score = [math]::Max(0, 100 - (20 * $c) - (6 * $w)); Critical = $c; Warning = $w }
}

function Get-SortedFindings {
    $order = @{ CRITICAL = 0; WARNING = 1; INFO = 2; OK = 3 }
    $script:Findings | Sort-Object @{ Expression = { $order[$_.Status] } }, Area
}

function Get-SectionText($Section) {
    $d = @($Section.Data)
    $txt = ''
    if ($d.Count -eq 0) { $txt = '  (nothing found)' }
    elseif ($d[0] -is [string]) { $txt = ($d | ForEach-Object { "  $_" }) -join "`r`n" }
    elseif ($Section.AsList) { $txt = ($d | Format-List | Out-String -Width 300).Trim([char[]]"`r`n") }
    else { $txt = ($d | Format-Table -AutoSize -Wrap | Out-String -Width 300).Trim([char[]]"`r`n") }
    return $txt + "`r`n"
}

function Export-Reports {
    $enc  = { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
    $hs   = Get-HealthScore
    $html = Join-Path $script:ReportDir 'WinDiag-Report.html'
    $txtF = Join-Path $script:ReportDir 'WinDiag-Report.txt'
    $when = Get-Date -Format 'yyyy-MM-dd HH:mm'

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>WinDiag - $env:COMPUTERNAME</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f9;color:#1d2433}
header{background:#1f2d46;color:#fff;padding:22px 32px}header h1{margin:0;font-size:24px}header p{margin:4px 0 0;opacity:.8}
main{padding:20px 32px;max-width:1400px}
.score{display:inline-block;font-size:42px;font-weight:700;margin-right:18px}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:16px 20px;margin:16px 0}
h2{margin:28px 0 6px;border-bottom:2px solid #1f2d46;padding-bottom:4px}h3{margin:18px 0 6px;font-size:15px;color:#1f2d46}
table{border-collapse:collapse;width:100%;font-size:13px;background:#fff}th,td{border:1px solid #dde2ea;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#eef1f6}pre{background:#fff;border:1px solid #dde2ea;padding:10px;font-size:12px;white-space:pre-wrap}
.note{color:#6b7385;font-size:12px;margin:0 0 6px}
tr.CRITICAL td{background:#fde2e2}tr.WARNING td{background:#fff4d6}tr.OK td{background:#e3f5e6}
.tag{font-weight:700}
</style></head><body>
<header><h1>WinDiag report - $(& $enc $env:COMPUTERNAME)</h1><p>Generated $when &middot; WinDiag $AppVersion &middot; Admin: $($script:IsAdmin)</p></header><main>
<div class="card"><span class="score">$($hs.Score)/100</span> $($hs.Critical) critical &middot; $($hs.Warning) warnings</div>
<h2>Summary</h2><table><tr><th>Status</th><th>Area</th><th>Finding</th><th>Suggested action</th></tr>
"@)
    foreach ($f in (Get-SortedFindings)) {
        [void]$sb.Append("<tr class=`"$($f.Status)`"><td class=`"tag`">$($f.Status)</td><td>$(& $enc $f.Area)</td><td>$(& $enc $f.Finding)</td><td>$(& $enc $f.Advice)</td></tr>`n")
    }
    [void]$sb.Append('</table>')

    $txt = New-Object System.Text.StringBuilder
    [void]$txt.AppendLine("WinDiag report - $env:COMPUTERNAME - $when")
    [void]$txt.AppendLine("Health score: $($hs.Score)/100 ($($hs.Critical) critical, $($hs.Warning) warnings)")
    [void]$txt.AppendLine('')
    [void]$txt.AppendLine('SUMMARY')
    foreach ($f in (Get-SortedFindings)) {
        [void]$txt.AppendLine(('  [{0,-8}] {1,-10} {2}' -f $f.Status, $f.Area, $f.Finding))
        if ($f.Advice) { [void]$txt.AppendLine("              -> $($f.Advice)") }
    }

    foreach ($c in $script:Checks) {
        $sections = $script:Results[$c.Key]
        if (-not $sections) { continue }
        [void]$sb.Append("<h2>$(& $enc $c.Title)</h2>")
        [void]$txt.AppendLine(''); [void]$txt.AppendLine(('=' * 90)); [void]$txt.AppendLine($c.Title.ToUpper()); [void]$txt.AppendLine(('=' * 90))
        foreach ($s in $sections) {
            [void]$sb.Append("<h3>$(& $enc $s.Title)</h3>")
            if ($s.Note) { [void]$sb.Append("<p class=`"note`">$(& $enc $s.Note)</p>") }
            $d = @($s.Data)
            if ($d.Count -eq 0) { [void]$sb.Append('<p class="note">(nothing found)</p>') }
            elseif ($d[0] -is [string]) { [void]$sb.Append('<pre>' + (& $enc ($d -join "`n")) + '</pre>') }
            else {
                $as = 'Table'; if ($s.AsList) { $as = 'List' }
                [void]$sb.Append((($d | ConvertTo-Html -Fragment -As $as) -join "`n"))
            }
            [void]$txt.AppendLine(''); [void]$txt.AppendLine("-- $($s.Title)")
            [void]$txt.Append((Get-SectionText $s))
        }
    }
    [void]$sb.Append('</main></body></html>')
    Set-Content -Path $html -Value $sb.ToString() -Encoding UTF8
    Set-Content -Path $txtF -Value $txt.ToString() -Encoding UTF8
    return $html
}

# ==================================================================================
#  GUI
# ==================================================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:Checks = @(
    @{ Key = 'System';   Title = 'System';               Fn = { Get-SystemInfo } }
    @{ Key = 'Disks';    Title = 'Disks';                Fn = { Get-DiskInfo } }
    @{ Key = 'Errors';   Title = 'Errors & Crashes';     Fn = { Get-ErrorInfo } }
    @{ Key = 'Network';  Title = 'Network';              Fn = { Get-NetworkInfo } }
    @{ Key = 'Startup';  Title = 'Startup & Processes';  Fn = { Get-StartupInfo } }
    @{ Key = 'Security'; Title = 'Security & Updates';   Fn = { Get-SecurityInfo } }
)

$C_Dark   = [System.Drawing.Color]::FromArgb(31, 45, 70)
$C_Accent = [System.Drawing.Color]::FromArgb(0, 120, 212)
$C_Crit   = [System.Drawing.Color]::FromArgb(253, 226, 226)
$C_Warn   = [System.Drawing.Color]::FromArgb(255, 244, 214)
$C_Ok     = [System.Drawing.Color]::FromArgb(227, 245, 230)
$FontUI   = New-Object System.Drawing.Font('Segoe UI', 9)
$FontMono = New-Object System.Drawing.Font('Consolas', 9.5)
$FontHead = New-Object System.Drawing.Font('Segoe UI', 10.5, [System.Drawing.FontStyle]::Bold)
$FontNote = New-Object System.Drawing.Font('Segoe UI', 8.5, [System.Drawing.FontStyle]::Italic)

function New-Button([string]$Text, [int]$Width = 150, $Back = $null) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Width = $Width; $b.Height = 32
    $b.FlatStyle = 'Flat'; $b.Cursor = 'Hand'
    if ($Back) { $b.BackColor = $Back; $b.ForeColor = [System.Drawing.Color]::White; $b.FlatAppearance.BorderSize = 0 }
    $b.Margin = New-Object System.Windows.Forms.Padding(4)
    return $b
}

function Write-Rtb($Rtb, $Sections) {
    $Rtb.Clear()
    foreach ($s in $Sections) {
        $Rtb.SelectionStart = $Rtb.TextLength; $Rtb.SelectionLength = 0
        $Rtb.SelectionFont = $FontHead; $Rtb.SelectionColor = $C_Dark
        $Rtb.AppendText(">> $($s.Title)`r`n")
        if ($s.Note) {
            $Rtb.SelectionStart = $Rtb.TextLength
            $Rtb.SelectionFont = $FontNote; $Rtb.SelectionColor = [System.Drawing.Color]::DimGray
            $Rtb.AppendText("   $($s.Note)`r`n")
        }
        $Rtb.SelectionStart = $Rtb.TextLength
        $Rtb.SelectionFont = $FontMono; $Rtb.SelectionColor = [System.Drawing.Color]::Black
        $Rtb.AppendText((Get-SectionText $s) + "`r`n")
    }
    $Rtb.SelectionStart = 0; $Rtb.ScrollToCaret()
}

# ---- Form -------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinDiag $AppVersion - $env:COMPUTERNAME" + $(if ($script:IsAdmin) { '' } else { '  [LIMITED MODE - not administrator]' })
$form.Size = New-Object System.Drawing.Size(1200, 800)
$form.MinimumSize = New-Object System.Drawing.Size(900, 600)
$form.StartPosition = 'CenterScreen'
$form.Font = $FontUI
$form.AutoScaleMode = 'Dpi'
try { $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon("$env:SystemRoot\System32\perfmon.exe") } catch {}

# Header
$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'; $header.Height = 70; $header.BackColor = $C_Dark
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'WinDiag'; $lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
$lblTitle.Location = New-Object System.Drawing.Point(14, 6); $lblTitle.AutoSize = $true
$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = "Portable Windows diagnostics  |  $env:COMPUTERNAME  |  Reports: $script:ReportDir"
$lblSub.ForeColor = [System.Drawing.Color]::FromArgb(190, 200, 220)
$lblSub.Location = New-Object System.Drawing.Point(17, 44); $lblSub.AutoSize = $true
$btnFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$btnFlow.Dock = 'Right'; $btnFlow.Width = 520; $btnFlow.FlowDirection = 'RightToLeft'
$btnFlow.Padding = New-Object System.Windows.Forms.Padding(0, 17, 10, 0); $btnFlow.BackColor = $C_Dark
$btnRun    = New-Button 'Run all checks' 140 $C_Accent
$btnSave   = New-Button 'Open HTML report' 140 ([System.Drawing.Color]::FromArgb(60, 80, 110))
$btnFolder = New-Button 'Reports folder' 130 ([System.Drawing.Color]::FromArgb(60, 80, 110))
$btnFlow.Controls.AddRange(@($btnRun, $btnSave, $btnFolder))
$header.Controls.AddRange(@($lblTitle, $lblSub, $btnFlow))

# Limited-mode banner
$banner = New-Object System.Windows.Forms.Panel
$banner.Dock = 'Top'; $banner.Height = 38; $banner.BackColor = $C_Warn; $banner.Visible = -not $script:IsAdmin
$lblBanner = New-Object System.Windows.Forms.Label
$lblBanner.Text = 'Not running as administrator: disk health, BitLocker, TPM and most repairs are unavailable.'
$lblBanner.AutoSize = $true; $lblBanner.Location = New-Object System.Drawing.Point(14, 11)
$btnElevate = New-Button 'Restart as admin' 130
$btnElevate.Height = 28; $btnElevate.Location = New-Object System.Drawing.Point(620, 5); $btnElevate.BackColor = [System.Drawing.Color]::White
$banner.Controls.AddRange(@($lblBanner, $btnElevate))

# Status bar
$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusLbl = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLbl.Text = 'Ready'; $statusLbl.Spring = $true; $statusLbl.TextAlign = 'MiddleLeft'
$progress = New-Object System.Windows.Forms.ToolStripProgressBar
$progress.Width = 220; $progress.Maximum = $script:Checks.Count
[void]$statusStrip.Items.Add($statusLbl); [void]$statusStrip.Items.Add($progress)

# Tabs
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.Padding = New-Object System.Drawing.Point(14, 5)

# Summary tab
$tpSum = New-Object System.Windows.Forms.TabPage; $tpSum.Text = 'Summary'
$sumTop = New-Object System.Windows.Forms.Panel; $sumTop.Dock = 'Top'; $sumTop.Height = 64; $sumTop.BackColor = [System.Drawing.Color]::White
$lblScore = New-Object System.Windows.Forms.Label
$lblScore.Font = New-Object System.Drawing.Font('Segoe UI', 22, [System.Drawing.FontStyle]::Bold)
$lblScore.Text = '--/100'; $lblScore.AutoSize = $true; $lblScore.Location = New-Object System.Drawing.Point(12, 10)
$lblScoreTxt = New-Object System.Windows.Forms.Label
$lblScoreTxt.Text = 'Running checks...'; $lblScoreTxt.AutoSize = $true; $lblScoreTxt.Location = New-Object System.Drawing.Point(170, 24)
$lblScoreTxt.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$sumTop.Controls.AddRange(@($lblScore, $lblScoreTxt))
$lv = New-Object System.Windows.Forms.ListView
$lv.View = 'Details'; $lv.FullRowSelect = $true; $lv.GridLines = $true; $lv.Dock = 'Fill'; $lv.HideSelection = $false
[void]$lv.Columns.Add('Status', 85); [void]$lv.Columns.Add('Area', 95)
[void]$lv.Columns.Add('Finding', 470); [void]$lv.Columns.Add('Suggested action', 520)
$tpSum.Controls.Add($lv); $tpSum.Controls.Add($sumTop)
$lv.BringToFront()
[void]$tabs.TabPages.Add($tpSum)

# Info tabs
foreach ($c in $script:Checks) {
    $tp = New-Object System.Windows.Forms.TabPage; $tp.Text = $c.Title
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock = 'Fill'; $rtb.ReadOnly = $true; $rtb.WordWrap = $false; $rtb.BackColor = [System.Drawing.Color]::White
    $rtb.BorderStyle = 'None'; $rtb.Font = $FontMono; $rtb.DetectUrls = $false
    $rtb.Text = 'Waiting for checks to run...'
    $tp.Controls.Add($rtb)
    $c.Box = $rtb
    [void]$tabs.TabPages.Add($tp)
}

# Repairs tab
$tpRep = New-Object System.Windows.Forms.TabPage; $tpRep.Text = 'Repairs & Tools'
$repFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$repFlow.Dock = 'Fill'; $repFlow.FlowDirection = 'TopDown'; $repFlow.WrapContents = $false; $repFlow.AutoScroll = $true
$repFlow.Padding = New-Object System.Windows.Forms.Padding(12); $repFlow.BackColor = [System.Drawing.Color]::White

$intro = New-Object System.Windows.Forms.Label
$intro.Text = "Each repair opens in its own window and is logged to the report folder. Nothing runs until you click it.`r`nTip: create a restore point first. Typical order for a misbehaving PC: Clear temp files -> DISM + SFC -> CHKDSK scan -> restart."
$intro.AutoSize = $true; $intro.MaximumSize = New-Object System.Drawing.Size(1050, 0)
$intro.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
$repFlow.Controls.Add($intro)

$lastGroup = ''
foreach ($r in $script:Repairs) {
    if ($r.Group -ne $lastGroup) {
        $g = New-Object System.Windows.Forms.Label
        $g.Text = $r.Group; $g.Font = $FontHead; $g.ForeColor = $C_Dark; $g.AutoSize = $true
        $g.Margin = New-Object System.Windows.Forms.Padding(0, 10, 0, 2)
        $repFlow.Controls.Add($g)
        $lastGroup = $r.Group
    }
    $row = New-Object System.Windows.Forms.Panel; $row.Width = 1050; $row.Height = 38; $row.Margin = New-Object System.Windows.Forms.Padding(0)
    $b = New-Button $r.Name 250 $C_Accent
    $b.Location = New-Object System.Drawing.Point(0, 2); $b.Tag = $r
    if ($r.Admin -and -not $script:IsAdmin) { $b.Enabled = $false; $b.BackColor = [System.Drawing.Color]::Silver }
    $d = New-Object System.Windows.Forms.Label
    $d.Text = $r.Desc; $d.AutoSize = $false; $d.Width = 780; $d.Height = 34; $d.Location = New-Object System.Drawing.Point(262, 0); $d.TextAlign = 'MiddleLeft'
    $row.Controls.AddRange(@($b, $d))
    $b.Add_Click({
        param($sender, $e)
        $rep = $sender.Tag
        if ($rep.Confirm) {
            $ans = [System.Windows.Forms.MessageBox]::Show($rep.Confirm, "WinDiag - $($rep.Name)", 'YesNo', 'Warning')
            if ($ans -ne 'Yes') { return }
        }
        try {
            if ($rep.Launch) { Start-Process $rep.Launch -ErrorAction Stop }
            else { Start-RepairWindow $rep.Name $rep.Body }
            $statusLbl.Text = "Started: $($rep.Name)"
        } catch {
            [void][System.Windows.Forms.MessageBox]::Show("Could not start: $($_.Exception.Message)", 'WinDiag', 'OK', 'Error')
        }
    })
    $repFlow.Controls.Add($row)
}

$gt = New-Object System.Windows.Forms.Label
$gt.Text = 'Windows tools'; $gt.Font = $FontHead; $gt.ForeColor = $C_Dark; $gt.AutoSize = $true
$gt.Margin = New-Object System.Windows.Forms.Padding(0, 14, 0, 2)
$repFlow.Controls.Add($gt)
$toolFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$toolFlow.Width = 1050; $toolFlow.AutoSize = $true; $toolFlow.WrapContents = $true
foreach ($t in $script:Tools) {
    $b = New-Button $t.Name 160
    $b.Tag = $t
    $b.Add_Click({
        param($sender, $e)
        $tool = $sender.Tag
        try {
            if ($tool.Args) { Start-Process $tool.Cmd -ArgumentList $tool.Args -ErrorAction Stop } else { Start-Process $tool.Cmd -ErrorAction Stop }
        } catch { [void][System.Windows.Forms.MessageBox]::Show("Could not open $($tool.Name): $($_.Exception.Message)", 'WinDiag', 'OK', 'Error') }
    })
    $toolFlow.Controls.Add($b)
}
$repFlow.Controls.Add($toolFlow)
$tpRep.Controls.Add($repFlow)
[void]$tabs.TabPages.Add($tpRep)

$form.Controls.Add($tabs)
$form.Controls.Add($banner)
$form.Controls.Add($header)
$form.Controls.Add($statusStrip)
$tabs.BringToFront()

# ---- Logic --------------------------------------------------------------------------
function Update-Summary {
    $lv.BeginUpdate()
    $lv.Items.Clear()
    foreach ($f in (Get-SortedFindings)) {
        $item = New-Object System.Windows.Forms.ListViewItem($f.Status)
        [void]$item.SubItems.Add($f.Area); [void]$item.SubItems.Add($f.Finding); [void]$item.SubItems.Add($f.Advice)
        switch ($f.Status) { 'CRITICAL' { $item.BackColor = $C_Crit } 'WARNING' { $item.BackColor = $C_Warn } 'OK' { $item.BackColor = $C_Ok } }
        [void]$lv.Items.Add($item)
    }
    $lv.EndUpdate()
    $hs = Get-HealthScore
    $lblScore.Text = "$($hs.Score)/100"
    if ($hs.Score -ge 85) { $lblScore.ForeColor = [System.Drawing.Color]::ForestGreen }
    elseif ($hs.Score -ge 60) { $lblScore.ForeColor = [System.Drawing.Color]::DarkOrange }
    else { $lblScore.ForeColor = [System.Drawing.Color]::Firebrick }
    $verdict = if ($hs.Critical -gt 0) { 'Needs attention - start with the red items.' } elseif ($hs.Warning -gt 0) { 'Mostly OK - a few things to look at.' } else { 'Looks healthy.' }
    $lblScoreTxt.Text = "$($hs.Critical) critical, $($hs.Warning) warnings.  $verdict  (Double-click a row to copy it.)"
}

function Invoke-AllChecks {
    $btnRun.Enabled = $false; $btnSave.Enabled = $false
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $script:Findings.Clear(); $script:Results = @{}
    $lblScore.Text = '--/100'; $lblScore.ForeColor = [System.Drawing.Color]::Gray; $lblScoreTxt.Text = 'Running checks...'
    $lv.Items.Clear()
    $i = 0
    foreach ($c in $script:Checks) {
        if ($form.IsDisposed) { return }
        $statusLbl.Text = "Checking: $($c.Title)..."
        $progress.Value = $i
        $c.Box.Text = 'Checking, please wait...'
        [System.Windows.Forms.Application]::DoEvents()
        $sections = @()
        try { $sections = @(& $c.Fn) }
        catch { $sections = @(New-Section 'Check failed' @("Error: $($_.Exception.Message)")) }
        if ($form.IsDisposed) { return }
        $script:Results[$c.Key] = $sections
        Write-Rtb $c.Box $sections
        Update-Summary
        $i++
        [System.Windows.Forms.Application]::DoEvents()
    }
    $progress.Value = $progress.Maximum
    $path = $null
    try { $path = Export-Reports } catch {}
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $btnRun.Enabled = $true; $btnSave.Enabled = $true
    if ($path) { $statusLbl.Text = "Done. Report saved: $path" } else { $statusLbl.Text = 'Done. (Could not save report file.)' }
}

$btnRun.Add_Click({ Invoke-AllChecks })
$btnSave.Add_Click({
    try { $p = Export-Reports; Start-Process $p } catch { [void][System.Windows.Forms.MessageBox]::Show("Could not save report: $($_.Exception.Message)", 'WinDiag') }
})
$btnFolder.Add_Click({ Start-Process explorer.exe -ArgumentList "`"$script:ReportDir`"" })
$btnElevate.Add_Click({
    try { Start-Elevated; $form.Close() } catch { [void][System.Windows.Forms.MessageBox]::Show('Administrator rights were not granted.', 'WinDiag') }
})
$lv.Add_DoubleClick({
    if ($lv.SelectedItems.Count -gt 0) {
        $it = $lv.SelectedItems[0]
        [System.Windows.Forms.Clipboard]::SetText(('[{0}] {1}: {2} -> {3}' -f $it.Text, $it.SubItems[1].Text, $it.SubItems[2].Text, $it.SubItems[3].Text))
        $statusLbl.Text = 'Copied to clipboard.'
    }
})
$form.Add_Shown({ $form.Activate(); Invoke-AllChecks })

try {
    if (-not $script:ReportDir) { throw 'No writable location for reports (USB, Desktop and TEMP all failed).' }
    [void]$form.ShowDialog()
} catch {
    [void][System.Windows.Forms.MessageBox]::Show("WinDiag hit an error:`r`n$($_.Exception.Message)`r`n`r`nRun 'WinDiag (debug).bat' to see details.", 'WinDiag', 'OK', 'Error')
}
