"""PowerShell collector for Windows hosts (shared with WinDiag)."""
SCRIPT = r'''param([string]$Check = 'System', [string]$Out = "$env:TEMP\windiag_out.json", [int]$Days = 30)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$script:IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

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
#  CHECK 7: Windows Server roles
# ==================================================================================
function Get-ServerInfo {
    $out  = New-Object System.Collections.ArrayList
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $isServer = ([int]$os.ProductType -ne 1)
    $roleNames = @{ 0 = 'Standalone workstation'; 1 = 'Member workstation'; 2 = 'Standalone server'; 3 = 'Member server'; 4 = 'Backup domain controller'; 5 = 'Primary domain controller' }
    $isDC = ([int]$cs.DomainRole -ge 4)

    [void]$out.Add((New-Section 'Server overview' ([pscustomobject]@{
        'Windows'      = $os.Caption
        'Server OS'    = $(if ($isServer) { 'Yes' } else { 'No (client Windows)' })
        'Domain'       = $(if ($cs.PartOfDomain) { $cs.Domain } else { "Workgroup: $($cs.Workgroup)" })
        'Domain role'  = $roleNames[[int]$cs.DomainRole]
    }) -List))

    # Installed roles
    if ($isServer -and (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        $roles = @(Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object {
            [pscustomobject]@{ Role = $_.DisplayName; Name = $_.Name }
        })
        [void]$out.Add((New-Section "Installed roles ($($roles.Count))" $roles))
    }

    # Role services
    $svcMap = [ordered]@{
        NTDS = 'AD Domain Services'; DNS = 'DNS Server'; DHCPServer = 'DHCP Server'; Netlogon = 'Netlogon'; Kdc = 'Kerberos KDC'
        DFSR = 'DFS Replication'; W3SVC = 'IIS Web Server'; WAS = 'IIS Process Activation'; vmms = 'Hyper-V Management'
        ClusSvc = 'Failover Cluster'; MSSQLSERVER = 'SQL Server (default)'; SQLSERVERAGENT = 'SQL Server Agent'
        CertSvc = 'Certificate Services'; WsusService = 'WSUS'; TermService = 'Remote Desktop'; TermServLicensing = 'RD Licensing'
        LanmanServer = 'File sharing (SMB)'; Spooler = 'Print Spooler'; WDSServer = 'Deployment Services'; MSExchangeIS = 'Exchange Store'
    }
    $svcRows = New-Object System.Collections.ArrayList
    $all = @(Get-Service)
    foreach ($k in $svcMap.Keys) {
        $s = $all | Where-Object { $_.Name -eq $k } | Select-Object -First 1
        if ($s) { [void]$svcRows.Add([pscustomobject]@{ Service = $s.Name; Role = $svcMap[$k]; Status = "$($s.Status)"; Start = "$($s.StartType)" }) }
    }
    foreach ($s in ($all | Where-Object { $_.Name -like 'MSSQL$*' -or $_.Name -like 'SQLAgent$*' })) {
        [void]$svcRows.Add([pscustomobject]@{ Service = $s.Name; Role = 'SQL Server instance'; Status = "$($s.Status)"; Start = "$($s.StartType)" })
    }
    [void]$out.Add((New-Section 'Role services' $svcRows))
    foreach ($r in $svcRows) {
        if ($r.Start -eq 'Automatic' -and $r.Status -ne 'Running' -and $r.Service -notin 'Spooler') {
            Add-Finding 'CRITICAL' 'Server' "$($r.Role) service ($($r.Service)) is $($r.Status)" "Start it (Start-Service $($r.Service)) and check the System log / Event Analyzer for why it stopped."
        }
    }
    if ($isDC -and ($svcRows | Where-Object { $_.Service -eq 'Spooler' -and $_.Status -eq 'Running' })) {
        Add-Finding 'WARNING' 'Server' 'Print Spooler is running on a domain controller' 'Disable the Print Spooler on DCs (PrintNightmare hardening) unless it is really needed.'
    }

    # IIS
    $appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        $pools = @(& $appcmd list apppool 2>$null | ForEach-Object {
            if ($_ -match 'APPPOOL "(.+?)" \((.*)\)') {
                $nm = $matches[1]; $set = $matches[2]
                $st = if ($set -match 'state:(\w+)') { $matches[1] } else { '?' }
                [pscustomobject]@{ 'App pool' = $nm; State = $st; Settings = $set }
            }
        })
        $sites = @(& $appcmd list site 2>$null | ForEach-Object {
            if ($_ -match 'SITE "(.+?)" \((.*)\)') {
                $nm = $matches[1]; $set = $matches[2]
                $st = if ($set -match 'state:(\w+)') { $matches[1] } else { '?' }
                $b  = if ($set -match 'bindings:(.*?),state:') { $matches[1] } else { '' }
                [pscustomobject]@{ Site = $nm; State = $st; Bindings = $b }
            }
        })
        [void]$out.Add((New-Section 'IIS sites' $sites))
        [void]$out.Add((New-Section 'IIS application pools' $pools))
        foreach ($p in ($pools | Where-Object { $_.State -eq 'Stopped' })) { Add-Finding 'WARNING' 'IIS' "IIS app pool '$($p.'App pool')' is stopped" 'Start it in IIS Manager. If it stops again, check WAS events 5002/5009/5011 (rapid-fail protection).' }
        foreach ($s in ($sites | Where-Object { $_.State -eq 'Stopped' })) { Add-Finding 'WARNING' 'IIS' "IIS site '$($s.Site)' is stopped" 'Start it in IIS Manager (check for port/binding conflicts).' }
    }

    # Certificates (machine store, with private key)
    $certs = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and $_.NotAfter -lt (Get-Date).AddDays(60) -and $_.NotAfter -gt (Get-Date).AddDays(-120) } | Sort-Object NotAfter | ForEach-Object {
        $days = [int]($_.NotAfter - (Get-Date)).TotalDays
        [pscustomobject]@{ Subject = $_.Subject; 'Expires' = '{0:yyyy-MM-dd}' -f $_.NotAfter; 'Days left' = $days; Thumbprint = $_.Thumbprint }
    })
    [void]$out.Add((New-Section 'Certificates expiring within 60 days (LocalMachine\My)' $certs))
    foreach ($c in $certs) {
        if ($c.'Days left' -lt 0) { Add-Finding 'CRITICAL' 'Certificates' "Certificate EXPIRED: $($c.Subject) ($($c.Expires))" 'Renew it and update the IIS/RDP/LDAPS binding that uses it.' }
        elseif ($c.'Days left' -lt 30) { Add-Finding 'WARNING' 'Certificates' "Certificate expires in $($c.'Days left') days: $($c.Subject)" 'Renew before it expires.' }
    }

    # Hyper-V host
    if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
        $vms = @(Get-VM)
        if ($vms.Count -gt 0) {
            $vmRows = foreach ($v in $vms) {
                $snaps = @(Get-VMSnapshot -VMName $v.Name)
                $oldest = $null
                if ($snaps.Count) { $oldest = ($snaps | Sort-Object CreationTime | Select-Object -First 1).CreationTime }
                $age = if ($oldest) { [int]((Get-Date) - $oldest).TotalDays } else { $null }
                if ($age -ge 7) { Add-Finding 'WARNING' 'Hyper-V' "VM '$($v.Name)' has checkpoints $age days old" 'Delete or merge old checkpoints - AVHDX chains grow and slow down disk I/O. Checkpoints are not backups.' }
                if ("$($v.Status)" -and "$($v.Status)" -notmatch 'Operating normally') { Add-Finding 'WARNING' 'Hyper-V' "VM '$($v.Name)' status: $($v.Status)" 'Check the Hyper-V-VMMS / Worker admin logs.' }
                if ("$($v.ReplicationHealth)" -eq 'Critical') { Add-Finding 'CRITICAL' 'Hyper-V' "Replication for VM '$($v.Name)' is Critical" 'Check Hyper-V Replica status and resume/resync replication.' }
                [pscustomobject]@{
                    VM = $v.Name; State = "$($v.State)"; 'CPU %' = $v.CPUUsage; Memory = Format-Size $v.MemoryAssigned
                    Uptime = '{0}d {1}h' -f $v.Uptime.Days, $v.Uptime.Hours; Status = $v.Status
                    'Integration svcs' = "$($v.IntegrationServicesState)"; Checkpoints = $snaps.Count; 'Oldest chkpt (days)' = $age; Replication = "$($v.ReplicationHealth)"
                }
            }
            [void]$out.Add((New-Section "Hyper-V virtual machines ($($vms.Count))" $vmRows))
            $running = @($vms | Where-Object { "$($_.State)" -eq 'Running' })
            $assigned = ($running | Measure-Object MemoryAssigned -Sum).Sum
            $hostRam = [double]$cs.TotalPhysicalMemory
            if ($hostRam -gt 0) {
                $pct = [math]::Round($assigned / $hostRam * 100)
                [void]$out.Add((New-Section 'Hyper-V host memory' ([pscustomobject]@{ 'Host RAM' = Format-Size $hostRam; 'Assigned to running VMs' = Format-Size $assigned; 'Percent' = "$pct %" }) -List))
                if ($pct -ge 90) { Add-Finding 'WARNING' 'Hyper-V' "Running VMs use $pct% of host RAM" 'Leave RAM for the host (parent partition) - reduce VM memory or enable Dynamic Memory.' }
            }
        }
    }

    # Active Directory (domain controllers)
    if ($isDC) {
        $repl = @()
        try {
            $repl = @(repadmin /showrepl * /csv 2>$null | ConvertFrom-Csv | Where-Object { [int]$_.'Number of Failures' -gt 0 } | ForEach-Object {
                [pscustomobject]@{ 'Destination DC' = $_.'Destination DSA'; 'Source DC' = $_.'Source DSA'; 'Naming context' = $_.'Naming Context'; Failures = $_.'Number of Failures'; 'Last failure' = $_.'Last Failure Time'; Status = $_.'Last Failure Status' }
            })
        } catch {}
        [void]$out.Add((New-Section 'AD replication failures (repadmin /showrepl)' $repl))
        if ($repl.Count -gt 0) { Add-Finding 'CRITICAL' 'Active Directory' "$($repl.Count) AD replication link(s) are failing" 'Run "repadmin /replsummary" and "dcdiag /q"; check DNS, time sync and firewall between DCs.' }
        else { Add-Finding 'OK' 'Active Directory' 'No AD replication failures' }
        $shares = @(Get-SmbShare -Name SYSVOL, NETLOGON -ErrorAction SilentlyContinue)
        if ($shares.Count -lt 2) { Add-Finding 'CRITICAL' 'Active Directory' 'SYSVOL / NETLOGON share is missing on this DC' 'Group Policy and logon scripts will fail - check DFSR (events 2213/4012) and SYSVOL replication.' }
        $fsmo = @(netdom query fsmo 2>$null | Where-Object { $_ -match '\S' -and $_ -notmatch 'completed successfully' })
        if ($fsmo.Count) { [void]$out.Add((New-Section 'FSMO role holders' ($fsmo | ForEach-Object { $_.Trim() }))) }
    }

    # Failover cluster
    if (Get-Command Get-ClusterNode -ErrorAction SilentlyContinue) {
        $nodes = @(Get-ClusterNode | ForEach-Object { [pscustomobject]@{ Node = $_.Name; State = "$($_.State)" } })
        if ($nodes.Count) {
            [void]$out.Add((New-Section 'Cluster nodes' $nodes))
            foreach ($n in ($nodes | Where-Object { $_.State -ne 'Up' })) { Add-Finding 'CRITICAL' 'Cluster' "Cluster node $($n.Node) is $($n.State)" 'Check network/heartbeat (event 1135) and the node itself.' }
            $groups = @(Get-ClusterGroup | ForEach-Object { [pscustomobject]@{ Group = $_.Name; Owner = "$($_.OwnerNode)"; State = "$($_.State)" } })
            [void]$out.Add((New-Section 'Cluster roles / groups' $groups))
            foreach ($g in ($groups | Where-Object { $_.State -in 'Failed', 'PartialOnline' })) { Add-Finding 'CRITICAL' 'Cluster' "Cluster group '$($g.Group)' is $($g.State)" 'Open Failover Cluster Manager and check the failed resource.' }
            $csv = @(Get-ClusterSharedVolume | ForEach-Object { [pscustomobject]@{ CSV = $_.Name; State = "$($_.State)"; Owner = "$($_.OwnerNode)" } })
            if ($csv.Count) { [void]$out.Add((New-Section 'Cluster Shared Volumes' $csv)) }
        }
    }

    # Failed logons (brute force)
    $fails = @(Get-EventsSafe @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-1) } 5000)
    $lock  = @(Get-EventsSafe @{ LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddDays(-1) } 500)
    if ($fails.Count -gt 0) {
        $top = $fails | Group-Object { "$($_.Properties[19].Value)" } | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object {
            $u = ($_.Group | Group-Object { "$($_.Properties[5].Value)" } | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $_.Name }) -join ', '
            [pscustomobject]@{ 'Source IP' = $(if ($_.Name -and $_.Name -ne '-') { $_.Name } else { '(local / none)' }); Attempts = $_.Count; 'Top usernames' = $u }
        }
        [void]$out.Add((New-Section "Failed logons - last 24h ($($fails.Count) total, $($lock.Count) lockouts)" $top -Note 'Security log event 4625. Many attempts from one public IP = password guessing (often exposed RDP).'))
        if ($fails.Count -ge 200) { Add-Finding 'WARNING' 'Security' "$($fails.Count) failed logons in 24h" 'Do not expose RDP/SMB to the internet - use VPN/RD Gateway, enable account lockout and NLA.' }
    } elseif ($script:IsAdmin) {
        [void]$out.Add((New-Section 'Failed logons - last 24h' 'None'))
    }

    # RDP / SMB hardening
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
    if ($ts -and $ts.fDenyTSConnections -eq 0 -and $nla -eq 0) { Add-Finding 'WARNING' 'Security' 'RDP is enabled WITHOUT Network Level Authentication' 'Enable NLA (System Properties > Remote).' }
    $smb1 = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
    if ($smb1) { Add-Finding 'WARNING' 'Security' 'SMBv1 is enabled' 'Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false' }

    # Windows Server Backup
    if (Get-Command Get-WBSummary -ErrorAction SilentlyContinue) {
        $wb = Get-WBSummary
        if ($wb) {
            [void]$out.Add((New-Section 'Windows Server Backup' ([pscustomobject]@{ 'Last successful backup' = '{0:yyyy-MM-dd HH:mm}' -f $wb.LastSuccessfulBackupTime; 'Last backup result' = '0x{0:X}' -f $wb.LastBackupResultHR; 'Next backup' = '{0:yyyy-MM-dd HH:mm}' -f $wb.NextBackupTime; 'Versions' = $wb.NumberOfVersions }) -List))
            if ($wb.LastSuccessfulBackupTime -and ((Get-Date) - $wb.LastSuccessfulBackupTime).TotalDays -gt 3) {
                Add-Finding 'WARNING' 'Backup' ("Last successful Windows Server Backup was {0:N0} days ago" -f ((Get-Date) - $wb.LastSuccessfulBackupTime).TotalDays) 'Check the backup schedule and target disk (Microsoft-Windows-Backup events).'
            }
        }
    }

    if (-not $isServer -and $out.Count -le 3) {
        [void]$out.Add((New-Section 'Note' 'This is client Windows - server role checks do not apply. (Hyper-V VMs and certificates are still checked.)'))
    }
    $out
}

# ==================================================================================
#  CHECK 8: Virtualization / platform
# ==================================================================================
function Get-VirtInfo {
    $out  = New-Object System.Collections.ArrayList
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $man = "$($cs.Manufacturer)"; $model = "$($cs.Model)"
    $platform = 'Physical machine'
    if ($model -match 'Virtual Machine' -and $man -match 'Microsoft') {
        $platform = 'Hyper-V'
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Azure') { $platform = 'Azure (Hyper-V)' }
    }
    elseif ($man -match 'VMware' -or $model -match 'VMware') { $platform = 'VMware' }
    elseif ($model -match 'VirtualBox' -or $man -match 'innotek') { $platform = 'VirtualBox' }
    elseif ($man -match 'Amazon' -or $model -match 'EC2') { $platform = 'AWS EC2' }
    elseif ($man -match 'Google') { $platform = 'Google Cloud' }
    elseif ($man -match 'QEMU|Red Hat|oVirt|Nutanix' -or $model -match 'KVM|QEMU|Standard PC|OpenStack|Proxmox|AHV') { $platform = 'KVM / QEMU (Proxmox, OpenStack, Nutanix...)' }
    elseif ($man -match 'Xen' -or $model -match 'HVM domU') { $platform = 'Xen / Citrix Hypervisor' }
    elseif ($man -match 'Parallels') { $platform = 'Parallels' }
    $isVM = $platform -ne 'Physical machine'

    $src = (w32tm /query /source 2>$null | Out-String).Trim()
    $info = [pscustomobject]@{
        'Platform'            = $platform
        'Manufacturer / model'= "$man / $model"
        'BIOS'                = "$($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)"
        'Hypervisor present'  = $cs.HypervisorPresent
        'Hyper-V host role'   = $(if (Get-Service vmms -ErrorAction SilentlyContinue) { 'Yes' } else { 'No' })
        'Time source'         = $src
        'Domain joined'       = $cs.PartOfDomain
    }
    [void]$out.Add((New-Section 'Platform' $info -List))

    $svcNames = @()
    switch -Regex ($platform) {
        'Hyper-V' { $svcNames = 'vmicheartbeat', 'vmickvpexchange', 'vmicshutdown', 'vmictimesync', 'vmicvss', 'WindowsAzureGuestAgent', 'RdAgent' }
        'VMware'  { $svcNames = 'VMTools' }
        'KVM'     { $svcNames = 'QEMU-GA', 'BalloonService' }
        'VirtualBox' { $svcNames = 'VBoxService' }
        'AWS'     { $svcNames = 'AmazonSSMAgent' }
        'Google'  { $svcNames = 'GCEAgent', 'google_osconfig_agent' }
        'Xen'     { $svcNames = 'xenagent', 'XenSvc' }
    }
    if ($isVM) {
        $gs = foreach ($n in $svcNames) {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($platform -match 'Azure' -or $n -notin 'WindowsAzureGuestAgent', 'RdAgent') {
                [pscustomobject]@{ 'Guest service' = $n; Status = $(if ($s) { "$($s.Status)" } else { 'NOT INSTALLED' }); Start = $(if ($s) { "$($s.StartType)" } else { '' }) }
            }
        }
        [void]$out.Add((New-Section 'Guest tools / integration services' $gs))
        $missing = @($gs | Where-Object { $_.Status -eq 'NOT INSTALLED' -and $_.'Guest service' -notin 'BalloonService', 'vmicvss' })
        $stopped = @($gs | Where-Object { $_.Status -eq 'Stopped' -and $_.Start -eq 'Automatic' })
        $adv = switch -Regex ($platform) {
            'VMware' { 'Install / update VMware Tools.' }
            'KVM'    { 'Install virtio-win guest tools (QEMU guest agent + VirtIO drivers).' }
            'Hyper-V' { 'Enable integration services in the VM settings on the host.' }
            default  { 'Install the platform guest agent.' }
        }
        if ($missing.Count) { Add-Finding 'WARNING' 'Virtualization' ("Guest tools missing on {0}: {1}" -f $platform, (($missing.'Guest service') -join ', ')) $adv }
        foreach ($s in $stopped) { Add-Finding 'WARNING' 'Virtualization' "Guest service $($s.'Guest service') is stopped" 'Start it; it handles shutdown, time sync and backups from the host.' }
        if ($missing.Count -eq 0 -and $stopped.Count -eq 0 -and $svcNames.Count) { Add-Finding 'OK' 'Virtualization' "Running on $platform with guest tools OK" }

        if ($platform -match 'KVM') {
            $vio = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -match 'VirtIO|Red Hat' } | ForEach-Object { [pscustomobject]@{ Device = $_.DeviceName; Driver = $_.DriverVersion } })
            [void]$out.Add((New-Section 'VirtIO drivers' $vio))
            if ($vio.Count -eq 0) { Add-Finding 'WARNING' 'Virtualization' 'No VirtIO drivers found on a KVM VM' 'Using emulated IDE/e1000 devices is slow - install virtio-win drivers and switch disks/NIC to VirtIO.' }
        }
    }

    # Time sync sanity
    if ([int]$cs.DomainRole -ge 4 -and $src -match 'VM IC Time|Hyper-V|VMware|VBox') {
        Add-Finding 'WARNING' 'Time' "Domain controller takes its time from the hypervisor ($src)" 'Disable host time sync for DC VMs; the PDC should sync from external NTP and other DCs from the domain hierarchy.'
    } elseif ($cs.PartOfDomain -and $src -match 'Local CMOS Clock') {
        Add-Finding 'WARNING' 'Time' 'Domain member is not syncing time (Local CMOS Clock)' 'Run: w32tm /config /syncfromflags:domhier /update ; w32tm /resync. Kerberos fails with >5 min skew.'
    }
    $st = @(w32tm /query /status 2>$null | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() })
    if ($st.Count) { [void]$out.Add((New-Section 'Time service status (w32tm /query /status)' $st)) }
    $out
}

# ==================================================================================
#  Raw events for the Python Event Analyzer
# ==================================================================================
function Get-RawEvents([int]$Days) {
    $since = (Get-Date).AddDays(-$Days)
    $all = @()
    $all += @(Get-EventsSafe @{ LogName = 'System';      Level = 1, 2, 3; StartTime = $since } 6000)
    $all += @(Get-EventsSafe @{ LogName = 'Application'; Level = 1, 2, 3; StartTime = $since } 4000)
    $all += @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Windows Error Reporting'; Id = 1001; StartTime = $since } 400)
    $all += @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'User32'; Id = 1074; StartTime = $since } 200)
    $all += @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'; StartTime = $since } 20)
    $all += @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19, 20; StartTime = $since } 300)
    $all += @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'; Id = 37; StartTime = $since } 200)
    foreach ($ch in 'Microsoft-Windows-Hyper-V-VMMS-Admin', 'Microsoft-Windows-Hyper-V-Worker-Admin', 'Microsoft-Windows-Hyper-V-StorageVSP-Admin', 'Microsoft-Windows-Backup', 'Microsoft-Windows-DNSServer/Audit') {
        $all += @(Get-EventsSafe @{ LogName = $ch; Level = 1, 2; StartTime = $since } 500)
    }
    foreach ($ch in 'Directory Service', 'DFS Replication', 'DNS Server') {
        $all += @(Get-EventsSafe @{ LogName = $ch; Level = 1, 2, 3; StartTime = $since } 1500)
    }
    $needMsg = 'WHEA|Resource-Exhaustion|MemoryDiagnostics|SystemErrorReporting|BugCheck'
    $seen = @{}
    $rows = New-Object System.Collections.ArrayList
    foreach ($e in $all) {
        if (-not $e) { continue }
        $key = "$($e.ProviderName)|$($e.Id)"
        $n = [int]$seen[$key]; $seen[$key] = $n + 1
        $msg = ''
        if ($n -lt 2 -or $e.ProviderName -match $needMsg) {
            $m = $e.Message
            if ($m) { $m = ($m -replace '\s+', ' ').Trim(); if ($m.Length -gt 500) { $m = $m.Substring(0, 500) } ; $msg = $m }
        }
        $props = @($e.Properties | ForEach-Object { $v = "$($_.Value)"; if ($v.Length -gt 200) { $v.Substring(0, 200) } else { $v } })
        [void]$rows.Add([pscustomobject]@{
            t = $e.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss'); log = $e.LogName; p = $e.ProviderName
            id = $e.Id; lvl = [int]$e.Level; rid = $e.RecordId; props = $props; msg = $msg
        })
    }
    return ,$rows
}

# ==================================================================================
#  Runner
# ==================================================================================
if ($Out -eq '-') { try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {} }
function Invoke-OneCheck([string]$Name) {
    switch ($Name) {
        'System'   { return @(Get-SystemInfo) }
        'Disks'    { return @(Get-DiskInfo) }
        'Errors'   { return @(Get-ErrorInfo) }
        'Network'  { return @(Get-NetworkInfo) }
        'Startup'  { return @(Get-StartupInfo) }
        'Security' { return @(Get-SecurityInfo) }
        'Server'   { return @(Get-ServerInfo) }
        'Virt'     { return @(Get-VirtInfo) }
    }
}
function ConvertTo-SectionJson($secs) {
    @($secs | Where-Object { $_ } | ForEach-Object { [ordered]@{ title = $_.Title; note = $_.Note; list = $_.AsList; data = @($_.Data) } })
}
if ($Check -eq 'All') {
    $osx = Get-CimInstance Win32_OperatingSystem
    $all = [ordered]@{ check = 'All'; os_family = 'windows'; hostname = $env:COMPUTERNAME; os = "$($osx.Caption)"; admin = $script:IsAdmin
                       generated = (Get-Date -Format 'yyyy-MM-dd HH:mm'); checks = [ordered]@{}; events = @() }
    foreach ($n in 'System', 'Disks', 'Errors', 'Network', 'Startup', 'Security', 'Server', 'Virt') {
        $script:Findings.Clear()
        $entry = [ordered]@{ sections = @(); findings = @(); error = $null }
        try { $entry.sections = ConvertTo-SectionJson (Invoke-OneCheck $n) } catch { $entry.error = $_.Exception.Message }
        $entry.findings = @($script:Findings)
        $all.checks[$n] = $entry
    }
    try { $all.events = Get-RawEvents $Days } catch {}
    $json = $all | ConvertTo-Json -Depth 7 -Compress
    [Console]::Out.Write($json)
    return
}
$result = [ordered]@{ check = $Check; admin = $script:IsAdmin; error = $null; sections = @(); findings = @(); events = @() }
try {
    $secs = @()
    switch ($Check) {
        'System'   { $secs = @(Get-SystemInfo) }
        'Disks'    { $secs = @(Get-DiskInfo) }
        'Errors'   { $secs = @(Get-ErrorInfo) }
        'Network'  { $secs = @(Get-NetworkInfo) }
        'Startup'  { $secs = @(Get-StartupInfo) }
        'Security' { $secs = @(Get-SecurityInfo) }
        'Server'   { $secs = @(Get-ServerInfo) }
        'Virt'     { $secs = @(Get-VirtInfo) }
        'Events'   { $result.events = Get-RawEvents $Days }
    }
    $result.sections = @($secs | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ title = $_.Title; note = $_.Note; list = $_.AsList; data = @($_.Data) }
    })
} catch { $result.error = $_.Exception.Message }
$result.findings = @($script:Findings)
$json = $result | ConvertTo-Json -Depth 6 -Compress
if ($Out -eq '-') { [Console]::Out.Write($json) }
else { [System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false))) }
'''
