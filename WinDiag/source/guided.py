"""
WinDiag Guided Fix
------------------
Step-by-step troubleshooting playbooks that follow Microsoft's documented procedures
(Microsoft Learn: "Advanced troubleshooting for Stop error or blue screen error",
"Common Windows Update errors", Bug Check Code Reference, Microsoft.PowerShell.Diagnostics).

Each step: why (in plain language), the official Microsoft doc, an action that runs the
built-in Windows tool, and a verification that checks the result automatically.

Pure data + parsing here (testable anywhere). Execution lives in the GUI / core.
"""
import json
import os
import re
from datetime import datetime

# ---------------------------------------------------------------------------------
#  Official Microsoft documentation
# ---------------------------------------------------------------------------------
ML = "https://learn.microsoft.com/en-us/"
DOCS = {
    "wifi_fix": ("Microsoft: Fix Wi-Fi connection issues in Windows", "https://support.microsoft.com/windows/fix-wi-fi-connection-issues-in-windows-9424a1f7-6a3b-65a6-4d78-7f07eee84d2c"),
    "net_support": ("Microsoft Support: network connection problems (search)", "https://support.microsoft.com/search/results?query=fix+network+connection+issues+windows"),
    "bsod": ("Microsoft: Troubleshoot stop errors (blue screens)", ML + "troubleshoot/windows-client/performance/stop-error-or-blue-screen-error-troubleshooting"),
    "bugcheck_ref": ("Microsoft: Bug check code reference", ML + "windows-hardware/drivers/debugger/bug-check-code-reference2"),
    "wu_errors": ("Microsoft: Common Windows Update errors", ML + "troubleshoot/windows-client/installing-updates-features-roles/common-windows-update-errors"),
    "wu_reference": ("Microsoft: Windows Update error code reference", ML + "windows/deployment/update/windows-update-error-reference"),
    "windbg": ("Microsoft: Install WinDbg", ML + "windows-hardware/drivers/debugger/"),
    "analyze": ("Microsoft: !analyze debugger command", ML + "windows-hardware/drivers/debuggercmds/-analyze"),
    "verifier": ("Microsoft: Driver Verifier", ML + "windows-hardware/drivers/devtest/driver-verifier"),
    "cleanboot": ("Microsoft: How to perform a clean boot", "https://support.microsoft.com/topic/how-to-perform-a-clean-boot-in-windows-da2f9573-6eec-00ad-2f8a-a97a1807f3dd"),
    "sfc": ("Microsoft: Use System File Checker / DISM", "https://support.microsoft.com/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e"),
    "dism": ("Microsoft: Repair a Windows image (DISM)", ML + "windows-hardware/manufacture/desktop/repair-a-windows-image"),
    "chkdsk": ("Microsoft: chkdsk command", ML + "windows-server/administration/windows-commands/chkdsk"),
    "getwinevent": ("Microsoft: Get-WinEvent (PowerShell Diagnostics)", ML + "powershell/module/microsoft.powershell.diagnostics/get-winevent"),
    "getcounter": ("Microsoft: Get-Counter (PowerShell Diagnostics)", ML + "powershell/module/microsoft.powershell.diagnostics/get-counter"),
    "diag_module": ("Microsoft: Microsoft.PowerShell.Diagnostics module", ML + "powershell/module/microsoft.powershell.diagnostics/"),
    "recovery": ("Microsoft: Recovery options in Windows", "https://support.microsoft.com/windows/recovery-options-in-windows-31ce2444-7de3-818c-d626-e3b5c9e6f1d8"),
    "restore": ("Microsoft: System Restore", "https://support.microsoft.com/windows/use-system-restore-a5ae3ed9-07c4-fd56-45ee-096777ecd14e"),
    "update_drivers": ("Microsoft: Update drivers manually in Windows", "https://support.microsoft.com/windows/update-drivers-manually-in-windows-ec62f46c-ff14-c91d-eead-d7126dc1f7b6"),
    "rollback": ("Microsoft: Roll back a device driver", ML + "previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732648(v=ws.11)"),
    "catalog": ("Microsoft Update Catalog", "https://www.catalog.update.microsoft.com/"),
    "defender_offline": ("Microsoft: Defender Offline scan", "https://support.microsoft.com/windows/help-protect-my-pc-with-microsoft-defender-offline-9306d528-64bf-4668-5b80-ff533f183d6c"),
    "mdsched": ("Microsoft Q&A: Reading Windows Memory Diagnostic results", ML + "answers/questions/2668870/how-do-you-interpret-the-very-intuitive-and-user-f"),
    "dumps": ("Microsoft: Configure memory dump files", ML + "troubleshoot/windows-server/performance/memory-dump-file-options"),
    "malware_troubleshoot": ("Microsoft: Troubleshoot detecting and removing malware", "https://support.microsoft.com/en-us/defender/troubleshoot-problems-with-detecting-and-removing-malware"),
    "malware_guidance": ("Microsoft: Resources and guidance for removal of malware and viruses", "https://support.microsoft.com/en-us/topic/microsoft-resources-and-guidance-for-removal-of-malware-and-viruses-424a7d42-df47-4f9d-a98e-39082a5e9427"),
    "msrt": ("Microsoft: Malicious Software Removal Tool (KB890830)", "https://www.microsoft.com/en-us/download/details.aspx?id=9905"),
    "trusted_root": ("Microsoft: Trusted Root Program", "https://learn.microsoft.com/en-us/security/trusted-root/program-requirements"),
    "free_space": ("Microsoft: Free up drive space in Windows", "https://support.microsoft.com/windows/free-up-drive-space-in-windows-85529ccb-c365-490d-b548-831022bc9b32"),
}

# Verified slugs from Microsoft's Bug Check Code Reference (learn.microsoft.com)
_BC = "windows-hardware/drivers/debugger/bug-check-"
BUGCHECK_SLUGS = {
    0x0A: "0xa--irql-not-less-or-equal", 0x19: "0x19--bad-pool-header", 0x1A: "0x1a--memory-management",
    0x1E: "0x1e--kmode-exception-not-handled", 0x24: "0x24--ntfs-file-system", 0x3B: "0x3b--system-service-exception",
    0x3F: "0x3f--no-more-system-ptes", 0x44: "0x44--multiple-irp-complete-requests", 0x4E: "0x4e--pfn-list-corrupt",
    0x50: "0x50--page-fault-in-nonpaged-area", 0x76: "0x76--process-has-locked-pages", 0x77: "0x77--kernel-stack-inpage-error",
    0x7A: "0x7a--kernel-data-inpage-error", 0x7B: "0x7b--inaccessible-boot-device", 0x7E: "0x7e--system-thread-exception-not-handled",
    0x7F: "0x7f--unexpected-kernel-mode-trap", 0x80: "0x80--nmi-hardware-failure", 0x8E: "0x8e--kernel-mode-exception-not-handled",
    0x9C: "0x9c--machine-check-exception", 0x9F: "0x9f--driver-power-state-failure", 0xA0: "0xa0--internal-power-error",
    0xA5: "0xa5--acpi-bios-error", 0xBE: "0xbe--attempted-write-to-readonly-memory", 0xC2: "0xc2--bad-pool-caller",
    0xC4: "0xc4--driver-verifier-detected-violation", 0xC5: "0xc5--driver-corrupted-expool", 0xD1: "0xd1--driver-irql-not-less-or-equal",
    0xD5: "0xd5--driver-page-fault-in-freed-special-pool", 0xE0: "0xe0--acpi-bios-fatal-error", 0xEA: "0xea--thread-stuck-in-device-driver",
    0xED: "0xed--unmountable-boot-volume", 0xEF: "0xef--critical-process-died", 0xF4: "0xf4--critical-object-termination",
    0xF7: "0xf7--driver-overran-stack-buffer", 0xFC: "0xfc---attempted-execute-of-noexecute-memory", 0xFE: "0xfe--bugcode-usb-driver",
    0x101: "0x101---clock-watchdog-timeout", 0x109: "0x109---critical-structure-corruption", 0x10D: "0x10d---wdf-violation",
    0x10E: "0x10e---video-memory-management-internal", 0x113: "0x113---video-dxgkrnl-fatal-error", 0x116: "0x116---video-tdr-failure",
    0x117: "0x117---video-tdr-timeout-detected", 0x119: "0x119---video-scheduler-internal-error", 0x121: "0x121---driver-violation",
    0x124: "0x124---whea-uncorrectable-error", 0x12B: "0x12b---faulty-hardware-corrupted-page", 0x133: "0x133-dpc-watchdog-violation",
    0x139: "0x139--kernel-security-check-failure", 0x13A: "0x13a--kernel-mode-heap-corruption", 0x144: "0x144--bugcode-usb3-driver",
    0x154: "0x154--unexpected-store-exception", 0x18B: "0x18b--secure-kernel-error", 0x19C: "0x19c--win32k-power-watchdog-timeout",
    0x1C8: "0x1c8--manually-initiated-power-button-hold", 0x1DE: "0x1de--bugcode-wifiadapter-driver",
    0x1000007E: "0x1000007e--system-thread-exception-not-handled-m", 0x1000008E: "0x1000008e--kernel-mode-exception-not-handled-m",
    0x100000EA: "0x100000ea--thread-stuck-in-device-driver-m", 0xC000021A: "0xc000021a--winlogin-fatal-error",
}


def bugcheck_url(code):
    slug = BUGCHECK_SLUGS.get(code)
    if slug:
        return ML + _BC + slug
    return ML + "search/?terms=" + ("bug%%20check%%200x%X" % code)


# Microsoft "Common Windows Update errors" table (learn.microsoft.com)
WU_ERRORS = {
    0x8024402F: ("WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS", "A web filter/proxy is interfering with downloads - add update URLs to its exception list."),
    0x80242006: ("WU_E_UH_INVALIDMETADATA", "Rename SoftwareDistribution and catroot2 (the 'Reset Windows Update' step)."),
    0x80070BC9: ("ERROR_FAIL_REBOOT_REQUIRED", "Restart; make sure the Windows Installer service is not disabled (startup type Manual)."),
    0x80200053: ("BG_E_VALIDATION_FAILED", "A firewall/proxy is altering downloads - disable download filtering."),
    0x80072EFD: ("TIME_OUT_ERRORS", "Cannot reach Windows Update - check firewall/proxy and internet access."),
    0x80072EFE: ("WININET_E_CONNECTION_ABORTED", "Connection dropped - check BITS, proxy and network."),
    0x80D02002: ("TIME_OUT_ERRORS", "Download timed out - check network/proxy."),
    0x8007000D: ("ERROR_INVALID_DATA", "Downloaded data is corrupt - reset Windows Update and retry."),
    0x8024A10A: ("USO_E_SERVICE_SHUTTING_DOWN", "Keep the PC awake/active during installation."),
    0x80240020: ("WU_E_NO_INTERACTIVE_USER", "Sign in and allow the device to restart."),
    0x80242014: ("WU_E_UH_POSTREBOOTSTILLPENDING", "Restart the PC to finish the installation."),
    0x80246017: ("WU_E_DM_UNAUTHORIZED_LOCAL_USER", "Install as a local administrator."),
    0x8024000B: ("WU_E_CALL_CANCELLED", "Retry; if it repeats, something is filtering update traffic."),
    0x8024000E: ("WU_E_XML_INVALID", "Update the Windows Update Agent (install the latest cumulative update)."),
    0x80070422: ("ERROR_SERVICE_DISABLED", "The Windows Update service is disabled - set it back to Manual and start it."),
    0x800F0821: ("CBS_E_ABORT", "Update timed out - give the PC more resources / install the latest servicing stack."),
    0x800F0825: ("CBS_E_CANNOT_UNINSTALL", "Run DISM /RestoreHealth then SFC /scannow."),
    0x800F0920: ("CBS_E_HANG_DETECTED", "Servicing hung - install the latest servicing stack update, then retry."),
    0x800F081F: ("CBS_E_SOURCE_MISSING", "Run DISM /RestoreHealth then SFC /scannow (DISM needs internet or a Windows ISO as source)."),
    0x800F0831: ("CBS_E_STORE_CORRUPTION", "Component store corrupt - run DISM /RestoreHealth then SFC /scannow."),
    0x80070005: ("E_ACCESSDENIED", "Permission problem - check CBS.log for the file/registry key; antivirus can cause this."),
    0x80070570: ("ERROR_FILE_CORRUPT", "Run DISM /RestoreHealth then SFC /scannow; check the disk (CHKDSK)."),
    0x80070003: ("ERROR_PATH_NOT_FOUND", "A path is missing - see CBS.log; reset Windows Update."),
    0x80070020: ("ERROR_SHARING_VIOLATION", "Another program (often antivirus) locks files - try a clean boot."),
    0x80073701: ("ERROR_SXS_ASSEMBLY_MISSING", "Run DISM /RestoreHealth then SFC /scannow."),
    0x8007371B: ("ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE", "Run DISM /RestoreHealth then SFC /scannow."),
    0x80072F8F: ("WININET_E_DECODING_FAILED", "TLS/clock problem - check the date/time and TLS 1.2 support."),
    0x80072EE2: ("WININET_E_TIMEOUT", "Network timeout - check internet and that update endpoints are reachable."),
    0x80240022: ("WU_E_ALL_UPDATES_FAILED", "Antivirus may be blocking the SoftwareDistribution folder."),
    0x8024401B: ("WU_E_PT_HTTP_STATUS_PROXY_AUTH_REQ", "Proxy needs authentication - configure the WinHTTP proxy."),
    0x80244022: ("WU_E_PT_HTTP_STATUS_SERVICE_UNAVAILABLE", "Update server unavailable - check connectivity and retry later."),
    0x80070490: ("ERROR_NOT_FOUND", "Component registration problem - run DISM + SFC; see Microsoft's article for the registry fix."),
    0x800F0922: ("CBS_E_INSTALLERS_FAILED", "Often low space on the System Reserved/EFI partition, VPN, or .NET/servicing issue - see Microsoft's article."),
    0x800706BE: ("RPC_S_CALL_FAILED", "Corrupted update registry state - reset Windows Update, then DISM + SFC."),
}


def wu_error_info(code_text):
    m = re.search(r"0x([0-9a-fA-F]{6,8})", code_text or "")
    if not m:
        try:
            v = int(code_text) & 0xFFFFFFFF
        except (TypeError, ValueError):
            return None
    else:
        v = int(m.group(1), 16)
    name, fix = WU_ERRORS.get(v, (None, None))
    return {"code": "0x%08X" % v, "name": name, "fix": fix, "known": name is not None}


# Friendly names for drivers that commonly show up in crash dumps
DRIVER_HINTS = [
    (r"^nvlddmkm", "NVIDIA graphics driver", "GPU"), (r"^(amdkmdag|atikmdag|atikmpag|amdkmpfd)", "AMD graphics driver", "GPU"),
    (r"^(igdkmd|igdkmdn|igdkmdnd)", "Intel graphics driver", "GPU"), (r"^(dxgkrnl|dxgmms\d|watchdog)", "DirectX graphics kernel (usually the GPU driver)", "GPU"),
    (r"^win32k", "Windows graphics/UI subsystem (often GPU driver)", "GPU"),
    (r"^(stornvme|storport|storahci|iastor\w*|nvme\w*|secnvme|samsungnvme)", "storage / NVMe driver", "NVME"),
    (r"^(ntfs|fltmgr|volmgr|volsnap|disk|classpnp)", "file system / disk stack", "DISK"),
    (r"^(tcpip|netio|ndis|afd|http)", "Windows network stack (often a NIC, VPN or firewall driver)", "NETWORK"),
    (r"^(netwtw|netwbw|netwsw)", "Intel Wi-Fi driver", "NETWORK"), (r"^(rt\w*64|rtwlane|rtux|rtkvhd)", "Realtek network/audio driver", "NETWORK"),
    (r"^(e1\w*|e2f\w*|iaNVMe)", "Intel Ethernet driver", "NETWORK"), (r"^(athw|athr|qca)", "Qualcomm Atheros Wi-Fi driver", "NETWORK"),
    (r"^(usbxhci|usbhub3|ucx01000|usbport|usbstor)", "USB controller driver", "USB"), (r"^(bthport|bthusb)", "Bluetooth driver", "DRIVER"),
    (r"^(hdaudbus|portcls|ks|hdaudio)", "audio driver stack", "DRIVER"),
    (r"^(wdfilter|mssecflt|wdboot|wdnisdrv)", "Microsoft Defender filter driver", "DRIVER"),
    (r"^(aswsp|aswsnx|aswmonflt|avgsp)", "Avast/AVG antivirus driver", "DRIVER"), (r"^(klif|kneps|klhk)", "Kaspersky antivirus driver", "DRIVER"),
    (r"^(epfw|ehdrv|eamonm)", "ESET antivirus driver", "DRIVER"), (r"^(mbam|mbamswissarmy|farflt)", "Malwarebytes driver", "DRIVER"),
    (r"^vgk", "Riot Vanguard anti-cheat driver", "DRIVER"), (r"^(easyanticheat|eac)", "EasyAntiCheat driver", "DRIVER"),
    (r"^bedaisy", "BattlEye anti-cheat driver", "DRIVER"), (r"^(vboxdrv|vmx86|vmci)", "VirtualBox/VMware host driver", "DRIVER"),
    (r"^(ntoskrnl|ntkrnlmp|nt)$", "Windows kernel - the real cause is usually a driver or hardware (RAM/CPU)", "RAM"),
    (r"^hal$", "Hardware abstraction layer - usually hardware (CPU/RAM/BIOS)", "CPU"),
    (r"^(memory_corruption|hardware)", "memory / hardware corruption", "RAM"),
]


def driver_hint(image):
    base = re.sub(r"\.(sys|exe|dll)$", "", (image or "").strip().lower())
    for rx, desc, cat in DRIVER_HINTS:
        if re.match(rx, base):
            return desc, cat
    if base:
        return "third-party driver '%s' - search its name to find the product/vendor" % image, "DRIVER"
    return "", None


def parse_analyze(text):
    """Parse cdb/WinDbg '!analyze -v' output."""
    def f(name):
        m = re.search(r"^\s*%s:\s*(.+)$" % name, text, re.M)
        return m.group(1).strip() if m else ""
    r = {"bugcheck": f("BUGCHECK_CODE"), "bugcheck_str": f("BUGCHECK_STR") or f("DEFAULT_BUCKET_ID"),
         "image": f("IMAGE_NAME"), "module": f("MODULE_NAME"), "process": f("PROCESS_NAME"),
         "bucket": f("FAILURE_BUCKET_ID"), "symbol": f("SYMBOL_NAME")}
    m = re.search(r"Probably caused by\s*:\s*(\S+)", text)
    r["probably"] = m.group(1) if m else ""
    m = re.search(r"^([A-Z0-9_]+)\s+\(([0-9a-f]+)\)\s*$", text, re.M)
    r["name"] = m.group(1) if m else ""
    img = r["image"] or r["probably"].split("(")[0]
    if "memory_corruption" in (r["bucket"] + r["probably"]).lower():
        img = "memory_corruption"
    r["culprit"] = img
    r["hint"], r["cat"] = driver_hint(img)
    return r


# ---------------------------------------------------------------------------------
#  PowerShell verification scripts (each prints ONE JSON object)
#  {since} is replaced by an ISO timestamp, {status} by a status-file path.
# ---------------------------------------------------------------------------------
# Invariant culture: a Thai/Persian/... calendar would read "2026-..." as a different year. en-US thread culture
# keeps event messages from coming back empty on mixed-locale systems and dates Gregorian.
PS_HEAD = ("$ErrorActionPreference='SilentlyContinue'; try { Remove-TypeData System.Array -ErrorAction Stop } catch {}; "
           "$since=[datetime]::Parse('{since}', [Globalization.CultureInfo]::InvariantCulture); "
           "try { [Threading.Thread]::CurrentThread.CurrentCulture = 'en-US' } catch {}\n")

VERIFY_PS = {
    "sfc": PS_HEAD + r"""
$log = "$env:windir\Logs\CBS\CBS.log"
$sr = @(Get-Content $log -Tail 60000 | Where-Object { $_ -match '\[SR\]' } | Where-Object {
    $t = $null; if ($_.Length -ge 19 -and [datetime]::TryParse($_.Substring(0,19), [ref]$t)) { $t -ge $since } else { $false } })
$bad = @($sr | Where-Object { $_ -match 'Cannot repair member file' }).Count
$fixed = @($sr | Where-Object { $_ -match 'Repairing corrupted file|Repaired file|Repairing \d+ components' }).Count
$done = @($sr | Where-Object { $_ -match 'Verify complete|Repair complete' }).Count
$st = if ($sr.Count -eq 0) { 'pending' } elseif ($bad -gt 0) { 'fail' } elseif ($fixed -gt 0) { 'fixed' } elseif ($done -gt 0) { 'pass' } else { 'pending' }
@{ status = $st; detail = "SFC log lines since start: $($sr.Count); repaired: $fixed; could not repair: $bad"; sample = @($sr | Select-Object -Last 5) } | ConvertTo-Json -Compress
""",
    "status_exit": PS_HEAD + r"""
$f = '{status}'
if (-not (Test-Path $f)) { @{ status = 'pending'; detail = 'The repair window has not finished yet.' } | ConvertTo-Json -Compress; return }
$s = Get-Content $f -Raw | ConvertFrom-Json
@{ status = 'done'; exit = $s.exit; extra = $s.extra; detail = "Finished $($s.finished), exit code $($s.exit)" } | ConvertTo-Json -Compress -Depth 4
""",
    "chkdsk_boot": PS_HEAD + r"""
# Wininit 1001 = boot-time CHKDSK result; Chkdsk 26212/26214/26226 = chkdsk /scan or offline results (IDs are locale-proof)
$e = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Microsoft-Windows-Wininit', 'Wininit'; Id = 1001; StartTime = $since } -MaxEvents 3 -ErrorAction SilentlyContinue) +
     @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Chkdsk'; Id = 26212, 26214, 26226; StartTime = $since } -MaxEvents 3 -ErrorAction SilentlyContinue) |
     Where-Object { $_ } | Sort-Object TimeCreated -Descending | Select-Object -First 1
if (-not $e) { @{ status = 'pending'; detail = 'No CHKDSK result yet - restart the PC to let CHKDSK run (it can take hours).' } | ConvertTo-Json -Compress; return }
$m = "$($e.Message)"
$bad = if ($m -match '(\d[\d,.]*)\s*KB in bad sectors') { $matches[1] } else { '' }
$st = 'review'
if ($m -match 'found no problems|No further action is required') { $st = 'pass' }
elseif ($m -match 'made corrections|Correcting|fixed|replaced') { $st = 'fixed' }
if ($bad -and $bad -notmatch '^0$') { $st = 'fail' }
$how = if ($st -eq 'review') { ' Read the CHKDSK summary below (it may be in your Windows language).' } else { '' }
@{ status = $st; detail = "CHKDSK result from $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm')). Bad sectors: $(if ($bad) { $bad + ' KB' } else { 'n/a' }).$how"; sample = @(($m -split "`n" | Where-Object { $_.Trim() }) | Select-Object -Last 12) } | ConvertTo-Json -Compress
""",
    "memtest": PS_HEAD + r"""
$e = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'; StartTime = $since } -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $e) { @{ status = 'pending'; detail = 'No memory test result yet - the test runs on the next restart and the result appears after you sign in.' } | ConvertTo-Json -Compress; return }
$st = if ($e.Id -in 1102, 1202 -or $e.Level -le 2) { 'fail' } else { 'pass' }
@{ status = $st; detail = "Event $($e.Id) at $($e.TimeCreated): $(($e.Message -split "`n")[0])" } | ConvertTo-Json -Compress
""",
    "wu_history": PS_HEAD + r"""
$h = @()
try { $s = New-Object -ComObject Microsoft.Update.Session; $q = $s.CreateUpdateSearcher(); $n = $q.GetTotalHistoryCount(); if ($n) { $h = @($q.QueryHistory(0, [math]::Min(80, $n))) } } catch {}
$new = @($h | Where-Object { $_.Date.ToLocalTime() -ge $since -and $_.Title })
$ok = @($new | Where-Object { $_.ResultCode -eq 2 }); $bad = @($new | Where-Object { $_.ResultCode -eq 4 })
$fails = @($bad | ForEach-Object { @{ title = $_.Title; code = ('0x{0:X8}' -f ($_.HResult -band 0xFFFFFFFF)) } })
$st = if ($bad.Count) { 'fail' } elseif ($ok.Count) { 'pass' } else { 'pending' }
@{ status = $st; detail = "Since this step: $($ok.Count) installed, $($bad.Count) failed"; fails = $fails; installed = @($ok | ForEach-Object { $_.Title }) } | ConvertTo-Json -Compress -Depth 4
""",
    "wu_service": PS_HEAD + r"""
$s = Get-Service wuauserv; $b = Get-Service bits
$p = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $p += 'servicing' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $p += 'windows update' }
$prob = @()
if ("$($s.StartType)" -eq 'Disabled') { $prob += 'Windows Update service is DISABLED' }
if ("$($b.StartType)" -eq 'Disabled') { $prob += 'BITS service is DISABLED' }
if ($p.Count) { $prob += "Restart pending ($($p -join ', ')) - restart first" }
@{ status = $(if ($prob.Count) { 'fail' } else { 'pass' }); detail = $(if ($prob.Count) { $prob -join '; ' } else { "Windows Update service: $($s.StartType)/$($s.Status); BITS: $($b.StartType); no restart pending" }) } | ConvertTo-Json -Compress
""",
    "space_c": PS_HEAD + r"""
$v = Get-Volume -DriveLetter ($env:SystemDrive.TrimEnd(':'))
$free = [math]::Round($v.SizeRemaining / 1GB, 1); $pct = [math]::Round($v.SizeRemaining / $v.Size * 100, 1)
# same rule as Tune-up: low = under 20 GB, or under 10% AND under 100 GB
$st = if ($free -lt 10) { 'fail' } elseif ($free -lt 20 -or ($pct -lt 10 -and $free -lt 100)) { 'review' } else { 'pass' }
@{ status = $st; detail = "$env:SystemDrive has $free GB free ($pct%). Windows updates need about 20 GB free." } | ConvertTo-Json -Compress
""",
    "wu_network": PS_HEAD + r"""
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$r = @()
foreach ($u in 'https://www.catalog.update.microsoft.com', 'http://www.msftconnecttest.com/connecttest.txt') {
    try { $w = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 10 -Method Head; $r += "$u -> $($w.StatusCode)" } catch { $r += "$u -> FAILED ($($_.Exception.Message))" }
}
# WinHTTP proxy from the registry (netsh output is translated): bytes 12-15 = length of the proxy server string
$wh = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name WinHttpSettings -ErrorAction SilentlyContinue).WinHttpSettings
$pxSet = [bool]($wh -and $wh.Length -ge 16 -and [BitConverter]::ToInt32([byte[]]$wh, 12) -gt 0)
$st = if (($r -match 'FAILED').Count) { 'fail' } else { 'pass' }
@{ status = $st; detail = ($r -join ' | ') + ' | WinHTTP proxy: ' + ($(if ($pxSet) { 'SET - check it' } else { 'none (direct)' })) } | ConvertTo-Json -Compress
""",
    "defender_defs": PS_HEAD + r"""
$m = Get-MpComputerStatus
$t = $m.AntivirusSignatureLastUpdated
$st = if (-not $t) { 'fail' } elseif ($t -ge (Get-Date).AddDays(-1)) { 'pass' } else { 'pending' }
@{ status = $st; detail = $(if ($t) { "Definitions dated $t (version $($m.AntivirusSignatureVersion))" } else { 'Microsoft Defender is not available on this PC.' }) } | ConvertTo-Json -Compress
""",
    "net_reset": PS_HEAD + r"""
$bad = @()
$is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
if ($is.ProxyEnable -eq 1) { $bad += "Proxy is on: $($is.ProxyServer)" }
if ($is.AutoConfigURL) { $bad += "PAC script: $($is.AutoConfigURL)" }
$h = @(Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*(#|$)' })
if ($h.Count) { $bad += "Hosts file has $($h.Count) custom line(s)" }
@{ status = $(if ($bad.Count) { 'review' } else { 'pass' }); detail = $(if ($bad.Count) { 'Still set - remove them if you did not add them on purpose.' } else { 'No proxy, PAC script or custom hosts entries.' }); sample = $bad } | ConvertTo-Json -Compress
""",
    "wu_pending": None,
    "restore_point": PS_HEAD + r"""
$rp = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1
if ($rp) { $t = [Management.ManagementDateTimeConverter]::ToDateTime($rp.CreationTime) }
$st = if ($rp -and $t -ge $since.AddHours(-24)) { 'pass' } else { 'pending' }
@{ status = $st; detail = $(if ($rp) { "Newest restore point: '$($rp.Description)' at $t" } else { 'No restore points found (System Protection may be off).' }) } | ConvertTo-Json -Compress
""",
    "devices": PS_HEAD + r"""
$bad = @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' | Where-Object { $_.ConfigManagerErrorCode -notin 22, 45 } | ForEach-Object { "$($_.Name) (Code $($_.ConfigManagerErrorCode))" })
@{ status = $(if ($bad.Count) { 'fail' } else { 'pass' }); detail = $(if ($bad.Count) { "$($bad.Count) device(s) with driver problems" } else { 'No devices with driver problems' }); sample = $bad } | ConvertTo-Json -Compress
""",
    "defender_scan": PS_HEAD + r"""
$m = Get-MpComputerStatus
$t = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $since })
$scanned = ($m.QuickScanEndTime -ge $since) -or ($m.FullScanEndTime -ge $since)
$st = if (-not $scanned) { 'pending' } elseif ($t.Count) { 'fixed' } else { 'pass' }
@{ status = $st; detail = "Scan since this step: $scanned; threats detected: $($t.Count); definitions: $($m.AntivirusSignatureLastUpdated)" } | ConvertTo-Json -Compress
""",
    "disk_health": PS_HEAD + r"""
$rows = @(); $bad = 0
foreach ($d in Get-PhysicalDisk) {
    $r = $d | Get-StorageReliabilityCounter
    $unc = [int64]$r.ReadErrorsUncorrected + [int64]$r.WriteErrorsUncorrected
    if ("$($d.HealthStatus)" -ne 'Healthy' -or $unc -gt 0 -or $r.Wear -ge 90) { $bad++ }
    $rows += "$($d.FriendlyName): $($d.HealthStatus), wear $($r.Wear)%, temp $($r.Temperature) C, uncorrected errors $unc"
}
@{ status = $(if ($bad) { 'fail' } else { 'pass' }); detail = $(if ($bad) { "$bad drive(s) report problems" } else { 'All drives report Healthy with no uncorrected errors' }); sample = $rows } | ConvertTo-Json -Compress
""",
    "disk_latency": PS_HEAD + r"""
# Raw counters over a 5 s window (the formatted class rounds to whole seconds = always 0 ms); per physical disk
$a = @(Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk | Where-Object { $_.Name -ne '_Total' }); Start-Sleep -Seconds 5
$b = @(Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk | Where-Object { $_.Name -ne '_Total' })
$vals = @(foreach ($x in $b) {
    $y = $a | Where-Object { $_.Name -eq $x.Name } | Select-Object -First 1
    if (-not $y) { continue }
    $dn = [double]$x.AvgDisksecPerTransfer - [double]$y.AvgDisksecPerTransfer
    $db = [double]$x.AvgDisksecPerTransfer_Base - [double]$y.AvgDisksecPerTransfer_Base
    if ($db -gt 0 -and $x.Frequency_PerfTime -gt 0) { [pscustomobject]@{ disk = $x.Name; ms = [math]::Round(($dn / $x.Frequency_PerfTime) / $db * 1000, 1); io = $db } }
    else { [pscustomobject]@{ disk = $x.Name; ms = $null; io = 0 } }
})
$busy = @($vals | Where-Object { $_.ms -ne $null })
if (-not $busy.Count) { @{ status = 'review'; detail = 'The disks were idle during the 5 s measurement (or the performance counters are disabled) - use the PC normally and check again.' } | ConvertTo-Json -Compress; return }
$worst = ($busy | Measure-Object ms -Maximum).Maximum
$st = if ($worst -ge 100) { 'fail' } elseif ($worst -ge 30) { 'review' } else { 'pass' }
@{ status = $st; detail = "Average disk response time over 5 s: " + (($vals | ForEach-Object { "$($_.disk): $(if ($_.ms -ne $null) { "$($_.ms) ms" } else { 'idle' })" }) -join ', ') + '. Under 20 ms is healthy for SSDs.' } | ConvertTo-Json -Compress
""",
    "aspm": PS_HEAD + r"""
$q = (powercfg /qh SCHEME_CURRENT SUB_PCIEXPRESS ASPM) -join "`n"
# The first 0x........ value is the current AC index, the second the DC index (labels are translated, the hex is not)
$hx = @([regex]::Matches($q, '(?i)\b0x([0-9a-f]{8})\b') | ForEach-Object { $_.Groups[1].Value })
$ac = if ($hx.Count) { [Convert]::ToInt32($hx[0], 16) } else { -1 }
@{ status = $(if ($ac -eq 0) { 'pass' } elseif ($ac -lt 0) { 'review' } else { 'pending' }); detail = $(if ($ac -eq 0) { 'PCI Express Link State Power Management is OFF' } elseif ($ac -lt 0) { 'Could not read the setting (hidden on some systems)' } else { "Link State Power Management is ON (level $ac)" }) } | ConvertTo-Json -Compress
""",
    "gpu_info": PS_HEAD + r"""
$g = @(Get-CimInstance Win32_VideoController | ForEach-Object { "$($_.Name) - driver $($_.DriverVersion) dated $('{0:yyyy-MM-dd}' -f $_.DriverDate)" })
$old = @(Get-CimInstance Win32_VideoController | Where-Object { $_.DriverDate -and $_.DriverDate -lt (Get-Date).AddMonths(-9) }).Count
@{ status = $(if ($old) { 'review' } else { 'pass' }); detail = $(if ($old) { 'GPU driver is older than 9 months - update it.' } else { 'GPU driver is recent.' }); sample = $g } | ConvertTo-Json -Compress
""",
    "bios_info": PS_HEAD + r"""
$b = Get-CimInstance Win32_BIOS; $cs = Get-CimInstance Win32_ComputerSystem; $bb = Get-CimInstance Win32_BaseBoard
$age = if ($b.ReleaseDate) { [int]((Get-Date) - $b.ReleaseDate).TotalDays } else { -1 }
@{ status = $(if ($age -gt 540) { 'review' } else { 'pass' }); detail = "BIOS $($b.SMBIOSBIOSVersion) from $('{0:yyyy-MM-dd}' -f $b.ReleaseDate) ($age days old). Board: $($bb.Manufacturer) $($bb.Product); PC: $($cs.Manufacturer) $($cs.Model). Check the maker's support page for a newer BIOS." } | ConvertTo-Json -Compress
""",
    "throttle": PS_HEAD + r"""
$n = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'; Id = 37; StartTime = $since } -MaxEvents 200 -ErrorAction SilentlyContinue).Count
$tz = @(Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | ForEach-Object { [math]::Round($_.CurrentTemperature / 10 - 273.15) })
@{ status = $(if ($n) { 'fail' } else { 'pass' }); detail = "CPU throttling events since this step: $n. ACPI thermal zones: $(if ($tz.Count) { ($tz -join ', ') + ' C' } else { 'not reported (use HWiNFO for real sensor readings)' })" } | ConvertTo-Json -Compress
""",
    "verifier": PS_HEAD + r"""
$q = (verifier /querysettings) -join "`n"
$on = $q -notmatch 'No drivers are currently verified' -and $q -match '\.sys'
@{ status = $(if ($on) { 'review' } else { 'pass' }); detail = $(if ($on) { 'Driver Verifier is ACTIVE. Remember to turn it off (verifier /reset) when done testing.' } else { 'Driver Verifier is off.' }); sample = @(($q -split "`n") | Where-Object { $_.Trim() } | Select-Object -Last 10) } | ConvertTo-Json -Compress
""",
    "dump_config": PS_HEAD + r"""
$k = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$names = @{ 0 = 'None'; 1 = 'Complete'; 2 = 'Kernel'; 3 = 'Small (minidump)'; 7 = 'Automatic' }
$mini = @(Get-ChildItem "$env:SystemRoot\Minidump" -Filter *.dmp -ErrorAction SilentlyContinue).Count
$pf = @(Get-CimInstance Win32_PageFileUsage).Count
$st = if ($k.CrashDumpEnabled -eq 0 -or $pf -eq 0) { 'fail' } else { 'pass' }
@{ status = $st; detail = "Dump type: $($names[[int]$k.CrashDumpEnabled]); page file present: $($pf -gt 0); minidumps on disk: $mini" } | ConvertTo-Json -Compress
""",
}

VERIFY_DOC = {  # which Microsoft PowerShell doc the check is based on
    "chkdsk_boot": "getwinevent", "memtest": "getwinevent", "throttle": "getwinevent",
}

# ---------------------------------------------------------------------------------
#  Extra repair actions used by the playbooks (merged into core.REPAIRS by name)
# ---------------------------------------------------------------------------------
EXTRA_REPAIRS = [
    dict(group="Advanced (used by Guided Fix)", name="Disable PCIe power saving (ASPM)", admin=True,
         desc="Sets PCI Express Link State Power Management to Off in the current power plan (reversible).",
         confirm="Turn off PCI Express power saving (ASPM) in the current power plan?\n\nThis changes a power setting: laptops may use a little more "
                 "battery. You can turn it back on in Power Options > PCI Express.",
         body=r"""powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0
powercfg /setdcvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0
powercfg /setactive SCHEME_CURRENT
Write-Host 'PCI Express Link State Power Management is now Off.' -ForegroundColor Green
$WDStatus = @{ ok = $true }"""),
    dict(group="Advanced (used by Guided Fix)", name="Install WinDbg (Microsoft debugger)", admin=True,
         desc="Installs Microsoft's free WinDbg with winget so crash dumps can be analysed.",
         body=r"""if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install -e --id Microsoft.WinDbg --accept-source-agreements --accept-package-agreements
    $WDStatus = @{ exit = $LASTEXITCODE }
} else {
    Write-Host 'winget is not available on this PC. Install WinDbg from the Microsoft Store or https://aka.ms/windbg/download' -ForegroundColor Yellow
    Start-Process 'https://aka.ms/windbg/download'
    $WDStatus = @{ exit = 1 }
}"""),
    dict(group="Advanced (used by Guided Fix)", name="Set dump type to Automatic memory dump", admin=True,
         desc="Microsoft's recommended dump setting, so the next blue screen can be analysed.",
         confirm="Change the crash dump setting to 'Automatic memory dump' (Microsoft's default)?\n\nThis changes a system setting; it takes effect after a restart.",
         body=r"""Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -Value 7
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name MinidumpDir -Value '%SystemRoot%\Minidump' -Type ExpandString
Write-Host 'Dump type set to Automatic memory dump (takes effect after restart).' -ForegroundColor Green
$WDStatus = @{ ok = $true }"""),
    dict(group="Advanced (used by Guided Fix)", name="Turn off Driver Verifier", admin=True,
         desc="Runs 'verifier /reset'. Restart afterwards.",
         confirm="Turn off Driver Verifier (verifier /reset)?\n\nThis removes all Driver Verifier settings. Restart the PC afterwards.",
         body=r"""verifier /reset
Write-Host 'Driver Verifier settings cleared. RESTART the PC.' -ForegroundColor Yellow
$WDStatus = @{ exit = $LASTEXITCODE }"""),
    dict(group="Advanced (used by Guided Fix)", name="Defender Offline scan", admin=True,
         desc="Restarts the PC into Microsoft Defender Offline to remove hard-to-find malware (~15 min).",
         confirm="The PC will RESTART into Microsoft Defender Offline scan (about 15 minutes). Save your work first. Continue?",
         body=r"""Start-MpWScan
$WDStatus = @{ ok = $true }"""),
]

# ---------------------------------------------------------------------------------
#  Playbooks
#  step fields: id, title, why, docs[list of DOCS keys], action{type, target}, verify{kind},
#               reboot(bool), advanced(bool), focus[list of categories that make it "recommended"],
#               manual[list of instructions], cmd (command shown to the user)
# ---------------------------------------------------------------------------------
def S(id, title, why, docs=(), action=None, verify=None, reboot=False, advanced=False, focus=(), manual=(), cmd=""):
    return {"id": id, "title": title, "why": why, "docs": list(docs), "action": action, "verify": verify,
            "reboot": reboot, "advanced": advanced, "focus": list(focus), "manual": list(manual), "cmd": cmd}


def R(name):
    return {"type": "repair", "target": name}


def L(target, label=None):
    return {"type": "launch", "target": target, "label": label}


import updates as _updates  # noqa: E402
VERIFY_PS["wu_pending"] = _updates.PENDING_VERIFY_PS

VERIFY_PS["net_quick"] = PS_HEAD + r"""
$c = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
$gw = "$(@($c.IPv4DefaultGateway)[0].NextHop)"
$r1 = $(if ($gw) { [bool](Test-Connection -ComputerName $gw -Count 2 -Quiet) } else { $false })
$r2 = [bool](Test-Connection -ComputerName 1.1.1.1 -Count 2 -Quiet)
$r3 = [bool](Resolve-DnsName www.microsoft.com -Type A -DnsOnly -QuickTimeout)
$r4 = $false; try { $w = Invoke-WebRequest 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 8; $r4 = "$($w.Content)" -match 'Microsoft Connect Test' } catch {}
$S = @("Router ($(if ($gw) { $gw } else { 'none' })): $(if ($r1) { 'answers' } else { 'NO answer' })", "Internet (1.1.1.1): $(if ($r2) { 'answers' } else { 'NO answer' })",
       "DNS lookup: $(if ($r3) { 'works' } else { 'FAILS' })", "Web test: $(if ($r4) { 'works' } else { 'FAILS' })")
$d = if ($r2 -and $r3 -and $r4) { 'The internet works.' } elseif (-not $gw) { 'No default gateway - the PC has no route to the internet (no IP from the router?).' }
     elseif (-not $r1 -and -not $r2) { "The PC can't reach the router - a local problem (Wi-Fi, cable, adapter or the router itself)." }
     elseif (-not $r2) { 'The router answers but the internet does not - modem or internet provider (or ICMP blocked).' }
     elseif (-not $r3) { 'Internet works but DNS fails - switch DNS (next steps).' } else { 'DNS works but web pages are blocked - proxy, captive portal (hotel/café login) or firewall.' }
@{ status = $(if ($r2 -and $r3 -and $r4) { 'pass' } elseif ($r4) { 'review' } else { 'fail' }); detail = $d; sample = $S } | ConvertTo-Json -Compress
"""
VERIFY_PS["wifi_signal"] = PS_HEAD + r"""
$t = (netsh wlan show interfaces) -join "`n"
# The signal is the only "NN%" value in this output, whatever the Windows language
if ($t -notmatch '(?m):\s*(\d{1,3})\s*%\s*$') { @{ status = 'review'; detail = 'Not connected to Wi-Fi - nothing to measure.' } | ConvertTo-Json -Compress; return }
$s = [int]$Matches[1]
$ch = if ($t -match '(?m)^\s*Channel\s*:\s*(\d+)') { $Matches[1] } else { '?' }
$st = if ($s -ge 60) { 'pass' } elseif ($s -ge 40) { 'review' } else { 'fail' }
$smp = @(($t -split "`n" | Where-Object { $_ -match '^\s*(SSID|Signal|Channel|Radio type|Receive rate|Band)\s*:' }) | ForEach-Object { $_.Trim() })
if (-not $smp.Count) { $smp = @(($t -split "`n" | Where-Object { $_ -match ':' -and $_ -notmatch '(?i)BSSID|GUID|Physical|Profile' }) | ForEach-Object { $_.Trim() } | Select-Object -First 12) }
@{ status = $st; detail = "Signal $s%$(if ($ch -ne '?') { " on channel $ch" }). Under 60% causes slow speeds; under 40% causes drop-outs."; sample = $smp } | ConvertTo-Json -Compress
"""
_DROPS = r"""
# Reason / ReasonCode come from the event XML (not the translated message text). Disconnects the user asked for
# are recognised by the English reason text where Windows is in English; elsewhere every disconnect counts and the
# sample shows the (translated) reason with its code so it can be looked up.
$ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; Id = 8003; StartTime = $since } -ErrorAction SilentlyContinue)
$rows = @(foreach ($e in $ev) {
    $rs = ''; $rc = ''
    try { foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { if ($d.Name -eq 'Reason') { $rs = "$($d.'#text')" } elseif ($d.Name -eq 'ReasonCode') { $rc = "$($d.'#text')" } } } catch {}
    [pscustomobject]@{ t = $e.TimeCreated; reason = $rs; code = $rc; user = ($rs -match '(?i)disconnected by the user|user explicitly|explicit disconnect') }
})
$user = @($rows | Where-Object { $_.user })
$n = $rows.Count - $user.Count
$st = if ($n -eq 0) { 'pass' } elseif ($n -le 2) { 'review' } else { 'fail' }
@{ status = $st; detail = "$n unexpected Wi-Fi disconnect(s) since $($since.ToString('yyyy-MM-dd HH:mm')) ($($user.Count) by the user)."; sample = @($rows | Where-Object { -not $_.user } | Select-Object -First 6 | ForEach-Object { "$($_.t.ToString('MM-dd HH:mm'))  $($_.reason)$(if ($_.code) { " (code $($_.code))" })" }) } | ConvertTo-Json -Compress
"""
VERIFY_PS["wifi_drops"] = PS_HEAD + _DROPS
VERIFY_PS["wifi_drops_week"] = PS_HEAD + "$since = (Get-Date).AddDays(-7)\n" + _DROPS
VERIFY_PS["nic_power"] = PS_HEAD + r"""
$on = @(Get-NetAdapterPowerManagement | Where-Object { "$($_.AllowComputerToTurnOffDevice)" -eq 'Enabled' } | ForEach-Object { $_.Name })
$up = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.Name })
$bad = @($on | Where-Object { $up -contains $_ })
@{ status = $(if ($bad.Count) { 'fail' } else { 'pass' }); detail = $(if ($bad.Count) { "Windows may still turn off: $($bad -join ', ')" } else { 'Windows will not turn the connected adapter(s) off to save power.' }) } | ConvertTo-Json -Compress
"""
VERIFY_PS["dns_ok"] = PS_HEAD + r"""
$sw = [Diagnostics.Stopwatch]::StartNew(); $ok = [bool](Resolve-DnsName ("windiag-" + (Get-Random) + ".microsoft.com") -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue); $t1 = $sw.ElapsedMilliseconds
$sw.Restart(); $ok2 = [bool](Resolve-DnsName www.wikipedia.org -Type A -DnsOnly -QuickTimeout); $t2 = $sw.ElapsedMilliseconds
$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')" })
@{ status = $(if ($ok2 -and $t2 -lt 300) { 'pass' } elseif ($ok2) { 'review' } else { 'fail' }); detail = "DNS lookup took $t2 ms $(if (-not $ok2) { '(FAILED)' })"; sample = $dns } | ConvertTo-Json -Compress
"""


def NF(fid, label):
    return {"type": "netfix", "target": fid, "label": label}


PLAYBOOKS = [
    {
        "id": "bsod", "title": "Blue screens (stop errors)",
        "triggers": {"cats": ["DRIVER", "RAM", "CPU", "KERNEL"], "keys": ["bsod|", "kp41|"]},
        "source": "bsod",
        "intro": "Follows Microsoft's 'Advanced troubleshooting for stop error or blue screen error': identify the stop code, "
                 "rule out recent changes and outdated software, test the hardware, then analyse the dump and test drivers.",
        "steps": [
            S("code", "Look up the stop code", "The stop code says what kind of failure happened. Microsoft's reference page for each code lists "
              "the typical causes and the meaning of its parameters.", ["bugcheck_ref"], action={"type": "stopcodes"}, cmd="Get-WinEvent System / BugCheck 1001"),
            S("dumpcfg", "Make sure crash dumps are saved", "Without a dump file the cause can't be analysed. Microsoft recommends 'Automatic memory dump' and a page file.",
              ["dumps"], action=R("Set dump type to Automatic memory dump"), verify="dump_config", cmd="HKLM\\...\\CrashControl CrashDumpEnabled"),
            S("dump", "Analyse the crash dump (!analyze -v)", "Microsoft's debugger reads the dump and names the driver or module that was running "
              "when Windows crashed ('Probably caused by'). This is the single most useful clue.", ["windbg", "analyze"],
              action={"type": "dump"}, focus=["DRIVER", "GPU", "NVME", "NETWORK", "USB"], cmd="cdb -z <dump> -c \"!analyze -v; q\""),
            S("changes", "Undo recent changes", "Most blue screens start after a change: a Windows update, a new driver, new hardware or software. "
              "If the crashes began right after one, uninstall/roll it back first.", ["rollback"],
              action=L("ms-settings:windowsupdate-history", "Open update history"),
              manual=["Settings > Windows Update > Update history > Uninstall updates (for a recent update).",
                      "Device Manager > device > Properties > Driver > Roll Back Driver (for a recent driver).",
                      "Uninstall software added just before the crashes started (antivirus, VPN, RGB/monitoring tools)."]),
            S("updates", "Install the latest Windows updates", "Microsoft fixes many known crash causes in cumulative updates.",
              ["bsod"], action=L("ms-settings:windowsupdate", "Open Windows Update"), verify="wu_history"),
            S("drivers", "Update BIOS, chipset and device drivers", "Microsoft: ~75% of stop errors are caused by drivers. Update the driver named by the dump analysis first, "
              "then chipset, storage, graphics and network drivers, and the BIOS/firmware, from the PC or motherboard maker.",
              ["update_drivers"], action=L("devmgmt.msc", "Open Device Manager"), verify="bios_info", focus=["DRIVER", "GPU", "NETWORK", "USB", "CPU"]),
            S("space", "Check free disk space", "Microsoft recommends keeping 10-15% of the system drive free.", ["free_space"],
              action=R("Clear temp files"), verify="space_c"),
            S("sfc", "Repair system files (DISM + SFC)", "Damaged Windows files can crash the kernel. DISM repairs the component store, SFC then fixes protected files.",
              ["sfc", "dism"], action=R("Full system repair (DISM + SFC)"), verify="sfc", focus=["SYSTEM"], cmd="DISM /Online /Cleanup-Image /RestoreHealth ; sfc /scannow"),
            S("chkdsk", "Check the disk (CHKDSK)", "Disk and file-system errors cause stop codes like 0x7A, 0x24 and 0xEF.", ["chkdsk"],
              action=R("CHKDSK scan (online)"), verify="status_exit", focus=["DISK", "NVME", "FS"], cmd="chkdsk C: /scan"),
            S("memtest", "Test the memory (Windows Memory Diagnostic)", "Faulty RAM causes random stop codes (0x1A, 0x50, 0x4E, 0x12B). The test runs at restart.",
              ["mdsched"], action=R("Memory (RAM) test"), verify="memtest", reboot=True, focus=["RAM"], cmd="mdsched.exe"),
            S("malware", "Scan for malware", "Microsoft lists a malware scan as a standard step; rootkits can crash the kernel.", ["defender_offline"],
              action=R("Defender quick scan"), verify="defender_scan"),
            S("cleanboot", "Clean boot", "Starts Windows with only Microsoft services. If the crashes stop, a third-party service or startup program is responsible.",
              ["cleanboot"], action=L("msconfig.exe", "Open System Configuration"), advanced=True,
              manual=["msconfig > Services > tick 'Hide all Microsoft services' > Disable all.", "Task Manager > Startup apps > disable all.",
                      "Restart and use the PC normally. Re-enable items in halves to find the culprit."]),
            S("verifier", "Driver Verifier (advanced)", "Microsoft's tool that stresses drivers so the faulty one crashes with its own name. "
              "Test only non-Microsoft/suspicious drivers, in groups of 10-20. It slows the PC and WILL cause crashes - that is the point.",
              ["verifier"], action=L("verifier.exe", "Open Driver Verifier"), verify="verifier", advanced=True, reboot=True,
              manual=["verifier.exe > Create custom settings > Standard settings > Select driver names from a list > pick 10-20 non-Microsoft drivers.",
                      "Restart and use the PC until it crashes, then run the dump analysis step again.",
                      "IMPORTANT: turn it off afterwards with 'Turn off Driver Verifier' (verifier /reset). If Windows won't start, boot into Safe Mode and run it there."]),
            S("verifier_off", "Turn off Driver Verifier", "Don't leave Driver Verifier running.", ["verifier"], action=R("Turn off Driver Verifier"), verify="verifier", advanced=True),
            S("restore", "Last resort: System Restore or Reset this PC", "If nothing above helped, go back to a restore point from before the crashes, or reset Windows (keeping files).",
              ["restore", "recovery"], action=L("rstrui.exe", "Open System Restore"), advanced=True),
            S("monitor", "Confirm the fix", "Checks the event log for NEW blue screens since you started this guide. Use the PC normally for a few days, then verify again.",
              ["getwinevent"], verify="monitor"),
        ],
    },
    {
        "id": "wu", "title": "Windows Update failures",
        "triggers": {"cats": ["UPDATE"], "keys": ["wu20|"]},
        "source": "wu_errors",
        "intro": "Follows Microsoft's 'Common Windows Update errors': identify the error code, make sure the service, restart state, disk space and network are fine, "
                 "reset the update cache, repair the component store (DISM + SFC), then retry.",
        "steps": [
            S("codes", "Look up the error code", "Each Windows Update error code has a specific fix in Microsoft's table.", ["wu_errors", "wu_reference"], action={"type": "wucodes"}),
            S("online", "Check online for missing updates", "Asks Windows Update (Microsoft's servers, or your company's) which updates this PC is still missing. "
              "The check passes only when nothing important is missing.", ["wu_errors"], action={"type": "page", "target": "updates", "label": "Open Updates & Drivers"},
              verify="wu_pending"),
            S("service", "Service running, no restart pending", "Error 0x80070422 = service disabled; 0x80242014 = a restart is still pending.", ["wu_errors"],
              verify="wu_service", action=L("services.msc", "Open Services")),
            S("space", "At least 20 GB free on C:", "Feature and cumulative updates fail silently without enough space.", ["free_space"], action=R("Clear temp files"), verify="space_c"),
            S("network", "Update servers reachable", "Timeouts (0x80072EFD/EE2) and proxy errors mean the PC can't reach Microsoft's servers.", ["wu_errors"], verify="wu_network"),
            S("reset", "Reset Windows Update components", "Microsoft's fix for corrupt metadata (0x80242006): rename SoftwareDistribution and catroot2.", ["wu_errors"],
              action=R("Reset Windows Update"), verify="status_exit"),
            S("sfc", "Repair the component store (DISM + SFC)", "Microsoft's fix for 0x800f081f, 0x800f0831, 0x80073701, 0x8007371b, 0x80070570.", ["dism", "sfc"],
              action=R("Full system repair (DISM + SFC)"), verify="sfc", cmd="DISM /Online /Cleanup-Image /RestoreHealth ; sfc /scannow"),
            S("retry", "Restart and retry Windows Update", "Restart, then check for updates. WinDiag checks the update history for successes/failures since this step.",
              ["wu_errors"], action=L("ms-settings:windowsupdate", "Open Windows Update"), verify="wu_history", reboot=True),
            S("catalog", "Install the update manually", "Download the failing KB from the Microsoft Update Catalog and run it.", ["catalog"],
              action={"type": "catalog"}, advanced=True),
            S("inplace", "In-place repair (keeps files and apps)", "Reinstalls Windows over itself: Windows 11 Settings > System > Recovery > 'Fix problems using Windows Update'.",
              ["recovery"], action=L("ms-settings:recovery", "Open Recovery settings"), advanced=True),
        ],
    },
    {
        "id": "disk", "title": "Disk / NVMe / file-system errors",
        "triggers": {"cats": ["DISK", "NVME", "FS"], "keys": []},
        "source": "chkdsk",
        "intro": "Protect your data first, confirm the drive's health, repair the file system, then remove common causes of drive resets (power saving, firmware, cables).",
        "steps": [
            S("backup", "Back up your important files NOW", "Disk errors can get worse suddenly. Copy documents/photos to another drive or the cloud before anything else.",
              action={"type": "manual"}, manual=["Copy important folders to an external drive or OneDrive.", "Then mark this step done."]),
            S("health", "Check the drive's health", "Reads the drive's own health status and error counters (full SMART / NVMe data on the Drive Health page).", ["getwinevent"],
              action={"type": "page", "target": "drives", "label": "Open Drive Health"}, verify="disk_health", cmd="Get-PhysicalDisk | Get-StorageReliabilityCounter"),
            S("latency", "Measure disk response time", "A struggling drive answers slowly. Measured with Get-Counter (PowerShell Diagnostics).", ["getcounter"],
              verify="disk_latency", cmd="Get-Counter '\\PhysicalDisk(*)\\Avg. Disk sec/Transfer'"),
            S("scan", "CHKDSK online scan", "Finds file-system errors without restarting.", ["chkdsk"], action=R("CHKDSK scan (online)"), verify="status_exit", cmd="chkdsk C: /scan"),
            S("fix", "CHKDSK repair at restart (if the scan found errors)", "Fixes errors and checks for bad sectors (/f /r). Can take hours on big drives.", ["chkdsk"],
              action=R("CHKDSK full repair at next restart"), verify="chkdsk_boot", reboot=True, cmd="chkdsk C: /f /r"),
            S("aspm", "Turn off PCIe power saving (NVMe resets)", "Aggressive link power saving is a common cause of NVMe 'reset to device' events (stornvme 129).",
              action=R("Disable PCIe power saving (ASPM)"), verify="aspm", focus=["NVME"], cmd="powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0"),
            S("firmware", "Update SSD firmware, storage driver and BIOS", "Many SSD timeouts are fixed by firmware (Samsung Magician, WD Dashboard, Crucial Storage Executive, Intel MAS).",
              ["update_drivers"], action=L("devmgmt.msc", "Open Device Manager"), verify="bios_info"),
            S("cables", "Reseat / replace cables (SATA) or reseat the NVMe", "CRC and link-reset errors are usually cables or connectors.", action={"type": "manual"},
              manual=["Desktop SATA: replace the data cable, try another port and another power connector.", "NVMe: power off, reseat the drive and its screw/heatsink."]),
            S("monitor", "Confirm the fix", "Checks for NEW disk/NVMe/file-system errors since you started this guide.", ["getwinevent"], verify="monitor"),
        ],
    },
    {
        "id": "power", "title": "Unexpected shutdowns / power loss",
        "triggers": {"cats": ["POWER", "THERMAL"], "keys": ["kp41|0", "kp41|button"]},
        "source": "bsod",
        "intro": "Kernel-Power 41 only says the last shutdown wasn't clean. This guide works out whether it was a crash, a freeze or a power problem and checks each cause.",
        "steps": [
            S("kind", "What kind of shutdown was it?", "Blue screen (stop code set), frozen + power button held, or power cut (no stop code) need different fixes.",
              ["bsod"], action={"type": "kp41"}),
            S("dumpcfg", "Make sure crashes are recorded", "If dumps are disabled, a crash can look like a power loss.", ["dumps"],
              action=R("Set dump type to Automatic memory dump"), verify="dump_config"),
            S("thermal", "Check for overheating / throttling", "Overheating CPUs throttle and then switch off.", verify="throttle",
              manual=["Clean dust from fans/heatsinks; check that all fans spin.", "For real temperatures use HWiNFO (free)."], cmd="Get-WinEvent Kernel-Processor-Power 37"),
            S("power", "Check the power supply / battery", "Weak PSUs, loose cables, bad power strips or worn laptop batteries cause sudden power-offs.",
              action=R("Battery report"), manual=["Desktop: check the power cable, try another outlet (not a power strip), test with another PSU if possible.",
                                                   "Laptop: check battery health in the battery report; test on the charger only."]),
            S("bios", "Update BIOS / firmware", "Firmware updates fix many power-management and stability bugs.", ["update_drivers"], verify="bios_info"),
            S("monitor", "Confirm the fix", "Checks for NEW unexpected shutdowns since you started this guide.", ["getwinevent"], verify="monitor"),
        ],
    },
    {
        "id": "gpu", "title": "Graphics driver crashes (TDR, 0x116/0x117)",
        "triggers": {"cats": ["GPU"], "keys": ["lke|141", "lke|117"]},
        "source": "bugcheck_ref",
        "intro": "Display driver timeouts are fixed in this order: current driver, clean reinstall, remove overclocks, then check heat and power.",
        "steps": [
            S("info", "Check the GPU and driver version", "Shows your GPU and how old its driver is.", verify="gpu_info", cmd="Get-CimInstance Win32_VideoController"),
            S("driver", "Clean-install the latest GPU driver", "Download from NVIDIA/AMD/Intel and choose 'clean install' (or remove the old one with DDU in Safe Mode).",
              ["update_drivers"], action=L("devmgmt.msc", "Open Device Manager"),
              manual=["NVIDIA: nvidia.com/drivers - AMD: amd.com/support - Intel: intel.com/content/www/us/en/support/detect.html"]),
            S("oc", "Remove GPU overclocks", "Factory or manual overclocks (MSI Afterburner etc.) are a common TDR cause.", action={"type": "manual"},
              manual=["Reset Afterburner/Adrenalin tuning to default; disable 'OC mode' in vendor apps."]),
            S("sfc", "Repair system files (DISM + SFC)", "Damaged DirectX / graphics components can also cause TDRs.", ["sfc", "dism"],
              action=R("Full system repair (DISM + SFC)"), verify="sfc"),
            S("monitor", "Confirm the fix", "Checks for NEW display driver crashes since you started this guide.", ["getwinevent"], verify="monitor"),
        ],
    },
    {
        "id": "hw", "title": "Hardware errors (WHEA / CPU / RAM)",
        "triggers": {"cats": ["CPU", "RAM", "PCIE"], "keys": []},
        "source": "bsod",
        "intro": "WHEA and machine-check errors come from the hardware itself. Microsoft's order: firmware/BIOS updates and hardware tests; remove overclocks first.",
        "steps": [
            S("oc", "Remove overclocks / XMP / undervolts", "Unstable settings are the most common cause of WHEA errors on desktops.", action={"type": "manual"},
              manual=["BIOS: Load optimized defaults (disables XMP/EXPO and CPU overclocks).", "Remove undervolt profiles (ThrottleStop, Ryzen Master, Intel XTU)."]),
            S("bios", "Update BIOS / CPU microcode", "Many CPU stability fixes ship as BIOS microcode updates.", ["update_drivers"], verify="bios_info"),
            S("memtest", "Test the memory", "Windows Memory Diagnostic runs at restart; for a thorough test use MemTest86 from a USB stick.", ["mdsched"],
              action=R("Memory (RAM) test"), verify="memtest", reboot=True, focus=["RAM"],
              manual=["Quicker option without restarting: WinDiag's Memory (RAM) page has an in-Windows test with a live block grid and a one-stick-at-a-time guide."]),
            S("thermal", "Check temperatures", "Overheating triggers machine checks and throttling.", verify="throttle"),
            S("monitor", "Confirm the fix", "Checks for NEW hardware (WHEA) errors since you started this guide.", ["getwinevent"], verify="monitor"),
        ],
    },
    {
        "id": "drivers", "title": "Driver and device problems",
        "triggers": {"cats": ["DRIVER", "USB", "NETWORK"], "keys": []},
        "source": "update_drivers",
        "intro": "Fix devices with problems in Device Manager, update or roll back drivers, repair system files and isolate third-party software with a clean boot.",
        "steps": [
            S("devices", "Devices with driver problems", "Lists devices showing a yellow '!' in Device Manager.", verify="devices", action=L("devmgmt.msc", "Open Device Manager")),
            S("update", "Update or roll back drivers", "Install drivers from the PC/device maker; if a problem started after a driver update, roll it back.",
              ["update_drivers", "rollback"], action=L("devmgmt.msc", "Open Device Manager")),
            S("sfc", "Repair system files (DISM + SFC)", "", ["sfc", "dism"], action=R("Full system repair (DISM + SFC)"), verify="sfc"),
            S("cleanboot", "Clean boot", "Isolates third-party services and startup apps.", ["cleanboot"], action=L("msconfig.exe", "Open System Configuration"), advanced=True),
            S("monitor", "Confirm the fix", "Checks for NEW driver/device errors since you started this guide.", ["getwinevent"], verify="monitor"),
        ],
    },
    {
        "id": "malware", "title": "Suspected malware / PC compromised",
        "triggers": {"cats": ["SECURITY"], "keys": []},
        "source": "malware_guidance",
        "intro": "Follows Microsoft's malware-removal guidance: find what is wrong, update and scan with Defender (then the Offline scan for hidden malware), "
                 "remove what keeps it running, undo network/certificate tampering, secure your accounts, and confirm. Nothing is deleted automatically - "
                 "WinDiag quarantines reversibly.",
        "steps": [
            S("triage", "Run the Security Scan", "Checks Defender, every auto-start location, running programs, certificates and boot security, and tells you what looks wrong.",
              ["malware_troubleshoot"], action={"type": "page", "target": "security", "label": "Open Security Scan"}, verify="security"),
            S("defs", "Update Defender definitions", "Scans only find what the definitions know about - update first.", ["malware_troubleshoot"],
              action=R("Update Defender definitions"), verify="defender_defs", cmd="Update-MpSignature"),
            S("isolate", "Disconnect from the network if it looks active", "If the scan found an ACTIVE threat, HTTPS interception or remote-access tools you don't know, unplug the network "
              "cable / turn off Wi-Fi (after updating definitions) so nothing can be stolen or spread while you clean up.", action={"type": "manual"},
              manual=["Unplug the network cable or turn off Wi-Fi (Action Center).", "Reconnect later only to update or when told to."], focus=["SECURITY"]),
            S("full", "Defender full scan", "Scans every file on the PC (can take an hour or more).", ["malware_troubleshoot"],
              action=R("Defender full scan"), verify="defender_scan", cmd="Start-MpScan -ScanType FullScan"),
            S("msrt", "Malicious Software Removal Tool (optional second opinion)", "Microsoft's free MSRT removes specific widespread malware families.", ["msrt"],
              action={"type": "launch", "target": "mrt.exe", "label": "Run MSRT (mrt.exe)"}, advanced=True,
              manual=["If mrt.exe is not present, download it from the Microsoft link above."]),
            S("offline", "Microsoft Defender Offline scan", "Restarts into a clean environment and scans before Windows (and any rootkit) loads. Removes malware that hides from normal scans.",
              ["defender_offline"], action=R("Defender Offline scan"), reboot=True,
              manual=["After the restart, check Windows Security > Virus & threat protection > Protection history, then click 'Mark done'."]),
            S("persist", "Remove what keeps it starting", "Malware survives restarts through startup entries, scheduled tasks, services and WMI. Quarantine the red items "
              "(reversible - restore from Files > Quarantine if something breaks).", action={"type": "page", "target": "security:Startup & persistence", "label": "Review startup items"}),
            S("certs", "Check trusted root certificates", "A rogue root certificate lets someone read your HTTPS traffic (banking, email). Roots not in Microsoft's list or with a private key are flagged.",
              ["trusted_root"], action={"type": "page", "target": "security:Certificates", "label": "Review certificates"}),
            S("net", "Undo proxy / hosts / DNS changes", "Adware and banking trojans redirect traffic with a proxy, the hosts file or DNS.", action=L("ms-settings:network-proxy", "Open proxy settings"),
              verify="net_reset", manual=["Settings > Network > Proxy: turn off anything you did not set.", "Remove unknown lines from C:\\Windows\\System32\\drivers\\etc\\hosts.",
                                           "Set DNS back to automatic in the adapter settings."]),
            S("passwords", "Change your passwords from a CLEAN device", "If anything was running, assume saved passwords and browser sessions were stolen.", action={"type": "manual"},
              manual=["Use your phone or another PC.", "Change email first (it resets everything else), then banking, Microsoft account, social media.",
                      "Turn on two-step verification and sign out of all sessions."]),
            S("confirm", "Confirm: run the Security Scan again", "Re-checks everything. It should come back with no red items and no active threats.", ["malware_troubleshoot"],
              action={"type": "page", "target": "security", "label": "Open Security Scan"}, verify="security"),
            S("reset", "If it keeps coming back: Reset this PC", "When malware returns after cleaning, a reset ('Remove everything' + 'Cloud download') is the reliable fix. Back up your files first "
              "(scan the backup before restoring).", ["recovery"], action=L("ms-settings:recovery", "Open Recovery settings"), advanced=True),
        ],
    },
    {
        "id": "noinet", "title": "No internet",
        "triggers": {"cats": ["NETWORK"], "keys": []},
        "source": "net_support",
        "intro": "Finds WHERE the connection breaks (this PC, the router, DNS, or the provider) and applies the matching fix. Every fix is measured before and after.",
        "steps": [
            S("test", "Test the connection", "Pings the router and the internet, looks up a name and loads Microsoft's connection-test page. The result says where it breaks.",
              action={"type": "page", "target": "nettools:Connection", "label": "Open live monitor"}, verify="net_quick"),
            S("router", "Restart the modem and router", "Fixes most outages. Unplug both for 30 seconds, plug the modem in first, wait until its lights settle, then the router.",
              action={"type": "manual"}, verify="net_quick", manual=["Unplug the modem and router power for 30 seconds.", "Plug in the modem, wait 2 minutes, then the router.",
                                                                     "Wait until Wi-Fi is back, then click 'Check result'."]),
            S("renew", "Renew the IP address", "Gets a fresh address from the router - fixes 169.254.x.x addresses.", action=NF("renew", "Renew IP (measured)"), verify="net_quick"),
            S("proxy", "Clear proxy settings", "A leftover or malicious proxy blocks web pages while everything else looks fine.", action=NF("proxy", "Clear proxy (measured)"),
              verify="net_reset"),
            S("dns", "Switch DNS", "If the test said DNS fails, use a public DNS server.", action=NF("dns_cf", "Switch DNS to Cloudflare (measured)"), verify="dns_ok"),
            S("adapter", "Restart the network adapter", "Resets the adapter without a reboot.", action=NF("restart", "Restart adapter (measured)"), verify="net_quick"),
            S("driver", "Update or reinstall the network driver", "Get the latest driver from the PC or adapter maker; in Device Manager you can also uninstall the adapter and restart "
              "(Windows reinstalls it).", ["update_drivers"], action=L("devmgmt.msc", "Open Device Manager")),
            S("reset", "Reset the network stack", "netsh winsock reset + int ip reset repairs network software broken by VPNs, antivirus or malware. Needs a restart.",
              action=NF("winsock", "Reset Winsock + TCP/IP"), reboot=True, verify="net_quick", advanced=True),
            S("fullreset", "Windows 'Network reset'", "Removes and reinstalls all network adapters and resets settings. VPN software may need reinstalling.", ["net_support"],
              action=L("ms-settings:network-status", "Open Network settings"), advanced=True, manual=["Settings > Network & internet > Advanced network settings > Network reset."]),
            S("isp", "Contact your internet provider", "If the router answers but the internet doesn't after a modem restart, the fault is on the line. Give them the live-monitor numbers.",
              action={"type": "page", "target": "nettools:Connection", "label": "Show live monitor numbers"}, advanced=True),
            S("monitor", "Confirm the fix", "Runs the connection test again.", verify="net_quick"),
        ],
    },
    {
        "id": "slownet", "title": "Slow internet",
        "triggers": {"cats": [], "keys": []},
        "source": "net_support",
        "intro": "Measures first (speed, Wi-Fi signal, DNS, latency), then fixes the most likely cause. Test on a cable next to the router at least once - it tells you whether it's Wi-Fi or the line.",
        "steps": [
            S("speed", "Run a speed test", "Compare with the speed your plan promises. Pause other downloads/streams first.",
              action={"type": "page", "target": "nettools:Speed & DNS", "label": "Open speed test"}),
            S("signal", "Check the Wi-Fi signal", "The most common cause of slow speeds. Under 60% signal, speeds drop a lot.", ["wifi_fix"],
              action={"type": "page", "target": "nettools:Wi-Fi", "label": "Open Wi-Fi analyzer"}, verify="wifi_signal"),
            S("channel", "Move to a quieter Wi-Fi channel or 5 GHz", "Neighbouring networks on the same channel slow each other down. The Wi-Fi tab shows the quietest channel.",
              action={"type": "page", "target": "nettools:Wi-Fi", "label": "Show channels"},
              manual=["Log in to the router (address on its label) > Wireless settings > set the channel shown as quietest.", "Prefer the 5 GHz network when you're near the router."]),
            S("latency", "Watch latency and loss", "Loss or jitter on the router line = Wi-Fi/local problem. Only on the internet line = provider.",
              action={"type": "page", "target": "nettools:Connection", "label": "Open live monitor"}, verify="net_quick"),
            S("dns", "Benchmark DNS", "A slow DNS makes every page start late (not downloads).", action={"type": "page", "target": "nettools:Speed & DNS", "label": "Open DNS benchmark"},
              verify="dns_ok"),
            S("hogs", "Find what's using the connection", "Updates, cloud sync (OneDrive, Dropbox), game launchers and torrents can use all the bandwidth.",
              action=L("resmon.exe", "Open Resource Monitor (Network tab)"), manual=["Resource Monitor > Network tab > sort 'Processes with Network Activity' by Total."]),
            S("power", "Turn off adapter power saving", "Power saving can throttle Wi-Fi.", action=NF("nic_power", "NIC power saving off (measured)"), verify="nic_power"),
            S("driver", "Update the network driver", "Old Wi-Fi drivers are a known cause of slow speeds on newer routers.", ["update_drivers"],
              action={"type": "page", "target": "updates", "label": "Check driver updates"}),
            S("mtu", "Check MTU (if some sites hang)", "A wrong MTU makes some pages or VPNs stall.", action={"type": "page", "target": "nettools:Route & ports", "label": "Open MTU check"},
              advanced=True),
            S("monitor", "Confirm: speed test again", "Run the speed test again and compare.", action={"type": "page", "target": "nettools:Speed & DNS", "label": "Open speed test"}),
        ],
    },
    {
        "id": "wifidrop", "title": "Wi-Fi keeps dropping",
        "triggers": {"cats": [], "keys": []},
        "source": "wifi_fix",
        "intro": "Counts the real disconnects in Windows' Wi-Fi log, then works through signal, interference, power saving, the saved profile and the driver. "
                 "The last step counts disconnects again since you started.",
        "steps": [
            S("count", "Count disconnects (last 7 days)", "Reads WLAN-AutoConfig event 8003 and ignores disconnects you made yourself.", ["wifi_fix"], verify="wifi_drops_week"),
            S("report", "Create the WLAN report", "Windows' own report of every Wi-Fi session, disconnect reason and error over the last 3 days.",
              action={"type": "page", "target": "nettools:Wi-Fi", "label": "Open Wi-Fi tab (WLAN report button)"}),
            S("signal", "Check the signal", "Drop-outs are almost always a weak signal (<40%) or interference.", action={"type": "page", "target": "nettools:Wi-Fi", "label": "Open Wi-Fi analyzer"},
              verify="wifi_signal"),
            S("power", "Stop Windows turning the adapter off", "The #1 cause of drops after sleep or idle.", action=NF("nic_power", "NIC power saving off (measured)"), verify="nic_power"),
            S("channel", "Change the router's channel", "Busy channels cause drops as well as slowness.", action={"type": "page", "target": "nettools:Wi-Fi", "label": "Show channels"}),
            S("rejoin", "Rejoin the network", "Reconnects with the saved password.", action=NF("wifi_rejoin", "Rejoin Wi-Fi (measured)")),
            S("forget", "Forget and re-add the network", "Fixes a corrupted saved profile. You'll need the Wi-Fi password.", action=NF("wifi_forget", "Forget this network"), advanced=True),
            S("driver", "Update the Wi-Fi driver", "Get it from the PC or adapter maker (Intel, Realtek, MediaTek, Qualcomm).", ["update_drivers"],
              action={"type": "page", "target": "updates", "label": "Check driver updates"}),
            S("router", "Update the router's firmware / restart it", "Router bugs cause drops for every device. If phones drop too, it's the router.", action={"type": "manual"},
              manual=["Router admin page > Firmware / Update.", "If all devices drop at the same time, the router or the line is at fault, not this PC."]),
            S("monitor", "Confirm the fix", "Counts unexpected disconnects since you started this guide. Use the PC normally for a day, then check again.", verify="wifi_drops"),
        ],
    },
]
PLAYBOOK_BY_ID = {p["id"]: p for p in PLAYBOOKS}

MONITOR_CATS = {"bsod": None, "wu": ["UPDATE"], "disk": ["DISK", "NVME", "FS"], "power": ["POWER"], "gpu": ["GPU"],
                "hw": ["CPU", "RAM", "PCIE"], "drivers": ["DRIVER", "USB", "NETWORK"], "malware": ["SECURITY"],
                "noinet": ["NETWORK"], "slownet": ["NETWORK"], "wifidrop": ["NETWORK"]}


def recommend(analysis, categories_map=None, security=None):
    """Return [(playbook, reason, strength)] sorted by relevance from the Event Analyzer output
    (and the Security Scan result, if one was run)."""
    out_sec = []
    if security:
        c = security.get("counts", {})
        if c.get("CRITICAL"):
            out_sec.append((PLAYBOOK_BY_ID["malware"], "Security Scan found %d critical item(s)" % c["CRITICAL"], 40 + 5 * c["CRITICAL"]))
        elif c.get("WARNING", 0) >= 3:
            out_sec.append((PLAYBOOK_BY_ID["malware"], "Security Scan found %d warning(s)" % c["WARNING"], 8))
    if not analysis:
        return out_sec
    probs = {p["cat"]: p for p in analysis.get("problems", [])}
    keys = [g.get("key", "") for g in analysis.get("matched", [])] if analysis.get("matched") and "key" in analysis["matched"][0] else []
    titles = [i.get("title", "") for i in analysis.get("instances", [])]
    out = []
    for pb in PLAYBOOKS:
        score, why = 0.0, []
        for c in pb["triggers"]["cats"]:
            if c in probs:
                score += probs[c]["score"]
                why.append("%s (%s)" % (probs[c]["name"], probs[c]["likelihood"]))
        if pb["id"] == "bsod":
            n = len([t for t in titles if t.startswith("Blue screen")])
            if n:
                score += 20 + 5 * n
                why.insert(0, "%d blue screen(s) found" % n)
        if pb["id"] == "power":
            n = len([t for t in titles if t.startswith(("Sudden power loss", "Frozen"))])
            if n:
                score += 10 + 3 * n
                why.insert(0, "%d unexpected shutdown(s) without a blue screen" % n)
        if pb["id"] == "gpu":
            n = len([t for t in titles if "Display" in t or "VIDEO" in t])
            score += 3 * n
        if score > 0:
            out.append((pb, "; ".join(why) or "related events found", score))
    out = [o for o in out if o[0]["id"] != "malware"] + out_sec
    out.sort(key=lambda x: -x[2])
    return out


# ---------------------------------------------------------------------------------
#  Progress state (saved next to WinDiag so it survives restarts)
# ---------------------------------------------------------------------------------
class State(object):
    def __init__(self, path):
        self.path = path
        self.data = {"playbooks": {}, "active": None}
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except Exception:
            pass

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1, default=str)
        except Exception:
            pass

    def pb(self, pid):
        d = self.data["playbooks"].setdefault(pid, {"started": None, "steps": {}})
        return d

    def start(self, pid):
        d = self.pb(pid)
        if not d["started"]:
            d["started"] = datetime.now().isoformat(timespec="seconds")
        self.data["active"] = pid
        self.save()
        return d

    def step(self, pid, sid):
        return self.pb(pid)["steps"].setdefault(sid, {"status": "todo"})

    def set(self, pid, sid, **kw):
        st = self.step(pid, sid)
        st.update(kw)
        st["updated"] = datetime.now().isoformat(timespec="seconds")
        self.save()
        return st

    def reset(self, pid):
        self.data["playbooks"].pop(pid, None)
        if self.data.get("active") == pid:
            self.data["active"] = None
        self.save()

    def progress(self, pid):
        pb = PLAYBOOK_BY_ID[pid]
        steps = self.pb(pid)["steps"]
        done = sum(1 for s in pb["steps"] if steps.get(s["id"], {}).get("status") in ("pass", "fixed", "done", "skipped"))
        return done, len(pb["steps"])

    def next_step(self, pid):
        pb = PLAYBOOK_BY_ID[pid]
        steps = self.pb(pid)["steps"]
        for s in pb["steps"]:
            if steps.get(s["id"], {}).get("status") not in ("pass", "fixed", "done", "skipped"):
                return s
        return None

    def waiting(self):
        """Steps started but not verified yet (e.g. waiting for a restart)."""
        out = []
        for pid, d in self.data.get("playbooks", {}).items():
            for sid, st in d.get("steps", {}).items():
                if st.get("status") in ("running", "waiting", "pending"):
                    out.append((pid, sid, st))
        return out


STATUS_TEXT = {"todo": "TO DO", "running": "RUNNING", "waiting": "WAITING FOR RESTART", "pending": "WAITING",
               "pass": "PASSED", "fixed": "FIXED", "fail": "PROBLEM FOUND", "review": "CHECK RESULT", "done": "DONE", "skipped": "SKIPPED"}
