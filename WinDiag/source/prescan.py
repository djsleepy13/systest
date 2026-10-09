"""
Security check before a scan (runs on the start screen, ~3 seconds, read-only):
  1. WinDiag's own files match the SHA-256 list shipped next to the exe (WinDiag.sha256)
  2. The PowerShell WinDiag uses is Microsoft's own, in System32, not redirected (IFEO)
  3. Microsoft Defender is running, no ACTIVE threat, no test-signing / disabled-by-policy
If something is wrong the scan results can't be fully trusted - the start screen says so.
"""
import hashlib
import os
import re
import sys

import core

PRE_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$R = [ordered]@{}
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$sig = Get-AuthenticodeSignature -LiteralPath $ps
$R.ps_sig = "$($sig.Status)"; $R.ps_os = [bool]$sig.IsOSBinary
$R.ps_signer = $(if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.GetNameInfo('SimpleName', $false) } else { '' })
$R.ifeo = @(foreach ($n in 'powershell.exe', 'cmd.exe', 'taskmgr.exe', 'MpCmdRun.exe', 'MsMpEng.exe', 'regedit.exe') {
    $d = [string](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$n").Debugger
    if ($d) {
        $exe = $(if ($d -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($d -match '^\s*(\S+\.exe)') { $Matches[1] } else { '' })
        $s = $(if ($exe -and (Test-Path -LiteralPath $exe)) { Get-AuthenticodeSignature -LiteralPath $exe } else { $null })
        [ordered]@{ image = $n; debugger = $d; sig = $(if ($s) { "$($s.Status)" } else { '' })
                    signer = $(if ($s -and $s.SignerCertificate) { [string]$s.SignerCertificate.GetNameInfo('SimpleName', $false) } else { '' }) }
    } })
$mp = Get-MpComputerStatus
$R.defender = [bool]$mp; $R.rtp = $mp.RealTimeProtectionEnabled; $R.sig_age = $mp.AntivirusSignatureAge; $R.am_mode = "$($mp.AMRunningMode)"
$R.active = @(Get-MpThreat | Where-Object { $_.IsActive } | ForEach-Object { [string]$_.ThreatName })
$R.policy_off = ((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender').DisableAntiSpyware -eq 1)
$R.other_av = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Where-Object { $_.displayName -notmatch '^(Windows|Microsoft) Defender' -and ('{0:x6}' -f [int]$_.productState).Substring(2, 2) -in '10', '11' } | ForEach-Object { [string]$_.displayName })
$os = Get-CimInstance Win32_OperatingSystem
$R.product_type = [int]$os.ProductType
# locale-proof test-signing check: the options the current boot really uses (bcdedit's Yes/No are translated on some languages)
$sso = "$((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').SystemStartOptions)"
$R.testsigning = ($sso -match '(^|\s)TESTSIGNING(\s|$)')
# Is WinDiag running as someone else than the signed-in user (UAC prompt answered with another admin account)?
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$sid = (Get-Process -Id $PID).SessionId
$ex = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { $_.SessionId -eq $sid } | Select-Object -First 1
$o = $(if ($ex) { Invoke-CimMethod -InputObject $ex -MethodName GetOwner } else { $null })
$R.me = "$me"; $R.desktop_user = $(if ($o -and $o.User) { "$($o.Domain)\$($o.User)" } else { '' })
$R | ConvertTo-Json -Depth 4 -Compress
"""

# Task-manager replacements techs install on purpose ("Replace Task Manager" writes IFEO\taskmgr.exe\Debugger)
TASKMGR_REPLACEMENTS = ("procexp", "procexp64", "procexp64a", "systeminformer", "processhacker")


def _s(x):
    if isinstance(x, dict):
        x = x.get("value", "")
    if x is None:
        return ""
    if isinstance(x, list):
        return ", ".join(_s(i) for i in x if i is not None)
    return x if isinstance(x, str) else str(x)


def _l(x):
    if isinstance(x, dict) and "value" in x and set(x) <= {"value", "Count", "Length"}:
        x = x["value"]
    if x in (None, "", {}):
        return []
    return [i for i in x if i is not None] if isinstance(x, list) else [x]


def _ifeo(x):
    """-> (image, debugger, sig, signer) from the new dict form or the old 'img -> debugger' string."""
    if isinstance(x, dict) and "image" in x:
        return _s(x.get("image")), _s(x.get("debugger")), _s(x.get("sig")), _s(x.get("signer"))
    t = _s(x)
    img, _, dbg = t.partition(" -> ")
    return img.strip(), dbg.strip(), "", ""


def ifeo_item(entries):
    """IFEO Debugger values on Windows tools -> list of (status, title, detail)."""
    out, bad = [], []
    for x in entries:
        img, dbg, sig, signer = _ifeo(x)
        if not img and not dbg:
            continue
        m = re.search(r'([^\\/":]+?)\.exe\b', dbg, re.I)
        name = m.group(1).strip().lower() if m else ""
        if img.lower() == "taskmgr.exe" and name in TASKMGR_REPLACEMENTS and sig in ("", "Valid"):
            out.append(("INFO", "Task Manager is replaced by %s" % ("System Informer" if "informer" in name or "hacker" in name else "Process Explorer"),
                        "Opening Task Manager starts %s instead (a technician setting).%s" % (dbg, (" Signed by %s." % signer) if signer else "")))
        else:
            bad.append("%s -> %s%s" % (img, dbg, (" (signature: %s)" % sig) if sig and sig != "Valid" else ""))
    if bad:
        out.insert(0, ("CRITICAL", "Windows tools are redirected", "Image File Execution Options hijack: %s. Malware uses this to fake or block tools." % "; ".join(bad)))
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def integrity():
    """Return (status, text). status OK / CRITICAL / INFO."""
    base = core.app_dir()
    man = os.path.join(base, "WinDiag.sha256")
    if not getattr(sys, "frozen", False):
        return "INFO", "Running from source code - no file check."
    if not os.path.exists(man):
        return "INFO", "No WinDiag.sha256 list next to the exe - can't confirm the files are original."
    bad, checked = [], 0
    try:
        with open(man, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(None, 1)
                if len(parts) != 2:
                    continue
                want, name = parts[0].lower(), parts[1].strip().lstrip("*")
                fp = os.path.join(base, name)
                if not os.path.exists(fp):
                    continue
                checked += 1
                if sha256(fp) != want:
                    bad.append(name)
    except Exception as e:
        return "INFO", "Could not read WinDiag.sha256: %s" % e
    if bad:
        return "CRITICAL", "Changed since release: %s. Get a fresh copy of WinDiag - this one may have been tampered with." % ", ".join(bad)
    return "OK", "%d file(s) match the release fingerprints (SHA-256)." % checked


def run():
    """Blocking (usually 1-4 s, never raises). Returns (list of (status, title, detail), exe_hash)."""
    items, exe_hash = [], ""
    try:
        st, txt = integrity()
    except Exception as e:
        core.log_error("prescan.integrity", e)
        st, txt = "INFO", "Couldn't check WinDiag's files: %s" % core.friendly_error(e)
    items.append((st, "WinDiag files", txt))
    if getattr(sys, "frozen", False):
        try:
            exe_hash = sha256(sys.executable)
        except Exception:
            pass
    try:
        items += _windows_checks()
    except Exception as e:
        core.log_error("prescan.run", e)
        items.append(("INFO", "Security pre-check incomplete", "Part of the check failed: %s" % core.friendly_error(e)))
    return items, exe_hash


def _windows_checks():
    items = []
    r = core.run_ps_json(PRE_PS, 20, "Security check", track=False)
    r = r if isinstance(r, dict) else {}
    if not r or (r.get("status") == "error" and "rtp" not in r and "ps_sig" not in r):
        items.append(("WARNING", "Windows PowerShell", "Could not run PowerShell: %s. Most checks will fail." % (_s(r.get("detail")) or "no answer")[:120]))
        return items
    ok_ps = r.get("ps_os") is True or (_s(r.get("ps_sig")) == "Valid" and "Microsoft" in _s(r.get("ps_signer")))
    items += ifeo_item(_l(r.get("ifeo")))
    items.append(("OK" if ok_ps else "CRITICAL", "Windows PowerShell", "Genuine Microsoft-signed PowerShell in System32." if ok_ps else
                  "PowerShell's signature is %s - results can't be trusted." % (_s(r.get("ps_sig")) or "unknown")))
    active = [a for a in (_s(x) for x in _l(r.get("active"))) if a]
    other = [a for a in (_s(x) for x in _l(r.get("other_av"))) if a]
    mode = _s(r.get("am_mode")).lower()
    passive = "passive" in mode or "edr" in mode
    try:
        server = int(r.get("product_type") or 1) in (2, 3)
    except (TypeError, ValueError):
        server = False
    if active:
        items.append(("CRITICAL", "Active malware detected", "Defender reports: %s. Malware can hide or fake scan results - run the Defender Offline scan first." % ", ".join(active[:3])))
    if other or passive:
        items.append(("OK", "Antivirus", (", ".join(other[:2]) if other else "Another antivirus / EDR product") +
                      ("; Microsoft Defender in %s" % _s(r.get("am_mode")) if passive else "") + (", no active threats" if not active else "")))
    elif r.get("policy_off") is True:
        if server:
            items.append(("INFO", "Defender switched off by policy", "Normal on servers that use another antivirus (Windows Server doesn't list other antivirus products)."))
        else:
            items.append(("WARNING", "Defender switched off by a policy", "No other antivirus is registered with Windows. On a company PC this is usually deliberate "
                                                                             "(its protection may not register); otherwise malware may have done it - run the Security Scan."))
    elif r.get("rtp") is False:
        if server:
            items.append(("INFO", "Real-time protection is off", "On a server another antivirus may protect it (Windows Server doesn't list other antivirus products)."))
        else:
            items.append(("WARNING", "Real-time protection is off", "Turn it on in Windows Security before trusting the results."))
    elif r.get("defender"):
        items.append(("OK", "Antivirus", "Microsoft Defender running" + (", no active threats" if not active else "")))
    if r.get("testsigning") is True:
        items.append(("WARNING", "Test-signing mode is on", "Unsigned drivers can load - a rootkit trick. See the Security Scan."))
    me, desk = _s(r.get("me")), _s(r.get("desktop_user"))
    if me and desk and me.lower() != desk.lower():
        items.append(("WARNING", "WinDiag runs as a different user",
                      "WinDiag runs as %s, but %s is signed in. Checks of personal settings (startup apps, proxy, browser, OneDrive, user files) "
                      "look at %s's profile, not %s's." % (me, desk, me.split("\\")[-1], desk.split("\\")[-1])))
    return items
