"""
WinDiag Security Scan
---------------------
Three layers (no home-made antivirus):
  1. Microsoft Defender: status, tampering (exclusions, disabled by policy), detections, scans.
  2. Persistence triage: every auto-start location (Run keys, Startup folders, scheduled tasks,
     services, WMI subscriptions, Winlogon, IFEO, AppInit), running processes, hosts/proxy/DNS,
     admin accounts and log-clearing events - each program's Authenticode signature is checked.
  3. Certificates & boot security: trusted roots vs Microsoft's official list (certutil
     -generateSSTFromWU), HTTPS interception test, weak/expired certs, Secure Boot, test-signing,
     HVCI, vulnerable-driver blocklist, LSA protection, unsigned drivers.
The PowerShell part only READS. Analysis (pure Python) turns the raw data into findings.
"""
import json
import re
import time
import urllib.request

# ---------------------------------------------------------------------------------
#  PowerShell triage (prints one JSON object)
# ---------------------------------------------------------------------------------
TRIAGE_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$R = [ordered]@{}
$sigCache = @{}

function Expand-Cmd([string]$c) { if (-not $c) { return '' }; return [Environment]::ExpandEnvironmentVariables($c.Trim()) }
function Get-ExePath([string]$cmd) {
    $c = Expand-Cmd $cmd
    if (-not $c) { return '' }
    if ($c -match '^"([^"]+)"') { $p = $matches[1] }
    elseif ($c -match '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|dll|scr|lnk|msi))(\s|,|$)') { $p = $matches[1] }
    else { $p = ($c -split '\s+')[0] }
    if ($p -notmatch '[\\/]') {
        $w = Get-Command $p -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($w) { $p = $w.Source } elseif (Test-Path "$env:windir\System32\$p") { $p = "$env:windir\System32\$p" }
    }
    return $p
}
function Get-Sig([string]$p) {
    if (-not $p) { return $null }
    if ($sigCache.ContainsKey($p)) { return $sigCache[$p] }
    $o = [ordered]@{ path = $p; exists = [bool](Test-Path -LiteralPath $p -PathType Leaf); status = ''; signer = ''; os = $false; sha256 = ''; size = 0; created = '' }
    if ($o.exists) {
        $s = Get-AuthenticodeSignature -LiteralPath $p
        $o.status = "$($s.Status)"
        if ($s.SignerCertificate) { $o.signer = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
        $o.os = [bool]$s.IsOSBinary
        $fi = Get-Item -LiteralPath $p -Force
        $o.size = $fi.Length; $o.created = $fi.CreationTime.ToString('s')
        if ($o.status -ne 'Valid') { $o.sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
    }
    $sigCache[$p] = $o
    return $o
}
function Add-Entry($list, $type, $location, $name, $cmd, $extra) {
    $p = Get-ExePath $cmd
    $arg = ''
    if ($p -match '\\(rundll32|regsvr32)\.exe$' -and (Expand-Cmd $cmd) -match '(?i)[\s"]([a-z]:\\[^",]+\.(dll|ocx|cpl))') { $arg = $matches[1] }
    $e = [ordered]@{ type = $type; location = $location; name = $name; command = "$cmd"; path = $p; sig = (Get-Sig $p); target = $(if ($arg) { Get-Sig $arg } else { $null }) }
    if ($extra) { foreach ($k in $extra.Keys) { $e[$k] = $extra[$k] } }
    [void]$list.Add($e)
}

# ---------------- Defender ----------------
$mp = Get-MpComputerStatus; $pref = Get-MpPreference
$pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$polrt = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
$av = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
    $h = '{0:x6}' -f [int]$_.productState; [ordered]@{ name = $_.displayName; enabled = ($h.Substring(2,2) -in '10','11'); uptodate = ($h.Substring(4,2) -eq '00'); path = $_.pathToSignedProductExe } })
$threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 50 | ForEach-Object {
    $t = Get-MpThreat -ThreatID $_.ThreatID
    [ordered]@{ time = $_.InitialDetectionTime.ToString('s'); name = $t.ThreatName; severity = $t.SeverityID; status = $_.ThreatStatusID; action_ok = $_.ActionSuccess; resources = @($_.Resources | Select-Object -First 5); process = $_.ProcessName } })
$R.defender = [ordered]@{
    present = [bool]$mp; service = $mp.AMServiceEnabled; realtime = $mp.RealTimeProtectionEnabled; tamper = $mp.IsTamperProtected
    antivirus_enabled = $mp.AntivirusEnabled; sig_updated = $(if ($mp.AntivirusSignatureLastUpdated) { $mp.AntivirusSignatureLastUpdated.ToString('s') } else { '' })
    quick_scan = $(if ($mp.QuickScanEndTime) { $mp.QuickScanEndTime.ToString('s') } else { '' }); full_scan = $(if ($mp.FullScanEndTime) { $mp.FullScanEndTime.ToString('s') } else { '' })
    mode = "$($mp.AMRunningMode)"
    excl_path = @($pref.ExclusionPath); excl_process = @($pref.ExclusionProcess); excl_ext = @($pref.ExclusionExtension); excl_ip = @($pref.ExclusionIpAddress)
    policy_disable = $pol.DisableAntiSpyware; policy_rt_off = $polrt.DisableRealtimeMonitoring; pref_rt_off = $pref.DisableRealtimeMonitoring
    products = $av; threats = $threats
}

# ---------------- Auto-start locations ----------------
$E = New-Object System.Collections.ArrayList
$runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
foreach ($k in $runKeys) {
    $it = Get-Item $k
    if ($it) { foreach ($v in $it.GetValueNames()) { if ($v) { Add-Entry $E 'run' $k $v "$($it.GetValue($v))" @{ key = $k; value = $v } } } }
}
$sh = New-Object -ComObject WScript.Shell
foreach ($d in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {
    foreach ($f in Get-ChildItem $d -File -Force) {
        if ($f.Name -eq 'desktop.ini') { continue }
        $cmd = $f.FullName
        if ($f.Extension -eq '.lnk') { $l = $sh.CreateShortcut($f.FullName); $cmd = ('"{0}" {1}' -f $l.TargetPath, $l.Arguments).Trim() }
        Add-Entry $E 'startup' $d $f.Name $cmd @{ file = $f.FullName }
    }
}
foreach ($t in Get-ScheduledTask) {
    if ("$($t.State)" -eq 'Disabled') { continue }
    foreach ($a in $t.Actions) {
        if ($a.Execute) { Add-Entry $E 'task' $t.TaskPath $t.TaskName ('"{0}" {1}' -f $a.Execute, $a.Arguments).Trim() @{ taskpath = $t.TaskPath; author = $t.Author } }
    }
}
foreach ($s in Get-CimInstance Win32_Service) {
    if ($s.StartMode -in 'Auto', 'Manual', 'Boot', 'System' -and $s.PathName) {
        Add-Entry $E 'service' $s.StartMode $s.Name $s.PathName @{ display = $s.DisplayName; state = $s.State; startmode = $s.StartMode; account = $s.StartName }
    }
}
$R.entries = $E

# ---------------- Special hijack points ----------------
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$wlu = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$R.winlogon = [ordered]@{ shell = $wl.Shell; userinit = $wl.Userinit; user_shell = $wlu.Shell }
$R.ifeo = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
    $d = $_.GetValue('Debugger'); if ($d) { [ordered]@{ image = $_.PSChildName; debugger = $d; key = $_.Name } } })
$ai = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$R.appinit = [ordered]@{ dlls = $ai.AppInit_DLLs; load = $ai.LoadAppInit_DLLs }
$R.wmi = [ordered]@{
    consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | ForEach-Object {
        [ordered]@{ class = $_.CimClass.CimClassName; name = $_.Name; command = "$($_.CommandLineTemplate)$($_.ScriptText)".Substring(0, [math]::Min(400, "$($_.CommandLineTemplate)$($_.ScriptText)".Length)); file = $_.ScriptFileName } })
    bindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | ForEach-Object { [ordered]@{ filter = "$($_.Filter)"; consumer = "$($_.Consumer)" } })
}
$R.accessibility = @(foreach ($n in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') { Get-Sig "$env:windir\System32\$n" })

# ---------------- Processes & network ----------------
$conns = @{}
foreach ($c in Get-NetTCPConnection -State Established) {
    if ($c.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|::$)') { $conns[[int]$c.OwningProcess] += @("$($c.RemoteAddress):$($c.RemotePort)") }
}
$R.processes = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | ForEach-Object {
    $p = $_.ExecutablePath
    $inWin = $p -like "$env:windir\*"
    $g = if ($inWin -and $_.Name -notin 'rundll32.exe', 'powershell.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe') { $null } else { Get-Sig $p }
    [ordered]@{ name = $_.Name; pid = $_.ProcessId; path = $p; cmd = "$($_.CommandLine)".Substring(0, [math]::Min(300, "$($_.CommandLine)".Length)); sig = $g; remote = @($conns[[int]$_.ProcessId] | Select-Object -Unique -First 6) } })

$R.hosts = @(Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*(#|$)' } | ForEach-Object { ($_ -replace '#.*', '').Trim() })
$is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$wh = ''; try { $wh = ((netsh winhttp show proxy) -join ' ') } catch {}
$R.proxy = [ordered]@{ enabled = $is.ProxyEnable; server = $is.ProxyServer; pac = $is.AutoConfigURL; winhttp = $wh }
$R.dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { [ordered]@{ ifname = $_.InterfaceAlias; servers = @($_.ServerAddresses) } })

# ---------------- Accounts & tamper events ----------------
$R.admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [ordered]@{ name = "$($_.Name)"; source = "$($_.PrincipalSource)"; class = "$($_.ObjectClass)" } })
$R.users = @(Get-LocalUser | ForEach-Object { [ordered]@{ name = $_.Name; enabled = $_.Enabled; sid = "$($_.SID)"; created = $(if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('s') } else { '' }); lastlogon = $(if ($_.LastLogon) { $_.LastLogon.ToString('s') } else { '' }) } })
$since = (Get-Date).AddDays(-30)
function EvList($f, $n) { @(Get-WinEvent -FilterHashtable $f -MaxEvents $n -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ time = $_.TimeCreated.ToString('s'); id = $_.Id; provider = $_.ProviderName; msg = (($_.Message -split "`n")[0]).Trim() } }) }
$R.events = [ordered]@{
    log_cleared = @(EvList @{ LogName = 'Security'; Id = 1102; StartTime = $since } 20) + @(EvList @{ LogName = 'System'; Id = 104; StartTime = $since } 20)
    user_created = EvList @{ LogName = 'Security'; Id = 4720; StartTime = $since } 20
    added_admin = EvList @{ LogName = 'Security'; Id = 4732; StartTime = $since } 20
    defender_off = EvList @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001, 5010, 5012; StartTime = $since } 20
    defender_cfg = EvList @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5007; StartTime = $since } 40
    service_installed = EvList @{ LogName = 'System'; Id = 7045; StartTime = $since } 40
}

# ---------------- Certificates ----------------
$ms = @{}; $msOk = $false
$sst = Join-Path $env:TEMP ('windiag_roots_{0}.sst' -f (Get-Random))
$null = certutil -generateSSTFromWU $sst 2>&1
if (Test-Path $sst) {
    try { $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection; $col.Import($sst); foreach ($c in $col) { $ms[$c.Thumbprint] = 1 }; $msOk = $ms.Count -gt 50 } catch {}
    if (-not $msOk) { foreach ($l in (certutil -dump $sst)) { if ($l -match 'Cert Hash\(sha1\):\s*([0-9a-fA-F ]+)') { $ms[($matches[1] -replace ' ', '').ToUpper()] = 1 } }; $msOk = $ms.Count -gt 50 }
    Remove-Item $sst -Force
}
function CertRow($c, $store) {
    $alg = "$($c.SignatureAlgorithm.FriendlyName)"
    $ks = 0; try { $ks = $c.PublicKey.Key.KeySize } catch {}
    [ordered]@{ store = $store; thumb = $c.Thumbprint; subject = $c.Subject; issuer = $c.Issuer; notbefore = $c.NotBefore.ToString('s'); notafter = $c.NotAfter.ToString('s')
                alg = $alg; keysize = $ks; privkey = $c.HasPrivateKey; selfsigned = ($c.Subject -eq $c.Issuer); inms = [bool]$ms[$c.Thumbprint]; friendly = $c.FriendlyName }
}
$roots = @()
foreach ($st in 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root', 'Cert:\LocalMachine\AuthRoot', 'Cert:\CurrentUser\AuthRoot') {
    foreach ($c in Get-ChildItem $st) { $roots += CertRow $c $st }
}
$mine = @()
foreach ($st in 'Cert:\LocalMachine\My', 'Cert:\CurrentUser\My') { foreach ($c in Get-ChildItem $st) { $mine += CertRow $c $st } }
$tls = [ordered]@{ ok = $false; chain = @(); error = '' }
try {
    $req = [Net.HttpWebRequest]::Create('https://www.microsoft.com/'); $req.Timeout = 10000; $req.Method = 'HEAD'; $req.AllowAutoRedirect = $false
    $resp = $req.GetResponse(); $resp.Close()
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $req.ServicePoint.Certificate
    $ch = New-Object System.Security.Cryptography.X509Certificates.X509Chain; [void]$ch.Build($cert)
    $tls.chain = @($ch.ChainElements | ForEach-Object { [ordered]@{ subject = $_.Certificate.Subject; thumb = $_.Certificate.Thumbprint; inms = [bool]$ms[$_.Certificate.Thumbprint]; privkey = $false } })
    $tls.ok = $true
} catch { $tls.error = $_.Exception.Message }
$R.certs = [ordered]@{ ms_list = $msOk; ms_count = $ms.Count; roots = $roots; mine = $mine; disallowed = @(Get-ChildItem Cert:\LocalMachine\Disallowed).Count; tls = $tls }

# ---------------- Boot & driver security ----------------
$sb = $null; try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch {}
$bcd = (bcdedit /enum '{current}') -join "`n"
# locale-proof: the options the CURRENT boot really uses (bcdedit's Yes/No values are translated on some Windows languages)
$sso = "$((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').SystemStartOptions)"
$yes = '(?im)^X\s+(Yes|Ja|Oui|S\u00ed|Si|Sim|Tak|Igen|Ano|Kyll\u00e4|Evet|\u0414\u0430|\u662f|\u306f\u3044|\uc608)\s*$'
$R.os = [ordered]@{ product_type = [int](Get-CimInstance Win32_OperatingSystem).ProductType }
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
$ci = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$R.boot = [ordered]@{
    secureboot = $sb
    testsigning = ($sso -match '(^|\s)TESTSIGNING(\s|$)') -or ($bcd -match $yes.Replace('X', 'testsigning'))
    nointegrity = ($sso -match '(^|\s)DISABLE_INTEGRITY_CHECKS(\s|$)') -or ($bcd -match $yes.Replace('X', 'nointegritychecks'))
    debug = ($sso -match '(^|\s)DEBUG(\s|=|$)') -or ($bcd -match $yes.Replace('X', 'debug'))
    hvci = [bool](@($dg.SecurityServicesRunning) -contains 2); vbs = [int]$dg.VirtualizationBasedSecurityStatus
    blocklist = $ci.VulnerableDriverBlocklistEnable; lsa_ppl = $lsa.RunAsPPL
    unsigned_drivers = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.IsSigned -eq $false -and $_.DeviceName } | ForEach-Object { [ordered]@{ device = $_.DeviceName; driver = $_.InfName; provider = $_.DriverProviderName } })
}
$R | ConvertTo-Json -Depth 7 -Compress
"""

# ---------------------------------------------------------------------------------
#  Analysis
# ---------------------------------------------------------------------------------
USER_WRITABLE = re.compile(r"(?i)\\(appdata\\local\\temp|temp|windows\\temp|users\\public|\$recycle\.bin|downloads|perflogs)\\")
APPDATA = re.compile(r"(?i)\\appdata\\(roaming|local)\\")
PROGRAMDATA_ROOT = re.compile(r"(?i)^[a-z]:\\programdata\\[^\\]+\.(exe|dll|scr|bat|vbs|ps1)$")
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "explorer.exe", "wininit.exe",
                "spoolsv.exe", "taskhostw.exe", "dwm.exe", "conhost.exe", "rundll32.exe", "lsm.exe", "searchindexer.exe"}
LOLBIN_RULES = [
    (r"(?i)powershell(\.exe)?\b.*(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}|frombase64string)", 5, "PowerShell runs an ENCODED (hidden) command"),
    (r"(?i)powershell(\.exe)?\b.*(downloadstring|downloadfile|invoke-webrequest|iwr |net\.webclient|start-bitstransfer|iex\b|invoke-expression)", 5, "PowerShell downloads/executes code from the internet"),
    (r"(?i)powershell(\.exe)?\b.*-w(indowstyle)?\s+h(idden)?", 2, "PowerShell runs in a hidden window"),
    (r"(?i)mshta(\.exe)?\b.*(https?:|javascript:|vbscript:)", 6, "mshta runs a script from the internet"),
    (r"(?i)regsvr32(\.exe)?\b.*/i:\s*https?:", 6, "regsvr32 loads a remote script (Squiblydoo technique)"),
    (r"(?i)rundll32(\.exe)?\b.*(javascript:|https?:)", 6, "rundll32 runs script/URL"),
    (r"(?i)certutil(\.exe)?\b.*(-urlcache|-decode)", 5, "certutil used to download/decode files"),
    (r"(?i)bitsadmin(\.exe)?\b.*/transfer", 4, "bitsadmin downloads a file"),
    (r"(?i)(wscript|cscript)(\.exe)?\b.*\.(js|jse|vbs|vbe|wsf)", 2, "Windows Script Host runs a script"),
    (r"(?i)cmd(\.exe)?\s+/c.*(\^.*){4,}", 3, "Obfuscated cmd command"),
]
KNOWN_DNS = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|8\.8\.|8\.26\.|1\.1\.1\.|1\.0\.0\.|9\.9\.9\.|149\.112\.|208\.67\.|94\.140\.|76\.76\.|185\.228\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)")
INSPECTION_VENDORS = re.compile(r"(?i)(avast|avg|kaspersky|eset|bitdefender|norton|symantec|mcafee|sophos|trend ?micro|fortinet|fortigate|zscaler|netskope|palo ?alto|cisco|umbrella|blue ?coat|forcepoint|checkpoint|check point|barracuda|webroot|malwarebytes|f-secure|gdata|g data|panda|comodo|adguard|fiddler|charles|mitmproxy|burp|portswigger)")
SENSITIVE_HOSTS = re.compile(r"(?i)(microsoft|windowsupdate|live\.com|office|google|apple|facebook|paypal|bank|amazon|defender|kaspersky|eset|avast|avg|norton|mcafee|malwarebytes|bitdefender|virustotal)")
THREAT_STATUS = {0: "unknown", 1: "detected", 2: "cleaned", 3: "quarantined", 4: "removed", 5: "allowed", 6: "blocked",
                 102: "quarantine FAILED", 103: "removal FAILED", 104: "allow failed", 105: "abandoned", 107: "block FAILED"}


_ETS_KEYS = {"value", "Count", "Length", "PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSIsContainer", "ReadCount"}


def _unwrap(x):
    """Undo PowerShell 5.1 JSON quirks: strings/arrays serialized as {'value': ..., 'PSPath': ...} / {'value': [...], 'Count': n}."""
    if isinstance(x, dict):
        if "value" in x and set(x) <= _ETS_KEYS and len(x) > 1:
            return _unwrap(x["value"])
        return {k: _unwrap(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_unwrap(i) for i in x]
    return x


def _l(x):
    if x is None or x == "" or x == {}:
        return []
    return [i for i in x if i is not None] if isinstance(x, list) else [x]


def _ld(x):
    return [i for i in _l(x) if isinstance(i, dict)]


def _str(x):
    if x is None:
        return ""
    if isinstance(x, list):
        return ", ".join(_str(i) for i in x if i is not None)
    if isinstance(x, dict):
        return _str(x.get("value", "")) if "value" in x else ""
    return x if isinstance(x, str) else str(x)


def _ls(x):
    return [t for t in (_str(i) for i in _l(x)) if t]


def _dict(x):
    if isinstance(x, list):
        x = next((i for i in x if isinstance(i, dict)), None)
    return x if isinstance(x, dict) else {}


def _int(x, default=0):
    try:
        return int(float(_str(x).replace(",", "."))) if not isinstance(x, (int, float)) or isinstance(x, bool) else int(x)
    except (TypeError, ValueError, OverflowError):
        return default


def _sigd(x):
    """A Get-Sig object (or None)."""
    x = _dict(x)
    if not x:
        return None
    for k in ("path", "status", "signer", "sha256", "created"):
        x[k] = _str(x.get(k))
    return x


def normalize(raw):
    """Make TRIAGE_PS output type-safe (PS 5.1, missing modules on Server/LTSC, locked-down PCs)."""
    raw = _unwrap(raw)
    raw = raw if isinstance(raw, dict) else {}
    d = _dict(raw.get("defender"))
    d["products"] = _ld(d.get("products"))
    for p in d["products"]:
        p["name"] = _str(p.get("name"))
    d["threats"] = _ld(d.get("threats"))
    for t in d["threats"]:
        t["resources"] = _ls(t.get("resources"))
        t["name"], t["time"] = _str(t.get("name")), _str(t.get("time"))
    for k in ("excl_path", "excl_process", "excl_ext", "excl_ip"):
        d[k] = _ls(d.get(k))
    for k in ("sig_updated", "mode"):
        d[k] = _str(d.get(k))
    raw["defender"] = d
    raw["entries"] = _ld(raw.get("entries"))
    for e in raw["entries"]:
        for k in ("type", "location", "name", "command", "path"):
            e[k] = _str(e.get(k))
        e["sig"], e["target"] = _sigd(e.get("sig")), _sigd(e.get("target"))
    wl = _dict(raw.get("winlogon"))
    raw["winlogon"] = {k: _str(wl.get(k)) for k in ("shell", "userinit", "user_shell")}
    raw["ifeo"] = _ld(raw.get("ifeo"))
    for i in raw["ifeo"]:
        for k in ("image", "debugger", "key"):
            i[k] = _str(i.get(k))
    raw["accessibility"] = [x for x in (_sigd(a) for a in _l(raw.get("accessibility"))) if x]
    ai = _dict(raw.get("appinit"))
    raw["appinit"] = {"dlls": _str(ai.get("dlls")), "load": _int(ai.get("load"))}
    wmi = _dict(raw.get("wmi"))
    wmi["consumers"] = _ld(wmi.get("consumers"))
    for c in wmi["consumers"]:
        for k in ("class", "name", "command", "file"):
            c[k] = _str(c.get(k))
    raw["wmi"] = wmi
    raw["processes"] = _ld(raw.get("processes"))
    for p in raw["processes"]:
        for k in ("name", "path", "cmd"):
            p[k] = _str(p.get(k))
        p["sig"], p["remote"] = _sigd(p.get("sig")), _ls(p.get("remote"))
    raw["hosts"] = _ls(raw.get("hosts"))
    px = _dict(raw.get("proxy"))
    raw["proxy"] = {"enabled": _int(px.get("enabled")), "server": _str(px.get("server")), "pac": _str(px.get("pac")), "winhttp": _str(px.get("winhttp"))}
    raw["dns"] = _ld(raw.get("dns"))
    for x in raw["dns"]:
        x["ifname"], x["servers"] = _str(x.get("ifname")), _ls(x.get("servers"))
    ev = _dict(raw.get("events"))
    for k in list(ev):
        ev[k] = _ld(ev[k])
        for e in ev[k]:
            e["time"], e["msg"] = _str(e.get("time")), _str(e.get("msg"))
    raw["events"] = ev
    raw["users"] = _ld(raw.get("users"))
    c = _dict(raw.get("certs"))
    for k in ("roots", "mine"):
        c[k] = _ld(c.get(k))
        for r in c[k]:
            for f in ("store", "thumb", "subject", "issuer", "notafter", "alg", "friendly"):
                r[f] = _str(r.get(f))
    tls = _dict(c.get("tls"))
    tls["chain"] = _ld(tls.get("chain"))
    for x in tls["chain"]:
        x["subject"] = _str(x.get("subject"))
    tls["error"] = _str(tls.get("error"))
    c["tls"] = tls
    raw["certs"] = c
    b = _dict(raw.get("boot"))
    b["unsigned_drivers"] = _ld(b.get("unsigned_drivers"))
    raw["boot"] = b
    raw["os"] = _dict(raw.get("os"))
    return raw


def _sig_text(sig):
    if not sig:
        return "n/a"
    if not sig.get("exists"):
        return "FILE MISSING"
    st = sig.get("status") or "?"
    return "%s%s" % ("Signed: " + sig["signer"] if st == "Valid" and sig.get("signer") else st, " (Windows)" if sig.get("os") else "")


def score_entry(e):
    """Return (score, reasons) for an auto-start entry or process."""
    reasons = []
    score = 0
    cmd = e.get("command") or e.get("cmd") or ""
    path = (e.get("path") or "")
    sig = e.get("sig") or {}
    tgt = e.get("target") or {}
    check_path = tgt.get("path") or path
    check_sig = tgt if tgt else sig
    valid = check_sig.get("status") == "Valid"
    ms_signed = valid and (check_sig.get("os") or "Microsoft" in (check_sig.get("signer") or ""))
    if USER_WRITABLE.search(check_path + "\\"):
        score += 3
        reasons.append("runs from a temporary / public / downloads folder")
    elif PROGRAMDATA_ROOT.search(check_path):
        score += 2
        reasons.append("program sits directly in C:\\ProgramData (unusual)")
    elif APPDATA.search(check_path) and not valid:
        score += 2
        reasons.append("unsigned program in the user profile (AppData)")
    if check_sig and check_sig.get("exists"):
        st = check_sig.get("status")
        if st == "HashMismatch":
            score += 6
            reasons.append("signature is BROKEN - the signed file was modified")
        elif st in ("NotSigned", "UnknownError", "NotTrusted", "NotSupportedFileFormat") and not ms_signed:
            if check_path.lower().endswith((".exe", ".dll", ".scr", ".sys")):
                score += 2
                reasons.append("not digitally signed")
    elif check_sig and check_sig.get("exists") is False and e.get("type") != "service":
        reasons.append("target file no longer exists (left-over entry)")
    if tgt and tgt.get("exists") and tgt.get("status") != "Valid" and re.search(r"(?i)\\(rundll32|regsvr32)\.exe$", path):
        score += 2
        reasons.append("an unsigned DLL is launched through %s" % path.rsplit("\\", 1)[-1])
    for rx, pts, why in LOLBIN_RULES:
        if re.search(rx, cmd):
            score += pts
            reasons.append(why)
    base = path.lower().rsplit("\\", 1)[-1]
    if base in SYSTEM_NAMES and path and not re.match(r"(?i)^[a-z]:\\windows\\", path):
        score += 7
        reasons.append("uses a Windows system file name (%s) from the WRONG folder - classic disguise" % base)
    if re.search(r"(?i)\\[a-z0-9]{12,}\.(exe|dll|scr)$", path) and not valid and re.search(r"\d", base) and re.search(r"[a-z]", base):
        score += 1
        reasons.append("random-looking file name")
    if e.get("remote") and score >= 3:
        score += 2
        reasons.append("has active internet connections: " + ", ".join(_l(e.get("remote"))[:3]))
    if ms_signed and score < 5:
        score = 0
        reasons = []
    return score, reasons


def _sev(score):
    return "CRITICAL" if score >= 6 else ("WARNING" if score >= 3 else None)


def analyze(raw):
    """raw = JSON from TRIAGE_PS. Returns dict(findings, tables)."""
    F = []

    def add(sev, cat, title, why="", advice="", item=None, detail=""):
        F.append({"severity": sev, "category": cat, "title": title, "why": why, "advice": advice, "item": item, "detail": detail})

    raw = normalize(raw)
    d = raw["defender"]
    prods = d["products"]
    other_av = [p for p in prods if p.get("enabled") is True and not re.match(r"(?i)^(windows|microsoft) defender", p["name"])]
    mode = d.get("mode", "").lower()
    passive = "passive" in mode or "edr" in mode            # AMRunningMode: Normal / Passive Mode / SxS Passive Mode / EDR Block Mode
    server = _int(raw["os"].get("product_type"), 1) in (2, 3)  # 2 = domain controller, 3 = server
    if d.get("present"):
        if passive:
            add("INFO", "Defender", "Microsoft Defender runs in %s" % (d.get("mode") or "passive mode"),
                "Another antivirus / EDR product is the main protection and Defender only assists%s." % (" (EDR block mode still blocks what it finds)" if "edr" in mode else ""),
                "Make sure that other product is running and up to date.")
        elif not d.get("realtime") and not other_av:
            if server:
                add("WARNING", "Defender", "Defender real-time protection is off on this server",
                    "Windows Server doesn't report other antivirus products to Windows Security, so WinDiag can't tell if another one protects it.",
                    "Check that the server's antivirus (Defender or a third-party product) is running.")
            else:
                add("CRITICAL", "Defender", "Microsoft Defender real-time protection is OFF",
                    "Nothing is scanning files as they are opened.", "Turn it on in Windows Security > Virus & threat protection. If it turns itself off again, malware may be disabling it.")
        if _int(d.get("policy_disable")) == 1 or _int(d.get("policy_rt_off")) == 1:
            calm = bool(other_av) or passive or server
            add("INFO" if calm else "CRITICAL", "Defender", "Defender is disabled by a POLICY setting",
                ("Normal when another antivirus or a company/server policy manages protection." if calm else
                 "A Group Policy / registry policy switches Defender off. Malware does this; so do some leftover third-party antivirus installs."),
                "" if calm else "If this is not a company PC, remove the policy values under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender and run an offline scan.")
        ex = [("folder", x) for x in d["excl_path"]] + [("process", x) for x in d["excl_process"]] + [("extension", x) for x in d["excl_ext"]]
        if any(x.upper().startswith("N/A") for _, x in ex):
            # non-admin: Get-MpPreference returns "N/A: Must be an administrator to view exclusions"
            ex = [(k, x) for k, x in ex if not x.upper().startswith("N/A")]
            add("INFO", "Defender", "Defender exclusions need admin to read",
                "Windows only shows the exclusion list to administrators.", "Run WinDiag as administrator to check exclusions.")
        for kind, x in ex:
            bad = kind == "extension" and x.lower().strip(".") in ("exe", "dll", "ps1", "bat", "js", "vbs") or \
                re.match(r"(?i)^[a-z]:\\?$", x) or USER_WRITABLE.search(x + "\\") or re.search(r"(?i)\\(appdata|programdata)\b", x)
            add("CRITICAL" if bad else "WARNING", "Defender", "Defender skips %s: %s" % (kind, x),
                "Exclusions stop Defender scanning that location. Malware adds exclusions for its own folder so it is never detected.",
                "If you did not add this on purpose, remove it: Windows Security > Virus & threat protection settings > Exclusions.")
        if d.get("sig_updated"):
            try:
                age = (time.time() - time.mktime(time.strptime(d["sig_updated"][:19], "%Y-%m-%dT%H:%M:%S"))) / 86400
                if age > 7:
                    add("WARNING", "Defender", "Virus definitions are %d days old" % age, "", "Update them (Guided Fix / Repairs > Update Defender definitions).")
            except (ValueError, OverflowError):
                pass
        if d.get("tamper") is False and not other_av and not passive:
            add("INFO", "Defender", "Tamper Protection is off", "Tamper Protection stops malware from switching Defender off.", "Turn it on in Windows Security > Virus & threat protection settings.")
    for t in d["threats"]:
        st = _int(t.get("status"))
        txt = THREAT_STATUS.get(st, str(st))
        active = st in (1, 5, 102, 103, 105, 107) or not t.get("action_ok")
        add("CRITICAL" if active else "INFO", "Defender", "%s: %s (%s)" % ("ACTIVE threat" if active else "Past detection", t.get("name"), txt),
            "Resources: " + "; ".join(t["resources"][:3]),
            "Run a Defender full scan and the Offline scan." if active else "Handled by Defender.", detail=t.get("time", ""))

    # ---- auto-start entries ----
    rows = []
    for e in _l(raw.get("entries")):
        sc, why = score_entry(e)
        sev = _sev(sc)
        loc = {"run": "Registry Run key", "startup": "Startup folder", "task": "Scheduled task", "service": "Service"}.get(e["type"], e["type"])
        rows.append({"Verdict": sev or ("REVIEW" if sc > 0 else "OK"), "Type": loc, "Name": e.get("name"), "Program": e.get("path"), "Signature": _sig_text((e.get("target") or e.get("sig"))),
                     "Why": "; ".join(why), "_entry": e})
        if sev:
            add(sev, "Startup / persistence", "%s '%s' looks suspicious" % (loc, e.get("name")), "; ".join(why),
                "Check the program online; if unknown, use 'Quarantine' (reversible).", item={"kind": "entry", "entry": e, "sha256": ((e.get("target") or e.get("sig") or {}).get("sha256"))},
                detail=e.get("command", "")[:300])
    # ---- special hijacks ----
    wl = raw.get("winlogon") or {}
    if wl.get("shell") and wl["shell"].strip().lower() not in ("explorer.exe",):
        add("CRITICAL", "Hijack", "Winlogon Shell was changed: %s" % wl["shell"], "Windows starts this instead of / in addition to Explorer at every sign-in.", "Set HKLM\\...\\Winlogon\\Shell back to explorer.exe.")
    if wl.get("user_shell"):
        add("WARNING", "Hijack", "Per-user Winlogon Shell is set: %s" % wl["user_shell"], "", "Remove HKCU\\...\\Winlogon\\Shell unless it is a kiosk setup.")
    if wl.get("userinit") and not re.match(r"(?i)^\s*c:\\windows\\system32\\userinit\.exe,?\s*$", wl["userinit"]):
        add("CRITICAL", "Hijack", "Winlogon Userinit was changed: %s" % wl["userinit"], "Extra programs here run at every sign-in.", "Set it back to C:\\Windows\\system32\\userinit.exe,")
    for i in _l(raw.get("ifeo")):
        acc = (i.get("image") or "").lower() in ("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe")
        add("CRITICAL" if acc else "WARNING", "Hijack", "Program redirect (IFEO Debugger) on %s -> %s" % (i.get("image"), i.get("debugger")),
            "Whenever %s starts, Windows runs the debugger program instead.%s" % (i.get("image"), " On an accessibility tool this is a known login-screen BACKDOOR." if acc else " Legit only for tools like Process Explorer."),
            "Remove the Debugger value if you did not set it.", item={"kind": "ifeo", "ifeo": i})
    for s in _l(raw.get("accessibility")):
        if s and s.get("exists") and not s.get("os") and s.get("status") != "Valid":
            add("CRITICAL", "Hijack", "Accessibility tool replaced: %s" % s.get("path"), "This file should be a signed Windows file. Replacing it gives a SYSTEM command prompt on the login screen.",
                "Run DISM + SFC to restore it and investigate how it was changed.")
    ai = raw.get("appinit") or {}
    if (ai.get("dlls") or "").strip() and ai.get("load") == 1:
        add("WARNING", "Hijack", "AppInit_DLLs loads into every program: %s" % ai["dlls"], "An old injection method used by adware and malware.", "Clear AppInit_DLLs unless required by known software.")
    wmi = raw.get("wmi") or {}
    for c in _l(wmi.get("consumers")):
        cls = c.get("class") or ""
        if cls in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
            legit = c.get("name") == "BVTConsumer" and "KernCap.vbs" in (c.get("command") or "")
            if not legit:
                add("CRITICAL", "Hijack", "WMI persistence: %s '%s'" % (cls, c.get("name")),
                    "A WMI subscription runs a command/script automatically - a favourite 'fileless' malware trick. Normal PCs rarely have one.",
                    "Investigate the command; remove the subscription (filter, consumer and binding) if unknown.", item={"kind": "wmi", "wmi": c}, detail=c.get("command", ""))
    # ---- processes ----
    prow = []
    for p in _l(raw.get("processes")):
        if not p.get("sig"):
            continue
        e = {"path": p.get("path"), "sig": p.get("sig"), "cmd": p.get("cmd"), "name": p.get("name"), "remote": p.get("remote"), "type": "process"}
        sc, why = score_entry(e)
        sev = _sev(sc)
        if sev or p.get("remote"):
            prow.append({"Verdict": sev or "OK", "Process": p.get("name"), "PID": p.get("pid"), "Path": p.get("path"), "Signature": _sig_text(p.get("sig")),
                         "Connections": ", ".join(_l(p.get("remote"))[:3]), "Why": "; ".join(why),
                         "_sha": (p.get("sig") or {}).get("sha256"), "_path": p.get("path"), "_cmd": p.get("cmd")})
        if sev:
            add(sev, "Running process", "Running program '%s' looks suspicious" % p.get("name"), "; ".join(why),
                "End it in Task Manager and quarantine the file if you don't recognise it.", item={"kind": "file", "path": p.get("path"), "sha256": (p.get("sig") or {}).get("sha256")},
                detail=p.get("cmd", ""))
    # ---- network tampering ----
    for h in _l(raw.get("hosts")):
        if SENSITIVE_HOSTS.search(h) and not h.startswith(("127.0.0.1 localhost", "::1")):
            add("CRITICAL", "Network", "Hosts file redirects a sensitive site: %s" % h, "Can block security updates or send you to a fake site.", "Remove the line from C:\\Windows\\System32\\drivers\\etc\\hosts.")
        elif not re.match(r"^(127\.0\.0\.1|::1|0\.0\.0\.0)\s+localhost", h):
            add("INFO", "Network", "Hosts file entry: %s" % h, "Custom entries redirect or block sites.", "Remove it if you don't know why it is there.")
    px = raw.get("proxy") or {}
    if px.get("enabled") == 1 or px.get("pac"):
        add("WARNING", "Network", "A proxy / PAC script is set: %s" % (px.get("server") or px.get("pac")), "All web traffic goes through it. Adware and banking trojans set proxies.",
            "If this is not a company/school PC, turn it off: Settings > Network > Proxy.")
    for dns in _l(raw.get("dns")):
        odd = [s for s in _l(dns.get("servers")) if not KNOWN_DNS.match(s)]
        if odd:
            add("INFO", "Network", "Unfamiliar DNS server on %s: %s" % (dns.get("ifname"), ", ".join(odd)), "DNS hijacking sends you to fake sites. It may also be your ISP's server.",
                "Check it belongs to your ISP/company; otherwise set DNS back to automatic.")
    # ---- accounts & tamper events ----
    ev = raw.get("events") or {}
    for e in _l(ev.get("log_cleared")):
        add("WARNING", "Tampering", "An event log was CLEARED on %s" % e.get("time", "")[:16].replace("T", " "), "Attackers clear logs to hide what they did.", "Make sure you or an admin did this on purpose.")
    for e in _l(ev.get("added_admin")):
        add("WARNING", "Accounts", "An account was added to Administrators on %s" % e.get("time", "")[:16].replace("T", " "), e.get("msg", ""), "Check that you recognise the account.")
    for e in _l(ev.get("user_created")):
        add("INFO", "Accounts", "New user account created on %s" % e.get("time", "")[:16].replace("T", " "), e.get("msg", ""), "")
    for e in _l(ev.get("defender_off"))[:3]:
        add("WARNING", "Defender", "Defender protection was turned off on %s (event %s)" % (e.get("time", "")[:16].replace("T", " "), e.get("id")), e.get("msg", ""), "")
    for u in _l(raw.get("users")):
        if u.get("enabled") and (u.get("sid") or "").endswith("-501"):
            add("WARNING", "Accounts", "The Guest account is enabled", "", "Disable it: net user guest /active:no")
    # ---- certificates ----
    c = raw.get("certs") or {}
    crows = []
    ms_ok = c.get("ms_list")
    seen = set()
    for r in _l(c.get("roots")):
        if r["thumb"] and r["thumb"] in seen:
            continue
        seen.add(r["thumb"])
        sys_ms = re.search(r"(?i)microsoft|thawte timestamping|copyright \(c\) 1997", r.get("subject") or "")
        vendor = INSPECTION_VENDORS.search((r.get("subject") or "") + " " + (r.get("friendly") or ""))
        verdict = "OK"
        if r.get("privkey"):
            verdict = "CRITICAL"
            add("CRITICAL", "Certificates", "Trusted ROOT certificate WITH PRIVATE KEY: %s" % r["subject"][:90],
                "Whoever holds this key can create fake certificates for ANY website that your PC will trust (HTTPS interception). Adware such as Superfish did exactly this.%s" % (" It appears to belong to %s (HTTPS scanning)." % vendor.group(1) if vendor else ""),
                "If you don't use a debugging proxy or security product that needs it, remove it (certmgr.msc > Trusted Root) and scan for malware.", item={"kind": "cert", "cert": r})
        elif ms_ok and not r.get("inms") and not sys_ms:
            verdict = "INFO" if vendor else "WARNING"
            add(verdict, "Certificates", "Trusted root NOT in Microsoft's program: %s" % r["subject"][:90],
                ("Added by %s (antivirus/proxy HTTPS scanning)." % vendor.group(1)) if vendor else
                "Not part of Microsoft's trusted root list. Company PCs have their own roots; on a home PC this can mean HTTPS interception by adware.",
                "Remove it if you can't identify it (keep a backup: WinDiag quarantines certificates reversibly).", item={"kind": "cert", "cert": r})
        crows.append({"Verdict": verdict, "Store": r["store"].replace("Cert:\\", ""), "Subject": r["subject"], "Expires": r["notafter"][:10],
                      "In Microsoft list": ("yes" if r.get("inms") else "NO") if ms_ok else "unknown", "Private key": "YES" if r.get("privkey") else "", "_cert": r})
    if not ms_ok:
        add("INFO", "Certificates", "Could not download Microsoft's trusted root list (offline?)", "Root certificates were only checked for private keys.", "Connect to the internet and scan again.")
    for r in _l(c.get("mine")):
        weak = re.search(r"(?i)sha1|md5", r.get("alg") or "") or (_int(r.get("keysize")) and _int(r.get("keysize")) < 2048 and "ec" not in (r.get("alg") or "").lower())
        if r.get("privkey") and weak and not r.get("selfsigned"):
            add("WARNING", "Certificates", "Weak certificate in use: %s (%s, %s-bit)" % (r["subject"][:70], r.get("alg"), r.get("keysize")), "SHA-1/MD5 or short keys are no longer secure.", "Replace it with a SHA-256, 2048-bit+ certificate.")
    tls = c.get("tls") or {}
    if tls.get("ok"):
        chain = _l(tls.get("chain"))
        root = chain[-1] if chain else {}
        issuer = (chain[1]["subject"] if len(chain) > 1 else "")
        vendor = INSPECTION_VENDORS.search(" ".join(x.get("subject", "") for x in chain))
        if ms_ok and root and not root.get("inms") and not re.search(r"(?i)digicert|microsoft|baltimore|globalsign", root.get("subject", "")):
            add("INFO" if vendor else "CRITICAL", "Certificates", "Your HTTPS traffic is being INTERCEPTED (issuer: %s)" % (issuer or root.get("subject"))[:90],
                "microsoft.com's certificate was not issued by its real public authority - something between you and the internet re-signs HTTPS traffic.%s" % (" It is %s (antivirus/proxy HTTPS scanning)." % vendor.group(1) if vendor else ""),
                "If this is not a known security product or company proxy, treat the PC as compromised.")
    elif tls.get("error"):
        add("INFO", "Certificates", "HTTPS interception test could not run", tls.get("error", "")[:150], "")
    # ---- boot & drivers ----
    b = raw.get("boot") or {}
    if b.get("secureboot") is False:
        add("WARNING", "Boot security", "Secure Boot is OFF", "Secure Boot blocks bootkits that load before Windows.", "Enable it in the BIOS/UEFI settings.")
    if b.get("testsigning"):
        add("CRITICAL", "Boot security", "Windows is in TEST-SIGNING mode", "Unsigned (possibly malicious) drivers can load.", "Run as admin: bcdedit /set testsigning off, then restart.")
    if b.get("nointegrity"):
        add("CRITICAL", "Boot security", "Driver signature checks are DISABLED (nointegritychecks)", "", "bcdedit /set nointegritychecks off, then restart.")
    if b.get("debug"):
        add("WARNING", "Boot security", "Kernel debugging is enabled", "", "bcdedit /debug off unless you are debugging.")
    if b.get("hvci") is False:
        add("INFO", "Boot security", "Memory Integrity (HVCI) is off", "It blocks malicious and vulnerable drivers.", "Windows Security > Device security > Core isolation.")
    if b.get("blocklist") == 0:
        add("INFO", "Boot security", "Microsoft's vulnerable driver blocklist is off", "", "Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist.")
    for u in _l(b.get("unsigned_drivers"))[:10]:
        add("WARNING", "Drivers", "Unsigned driver: %s (%s)" % (u.get("device"), u.get("driver")), "Unsigned drivers bypass Microsoft's checks.", "Update it from the device maker or remove the device.")

    order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    F.sort(key=lambda f: (order.get(f["severity"], 9), f["category"]))
    rows.sort(key=lambda r: ({"CRITICAL": 0, "WARNING": 1}.get(r["Verdict"], 2), r["Type"]))
    return {"findings": F, "entries": rows, "processes": prow, "certs": crows,
            "counts": {k: sum(1 for f in F if f["severity"] == k) for k in ("CRITICAL", "WARNING", "INFO")},
            "defender": d}


# ---------------------------------------------------------------------------------
#  Optional VirusTotal hash lookup (only SHA-256 hashes are sent)
# ---------------------------------------------------------------------------------
def vt_lookup(api_key, hashes, progress=None, delay=15.5):
    out = {}
    hashes = [h for h in dict.fromkeys(hashes) if h and len(h) == 64]
    for i, h in enumerate(hashes):
        if progress:
            progress("VirusTotal: checking %d of %d (free API allows 4 per minute)..." % (i + 1, len(hashes)))
        req = urllib.request.Request("https://www.virustotal.com/api/v3/files/%s" % h.lower(), headers={"x-apikey": api_key})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read().decode("utf-8"))
            st = data["data"]["attributes"].get("last_analysis_stats", {})
            names = data["data"]["attributes"].get("popular_threat_classification", {}).get("suggested_threat_label", "")
            out[h] = {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0), "harmless": st.get("harmless", 0),
                      "undetected": st.get("undetected", 0), "label": names, "link": "https://www.virustotal.com/gui/file/%s" % h.lower()}
        except urllib.error.HTTPError as e:
            out[h] = {"error": "not known to VirusTotal" if e.code == 404 else ("invalid API key" if e.code in (401, 403) else "HTTP %d" % e.code),
                      "link": "https://www.virustotal.com/gui/file/%s" % h.lower()}
            if e.code in (401, 403):
                break
        except Exception as e:
            out[h] = {"error": str(e)[:80]}
        if i < len(hashes) - 1:
            time.sleep(delay)
    return out
