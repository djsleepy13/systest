"""
Online update check + driver age report.
- Asks Windows Update (the same Microsoft service Settings uses, or the company's WSUS if configured)
  which updates are MISSING on this PC: software/security updates and driver updates (incl. optional).
- Lists installed third-party drivers with their date, matches them to driver updates offered by
  Windows Update, and flags old ones with a link to the maker's download page.
Read-only. Installing is done by Windows Update itself (repair "Install available Windows updates").
"""
import re
from datetime import datetime

SEARCH_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$R = [ordered]@{ ok = $false; error = ''; server = ''; updates = @(); reboot = $false; searched = (Get-Date).ToString('s'); drivers = @(); sysmaker = '' }
function U($u) {
    $o = [ordered]@{ title = $u.Title; kb = (@($u.KBArticleIDs) -join ','); type = [int]$u.Type; severity = "$($u.MsrcSeverity)"; optional = [bool]$u.BrowseOnly
                     downloaded = [bool]$u.IsDownloaded; size = [int64]$u.MaxDownloadSize; categories = @($u.Categories | ForEach-Object { "$($_.Name)" })
                     category_ids = @($u.Categories | ForEach-Object { "$($_.CategoryID)" })
                     date = $(try { $u.LastDeploymentChangeTime.ToString('s') } catch { '' }); url = "$(@($u.MoreInfoUrls)[0])" }
    if ($u.Type -eq 2) { $o.driver_class = "$($u.DriverClass)"; $o.driver_maker = "$($u.DriverManufacturer)"; $o.driver_model = "$($u.DriverModel)"
                         $o.driver_provider = "$($u.DriverProvider)"; $o.driver_date = $(try { $u.DriverVerDate.ToString('s') } catch { '' }); $o.hwid = "$($u.DriverHardwareID)" }
    $o
}
try {
    $s = New-Object -ComObject Microsoft.Update.Session
    $s.ClientApplicationID = 'WinDiag'
    $q = $s.CreateUpdateSearcher()
    $q.Online = $true
    $R.server = @('Default', 'Company server (WSUS)', 'Windows Update', 'Other')[[int]$q.ServerSelection]
    $wsus = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate').WUServer
    if ($wsus) { $R.server = "Company server (WSUS): $wsus" } else { $R.server = 'Microsoft Windows Update (online)' }
    $a = $q.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $b = $q.Search("IsInstalled=0 and IsHidden=0 and Type='Driver'")
    $R.updates = @(@($a.Updates) + @($b.Updates) | ForEach-Object { U $_ })
    $R.ok = $true
} catch { $R.error = "$($_.Exception.Message) (0x{0:X8})" -f ($_.Exception.HResult -band 0xFFFFFFFF) }
try { $R.reboot = (New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch {}
$R.sysmaker = "$((Get-CimInstance Win32_ComputerSystem).Manufacturer)"
$R.drivers = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -and $_.DriverVersion } | ForEach-Object {
    [ordered]@{ device = $_.DeviceName; class = "$($_.DeviceClass)"; maker = "$($_.Manufacturer)"; provider = "$($_.DriverProviderName)"; version = $_.DriverVersion
                date = $(if ($_.DriverDate) { $_.DriverDate.ToString('s') } else { '' }); inf = $_.InfName; hwid = "$($_.HardWareID)"; signed = $_.IsSigned } })
$R | ConvertTo-Json -Depth 5 -Compress
"""

# Used by Guided Fix "Check online for missing updates" (verify kind wu_pending).
# Defender definition updates (category "Definition Updates", arrive several times a day) never count as missing.
PENDING_VERIFY_PS = r"""
$ErrorActionPreference='SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
try {
    $q = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $q.Online = $true
    $u = @($q.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates | Where-Object {
        -not $_.BrowseOnly -and -not (@($_.Categories | ForEach-Object { "$($_.CategoryID)" }) -contains 'e0789628-ce08-4437-be74-2495b842f43b') -and
        "$($_.Title)" -notmatch 'Security Intelligence Update|Definition Update' })
    $st = if ($u.Count) { 'fail' } else { 'pass' }
    @{ status = $st; detail = $(if ($u.Count) { "$($u.Count) update(s) still missing - install them in Settings > Windows Update." } else { 'Windows Update reports no missing updates.' }); sample = @($u | Select-Object -First 8 | ForEach-Object { $_.Title }) } | ConvertTo-Json -Compress
} catch { @{ status = 'error'; detail = "Windows Update search failed: $($_.Exception.Message)" } | ConvertTo-Json -Compress }
"""

INSTALL_BODY = r"""$s = New-Object -ComObject Microsoft.Update.Session
$s.ClientApplicationID = 'WinDiag'
Write-Host 'Searching Windows Update...' -ForegroundColor Yellow
$q = $s.CreateUpdateSearcher(); $q.Online = $true
$res = $q.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$list = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $res.Updates) { if (-not $u.BrowseOnly) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$list.Add($u); Write-Host (' + ' + $u.Title) } }
if ($list.Count -eq 0) { Write-Host 'Nothing to install - this PC is up to date.' -ForegroundColor Green; $WDStatus = @{ exit = 0; installed = 0 } }
else {
    Write-Host ("Downloading {0} update(s)..." -f $list.Count) -ForegroundColor Yellow
    $d = $s.CreateUpdateDownloader(); $d.Updates = $list; [void]$d.Download()
    Write-Host 'Installing...' -ForegroundColor Yellow
    $i = $s.CreateUpdateInstaller(); $i.Updates = $list; $r = $i.Install()
    for ($k = 0; $k -lt $list.Count; $k++) { $rc = $r.GetUpdateResult($k).ResultCode; Write-Host ("{0}  {1}" -f @('?','?','OK','OK (errors)','FAILED','aborted')[$rc], $list.Item($k).Title) }
    if ($r.RebootRequired) { Write-Host 'RESTART the PC to finish installing.' -ForegroundColor Yellow }
    $WDStatus = @{ exit = $(if ($r.ResultCode -in 2, 3) { 0 } else { [int]$r.ResultCode }); reboot = $r.RebootRequired }
}"""

KEY_CLASSES = {"DISPLAY": "Graphics", "NET": "Network", "SCSIADAPTER": "Storage controller", "HDC": "Storage controller", "MEDIA": "Audio",
               "BLUETOOTH": "Bluetooth", "SYSTEM": "Chipset / system", "USB": "USB", "CAMERA": "Camera", "IMAGE": "Camera", "FIRMWARE": "Firmware (BIOS/UEFI)",
               "HIDCLASS": "Input", "BIOMETRIC": "Fingerprint / face", "SOFTWARECOMPONENT": "Software component", "EXTENSION": "Driver extension"}
IMPORTANT = {"DISPLAY", "NET", "SCSIADAPTER", "HDC", "FIRMWARE", "MEDIA", "BLUETOOTH", "SYSTEM"}

VENDOR_LINKS = [
    (r"nvidia", "NVIDIA drivers", "https://www.nvidia.com/Download/index.aspx"),
    (r"\bamd\b|advanced micro|\bati\b|radeon", "AMD drivers", "https://www.amd.com/en/support/download/drivers.html"),
    (r"intel", "Intel Driver & Support Assistant", "https://www.intel.com/content/www/us/en/support/detect.html"),
    (r"realtek", "Realtek (or your PC maker)", "https://www.realtek.com/"),
    (r"killer|rivet", "Intel Driver & Support Assistant", "https://www.intel.com/content/www/us/en/support/detect.html"),
    (r"samsung", "Samsung SSD tools & drivers", "https://semiconductor.samsung.com/consumer-storage/support/tools/"),
    (r"qualcomm|atheros", "Qualcomm / PC maker drivers", None),
    (r"mediatek", "MediaTek / PC maker drivers", None),
    (r"broadcom", "Broadcom / PC maker drivers", None),
]
PC_MAKERS = [
    (r"dell", "Dell SupportAssist / drivers", "https://www.dell.com/support/home"),
    (r"\bhp\b|hewlett", "HP drivers", "https://support.hp.com/drivers"),
    (r"lenovo", "Lenovo drivers", "https://pcsupport.lenovo.com/"),
    (r"asus", "ASUS download center", "https://www.asus.com/support/download-center/"),
    (r"acer", "Acer drivers", "https://www.acer.com/support"),
    (r"micro-star|msi", "MSI drivers", "https://www.msi.com/support/download"),
    (r"gigabyte", "GIGABYTE support", "https://www.gigabyte.com/Support"),
    (r"microsoft", "Surface drivers & firmware", "https://support.microsoft.com/surface/download-drivers-and-firmware-for-surface"),
    (r"asrock", "ASRock support", "https://www.asrock.com/support/index.asp"),
]


DEFINITION_CAT = "e0789628-ce08-4437-be74-2495b842f43b"   # Windows Update category "Definition Updates"


def _l(x):
    if isinstance(x, dict) and isinstance(x.get("value"), list):     # PS 5.1 System.Array wrapper
        x = x["value"]
    return x if isinstance(x, list) else ([] if x is None or x == "" else [x])


def _s(x):
    """Plain string from a PS value (PS 5.1 can serialise a string as {value: ..., PSPath: ...})."""
    if isinstance(x, dict):
        x = x.get("value")
    return "" if x is None or isinstance(x, (dict, list)) else str(x)


def _date(s):
    """Driver date or None. Dates before 2000 are placeholders (Intel's chipset INFs are dated 1968 on purpose) = unknown."""
    try:
        d = datetime.strptime(_s(s)[:10], "%Y-%m-%d")
    except ValueError:
        return None
    return d if d.year >= 2000 else None


def is_definition(u):
    """Defender 'Security Intelligence' / definition updates: installed automatically several times a day, never 'missing'."""
    cats = " ".join(_s(c) for c in _l(u.get("categories")))
    ids = [_s(c).lower() for c in _l(u.get("category_ids"))]
    return (DEFINITION_CAT in ids or bool(re.search(r"(?i)definition", cats))
            or bool(re.search(r"(?i)security intelligence update|definition update", _s(u.get("title")))))


def vendor_link(driver, sysmaker=""):
    txt = "%s %s %s" % (_s(driver.get("maker")), _s(driver.get("provider")), _s(driver.get("device")))
    for rx, name, url in VENDOR_LINKS:
        if re.search(rx, txt, re.I) and url:
            return name, url
    for rx, name, url in PC_MAKERS:
        if re.search(rx, _s(sysmaker), re.I):
            return name, url
    return "Search online", "https://www.bing.com/search?q=%s" % ("%s driver download" % driver.get("device")).replace(" ", "+")


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", _s(s).lower())


def analyze(raw, now=None):
    """Return dict: ok, error, server, updates (software), driver_updates, drivers (report rows), counts, findings."""
    now = now or datetime.now()
    raw = raw if isinstance(raw, dict) else {}
    ups = [u for u in _l(raw.get("updates")) if isinstance(u, dict)]

    def _type(u):
        try:
            return int(_s(u.get("type")) or 1)
        except ValueError:
            return 1
    sw = [u for u in ups if _type(u) != 2]
    dr = [u for u in ups if _type(u) == 2]
    for u in sw:
        cats = " ".join(_s(c) for c in _l(u.get("categories")))
        title = _s(u.get("title"))
        u["kind"] = ("Definition" if is_definition(u) else
                     "Security" if re.search(r"(?i)security", cats + " " + title) or _s(u.get("severity")) else
                     "Feature" if re.search(r"(?i)upgrade|feature update", cats + " " + title) else
                     "Driver" if re.search(r"(?i)driver", cats) else "Update")
    installed = [d for d in _l(raw.get("drivers")) if isinstance(d, dict)]
    sysmaker = _s(raw.get("sysmaker"))
    rows = []
    for d in installed:
        cls = _s(d.get("class")).upper()
        prov = _s(d.get("provider"))
        if cls not in KEY_CLASSES:
            continue
        inbox = prov.lower().startswith("microsoft") and cls not in ("FIRMWARE",)
        dt = _date(d.get("date"))
        age = (now - dt).days / 365.25 if dt else None
        match = None
        hw = _s(d.get("hwid")).lower()
        for u in dr:
            uh = _s(u.get("hwid")).lower()
            if (uh and hw and (uh == hw or uh in hw or hw in uh)) or (u.get("driver_model") and _norm(u["driver_model"]) and _norm(u["driver_model"]) in _norm(d.get("device"))):
                match = u
                break
        if match:
            status, sev = "Update on Windows Update%s" % (" (optional)" if match.get("optional") else ""), "WARNING"
        elif inbox:
            status, sev = "Windows built-in driver", "OK"
        elif age is not None and age >= (3 if cls in IMPORTANT else 5):
            status, sev = "Old (%.0f years) - check the maker" % age, "INFO" if cls not in IMPORTANT else "WARNING"
        else:
            status, sev = "OK", "OK"
        name, url = vendor_link(d, sysmaker)
        rows.append({"Status": status, "Device": _s(d.get("device")), "Type": KEY_CLASSES.get(cls, cls.title()), "Version": _s(d.get("version")),
                     "Date": dt.strftime("%Y-%m-%d") if dt else "unknown", "Age": ("%.1f y" % age) if age is not None else "?", "Provider": prov,
                     "_sev": sev, "_link": url, "_linkname": name, "_update": match, "_class": cls})
    order = {"WARNING": 0, "INFO": 1, "OK": 2}
    rows.sort(key=lambda r: (order.get(r["_sev"], 3), 0 if r["_update"] else 1, r["Type"], r["Device"] or ""))
    important = [u for u in sw if not u.get("optional") and u["kind"] != "Definition"]
    sec = [u for u in important if u["kind"] == "Security"]
    F = []
    if not raw.get("ok"):
        F.append({"Status": "WARNING", "Area": "Updates", "Finding": "Could not check Windows Update online", "Advice": _s(raw.get("error")) or "No internet / service disabled."})
    else:
        if important:
            F.append({"Status": "CRITICAL" if sec else "WARNING", "Area": "Updates",
                      "Finding": "%d Windows update(s) missing%s" % (len(important), (" (%d security)" % len(sec)) if sec else ""),
                      "Advice": "Install them: Updates & Drivers page > Install updates (or Settings > Windows Update)."})
        else:
            F.append({"Status": "OK", "Area": "Updates", "Finding": "Windows Update: no missing updates (checked online)", "Advice": ""})
        if dr:
            F.append({"Status": "INFO", "Area": "Updates", "Finding": "%d driver update(s) offered by Windows Update" % len(dr),
                      "Advice": "Settings > Windows Update > Advanced options > Optional updates."})
    if raw.get("reboot"):
        F.append({"Status": "WARNING", "Area": "Updates", "Finding": "A restart is needed to finish installing updates", "Advice": "Restart the PC."})
    old = [r for r in rows if r["_sev"] == "WARNING" and r["Status"].startswith("Old")]
    if old:
        F.append({"Status": "INFO", "Area": "Updates", "Finding": "%d important driver(s) are 3+ years old (%s)" % (len(old), ", ".join(r["Device"] for r in old[:3])),
                  "Advice": "Old is not always bad - but graphics, network and storage drivers are worth updating from the maker."})
    return {"ok": raw.get("ok"), "error": raw.get("error"), "server": raw.get("server"), "searched": raw.get("searched"), "reboot": raw.get("reboot"),
            "updates": sw, "driver_updates": dr, "drivers": rows, "findings": F,
            "counts": {"missing": len(important), "security": len(sec), "definitions": len([u for u in sw if u["kind"] == "Definition"]),
                       "optional": len([u for u in sw if u.get("optional") and u["kind"] != "Definition"]), "drivers": len(dr), "old": len(old)}}


# ---------------------------------------------------------------------------------
#  Online search, shared by the scan and the page button (only one search at a time)
# ---------------------------------------------------------------------------------
import threading as _threading
_fetch_lock = _threading.Lock()
_inflight = {"ev": None, "res": None}


def fetch():
    """Worker-thread safe; never raises. Returns analyze() output. A second caller waits for the running search."""
    import core
    with _fetch_lock:
        ev = _inflight["ev"]
        owner = ev is None
        if owner:
            ev = _inflight["ev"] = _threading.Event()
    if not owner:
        ev.wait()
        return _inflight["res"]
    res = None
    try:
        raw = core.run_ps_json(SEARCH_PS, 600, "Windows Update search")
        if raw.get("status") == "error" and "updates" not in raw:
            raw = {"ok": False, "error": raw.get("detail")}
        res = analyze(raw)
    except Exception as e:
        core.log_error("updates fetch", e)
        try:
            res = analyze({"ok": False, "error": core.friendly_error(e)})
        except Exception:
            res = {"ok": False, "error": core.friendly_error(e), "findings": [],
                   "counts": {"missing": 0, "security": 0, "definitions": 0, "optional": 0, "drivers": 0}}
    finally:
        with _fetch_lock:
            _inflight["res"] = res
            _inflight["ev"] = None
        ev.set()
    return res
