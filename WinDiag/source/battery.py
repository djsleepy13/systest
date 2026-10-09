"""Battery health: WMI (root\\wmi Battery*), Win32_Battery and powercfg /batteryreport /xml (capacity history)."""
import ctypes
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime

BATTERY_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$R = [ordered]@{ present = $false }
$wb = @(Get-CimInstance Win32_Battery)
if ($wb.Count) {
    $R.present = $true
    $R.win32 = @($wb | ForEach-Object { [ordered]@{ name = $_.Name; charge = $_.EstimatedChargeRemaining; runtime = $_.EstimatedRunTime; status = $_.BatteryStatus; chemistry = $_.Chemistry; id = $_.DeviceID } })
    $R.static = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData | ForEach-Object { [ordered]@{ design = $_.DesignedCapacity; maker = "$($_.ManufactureName)".Trim(); serial = "$($_.SerialNumber)".Trim(); chem = $_.Chemistry; name = "$($_.DeviceName)".Trim(); date = $_.ManufactureDate } })
    $R.full = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity | ForEach-Object { $_.FullChargedCapacity })
    $R.cycles = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryCycleCount | ForEach-Object { $_.CycleCount })
    $R.status = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStatus | ForEach-Object { [ordered]@{ remaining = $_.RemainingCapacity; charge_rate = $_.ChargeRate; discharge_rate = $_.DischargeRate; voltage = $_.Voltage; online = $_.PowerOnline; charging = $_.Charging; discharging = $_.Discharging; critical = $_.Critical } })
    $x = Join-Path $env:TEMP ('windiag_battery_{0}.xml' -f (Get-Random))
    powercfg /batteryreport /xml /output "$x" | Out-Null
    if (Test-Path $x) { $R.xml = [IO.File]::ReadAllText($x); Remove-Item $x -Force }   # plain string (Get-Content adds PSPath etc. in PS 5.1 JSON)
}
$R.modern_standby = [bool]((powercfg /a) -join ' ' -match 'S0 Low Power Idle')
$R.maker = "$((Get-CimInstance Win32_ComputerSystem).Manufacturer)"
$R | ConvertTo-Json -Depth 5 -Compress
"""

LIVE_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$s = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStatus)
@{ status = @($s | ForEach-Object { @{ remaining = $_.RemainingCapacity; charge_rate = $_.ChargeRate; discharge_rate = $_.DischargeRate; online = $_.PowerOnline; charging = $_.Charging } }) } | ConvertTo-Json -Depth 3 -Compress
"""

CHEM = {1: "Other", 2: "Unknown", 3: "Lead acid", 4: "Nickel cadmium", 5: "Nickel metal hydride", 6: "Lithium-ion", 7: "Zinc air", 8: "Lithium polymer"}
CHARGE_LIMIT = [
    (r"lenovo", "Lenovo Vantage > Device > Power > Battery charge threshold / Conservation mode"),
    (r"dell", "Dell Power Manager (or BIOS) > Battery settings > Primarily AC use / Custom charge"),
    (r"\bhp\b|hewlett", "HP BIOS > Advanced > Power management > Battery health manager / Adaptive battery optimizer"),
    (r"asus", "MyASUS > Customization > Battery health charging (60% / 80%)"),
    (r"microsoft", "Surface: UEFI 'Enable Battery Limit' mode or Smart Charging in the Surface app"),
    (r"acer", "Acer Care Center > Battery charge limit (80%)"),
    (r"samsung", "Samsung Settings > Battery life extender"),
    (r"msi", "MSI Center > Battery master (Best for battery)"),
    (r"razer", "Razer Synapse > Battery health optimizer"),
]


_ETS_KEYS = {"PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSIsContainer", "ReadCount", "Count", "Length"}
UNKNOWN_RATE = 500000       # mW. BATTERY_UNKNOWN_RATE (0x80000000 -> -2147483648 as sint32) and other garbage are above this


def ps_clean(o):
    """Undo Windows PowerShell 5.1 ConvertTo-Json quirks: {"value": x, "PSPath": ...} -> x, None list entries dropped."""
    if isinstance(o, dict):
        if "value" in o and len(o) > 1 and set(o) - {"value"} <= _ETS_KEYS:
            return ps_clean(o["value"])
        return {k: ps_clean(v) for k, v in o.items()}
    if isinstance(o, list):
        return [ps_clean(v) for v in o if v is not None]
    return o


def _l(x):
    return x if isinstance(x, list) else ([] if x is None else [x])


def _dl(x):
    """List of dicts; anything else in the list becomes {} so indexes still line up."""
    return [v if isinstance(v, dict) else {} for v in _l(x)] if not isinstance(x, str) else []


def _str(v):
    return v.strip() if isinstance(v, str) else ("" if v is None or isinstance(v, (dict, list, bool)) else str(v))


def _rate(v):
    """Charge/discharge rate in mW, or None when unknown / implausible."""
    n = _num(v)
    return None if n is None or abs(n) >= UNKNOWN_RATE else n


def watts_of(st):
    """BatteryStatus dict -> watts (negative = discharging) or None."""
    if not isinstance(st, dict):
        return None
    dr, cr = _rate(st.get("discharge_rate")), _rate(st.get("charge_rate"))
    if dr:
        return -abs(dr) / 1000.0
    if cr:
        return abs(cr) / 1000.0
    return None


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _num(v):
    if isinstance(v, bool):
        return None
    try:
        return int(float(v))
    except (TypeError, ValueError, OverflowError):
        return None


def _dur(v):
    """ISO-8601 duration (PT1H23M4S) -> minutes."""
    m = re.match(r"P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?", v or "")
    if not m or not any(m.groups()):
        return None
    d, h, mi, se = (float(x) if x else 0 for x in m.groups())
    return int(d * 1440 + h * 60 + mi + se / 60)


def parse_report(xml_text):
    """Returns dict(batteries=[...], history=[(date, full, design)], runtime={'full': min, 'design': min})."""
    out = {"batteries": [], "history": [], "runtime": {}}
    if isinstance(xml_text, dict):          # Windows PowerShell 5.1: string with PSPath/ReadCount note properties
        xml_text = xml_text.get("value")
    if not isinstance(xml_text, (str, bytes)) or not xml_text:
        return out
    try:
        root = ET.fromstring(xml_text.encode("utf-8") if isinstance(xml_text, str) else xml_text)
    except (ET.ParseError, ValueError, TypeError):
        return out
    for el in root.iter():
        name = _local(el.tag)
        kids = {_local(c.tag): (c.text or "").strip() for c in el}
        if name == "Battery" and ("DesignCapacity" in kids or "FullChargeCapacity" in kids):
            out["batteries"].append({"id": kids.get("Id") or kids.get("id"), "maker": kids.get("Manufacturer"), "serial": kids.get("SerialNumber"),
                                     "date": kids.get("ManufactureDate"), "chemistry": kids.get("Chemistry"), "design": _num(kids.get("DesignCapacity")),
                                     "full": _num(kids.get("FullChargeCapacity")), "cycles": _num(kids.get("CycleCount"))})
        attrs = dict(el.attrib)
        vals = dict(kids)
        vals.update(attrs)
        if name != "Battery" and "FullChargeCapacity" in vals and "DesignCapacity" in vals:
            date = vals.get("LocalStartDate") or vals.get("StartDate") or vals.get("LocalEndDate") or vals.get("EndDate") or vals.get("Date")
            if date:
                try:
                    dt = datetime.strptime(date[:10], "%Y-%m-%d")
                except ValueError:
                    continue
                f, d = _num(vals.get("FullChargeCapacity")), _num(vals.get("DesignCapacity"))
                if f and d:
                    out["history"].append((dt, f, d))
        if name == "RuntimeEstimates":
            for c in el:
                act = next((x for x in c.iter() if _local(x.tag) == "ActiveRuntime"), None)
                if act is not None and act.text:
                    out["runtime"][_local(c.tag)] = _dur(act.text)
    out["history"].sort(key=lambda x: x[0])
    return out


def assess(raw):
    """Returns dict with present, batteries (list of per-battery dicts), status, findings, history, runtime, tips."""
    if isinstance(raw, dict) and isinstance(raw.get("xml"), dict):
        raw = dict(raw, xml=raw["xml"].get("value"))
    raw = ps_clean(raw) if isinstance(raw, dict) else {}
    if raw.get("present") is not True and str(raw.get("present")).lower() != "true":
        return {"present": False}
    rep = parse_report(raw.get("xml"))
    static, status, w32 = _dl(raw.get("static")), _dl(raw.get("status")), _dl(raw.get("win32"))
    full, cycles = [_num(x) for x in _l(raw.get("full"))], [_num(x) for x in _l(raw.get("cycles"))]
    bats = []
    n = max(len(static), len(full), len(rep["batteries"]), len(w32), 1)
    for i in range(n):
        s = static[i] if i < len(static) else {}
        r = rep["batteries"][i] if i < len(rep["batteries"]) else {}
        design = r.get("design") or _num(s.get("design"))
        fc = r.get("full") or (full[i] if i < len(full) else None)
        cyc = r.get("cycles") if r.get("cycles") else (cycles[i] if i < len(cycles) and cycles[i] else None)
        st = status[i] if i < len(status) else {}
        w = w32[i] if i < len(w32) else {}
        health = round(fc * 100.0 / design, 1) if design and design > 0 and fc and fc > 0 else None
        runtime = _num(w.get("runtime"))
        charge = _num(w.get("charge"))
        bats.append({"name": _str(s.get("name")) or _str(w.get("name")) or "Battery %d" % (i + 1), "maker": r.get("maker") or _str(s.get("maker")),
                     "serial": r.get("serial") or _str(s.get("serial")), "chemistry": r.get("chemistry") or CHEM.get(_num(s.get("chem")) or _num(w.get("chemistry")), ""),
                     "made": r.get("date"), "design": design, "full": fc, "health": health, "cycles": cyc,
                     "charge": charge if charge is not None and 0 <= charge <= 100 else None,
                     "remaining": _num(st.get("remaining")), "watts": watts_of(st), "online": st.get("online") is True, "charging": st.get("charging") is True,
                     "voltage": _num(st.get("voltage")), "runtime_min": runtime if runtime and 0 < runtime < 71582788 else None})
    F = []
    for b in bats:
        h = b["health"]
        if h is None:
            F.append({"Status": "INFO", "Area": "Battery", "Finding": "%s: capacity not reported" % b["name"], "Advice": "Some batteries/firmware don't report capacity to Windows."})
        elif h < 50:
            F.append({"Status": "CRITICAL", "Area": "Battery", "Finding": "Battery health %.0f%% - needs replacing" % h,
                      "Advice": "It holds less than half its original charge; sudden shutdowns are likely. Replace the battery."})
        elif h < 80:
            F.append({"Status": "WARNING", "Area": "Battery", "Finding": "Battery health %.0f%% - worn" % h,
                      "Advice": "Most makers consider under 80% worn (often the warranty threshold). Plan a replacement."})
        else:
            F.append({"Status": "OK", "Area": "Battery", "Finding": "Battery health %.0f%%" % h, "Advice": ""})
        if h and h > 105:
            F.append({"Status": "INFO", "Area": "Battery", "Finding": "Reported capacity is above design (%.0f%%)" % h,
                      "Advice": "The battery gauge needs calibrating: run it down to ~5%, then charge to 100% without interruption."})
    hist = rep["history"]
    wear = wear_per_year(hist)
    tips = ["Keep it between about 20% and 80% day to day; avoid leaving it at 100% on the charger for weeks.",
            "Heat wears batteries fastest - don't game on a soft surface or leave the laptop in a hot car.",
            "If the % jumps around or it shuts down early, recalibrate: run down to ~5%, then charge to 100% in one go.",
            "Replace when health is under ~60% or it shuts down unexpectedly. Use the maker's part number (see the battery's name/serial)."]
    maker = _str(raw.get("maker"))
    for rx, t in CHARGE_LIMIT:
        if re.search(rx, maker, re.I):
            tips.insert(1, "Charge limit on this PC: " + t)
            break
    return {"present": True, "batteries": bats, "findings": F, "history": hist, "runtime": rep["runtime"], "wear_per_year": wear, "tips": tips,
            "modern_standby": raw.get("modern_standby") is True}


def wear_per_year(hist):
    """% of design capacity lost per year, from the battery report history [(date, full, design)].
    Only the history after the last battery replacement / recalibration counts: a big upward capacity jump
    (> 10% of design) or a changed design capacity starts a new segment. Never negative."""
    if len(hist) < 2:
        return None
    start = 0
    for k in range(1, len(hist)):
        (_, fa, da), (_, fb, db) = hist[k - 1], hist[k]
        if da != db or fb - fa > 0.10 * max(da, db, 1):
            start = k
    seg = hist[start:]
    if len(seg) < 2:
        return None
    (d0, f0, _), (d1, f1, ds1) = seg[0], seg[-1]
    days = (d1 - d0).days
    if days < 30 or not ds1:
        return None
    return max(0.0, round((f0 - f1) * 100.0 / ds1 / (days / 365.0), 1))


def live_status():
    """Instant: (ac_online, percent, seconds_left) via GetSystemPowerStatus. None on non-Windows."""
    if os.name != "nt":
        return None

    class SPS(ctypes.Structure):
        _fields_ = [("ac", ctypes.c_ubyte), ("flag", ctypes.c_ubyte), ("pct", ctypes.c_ubyte), ("saver", ctypes.c_ubyte),
                    ("life", ctypes.c_ulong), ("full", ctypes.c_ulong)]
    s = SPS()
    if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(s)):
        return None
    return (s.ac == 1, None if s.pct == 255 else s.pct, None if s.life in (0xFFFFFFFF,) else s.life, s.flag)
