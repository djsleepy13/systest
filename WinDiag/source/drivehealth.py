"""
WinDiag Drive Health
--------------------
Health data  - read straight from the drive with Windows' own interfaces (no extra tools):
               NVMe SMART/Health log (IOCTL_STORAGE_QUERY_PROPERTY, log page 02h),
               ATA SMART attributes + thresholds (root\\wmi MSStorageDriver_FailurePredict*),
               Get-PhysicalDisk / Get-StorageReliabilityCounter.
               smartctl (smartmontools) is used as well when it is present - it adds the
               drive's own self-tests.
Verdict      - GOOD / CAUTION / CRITICAL + health %. Tests are offered for GOOD / no-data drives and for
               SSDs whose only issue is normal wear.
Tests        - ALL READ-ONLY: drive self-test (smartctl), quick read test, full surface scan.
               The disk is opened with GENERIC_READ only - Windows rejects writes on that handle.
Drive map    - which parts of the disk are partitioned / used / free (FSCTL_GET_VOLUME_BITMAP),
               overlaid with read-test results.
Wipe         - diskpart 'clean all' (writes zeros to every sector). Refused on the Windows disk
               and on the disk WinDiag runs from.
"""
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time

CELLS = 1200            # drive map: 60 x 20
GOOD_MIN = 70           # legacy: health % below this used to block tests (wear thresholds decide now)

# ---------------------------------------------------------------------------------
#  PowerShell collector
# ---------------------------------------------------------------------------------
NVME_CS = r"""
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class WDNvme {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inBuf, int inLen, byte[] outBuf, int outLen, out int ret, IntPtr ov);
    static string Query(int disk, uint access) {
        using (SafeFileHandle h = CreateFile("\\\\.\\PhysicalDrive" + disk, access, 3, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (h.IsInvalid) return "ERR:open:" + Marshal.GetLastWin32Error();
            byte[] b = new byte[8 + 40 + 512];
            BitConverter.GetBytes(50).CopyTo(b, 0);   // StorageDeviceProtocolSpecificProperty
            BitConverter.GetBytes(0).CopyTo(b, 4);    // PropertyStandardQuery
            BitConverter.GetBytes(3).CopyTo(b, 8);    // ProtocolTypeNvme
            BitConverter.GetBytes(2).CopyTo(b, 12);   // NVMeDataTypeLogPage
            BitConverter.GetBytes(2).CopyTo(b, 16);   // log page 02h = SMART / Health Information
            BitConverter.GetBytes(40).CopyTo(b, 24);  // ProtocolDataOffset
            BitConverter.GetBytes(512).CopyTo(b, 28); // ProtocolDataLength
            int ret;
            if (!DeviceIoControl(h, 0x2D1400, b, b.Length, b, b.Length, out ret, IntPtr.Zero)) return "ERR:ioctl:" + Marshal.GetLastWin32Error();
            int off = BitConverter.ToInt32(b, 8 + 16);
            int len = BitConverter.ToInt32(b, 8 + 20);
            // Return the WHOLE reply plus the offset the driver claims: some storage drivers (vendor / RAID / RST)
            // put the log at a different place, so WinDiag locates and validates it in Python instead of trusting it.
            int n = Math.Min(b.Length, Math.Max(0, ret));
            if (n < 512) n = b.Length;
            return "OFF:" + (8 + off) + ":" + len + ":" + BitConverter.ToString(b, 0, n).Replace("-", "");
        }
    }
    // Read-only query. Some drivers insist on a read/write handle for this IOCTL - nothing is written either way.
    public static string HealthLog(int disk) {
        string r = Query(disk, 0x80000000);
        if (r.StartsWith("ERR:ioctl:5") || r.StartsWith("ERR:open:5")) r = Query(disk, 0xC0000000);
        return r;
    }
}
"""

DRIVES_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$nvmeOk = $true
try { Add-Type -TypeDefinition @'
""" + NVME_CS + r"""
'@ -ErrorAction Stop } catch { $nvmeOk = $false }
$wmiData = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictData)
$wmiThr  = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictThresholds)
$wmiSt   = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus)
$dd = @{}; foreach ($d in Get-CimInstance Win32_DiskDrive) { $dd[[int]$d.Index] = $d }
function Hex($bytes) { if ($bytes) { ([BitConverter]::ToString([byte[]]$bytes)) -replace '-', '' } else { '' } }
$out = @()
foreach ($pd in Get-PhysicalDisk) {
    $n = [int]$pd.DeviceId
    $disk = Get-Disk -Number $n
    $r = $pd | Get-StorageReliabilityCounter
    $w = $dd[$n]
    $pnp = "$($w.PNPDeviceID)".ToUpper()
    $ata = $null
    if ($pnp) {
        $m = $wmiData | Where-Object { "$($_.InstanceName)".ToUpper().StartsWith($pnp) } | Select-Object -First 1
        if ($m) {
            $t = $wmiThr | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
            $s = $wmiSt | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
            $ata = [ordered]@{ data = (Hex $m.VendorSpecific); thresholds = (Hex $t.VendorSpecific); predict_failure = [bool]$s.PredictFailure }
        }
    }
    $nv = ''
    if ("$($pd.BusType)" -eq 'NVMe' -and $nvmeOk) { $nv = [WDNvme]::HealthLog($n) }
    $parts = @(Get-Partition -DiskNumber $n | ForEach-Object {
        $v = $_ | Get-Volume
        [ordered]@{ number = $_.PartitionNumber; offset = [int64]$_.Offset; size = [int64]$_.Size; letter = "$($_.DriveLetter)".Trim([char]0).Trim()
                    type = "$($_.Type)"; gpt = "$($_.GptType)"; access = @($_.AccessPaths | Where-Object { $_ -like '\\?\Volume*' }) | Select-Object -First 1
                    fs = "$($v.FileSystem)"; label = "$($v.FileSystemLabel)"; vsize = [int64]$v.Size; free = [int64]$v.SizeRemaining }
    })
    $out += [ordered]@{
        number = $n; model = "$($pd.FriendlyName)".Trim(); serial = "$($pd.SerialNumber)".Trim(); firmware = "$($pd.FirmwareVersion)"
        bus = "$($pd.BusType)"; media = "$($pd.MediaType)"; spindle = $pd.SpindleSpeed; size = [int64]$pd.Size
        lsector = $pd.LogicalSectorSize; psector = $pd.PhysicalSectorSize; health = "$($pd.HealthStatus)"; opstatus = "$($pd.OperationalStatus)"
        is_boot = [bool]$disk.IsBoot; is_system = [bool]$disk.IsSystem; offline = [bool]$disk.IsOffline; style = "$($disk.PartitionStyle)"
        pnp = $pnp; iface = "$($w.InterfaceType)"
        rel = [ordered]@{ temp = $r.Temperature; temp_max = $r.TemperatureMax; wear = $r.Wear; hours = $r.PowerOnHours; starts = $r.StartStopCycleCount
                          read_unc = $r.ReadErrorsUncorrected; write_unc = $r.WriteErrorsUncorrected; read_corr = $r.ReadErrorsCorrected; latency_max = $r.ReadLatencyMax }
        ata = $ata; nvme = $nv; partitions = $parts
    }
}
@{ drives = $out; nvme_helper = $nvmeOk } | ConvertTo-Json -Depth 6 -Compress
"""

# ---------------------------------------------------------------------------------
#  Parsers
# ---------------------------------------------------------------------------------
ATA_NAMES = {1: "Raw read error rate", 3: "Spin-up time", 4: "Start/stop count", 5: "Reallocated sectors", 7: "Seek error rate",
             9: "Power-on hours", 10: "Spin retry count", 12: "Power cycles", 169: "Remaining life", 170: "Reserved blocks",
             171: "Program fail count", 172: "Erase fail count", 173: "Wear leveling (avg erase)", 174: "Unexpected power loss",
             177: "Wear leveling count", 179: "Used reserved blocks", 180: "Unused reserved blocks", 181: "Program fail count",
             182: "Erase fail count", 183: "Runtime bad blocks", 184: "End-to-end errors", 187: "Reported uncorrectable errors",
             188: "Command timeouts", 189: "High fly writes", 190: "Airflow temperature", 191: "G-sense errors", 192: "Power-off retracts",
             193: "Load cycles", 194: "Temperature", 195: "Hardware ECC recovered", 196: "Reallocation events", 197: "Pending sectors",
             198: "Offline uncorrectable", 199: "Interface CRC errors (cable)", 200: "Write error rate", 202: "Percent life remaining",
             230: "Media wearout (WD/SanDisk)", 231: "SSD life left", 232: "Available reserved space", 233: "Media wearout indicator",
             234: "Average erase count", 235: "Good block count", 241: "Total LBAs written", 242: "Total LBAs read", 246: "Total host sector writes"}
LIFE_ATTRS = (231, 202, 233, 169, 177, 230)   # normalised value = % life left on most SSDs
SSD_ONLY_ATTRS = (169, 173, 177, 202, 231, 233)   # only SSDs report these (used when Windows says media "Unspecified")
# Crucial/Micron RealSSD C300/C400/m4/P300 (smartmontools drivedb): 181 = Non4k_Aligned_Access, not program failures
RX_NON4K_181 = re.compile(r"(?i)(\bm4-ct|\bct\d+m4|\bc[34]00\b|\bc[34]00-|\bmtfdda[ac]\d|\bmtfddak\d+ma[mn]|realssd|\bp300\b|crucial[_ ]m4|\bm4\b)")
RX_MX500 = re.compile(r"(?i)mx500")
# Units of attribute 241/242 (Total LBAs written/read) differ by controller.
UNITS_241 = [
    (re.compile(r"(?i)\bintel\b|^ssdsc|\bssdsa"), 32 << 20, "32 MiB units"),
    (re.compile(r"(?i)kingston|\bsa400|\ba400\b|\bsuv\d|\buv[345]00|\bskc|\bkc[46]00|phison|patriot|pny|\bcs900|\bcs1311|silicon power|sandisk|"
                r"crucial bx|\bct\d+bx|\bbx500|teamgroup|team group|gigabyte gp-|adata su\d|\bsu[678]\d0"), 1 << 30, "GiB units"),
    (re.compile(r"(?i)samsung|\bmz7|crucial|\bct\d+mx|\bmx[1-5]00|micron|wdc wds|wd (blue|green|red)|western digital"),
     512, "512-byte LBAs"),
]


def _units_241(model):
    for rx, mult, name in UNITS_241:
        if rx.search(model or ""):
            return mult, name
    return None, None


def _hex(s):
    try:
        return bytes.fromhex(s or "")
    except ValueError:
        return b""


def _u(b, off, n):
    return int.from_bytes(b[off:off + n], "little")


# ---- Windows PowerShell 5.1 ConvertTo-Json quirks: strings/arrays with ETS note properties become
#      {"value": ..., "PSPath": ...} / {"value": [...], "Count": n}; single-element arrays collapse; $null entries.
_ETS_KEYS = {"PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSIsContainer", "ReadCount", "Count", "Length"}


def ps_clean(o):
    """Undo PS 5.1 JSON quirks recursively (ETS-wrapped values -> plain value, None list entries dropped)."""
    if isinstance(o, dict):
        if "value" in o and len(o) > 1 and set(o) - {"value"} <= _ETS_KEYS:
            return ps_clean(o["value"])
        return {k: ps_clean(v) for k, v in o.items()}
    if isinstance(o, list):
        return [ps_clean(v) for v in o if v is not None]
    return o


def _s(v):
    """Always a str (None / lists / dicts -> '')."""
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return str(v)
    return ""


def _i(v):
    """int or None (accepts '123', 12.5; rejects lists/dicts/bools/NaN)."""
    if isinstance(v, bool) or v is None:
        return None
    try:
        return int(float(v)) if isinstance(v, (str, float)) else int(v)
    except (TypeError, ValueError, OverflowError):
        return None


def _dl(v):
    """List of dicts (a single dict = one-element list)."""
    if isinstance(v, dict):
        v = [v]
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _dd(v):
    """A dict (a one-element list holding a dict is unwrapped)."""
    if isinstance(v, list) and v and isinstance(v[0], dict):
        v = v[0]
    return v if isinstance(v, dict) else {}


def _nvme_plausible(b):
    """True if 512 bytes look like a real NVMe SMART/Health log.
    Byte 6 is the Endurance Group Critical Warning Summary (NVMe 1.4+), bytes 7-31 are reserved = 0."""
    if len(b) < 512 or any(b[7:32]):
        return False
    k = _u(b, 1, 2)
    if k and not 200 <= k <= 420:
        return False
    if b[3] > 100 or b[4] > 100 or b[0] & 0xC0:
        return False
    if _u(b, 128, 16) > 2000000 or _u(b, 160, 16) > 1 << 40 or _u(b, 176, 16) > 1 << 48:
        return False
    if _u(b, 32, 16) * 512000 > 10 ** 18 or _u(b, 48, 16) * 512000 > 10 ** 18 or _u(b, 112, 16) > 1 << 32:
        return False
    return True


def locate_nvme_log(text):
    """text = what DRIVES_PS returned: 'OFF:<offset>:<len>:<hex of whole reply>' (3.2+) or plain log hex (older).
    Returns (512-byte log or None, note)."""
    text = _s(text)
    if not text or text.startswith("ERR"):
        return None, text or ""
    if text.startswith("OFF:"):
        parts = text.split(":", 3)
        if len(parts) < 4:
            return None, "The storage driver returned incomplete health data - ignored."
        buf, hint = _hex(parts[3]), _i(parts[1])
        if hint is None or hint < 0:
            hint = 0
    else:
        buf, hint = _hex(text), 0
    tried = [hint] + [o for o in range(0, max(0, len(buf) - 511), 4) if o != hint]
    for o in tried:
        chunk = buf[o:o + 512]
        if _nvme_plausible(chunk):
            return chunk, ("" if o == hint else "health log found at offset %d (driver said %d)" % (o, hint))
    return None, "The storage driver returned health data WinDiag couldn't validate - ignored (Windows' own counters used instead)."


def parse_nvme_log(b):
    """NVMe SMART / Health Information log (page 02h), NVMe base spec layout."""
    if len(b) < 200:
        return None
    k = _u(b, 1, 2)
    sensors = [_u(b, 200 + 2 * i, 2) - 273 for i in range(8) if _u(b, 200 + 2 * i, 2)]
    return {"critical_warning": b[0], "temperature": (k - 273) if k else None, "available_spare": b[3], "available_spare_threshold": b[4],
            "percentage_used": b[5], "data_units_read": _u(b, 32, 16), "data_units_written": _u(b, 48, 16), "host_reads": _u(b, 64, 16),
            "host_writes": _u(b, 80, 16), "controller_busy_time": _u(b, 96, 16), "power_cycles": _u(b, 112, 16), "power_on_hours": _u(b, 128, 16),
            "unsafe_shutdowns": _u(b, 144, 16), "media_errors": _u(b, 160, 16), "num_err_log_entries": _u(b, 176, 16),
            "warning_temp_time": _u(b, 192, 4), "critical_comp_time": _u(b, 196, 4), "temperature_sensors": sensors}


def parse_ata_smart(data, thr=b""):
    """VendorSpecific blob from MSStorageDriver_FailurePredictData: 2-byte revision, then 30 x 12-byte entries."""
    th = {}
    for i in range(30):
        o = 2 + i * 12
        if o + 12 <= len(thr) and thr[o]:
            th[thr[o]] = thr[o + 1]
    out = []
    for i in range(30):
        o = 2 + i * 12
        if o + 12 > len(data):
            break
        aid = data[o]
        if not aid:
            continue
        raw = _u(data, o + 5, 6)
        out.append({"id": aid, "name": ATA_NAMES.get(aid, "Attribute %d" % aid), "value": data[o + 3], "worst": data[o + 4],
                    "thresh": th.get(aid, 0), "raw": raw})
    return out


def _raw(a):
    """Interpret raw values that are packed on many drives."""
    if a["id"] in (190, 194):
        return a["raw"] & 0xFF
    if a["id"] in (9,):
        return a["raw"] & 0xFFFFFFFF
    if a["id"] in (188, 5, 197, 198, 196, 187, 10, 199, 181, 182, 171, 172, 183):
        return a["raw"] & 0xFFFFFFFF
    return a["raw"]


def parse_smartctl(j):
    """Normalise `smartctl -a -j` output."""
    d = {"serial": (j.get("serial_number") or "").strip(), "model": j.get("model_name"), "firmware": j.get("firmware_version"),
         "passed": (j.get("smart_status") or {}).get("passed"), "rotation": j.get("rotation_rate"), "attrs": [], "nvme": None, "selftests": [],
         "device": (j.get("device") or {}).get("name"), "dtype": (j.get("device") or {}).get("type")}
    for a in (j.get("ata_smart_attributes") or {}).get("table", []):
        d["attrs"].append({"id": a.get("id"), "name": ATA_NAMES.get(a.get("id"), a.get("name", "").replace("_", " ")), "value": a.get("value"),
                           "worst": a.get("worst"), "thresh": a.get("thresh", 0), "raw": (a.get("raw") or {}).get("value", 0)})
    n = j.get("nvme_smart_health_information_log")
    if n:
        d["nvme"] = {k: n.get(k) for k in ("critical_warning", "temperature", "available_spare", "available_spare_threshold", "percentage_used",
                                           "data_units_read", "data_units_written", "power_cycles", "power_on_hours", "unsafe_shutdowns",
                                           "media_errors", "num_err_log_entries", "warning_temp_time", "critical_comp_time")}
        d["nvme"]["temperature_sensors"] = n.get("temperature_sensors") or []
    for t in ((j.get("ata_smart_self_test_log") or {}).get("standard") or {}).get("table", []):
        d["selftests"].append({"type": (t.get("type") or {}).get("string"), "passed": (t.get("status") or {}).get("passed"),
                               "result": (t.get("status") or {}).get("string"), "hours": t.get("lifetime_hours")})
    for t in (j.get("nvme_self_test_log") or {}).get("table", []):
        d["selftests"].append({"type": (t.get("self_test_code") or {}).get("string"), "passed": (t.get("self_test_result") or {}).get("value") == 0,
                               "result": (t.get("self_test_result") or {}).get("string"), "hours": t.get("power_on_hours")})
    return d


# ---------------------------------------------------------------------------------
#  smartctl (optional)
# ---------------------------------------------------------------------------------
def find_smartctl(app_dir):
    for p in (os.path.join(app_dir, "tools", "smartctl.exe"), os.path.join(app_dir, "smartctl.exe"),
              os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "smartmontools", "bin", "smartctl.exe"),
              shutil.which("smartctl") or ""):
        if p and os.path.isfile(p):
            return p
    return None


def _run(args, timeout=60):
    import core
    rc, out, err = core.tracked_run(args, timeout, "smartctl")
    return out.decode("utf-8", "replace")


def smartctl_json(exe, *args, timeout=60):
    try:
        return json.loads(_run([exe, "-j"] + list(args), timeout))
    except Exception as e:
        return {"_error": str(e)}


def smartctl_all(exe):
    """Return {serial: parsed} for every device smartctl can open."""
    out = {}
    scan = smartctl_json(exe, "--scan-open")
    for dev in scan.get("devices", []):
        args = ["-a", dev["name"]]
        if dev.get("type") and dev["type"] not in ("auto",):
            args = ["-a", "-d", dev["type"], dev["name"]]
        j = smartctl_json(exe, *args, timeout=90)
        if j.get("serial_number"):
            p = parse_smartctl(j)
            p["args"] = args[1:-1] + [dev["name"]] if len(args) > 2 else [dev["name"]]
            out[_norm_serial(j["serial_number"])] = p
    return out


def _norm_serial(s):
    return re.sub(r"[\s_.-]", "", s or "").upper()


def selftest_start(exe, dev_args, kind):
    j = smartctl_json(exe, "-t", kind, *dev_args, timeout=60)
    msgs = [m.get("string", "") for m in (j.get("smartctl") or {}).get("messages", [])]
    rc = (j.get("smartctl") or {}).get("exit_status", 1)
    return {"ok": rc in (0, 4) and not any("not supported" in m.lower() or "failed" in m.lower() for m in msgs), "messages": msgs,
            "minutes": ((j.get("ata_smart_data") or {}).get("self_test") or {}).get("polling_minutes", {}).get(kind)}


def selftest_status(exe, dev_args):
    """Return (running: bool, percent_done, last_result dict)."""
    j = smartctl_json(exe, "-c", "-l", "selftest", *dev_args, timeout=60)
    st = ((j.get("ata_smart_data") or {}).get("self_test") or {}).get("status") or {}
    running, pct = False, None
    if st:
        running = st.get("value", 0) >> 4 == 0xF
        pct = 100 - st.get("remaining_percent", 0) if running else 100
    nv = j.get("nvme_self_test_log") or {}
    if nv:
        op = (nv.get("current_self_test_operation") or {}).get("value", 0)
        running = op != 0
        pct = nv.get("current_self_test_completion_percent", 0) if running else 100
    last = parse_smartctl(j)["selftests"][:1]
    return running, pct, (last[0] if last else None)


# ---------------------------------------------------------------------------------
#  Assessment
# ---------------------------------------------------------------------------------
def kind_of(d):
    bus, media = (d.get("bus") or "").upper(), (d.get("media") or "").upper()
    model = (d.get("model") or "").lower()
    if "virtual" in model or bus in ("FILEBACKEDVIRTUAL", "VIRTUAL") or re.search(r"(?i)msft virtual|vmware|vbox|qemu|virtio", model):
        return "Virtual disk"
    if bus == "NVME":
        return "NVMe SSD"
    spin = _i(d.get("spindle")) or 0
    if media == "HDD" or 0 < spin != 4294967295:
        return "Hard drive (HDD)"
    if media != "SSD" and bus != "USB":
        # Intel RST / RAID mode hides the media type ("Unspecified"): SSD-only SMART attributes or "SSD" in the name give it away.
        ids = {a.get("id") for a in (d.get("attrs") or []) if isinstance(a, dict)}
        if ids & set(SSD_ONLY_ATTRS) or re.search(r"(?i)\bssd|ssd\b|solid state", model):
            media = "SSD"
    if media == "SSD":
        return "SATA SSD" if bus in ("SATA", "RAID", "SAS", "ATA") else "SSD (%s)" % d.get("bus")
    if bus == "USB":
        return "USB drive"
    return "Drive (%s)" % (d.get("bus") or "?")


def _f(sev, title, why="", fix=None):
    return {"severity": sev, "title": title, "why": why, "fix": list(fix or [])}


def assess(d):
    """Return verdict dict: status GOOD/CAUTION/CRITICAL/UNKNOWN, health %, findings, metrics, can_test.
    Health % on SSDs is mostly 'life left' (write endurance). Wear alone never makes a drive CRITICAL/CAUTION
    until the maker's life-left figure is low (<=30% CAUTION, <=10% CRITICAL)."""
    F, health, status = [], 100, "GOOD"
    kind = kind_of(d)
    d["kind"] = kind
    ssd = "SSD" in kind
    model = _s(d.get("model"))
    m = {}
    has_data = False
    problems = []       # reasons other than normal wear (these block tests on a CAUTION drive)

    def worst(s, wear=False):
        nonlocal status
        order = {"GOOD": 0, "UNKNOWN": 0, "CAUTION": 1, "CRITICAL": 2}
        if not wear and order[s]:
            problems.append(s)
        if order[s] > order[status]:
            status = s

    def wear_check(left, source):
        """Life left % -> findings. Returns nothing; adjusts health/status."""
        nonlocal health
        left = max(0, min(100, int(left)))
        health = min(health, left)
        m["Life left"] = left
        if left <= 10:
            worst("CRITICAL", wear=True)
            F.append(_f("CRITICAL", "SSD is worn out: %d%% of its rated life left" % left,
                        "Flash cells survive a limited number of writes and this drive has used up almost all of them (%s). It can turn read-only or fail." % source,
                        ["Back up now", "Replace the drive"]))
        elif left <= 30:
            worst("CAUTION", wear=True)
            F.append(_f("WARNING", "SSD wear: %d%% of its rated life left" % left,
                        "The drive is healthy but has used most of its rated write endurance (%s). Plan a replacement in the coming months/years." % source,
                        ["Keep backups current", "Plan a replacement"]))
        elif left < 80:
            F.append(_f("INFO", "SSD has used %d%% of its rated life - normal wear" % (100 - left),
                        "Health %% here is the life left that the drive reports (%s). It is not a fault - wear only becomes a concern below 30%%." % source, []))

    wh = _s(d.get("health")).lower()
    if wh == "unhealthy":
        worst("CRITICAL")
        health = min(health, 10)
        F.append(_f("CRITICAL", "Windows reports this drive as UNHEALTHY", "The drive itself reported a failure condition to Windows.",
                    ["Back up now", "Replace the drive"]))
    elif wh == "warning":
        worst("CAUTION")
        F.append(_f("WARNING", "Windows reports a health WARNING for this drive", "The drive reported it is degrading.", ["Back up now"]))

    # ---------- NVMe ----------
    nv = d.get("nvme_log")
    if nv:
        has_data = True
        cw = _i(nv.get("critical_warning")) or 0
        spare, sthr = _i(nv.get("available_spare")), _i(nv.get("available_spare_threshold"))
        used = _i(nv.get("percentage_used"))
        m.update({"Temperature": nv.get("temperature"), "Power-on hours": nv.get("power_on_hours"),
                  "Data written": _tb(_i(nv.get("data_units_written"))), "Data read": _tb(_i(nv.get("data_units_read"))), "Power cycles": nv.get("power_cycles"),
                  "Unsafe shutdowns": nv.get("unsafe_shutdowns"), "Media errors": nv.get("media_errors"), "Error log entries": nv.get("num_err_log_entries"),
                  "Spare": "%s%% (min %s)" % (spare, sthr) if spare is not None else None,
                  "Time too hot": "%s min" % nv.get("warning_temp_time") if nv.get("warning_temp_time") is not None else None})
        if cw & 0x01 or (spare is not None and sthr and spare < sthr):
            worst("CRITICAL"); health = min(health, 10)
            F.append(_f("CRITICAL", "Spare blocks used up (available spare %s%% < %s%%)" % (spare, sthr),
                        "The SSD has run out of replacement blocks for worn-out flash. Failure or read-only mode is close.", ["Back up now", "Replace the drive"]))
        if cw & 0x04:
            worst("CRITICAL"); health = min(health, 10)
            F.append(_f("CRITICAL", "Drive reports its RELIABILITY IS DEGRADED", "Too many internal/media errors (NVMe critical warning bit 2).", ["Back up now", "Replace the drive"]))
        if cw & 0x08:
            worst("CRITICAL"); health = min(health, 5)
            F.append(_f("CRITICAL", "Drive has switched to READ-ONLY mode", "It protects the remaining data - you can still copy files off, but not write.", ["Copy your files off now", "Replace the drive"]))
        if cw & 0x10:
            worst("CRITICAL")
            F.append(_f("CRITICAL", "Volatile memory backup has failed", "The power-loss protection is broken.", ["Back up", "Replace the drive"]))
        if cw & 0x02:
            worst("CAUTION")
            F.append(_f("WARNING", "Drive reports a temperature warning", "It is (or was) running above its safe temperature.", FIX_HEAT))
        if used is not None:
            wear_check(100 - used, "NVMe 'percentage used' %d%%" % used)
        me = _i(nv.get("media_errors")) or 0
        if me >= 10 or (me and cw & 0x04):
            worst("CRITICAL"); health = min(health, 20)
            F.append(_f("CRITICAL", "%d media / data integrity error(s)" % me, "The SSD could not read data back correctly (unrecovered ECC errors). Data may already be damaged.",
                        ["Back up now", "Update SSD firmware", "Replace the drive"]))
        elif me:
            worst("CAUTION"); health = min(health, 60)
            F.append(_f("WARNING", "%d media / data integrity error(s)" % me,
                        "The SSD once failed to read some data back correctly. A single event can be a one-off (e.g. after a power loss); a rising count means the flash is failing.",
                        ["Back up", "Update SSD firmware", "Check again in a week - if the count grows, replace the drive"]))
        t = _i(nv.get("temperature"))
        if t and t >= 70:
            worst("CAUTION")
            F.append(_f("WARNING", "Running hot: %d C" % t, "NVMe drives throttle and can drop off the bus when hot.", FIX_HEAT))
        if _i(nv.get("critical_comp_time")):
            worst("CAUTION")
            F.append(_f("WARNING", "Spent %s min above its CRITICAL temperature" % nv["critical_comp_time"], "Serious overheating has happened.", FIX_HEAT))
        elif _i(nv.get("warning_temp_time")):
            F.append(_f("INFO", "Spent %s min above its warning temperature (lifetime)" % nv["warning_temp_time"], "Heat history - relevant if you see NVMe resets.", FIX_HEAT))
        if (_i(nv.get("num_err_log_entries")) or 0) > 0 and not me:
            F.append(_f("INFO", "%d entries in the drive's error log" % _i(nv["num_err_log_entries"]),
                        "Usually harmless (e.g. unsupported commands from Windows) when there are no media errors.", []))

    # ---------- ATA SMART ----------
    attrs = [a for a in (d.get("attrs") or []) if isinstance(a, dict) and _i(a.get("id")) is not None]
    if attrs:
        has_data = True
        for a in attrs:
            a["id"], a["value"], a["thresh"], a["raw"] = _i(a["id"]), _i(a.get("value")) or 0, _i(a.get("thresh")) or 0, _i(a.get("raw")) or 0
            a["name"] = _s(a.get("name")) or ATA_NAMES.get(a["id"], "Attribute %s" % a["id"])
        non4k = bool(RX_NON4K_181.search(model))
        if non4k:
            for a in attrs:
                if a["id"] == 181:
                    a["name"] = "Unaligned (non-4K) writes - not an error"
        A = {a["id"]: a for a in attrs}

        def raw(i):
            return _raw(A[i]) if i in A else 0
        for a in attrs:
            if a.get("thresh") and a["value"] and a["value"] <= a["thresh"] and a["id"] not in (190,):
                worst("CRITICAL"); health = min(health, 15)
                F.append(_f("CRITICAL", "SMART attribute FAILED: %s (value %s <= threshold %s)" % (a["name"], a["value"], a["thresh"]),
                            "The drive itself says this value is beyond its failure limit.", ["Back up now", "Replace the drive"]))
        if d.get("predict_failure") is True:
            worst("CRITICAL"); health = min(health, 10)
            F.append(_f("CRITICAL", "Drive PREDICTS ITS OWN FAILURE (SMART)", "", ["Back up now", "Replace the drive"]))
        r5, r197, r198, r187 = raw(5), raw(197), raw(198), raw(187)
        if ssd and r197 == 1 and not r198:
            # Crucial MX500 (and a few others) flip 197 between 0 and 1 during internal housekeeping - not a real bad sector.
            worst("CAUTION"); health = min(health, 69)
            F.append(_f("WARNING", "1 pending sector reported",
                        ("Crucial MX500 SSDs are known to show 1 pending sector for a while during internal background work - it usually clears by itself. "
                         if RX_MX500.search(model) else "On an SSD a single pending sector often clears by itself after the next write. ") +
                        "If it stays or the count grows, the flash is failing.",
                        ["Back up", "Update SSD firmware", "Check again in a week - if it grows, replace the drive"]))
        elif r197 or r198:
            worst("CRITICAL"); health = min(health, 25, max(0, 60 - r197 - r198))
            F.append(_f("CRITICAL", "%d sector(s) currently UNREADABLE (pending %d, offline uncorrectable %d)" % (max(r197, r198), r197, r198),
                        "Some data on the drive can't be read right now. Heavy use can make it worse.",
                        ["Copy important files off FIRST", "Clone the drive with a tool that skips bad sectors", "Replace the drive"]))
        if r5:
            sev = "CRITICAL" if r5 >= 100 else "WARNING"
            worst("CRITICAL" if sev == "CRITICAL" else "CAUTION")
            health = min(health, max(10, 90 - r5 // 2) if r5 < 100 else 25)
            F.append(_f(sev, "%d reallocated sector(s)" % r5, "Bad sectors were replaced with spares. A rising count means the surface/flash is failing.",
                        ["Back up", "Check again in a week - if it grows, replace the drive"]))
        if r187:
            worst("CAUTION"); health = min(health, 75)
            F.append(_f("WARNING", "%d uncorrectable read error(s) reported" % r187, "The drive failed to read data at some point.", ["Back up", "Run CHKDSK /scan after backing up"]))
        if raw(10):
            worst("CAUTION"); health = min(health, 70)
            F.append(_f("WARNING", "Spin-up retries: %d" % raw(10), "The motor struggled to spin up - mechanical or power problem.", ["Back up", "Check the power cable"]))
        for i, nm in ((181, "program"), (182, "erase"), (171, "program"), (172, "erase")):
            if i == 181 and non4k:
                continue
            if raw(i):
                worst("CAUTION"); health = min(health, 70)
                F.append(_f("WARNING", "Flash %s failures: %d" % (nm, raw(i)), "NAND blocks failed and were retired.", ["Back up", "Update SSD firmware"]))
        if raw(199):
            F.append(_f("WARNING", "%d interface CRC error(s)" % raw(199), "Data got corrupted on the CABLE / connector, not on the drive. Old counts never reset.",
                        ["Replace the SATA cable", "Try another SATA port", "If the count keeps rising, it's the cable/port"]))
        life_id = next((i for i in LIFE_ATTRS if i in A and 0 < A[i]["value"] <= 100 and ssd), None)
        if life_id is not None:
            wear_check(A[life_id]["value"], "SMART attribute %d" % life_id)
        t = raw(194) or raw(190)
        m.update({"Temperature": t or None, "Power-on hours": raw(9) or None, "Power cycles": raw(12) or None,
                  "Reallocated": r5, "Pending": r197, "Uncorrectable": r198, "CRC errors": raw(199)})
        if ssd:
            mult, uname = _units_241(model)
            for aid, key in ((241, "Data written"), (242, "Data read")):
                if aid in A:
                    m[key] = _bytes_str(A[aid]["raw"] * mult) if mult else "raw %s (units vary)" % A[aid]["raw"]
        if t and t >= (70 if ssd else 55):
            worst("CAUTION")
            F.append(_f("WARNING", "Running hot: %d C" % t, "", FIX_HEAT))

    # ---------- Windows reliability counters (fallback) ----------
    rel = _dd(d.get("rel"))
    if d.get("nvme_error") and not str(d["nvme_error"]).startswith("ERR:open"):
        F.append(_f("INFO", "NVMe health log not used", str(d["nvme_error"]), []))
    if not has_data and any(_i(rel.get(k)) not in (None, 0) for k in ("temp", "wear", "hours")):
        has_data = True
        m.update({"Temperature": _i(rel.get("temp")) or None, "Power-on hours": _i(rel.get("hours"))})
        if _i(rel.get("wear")) is not None and (ssd or _i(rel.get("wear"))):
            wear_check(100 - _i(rel["wear"]), "Windows wear counter %d%%" % _i(rel["wear"]))
    unc = (_i(rel.get("read_unc")) or 0) + (_i(rel.get("write_unc")) or 0)
    if unc:
        worst("CAUTION"); health = min(health, 60)
        F.append(_f("WARNING", "%d uncorrected read/write error(s) (Windows counter)" % unc, "", ["Back up", "Run CHKDSK /scan"]))
    for st in d.get("selftests") or []:
        if isinstance(st, dict) and st.get("passed") is False:
            worst("CRITICAL"); health = min(health, 20)
            F.append(_f("CRITICAL", "Last drive self-test FAILED: %s" % st.get("result"), "The drive found errors when it tested itself.", ["Back up now", "Replace the drive"]))
        break
    if d.get("smart_passed") is False:
        worst("CRITICAL"); health = min(health, 10)
        F.append(_f("CRITICAL", "Overall SMART health check: FAILED", "", ["Back up now", "Replace the drive"]))

    if not has_data and status == "GOOD":
        status = "UNKNOWN"
        why = {"Virtual disk": "This is a virtual disk - health data lives on the host's physical drives.",
               "USB drive": "USB sticks and most USB enclosures don't pass health data through."}.get(kind, "The drive didn't report health data to Windows (or WinDiag isn't running as admin).")
        F.append(_f("INFO", "No health data available", why, []))
    health = max(0, min(100, int(health)))
    if status == "CRITICAL":
        health = min(health, 29)
    elif status == "CAUTION":
        health = min(health, 69)
    order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    F.sort(key=lambda f: order.get(f["severity"], 9))
    fixes = []
    for f in F:
        for x in f["fix"]:
            if x not in fixes:
                fixes.append(x)
    # Tests are read-only: allowed on healthy drives and on drives whose ONLY issue is normal wear (not worn out).
    can_test = d.get("number") is not None and (status in ("GOOD", "UNKNOWN") or (status == "CAUTION" and not problems))
    return {"status": status, "health": None if status == "UNKNOWN" else health, "kind": kind, "findings": F, "metrics": {k: v for k, v in m.items() if v not in (None, "")},
            "fixes": fixes, "can_test": can_test, "wear_only": status == "CAUTION" and not problems}


FIX_HEAT = ["Improve airflow / add an NVMe heatsink", "Keep laptops on a hard surface", "Clean dust from fans"]


def _bytes_str(b):
    return "%.2f TB" % (b / 1e12) if b >= 1e12 else "%.0f GB" % (b / 1e9)


def _tb(units):
    if units is None:
        return None
    return _bytes_str(units * 512000)


def _tb_lba(lbas):
    return _bytes_str(lbas * 512)


def _norm_drive(d, idx):
    """Coerce one DRIVES_PS drive entry into the shapes the rest of the code expects."""
    for k in ("model", "serial", "firmware", "bus", "media", "health", "opstatus", "style", "pnp", "iface", "nvme"):
        d[k] = _s(d.get(k)).strip()
    for k in ("number", "spindle", "size", "lsector", "psector"):
        d[k] = _i(d.get(k))
    rel = _dd(d.get("rel"))
    d["rel"] = {k: (_i(v) if not isinstance(v, (int, float)) or isinstance(v, bool) else v) for k, v in rel.items()}
    parts = []
    for p in _dl(d.get("partitions")):
        for k in ("letter", "type", "gpt", "access", "fs", "label"):
            p[k] = _s(p.get(k)).strip()
        for k in ("number", "offset", "size", "vsize", "free"):
            p[k] = _i(p.get(k))
        parts.append(p)
    d["partitions"] = parts
    ata = _dd(d.get("ata"))
    d["ata"] = {"data": _s(ata.get("data")), "thresholds": _s(ata.get("thresholds")), "predict_failure": ata.get("predict_failure") is True} if ata else None
    return d


def build(raw, smart=None):
    """raw = DRIVES_PS JSON, smart = smartctl_all() result or None. Returns list of drive dicts with 'verdict'."""
    raw = ps_clean(raw) if isinstance(raw, dict) else {}
    drives = [_norm_drive(d, i) for i, d in enumerate(_dl(raw.get("drives")))]
    for d in drives:
        nvh = d.get("nvme") or ""
        blob, note = locate_nvme_log(nvh)
        d["nvme_log"] = parse_nvme_log(blob) if blob else None
        d["nvme_error"] = note if (nvh and not blob) else None
        d["nvme_note"] = note if blob else ""
        rel = d["rel"]
        nv = d["nvme_log"]
        # Cross-check with Windows' own reading (the numbers Settings > Disks shows). A big disagreement = misread log.
        if nv and rel.get("wear") is not None and nv.get("percentage_used") is not None and abs(int(rel["wear"]) - nv["percentage_used"]) > 10:
            d["nvme_log"] = None
            d["nvme_error"] = "Health log disagrees with Windows (wear %s%% vs %s%%) - ignored, Windows' counters used." % (nv["percentage_used"], rel["wear"])
        ata = d.get("ata") or {}
        d["attrs"] = parse_ata_smart(_hex(ata.get("data")), _hex(ata.get("thresholds"))) if ata.get("data") else []
        d["predict_failure"] = ata.get("predict_failure")
        s = (smart or {}).get(_norm_serial(d.get("serial")))
        d["smartctl"] = bool(s)
        if s:
            if s.get("nvme"):
                d["nvme_log"] = s["nvme"]
            if s.get("attrs"):
                d["attrs"] = s["attrs"]
            d["selftests"] = s.get("selftests")
            d["smart_passed"] = s.get("passed")
            d["smart_args"] = s.get("args")
        d["verdict"] = assess(d)
    drives.sort(key=lambda x: (x.get("number") is None, x.get("number") or 0))
    return drives


def summary_findings(drives):
    out = []
    for d in drives:
        v = d["verdict"]
        name = "Disk %s (%s)" % (d.get("number"), d.get("model"))
        if v["status"] in ("CRITICAL", "CAUTION"):
            top = next((f for f in v["findings"] if f["severity"] in ("CRITICAL", "WARNING")), None)
            out.append({"Status": "CRITICAL" if v["status"] == "CRITICAL" else "WARNING", "Area": "Drive health",
                        "Finding": "%s: %s (health %s%%)%s" % (name, v["status"], v["health"], (" - " + top["title"]) if top else ""),
                        "Advice": "; ".join(v["fixes"][:3]), "_drive": d.get("number")})
        elif v["status"] == "GOOD":
            out.append({"Status": "OK", "Area": "Drive health", "Finding": "%s: GOOD (health %s%%)" % (name, v["health"]), "Advice": ""})
    return out


# ---------------------------------------------------------------------------------
#  Guards
# ---------------------------------------------------------------------------------
def disk_of_path(drives, path):
    letter = os.path.splitdrive(os.path.abspath(path))[0][:1].upper()
    for d in drives:
        for p in d["partitions"]:
            if (p.get("letter") or "").upper() == letter and letter:
                return d.get("number")
    return None


def wipe_blockers(d, windiag_disk):
    why = []
    if d.get("is_system") or d.get("is_boot"):
        why.append("it holds Windows / the boot files")
    if windiag_disk is not None and d.get("number") == windiag_disk:
        why.append("WinDiag is running from it")
    for p in d["partitions"]:
        if (p.get("letter") or "").upper() == (os.environ.get("SystemDrive", "C:")[:1]).upper():
            why.append("it contains the system drive %s:" % p["letter"])
    return why


def wipe_script(number, new_partition=True, label="Wiped"):
    s = ["select disk %d" % int(number), "attributes disk clear readonly", "online disk noerr", "clean all"]
    if new_partition:
        s += ["convert gpt noerr", "create partition primary", 'format fs=ntfs quick label="%s"' % label, "assign"]
    return "\n".join(s) + "\n"


# ---------------------------------------------------------------------------------
#  Read test / surface scan (READ-ONLY)
# ---------------------------------------------------------------------------------
class WinDiskReader(object):
    """Opens \\\\.\\PhysicalDriveN with GENERIC_READ only. Windows rejects any write on this handle."""
    GENERIC_READ, SHARE_RW, OPEN_EXISTING, NO_BUFFERING = 0x80000000, 3, 3, 0x20000000

    def __init__(self, number, size):
        import ctypes
        from ctypes import wintypes
        self.ct = ctypes
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k.CreateFileW.restype = wintypes.HANDLE
        self.k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.k.VirtualAlloc.restype = ctypes.c_void_p
        self.k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        self.k.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong, ctypes.c_void_p, wintypes.DWORD]
        self.k.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        self.h = self.k.CreateFileW("\\\\.\\PhysicalDrive%d" % number, self.GENERIC_READ, self.SHARE_RW, None, self.OPEN_EXISTING, self.NO_BUFFERING, None)
        if not self.h or self.h == wintypes.HANDLE(-1).value:
            raise OSError("Could not open disk %d read-only (error %d). Run WinDiag as administrator." % (number, ctypes.get_last_error()))
        self.size = size - size % 4096
        self.bufsize = 4 << 20
        self.buf = self.k.VirtualAlloc(None, self.bufsize, 0x3000, 0x04)

    def read(self, offset, n):
        """Return None on success or a Windows error code."""
        from ctypes import wintypes
        if not self.k.SetFilePointerEx(self.h, offset, None, 0):
            return self.ct.get_last_error()
        got = wintypes.DWORD(0)
        if not self.k.ReadFile(self.h, self.buf, n, self.ct.byref(got), None):
            return self.ct.get_last_error() or 1
        return None if got.value == n else 38

    def read_bytes(self, offset, n):
        """Return the bytes read (n must be a multiple of 4096 and <= 4 MiB), or None on error."""
        if self.read(offset, n) is not None:
            return None
        return self.ct.string_at(self.buf, n)

    def close(self):
        try:
            self.k.CloseHandle(self.h)
            self.k.VirtualFree(self.ct.c_void_p(self.buf), 0, 0x8000)
        except Exception:
            pass


class FileReader(object):
    """For tests: reads a normal file, with optional simulated bad/slow regions."""

    def __init__(self, path, bad=(), slow=()):
        self.f = open(path, "rb", buffering=0)
        self.size = os.path.getsize(path) - os.path.getsize(path) % 4096
        self.bufsize = 4 << 20
        self.bad, self.slow = bad, slow

    def read(self, offset, n):
        if any(offset < b and offset + n > a for a, b in self.bad):
            return 23
        if any(a <= offset < b for a, b in self.slow):
            time.sleep(0.25)
        self.f.seek(offset)
        self.f.read(n)
        return None

    def read_bytes(self, offset, n):
        if any(offset < b and offset + n > a for a, b in self.bad):
            return None
        self.f.seek(offset)
        return self.f.read(n)

    def close(self):
        self.f.close()


READ_ERRORS = {23: "data error (CRC) - unreadable sector", 1117: "I/O device error", 21: "device not ready", 55: "device no longer available",
               1167: "device not connected", 483: "hardware error", 38: "short read"}
BAD_BLOCK_ERRORS = (23, 1117, 483)          # the medium itself could not be read
DISCONNECT_ERRORS = (21, 55, 1167)          # the drive went away (unplugged, USB reset, sleep) - NOT bad sectors


class ReadTest(object):
    """mode 'quick': 1 MiB sample in every map cell (a few minutes max).  mode 'full': every byte, sequential."""

    def __init__(self, reader, mode="quick", cells=CELLS, progress=None):
        self.r, self.mode, self.n, self.progress = reader, mode, cells, progress
        self.cancel = threading.Event()
        self.speed = [None] * cells     # MB/s per cell
        self.lat = [0.0] * cells        # max latency ms per cell
        self.err = [0] * cells          # unreadable blocks per cell
        self.errors = []                # (offset, code)
        self.other_errors = 0           # failed reads that are not medium errors (odd driver codes)
        self.disconnected = None        # Windows error code if the drive went away mid-test
        self.done_bytes = 0
        self.t0 = None
        self.finished = False
        size = max(0, getattr(reader, "size", 0) or 0)
        bufsize = getattr(reader, "bufsize", 4 << 20) or (4 << 20)
        self.chunk = (1 << 20) if mode == "quick" else min(bufsize, max(1 << 16, (size // max(1, cells)) // (1 << 16) * (1 << 16)))

    def cell_of(self, off):
        return min(self.n - 1, int(off * self.n // max(1, self.r.size)))

    def _timed(self, off, n):
        t = time.perf_counter()
        e = self.r.read(off, n)
        return e, time.perf_counter() - t

    def _failed(self, off, e, c):
        """Record a failed read. Returns True if the test must stop (drive disconnected)."""
        if e in DISCONNECT_ERRORS:
            self.disconnected = e
            return True
        if e in BAD_BLOCK_ERRORS:
            self.err[c] += 1
        else:
            self.other_errors += 1
        if len(self.errors) < 500:
            self.errors.append((off, e))
        return False

    def _pinpoint(self, off, n, c):
        """Find which 64 KiB blocks inside a failed read are bad (still read-only). Returns True if the drive went away."""
        step = 64 << 10
        for o in range(off, off + n, step):
            if self.cancel.is_set():
                return False
            e, _ = self._timed(o, min(step, off + n - o))
            if e and self._failed(o, e, c):
                return True
        return False

    def run(self):
        self.t0 = time.time()
        size = self.r.size
        try:
            if self.mode == "quick":
                n = self.chunk
                for c in range(self.n):
                    if self.cancel.is_set():
                        break
                    start = (size * c // self.n) // 4096 * 4096
                    end = (size * (c + 1) // self.n) // 4096 * 4096
                    off = start + ((end - start - n) // 2) // 4096 * 4096 if end - start > n else start
                    if off + n > size:
                        n2 = size - off
                        if n2 <= 0:
                            continue
                    else:
                        n2 = n
                    e, dt = self._timed(off, n2)
                    self.lat[c] = dt * 1000
                    if e in DISCONNECT_ERRORS:
                        self.disconnected = e
                        break
                    if e:
                        if self._pinpoint(off, n2, c):
                            break
                    else:
                        self.speed[c] = n2 / max(dt, 1e-6) / 1e6
                    self.done_bytes += n2
                    if self.progress and c % 10 == 0:
                        self.progress(self, c / self.n)
            else:
                chunk = self.chunk
                off = 0
                acc = {}
                while off < size and not self.cancel.is_set():
                    n = min(chunk, size - off)
                    c = self.cell_of(off)
                    e, dt = self._timed(off, n)
                    self.lat[c] = max(self.lat[c], dt * 1000)
                    if e in DISCONNECT_ERRORS:
                        self.disconnected = e
                        break
                    if e:
                        if self._pinpoint(off, n, c):
                            break
                    else:
                        b, t = acc.get(c, (0, 0.0))
                        acc[c] = (b + n, t + dt)
                        self.speed[c] = acc[c][0] / max(acc[c][1], 1e-6) / 1e6
                    off += n
                    self.done_bytes = off
                    if self.progress and (off // chunk) % 16 == 0:
                        self.progress(self, off / size)
        finally:
            self.finished = True
            self.r.close()
            if self.progress:
                self.progress(self, 1.0)
        return self.summary()

    def thresholds(self):
        """(slow_ms, veryslow_ms) for one read of self.chunk bytes, relative to this drive's own median speed,
        so a slow-but-healthy USB stick isn't reported as 'weak sectors'."""
        sp = [s for s in self.speed if s]
        med = statistics.median(sp) if sp else 0
        expect = (self.chunk / (med * 1e6) * 1000) if med else 0      # ms one chunk normally takes on this drive
        return max(150.0, 2.5 * expect), max(500.0, 5 * expect), med

    def classify(self):
        """Per-cell class: None untested, 'ok', 'slow', 'veryslow', 'bad'."""
        slow_ms, vslow_ms, med = self.thresholds()
        out = []
        for i in range(self.n):
            if self.err[i]:
                out.append("bad")
            elif self.speed[i] is None:
                out.append(None)
            elif self.lat[i] > vslow_ms:
                out.append("veryslow")      # the drive retried a weak sector
            elif self.lat[i] > slow_ms or (med and self.speed[i] < med * 0.25 and self.lat[i] > 40):
                out.append("slow")
            else:
                out.append("ok")
        return out

    def summary(self):
        sp = [s for s in self.speed if s]
        cl = self.classify()
        el = time.time() - (self.t0 or time.time())
        res = {"mode": self.mode, "cancelled": self.cancel.is_set(), "seconds": round(el), "bytes": self.done_bytes,
               "avg_mbs": round(statistics.mean(sp), 1) if sp else None, "median_mbs": round(statistics.median(sp), 1) if sp else None,
               "min_mbs": round(min(sp), 1) if sp else None, "max_latency_ms": round(max(self.lat), 1) if self.lat else None,
               "slow": cl.count("slow"), "veryslow": cl.count("veryslow"), "bad_cells": cl.count("bad"), "bad_blocks": sum(self.err),
               "other_errors": self.other_errors, "disconnected": self.disconnected,
               "errors": [(o, READ_ERRORS.get(e, "error %s" % e)) for o, e in self.errors[:50]]}
        if self.disconnected:
            res["verdict"] = "ERROR"
            res["text"] = ("The drive stopped responding / was disconnected during the test (Windows: %s) after %s. This is NOT a bad-sector result - "
                           "reconnect it (another USB port or cable, no hub) and run the test again.%s" % (
                               READ_ERRORS.get(self.disconnected, "error %s" % self.disconnected), fmt_bytes(self.done_bytes),
                               (" Before that, %d unreadable 64 KiB block(s) were found." % res["bad_blocks"]) if res["bad_blocks"] else ""))
        elif res["bad_blocks"]:
            res["verdict"] = "FAIL"
            res["text"] = "%d unreadable 64 KiB block(s) found - the drive has bad sectors. Back up now and replace it." % res["bad_blocks"]
        elif self.other_errors:
            res["verdict"] = "WARN"
            res["text"] = ("%d read(s) failed with an unusual Windows error (%s) - that points to the driver/connection rather than bad sectors. "
                           "Run the test again; if it repeats, check the cable/port." % (self.other_errors, res["errors"][0][1] if res["errors"] else "?"))
        elif res["veryslow"] > max(2, self.n // 200):
            res["verdict"] = "WARN"
            res["text"] = "%d area(s) read very slowly - weak sectors that the drive struggles to read (early sign of failure on hard drives)." % res["veryslow"]
        else:
            res["verdict"] = "PASS"
            res["text"] = "Everything read back without errors%s." % (" (%d slightly slow areas - normal for HDDs toward the inner tracks)" % res["slow"] if res["slow"] else "")
        return res


# ---------------------------------------------------------------------------------
#  Drive map: which parts of the disk are used (FSCTL_GET_VOLUME_BITMAP, read-only)
# ---------------------------------------------------------------------------------
def volume_bitmap_usage(vol_path, root_path, part_size, slots):
    """Return list of `slots` fractions (0..1) of used clusters across a volume, or None if unreadable."""
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    spc, bps, fc, tc = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
    if not k.GetDiskFreeSpaceW(root_path, ctypes.byref(spc), ctypes.byref(bps), ctypes.byref(fc), ctypes.byref(tc)):
        return None
    cluster = spc.value * bps.value
    h = k.CreateFileW(vol_path, 0x80000000, 3, None, 3, 0, None)
    if not h or h == wintypes.HANDLE(-1).value:
        return None
    bits = bytearray()
    total = 0
    try:
        start = 0
        out = ctypes.create_string_buffer(16 + (1 << 20))
        while True:
            inb = ctypes.c_longlong(start)
            ret = wintypes.DWORD()
            ok = k.DeviceIoControl(h, 0x0009006F, ctypes.byref(inb), 8, out, len(out), ctypes.byref(ret), None)
            err = ctypes.get_last_error()
            if not ok and err != 234:
                break
            s_lcn = int.from_bytes(out.raw[0:8], "little", signed=True)
            nbits = int.from_bytes(out.raw[8:16], "little", signed=True)
            got = ret.value - 16
            if total == 0:
                total = s_lcn + nbits
            bits += out.raw[16:16 + got]
            start = s_lcn + got * 8
            if ok or got <= 0:
                break
    finally:
        k.CloseHandle(h)
    if not bits:
        return None
    return bitmap_fractions(bytes(bits), total or len(bits) * 8, slots)


def bitmap_fractions(bits, nclusters, slots):
    nbytes = max(1, (nclusters + 7) // 8)
    bits = bits[:nbytes]
    out = []
    for i in range(slots):
        a, b = nbytes * i // slots, max(nbytes * (i + 1) // slots, nbytes * i // slots + 1)
        seg = bits[a:b]
        if not seg:
            out.append(out[-1] if out else 0.0)
            continue
        out.append(bin(int.from_bytes(seg, "little")).count("1") / (len(seg) * 8))
    return out


def usage_map(d, cells=CELLS, bitmap_fn=None):
    """Per-cell: {'part': index or None, 'used': 0..1 or None (unknown)}."""
    size = d.get("size") or 1
    cell_bytes = size / cells
    res = [{"part": None, "used": None} for _ in range(cells)]
    bitmap_fn = bitmap_fn or volume_bitmap_usage
    for pi, p in enumerate(d["partitions"]):
        off, ps = p.get("offset") or 0, p.get("size") or 0
        c0, c1 = int(off // cell_bytes), min(cells - 1, int((off + ps - 1) // cell_bytes))
        slots = max(1, c1 - c0 + 1)
        fr = None
        if p.get("fs"):
            vol = (p.get("access") or "").rstrip("\\") or ("\\\\.\\%s:" % p["letter"] if p.get("letter") else None)
            root = (p.get("access") or "") if p.get("access") else ("%s:\\" % p["letter"] if p.get("letter") else None)
            if vol and root:
                try:
                    fr = bitmap_fn(vol, root, ps, slots)
                except Exception:
                    fr = None
            if fr is None and p.get("vsize"):
                u = 1 - (p.get("free") or 0) / max(1, p["vsize"])
                fr = [u] * slots
        for j, c in enumerate(range(c0, c1 + 1)):
            res[c] = {"part": pi, "used": fr[j] if fr and j < len(fr) else None}
    return res


def fmt_bytes(b):
    b = float(b or 0)
    for u, s in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6)):
        if b >= s:
            return "%.2f %s" % (b / s, u) if u == "TB" else "%.1f %s" % (b / s, u)
    return "%d B" % b
