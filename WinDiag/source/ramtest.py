"""
WinDiag Memory (RAM)
--------------------
Slots   - which slots are filled, size/speed/maker of each stick (Win32_PhysicalMemory),
          ECC, rated vs configured speed, mixed kits, WHEA memory errors, last Windows
          Memory Diagnostic result.
Test    - in-Windows pattern test: takes most of the FREE RAM, locks it in physical memory
          (so nothing is paged to disk), writes patterns (00/FF/55/AA, address, random) and reads them
          back. Only WinDiag's own memory is touched. Windows and running programs keep the
          rest, so coverage is ~70-85% and positions are virtual, not physical addresses.
"""
import ctypes
import os
import sys
import threading
import time

CELLS = 1200
BLOCK = 64 << 20            # allocation unit
CHUNK = 1 << 20             # compare unit

RAM_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$os = Get-CimInstance Win32_OperatingSystem
$arr = @(Get-CimInstance Win32_PhysicalMemoryArray | Where-Object { $_.Use -eq 3 -or -not $_.Use })
$sticks = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
    [ordered]@{ slot = "$($_.DeviceLocator)".Trim(); bank = "$($_.BankLabel)".Trim(); size = [int64]$_.Capacity; speed = $_.Speed; configured = $_.ConfiguredClockSpeed
                maker = "$($_.Manufacturer)".Trim(); part = "$($_.PartNumber)".Trim(); serial = "$($_.SerialNumber)".Trim(); type = $_.SMBIOSMemoryType; mtype = $_.MemoryType
                form = $_.FormFactor; width = $_.TotalWidth; datawidth = $_.DataWidth; voltage = $_.ConfiguredVoltage } })
$since = (Get-Date).AddDays(-90)
$whea = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since } -MaxEvents 300 |
          Where-Object { $_.Message -match '(?i)memory' } | ForEach-Object { [ordered]@{ time = $_.TimeCreated.ToString('s'); id = $_.Id; msg = (($_.Message -split "`n")[0]).Trim() } })
$md = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } -MaxEvents 1
$cs = Get-CimInstance Win32_ComputerSystem
@{
    total = [int64]$os.TotalVisibleMemorySize * 1024; free = [int64]$os.FreePhysicalMemory * 1024; installed = [int64]$cs.TotalPhysicalMemory
    slots = [int]($arr | Measure-Object -Property MemoryDevices -Sum).Sum; max = [int64]($arr | Measure-Object -Property MaxCapacityEx -Sum).Sum
    ecc = @($arr | ForEach-Object { $_.MemoryErrorCorrection }); sticks = $sticks; whea = $whea
    mdsched = $(if ($md) { [ordered]@{ time = $md.TimeCreated.ToString('s'); id = $md.Id; msg = (($md.Message -split "`n")[0]).Trim() } } else { $null })
    model = "$($cs.Manufacturer) $($cs.Model)"
} | ConvertTo-Json -Depth 5 -Compress
"""

# SMBIOS 3.x Type 17 "Memory Type" (Win32_PhysicalMemory.SMBIOSMemoryType)
MEM_TYPES = {3: "DRAM", 15: "SDRAM", 17: "RDRAM", 18: "DDR", 19: "DDR2", 20: "DDR2 FB-DIMM", 24: "DDR3", 25: "FBD2", 26: "DDR4", 27: "LPDDR",
             28: "LPDDR2", 29: "LPDDR3", 30: "LPDDR4", 31: "Logical non-volatile", 32: "HBM", 33: "HBM2", 34: "DDR5", 35: "LPDDR5", 36: "HBM3"}
# Legacy Win32_PhysicalMemory.MemoryType (CIM enum) -> SMBIOS code, used only when SMBIOSMemoryType is 0/1/2 (unknown)
LEGACY_TYPES = {17: 15, 20: 18, 21: 19, 22: 20, 24: 24, 25: 25, 26: 26}
MAX_SLOTS = 64
ECC = {3: "No ECC", 4: "Parity", 5: "Single-bit ECC", 6: "Multi-bit ECC", 7: "CRC"}
MAKERS = {"80CE": "Samsung", "CE00": "Samsung", "80AD": "SK hynix", "AD00": "SK hynix", "802C": "Micron", "2C00": "Micron", "859B": "Crucial",
          "9E": "Corsair", "04CD": "G.Skill", "CD04": "G.Skill", "0198": "Kingston", "9801": "Kingston", "04F1": "Kingston", "029E": "Corsair"}


_ETS_KEYS = {"PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSIsContainer", "ReadCount", "Count", "Length"}


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


def _n(v):
    """int or None."""
    if isinstance(v, bool) or v is None:
        return None
    try:
        return int(float(v)) if isinstance(v, (str, float)) else int(v)
    except (TypeError, ValueError, OverflowError):
        return None


def _str(v):
    return v.strip() if isinstance(v, str) else ("" if v is None or isinstance(v, (dict, list, bool)) else str(v))


def type_code(s):
    """SMBIOS memory type code for a stick (SMBIOSMemoryType first, legacy MemoryType as fallback)."""
    t = _n(s.get("type"))
    if t in MEM_TYPES:
        return t
    return LEGACY_TYPES.get(_n(s.get("mtype")))


def type_name(s):
    return MEM_TYPES.get(type_code(s), "")


def running_mts(speed, configured):
    """ConfiguredClockSpeed is MT/s on current SMBIOS but MHz (half the data rate) on older firmware:
    DDR4-3200 running at full speed can show 1600. Returns the data rate in MT/s."""
    if not configured:
        return None
    if speed and abs(configured * 2 - speed) <= max(2, speed * 0.02):
        return configured * 2
    return configured


def _norm_stick(s):
    s = dict(s)
    for k in ("slot", "bank", "maker", "part", "serial"):
        s[k] = _str(s.get(k))
    for k in ("size", "speed", "configured", "form", "width", "datawidth", "voltage"):
        s[k] = _n(s.get(k))
    s["size"] = max(0, s["size"] or 0)
    s["configured_raw"] = s["configured"]
    s["configured"] = running_mts(s["speed"], s["configured"])
    s["type"] = type_code(s)
    return s


def maker_name(m):
    m = (m or "").strip()
    key = m.upper().replace(" ", "")
    for k, v in MAKERS.items():
        if key.startswith(k):
            return v
    return m or "?"


def assess(raw):
    """Return dict: sticks, slots (list incl. empty), findings, summary."""
    raw = ps_clean(raw) if isinstance(raw, dict) else {}
    sticks = [_norm_stick(s) for s in _l(raw.get("sticks")) if isinstance(s, dict)]
    nslots = min(MAX_SLOTS, max(max(0, _n(raw.get("slots")) or 0), len(sticks)))
    sticks = sticks[:MAX_SLOTS]
    F = []

    def add(sev, title, why="", fix=()):
        F.append({"severity": sev, "title": title, "why": why, "fix": list(fix)})
    sizes = {s.get("size") for s in sticks}
    parts = {s.get("part") for s in sticks if s.get("part")}
    total = sum(s.get("size") or 0 for s in sticks)
    types = {MEM_TYPES.get(s.get("type"), "") for s in sticks} - {""}
    if len(sticks) > 1 and (len(sizes) > 1 or len(parts) > 1):
        add("INFO", "Mixed RAM sticks (%s)" % ", ".join(sorted({"%d GB %s" % ((s.get("size") or 0) >> 30, s.get("part") or "?") for s in sticks})),
            "Different kits can be unstable together, especially with XMP/EXPO on. If you get crashes, test with matching sticks only.")
    rated = [s for s in sticks if s.get("speed") and s.get("configured") and s["configured"] < s["speed"]]
    if rated:
        add("INFO", "RAM runs slower than rated (%s of %s MT/s)" % (rated[0]["configured"], rated[0]["speed"]),
            "Usually XMP/EXPO is off in the BIOS - safe and most stable. Turn it on only if the PC is stable.")
    if len(sticks) == 1 and nslots >= 2:
        add("INFO", "Only one RAM stick - running in single-channel mode", "Two matching sticks (one per channel) are noticeably faster.")
    ecc = [ECC.get(_n(e)) for e in _l(raw.get("ecc")) if _n(e) in ECC]
    whea = [w for w in _l(raw.get("whea")) if w]
    if whea:
        add("CRITICAL" if len(whea) >= 3 else "WARNING", "%d hardware memory error(s) reported by the CPU (WHEA) in 90 days" % len(whea),
            "The memory controller detected RAM errors. Some were corrected, but they mean a stick, slot or setting is unstable.",
            ["Turn off XMP/EXPO / overclocks", "Run the RAM test below", "Test one stick at a time"])
    md = raw.get("mdsched")
    if isinstance(md, list):
        md = md[0] if md and isinstance(md[0], dict) else None
    if isinstance(md, dict) and md:
        msg, when = _str(md.get("msg")), _str(md.get("time"))[:10]
        bad = _n(md.get("id")) == 1202 or ("error" in msg.lower() and "no errors" not in msg.lower())
        if bad:
            add("CRITICAL", "Windows Memory Diagnostic found errors (%s)" % when, msg,
                ["Test one stick at a time", "Replace the faulty stick"])
        else:
            add("OK", "Last Windows Memory Diagnostic: no errors (%s)" % when, "")
    slots = []
    for i in range(nslots):
        s = sticks[i] if i < len(sticks) else None
        slots.append(s)
    return {"sticks": sticks, "slots": slots, "nslots": nslots, "total": total or _n(raw.get("installed")), "visible": _n(raw.get("total")),
            "free": _n(raw.get("free")), "types": sorted(types), "ecc": ecc[0] if ecc else "Unknown", "findings": F, "model": _str(raw.get("model"))}


# ---------------------------------------------------------------------------------
#  Memory backend
# ---------------------------------------------------------------------------------
class WinMem(object):
    """VirtualAlloc + VirtualLock so tested pages stay in physical RAM (not the page file)."""

    def __init__(self):
        from ctypes import wintypes
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k.VirtualAlloc.restype = ctypes.c_void_p
        self.k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        self.k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
        self.k.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.k.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.k.GetCurrentProcess.restype = wintypes.HANDLE
        self.k.SetProcessWorkingSetSizeEx.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t, wintypes.DWORD]
        self.memcmp = ctypes.cdll.msvcrt.memcmp
        self.memcmp.restype = ctypes.c_int
        self.memcmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    def free_bytes(self):
        class MS(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                        ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong), ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong), ("ae", ctypes.c_ulonglong)]
        m = MS()
        m.len = ctypes.sizeof(MS)
        self.k.GlobalMemoryStatusEx(ctypes.byref(m))
        return m.avail, m.total

    def reserve(self, nbytes):
        # working set must be big enough to lock this much
        self.k.SetProcessWorkingSetSizeEx(self.k.GetCurrentProcess(), nbytes + (64 << 20), nbytes + (256 << 20), 0)

    def alloc(self, n):
        p = self.k.VirtualAlloc(None, n, 0x3000, 0x04)
        if not p:
            return None, False
        locked = bool(self.k.VirtualLock(p, n))
        return p, locked

    def free(self, p, n):
        try:
            self.k.VirtualUnlock(p, n)
        except Exception:
            pass
        self.k.VirtualFree(p, 0, 0x8000)


class PyMem(object):
    """Portable backend for testing (ctypes buffers, libc memcmp)."""

    def __init__(self, limit=256 << 20, fault=None):
        import ctypes.util
        self.libc = ctypes.CDLL(ctypes.util.find_library("c"))
        self.memcmp = self.libc.memcmp
        self.memcmp.restype = ctypes.c_int
        self.memcmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        self.limit, self.bufs, self.fault = limit, {}, fault

    def free_bytes(self):
        return self.limit + (1 << 30), 16 << 30

    def reserve(self, n):
        pass

    def alloc(self, n):
        b = ctypes.create_string_buffer(n)
        p = ctypes.addressof(b)
        self.bufs[p] = b
        return p, True

    def free(self, p, n):
        self.bufs.pop(p, None)


# ---------------------------------------------------------------------------------
#  Test
# ---------------------------------------------------------------------------------
PATTERNS = [("zeros", 0x00), ("ones", 0xFF), ("checker 01", 0x55), ("checker 10", 0xAA), ("address", "addr"),
            ("random A", "rA"), ("random B", "rB")]
# "address": every 1 MiB chunk gets one of ADDR_REFS different random buffers, chosen by its position. 17 is coprime with
# every power of two, so address-line faults (one address aliasing another 2^k bytes away) show up as a wrong chunk;
# random data inside a chunk catches aliasing within it. Verified in reverse order (moving-inversion style).
ADDR_REFS = 17
LOCATE_CAP = 256          # bad bytes pinpointed per 1 MiB chunk (the rest of a broken chunk is not itemised)


class RamTest(object):
    def __init__(self, backend=None, target=None, passes=1, progress=None, cells=CELLS, reserve_free=None):
        self.m = backend or (WinMem() if os.name == "nt" else PyMem())
        self.passes, self.progress, self.n = passes, progress, cells
        self.cancel = threading.Event()
        avail, total = self.m.free_bytes()
        keep = reserve_free if reserve_free is not None else max(768 << 20, int(total * 0.12))
        self.total_ram = total
        self.target = target if target is not None else max(0, avail - keep)
        self.blocks = []            # (ptr, size)
        self.tested = 0
        self.locked_all = True
        self.cell_state = [None] * cells     # None untested, 'run', 'ok', 'bad'
        self.cell_err = [0] * cells
        self.errors = []            # (virtual offset, expected, got)
        self.pass_no = 0
        self.pattern = ""
        self.t0 = None
        self.done_bytes = 0

    # -------- helpers
    def _refs(self):
        r = {}
        for name, v in PATTERNS:
            if isinstance(v, int):
                buf = ctypes.create_string_buffer(bytes([v]) * CHUNK, CHUNK)
            elif v == "addr":
                buf = [ctypes.create_string_buffer(os.urandom(CHUNK), CHUNK) for _ in range(ADDR_REFS)]
            else:
                buf = ctypes.create_string_buffer(os.urandom(CHUNK), CHUNK)
            r[name] = buf
        return r

    def cell_of(self, off):
        return min(self.n - 1, int(off * self.n // max(1, self.tested)))

    def _allocate(self):
        self.m.reserve(self.target)
        got = 0
        while got + BLOCK <= self.target and not self.cancel.is_set():
            p, locked = self.m.alloc(BLOCK)
            if not p:
                break
            if not locked:
                self.m.free(p, BLOCK)       # would be paged to disk - don't test it
                self.locked_all = False
                break
            self.blocks.append((p, BLOCK))
            got += BLOCK
        self.tested = got

    def _release(self):
        for p, n in self.blocks:
            self.m.free(p, n)
        self.blocks = []

    def inject_fault(self, block_index, offset):
        """Test hook: flip one byte after writing (simulates a bad memory cell)."""
        self._fault = (block_index, offset)

    def run(self):
        self.t0 = time.time()
        refs = self._refs()
        try:
            self._allocate()
            if not self.blocks:
                return self.summary("Could not reserve memory for the test (not enough free RAM, or Windows refused to lock it).")
            passes = self.passes if self.passes > 0 else 10 ** 9
            total_steps = len(PATTERNS) * len(self.blocks)
            for pn in range(passes):
                self.pass_no = pn + 1
                for pi, (name, _v) in enumerate(PATTERNS):
                    self.pattern = name
                    allrefs = refs[name] if isinstance(refs[name], list) else [refs[name]]
                    nref = len(allrefs)
                    rps = [ctypes.addressof(r) for r in allrefs]
                    ref = allrefs[0]
                    # write all blocks, then verify all (so data sits in RAM a while before checking)
                    for bi, (p, n) in enumerate(self.blocks):
                        if self.cancel.is_set():
                            return self.summary()
                        c0 = self.cell_of(bi * BLOCK)
                        if self.cell_state[c0] is None:
                            self.cell_state[c0] = "run"
                        for o in range(0, n, CHUNK):
                            ctypes.memmove(p + o, rps[((bi * BLOCK + o) // CHUNK) % nref], CHUNK)
                        f = getattr(self, "_fault", None)
                        if f and f[0] == bi and pi == len(PATTERNS) - 1:
                            ctypes.memset(p + f[1], (ref.raw[f[1] % CHUNK] ^ 0x10), 1)
                    order = list(enumerate(self.blocks))
                    if nref > 1:
                        order.reverse()
                    for step, (bi, (p, n)) in enumerate(order):
                        if self.cancel.is_set():
                            return self.summary()
                        for o in range(0, n, CHUNK):
                            k = ((bi * BLOCK + o) // CHUNK) % nref
                            if self.m.memcmp(p + o, rps[k], CHUNK) != 0:
                                self._locate(bi, p, o, allrefs[k])
                        base = bi * BLOCK
                        for c in range(self.cell_of(base), self.cell_of(base + n - 1) + 1):
                            if self.cell_state[c] != "bad":
                                self.cell_state[c] = "ok" if pi == len(PATTERNS) - 1 else "run"
                        self.done_bytes += n
                        if self.progress and step % 4 == 0:
                            frac = (pi * len(self.blocks) + step + 1) / total_steps
                            self.progress(self, min(0.999, (pn + frac) / self.passes if self.passes > 0 else frac))
            return self.summary()
        finally:
            self._release()
            if self.progress:
                self.progress(self, 1.0)

    def _locate(self, bi, p, o, ref):
        """Find the wrong bytes in one failed 1 MiB chunk. Compares 4 KiB pages first and stops after LOCATE_CAP
        bad bytes per chunk, so a badly broken / aliased stick can't stall the test for minutes in a Python byte loop."""
        got = ctypes.string_at(p + o, CHUNK)
        exp = ref.raw
        found = 0
        for pg in range(0, CHUNK, 4096):
            if got[pg:pg + 4096] == exp[pg:pg + 4096]:
                continue
            for i in range(pg, pg + 4096):
                if got[i] != exp[i]:
                    voff = bi * BLOCK + o + i
                    c = self.cell_of(voff)
                    self.cell_state[c] = "bad"
                    self.cell_err[c] += 1
                    if len(self.errors) < 200:
                        self.errors.append((voff, exp[i], got[i]))
                    found += 1
                    if found >= LOCATE_CAP:
                        return

    def summary(self, fail_text=None):
        el = time.time() - (self.t0 or time.time())
        nerr = sum(self.cell_err)
        cov = self.tested / max(1, self.total_ram)
        res = {"tested": self.tested, "coverage": round(cov * 100), "passes": self.pass_no, "seconds": round(el), "errors": nerr,
               "cancelled": self.cancel.is_set(), "locked": self.locked_all, "bad_cells": self.cell_state.count("bad"),
               "samples": [("%s" % _fmt(o), "expected %02X, read %02X (bits %s)" % (e, g, _bits(e ^ g))) for o, e, g in self.errors[:10]]}
        if fail_text:
            res.update(verdict="ERROR", text=fail_text)
        elif nerr:
            res.update(verdict="FAIL", text="%d memory ERROR(S) found - RAM is faulty or unstable. Turn off XMP/overclocks, then test one stick at a time to find the bad one." % nerr)
        elif self.cancel.is_set() and self.pass_no <= 1 and self.cell_state.count("ok") < self.n // 2:
            res.update(verdict="STOPPED", text="Stopped early - no errors in the part that was tested.")
        else:
            res.update(verdict="PASS", text=("No errors found in the %s (%d%% of the RAM) that Windows let us test, %d pass(es). This can't rule out "
                                              "every RAM fault (the rest is in use by Windows, and some faults only show under heat or long runs) - "
                                              "for proof, run MemTest86 from a USB stick." % (_fmt(self.tested), round(cov * 100), self.pass_no)))
        return res


def _bits(x):
    return ",".join(str(i) for i in range(8) if x >> i & 1)


def _fmt(b):
    b = float(b)
    return "%.1f GB" % (b / (1 << 30)) if b >= 1 << 30 else "%.0f MB" % (b / (1 << 20))
