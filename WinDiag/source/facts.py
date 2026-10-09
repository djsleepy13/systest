"""Pulls friendly facts out of the check results (used by the dashboard and the spec sheet)."""
import ctypes
import os
import re
import time


def sec(results, check, prefix):
    for s in results.get(check, []) or []:
        if (s.get("title") or "").lower().startswith(prefix.lower()):
            d = s.get("data") or []
            return d if isinstance(d, list) else [d]
    return []


def first(results, check, prefix):
    d = [x for x in sec(results, check, prefix) if isinstance(x, dict)]
    return d[0] if d else {}


def gather(app):
    r = app.results
    f = {
        "overview": first(r, "System", "Overview"),
        "ram_modules": [x for x in sec(r, "System", "Memory modules") if isinstance(x, dict)],
        "gpus": [x for x in sec(r, "System", "Graphics") if isinstance(x, dict)],
        "devices_bad": [x for x in sec(r, "System", "Device Manager") if isinstance(x, dict)],
        "phys": [x for x in sec(r, "Disks", "Physical drives") if isinstance(x, dict)],
        "volumes": [x for x in sec(r, "Disks", "Drive letters") if isinstance(x, dict)],
        "adapters": [x for x in sec(r, "Network", "Network adapters") if isinstance(x, dict)],
        "ipconf": [x for x in sec(r, "Network", "IP configuration") if isinstance(x, dict)],
        "conn": [x for x in sec(r, "Network", "Connectivity tests") if isinstance(x, dict)],
        "av": [x for x in sec(r, "Security", "Antivirus products") if isinstance(x, dict)],
        "defender": first(r, "Security", "Microsoft Defender"),
        "firewall": [x for x in sec(r, "Security", "Firewall") if isinstance(x, dict)],
        "bitlocker": [x for x in sec(r, "Security", "BitLocker") if isinstance(x, dict)],
        "pending": " ".join(str(x) for x in sec(r, "Security", "Pending restart")),
        "updates": [x for x in sec(r, "Security", "Windows Update") if isinstance(x, dict)],
        "battery": [x for x in sec(r, "Security", "Battery") if isinstance(x, dict)],
        "platform": first(r, "Virt", "Platform"),
        "server": first(r, "Server", "Server overview"),
        "drives": getattr(app, "drive_result", None) or [],
        "ram": (getattr(app, "ram_result", None) or {}).get("info"),
        "ramtest": (getattr(app, "ram_result", None) or {}).get("test"),
        "security_scan": getattr(app, "security_result", None),
    }
    return f


def worst(findings, areas):
    order = {"CRITICAL": 3, "WARNING": 2, "INFO": 1, "OK": 0}
    w, hits = "OK", []
    for x in findings:
        if (x.get("Area") or "") in areas:
            s = x.get("Status", "INFO")
            if s in ("CRITICAL", "WARNING"):
                hits.append(x)
            if order.get(s, 0) > order.get(w, 0) and s in ("CRITICAL", "WARNING"):
                w = s
    return w, hits


def gb(text):
    """'15.9 GB' -> 15.9 ; '1.82 TB' -> 1863"""
    m = re.search(r"([\d.,]+)\s*(TB|GB|MB)", str(text or ""))
    if not m:
        return None
    v = float(m.group(1).replace(",", ""))
    return v * 1024 if m.group(2) == "TB" else (v / 1024 if m.group(2) == "MB" else v)


def fmt_bytes(b):
    b = float(b or 0)
    for u, s in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6)):
        if b >= s:
            return "%.1f %s" % (b / s, u) if u != "TB" else "%.2f %s" % (b / s, u)
    return "%d B" % b


# ---------------------------------------------------------------------------------
#  Live performance (no extra packages): CPU % and RAM %
# ---------------------------------------------------------------------------------
class Perf(object):
    def __init__(self):
        self.prev = None
        self.cpu_hist, self.ram_hist = [], []

    def _times(self):
        if os.name == "nt":
            from ctypes import wintypes
            idle, kern, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
            ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user))
            q = lambda ft: (ft.dwHighDateTime << 32) | ft.dwLowDateTime
            i, k, u = q(idle), q(kern), q(user)
            return i, k + u
        with open("/proc/stat") as fh:
            p = [int(x) for x in fh.readline().split()[1:]]
        return p[3] + p[4], sum(p)

    def _mem(self):
        if os.name == "nt":
            class MS(ctypes.Structure):
                _fields_ = [("len", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                            ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong), ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong), ("ae", ctypes.c_ulonglong)]
            m = MS()
            m.len = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return m.load, m.total, m.total - m.avail
        info = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                k, v = line.split(":")
                info[k] = int(v.split()[0]) * 1024
        used = info["MemTotal"] - info.get("MemAvailable", info["MemFree"])
        return used * 100 // info["MemTotal"], info["MemTotal"], used

    def sample(self):
        try:
            idle, total = self._times()
            cpu = None
            if self.prev:
                di, dt = idle - self.prev[0], total - self.prev[1]
                cpu = max(0.0, min(100.0, 100.0 * (1 - di / dt))) if dt > 0 else 0.0
            self.prev = (idle, total)
            load, tot, used = self._mem()
            if cpu is not None:
                self.cpu_hist = (self.cpu_hist + [cpu])[-60:]
            self.ram_hist = (self.ram_hist + [float(load)])[-60:]
            return cpu, load, tot, used
        except Exception:
            return None, None, None, None
