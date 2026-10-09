"""Instant facts about this PC (registry / API) - no PowerShell, no UI."""
import ctypes
import os
import platform


def quick_facts():
    """Instant facts (registry / API) for the start screen - no PowerShell."""
    f = {"name": os.environ.get("COMPUTERNAME") or platform.node(), "os": platform.platform(), "model": "", "cpu": platform.processor(), "ram": ""}
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        pn = winreg.QueryValueEx(k, "ProductName")[0]
        try:
            dv = winreg.QueryValueEx(k, "DisplayVersion")[0]
        except OSError:
            dv = ""
        build = int(winreg.QueryValueEx(k, "CurrentBuildNumber")[0])
        if build >= 22000:
            pn = pn.replace("Windows 10", "Windows 11")
        f["os"] = ("%s %s" % (pn, dv)).strip()
        b = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
        f["model"] = ("%s %s" % (winreg.QueryValueEx(b, "SystemManufacturer")[0], winreg.QueryValueEx(b, "SystemProductName")[0])).strip()
        c = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        f["cpu"] = winreg.QueryValueEx(c, "ProcessorNameString")[0].strip()
    except Exception:
        pass
    try:
        if os.name == "nt":
            class MS(ctypes.Structure):
                _fields_ = [("len", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                            ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong), ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong), ("ae", ctypes.c_ulonglong)]
            m = MS()
            m.len = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            f["ram"] = "%.0f GB RAM" % (m.total / 2 ** 30)
        else:
            with open("/proc/meminfo") as fh:
                f["ram"] = "%.0f GB RAM" % (int(fh.readline().split()[1]) / 2 ** 20)
    except Exception:
        pass
    return f
