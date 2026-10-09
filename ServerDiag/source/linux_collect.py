"""
ServerDiag - Linux health checks.
Stdlib only, Python 3.6+. Works on Ubuntu/Debian; most checks also work on RHEL/Rocky/Alma/SUSE.
Every check returns a list of sections and adds findings. Nothing here changes the system.
"""
import glob
import json
import os
import re
import socket
import time
from datetime import datetime

from .common import run, which, read, section, fmt_size

DB_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
            11211: "Memcached", 5984: "CouchDB", 9042: "Cassandra", 2375: "Docker API (unauthenticated!)", 8086: "InfluxDB"}


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def os_release():
    d = {}
    for line in read("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v.strip().strip('"')
    return d


# ---------------------------------------------------------------------------------
#  Short performance sample (CPU incl. steal, disk latency) taken before heavy work
# ---------------------------------------------------------------------------------
def _cpu_stat():
    line = read("/proc/stat").splitlines()[0].split()
    vals = [int(x) for x in line[1:]]
    while len(vals) < 8:
        vals.append(0)
    return vals


def _diskstats():
    d = {}
    for line in read("/proc/diskstats").splitlines():
        p = line.split()
        if len(p) < 14:
            continue
        name = p[2]
        if re.match(r"^(loop|ram|zram|fd|sr|dm-|md)", name) or re.match(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+)\d+$", name) \
                or re.match(r"^nvme\d+n\d+p\d+$", name) or re.match(r"^mmcblk\d+p\d+$", name):
            continue
        d[name] = [int(x) for x in p[3:14]]
    return d


def perf_sample(seconds=2.0):
    c1, d1 = _cpu_stat(), _diskstats()
    time.sleep(seconds)
    c2, d2 = _cpu_stat(), _diskstats()
    dc = [b - a for a, b in zip(c1, c2)]
    total = float(sum(dc[:8])) or 1.0
    # user nice system idle iowait irq softirq steal
    cpu = {"busy": round(100 * (total - dc[3] - dc[4]) / total, 1), "iowait": round(100 * dc[4] / total, 1),
           "steal": round(100 * dc[7] / total, 1)}
    disks = {}
    for name, a in d1.items():
        b = d2.get(name)
        if not b:
            continue
        ios = (b[0] - a[0]) + (b[4] - a[4])
        ms = (b[3] - a[3]) + (b[7] - a[7])
        busy = b[9] - a[9]
        disks[name] = {"iops": round(ios / seconds, 1), "await_ms": round(ms / float(ios), 1) if ios else 0.0,
                       "util": min(100.0, round(100.0 * busy / (seconds * 1000), 1))}
    return {"cpu": cpu, "disks": disks, "seconds": seconds}


# ---------------------------------------------------------------------------------
#  1. System
# ---------------------------------------------------------------------------------
def check_system(F, ctx):
    out = []
    osr = ctx["os"]
    uptime_s = float((read("/proc/uptime") or "0 0").split()[0])
    boot = datetime.fromtimestamp(time.time() - uptime_s)
    mem = {}
    for line in read("/proc/meminfo").splitlines():
        p = line.split()
        if len(p) >= 2:
            mem[p[0].rstrip(":")] = int(p[1]) * 1024
    total = mem.get("MemTotal", 0)
    avail = mem.get("MemAvailable", mem.get("MemFree", 0))
    swt, swf = mem.get("SwapTotal", 0), mem.get("SwapFree", 0)
    cpus = os.cpu_count() or 1
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
    model = ""
    for line in read("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name") or line.startswith("Model") or line.startswith("cpu model"):
            model = line.split(":", 1)[1].strip()
            break
    virt = ctx["virt"]
    rc, td = run(["timedatectl", "show"], 10) if which("timedatectl") else (1, "")
    tdd = dict(l.split("=", 1) for l in td.splitlines() if "=" in l)
    synced = tdd.get("NTPSynchronized")
    ov = {
        "Hostname": socket.getfqdn(),
        "OS": osr.get("PRETTY_NAME", "Linux"),
        "Kernel": os.uname().release,
        "Architecture": os.uname().machine,
        "Platform": virt if virt != "none" else "Physical (bare metal)",
        "Uptime": "%dd %dh %dm" % (uptime_s // 86400, (uptime_s % 86400) // 3600, (uptime_s % 3600) // 60),
        "Booted": boot.strftime("%Y-%m-%d %H:%M"),
        "CPU": "%s (%d threads)" % (model or "?", cpus),
        "Load average": "%.2f / %.2f / %.2f  (1/5/15 min, %d CPUs)" % (load[0], load[1], load[2], cpus),
        "CPU now": "%s%% busy, %s%% iowait, %s%% steal" % (ctx["perf"]["cpu"]["busy"], ctx["perf"]["cpu"]["iowait"], ctx["perf"]["cpu"]["steal"]),
        "Memory": "%s total, %s available (%d%% used)" % (fmt_size(total), fmt_size(avail), 100 - (100 * avail // total if total else 0)),
        "Swap": "%s total, %s used" % (fmt_size(swt), fmt_size(swt - swf)) if swt else "none",
        "Timezone": tdd.get("Timezone", "?"),
        "Clock synchronised": {"yes": "Yes", "no": "NO"}.get(synced, "unknown"),
        "Running as root": "Yes" if is_root() else "No (limited)",
    }
    out.append(section("Overview", ov, True))

    # Pressure stall information
    psi = []
    for res in ("cpu", "memory", "io"):
        txt = read("/proc/pressure/" + res)
        for line in txt.splitlines():
            m = re.match(r"(some|full) avg10=([\d.]+) avg60=([\d.]+) avg300=([\d.]+)", line)
            if m:
                psi.append({"Resource": res, "Type": m.group(1), "avg10 %": m.group(2), "avg60 %": m.group(3), "avg300 %": m.group(4)})
                v = float(m.group(3))
                if res == "io" and m.group(1) == "some" and v >= 25:
                    F.add("WARNING", "Performance", "Processes spent %.0f%% of the last minute waiting for disk I/O" % v,
                          "Storage is a bottleneck - see Storage tab (latency) and `iotop -o`.")
                if res == "memory" and m.group(1) == "full" and v >= 5:
                    F.add("WARNING", "Performance", "Memory pressure: all tasks stalled %.1f%% of the last minute" % v,
                          "The server is short on RAM - reduce usage or add memory.")
                if res == "cpu" and m.group(1) == "some" and v >= 60:
                    F.add("WARNING", "Performance", "CPU pressure: tasks waited for CPU %.0f%% of the last minute" % v,
                          "CPU-bound - check top processes (Services tab).")
    if psi:
        out.append(section("Pressure stall information (PSI)", psi, note="How much time tasks were stalled waiting for a resource. Near 0 is ideal."))

    # Reboot required / new kernel
    pkgs = [l.strip() for l in read("/var/run/reboot-required.pkgs").splitlines() if l.strip()]
    reboot = os.path.exists("/var/run/reboot-required")
    if not reboot and which("needs-restarting"):
        rc, _ = run(["needs-restarting", "-r"], 30)
        reboot = rc == 1
    running = os.uname().release
    kernels = sorted(os.path.basename(p).replace("vmlinuz-", "") for p in glob.glob("/boot/vmlinuz-*"))

    def kkey(v):
        return [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.split(r"[.\-+_]", v)]
    newest = sorted(kernels, key=kkey)[-1] if kernels else running
    out.append(section("Kernels", {"Running": running, "Newest installed": newest,
                                   "Reboot required": ("YES (%s)" % ", ".join(sorted(set(pkgs))[:6]) if pkgs else "YES") if reboot else "No"}, True))
    if reboot:
        F.add("WARNING", "System", "A reboot is required to finish updates%s" % ((" (" + ", ".join(sorted(set(pkgs))[:4]) + ")") if pkgs else ""),
              "Schedule a reboot; security fixes for the kernel/libc are not active until then.")
    elif newest != running and kernels and running in kernels:
        F.add("INFO", "System", "A newer kernel (%s) is installed but not running" % newest, "Reboot to load it.")

    # Findings
    if total and avail * 100.0 / total < 10:
        F.add("CRITICAL", "Memory", "Only %s RAM available (%d%%)" % (fmt_size(avail), avail * 100 // total), "Find the memory hog (Services tab) - the OOM killer will start killing processes.")
    elif total and avail * 100.0 / total < 20:
        F.add("WARNING", "Memory", "Only %s RAM available (%d%%)" % (fmt_size(avail), avail * 100 // total), "Check top memory processes.")
    if swt and (swt - swf) * 100.0 / swt > 60:
        F.add("WARNING", "Memory", "Swap is %d%% used" % ((swt - swf) * 100 // swt), "Heavy swapping slows everything - the server needs more RAM or a process is leaking.")
    if load[1] > cpus * 1.5:
        F.add("WARNING", "CPU", "High load: 5-min load %.1f on %d CPUs" % (load[1], cpus), "Check top CPU processes and I/O wait.")
    if synced == "no":
        F.add("WARNING", "Time", "System clock is NOT synchronised (NTP)", "Enable time sync: `timedatectl set-ntp true` (chrony or systemd-timesyncd).")
    if uptime_s > 180 * 86400:
        F.add("INFO", "System", "Up for %d days" % (uptime_s // 86400), "Long uptimes usually mean kernel security updates are not applied (reboot or use livepatch).")
    return out


# ---------------------------------------------------------------------------------
#  2. Storage
# ---------------------------------------------------------------------------------
SKIP_FS = {"tmpfs", "devtmpfs", "squashfs", "overlay", "efivarfs", "proc", "sysfs", "cgroup", "cgroup2", "devpts",
           "securityfs", "pstore", "bpf", "tracefs", "debugfs", "configfs", "fusectl", "mqueue", "hugetlbfs",
           "autofs", "binfmt_misc", "nsfs", "rpc_pipefs", "ramfs", "fuse.lxcfs", "fuse.snapfuse", "fuse.gvfsd-fuse"}


def check_storage(F, ctx):
    out = []
    # df
    rc, txt = run(["df", "-PT"], 20)
    rc2, itxt = run(["df", "-Pi"], 20)
    inodes = {}
    for line in itxt.splitlines()[1:]:
        p = line.split()
        if len(p) >= 6:
            inodes[p[-1]] = p[4]
    fstab_ro = set()
    for line in read("/etc/fstab").splitlines():
        p = line.split()
        if len(p) >= 4 and not p[0].startswith("#") and "ro" in p[3].split(","):
            fstab_ro.add(p[1])
    ro_mounts = {}
    for line in read("/proc/mounts").splitlines():
        p = line.split()
        if len(p) >= 4 and p[2] in ("ext4", "ext3", "xfs", "btrfs") and "ro" in p[3].split(",") \
                and not p[1].startswith("/snap") and p[1] not in fstab_ro:
            ro_mounts[p[1]] = (p[0], p[2])
    rows = []
    for line in txt.splitlines()[1:]:
        p = line.split()
        if len(p) < 7:
            continue
        dev, fs, size, used, availk, pct, mnt = p[0], p[1], int(p[2]) * 1024, int(p[3]) * 1024, int(p[4]) * 1024, p[5], " ".join(p[6:])
        if fs in SKIP_FS or mnt.startswith("/snap/") or mnt.startswith("/var/lib/docker/"):
            continue
        usep = int(pct.rstrip("%") or 0) if pct.rstrip("%").isdigit() else 0
        ip = inodes.get(mnt, "-")
        rows.append({"Mount": mnt, "Device": dev, "FS": fs, "Size": fmt_size(size), "Used": fmt_size(used),
                     "Free": fmt_size(availk), "Use %": usep, "Inodes %": ip})
        if mnt in ro_mounts:
            continue
        if fs in ("vfat",) and mnt.startswith("/boot"):
            limit_c, limit_w = 95, 90
        else:
            limit_c, limit_w = 90, 80
        if usep >= limit_c:
            F.add("CRITICAL", "Storage", "%s is %d%% full (%s free)" % (mnt, usep, fmt_size(availk)),
                  "Free space: `du -xh %s --max-depth=2 | sort -h | tail`, `journalctl --vacuum-size=500M`, `apt clean`, old logs/backups, `docker system prune`." % mnt)
        elif usep >= limit_w:
            F.add("WARNING", "Storage", "%s is %d%% full (%s free)" % (mnt, usep, fmt_size(availk)), "Plan cleanup or grow the volume.")
        if ip not in ("-", "") and ip.rstrip("%").isdigit() and int(ip.rstrip("%")) >= 85:
            F.add("WARNING", "Storage", "%s has used %s of its inodes" % (mnt, ip), "Millions of small files (cache, sessions, mail queue). Find them: `du --inodes -x %s | sort -n | tail`." % mnt)
    out.append(section("Filesystems", rows))

    # Read-only mounts
    ro = []
    for mnt, (dev, fs) in sorted(ro_mounts.items()):
        ro.append({"Mount": mnt, "Device": dev, "FS": fs})
        important = mnt in ("/", "/var", "/home", "/srv", "/data", "/opt", "/var/lib", "/tmp") or mnt.startswith(("/var/lib/", "/srv/", "/data"))
        F.add("CRITICAL" if important else "WARNING", "Storage", "%s is mounted READ-ONLY (not set in fstab)" % mnt,
              "Usually the kernel remounted it after disk/filesystem errors - see Log Analyzer, then fsck in maintenance mode.")
    if ro:
        out.append(section("Read-only filesystems", ro))

    # Block devices
    disks = []
    rc, lj = run(["lsblk", "-J", "-b", "-d", "-o", "NAME,SIZE,TYPE,ROTA,MODEL,SERIAL,TRAN,VENDOR"], 15)
    try:
        for d in json.loads(lj).get("blockdevices", []):
            if d.get("type") != "disk" or re.match(r"^(loop|ram|zram|fd|sr)", d.get("name", "")):
                continue
            disks.append(d)
    except Exception:
        pass
    perf = ctx["perf"]["disks"]
    brow = []
    for d in disks:
        pf = perf.get(d["name"], {})
        rota = d.get("rota")
        if d["name"].startswith("nvme"):
            kind = "NVMe"
        elif (d.get("tran") or "") == "virtio" or re.match(r"^(vd|xvd)", d["name"]) or (ctx["virt"] != "none" and not d.get("tran")):
            kind = "Virtual"
        else:
            kind = "HDD" if str(rota) in ("1", "True", "true") else "SSD"
        brow.append({"Disk": "/dev/" + d["name"], "Type": kind, "Size": fmt_size(d.get("size") or 0),
                     "Model": ((d.get("vendor") or "").strip() + " " + (d.get("model") or "").strip()).strip(),
                     "Bus": d.get("tran") or "", "IOPS": pf.get("iops", ""), "Latency ms": pf.get("await_ms", ""), "Busy %": pf.get("util", "")})
        if pf and pf.get("util", 0) >= 90 and pf.get("await_ms", 0) >= 50:
            F.add("WARNING", "Storage", "/dev/%s is saturated (%.0f%% busy, %.0f ms latency)" % (d["name"], pf["util"], pf["await_ms"]),
                  "Find the I/O heavy process with `iotop -o` / `pidstat -d 1`. On a VM, the host storage may be overloaded.")
        elif pf and pf.get("await_ms", 0) >= 200 and pf.get("iops", 0) >= 1:
            F.add("WARNING", "Storage", "/dev/%s has very high latency (%.0f ms)" % (d["name"], pf["await_ms"]), "Slow or failing disk / overloaded host storage.")
    out.append(section("Disks (2-second performance sample)", brow))

    # SMART
    out.extend(_smart(F, ctx, disks))

    # mdraid
    md = read("/proc/mdstat")
    if "active" in md or "inactive" in md:
        rows = []
        lines = md.splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"^(md\d+)\s*:\s*(\w+)\s+(\w+)?\s*(.*)", line)
            if not m:
                continue
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            st = re.search(r"\[(\d+)/(\d+)\]\s*\[([U_]+)\]", nxt)
            prog = ""
            if i + 2 < len(lines) and re.search(r"(recovery|resync|reshape|check)\s*=", lines[i + 2]):
                prog = lines[i + 2].strip()
            state = "clean"
            if st and "_" in st.group(3):
                state = "DEGRADED %s" % st.group(3)
                F.add("CRITICAL", "RAID", "Software RAID %s is DEGRADED (%s)" % (m.group(1), st.group(3)),
                      "A member disk failed or dropped out: `mdadm --detail /dev/%s`, replace the disk and re-add it." % m.group(1))
            if m.group(2) == "inactive":
                state = "INACTIVE"
                F.add("CRITICAL", "RAID", "Software RAID %s is INACTIVE" % m.group(1), "`mdadm --detail --scan`; the array did not assemble.")
            if prog:
                F.add("INFO", "RAID", "%s: %s" % (m.group(1), prog[:80]), "Rebuild/check in progress - performance is reduced until it finishes.")
            rows.append({"Array": m.group(1), "Level": m.group(3) or "", "Members": m.group(4)[:60], "State": state, "Progress": prog[:50]})
        out.append(section("Software RAID (mdadm)", rows))

    # ZFS
    if which("zpool"):
        rc, zl = run(["zpool", "list", "-H", "-o", "name,size,alloc,free,cap,frag,health"], 20)
        rows = []
        for line in zl.splitlines():
            p = line.split("\t")
            if len(p) >= 7:
                rows.append({"Pool": p[0], "Size": p[1], "Used": p[2], "Free": p[3], "Cap": p[4], "Frag": p[5], "Health": p[6]})
                cap = int(p[4].rstrip("%") or 0) if p[4].rstrip("%").isdigit() else 0
                if p[6] != "ONLINE":
                    F.add("CRITICAL", "ZFS", "ZFS pool %s is %s" % (p[0], p[6]), "`zpool status -v %s` - replace the faulted device." % p[0])
                if cap >= 80:
                    F.add("WARNING", "ZFS", "ZFS pool %s is %d%% full" % (p[0], cap), "ZFS slows down sharply above ~80% - free space or add vdevs.")
        if rows:
            out.append(section("ZFS pools", rows))
            rc, zs = run(["zpool", "status", "-x"], 20)
            out.append(section("zpool status -x", [l for l in zs.splitlines() if l.strip()][:40]))

    # LVM thin pools
    if which("lvs") and is_root():
        rc, lv = run(["lvs", "--noheadings", "--separator", "|", "-o", "vg_name,lv_name,lv_size,data_percent,metadata_percent,lv_attr"], 20)
        rows = []
        for line in lv.splitlines():
            p = [x.strip() for x in line.split("|")]
            if len(p) < 6:
                continue
            rows.append({"VG": p[0], "LV": p[1], "Size": p[2], "Data %": p[3], "Meta %": p[4], "Attr": p[5]})
            try:
                if p[3] and float(p[3]) >= 90:
                    F.add("CRITICAL" if float(p[3]) >= 95 else "WARNING", "LVM", "Thin pool %s/%s data is %s%% full" % (p[0], p[1], p[3]),
                          "When a thin pool fills, every VM/volume on it freezes or corrupts. Extend it now (`lvextend`).")
                if p[4] and float(p[4]) >= 80:
                    F.add("CRITICAL", "LVM", "Thin pool %s/%s METADATA is %s%% full" % (p[0], p[1], p[4]), "Extend metadata: `lvextend --poolmetadatasize +1G %s/%s`." % (p[0], p[1]))
            except ValueError:
                pass
        if rows:
            out.append(section("LVM logical volumes", rows))
    return out


def _smart(F, ctx, disks):
    out = []
    if not disks:
        return out
    if not which("smartctl"):
        out.append(section("Drive health (SMART)", "smartctl not installed - install it for drive health: `apt install smartmontools` (or dnf install smartmontools)."))
        if ctx["virt"] == "none":
            F.add("INFO", "Storage", "smartmontools is not installed - drive health cannot be checked", "`apt install smartmontools` (physical servers should also run smartd).")
        return out
    if not is_root():
        out.append(section("Drive health (SMART)", "Needs root - run with sudo."))
        return out
    rows = []
    for d in disks:
        dev = "/dev/" + d["name"]
        rc, j = run(["smartctl", "-j", "-H", "-A", "-i", dev], 30)
        data = None
        try:
            data = json.loads(j)
        except Exception:
            data = None
        if data is None:
            rc, t = run(["smartctl", "-H", "-A", dev], 30)
            hl = re.search(r"(overall-health self-assessment test result|SMART Health Status):\s*(\S+)", t)
            rows.append({"Disk": dev, "Health": hl.group(2) if hl else "n/a", "Temp C": "", "Power-on h": "", "Wear %": "", "Bad sectors": "", "Notes": "old smartctl (no JSON)"})
            if hl and hl.group(2) not in ("PASSED", "OK"):
                F.add("CRITICAL", "Storage", "%s SMART health: %s" % (dev, hl.group(2)), "Back up now and replace the drive.")
            continue
        passed = (data.get("smart_status") or {}).get("passed")
        if passed is None:
            rows.append({"Disk": dev, "Health": "n/a", "Temp C": "", "Power-on h": "", "Wear %": "", "Bad sectors": "",
                         "Notes": "virtual disk / SMART unavailable" if ctx["virt"] != "none" else "SMART unavailable (RAID controller? try -d megaraid,N)"})
            continue
        temp = (data.get("temperature") or {}).get("current", "")
        poh = (data.get("power_on_time") or {}).get("hours", "")
        wear, bad, notes = "", 0, []
        attrs = {a.get("id"): a for a in ((data.get("ata_smart_attributes") or {}).get("table") or [])}

        def raw(i):
            try:
                return int(((attrs.get(i) or {}).get("raw") or {}).get("value") or 0)
            except (TypeError, ValueError):
                return 0
        realloc, pending, offl, crc = raw(5), raw(197), raw(198), raw(199)
        bad = realloc + pending + offl
        if realloc:
            notes.append("%d reallocated" % realloc)
        if pending:
            notes.append("%d pending" % pending)
        if offl:
            notes.append("%d uncorrectable" % offl)
        if crc:
            notes.append("%d CRC (cable) errors" % crc)
        nv = data.get("nvme_smart_health_information_log") or {}
        if nv:
            wear = nv.get("percentage_used", "")
            me = nv.get("media_errors", 0) or 0
            if me:
                notes.append("%d media errors" % me)
                bad += me
            if nv.get("critical_warning"):
                notes.append("critical_warning=%s" % nv.get("critical_warning"))
                F.add("CRITICAL", "Storage", "%s NVMe reports critical warning %s" % (dev, nv.get("critical_warning")), "Back up and replace the drive.")
            sp = nv.get("available_spare")
            if sp is not None and sp < (nv.get("available_spare_threshold") or 10):
                F.add("CRITICAL", "Storage", "%s spare blocks are exhausted (%s%%)" % (dev, sp), "Replace the SSD.")
        else:
            wl = attrs.get(177) or attrs.get(231) or attrs.get(233)
            if wl and wl.get("value") is not None and d["name"].startswith("sd") and str(d.get("rota")) in ("0", "False", "false"):
                wear = 100 - int(wl.get("value"))
        rows.append({"Disk": dev, "Health": "PASSED" if passed else "FAILED", "Temp C": temp, "Power-on h": poh,
                     "Wear %": wear, "Bad sectors": bad, "Notes": ", ".join(notes)})
        if not passed:
            F.add("CRITICAL", "Storage", "%s SMART overall health FAILED" % dev, "The drive predicts its own failure - back up and replace it now.")
        elif pending or offl:
            F.add("CRITICAL", "Storage", "%s has %d unreadable sectors (pending/uncorrectable)" % (dev, pending + offl), "Data on those sectors is at risk - back up and plan replacement; run a long test: `smartctl -t long %s`." % dev)
        elif realloc >= 10:
            F.add("WARNING", "Storage", "%s has %d reallocated sectors" % (dev, realloc), "The drive is wearing out - watch whether the count grows.")
        if crc >= 10:
            F.add("WARNING", "Storage", "%s has %d interface CRC errors" % (dev, crc), "Replace/reseat the SATA/SAS cable or backplane slot.")
        try:
            if wear != "" and int(wear) >= 90:
                F.add("CRITICAL", "Storage", "%s SSD is %s%% worn out" % (dev, wear), "Replace the SSD soon.")
            elif wear != "" and int(wear) >= 75:
                F.add("WARNING", "Storage", "%s SSD is %s%% worn" % (dev, wear), "Plan a replacement.")
        except (TypeError, ValueError):
            pass
        try:
            if temp != "" and int(temp) >= 65:
                F.add("WARNING", "Storage", "%s is hot (%s C)" % (dev, temp), "Check airflow / fans.")
        except (TypeError, ValueError):
            pass
    out.append(section("Drive health (SMART)", rows, note="Bad sectors = reallocated + pending + uncorrectable (+ NVMe media errors)."))
    return out


# ---------------------------------------------------------------------------------
#  3. Network
# ---------------------------------------------------------------------------------
def _ping(host, count=3):
    rc, t = run(["ping", "-c", str(count), "-W", "2", "-q", host], count * 3 + 5)
    m = re.search(r"= [\d.]+/([\d.]+)/", t)
    rx = re.search(r"(\d+) (?:packets )?received", t)
    return (rx is not None and int(rx.group(1)) > 0), (float(m.group(1)) if m else None)


def check_network(F, ctx):
    out = []
    ifs = []
    rc, j = run(["ip", "-j", "addr"], 10)
    try:
        for i in json.loads(j):
            name = i.get("ifname")
            if name == "lo" or name.startswith(("veth", "docker", "br-", "virbr", "cali", "flannel", "cni", "tap", "vnet", "fw")):
                continue
            addrs = ["%s/%s" % (a.get("local"), a.get("prefixlen")) for a in i.get("addr_info", []) if a.get("scope") == "global"]
            st = "/sys/class/net/%s/" % name

            def n(f):
                try:
                    return int(read(st + "statistics/" + f, "0").strip() or 0)
                except ValueError:
                    return 0
            speed = read(st + "speed").strip()
            rxp, rxe, txe, rxd = n("rx_packets"), n("rx_errors"), n("tx_errors"), n("rx_dropped")
            ifs.append({"Interface": name, "State": i.get("operstate"), "Addresses": ", ".join(addrs),
                        "MTU": i.get("mtu"), "Speed": (speed + " Mb/s") if speed and not speed.startswith("-") else "",
                        "RX errors": rxe, "TX errors": txe, "RX dropped": rxd})
            if rxp > 10000 and (rxe + txe) * 1000 > rxp:
                F.add("WARNING", "Network", "%s has many packet errors (%d rx / %d tx)" % (name, rxe, txe), "Bad cable/port, duplex mismatch or driver issue: `ethtool -S %s`." % name)
            if speed.isdigit() and 0 < int(speed) < 1000 and ctx["virt"] == "none" and i.get("operstate") == "UP":
                F.add("WARNING", "Network", "%s linked at only %s Mb/s" % (name, speed), "Check the cable / switch port (should be 1000+).")
    except Exception:
        rc, t = run(["ip", "-o", "addr"], 10)
        ifs = [l for l in t.splitlines()]
    out.append(section("Interfaces", ifs))

    gw, dev = None, None
    rc, j = run(["ip", "-j", "route", "show", "default"], 10)
    try:
        r = json.loads(j)
        if r:
            gw, dev = r[0].get("gateway"), r[0].get("dev")
    except Exception:
        pass
    dns = []
    rc, rs = run(["resolvectl", "dns"], 10) if which("resolvectl") else (1, "")
    for line in rs.splitlines():
        if ":" in line:
            dns += [x for x in line.split(":", 1)[1].split() if x]
    if not dns:
        dns = re.findall(r"^nameserver\s+(\S+)", read("/etc/resolv.conf"), re.M)
    dns = list(dict.fromkeys(dns))

    tests = []
    gw_ok = None
    if gw:
        gw_ok, gms = _ping(gw, 2)
        tests.append({"Test": "Ping gateway %s" % gw, "Result": "OK" if gw_ok else "FAILED", "Detail": ("%.1f ms" % gms) if gms else "no reply (may block ICMP)"})
    else:
        tests.append({"Test": "Default route", "Result": "MISSING", "Detail": "no default gateway"})
        F.add("WARNING", "Network", "No default route / gateway", "Fine for isolated servers; otherwise check netplan / network config.")
    inet_ok, ims = _ping("1.1.1.1", 3)
    tests.append({"Test": "Ping 1.1.1.1", "Result": "OK" if inet_ok else "FAILED", "Detail": ("%.1f ms" % ims) if ims else ""})
    rc, g = run(["getent", "hosts", "archive.ubuntu.com"], 10)
    dns_ok = rc == 0 and bool(g.strip())
    tests.append({"Test": "DNS lookup", "Result": "OK" if dns_ok else "FAILED", "Detail": (g.split()[0] if dns_ok else "servers: " + ", ".join(dns[:3]))})
    https_ok = False
    try:
        s = socket.create_connection(("1.1.1.1", 443), 5)
        s.close()
        https_ok = True
    except Exception:
        pass
    tests.append({"Test": "TCP 443 outbound", "Result": "OK" if https_ok else "FAILED", "Detail": ""})
    out.append(section("Connectivity", tests, note="Default gateway: %s via %s   DNS: %s" % (gw or "-", dev or "-", ", ".join(dns) or "-")))
    if not dns_ok and (inet_ok or https_ok):
        F.add("CRITICAL", "Network", "Internet reachable but DNS lookups fail", "Check DNS servers (%s): `resolvectl status`, /etc/netplan/*.yaml." % (", ".join(dns) or "none"))
    elif not inet_ok and not https_ok:
        F.add("WARNING", "Network", "No outbound internet access", "Fine if this server is intentionally isolated; otherwise check gateway / firewall / proxy. Updates will fail.")
    else:
        F.add("OK", "Network", "Network and DNS work%s" % ((" (%.0f ms to internet)" % ims) if ims else ""))
    if ims and ims > 150:
        F.add("WARNING", "Network", "High internet latency (%.0f ms)" % ims, "")

    # Listening ports
    rc, ss = run(["ss", "-tulpnH"], 15)
    lst = []
    for line in ss.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        proto, local = p[0], p[4]
        port = local.rsplit(":", 1)[-1]
        addr = local.rsplit(":", 1)[0]
        proc = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            proc = m.group(1)
        lst.append({"Proto": proto, "Address": addr, "Port": port, "Process": proc})
        if port.isdigit() and int(port) in DB_PORTS and addr in ("0.0.0.0", "*", "[::]", "::") and proto == "tcp":
            F.add("WARNING", "Security", "%s (port %s) listens on ALL interfaces" % (DB_PORTS[int(port)], port),
                  "Bind it to 127.0.0.1 / private IP or make sure the firewall blocks it from the internet.")
    seen = set()
    uniq = []
    for r in lst:
        k = (r["Proto"], r["Address"], r["Port"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    out.append(section("Listening ports", sorted(uniq, key=lambda r: (r["Proto"], int(r["Port"]) if r["Port"].isdigit() else 0))))

    # conntrack / sockets
    cnt, mx = read("/proc/sys/net/netfilter/nf_conntrack_count").strip(), read("/proc/sys/net/netfilter/nf_conntrack_max").strip()
    misc = {}
    if cnt.isdigit() and mx.isdigit() and int(mx):
        pct = 100 * int(cnt) // int(mx)
        misc["conntrack table"] = "%s / %s (%d%%)" % (cnt, mx, pct)
        if pct >= 80:
            F.add("WARNING", "Network", "Connection-tracking table %d%% full" % pct, "When full, new connections are dropped. Raise net.netfilter.nf_conntrack_max or find the connection flood.")
    rc, sss = run(["ss", "-s"], 10)
    m = re.search(r"TCP:\s+(\d+) \(estab (\d+), closed (\d+), orphaned (\d+), timewait (\d+)", sss)
    if m:
        misc["TCP sockets"] = "%s total, %s established, %s time-wait, %s orphaned" % (m.group(1), m.group(2), m.group(5), m.group(4))
    if misc:
        out.append(section("Connections", misc, True))
    return out


# ---------------------------------------------------------------------------------
#  4. Services & processes
# ---------------------------------------------------------------------------------
def check_services(F, ctx):
    out = []
    if which("systemctl"):
        rc, t = run(["systemctl", "--failed", "--plain", "--no-legend", "--no-pager"], 15)
        failed = []
        for line in t.splitlines():
            p = line.split(None, 4)
            if len(p) >= 4:
                failed.append({"Unit": p[0], "Load": p[1], "Active": p[2], "Sub": p[3], "Description": p[4] if len(p) > 4 else ""})
                F.add("WARNING", "Services", "Service %s has FAILED" % p[0],
                      "See why: `journalctl -u %s -n 50 --no-pager`; restart: `systemctl restart %s` (or disable it if unused)." % (p[0], p[0]))
        out.append(section("Failed units (%d)" % len(failed), failed))

        rc, t = run(["systemctl", "list-units", "--type=service", "--state=running", "--plain", "--no-legend", "--no-pager"], 15)
        running = [l.split()[0] for l in t.splitlines() if l.strip()]
        restarts = []
        if running:
            rc, sh = run(["systemctl", "show", "-p", "Id", "-p", "NRestarts", "-p", "ActiveEnterTimestamp"] + running[:300], 30)
            for block in sh.split("\n\n"):
                kv = dict(l.split("=", 1) for l in block.splitlines() if "=" in l)
                nr = kv.get("NRestarts", "0")
                if nr.isdigit() and int(nr) >= 3:
                    restarts.append({"Service": kv.get("Id"), "Restarts": int(nr), "Running since": kv.get("ActiveEnterTimestamp", "")})
                    F.add("WARNING", "Services", "%s has restarted %s times (crash loop?)" % (kv.get("Id"), nr), "`journalctl -u %s -n 100` to see why it keeps dying." % kv.get("Id"))
        out.append(section("Services with automatic restarts", restarts, note="%d services running." % len(running)))

    # Docker
    if which("docker"):
        rc, t = run(["docker", "ps", "-a", "--format", "{{json .}}"], 20)
        rows = []
        for line in t.splitlines():
            try:
                c = json.loads(line)
            except Exception:
                continue
            st = c.get("Status", "")
            rows.append({"Container": c.get("Names"), "Image": c.get("Image", "")[:40], "State": c.get("State", ""), "Status": st})
            if "unhealthy" in st or "Restarting" in st:
                F.add("WARNING", "Containers", "Container %s is %s" % (c.get("Names"), st), "`docker logs --tail 100 %s`" % c.get("Names"))
            elif c.get("State") == "exited" and not re.search(r"Exited \(0\)", st) and "ago" in st:
                F.add("INFO", "Containers", "Container %s exited: %s" % (c.get("Names"), st), "`docker logs %s` (remove it if no longer needed)." % c.get("Names"))
        if rows or rc == 0:
            out.append(section("Docker containers (%d)" % len(rows), rows))

    # Processes
    rc, t = run(["ps", "-eo", "pid,user,pcpu,pmem,rss,etimes,stat,comm", "--sort=-pcpu", "--no-headers"], 15)
    procs, zombies = [], 0
    for line in t.splitlines():
        p = line.split(None, 7)
        if len(p) < 8:
            continue
        if "Z" in p[6]:
            zombies += 1
        procs.append({"PID": p[0], "User": p[1], "CPU %": float(p[2]), "Mem %": float(p[3]), "RSS": fmt_size(int(p[4]) * 1024),
                      "Running": "%dd %dh" % (int(p[5]) // 86400, (int(p[5]) % 86400) // 3600) if p[5].isdigit() else "", "Command": p[7]})
    out.append(section("Top processes by CPU", procs[:12]))
    out.append(section("Top processes by memory", sorted(procs, key=lambda r: -r["Mem %"])[:12]))
    if zombies >= 20:
        F.add("WARNING", "Processes", "%d zombie processes" % zombies, "A parent process is not reaping its children - restart that service.")
    fnr = read("/proc/sys/fs/file-nr").split()
    if len(fnr) == 3 and fnr[2].isdigit() and int(fnr[2]) > 0 and int(fnr[0]) * 100 // int(fnr[2]) >= 80:
        F.add("WARNING", "Processes", "Open file handles at %d%% of the system limit" % (int(fnr[0]) * 100 // int(fnr[2])), "Raise fs.file-max or find the process leaking file descriptors.")
    return out


# ---------------------------------------------------------------------------------
#  5. Security & updates
# ---------------------------------------------------------------------------------
EOL = {  # standard support end (month precision)
    ("ubuntu", "16.04"): "2021-04", ("ubuntu", "18.04"): "2023-05", ("ubuntu", "20.04"): "2025-05",
    ("ubuntu", "22.04"): "2027-06", ("ubuntu", "24.04"): "2029-06",
    ("debian", "9"): "2022-06", ("debian", "10"): "2024-06", ("debian", "11"): "2026-08", ("debian", "12"): "2028-06",
    ("centos", "7"): "2024-06", ("centos", "8"): "2021-12", ("rhel", "7"): "2024-06",
}


def check_security(F, ctx):
    out = []
    osr = ctx["os"]
    oid, ver = osr.get("ID", ""), osr.get("VERSION_ID", "")
    info = {}

    # End of life
    eol = EOL.get((oid, ver))
    if eol:
        info["Standard support ends"] = eol
        if eol < datetime.now().strftime("%Y-%m"):
            pro = ""
            if which("pro"):
                rc, ps = run(["pro", "status"], 20)
                if re.search(r"esm-infra\s+yes\s+enabled", ps):
                    pro = "esm"
            if pro:
                F.add("INFO", "Security", "%s is past standard support (%s) but Ubuntu Pro ESM is enabled" % (osr.get("PRETTY_NAME"), eol), "Plan an upgrade before ESM ends.")
            else:
                F.add("CRITICAL", "Security", "%s is END OF LIFE since %s - no more security updates" % (osr.get("PRETTY_NAME"), eol),
                      "Upgrade the release (do-release-upgrade / new VM) or enable extended support (Ubuntu Pro ESM / Debian LTS).")

    # Updates
    if which("apt-get"):
        rc, t = run(["apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"], 90)
        inst = [l for l in t.splitlines() if l.startswith("Inst ")]
        sec = [l for l in inst if "-security" in l]
        stamp = None
        for f in ("/var/lib/apt/periodic/update-success-stamp", "/var/cache/apt/pkgcache.bin", "/var/lib/apt/lists"):
            if os.path.exists(f):
                stamp = os.path.getmtime(f)
                break
        age = int((time.time() - stamp) / 86400) if stamp else None
        info["Pending updates"] = "%d (%d security)" % (len(inst), len(sec))
        info["Package lists refreshed"] = ("%d days ago" % age) if age is not None else "unknown"
        auto = read("/etc/apt/apt.conf.d/20auto-upgrades")
        info["Unattended upgrades"] = "enabled" if re.search(r'Unattended-Upgrade\s+"1"', auto) else "disabled"
        if sec:
            F.add("CRITICAL" if len(sec) >= 20 else "WARNING", "Updates", "%d security updates pending" % len(sec),
                  "`sudo apt update && sudo apt upgrade` (then reboot if a kernel was updated).")
        elif inst:
            F.add("INFO", "Updates", "%d package updates pending" % len(inst), "`sudo apt upgrade`")
        if age is not None and age > 14:
            F.add("WARNING", "Updates", "Package lists not refreshed for %d days" % age, "`apt update` is not running - update counts may be wrong and security fixes missed.")
        if info["Unattended upgrades"] == "disabled":
            F.add("INFO", "Updates", "Automatic security updates are disabled", "`sudo dpkg-reconfigure -plow unattended-upgrades` (unless you patch another way).")
        out.append(section("Pending upgrades", [l[5:][:110] for l in inst[:40]], note="Showing up to 40. Lines containing -security are security fixes."))
    elif which("dnf") or which("yum"):
        tool = which("dnf") or which("yum")
        rc, t = run([tool, "-q", "check-update", "--security"], 120)
        n = len([l for l in t.splitlines() if l.strip() and not l.startswith(("Last metadata", "Security:"))])
        rc2, t2 = run([tool, "-q", "check-update"], 120)
        n2 = len([l for l in t2.splitlines() if re.match(r"^\S+\.\S+\s+\S+\s+\S+", l)])
        info["Pending updates"] = "%d (%d security)" % (n2, n)
        if n:
            F.add("WARNING", "Updates", "%d security updates pending" % n, "`sudo %s upgrade --security`" % os.path.basename(tool))

    # Firewall
    fw = "none detected"
    if which("ufw"):
        rc, t = run(["ufw", "status"], 10)
        if "Status: active" in t:
            fw = "ufw (active)"
    if fw == "none detected" and which("firewall-cmd"):
        rc, t = run(["firewall-cmd", "--state"], 10)
        if "running" in t:
            fw = "firewalld (running)"
    if fw == "none detected" and which("nft") and is_root():
        rc, t = run(["nft", "list", "ruleset"], 10)
        if len([l for l in t.splitlines() if l.strip().startswith(("tcp", "udp", "ip ", "iifname", "ct state", "counter"))]) > 2:
            fw = "nftables rules"
    if fw == "none detected" and which("iptables") and is_root():
        rc, t = run(["iptables", "-S"], 10)
        rules = [l for l in t.splitlines() if l.startswith("-A")]
        if len(rules) > 3 or "-P INPUT DROP" in t:
            fw = "iptables (%d rules)" % len(rules)
    info["Firewall"] = fw
    if fw == "none detected" and is_root():
        F.add("WARNING", "Security", "No host firewall is active", "OK only if a cloud security group / network firewall protects this server. Otherwise: `ufw allow OpenSSH && ufw enable`.")

    # SSH
    ssh = {}
    if which("sshd") and is_root():
        rc, t = run(["sshd", "-T"], 10)
        for line in t.splitlines():
            p = line.split(None, 1)
            if len(p) == 2:
                ssh[p[0]] = p[1]
    ctx["sshd"] = ssh
    if ssh:
        info["SSH port"] = ssh.get("port", "22")
        info["SSH root login"] = ssh.get("permitrootlogin", "?")
        info["SSH password login"] = ssh.get("passwordauthentication", "?")
        if ssh.get("permitrootlogin") == "yes":
            F.add("WARNING", "Security", "SSH allows root login with a password", "Set `PermitRootLogin prohibit-password` (or no) in /etc/ssh/sshd_config.d/ and use keys.")
        if ssh.get("passwordauthentication") == "yes":
            F.add("INFO", "Security", "SSH password authentication is enabled", "Use SSH keys and set `PasswordAuthentication no`, or protect with fail2ban.")
    if which("fail2ban-client") and is_root():
        rc, t = run(["fail2ban-client", "status"], 10)
        m = re.search(r"Jail list:\s*(.*)", t)
        info["fail2ban"] = ("jails: " + m.group(1).strip()) if m else "installed"
    else:
        info["fail2ban"] = "not installed"

    # MAC
    if which("aa-status"):
        rc, _ = run(["aa-status", "--enabled"], 5)
        info["AppArmor"] = "enabled" if rc == 0 else "disabled"
    if which("getenforce"):
        rc, t = run(["getenforce"], 5)
        info["SELinux"] = t.strip()

    # Accounts
    uid0 = [l.split(":")[0] for l in read("/etc/passwd").splitlines() if l.count(":") >= 3 and l.split(":")[2] == "0" and l.split(":")[0] != "root"]
    if uid0:
        F.add("CRITICAL", "Security", "Extra accounts with UID 0 (root powers): %s" % ", ".join(uid0), "Unless you created them on purpose this is a backdoor - investigate now.")
    empty = []
    if is_root():
        for l in read("/etc/shadow").splitlines():
            p = l.split(":")
            if len(p) > 2 and p[1] == "":
                empty.append(p[0])
        if empty:
            F.add("CRITICAL", "Security", "Accounts with NO password: %s" % ", ".join(empty), "`passwd -l <user>` to lock them.")
    sudoers = []
    for grp in ("sudo", "wheel", "admin"):
        m = re.search(r"^%s:[^:]*:\d+:(.*)$" % grp, read("/etc/group"), re.M)
        if m and m.group(1).strip():
            sudoers += m.group(1).strip().split(",")
    info["Admin (sudo) users"] = ", ".join(sorted(set(sudoers))) or "-"
    out.insert(0, section("Security overview", info, True))

    rc, t = run(["last", "-n", "10", "-w", "-F"], 10) if which("last") else (1, "")
    logins = [l for l in t.splitlines() if l.strip() and not l.startswith(("wtmp", "reboot"))][:10]
    if logins:
        out.append(section("Recent logins", logins))

    # TLS certificates (Let's Encrypt / common paths)
    certs = []
    if which("openssl"):
        paths = glob.glob("/etc/letsencrypt/live/*/cert.pem") + glob.glob("/etc/ssl/private/*.crt") + glob.glob("/etc/nginx/ssl/*.crt") + glob.glob("/etc/pki/tls/certs/*.crt")
        for pth in paths[:30]:
            rc, t = run(["openssl", "x509", "-enddate", "-subject", "-noout", "-in", pth], 10)
            m = re.search(r"notAfter=(.+)", t)
            if not m:
                continue
            try:
                end = datetime.strptime(m.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                continue
            days = (end - datetime.utcnow()).days
            subj = re.search(r"subject=(.+)", t)
            certs.append({"Certificate": pth, "Subject": (subj.group(1).strip() if subj else "")[:60], "Expires": end.strftime("%Y-%m-%d"), "Days left": days})
            if days < 0:
                F.add("CRITICAL", "Certificates", "TLS certificate EXPIRED: %s" % pth, "Renew it (`certbot renew`) and reload the web server.")
            elif days < 14:
                F.add("CRITICAL", "Certificates", "TLS certificate expires in %d days: %s" % (days, pth), "`certbot renew --dry-run` to see why auto-renew fails.")
            elif days < 30:
                F.add("WARNING", "Certificates", "TLS certificate expires in %d days: %s" % (days, pth), "Check that auto-renewal works.")
    if certs:
        out.append(section("TLS certificates", certs))
    return out


# ---------------------------------------------------------------------------------
#  6. Platform: virtualization / cloud / hardware
# ---------------------------------------------------------------------------------
GUEST_AGENTS = {
    "microsoft": [("hv_kvp_daemon", "hyperv-daemons / linux-cloud-tools (KVP)"), ("hv_vss_daemon", "Hyper-V VSS daemon (backups)")],
    "vmware": [("vmtoolsd", "open-vm-tools")],
    "kvm": [("qemu-ga", "qemu-guest-agent")],
    "qemu": [("qemu-ga", "qemu-guest-agent")],
    "oracle": [("VBoxService", "VirtualBox Guest Additions")],
    "xen": [("xe-daemon", "xe-guest-utilities")],
}


def _procs():
    names = set()
    for p in glob.glob("/proc/[0-9]*/comm"):
        names.add(read(p).strip())
    return names


def check_platform(F, ctx):
    out = []
    virt = ctx["virt"]
    dmi = {k: read("/sys/class/dmi/id/" + k).strip() for k in ("sys_vendor", "product_name", "bios_vendor", "bios_version", "chassis_asset_tag", "board_vendor")}
    cloud = ""
    if dmi["chassis_asset_tag"] == "7783-7084-3265-9085-8269-3286-77":
        cloud = "Microsoft Azure"
    elif "Amazon" in dmi["sys_vendor"] or dmi["bios_vendor"].startswith("Amazon") or "amazon" in dmi["bios_version"].lower():
        cloud = "AWS EC2"
    elif "Google" in dmi["sys_vendor"]:
        cloud = "Google Cloud"
    elif "DigitalOcean" in dmi["sys_vendor"]:
        cloud = "DigitalOcean"
    elif "Hetzner" in dmi["sys_vendor"]:
        cloud = "Hetzner Cloud"
    elif "OpenStack" in dmi["product_name"]:
        cloud = "OpenStack"
    elif "Proxmox" in dmi["product_name"] or "Proxmox" in dmi["bios_version"]:
        cloud = "Proxmox VE"
    rc, cont = run(["systemd-detect-virt", "-c"], 5) if which("systemd-detect-virt") else (1, "none")
    info = {"Hypervisor": virt, "Container": cont.strip() or "none", "Cloud / platform": cloud or "-",
            "Vendor / model": ("%s / %s" % (dmi["sys_vendor"], dmi["product_name"])).strip(" /"),
            "BIOS": ("%s %s" % (dmi["bios_vendor"], dmi["bios_version"])).strip(),
            "Clocksource": read("/sys/devices/system/clocksource/clocksource0/current_clocksource").strip()}
    steal = ctx["perf"]["cpu"]["steal"]
    info["CPU steal (sample)"] = "%s %%" % steal
    out.append(section("Platform", info, True))

    if virt != "none" and (cont.strip() or "none") == "none":
        procs = _procs()
        agents = []
        key = "microsoft" if virt in ("microsoft", "hyperv") else virt
        for proc, pkg in GUEST_AGENTS.get(key, []):
            agents.append({"Agent": pkg, "Process": proc, "Running": "yes" if proc in procs else "NO"})
        if cloud == "Microsoft Azure":
            agents.append({"Agent": "Azure Linux Agent (walinuxagent)", "Process": "waagent", "Running": "yes" if any("waagent" in p or "python" in p for p in procs) and os.path.exists("/var/lib/waagent") else "NO"})
        if cloud == "AWS EC2":
            agents.append({"Agent": "AWS SSM agent (optional)", "Process": "amazon-ssm-agent", "Running": "yes" if "amazon-ssm-agen" in procs or "amazon-ssm-agent" in procs else "no"})
        out.append(section("Guest agent / integration services", agents))
        for a in agents:
            if a["Running"] == "NO" and "optional" not in a["Agent"]:
                F.add("WARNING", "Virtualization", "%s is not running on this %s VM" % (a["Agent"], virt),
                      "Install/start it (e.g. `apt install %s`) so the host can shut down, back up and monitor the VM cleanly." %
                      {"vmtoolsd": "open-vm-tools", "qemu-ga": "qemu-guest-agent", "hv_kvp_daemon": "linux-cloud-tools-virtual hyperv-daemons"}.get(a["Process"], a["Agent"].split()[0]))
        if not [a for a in agents if a["Running"] == "NO"] and agents:
            F.add("OK", "Virtualization", "Running on %s%s with guest agent OK" % (virt, (" (" + cloud + ")") if cloud else ""))
        if steal >= 15:
            F.add("CRITICAL", "Virtualization", "CPU steal is %.0f%% - the hypervisor is not giving this VM its CPU time" % steal, "The host is overcommitted: move VMs, reduce vCPUs elsewhere or ask your provider.")
        elif steal >= 5:
            F.add("WARNING", "Virtualization", "CPU steal is %.0f%%" % steal, "Some host CPU contention - watch performance.")
        if which("cloud-init"):
            rc, t = run(["cloud-init", "status"], 15)
            if "error" in t:
                F.add("WARNING", "Virtualization", "cloud-init finished with errors", "`cloud-init status --long` and /var/log/cloud-init.log")

    # time sync quality
    tq = {}
    if which("chronyc"):
        rc, t = run(["chronyc", "tracking"], 10)
        m = re.search(r"System time\s*:\s*([\d.]+) seconds (fast|slow)", t)
        if m:
            tq["Offset"] = "%s s %s" % (m.group(1), m.group(2))
            if float(m.group(1)) > 0.5:
                F.add("WARNING", "Time", "Clock is %s s %s of NTP" % (m.group(1), m.group(2)), "Check chrony sources: `chronyc sources -v`.")
        m = re.search(r"Reference ID\s*:\s*\S+ \(([^)]*)\)", t)
        if m:
            tq["Source"] = m.group(1)
    elif which("timedatectl"):
        rc, t = run(["timedatectl", "timesync-status"], 10)
        m = re.search(r"Offset:\s*(\S+)", t)
        if m:
            tq["Offset"] = m.group(1)
        m = re.search(r"Server:\s*(.+)", t)
        if m:
            tq["Source"] = m.group(1).strip()
    if tq:
        out.append(section("Time synchronisation", tq, True))

    # Physical hardware
    if virt == "none":
        temps = []
        for hw in glob.glob("/sys/class/hwmon/hwmon*"):
            name = read(hw + "/name").strip()
            for tin in glob.glob(hw + "/temp*_input"):
                try:
                    v = int(read(tin).strip()) / 1000.0
                except ValueError:
                    continue
                lab = read(tin.replace("_input", "_label")).strip() or os.path.basename(tin)
                temps.append({"Sensor": name, "Label": lab, "Temp C": v})
        if temps:
            hot = sorted(temps, key=lambda t: -t["Temp C"])
            out.append(section("Temperatures", hot[:15]))
            if hot[0]["Temp C"] >= 90 and hot[0]["Sensor"] in ("coretemp", "k10temp", "zenpower"):
                F.add("WARNING", "Hardware", "CPU temperature %.0f C" % hot[0]["Temp C"], "Check fans, heatsinks and datacenter/room cooling.")
        edac = []
        for mc in glob.glob("/sys/devices/system/edac/mc/mc*"):
            ce, ue = read(mc + "/ce_count").strip(), read(mc + "/ue_count").strip()
            edac.append({"Controller": os.path.basename(mc), "Corrected (CE)": ce, "Uncorrected (UE)": ue})
            if ue.isdigit() and int(ue) > 0:
                F.add("CRITICAL", "Hardware", "%s uncorrectable memory errors on %s" % (ue, os.path.basename(mc)), "Faulty RAM - identify the DIMM (`edac-util -v`, BMC/iDRAC/iLO log) and replace it.")
            elif ce.isdigit() and int(ce) >= 10:
                F.add("WARNING", "Hardware", "%s corrected memory (ECC) errors on %s" % (ce, os.path.basename(mc)), "A DIMM is degrading - check the BMC log and plan replacement.")
        if edac:
            out.append(section("ECC memory (EDAC)", edac))
        if which("ipmitool") and is_root():
            rc, t = run(["ipmitool", "sel", "elist", "last", "40"], 30)
            lines = [l.strip() for l in t.splitlines() if l.strip()]
            if lines:
                out.append(section("BMC / IPMI event log (last 40)", lines))
                bad = [l for l in lines if re.search(r"(Uncorrectable|Critical|Failure|Power Supply.*(lost|fail)|Correctable ECC|Predictive Failure)", l, re.I) and "Deasserted" not in l]
                if bad:
                    F.add("WARNING", "Hardware", "%d hardware events in the BMC log (e.g. %s)" % (len(bad), bad[-1][:80]), "Review with `ipmitool sel elist` or the iDRAC/iLO web UI.")
    return out


# ---------------------------------------------------------------------------------
#  Runner
# ---------------------------------------------------------------------------------
CHECKS = [("system", "System", check_system), ("storage", "Storage", check_storage), ("network", "Network", check_network),
          ("services", "Services", check_services), ("security", "Security", check_security), ("platform", "Platform", check_platform)]


def detect_virt():
    if which("systemd-detect-virt"):
        rc, t = run(["systemd-detect-virt", "-v"], 5)
        return t.strip() or "none"
    cpuinfo = read("/proc/cpuinfo")
    if " hypervisor" in cpuinfo:
        v = read("/sys/class/dmi/id/sys_vendor").lower()
        for k in ("vmware", "microsoft", "qemu", "xen", "innotek"):
            if k in v:
                return {"innotek": "oracle"}.get(k, k)
        return "vm"
    return "none"


def collect(progress=None):
    """Run all checks. Returns (ctx, checks dict)."""
    from .common import Findings
    ctx = {"os": os_release(), "virt": detect_virt()}
    if progress:
        progress("Sampling performance (2 s)...")
    ctx["perf"] = perf_sample(2.0)
    checks = {}
    for key, title, fn in CHECKS:
        if progress:
            progress("Checking %s..." % title)
        F = Findings()
        try:
            secs = fn(F, ctx)
            err = None
        except Exception as e:  # never let one check kill the run
            import traceback
            secs, err = [], "%s: %s" % (type(e).__name__, traceback.format_exc(limit=3)[-400:])
        checks[key] = {"title": title, "sections": secs, "findings": F.items, "error": err}
    return ctx, checks
