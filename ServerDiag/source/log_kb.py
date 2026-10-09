"""
ServerDiag Log Analyzer (Linux)
-------------------------------
Reads journald (or /var/log/syslog as fallback), matches messages against a pattern
knowledge base and ranks the likely root causes: NVMe, disk, filesystem, RAID, RAM, CPU,
OOM / memory pressure, kernel bugs, hung I/O, network, services, SSH brute force,
time, hypervisor problems, unclean shutdowns...
"""
import glob
import json
import math
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta

from .common import run, which, read

# ---------------------------------------------------------------------------------
#  Categories
# ---------------------------------------------------------------------------------
CATEGORIES = {
    "NVME": ("NVMe SSD / controller", "The NVMe drive is timing out, resetting or returning errors.",
             ["Check drive health: `smartctl -a /dev/nvme0` (media errors, critical warning, wear).",
              "Update the SSD firmware and the server BIOS.",
              "Disable APST power saving as a test: kernel parameter `nvme_core.default_ps_max_latency_us=0`.",
              "Back up now if media errors are growing; replace the drive."]),
    "DISK": ("Disk / controller / cable (SATA/SAS)", "A drive or its path (cable, backplane, HBA/RAID controller) is returning errors or timing out.",
             ["`smartctl -a /dev/sdX` - look at reallocated/pending sectors and CRC errors.",
              "CRC / link resets usually mean a bad cable or backplane slot - reseat or replace it.",
              "Check the RAID controller / HBA logs (storcli, ssacli, perccli) and firmware.",
              "Back up and replace the drive if bad sectors keep growing."]),
    "FS": ("Filesystem corruption", "The kernel found damaged filesystem structures, often followed by a read-only remount.",
           ["Find the device in the evidence, then run fsck from maintenance/rescue mode (`fsck -f /dev/...` unmounted; xfs_repair for XFS).",
            "Check the underlying disk first (SMART, RAID state) - corruption is usually a symptom.",
            "Restore from backup if repair fails."]),
    "SPACE": ("Disk full", "Programs failed with 'No space left on device'.",
              ["`df -h` and `df -i`; find big dirs: `du -xh / --max-depth=2 | sort -h | tail -20`.",
               "`journalctl --vacuum-size=500M`, `apt clean`, rotate logs, `docker system prune`."]),
    "RAID": ("RAID / ZFS array", "A RAID or ZFS array lost a member or reported checksum/IO errors.",
             ["`cat /proc/mdstat`, `mdadm --detail /dev/mdX` or `zpool status -v`.",
              "Replace the failed disk and re-add / `zpool replace` it.",
              "Make sure mdadm/ZED email alerts are configured."]),
    "RAM": ("Memory (RAM / ECC)", "The memory controller reported corrected or uncorrected errors.",
            ["Identify the DIMM: `edac-util -v`, `ras-mc-ctl --errors` or the BMC (iDRAC/iLO) log.",
             "Reseat or replace the failing DIMM; update BIOS.",
             "Run a memory test (memtest86+) in a maintenance window."]),
    "CPU": ("CPU / machine check", "The CPU reported hardware errors (MCE).",
            ["Decode with `rasdaemon` / `mcelog` to find the bank and component.",
             "Update BIOS/microcode (`intel-microcode` / `amd64-microcode`).",
             "Check temperatures and power; contact the hardware vendor if errors persist."]),
    "PCIE": ("PCIe device / slot", "A PCI Express device reported AER errors.",
             ["Find the device in the evidence (`lspci -s <addr>`).",
              "Reseat the card / NVMe; update firmware and BIOS.",
              "Try `pcie_aspm=off` if corrected errors flood the log."]),
    "THERMAL": ("Overheating / throttling", "CPUs were throttled or hit critical temperature.",
                ["Check fans, airflow, dust and room/rack temperature.", "Check BMC sensor readings (`ipmitool sdr`)."]),
    "MEMPRESSURE": ("Out of memory (OOM kills)", "The kernel (or systemd-oomd) killed processes because RAM ran out.",
                    ["See which process was killed and which one was using the most memory at the time.",
                     "Add RAM/swap, limit the app (e.g. JVM -Xmx, PHP-FPM pm.max_children, DB buffers) or set MemoryMax= for the service.",
                     "For containers: raise the memory limit or fix the leak."]),
    "KERNEL": ("Kernel bug / crash", "The kernel hit a BUG, Oops or panic - usually a driver or kernel bug (or bad hardware).",
               ["Update the kernel (`apt full-upgrade`) and reboot.",
                "Look at the module named in the call trace; update or remove that driver/DKMS module.",
                "If it recurs across kernels, suspect RAM/CPU hardware."]),
    "HUNG": ("Hung tasks / CPU lockups (I/O stalls)", "Tasks were blocked for minutes or CPUs stopped responding - almost always slow/hung storage or an overloaded hypervisor.",
             ["Check storage latency (Storage tab) and the SAN/NFS/iSCSI path.",
              "On a VM: check the host for CPU/storage overcommit, snapshots, backups running.",
              "Update kernel and storage/virtio drivers."]),
    "NETWORK": ("Network", "Network interfaces flapped, NIC timed out, or connection tables overflowed.",
                ["Check cable/switch port and NIC firmware/driver (`ethtool -i`, `ethtool -S`).",
                 "conntrack full: raise `net.netfilter.nf_conntrack_max` or reduce connections.",
                 "Bond failover: check both links and switch config (LACP)."]),
    "SERVICE": ("Failing services", "systemd services are failing or stuck in restart loops.",
                ["`systemctl status <unit>` and `journalctl -u <unit> -n 100`.",
                 "Fix the config error / dependency, then `systemctl restart <unit>`.",
                 "Disable services you do not need."]),
    "APP": ("Crashing applications", "Programs crashed with segfaults or core dumps.",
            ["Update the application and its libraries.", "`coredumpctl list` / `coredumpctl info <pid>` for details.",
             "If many unrelated programs crash, test RAM."]),
    "SECURITY": ("SSH brute force / authentication", "Many failed login attempts were recorded.",
                 ["Disable password logins (`PasswordAuthentication no`) and use SSH keys.",
                  "Install fail2ban or restrict SSH to known IPs (firewall / VPN).",
                  "Check `last` / `journalctl -u ssh` for any SUCCESSFUL logins from unknown IPs."]),
    "TIME": ("Clock / time sync", "The clock drifted, jumped or the clocksource was unstable.",
             ["Make sure chrony/timesyncd is running and reachable NTP servers are configured.",
              "On VMs: use the hypervisor clocksource (kvm-clock / hyperv) and disable conflicting host time sync."]),
    "VIRT": ("Hypervisor / virtual hardware", "Virtual device drivers (Hyper-V, VMware, virtio, Xen) reported errors or timeouts.",
             ["Check the host: storage latency, CPU overcommit, snapshots/backups at that time.",
              "Update guest tools/integration services and the guest kernel.",
              "Correlate the timestamps with host events."]),
    "POWER": ("Unclean shutdowns / power loss", "The server stopped without a clean shutdown and without a logged kernel panic.",
              ["Physical: check PSUs, UPS and BMC log (`ipmitool sel elist`) for power events.",
               "VM: check the hypervisor for host crashes, forced resets or out-of-memory on the host.",
               "Enable kdump so the next kernel crash leaves a dump (`apt install kdump-tools`)."]),
    "UPDATE": ("Package updates", "Automatic upgrades or package installs failed.",
               ["Run `sudo apt update && sudo apt upgrade` manually and read the error.", "`sudo dpkg --configure -a` if dpkg was interrupted."]),
    "BIOS": ("Firmware / ACPI / IOMMU", "Firmware tables or the IOMMU reported errors (often harmless on some hardware).",
             ["Update the BIOS/UEFI firmware.", "Ignore isolated 'ACPI Error: AE_NOT_FOUND' messages if nothing else is wrong."]),
}

# ---------------------------------------------------------------------------------
#  Patterns: (id, regex, cats, meaning-template, kind)
#  meaning-template can use named groups, e.g. {proc}. kind: event|crash|info
# ---------------------------------------------------------------------------------
P = [
    # NVMe
    ("nvme_timeout", r"nvme\d+(?:n\d+)?:?.*I/O (?:\d+ )?(?:\(\w+\) )?QID \d+ timeout", {"NVME": 6}, "NVMe I/O timeout", "event"),
    ("nvme_down", r"nvme\d+: .*(controller is down|Removing after probe failure|Device not ready|Shutdown timeout|failed to set APST)", {"NVME": 9}, "NVMe controller failure / removed", "crash"),
    ("nvme_reset", r"nvme\d+: .*resetting controller", {"NVME": 5}, "NVMe controller reset", "event"),
    ("nvme_ioerr", r"(?P<dev>nvme\d+n\d+): I/O Cmd\(0x\w+\) @ LBA \d+, \d+ blocks, I/O Error", {"NVME": 6}, "NVMe command I/O error on {dev}", "event"),
    ("nvme_media", r"critical medium error, dev (?P<dev>nvme\S+)", {"NVME": 9}, "Unreadable data on {dev}", "event"),
    # SATA / SCSI
    ("ata_err", r"(?P<dev>ata\d+(?:\.\d+)?): (exception Emask|failed command|SError:|hard resetting link|COMRESET failed|link is slow to respond|limiting SATA link speed)", {"DISK": 4}, "SATA link / command errors on {dev} (cable, port or drive)", "event"),
    ("medium", r"(critical medium error|Medium Error|Unrecovered read error|Sense Key : Medium Error)", {"DISK": 8}, "Unreadable sectors (medium error)", "event"),
    ("hwerr", r"Sense Key : Hardware Error", {"DISK": 7}, "Drive reported a hardware error", "event"),
    ("ioerr", r"I/O error, dev (?P<dev>[a-z]+\d*(?:n\d+)?), sector", {"DISK": 6}, "I/O error on /dev/{dev}", "event"),
    ("blkupd", r"blk_update_request: (critical )?(I/O|medium|target|critical target) error, dev (?P<dev>\S+)", {"DISK": 6}, "Block I/O error on /dev/{dev}", "event"),
    ("bufio", r"Buffer I/O error on dev (?P<dev>[^,\s]+)", {"DISK": 5}, "Buffer I/O error on {dev}", "event"),
    ("scsi_to", r"sd \S+: \[(?P<dev>\w+)\] (tag#\d+ )?(FAILED Result|timing out command|task abort|abort)", {"DISK": 4, "VIRT": 1}, "SCSI command timeout/abort on {dev}", "event"),
    ("smartd", r"^(Device: )?/dev/(?P<dev>\S+).*(FAILED|Currently unreadable|Offline uncorrectable|Prefailure|failure|ATA error count increased)", {"DISK": 8}, "smartd reports a problem on /dev/{dev}", "event"),
    ("raidctl", r"(megaraid_sas|mpt\dsas|mpt3sas|aacraid|hpsa|smartpqi|arcmsr)\S*:? .*(fault|FW in FAULT|reset|error|failed)", {"DISK": 5}, "RAID controller / HBA error", "event"),
    # FS
    ("ext4_ro", r"EXT4-fs \((?P<dev>[^)]+)\): (Remounting filesystem read-only|Aborting journal|previous I/O error to superblock)", {"FS": 10}, "{dev} filesystem was remounted READ-ONLY", "crash"),
    ("ext4_err", r"EXT4-fs error \(device (?P<dev>[^)]+)\)", {"FS": 8}, "ext4 filesystem error on {dev}", "event"),
    ("xfs_err", r"XFS \((?P<dev>[^)]+)\): (Corruption|metadata I/O error|Internal error|Filesystem has been shut down|log I/O error|Metadata corruption)", {"FS": 9}, "XFS error on {dev}", "event"),
    ("btrfs_err", r"BTRFS (error|critical) \(device (?P<dev>[^)]+)\)", {"FS": 7}, "Btrfs error on {dev}", "event"),
    ("jbd2", r"JBD2: .*(error|Detected IO errors)", {"FS": 6}, "Journal (JBD2) I/O error", "event"),
    ("nospace", r"No space left on device", {"SPACE": 5}, "No space left on device", "event"),
    ("mountfail", r"Failed to mount (?P<what>.+?)\.?$", {"FS": 4}, "Failed to mount {what}", "event"),
    # RAID / ZFS
    ("md_fail", r"md/raid\d*:(?P<dev>md\d+): (Disk failure on|Operation continuing on \d+ devices)", {"RAID": 10}, "RAID {dev} lost a disk (degraded)", "crash"),
    ("mdadm", r"mdadm.*(Fail|DegradedArray|DeviceDisappeared)", {"RAID": 9}, "mdadm reported a failed/degraded array", "crash"),
    ("zfs", r"class=(?P<cls>checksum|io|data|deadman|statechange|probe_failure)\b.*pool[=' ]+'?(?P<pool>[\w-]+)", {"RAID": 5, "DISK": 2}, "ZFS {cls} event on pool {pool}", "event"),
    # Memory / CPU / PCIe
    ("edac_ue", r"EDAC .*(UE|Uncorrected|uncorrectable)", {"RAM": 12}, "UNCORRECTABLE memory error (ECC)", "crash"),
    ("edac_ce", r"EDAC .*\b(CE|[Cc]orrected)\b", {"RAM": 5}, "Corrected memory (ECC) error", "event"),
    ("mce_mem", r"mce: \[Hardware Error\]: .*(Memory|memory|MEMORY)", {"RAM": 7}, "Machine check: memory error", "event"),
    ("mce", r"mce: \[Hardware Error\]", {"CPU": 7}, "Machine check (hardware error) reported by CPU", "event"),
    ("mce_log", r"Machine check events logged", {"CPU": 4}, "Machine check events logged", "event"),
    ("nmi", r"(Uhhuh\. NMI received|NMI: PCI system error|NMI: IOCK error)", {"CPU": 4, "PCIE": 2}, "NMI - hardware signalled a fault", "event"),
    ("aer_ce", r"AER: (Multiple )?Corrected error received(: (?P<dev>\S+))?", {"PCIE": 3}, "PCIe corrected error {dev}", "event"),
    ("aer_ue", r"AER: (Multiple )?Uncorrected \((Non-Fatal|Fatal)\) error received(: (?P<dev>\S+))?", {"PCIE": 8}, "PCIe UNCORRECTED error {dev}", "event"),
    ("iommu", r"(DMAR|AMD-Vi|iommu).*(fault|IO_PAGE_FAULT|Event logged)", {"BIOS": 3, "PCIE": 2}, "IOMMU fault (device DMA error)", "event"),
    # Thermal
    ("throttle", r"(Core|Package) temperature above threshold, cpu clock throttled", {"THERMAL": 5}, "CPU throttled - temperature above threshold", "event"),
    ("thermal_crit", r"(critical temperature reached|thermal_zone\d+: critical)", {"THERMAL": 10}, "CRITICAL temperature reached", "crash"),
    # Memory pressure
    ("oom", r"Out of memory: Killed process \d+ \((?P<proc>[^)]+)\)", {"MEMPRESSURE": 7}, "OOM killer killed {proc}", "crash"),
    ("oom_cg", r"Memory cgroup out of memory: Killed process \d+ \((?P<proc>[^)]+)\)", {"MEMPRESSURE": 4}, "Container/cgroup memory limit hit - {proc} killed", "event"),
    ("oomd", r"systemd-oomd.*Killed (?P<proc>\S+)", {"MEMPRESSURE": 5}, "systemd-oomd killed {proc}", "event"),
    ("pgalloc", r"(?P<proc>\S+): page allocation failure", {"MEMPRESSURE": 3}, "Kernel memory allocation failure ({proc})", "event"),
    # Kernel
    ("panic", r"Kernel panic - not syncing", {"KERNEL": 12}, "KERNEL PANIC", "crash"),
    ("oops", r"(kernel BUG at|BUG: unable to handle|BUG: kernel NULL pointer|Oops: |general protection fault)", {"KERNEL": 9}, "Kernel BUG / Oops", "crash"),
    ("kwarn", r"WARNING: CPU: \d+ PID: \d+ at (?P<where>\S+)", {"KERNEL": 2}, "Kernel warning in {where}", "event"),
    ("softlock", r"watchdog: BUG: soft lockup - CPU#\d+ stuck for", {"HUNG": 7, "VIRT": 2}, "CPU soft lockup", "crash"),
    ("hardlock", r"(Watchdog detected hard LOCKUP|NMI watchdog: .*hard LOCKUP)", {"HUNG": 9}, "CPU hard lockup", "crash"),
    ("rcu", r"(rcu: INFO: rcu_\w+ (self-)?detected (expedited )?stalls?|rcu_sched self-detected stall|rcu_preempt detected stalls)", {"HUNG": 6, "VIRT": 2}, "RCU stall (CPU not responding)", "event"),
    ("hungtask", r"INFO: task (?P<proc>[^:]+):\d+ blocked for more than \d+ seconds", {"HUNG": 5, "DISK": 2}, "Task {proc} blocked >120 s (waiting on I/O)", "event"),
    ("hrtimer", r"hrtimer: interrupt took \d+ ns", {"VIRT": 2}, "Timer interrupt delayed (host contention)", "event"),
    # Apps
    ("segv", r"(?P<proc>[\w.@+-]+)\[\d+\]: segfault at", {"APP": 2}, "{proc} crashed (segfault)", "event"),
    ("trap", r"traps: (?P<proc>[\w.@+-]+)\[\d+\] (general protection|trap)", {"APP": 2}, "{proc} crashed (trap)", "event"),
    ("core", r"Process \d+ \((?P<proc>[^)]+)\) of user \d+ dumped core", {"APP": 2}, "{proc} dumped core", "event"),
    # Time
    ("clocksrc", r"clocksource.*(unstable|Marking clocksource .* as unstable|timekeeping watchdog)", {"TIME": 4, "VIRT": 3}, "Unstable clocksource", "event"),
    ("clockwrong", r"System clock wrong by (?P<sec>-?[\d.]+) seconds", {"TIME": 5}, "Clock was wrong by {sec} s", "event"),
    ("ntpfail", r"(Can't synchronise: no selectable sources|No suitable source|no servers can be used|Timed out waiting for reply from)", {"TIME": 2}, "Time sync cannot reach NTP servers", "event"),
    # Hypervisors
    ("hyperv", r"(hv_vmbus|hv_netvsc|hv_storvsc|hv_balloon|hv_utils|hv_vss|hv_kvp)\S*:? .*(error|fail|timeout|unable|Unable)", {"VIRT": 4}, "Hyper-V driver error", "event"),
    ("storvsc", r"storvsc.*(abort|reset|SRB status|cmd 0x\w+ scsi status)", {"VIRT": 4, "DISK": 2}, "Hyper-V storage (storvsc) error/abort", "event"),
    ("vmware", r"(vmw_pvscsi.*(abort|reset)|vmxnet3.*(tx hang|resetting|Error))", {"VIRT": 4}, "VMware virtual device error", "event"),
    ("virtio", r"(virtio_\w+|virtio-pci|virtio\d+).*(error|fail|timeout)", {"VIRT": 3}, "virtio device error", "event"),
    ("xen", r"xen\S*:? .*(error|fail)", {"VIRT": 2}, "Xen driver error", "event"),
    # Network
    ("netdev_wd", r"NETDEV WATCHDOG: (?P<dev>\S+)", {"NETWORK": 8}, "NIC {dev} transmit timeout (driver/firmware/hardware)", "event"),
    ("linkdown", r"(?P<dev>(eth|ens|enp|eno|em|bond|p\d+p)\S*): (Link is Down|NIC Link is Down)", {"NETWORK": 3}, "{dev} link down", "event"),
    ("conntrack", r"nf_conntrack: (nf_conntrack: )?table full, dropping packet", {"NETWORK": 8}, "conntrack table FULL - connections dropped", "event"),
    ("synflood", r"Possible SYN flooding on port (?P<port>\d+)", {"NETWORK": 3, "SECURITY": 2}, "Possible SYN flood on port {port}", "event"),
    ("neigh", r"neighbour( table)?:? .*(table overflow|neighbor table overflow)", {"NETWORK": 5}, "ARP/neighbour table overflow", "event"),
    ("bond", r"(?P<dev>bond\d+): .*(link status definitely down|now running without any active interface)", {"NETWORK": 7}, "Bond {dev} lost a link", "event"),
    ("dhcp", r"(No DHCPOFFERS received|DHCPv[46] .*(timed out|failed)|Could not acquire DHCP|DHCP lease lost)", {"NETWORK": 4}, "DHCP failure", "event"),
    # Services
    ("svc_fail", r"(?P<unit>[\w@.:-]+\.service): Failed with result '(?P<res>[\w-]+)'", {"SERVICE": 3}, "{unit} failed ({res})", "event"),
    ("svc_loop", r"(?P<unit>[\w@.:-]+\.service): Start request repeated too quickly", {"SERVICE": 5}, "{unit} crash loop (start limit hit)", "event"),
    ("svc_kill", r"(?P<unit>[\w@.:-]+\.service): Main process exited, code=(killed|dumped), status=(?P<st>\S+)", {"SERVICE": 3}, "{unit} was killed ({st})", "event"),
    ("svc_wd", r"(?P<unit>[\w@.:-]+\.service): Watchdog timeout", {"SERVICE": 5}, "{unit} watchdog timeout (hung)", "event"),
    ("svc_start", r"^Failed to start (?P<desc>.+?)\.?$", {"SERVICE": 2}, "Failed to start {desc}", "event"),
    # Updates
    ("uu_err", r"unattended-upgrade.*(error|Error|failed|Traceback)", {"UPDATE": 3}, "unattended-upgrades error", "event"),
    ("dpkg_err", r"dpkg: error processing", {"UPDATE": 3}, "dpkg error while installing packages", "event"),
    # Firmware
    ("acpi", r"ACPI (BIOS )?Error", {"BIOS": 1}, "ACPI firmware error (often harmless)", "event"),
    # Info (timeline only)
    ("powerkey", r"(Power key pressed|Power Button)", {}, "Power button pressed", "info"),
]

SSH_FAIL = re.compile(r"(Failed (password|publickey) for (invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)|Invalid user (?P<user2>\S*) from (?P<ip2>[0-9a-fA-F:.]+))")
SSH_OK = re.compile(r"Accepted (?P<how>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")

NOISE = [
    (re.compile(r"\[UFW (BLOCK|AUDIT)\]"), "Firewall (ufw) blocked packets - normal on internet-facing servers"),
    (re.compile(r"^audit: type=|audit\(\d"), "Audit subsystem messages"),
    (re.compile(r"(I/O error|Buffer I/O error).*dev (fd0|sr0)"), "Virtual floppy / CD drive - harmless"),
    (re.compile(r"systemd-resolved.*(degraded feature set|Grace period over)"), "DNS resolver fallback - harmless"),
    (re.compile(r"hv_balloon: Unhandled message|piix4_smbus.*SMBus|Cannot read proc file system|vmwgfx"), "Common VM driver noise - harmless"),
    (re.compile(r"GPT:.*(Alternate GPT header not at the end|Use GNU Parted to correct)"), "Disk was resized; GPT backup header not at end - harmless"),
    (re.compile(r"(kauditd_printk_skb|IPv6: ADDRCONF|random: crng init|clocksource: Switched to)"), "Kernel info messages"),
    (re.compile(r"snapd\["), "snapd messages - usually harmless"),
    (re.compile(r"(pam_unix\(cron:session\)|CRON\[\d+\])"), "cron session messages"),
    (re.compile(r"(Invalid user|Failed password|Connection closed by .* \[preauth\]|Received disconnect from .*\[preauth\]|Disconnected from .*\[preauth\]|error: kex_exchange_identification|banner exchange)"), "SSH scanner noise (counted in brute-force stats)"),
]

SEV_PRIO = {0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning", 5: "notice", 6: "info", 7: "debug"}
_COMPILED = [(pid, re.compile(rx), cats, meaning, kind) for pid, rx, cats, meaning, kind in P]


# ---------------------------------------------------------------------------------
#  Collection
# ---------------------------------------------------------------------------------
def _journal(args, limit, timeout=90):
    rc, out = run(["journalctl", "--no-pager", "-q", "-o", "json", "-n", str(limit)] + args, timeout)
    evs = []
    for line in out.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        msg = j.get("MESSAGE")
        if isinstance(msg, list):  # binary message
            try:
                msg = bytes(msg).decode("utf-8", "replace")
            except Exception:
                msg = ""
        if not msg:
            continue
        ts = int(j.get("__REALTIME_TIMESTAMP", "0") or 0) / 1e6
        evs.append({"t": ts, "src": j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or ("kernel" if j.get("_TRANSPORT") == "kernel" else "?"),
                    "unit": j.get("_SYSTEMD_UNIT", ""), "prio": int(j.get("PRIORITY", 6) or 6), "msg": msg[:600],
                    "cur": j.get("__CURSOR", ""), "boot": j.get("_BOOT_ID", "")})
    return evs


_SYSLOG_RE = re.compile(r"^(?P<ts>\w{3}\s+\d+ \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT[\d:.]+[+-Z][\d:]*) \S+ (?P<src>[^:\[\s]+)(\[\d+\])?: (?P<msg>.*)$")


def _syslog_files(days):
    """Fallback for systems without journald access."""
    evs = []
    since = time.time() - days * 86400
    year = datetime.now().year
    for pattern in ("/var/log/syslog", "/var/log/syslog.1", "/var/log/messages", "/var/log/messages-*", "/var/log/kern.log", "/var/log/auth.log", "/var/log/auth.log.1", "/var/log/secure"):
        for f in glob.glob(pattern):
            if os.path.getmtime(f) < since:
                continue
            for line in read(f).splitlines()[-50000:]:
                m = _SYSLOG_RE.match(line)
                if not m:
                    continue
                tss = m.group("ts")
                try:
                    if tss[0].isdigit():
                        t = datetime.strptime(tss[:19], "%Y-%m-%dT%H:%M:%S").timestamp()
                    else:
                        t = datetime.strptime("%d %s" % (year, re.sub(r"\s+", " ", tss)), "%Y %b %d %H:%M:%S").timestamp()
                except ValueError:
                    continue
                if t < since:
                    continue
                msg = m.group("msg")
                prio = 3 if re.search(r"(error|fail|critical)", msg, re.I) else 6
                evs.append({"t": t, "src": m.group("src"), "unit": "", "prio": prio, "msg": msg[:600], "cur": "%s:%d" % (f, hash(line)), "boot": ""})
    return evs


def boot_history(max_boots=15):
    """Return list of previous boots with clean/unclean flag (needs persistent journal)."""
    rc, t = run(["journalctl", "--list-boots", "--no-pager", "-q"], 20)
    boots = []
    for line in t.splitlines():
        m = re.match(r"\s*(-?\d+)\s+(\w+)\s+\w{3} (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \w+\s*[-\u2014]+\s*\w{3} (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", line)
        if m:
            boots.append({"idx": int(m.group(1)), "id": m.group(2), "start": m.group(3), "end": m.group(4)})
    boots = [b for b in boots if b["idx"] < 0][-max_boots:]
    for b in boots:
        rc, tail = run(["journalctl", "-b", str(b["idx"]), "-n", "40", "-o", "cat", "--no-pager", "-q"], 20)
        clean = bool(re.search(r"(Journal stopped|systemd-shutdown|Reached target (System )?(Power-?Off|Reboot|Halt|Shutdown|Kexec)|reboot: (Restarting system|Power down)|Stopped target Multi-User|Shutting down\.)", tail))
        panic = bool(re.search(r"(Kernel panic|BUG:|Oops)", tail))
        b["clean"] = clean
        b["panic"] = panic
        b["last"] = [l for l in tail.splitlines() if l.strip()][-3:]
    return boots


def apt_history(days):
    out = []
    since = datetime.now() - timedelta(days=days)
    for f in sorted(glob.glob("/var/log/apt/history.log*")):
        if f.endswith(".gz"):
            continue
        cur = None
        for line in read(f).splitlines():
            if line.startswith("Start-Date:"):
                try:
                    cur = datetime.strptime(line.split(":", 1)[1].strip(), "%Y-%m-%d  %H:%M:%S")
                except ValueError:
                    try:
                        cur = datetime.strptime(" ".join(line.split(":", 1)[1].split()), "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        cur = None
            elif cur and cur >= since and line.startswith(("Upgrade:", "Install:")):
                pk = re.findall(r"([\w.+-]+):\w+ \(", line)
                kern = [p for p in pk if p.startswith("linux-image")]
                what = "%s %d package(s)%s" % (line.split(":")[0].lower(), len(pk), (" incl. " + ", ".join(kern[:2])) if kern else (": " + ", ".join(pk[:4]) if pk else ""))
                out.append({"t": cur.timestamp(), "what": what})
    return out


def collect_logs(days=7, progress=None):
    evs = []
    source = "journald"
    if which("journalctl"):
        since = "-%dd" % days
        if progress:
            progress("Reading journal (warnings and errors)...")
        evs += _journal(["--since", "%d days ago" % days, "-p", "warning"], 60000)
        if progress:
            progress("Reading kernel log...")
        evs += _journal(["--since", "%d days ago" % days, "-k", "-p", "notice"], 30000)
        if progress:
            progress("Reading SSH / auth log...")
        for ident in ("sshd", "sshd-session"):
            evs += _journal(["--since", "%d days ago" % days, "SYSLOG_IDENTIFIER=%s" % ident], 40000)
        evs += _journal(["--since", "%d days ago" % days, "_PID=1", "-p", "notice"], 20000)
        evs += _journal(["--since", "%d days ago" % days, "SYSLOG_IDENTIFIER=smartd"], 2000)
    if not evs:
        source = "syslog files"
        evs = _syslog_files(days)
    seen = set()
    uniq = []
    for e in evs:
        k = e["cur"] or (e["t"], e["msg"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(e)
    uniq.sort(key=lambda e: -e["t"])
    persistent = os.path.isdir("/var/log/journal")
    boots = boot_history() if which("journalctl") else []
    return {"events": uniq, "source": source, "persistent": persistent, "boots": boots, "apt": apt_history(days), "days": days}


# ---------------------------------------------------------------------------------
#  Analysis
# ---------------------------------------------------------------------------------
def _recency(t, now):
    age = (now - t) / 86400.0
    return 1.0 if age <= 7 else (0.75 if age <= 30 else 0.5)


def likelihood(score):
    if score >= 25:
        return "HIGH"
    if score >= 10:
        return "MEDIUM"
    if score >= 3:
        return "LOW"
    return None


def _norm(msg):
    m = re.sub(r"0x[0-9a-fA-F]+", "#", msg)
    m = re.sub(r"\b\d+\b", "#", m)
    m = re.sub(r"[0-9a-f]{8,}", "#", m)
    return m[:140]


def _fmt(t):
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if t else ""


def analyze(logs, ctx=None, now=None):
    ctx = ctx or {}
    now = now or time.time()
    virt = ctx.get("virt", "none")
    groups = {}
    unknown = {}
    noise = defaultdict(lambda: {"count": 0, "last": 0})
    timeline = []
    ssh_fail = {"count": 0, "ips": defaultdict(int), "users": defaultdict(int), "last": 0}
    ssh_ok = []

    def add(key, cats, meaning, e, kind, src):
        g = groups.get(key)
        if not g:
            g = groups[key] = {"source": src, "count": 0, "last": e["t"], "first": e["t"], "cats": cats, "meaning": meaning,
                               "kind": kind, "sample": e["msg"][:300]}
        g["count"] += 1
        g["first"] = min(g["first"], e["t"])
        g["last"] = max(g["last"], e["t"])
        if kind == "crash" or (cats and max(cats.values()) >= 8):
            timeline.append({"t": e["t"], "what": meaning, "src": src, "kind": kind})

    for e in logs.get("events", []):
        msg = e["msg"]
        src = e["src"]
        m = SSH_FAIL.search(msg)
        if m and src.startswith("sshd"):
            ip = m.group("ip") or m.group("ip2")
            user = m.group("user") or m.group("user2") or "?"
            ssh_fail["count"] += 1
            ssh_fail["ips"][ip] += 1
            ssh_fail["users"][user] += 1
            ssh_fail["last"] = max(ssh_fail["last"], e["t"])
            continue
        m = SSH_OK.search(msg)
        if m and src.startswith("sshd"):
            ssh_ok.append({"t": e["t"], "user": m.group("user"), "ip": m.group("ip"), "how": m.group("how")})
            timeline.append({"t": e["t"], "what": "SSH login: %s from %s (%s)" % (m.group("user"), m.group("ip"), m.group("how")), "src": "sshd", "kind": "info"})
            continue
        # smartd lines carry the device at the start
        matched = False
        for pid, rx, cats, meaning, kind in _COMPILED:
            if pid == "smartd" and not src.startswith("smartd"):
                continue
            mm = rx.search(msg)
            if not mm:
                continue
            gd = {k: (v or "") for k, v in mm.groupdict().items()}
            if pid in ("ioerr", "blkupd", "bufio") and re.match(r"^(fd\d|sr\d)", gd.get("dev", "")):
                break  # virtual floppy/CD -> noise below
            c = dict(cats)
            if pid in ("ioerr", "blkupd", "bufio") and gd.get("dev", "").startswith("nvme"):
                c = {"NVME": c.pop("DISK", 6)}
            if pid == "svc_fail" and gd.get("res") == "oom-kill":
                c = {"MEMPRESSURE": 5}
            try:
                text = meaning.format(**gd).replace("  ", " ").strip()
            except (KeyError, IndexError):
                text = meaning
            key = pid + "|" + "|".join(gd.get(k, "") for k in ("dev", "proc", "unit", "desc", "pool") if gd.get(k))
            add(key, c, text, e, kind, src)
            matched = True
            break
        if matched:
            continue
        nz = None
        for rx, why in NOISE:
            if rx.search(msg):
                nz = why
                break
        if nz:
            noise[nz]["count"] += 1
            noise[nz]["last"] = max(noise[nz]["last"], e["t"])
            continue
        if e["prio"] <= 3:
            k = (src, _norm(msg))
            u = unknown.setdefault(k, {"source": src, "count": 0, "last": e["t"], "msg": msg[:300]})
            u["count"] += 1

    # SSH brute force
    if ssh_fail["count"]:
        pw = (ctx.get("sshd") or {}).get("passwordauthentication")
        w = 1 if pw == "no" else 3
        top = sorted(ssh_fail["ips"].items(), key=lambda kv: -kv[1])[:5]
        groups["ssh-bruteforce"] = {"source": "sshd", "count": ssh_fail["count"], "last": ssh_fail["last"], "first": ssh_fail["last"],
                                    "cats": {"SECURITY": w} if ssh_fail["count"] >= 20 else {},
                                    "meaning": "%d failed SSH logins from %d IPs (top: %s)%s" % (
                                        ssh_fail["count"], len(ssh_fail["ips"]), ", ".join("%s x%d" % kv for kv in top),
                                        " - password login is disabled, so these cannot succeed" if pw == "no" else ""),
                                    "kind": "event", "sample": "top users tried: " + ", ".join(u for u, _ in sorted(ssh_fail["users"].items(), key=lambda kv: -kv[1])[:8])}
    root_pw = [s for s in ssh_ok if s["user"] == "root" and s["how"] == "password"]
    if root_pw:
        groups["ssh-rootpw"] = {"source": "sshd", "count": len(root_pw), "last": root_pw[0]["t"], "first": root_pw[-1]["t"], "cats": {"SECURITY": 4},
                                "meaning": "root logged in with a PASSWORD over SSH (from %s)" % ", ".join(sorted(set(s["ip"] for s in root_pw))[:3]),
                                "kind": "event", "sample": ""}

    # Unclean shutdowns
    for b in logs.get("boots", []):
        try:
            end = datetime.strptime(b["end"], "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            end = now
        timeline.append({"t": datetime.strptime(b["start"], "%Y-%m-%d %H:%M:%S").timestamp() if b.get("start") else end,
                         "what": "Boot %s" % b["idx"], "src": "systemd", "kind": "info"})
        if not b.get("clean"):
            key = "unclean|panic" if b.get("panic") else "unclean"
            cats = {"KERNEL": 6} if b.get("panic") else {"POWER": 6, "VIRT": 1 if virt != "none" else 0}
            cats = {k: v for k, v in cats.items() if v}
            e = {"t": end, "msg": " / ".join(b.get("last", []))}
            add(key, cats, "Unclean shutdown%s (boot ended %s without a clean shutdown)" % (" after a kernel crash" if b.get("panic") else "", b["end"]), e, "crash", "boot history")

    for a in logs.get("apt", []):
        timeline.append({"t": a["t"], "what": "apt: " + a["what"], "src": "apt", "kind": "update"})

    # Score
    scores = defaultdict(float)
    evidence = defaultdict(list)
    for g in groups.values():
        if not g["cats"]:
            continue
        mult = (1 + math.log(max(1, g["count"]), 2)) * _recency(g["last"], now)
        for cat, w in g["cats"].items():
            scores[cat] += w * mult
            evidence[cat].append((w * mult, g))
    # context boosts
    if virt != "none" and scores.get("HUNG"):
        scores["VIRT"] += scores["HUNG"] * 0.3
        evidence["VIRT"].append((0, {"count": 0, "source": "context", "meaning": "hung tasks / lockups on a VM usually mean host CPU or storage contention", "last": 0}))

    problems = []
    for cat, sc in sorted(scores.items(), key=lambda kv: -kv[1]):
        lk = likelihood(sc)
        if not lk:
            continue
        name, why, fix = CATEGORIES.get(cat, (cat, "", []))
        ev = []
        for _, g in sorted(evidence[cat], key=lambda x: -x[0])[:6]:
            if g["count"]:
                ev.append("%dx  %s  -  %s  (last %s)" % (g["count"], g["source"], g["meaning"], _fmt(g["last"])))
            else:
                ev.append("note: " + g["meaning"])
        problems.append({"cat": cat, "name": name, "score": round(sc, 1), "likelihood": lk, "why": why, "fix": fix, "evidence": ev})

    # Insights
    insights = []
    crashes = sorted(g["first"] for g in groups.values() if g["kind"] == "crash")
    if crashes:
        first = crashes[0]
        ups = [a for a in logs.get("apt", []) if 0 <= first - a["t"] <= 3 * 86400]
        if ups:
            insights.append("The first crash/failure in this period (%s) came within 3 days after: %s. If problems started then, suspect that update." % (_fmt(first), ups[-1]["what"]))
    unclean = [b for b in logs.get("boots", []) if not b.get("clean") and not b.get("panic")]
    if len(unclean) >= 2:
        insights.append("%d unclean shutdowns without a kernel panic - points to power loss, a hard reset%s, or a hang that needed a forced reboot." % (
            len(unclean), " from the hypervisor/host" if virt != "none" else " / PSU problem"))
    ooms = [g for k, g in groups.items() if k.startswith("oom|")]
    if ooms:
        top = sorted(ooms, key=lambda g: -g["count"])[0]
        insights.append("The OOM killer fired %d time(s); most often it killed: %s." % (sum(g["count"] for g in ooms), top["meaning"].replace("OOM killer killed ", "")))
    if not logs.get("persistent") and which("journalctl"):
        insights.append("The journal is not persistent, so history is lost on every reboot (crashes before the last reboot are invisible). Enable it: `sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald`.")

    timeline.sort(key=lambda x: -x["t"])
    matched = sorted(groups.values(), key=lambda g: -((max(g["cats"].values()) if g["cats"] else 0) * g["count"]))
    return {
        "total_events": len(logs.get("events", [])),
        "source": logs.get("source"),
        "days": logs.get("days"),
        "problems": problems,
        "insights": insights,
        "matched": [{"count": g["count"], "last": _fmt(g["last"]), "source": g["source"], "meaning": g["meaning"],
                     "category": CATEGORIES.get(max(g["cats"], key=g["cats"].get), ("info",))[0] if g["cats"] else "info",
                     "weight": max(g["cats"].values()) if g["cats"] else 0, "sample": g.get("sample", "")} for g in matched],
        "unknown": [{"count": u["count"], "last": _fmt(u["last"]), "source": u["source"], "msg": u["msg"]} for u in sorted(unknown.values(), key=lambda u: -u["count"])[:40]],
        "noise": [{"count": v["count"], "last": _fmt(v["last"]), "meaning": k} for k, v in sorted(noise.items(), key=lambda kv: -kv[1]["count"])],
        "timeline": [{"time": _fmt(x["t"]), "kind": x["kind"], "source": x["src"], "what": x["what"]} for x in timeline[:250]],
        "boots": [{"boot": b["idx"], "start": b["start"], "end": b["end"], "clean": b.get("clean"), "panic": b.get("panic")} for b in logs.get("boots", [])],
    }
