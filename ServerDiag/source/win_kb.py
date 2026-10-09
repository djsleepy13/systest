"""
WinDiag Event Analyzer
----------------------
Takes raw Windows events (from the PowerShell collector), matches them against a
knowledge base of event IDs / blue-screen stop codes, and ranks the most likely
root causes (NVMe, disk, RAM, CPU, PSU/power, GPU, driver, ...).

Pure Python - no Windows dependencies, so it can be unit-tested anywhere.
"""
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------------
#  Problem categories
# ---------------------------------------------------------------------------------
CATEGORIES = {
    "NVME": {
        "name": "NVMe SSD / storage controller",
        "why": "The NVMe drive (or its driver) is timing out, resetting or reporting controller errors.",
        "fix": ["Back up important files now.",
                "Update the SSD firmware (Samsung Magician, WD Dashboard, Crucial Storage Executive...).",
                "Update chipset / storage drivers and the BIOS.",
                "Power plan > PCI Express > Link State Power Management = Off (rules out ASPM power saving).",
                "Check SSD temperature and wear in the Disks tab; reseat the drive if possible."]},
    "DISK": {
        "name": "Hard drive / SATA SSD / cable",
        "why": "A drive is returning read/write errors, bad blocks or timeouts.",
        "fix": ["Back up important files now.",
                "Check health / uncorrected errors in the Disks tab.",
                "Replace or reseat the SATA data + power cable, try another SATA port.",
                "Run the CHKDSK scan (Repairs tab).",
                "If errors continue, replace the drive."]},
    "FS": {
        "name": "File system corruption",
        "why": "Windows found damaged file-system structures (NTFS).",
        "fix": ["Run CHKDSK full repair at next restart (Repairs tab).",
                "Then run DISM + SFC.",
                "If it keeps coming back, the drive itself may be failing - check the Disks tab."]},
    "SPACE": {
        "name": "Low disk space",
        "why": "A drive ran out of space, which breaks updates, restore points and crash dumps.",
        "fix": ["Run 'Clear temp files' and Disk Cleanup.", "Uninstall unused apps; move large files elsewhere."]},
    "RAM": {
        "name": "Memory (RAM)",
        "why": "Errors point to faulty or unstable RAM (or memory settings).",
        "fix": ["Disable XMP / EXPO / memory overclock in the BIOS and test again.",
                "Run the Memory test (Repairs tab) - or MemTest86 from a bootable USB for a thorough test.",
                "Test one RAM stick at a time to find the bad one; reseat the sticks.",
                "Update the BIOS."]},
    "CPU": {
        "name": "CPU / overclock / voltage instability",
        "why": "The processor reported machine-check / hardware errors.",
        "fix": ["Remove any CPU overclock or undervolt; load BIOS defaults.",
                "Update the BIOS (many CPU stability fixes ship as microcode updates).",
                "Check CPU temperatures under load (HWiNFO / Core Temp).",
                "Intel 13th/14th gen: install the latest BIOS with the 0x12B+ microcode."]},
    "PCIE": {
        "name": "PCIe device or slot (GPU, NVMe, Wi-Fi card)",
        "why": "A PCI Express link is reporting errors.",
        "fix": ["Update chipset drivers and BIOS.",
                "Reseat the GPU / NVMe / expansion card; remove riser cables to test.",
                "Power plan > PCI Express > Link State Power Management = Off.",
                "Force the slot to PCIe Gen3/Gen4 in the BIOS if errors continue."]},
    "POWER": {
        "name": "Power loss / power supply (PSU) / battery",
        "why": "The PC shut off without a clean shutdown and without a crash - typical of power problems.",
        "fix": ["Check for power cuts, loose power cables, faulty power strip / UPS.",
                "Desktop: an old or weak PSU can switch off under load (gaming) - test with another PSU.",
                "Laptop: check battery health (Security & Updates tab / Battery report).",
                "Rule out overheating (it can trigger emergency shutdowns)."]},
    "THERMAL": {
        "name": "Overheating / power throttling",
        "why": "The CPU was slowed down by firmware - usually heat or power limits.",
        "fix": ["Clean dust from fans and heatsinks; make sure vents are not blocked.",
                "Check temperatures with HWiNFO; renew thermal paste on older PCs.",
                "Laptop: use the correct/original charger - a weak charger also causes throttling."]},
    "GPU": {
        "name": "Graphics card / display driver",
        "why": "The graphics driver crashed, hung or timed out.",
        "fix": ["Clean-install the latest GPU driver (use DDU in Safe Mode for a clean removal).",
                "Remove GPU overclocks / MSI Afterburner profiles.",
                "Check GPU temperatures and PSU capacity/cables.",
                "If it only happens in one game/app, update or reinstall that app."]},
    "DRIVER": {
        "name": "Faulty or outdated driver",
        "why": "A driver or system service is crashing or failing to load.",
        "fix": ["Install the latest chipset, Wi-Fi, LAN, audio, storage and GPU drivers from the PC / motherboard maker.",
                "Uninstall recently added hardware software, VPNs, antivirus or RGB/monitoring tools.",
                "Open the newest .dmp in BlueScreenView / WinDbg to see the exact driver name.",
                "Disable Fast Startup if problems happen after sleep / shutdown."]},
    "USB": {
        "name": "USB / external devices",
        "why": "A USB device or controller is disconnecting or its driver crashes.",
        "fix": ["Unplug USB hubs, docks and unneeded devices, then add them back one by one.",
                "Update chipset / USB / Thunderbolt drivers and dock firmware.",
                "Power plan > USB selective suspend = Disabled."]},
    "NETWORK": {
        "name": "Network adapter / connection",
        "why": "The network adapter or connection is dropping or misconfigured.",
        "fix": ["Update the Wi-Fi / Ethernet driver from Intel / Realtek / the PC maker.",
                "Adapter properties > Power Management: untick 'Allow the computer to turn off this device'.",
                "Try the 'Full network reset' repair; check cable / router."]},
    "UPDATE": {
        "name": "Windows Update",
        "why": "Updates are failing to install.",
        "fix": ["Run 'Reset Windows Update' then 'DISM + SFC' (Repairs tab).",
                "Make sure there is at least 20 GB free on C:.",
                "Search the error code shown in the evidence."]},
    "SYSTEM": {
        "name": "Windows system files / OS corruption",
        "why": "Core Windows components are failing, which points to damaged system files.",
        "fix": ["Run DISM + SFC (Repairs tab).",
                "Uninstall the most recent Windows update if problems started right after it.",
                "Last resort: in-place repair install (Windows 11 Settings > System > Recovery > Fix problems using Windows Update)."]},
    "APP": {
        "name": "Specific applications",
        "why": "One or more programs keep crashing, but Windows itself looks stable.",
        "fix": ["Update or reinstall the crashing app.",
                "Reinstall the Microsoft Visual C++ Redistributables (x86 + x64) and .NET runtimes.",
                "If many different apps crash, test RAM and run DISM + SFC."]},
    "AD": {
        "name": "Active Directory / DNS / Group Policy",
        "why": "Domain services are reporting replication, DNS, Kerberos or Group Policy errors.",
        "fix": ["Run 'dcdiag /q' and 'repadmin /replsummary' on a DC.",
                "Check that DCs and members use ONLY internal AD DNS servers (no 8.8.8.8 on NICs).",
                "Check time sync (w32tm /query /status) - Kerberos fails with >5 min skew.",
                "DFSR 2213: resume replication with the WMI command in the event text; DFSR 4012: SYSVOL needs an authoritative/non-authoritative restore."]},
    "HYPERV": {
        "name": "Hyper-V host / virtual machines",
        "why": "The Hyper-V management service or VM worker processes are failing.",
        "fix": ["Open the Hyper-V-VMMS and Hyper-V-Worker admin logs for the VM name.",
                "Check free space on the volume holding VHDX/AVHDX files; merge old checkpoints.",
                "Update integration services and the host (cumulative updates).",
                "Check antivirus exclusions for VHDX folders and vmms.exe / vmwp.exe."]},
    "CLUSTER": {
        "name": "Failover cluster",
        "why": "Cluster nodes lost contact, resources failed or quorum was at risk.",
        "fix": ["Check cluster network(s) - NIC teaming, switch, MTU; event 1135 = node lost heartbeats.",
                "Run 'Test-Cluster' (validation report) in a maintenance window.",
                "Check storage paths to CSVs (event 5120) and the quorum witness."]},
    "IIS": {
        "name": "IIS web server / application pools",
        "why": "IIS worker processes are crashing or app pools were disabled by rapid-fail protection.",
        "fix": ["Find the failing app pool in the event text; check the app's own logs.",
                "WAS 5002 = pool disabled after repeated crashes - fix the cause, then start the pool.",
                "Check the app pool identity password and .NET version."]},
    "SQL": {
        "name": "SQL Server",
        "why": "SQL Server reported I/O, log-full or scheduler problems.",
        "fix": ["Errors 823/824/825 = storage corruption risk: run DBCC CHECKDB and check the disks now.",
                "Error 833 = slow I/O (>15 s) - check the storage/SAN latency.",
                "Error 9002 = transaction log full - take a log backup or fix the recovery model.",
                "Error 17883/17884 = scheduler hang - update SQL Server CU."]},
    "BACKUP": {
        "name": "Backups / Volume Shadow Copy",
        "why": "Backup jobs or the VSS writers they depend on are failing.",
        "fix": ["Run 'vssadmin list writers' and check for writers in a failed state.",
                "Restart the service behind the failed writer (or reboot) and re-run the backup.",
                "Check free space on the backup target and the shadow storage (vssadmin list shadowstorage)."]},
    "SECURITY": {
        "name": "Security / authentication",
        "why": "Logons are failing repeatedly or accounts are being locked out.",
        "fix": ["See the failed-logon source IPs in the Server Roles page.",
                "Never expose RDP directly to the internet - use VPN or RD Gateway with MFA.",
                "Enable account lockout policy and NLA."]},
    "BIOS": {
        "name": "BIOS / firmware",
        "why": "The firmware (ACPI) is reporting errors to Windows.",
        "fix": ["Update the BIOS / UEFI from the PC or motherboard maker.", "Load BIOS defaults."]},
}

# ---------------------------------------------------------------------------------
#  Blue screen stop codes -> meaning + categories
# ---------------------------------------------------------------------------------
STOP_CODES = {
    0x0A: ("IRQL_NOT_LESS_OR_EQUAL", {"DRIVER": 8, "RAM": 4}, "A driver accessed memory it should not - bad driver or bad RAM."),
    0x19: ("BAD_POOL_HEADER", {"DRIVER": 7, "RAM": 4}, "Kernel memory pool damaged - usually a driver, sometimes RAM."),
    0x1A: ("MEMORY_MANAGEMENT", {"RAM": 10, "DRIVER": 3}, "Memory management error - most often faulty/unstable RAM."),
    0x1E: ("KMODE_EXCEPTION_NOT_HANDLED", {"DRIVER": 7, "RAM": 3}, "A kernel driver crashed."),
    0x24: ("NTFS_FILE_SYSTEM", {"FS": 8, "DISK": 4}, "NTFS file-system driver failed - corruption or failing disk."),
    0x3B: ("SYSTEM_SERVICE_EXCEPTION", {"DRIVER": 7, "GPU": 3, "SYSTEM": 2}, "A system service crashed - often graphics or antivirus drivers."),
    0x44: ("MULTIPLE_IRP_COMPLETE_REQUESTS", {"DRIVER": 8}, "A driver bug."),
    0x4E: ("PFN_LIST_CORRUPT", {"RAM": 9, "DRIVER": 3}, "Memory page list corrupted - usually RAM."),
    0x50: ("PAGE_FAULT_IN_NONPAGED_AREA", {"RAM": 6, "DRIVER": 5, "DISK": 2}, "Invalid memory referenced - RAM, a driver or antivirus."),
    0x76: ("PROCESS_HAS_LOCKED_PAGES", {"DRIVER": 5}, "A driver did not release memory."),
    0x77: ("KERNEL_STACK_INPAGE_ERROR", {"DISK": 8, "RAM": 3}, "Could not read kernel data from the disk - drive/cable or RAM."),
    0x7A: ("KERNEL_DATA_INPAGE_ERROR", {"DISK": 8, "RAM": 3}, "Could not read data from the page file on disk - failing drive, cable or RAM."),
    0x7B: ("INACCESSIBLE_BOOT_DEVICE", {"DISK": 6, "DRIVER": 5}, "Windows lost access to the boot drive - storage driver, AHCI/RAID mode change, or failing drive."),
    0x7E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", {"DRIVER": 8}, "A system thread crashed - almost always a driver."),
    0x7F: ("UNEXPECTED_KERNEL_MODE_TRAP", {"RAM": 6, "CPU": 4, "DRIVER": 4}, "CPU trap - often hardware (RAM, overclock, heat)."),
    0x9C: ("MACHINE_CHECK_EXCEPTION", {"CPU": 10, "RAM": 3}, "CPU reported a fatal hardware error."),
    0x9F: ("DRIVER_POWER_STATE_FAILURE", {"DRIVER": 8, "POWER": 2}, "A driver mishandled sleep / wake - update chipset, Wi-Fi, GPU drivers."),
    0xA0: ("INTERNAL_POWER_ERROR", {"DRIVER": 5, "POWER": 4}, "Power management failure."),
    0xAB: ("SESSION_HAS_VALID_POOL_ON_EXIT", {"DRIVER": 5}, "A driver leaked memory on logoff."),
    0xBE: ("ATTEMPTED_WRITE_TO_READONLY_MEMORY", {"DRIVER": 8}, "A driver wrote to read-only memory."),
    0xC2: ("BAD_POOL_CALLER", {"DRIVER": 8}, "A driver made a bad memory request."),
    0xC4: ("DRIVER_VERIFIER_DETECTED_VIOLATION", {"DRIVER": 9}, "Driver Verifier is on and caught a faulty driver."),
    0xC5: ("DRIVER_CORRUPTED_EXPOOL", {"DRIVER": 8, "RAM": 2}, "A driver corrupted kernel memory."),
    0xD1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", {"DRIVER": 9, "NETWORK": 2}, "A driver accessed invalid memory - frequently network/Wi-Fi, USB or storage drivers."),
    0xD5: ("DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL", {"DRIVER": 9}, "A driver used memory after freeing it."),
    0xEA: ("THREAD_STUCK_IN_DEVICE_DRIVER", {"GPU": 9}, "Stuck in the graphics driver - GPU driver or card."),
    0xED: ("UNMOUNTABLE_BOOT_VOLUME", {"FS": 7, "DISK": 5}, "Boot volume could not be mounted - corruption or failing drive."),
    0xEF: ("CRITICAL_PROCESS_DIED", {"SYSTEM": 7, "DISK": 3, "DRIVER": 2}, "A critical Windows process died - system file corruption or disk errors."),
    0xF4: ("CRITICAL_OBJECT_TERMINATION", {"DISK": 6, "SYSTEM": 4}, "A critical process ended - often disk / cable I/O errors."),
    0xF7: ("DRIVER_OVERRAN_STACK_BUFFER", {"DRIVER": 8}, "Driver buffer overrun."),
    0xFC: ("ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY", {"DRIVER": 7, "RAM": 3}, "Code executed from non-executable memory - driver or RAM."),
    0xFE: ("BUGCODE_USB_DRIVER", {"USB": 9}, "USB driver crashed."),
    0x101: ("CLOCK_WATCHDOG_TIMEOUT", {"CPU": 10, "DRIVER": 2}, "A CPU core stopped responding - overclock/undervolt, BIOS or CPU."),
    0x109: ("CRITICAL_STRUCTURE_CORRUPTION", {"RAM": 6, "DRIVER": 6}, "Kernel code/data modified - bad driver or RAM."),
    0x10D: ("WDF_VIOLATION", {"DRIVER": 6, "USB": 4}, "Driver framework violation - often USB / Bluetooth / input device drivers."),
    0x10E: ("VIDEO_MEMORY_MANAGEMENT_INTERNAL", {"GPU": 9}, "Graphics memory manager failure."),
    0x113: ("VIDEO_DXGKRNL_FATAL_ERROR", {"GPU": 9}, "DirectX graphics kernel failure."),
    0x116: ("VIDEO_TDR_FAILURE", {"GPU": 10}, "Graphics driver stopped responding and could not recover."),
    0x117: ("VIDEO_TDR_TIMEOUT_DETECTED", {"GPU": 8}, "Graphics driver timed out."),
    0x119: ("VIDEO_SCHEDULER_INTERNAL_ERROR", {"GPU": 9}, "GPU scheduler error - GPU driver or card."),
    0x121: ("DRIVER_VIOLATION", {"DRIVER": 7}, "Driver violation."),
    0x124: ("WHEA_UNCORRECTABLE_ERROR", {"CPU": 10, "RAM": 4, "POWER": 3, "THERMAL": 3}, "Fatal hardware error - overclock/undervolt, CPU voltage, overheating or PSU."),
    0x12B: ("FAULTY_HARDWARE_CORRUPTED_PAGE", {"RAM": 12}, "RAM returned corrupted data - faulty memory."),
    0x133: ("DPC_WATCHDOG_VIOLATION", {"DRIVER": 6, "NVME": 5, "DISK": 3}, "A driver took too long - frequently SSD firmware or storage drivers (iaStorA / storahci)."),
    0x139: ("KERNEL_SECURITY_CHECK_FAILURE", {"DRIVER": 7, "RAM": 3, "SYSTEM": 2}, "Kernel data structure corrupted - usually a driver."),
    0x13A: ("KERNEL_MODE_HEAP_CORRUPTION", {"DRIVER": 8, "GPU": 2}, "Kernel heap corrupted by a driver."),
    0x144: ("BUGCODE_USB3_DRIVER", {"USB": 9}, "USB 3 driver crashed."),
    0x154: ("UNEXPECTED_STORE_EXCEPTION", {"NVME": 6, "DISK": 5, "SYSTEM": 2}, "Memory store error - SSD, its firmware, or antivirus."),
    0x18B: ("SECURE_KERNEL_ERROR", {"DRIVER": 5}, "Virtualization-based security error."),
    0x19C: ("WIN32K_POWER_WATCHDOG_TIMEOUT", {"GPU": 4, "DRIVER": 4, "POWER": 2}, "Display power state change timed out."),
    0x1C8: ("MANUALLY_INITIATED_POWER_BUTTON_HOLD", {"DRIVER": 2, "GPU": 1}, "Power button held because the PC was frozen."),
    0xC000021A: ("WINLOGON_FATAL_ERROR", {"SYSTEM": 9}, "A critical user-mode subsystem failed - system files or a bad update."),
}

# Live kernel events (Windows Error Reporting, recovered without a BSOD)
LIVE_KERNEL = {
    "141": ("VIDEO_ENGINE_TIMEOUT_DETECTED", {"GPU": 7}, "GPU hung and the driver was reset."),
    "117": ("VIDEO_TDR_TIMEOUT_DETECTED", {"GPU": 7}, "Graphics driver timed out and recovered."),
    "193": ("VIDEO_DXGKRNL_LIVEDUMP", {"GPU": 2}, "Graphics kernel diagnostic dump."),
    "144": ("BUGCODE_USB3_DRIVER", {"USB": 6}, "USB 3 controller/driver error."),
    "15f": ("CONNECTED_STANDBY_WATCHDOG", {"DRIVER": 3, "POWER": 2}, "Modern Standby (sleep) watchdog - a driver blocked sleep."),
    "1a1": ("WIN32K_CALLOUT_WATCHDOG", {"DRIVER": 2}, "Desktop/window subsystem hang."),
    "1b8": ("MINICALL_ATTEMPT_OCCURRED", {"DRIVER": 1}, "Driver diagnostic dump."),
    "abc": ("NDIS_NET_BUFFER_LIST_INFO_ILLEGALLY_TRANSFERRED", {"NETWORK": 3}, "Network driver issue."),
}

# ---------------------------------------------------------------------------------
#  Event knowledge base:  (provider lower-case, event id) -> (cats, meaning)
# ---------------------------------------------------------------------------------
def _r(cats, meaning):
    return {"cats": cats, "meaning": meaning}

KB = {
    # ---- Storage ------------------------------------------------------------------
    ("disk", 7):   _r({"DISK": 8}, "Bad block found - the drive has unreadable sectors/cells."),
    ("disk", 11):  _r({"DISK": 7}, "Controller error on the drive - cable, port, controller or failing drive."),
    ("disk", 15):  _r({"DISK": 5}, "Drive not ready for access - it dropped out."),
    ("disk", 51):  _r({"DISK": 5}, "Error during a paging operation - drive or cable problem."),
    ("disk", 52):  _r({"DISK": 12}, "The drive reports that FAILURE IS PREDICTED (SMART)."),
    ("disk", 153): _r({"DISK": 4}, "I/O had to be retried - drive slow to respond (cable, power saving, firmware or failing drive)."),
    ("disk", 154): _r({"DISK": 8}, "I/O failed because of a hardware error."),
    ("disk", 157): _r({"USB": 3, "DISK": 2}, "Disk was 'surprise removed' - USB drive unplugged, loose cable or drive lost power."),
    ("stornvme", 11):  _r({"NVME": 7}, "NVMe controller error."),
    ("stornvme", 129): _r({"NVME": 5}, "Reset issued to the NVMe drive - it stopped responding (firmware, power saving/ASPM, heat or failing)."),
    ("stornvme", 7):   _r({"NVME": 6}, "NVMe device error."),
    ("storahci", 11):  _r({"DISK": 6}, "SATA (AHCI) controller error."),
    ("storahci", 129): _r({"DISK": 5}, "Reset issued to a SATA device - it stopped responding."),
    ("ntfs", 55):  _r({"FS": 8}, "File-system structure on disk is corrupt."),
    ("microsoft-windows-ntfs", 55): _r({"FS": 8}, "File-system structure on disk is corrupt."),
    ("ntfs", 50):  _r({"DISK": 3, "USB": 2, "FS": 2}, "Delayed write lost - data could not be written."),
    ("ntfs", 57):  _r({"DISK": 3, "USB": 2, "FS": 2}, "Failed to flush data to disk (drive removed, cable, or failing)."),
    ("ntfs", 137): _r({"FS": 3}, "NTFS transaction log error."),
    ("microsoft-windows-ntfs", 140): _r({"DISK": 3, "USB": 2, "FS": 2}, "Failed to flush data to the transaction log - data may be corrupted."),
    ("volsnap", 25): _r({"SPACE": 3}, "Shadow copies (restore points) deleted - not enough disk space."),
    ("volsnap", 36): _r({"SPACE": 3}, "Shadow copies (restore points) deleted - storage limit reached."),
    ("srv", 2013):   _r({"SPACE": 4}, "A disk is at or near capacity."),
    ("volmgr", 161): _r({"SYSTEM": 2}, "Crash dump could not be created - page file too small or disabled."),
    ("volmgr", 49):  _r({"SYSTEM": 2}, "Page file for crash dumps could not be configured."),

    # ---- Memory / CPU / hardware -----------------------------------------------------
    ("microsoft-windows-resource-exhaustion-detector", 2004):
        _r({"RAM": 2, "APP": 3}, "Low on memory - a program is using too much (named in the event message)."),
    ("microsoft-windows-whea-logger", 1):  _r({"CPU": 8, "RAM": 4, "PCIE": 4}, "Fatal hardware error reported by the platform."),
    ("microsoft-windows-whea-logger", 17): _r({"PCIE": 4}, "Corrected PCI Express error (often ASPM power saving, riser, GPU/NVMe link)."),
    ("microsoft-windows-whea-logger", 18): _r({"CPU": 12, "RAM": 4}, "FATAL machine-check error from the CPU (core/cache/interconnect)."),
    ("microsoft-windows-whea-logger", 19): _r({"CPU": 5}, "Corrected CPU/cache error (often an unstable overclock, undervolt or XMP)."),
    ("microsoft-windows-whea-logger", 20): _r({"PCIE": 6, "CPU": 4}, "Fatal hardware error on a device/bus."),
    ("microsoft-windows-whea-logger", 47): _r({"RAM": 6}, "Corrected memory (RAM) error."),
    ("microsoft-windows-kernel-processor-power", 37):
        _r({"THERMAL": 3}, "CPU speed is being limited by the firmware (heat or power limit)."),
    ("eventlog", 6008): _r({"POWER": 3}, "The previous shutdown was unexpected."),
    ("acpi", 13): _r({"BIOS": 2}, "ACPI firmware error."),

    # ---- Graphics --------------------------------------------------------------------
    ("display", 4101): _r({"GPU": 7}, "Display driver stopped responding and recovered (TDR)."),

    # ---- Drivers / services ------------------------------------------------------------
    ("service control manager", 7000): _r({"DRIVER": 2}, "A service or driver failed to start."),
    ("service control manager", 7001): _r({"DRIVER": 1}, "A service failed because a service it depends on did not start."),
    ("service control manager", 7009): _r({"DRIVER": 1}, "A service took too long to start."),
    ("service control manager", 7011): _r({"DRIVER": 1}, "A service did not respond in time."),
    ("service control manager", 7023): _r({"DRIVER": 2}, "A service stopped with an error."),
    ("service control manager", 7024): _r({"DRIVER": 2}, "A service stopped with a service-specific error."),
    ("service control manager", 7026): _r({"DRIVER": 4}, "A boot/system-start driver failed to load."),
    ("service control manager", 7031): _r({"DRIVER": 2}, "A service crashed unexpectedly."),
    ("service control manager", 7034): _r({"DRIVER": 2}, "A service crashed unexpectedly."),
    ("microsoft-windows-kernel-pnp", 219): _r({"DRIVER": 3}, "The driver for a device failed to load."),
    ("microsoft-windows-kernel-pnp", 411): _r({"DRIVER": 3}, "Problem starting a device."),
    ("microsoft-windows-driverframeworks-usermode", 10110): _r({"USB": 3}, "User-mode driver problem (often a USB / phone / MTP device)."),
    ("microsoft-windows-driverframeworks-usermode", 10111): _r({"USB": 3}, "A device went offline because its driver failed."),
    ("microsoft-windows-driverframeworks-usermode", 10114): _r({"USB": 2}, "User-mode driver restarted repeatedly."),

    # ---- Network -----------------------------------------------------------------------
    ("tcpip", 4199): _r({"NETWORK": 4}, "IP address conflict with another device on the network."),
    ("tcpip", 4227): _r({"NETWORK": 3}, "TCP/IP ran out of ports (port exhaustion) - a program opens too many connections."),
    ("tcpip", 4231): _r({"NETWORK": 3}, "TCP/IP port exhaustion."),
    ("microsoft-windows-dns-client", 1014): _r({"NETWORK": 2}, "DNS name resolution timed out."),
    ("netlogon", 5719): _r({"NETWORK": 1}, "Could not reach a domain controller (normal off the company network)."),
    ("microsoft-windows-time-service", 36): _r({"NETWORK": 1}, "Clock has not synchronised for a long time."),
    ("microsoft-windows-time-service", 129): _r({"NETWORK": 1}, "Time server could not be reached."),

    # ---- Windows Server: AD / DNS / GPO -------------------------------------------------
    ("microsoft-windows-activedirectory_domainservice", 1311): _r({"AD": 6}, "Replication topology could not be built (KCC) - sites/links or DC unreachable."),
    ("microsoft-windows-activedirectory_domainservice", 1388): _r({"AD": 6}, "Lingering objects detected during replication."),
    ("microsoft-windows-activedirectory_domainservice", 1988): _r({"AD": 7}, "Lingering object on source DC - replication blocked (strict consistency)."),
    ("microsoft-windows-activedirectory_domainservice", 2042): _r({"AD": 10}, "DC has NOT replicated for longer than the tombstone lifetime."),
    ("microsoft-windows-activedirectory_domainservice", 2087): _r({"AD": 6}, "Replication failed: DNS lookup of the source DC failed."),
    ("microsoft-windows-activedirectory_domainservice", 2088): _r({"AD": 4}, "DNS lookup for source DC failed, but replication worked via NetBIOS - fix DNS."),
    ("microsoft-windows-activedirectory_domainservice", 1864): _r({"AD": 5}, "DC has not replicated with some partners for too long."),
    ("microsoft-windows-activedirectory_domainservice", 1925): _r({"AD": 5}, "Could not establish a replication link."),
    ("dfsr", 2213): _r({"AD": 9}, "DFSR stopped after a dirty shutdown - SYSVOL/DFS replication is PAUSED until resumed."),
    ("dfsr", 4012): _r({"AD": 10}, "DFSR stopped replicating this folder - disconnected too long (content-freshness)."),
    ("dfsr", 5002): _r({"AD": 4}, "DFSR cannot communicate with a partner."),
    ("dfsr", 5008): _r({"AD": 4}, "DFSR cannot communicate with a partner (RPC)."),
    ("dfsr", 5014): _r({"AD": 3}, "DFSR connection to a partner was interrupted."),
    ("dfsr", 4614): _r({"AD": 3}, "SYSVOL initialised but waiting for initial replication."),
    ("microsoft-windows-dns-server-service", 4013): _r({"AD": 5}, "DNS server is waiting for AD to load zones (slow start / replication issue)."),
    ("microsoft-windows-dns-server-service", 4000): _r({"AD": 7}, "DNS server could not open Active Directory - AD-integrated zones not loaded."),
    ("microsoft-windows-dns-server-service", 4015): _r({"AD": 7}, "DNS server hit a critical error talking to AD."),
    ("microsoft-windows-dns-server-service", 4004): _r({"AD": 5}, "DNS server could not enumerate zones in AD."),
    ("netlogon", 5722): _r({"AD": 4, "SECURITY": 2}, "A computer failed to authenticate - its machine account password is out of sync."),
    ("netlogon", 5723): _r({"AD": 4}, "Session setup failed - no trust account for this computer."),
    ("netlogon", 5805): _r({"AD": 4}, "Machine account failed to authenticate (secure channel)."),
    ("netlogon", 3210): _r({"AD": 5}, "This computer could not authenticate with the DC - broken secure channel (Test-ComputerSecureChannel -Repair)."),
    ("microsoft-windows-security-kerberos", 4): _r({"AD": 4}, "Kerberos KRB_AP_ERR_MODIFIED - duplicate SPN, stale DNS record or wrong account password."),
    ("microsoft-windows-kerberos-key-distribution-center", 14): _r({"AD": 3}, "KDC: no suitable key / encryption type for an account."),
    ("microsoft-windows-kerberos-key-distribution-center", 16): _r({"AD": 3}, "KDC: encryption type mismatch."),
    ("microsoft-windows-kerberos-key-distribution-center", 27): _r({"AD": 3}, "KDC: requested encryption type not supported by the account."),
    ("microsoft-windows-grouppolicy", 1129): _r({"AD": 4}, "Group Policy failed: no network connectivity to a DC."),
    ("microsoft-windows-grouppolicy", 1053): _r({"AD": 4}, "Group Policy could not resolve the user/computer name (DNS / DC)."),
    ("microsoft-windows-grouppolicy", 1054): _r({"AD": 4}, "Group Policy could not find a domain controller."),
    ("microsoft-windows-grouppolicy", 1055): _r({"AD": 4}, "Group Policy could not resolve the computer name."),
    ("microsoft-windows-grouppolicy", 1058): _r({"AD": 5}, "Group Policy could not read gpt.ini from SYSVOL (DFSR / SYSVOL / DNS)."),
    ("microsoft-windows-grouppolicy", 7016): _r({"AD": 2}, "A Group Policy extension failed."),
    ("microsoft-windows-time-service", 24): _r({"AD": 2}, "Time provider could not reach a time source."),
    ("microsoft-windows-time-service", 47): _r({"AD": 2}, "Time provider got no valid response from a manually configured peer."),
    ("microsoft-windows-time-service", 50): _r({"AD": 3}, "Time service detected a large time difference."),
    # ---- Failover clustering --------------------------------------------------------------
    ("microsoft-windows-failoverclustering", 1135): _r({"CLUSTER": 9, "NETWORK": 3}, "Cluster node was REMOVED from membership (lost heartbeats)."),
    ("microsoft-windows-failoverclustering", 1069): _r({"CLUSTER": 6}, "A cluster resource failed."),
    ("microsoft-windows-failoverclustering", 1146): _r({"CLUSTER": 6}, "Cluster resource host subsystem (RHS) crashed."),
    ("microsoft-windows-failoverclustering", 1177): _r({"CLUSTER": 10}, "Cluster LOST QUORUM and shut down."),
    ("microsoft-windows-failoverclustering", 1205): _r({"CLUSTER": 7}, "A clustered role could not be brought fully online."),
    ("microsoft-windows-failoverclustering", 1254): _r({"CLUSTER": 6}, "Clustered role exceeded its failover threshold."),
    ("microsoft-windows-failoverclustering", 1126): _r({"CLUSTER": 4, "NETWORK": 4}, "Cluster network interface is unreachable."),
    ("microsoft-windows-failoverclustering", 1127): _r({"CLUSTER": 5, "NETWORK": 4}, "Cluster network interface failed."),
    ("microsoft-windows-failoverclustering", 1129): _r({"CLUSTER": 5, "NETWORK": 4}, "Cluster network partitioned."),
    ("microsoft-windows-failoverclustering", 1130): _r({"CLUSTER": 6, "NETWORK": 4}, "Cluster network is down."),
    ("microsoft-windows-failoverclustering", 5120): _r({"CLUSTER": 7, "DISK": 4}, "Cluster Shared Volume was paused - storage path lost."),
    ("microsoft-windows-failoverclustering", 5142): _r({"CLUSTER": 7, "DISK": 4}, "Cluster Shared Volume is no longer accessible."),
    # ---- IIS ------------------------------------------------------------------------------
    ("microsoft-windows-was", 5002): _r({"IIS": 9}, "IIS app pool was DISABLED automatically after repeated worker failures (rapid-fail)."),
    ("microsoft-windows-was", 5009): _r({"IIS": 5}, "IIS worker process terminated unexpectedly."),
    ("microsoft-windows-was", 5010): _r({"IIS": 4}, "IIS worker process failed to respond to a ping."),
    ("microsoft-windows-was", 5011): _r({"IIS": 5}, "IIS worker process had a fatal communication error."),
    ("microsoft-windows-was", 5057): _r({"IIS": 5}, "App pool disabled - identity is invalid (password changed?)."),
    ("microsoft-windows-was", 5059): _r({"IIS": 6}, "App pool disabled - failed to start a worker process."),
    ("was", 5002): _r({"IIS": 9}, "IIS app pool was DISABLED automatically after repeated worker failures (rapid-fail)."),
    ("was", 5009): _r({"IIS": 5}, "IIS worker process terminated unexpectedly."),
    ("was", 5011): _r({"IIS": 5}, "IIS worker process had a fatal communication error."),
    ("microsoft-windows-iis-w3svc-wp", 2276): _r({"IIS": 3}, "IIS worker failed to load a module / configuration."),
    ("w3svc", 1014): _r({"IIS": 3}, "IIS failed to start a site - usually a port/binding conflict."),
    # ---- Backup / DHCP ----------------------------------------------------------------------
    ("microsoft-windows-backup", 5): _r({"BACKUP": 7}, "Windows Server Backup FAILED."),
    ("microsoft-windows-backup", 9): _r({"BACKUP": 6}, "Backup operation failed."),
    ("microsoft-windows-backup", 17): _r({"BACKUP": 4}, "Backup failed - target volume issue."),
    ("microsoft-windows-backup", 49): _r({"BACKUP": 5}, "Backup target not found / not available."),
    ("microsoft-windows-backup", 517): _r({"BACKUP": 6}, "Backup failed with errors."),
    ("microsoft-windows-backup", 521): _r({"BACKUP": 6}, "Backup of a volume failed."),
    ("microsoft-windows-backup", 546): _r({"BACKUP": 4}, "Backup failed - too little space on the target."),
    ("microsoft-windows-dhcp-server", 1056): _r({"NETWORK": 2}, "DHCP server has a dynamic IP - give it a static address."),
    ("microsoft-windows-dhcp-server", 1046): _r({"AD": 4}, "DHCP server is not authorised in AD and was shut down."),
    ("microsoft-windows-dhcp-server", 1063): _r({"NETWORK": 5}, "DHCP scope has NO free addresses left."),
    ("microsoft-windows-dhcp-server", 20090): _r({"NETWORK": 2}, "DHCP failover partner is unreachable."),

    # ---- Updates / system / apps ---------------------------------------------------------
    ("microsoft-windows-windowsupdateclient", 20): _r({"UPDATE": 3}, "A Windows update failed to install."),
    ("microsoft-windows-wininit", 1015): _r({"SYSTEM": 6}, "A critical system process died."),
    ("wininit", 1015): _r({"SYSTEM": 6}, "A critical system process died."),
    ("sidebyside", 33): _r({"APP": 2}, "App could not start - missing Visual C++ runtime (reinstall VC++ Redistributables)."),
    ("sidebyside", 35): _r({"APP": 2}, "Side-by-side configuration error (Visual C++ runtime)."),
    ("sidebyside", 59): _r({"APP": 1}, "Side-by-side configuration error."),
    (".net runtime", 1026): _r({"APP": 2}, "A .NET application crashed."),
    ("application hang", 1002): _r({"APP": 1}, "An application froze (stopped responding) and was closed."),
    ("microsoft-windows-user profiles service", 1511): _r({"SYSTEM": 3}, "Signed in with a TEMPORARY profile."),
    ("microsoft-windows-user profiles service", 1515): _r({"SYSTEM": 3}, "User profile was backed up / loaded with problems."),
}

# Provider families (regex on provider name) -> handled as a group
PROVIDER_FAMILIES = [
    (r"^microsoft-windows-hyper-v-vmms$", None, {"HYPERV": 3}, "Hyper-V management (VMMS) error - see the event text for the VM."),
    (r"^microsoft-windows-hyper-v-worker$", None, {"HYPERV": 4}, "Hyper-V VM worker process error (VM failed/crashed or could not start)."),
    (r"^microsoft-windows-hyper-v-storagevsp$", None, {"HYPERV": 3, "DISK": 2}, "Hyper-V virtual storage error."),
    (r"^microsoft-windows-hyper-v-hypervisor$", None, {"HYPERV": 4}, "Hypervisor error."),
    (r"^(mssqlserver|mssql\$\S+)$", {823, 824}, {"SQL": 10, "DISK": 6}, "SQL Server I/O error / page corruption (823/824)."),
    (r"^(mssqlserver|mssql\$\S+)$", {825}, {"SQL": 6, "DISK": 5}, "SQL Server read succeeded only after retries (825) - disk failing."),
    (r"^(mssqlserver|mssql\$\S+)$", {833}, {"SQL": 5, "DISK": 4}, "SQL Server I/O took longer than 15 seconds (833) - slow storage."),
    (r"^(mssqlserver|mssql\$\S+)$", {9002, 1105}, {"SQL": 6, "SPACE": 3}, "SQL Server log/filegroup is full (9002/1105)."),
    (r"^(mssqlserver|mssql\$\S+)$", {17883, 17884, 17888}, {"SQL": 6}, "SQL Server scheduler non-yielding / deadlocked schedulers."),
    (r"^(mssqlserver|mssql\$\S+)$", {18456}, {"SECURITY": 1}, "SQL Server login failed (wrong password or brute force)."),
    (r"^nvlddmkm$", None, {"GPU": 5}, "NVIDIA graphics driver error."),
    (r"^(amdkmdag|amdkmdap|atikmpag|atikmdag|amdwddmg)$", None, {"GPU": 5}, "AMD graphics driver error."),
    (r"^(igfx\w*|igdkmd\w*)$", None, {"GPU": 3}, "Intel graphics driver error."),
    (r"^iastor\w*$", {9, 129, 11}, {"DISK": 5}, "Intel RST storage driver timeout / reset."),
    (r"^(usbhub|usbhub3|usbxhci|microsoft-windows-usb-usbhub3|microsoft-windows-usb-usbxhci)$", None, {"USB": 3}, "USB controller / hub error."),
    (r"^(netwtw\d*|netwbw\d*|netwsw\d*|e1[a-z]express|e1[a-z]65x64|e2fexpress|rt640x64|rtux64w10|rt68cx21|rtcx21x64|athw\w*|qcamain\w*|mtkwl\w*|b57nd60a|bcmwl\w*|mrvl\w*)$",
     {27}, {"NETWORK": 2}, "Network link disconnected."),
    (r"^(netwtw\d*|netwbw\d*|netwsw\d*|e1[a-z]express|e1[a-z]65x64|e2fexpress|rt640x64|rtux64w10|rt68cx21|rtcx21x64|athw\w*|qcamain\w*|mtkwl\w*|b57nd60a|bcmwl\w*|mrvl\w*)$",
     None, {"NETWORK": 2}, "Network adapter driver error / warning."),
]

# Known noise: shown, but never counted as a problem
NOISE = {
    ("microsoft-windows-distributedcom", None): "DCOM permission warnings - appear on every PC, safe to ignore.",
    ("distributedcom", None): "DCOM permission warnings - appear on every PC, safe to ignore.",
    ("schannel", None): "TLS/SSL handshake alerts - usually harmless.",
    ("microsoft-windows-security-spp", None): "Licensing service scheduling messages - usually harmless.",
    ("perflib", None): "Performance counter messages - harmless.",
    ("esent", None): "Search / Store database messages - usually harmless.",
    ("microsoft-windows-user profiles service", 1534): "Profile notification - harmless.",
    ("volmgr", 46): "Crash dump initialisation message - harmless.",
    ("bthusb", 17): "Bluetooth pairing-key storage message - harmless.",
    ("microsoft-windows-wmi", 10): "WMI filter message - harmless.",
    ("lsasrv", 6155): "LSA protection message - harmless.",
    ("vss", None): "Volume Shadow Copy message - usually harmless.",
    ("microsoft-windows-devicesetupmanager", None): "Could not download device info/icons - harmless.",
    ("edgeupdate", None): "Edge updater - harmless.",
    ("gupdate", None): "Google updater - harmless.",
    ("microsoft-windows-restartmanager", None): "Restart Manager message - harmless.",
    ("microsoft-windows-kernel-eventtracing", None): "Event tracing session message - harmless.",
    ("microsoft-windows-winmgmt", None): "WMI message - usually harmless.",
    ("microsoft-windows-dhcpv6-client", None): "IPv6 DHCP message - usually harmless.",
    ("microsoft-windows-kernel-power", 172): "Connectivity state change - informational.",
}

GPU_MODULES = re.compile(r"(nvwgf2um|nvoglv|nvd3dum|nvcuda|nvlddmkm|atio6axx|atiumd|amdxx|amdvlk|aticfx|igd10|igd12|igdumd|igxelpicd|ig\d+icd|igc64|d3d11|d3d12|dxgi|vulkan-1)", re.I)
VCRT_MODULES = re.compile(r"(ucrtbase|msvcp\d+|vcruntime\d+|msvcr\d+)", re.I)
DOTNET_MODULES = re.compile(r"(clr\.dll|coreclr|clrjit|mscorwks)", re.I)

# ---------------------------------------------------------------------------------
#  What is likely to happen if the problem is ignored (per category)
# ---------------------------------------------------------------------------------
IMPACT = {
    "NVME": "Freezes and stutters while the drive resets, blue screens (0x7A, 0x133, 0xEF, 0x154), corrupted files - and if the drive is dying, Windows may stop booting and data can be lost.",
    "DISK": "Slow file access and freezes, corrupted or unreadable files, failed updates - and complete data loss if the drive fails.",
    "FS": "Files or folders become unreadable or vanish, apps and Windows Update fail, and the PC may eventually fail to boot.",
    "SPACE": "Windows Update, restore points and crash dumps stop working; apps crash or cannot save files.",
    "RAM": "Random blue screens with changing stop codes, apps crashing, corrupted downloads/installs and silently corrupted files.",
    "CPU": "Random reboots and blue screens (0x124, 0x101, 0x9C), mostly under load; instability usually gets worse, not better.",
    "PCIE": "Devices dropping out (GPU, NVMe, Wi-Fi), stutters, and fatal WHEA blue screens once errors become uncorrectable.",
    "POWER": "More sudden shutdowns: unsaved work is lost and each hard power-off risks file-system corruption and drive damage.",
    "THERMAL": "Lower performance from throttling, then emergency shutdowns; heat shortens the life of the CPU, board and drives.",
    "GPU": "Black screens and flicker, games/apps crashing, 'display driver stopped responding', and 0x116 / 0x117 blue screens.",
    "DRIVER": "More blue screens, devices that stop working, and problems after sleep/resume or Windows updates.",
    "USB": "Devices disconnecting, data loss on external drives, occasional blue screens (0xFE / 0x144).",
    "NETWORK": "Dropped connections, slow or no internet, VPN / remote sessions disconnecting.",
    "UPDATE": "Security fixes stay missing; Windows keeps retrying the same updates and wasting disk space.",
    "SYSTEM": "Windows features and apps failing in odd ways, errors that spread over time, possible boot failure.",
    "APP": "That program keeps crashing or losing work; the rest of Windows is usually unaffected.",
    "BIOS": "Sleep/power problems, device quirks and occasional instability.",
    "AD": "Users cannot log on or get the wrong Group Policy, logon scripts/SYSVOL break, stale passwords and objects spread between DCs.",
    "HYPERV": "VMs fail to start, save, checkpoint or back up; failed merges can leave VMs on a broken disk chain.",
    "CLUSTER": "Clustered roles fail over or go offline; if quorum is lost the whole cluster stops.",
    "IIS": "Websites return HTTP 503 errors and stay down until the application pool is started again.",
    "SQL": "Database corruption, failed queries and outages; ongoing I/O errors can mean real data loss.",
    "BACKUP": "Backups are not being made - there may be nothing to restore when you need it.",
    "SECURITY": "Account lockouts and a real risk that a password gets guessed.",
}

# ---------------------------------------------------------------------------------
#  Plain-language "what does this event actually mean" (+ optional specific fixes)
# ---------------------------------------------------------------------------------
EVENT_DETAILS = {
    ("microsoft-windows-kernel-power", 41): {"explain": "Logged when Windows starts and finds that the previous session did not shut down cleanly. It is a symptom, not a cause: a non-zero BugcheckCode means a blue screen happened; zero means the power was cut, the PC froze and was forced off, or it lost power."},
    ("eventlog", 6008): {"explain": "Logged at boot: 'The previous system shutdown was unexpected'. It confirms a crash, a freeze followed by a forced power-off, or a power loss at that time."},
    ("disk", 7): {"explain": "The drive reported a bad block - a sector that could not be read or written. Bad blocks almost always increase over time.",
                  "fix": ["Back up your files immediately.", "Check the drive in the Disks tab (health, uncorrected errors).", "Replace the drive - bad blocks are a sign of physical wear or damage."]},
    ("disk", 11): {"explain": "The storage controller got an error while talking to the drive. Common causes are a loose/bad cable, a bad port, a controller/driver problem or a failing drive."},
    ("disk", 51): {"explain": "An error happened while Windows was moving memory data to or from the page file on disk. Usually a drive or cable problem."},
    ("disk", 52): {"explain": "The drive's own self-monitoring (SMART) is predicting that it will fail soon.",
                   "fix": ["Back up everything NOW.", "Replace the drive as soon as possible - do not wait for it to fail."]},
    ("disk", 153): {"explain": "Windows had to retry a read/write because the drive did not answer in time. A few are harmless; many in a row mean the drive, its cable or its power saving is struggling."},
    ("disk", 157): {"explain": "The disk disappeared while it was in use (unplugged, lost power or the connection dropped)."},
    ("stornvme", 129): {"explain": "The NVMe driver had to reset the SSD because it stopped answering commands. The system usually freezes for a few seconds while this happens."},
    ("stornvme", 11): {"explain": "The NVMe SSD's controller reported an error to Windows."},
    ("storahci", 129): {"explain": "The SATA driver had to reset a drive because it stopped answering commands."},
    ("ntfs", 55): {"explain": "NTFS found corruption in the file-system structures on disk (the index of where files are stored).",
                   "fix": ["Run 'CHKDSK full repair at next restart' (Repairs tab).", "Check the drive health first - corruption is often caused by a failing drive or sudden power loss."]},
    ("microsoft-windows-ntfs", 55): {"explain": "NTFS found corruption in the file-system structures on disk (the index of where files are stored)."},
    ("ntfs", 50): {"explain": "Windows could not write data it had cached for a drive - that data was lost."},
    ("ntfs", 57): {"explain": "Windows could not flush cached data to the drive - recently written data may be lost or corrupted."},
    ("microsoft-windows-ntfs", 140): {"explain": "Windows could not write to the file-system transaction log - recently written data may be corrupted."},
    ("microsoft-windows-whea-logger", 1): {"explain": "WHEA (Windows Hardware Error Architecture) recorded a FATAL hardware error - the hardware itself reported a failure it could not recover from."},
    ("microsoft-windows-whea-logger", 17): {"explain": "A PCI Express link (between the CPU/chipset and a device like the GPU or NVMe) had a transmission error that the hardware corrected."},
    ("microsoft-windows-whea-logger", 18): {"explain": "The CPU raised a fatal Machine Check: a core, its cache or the internal bus reported an error it could not correct. Usually followed by a 0x124 blue screen.",
                                             "fix": ["Remove all CPU/RAM overclocks and undervolts (load BIOS defaults, disable XMP/EXPO to test).", "Update the BIOS / CPU microcode.", "Check CPU temperatures and cooler mounting.", "If it continues at stock settings, the CPU or motherboard may be faulty (warranty)."]},
    ("microsoft-windows-whea-logger", 19): {"explain": "The CPU detected a hardware error and corrected it. The PC keeps running, but repeated corrected errors mean something is unstable (overclock, undervolt, voltage, heat)."},
    ("microsoft-windows-whea-logger", 20): {"explain": "A fatal hardware error was reported by a device or bus."},
    ("microsoft-windows-whea-logger", 47): {"explain": "A memory (RAM) error was detected and corrected by ECC. Repeated ones point to a failing memory module."},
    ("display", 4101): {"explain": "The graphics driver stopped responding for more than 2 seconds, so Windows reset it (TDR - Timeout Detection and Recovery). The screen usually goes black or flickers briefly."},
    ("microsoft-windows-kernel-processor-power", 37): {"explain": "The firmware limited the CPU below its normal speed - it was too hot or hit a power limit."},
    ("microsoft-windows-resource-exhaustion-detector", 2004): {"explain": "Windows ran low on virtual memory (RAM + page file). The event text names the programs using the most memory at that moment."},
    ("microsoft-windows-windowsupdateclient", 20): {"explain": "A Windows update failed to install; the error code in the event says why."},
    ("service control manager", 7000): {"explain": "A Windows service or driver could not start when it was supposed to."},
    ("service control manager", 7026): {"explain": "One or more drivers that load at startup failed to load."},
    ("service control manager", 7031): {"explain": "A Windows service crashed; Windows may have restarted it automatically."},
    ("service control manager", 7034): {"explain": "A Windows service crashed unexpectedly."},
    ("microsoft-windows-kernel-pnp", 219): {"explain": "The driver for a device failed to load during startup, so the device may not work."},
    ("microsoft-windows-kernel-pnp", 411): {"explain": "Windows had a problem starting a device (see Device Manager for the device)."},
    ("dfsr", 2213): {"explain": "DFS Replication stopped after the server was shut down uncleanly and is waiting for you to resume it. SYSVOL / DFS shares will not replicate until then.",
                     "fix": ["Run the WMI command shown in the event text (wmic /namespace:\\\\root\\microsoftdfs path dfsrVolumeConfig where volumeGuid=\"...\" call ResumeReplication).", "Check why the server shut down uncleanly."]},
    ("dfsr", 4012): {"explain": "DFS Replication refused to replicate because this server was disconnected longer than allowed (content freshness). SYSVOL on this DC is now stale."},
    ("microsoft-windows-failoverclustering", 1135): {"explain": "A cluster node stopped answering heartbeats and was removed from the cluster. Its roles fail over to other nodes."},
    ("microsoft-windows-was", 5002): {"explain": "IIS turned off an application pool because its worker process crashed too many times in a short period (rapid-fail protection)."},
}
GENERIC_EXPLAIN = {
    "bsod": "Windows hit a fatal error and stopped with a blue screen (bug check) to prevent damage. The stop code identifies the type of failure; a crash dump was written to C:\\Windows\\Minidump (or MEMORY.DMP).",
    "lke": "Windows detected a serious kernel-level problem but recovered without a blue screen, and saved a 'live dump' in C:\\Windows\\LiveKernelReports.",
    "apperr": "A program crashed. The 'faulting module' shows where it crashed: inside the program itself, in a Windows library, or in a driver component (e.g. the graphics driver).",
    "memdiag": "Result of the Windows Memory Diagnostic test (mdsched).",
    "user32": "A program or user requested a shutdown/restart (normal, e.g. Windows Update restarts).",
    "wu19": "A Windows update was installed successfully.",
    "wu20": "A Windows update failed to install; the error code says why.",
    "multi": "Several different programs crashed in the same period.",
}

# ---------------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------------
def _parse_time(s):
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None

def _props(ev):
    p = ev.get("props") or []
    if isinstance(p, str):
        p = [p]
    return [str(x) if x is not None else "" for x in p]

def normalize_stop(code):
    if code & 0xF0000000 == 0x10000000:
        code &= 0x0FFFFFFF
    return code

def describe_stop(code):
    code = normalize_stop(code)
    if code in STOP_CODES:
        name, cats, hint = STOP_CODES[code]
        return name, cats, hint
    return "UNKNOWN_STOP_CODE", {"DRIVER": 4}, "Search this stop code online; open the .dmp file to find the driver."

def _hex(code):
    return "0x%08X" % code

def _noise(prov, eid):
    return NOISE.get((prov, eid)) or NOISE.get((prov, None))

def _cat_names(cats):
    return [CATEGORIES.get(c, {}).get("name", c) for c, _ in sorted(cats.items(), key=lambda kv: -kv[1])] if cats else []


def explain_for(key, prov, eid, cats):
    """Return dict(explain, impact, fix, categories) for an event classification."""
    pl = (prov or "").lower()
    det = EVENT_DETAILS.get((pl, eid), {})
    kind = key.split("|", 1)[0]
    explain = det.get("explain")
    if not explain:
        if kind == "bsod":
            explain = GENERIC_EXPLAIN["bsod"]
        elif kind == "kp41":
            explain = EVENT_DETAILS[("microsoft-windows-kernel-power", 41)]["explain"]
        elif kind in GENERIC_EXPLAIN:
            explain = GENERIC_EXPLAIN[kind]
        elif key == "multi-app":
            explain = GENERIC_EXPLAIN["multi"]
        else:
            explain = "Event %s logged by '%s'." % (eid, prov)
    if not cats and kind == "kp41":
        code = key.split("|", 1)[1]
        if code.isdigit() and int(code):
            cats = describe_stop(int(code))[1]
        elif code.startswith("0"):
            cats = {"POWER": 6}
    top = max(cats, key=cats.get) if cats else None
    impact = det.get("impact") or (IMPACT.get(top) if top else "") or "Informational - no direct impact expected."
    fix = det.get("fix") or (CATEGORIES.get(top, {}).get("fix") if top else []) or []
    return {"explain": explain, "impact": impact, "fix": list(fix), "categories": _cat_names(cats), "_cats": cats}


def _trend(recent, older, days_total):
    if recent + older < 3:
        return ""
    older_days = max(1, days_total - 7)
    rate_recent, rate_older = recent / 7.0, older / float(older_days)
    if older == 0 and recent >= 3:
        return "New: all %d occurrences are from the last 7 days." % recent
    if rate_recent > rate_older * 1.5:
        return "Getting MORE frequent (%d in the last 7 days vs %d before)." % (recent, older)
    if recent == 0:
        return "Not seen in the last 7 days (%d earlier) - may already be resolved." % older
    return "Steady: %d in the last 7 days, %d before." % (recent, older)


# ---------------------------------------------------------------------------------
#  Classify one event
#  returns dict(cats, meaning, detail, key) or None (unknown) or {"noise": text}
# ---------------------------------------------------------------------------------
def classify(ev, ctx):
    prov = (ev.get("p") or "").strip()
    pl = prov.lower()
    eid = int(ev.get("id") or 0)
    props = _props(ev)
    joined = " | ".join(props)
    msg = ev.get("msg") or ""

    # --- Blue screen ---
    if (pl in ("microsoft-windows-wer-systemerrorreporting", "bugcheck")) and eid == 1001:
        m = re.search(r"0x([0-9a-fA-F]{1,8})", joined) or re.search(r"0x([0-9a-fA-F]{1,8})", msg)
        if m:
            code = normalize_stop(int(m.group(1), 16))
            name, cats, hint = describe_stop(code)
            return dict(cats=cats, meaning=f"BLUE SCREEN {_hex(code)} {name}: {hint}",
                        detail=_hex(code), key=f"bsod|{code}", kind="crash", label=f"Blue screen {name}")
        return dict(cats={"DRIVER": 4}, meaning="Blue screen (stop code unknown).", detail="", key="bsod|?", kind="crash", label="Blue screen")

    # --- Kernel-Power 41 ---
    if pl == "microsoft-windows-kernel-power" and eid == 41:
        code = 0
        try:
            code = int(props[0]) if props else 0
        except ValueError:
            code = 0
        button = len(props) > 6 and props[6] not in ("", "0")
        sleeping = len(props) > 5 and props[5] not in ("", "0")
        t = _parse_time(ev.get("t", ""))
        if code:
            code = normalize_stop(code)
            name, cats, hint = describe_stop(code)
            # already counted via the BSOD event? then don't double count
            dup = t and any(abs((t - b).total_seconds()) < 900 for b in ctx["bsod_times"])
            return dict(cats={} if dup else cats,
                        meaning=f"Restarted after a blue screen {_hex(code)} {name}." + ("" if dup else f" {hint}"),
                        detail=_hex(code), key=f"kp41|{code}", kind="crash", label=f"Crash restart ({name})")
        if button:
            return dict(cats={"DRIVER": 2, "GPU": 1, "POWER": 1},
                        meaning="PC was FROZEN and forced off with the power button (hard hang: driver, GPU, RAM or PSU).",
                        detail="power button", key="kp41|button", kind="crash", label="Frozen - power button held")
        extra = " It happened during sleep/resume." if sleeping else ""
        return dict(cats={"POWER": 6, "THERMAL": 2, **({"DRIVER": 2} if sleeping else {})},
                    meaning="Sudden power loss / hard reset with no blue screen - power cut, PSU, battery, loose cable or overheating shutdown." + extra,
                    detail="no stop code", key="kp41|0" + ("s" if sleeping else ""), kind="crash", label="Sudden power loss")

    # --- Windows Error Reporting (application log): LiveKernelEvent ---
    if pl == "windows error reporting" and eid == 1001:
        if "LiveKernelEvent" in joined:
            idx = props.index("LiveKernelEvent") if "LiveKernelEvent" in props else -1
            code = ""
            if 0 <= idx and idx + 3 < len(props):
                code = props[idx + 3].strip().lower()
            if not code:
                m = re.search(r"P1:\s*(\w+)", msg)
                code = m.group(1).lower() if m else "?"
            code = code.lstrip("0") or code
            name, cats, hint = LIVE_KERNEL.get(code, ("LIVE_KERNEL_EVENT", {"DRIVER": 2}, "Kernel problem that Windows recovered from."))
            return dict(cats=cats, meaning=f"Live kernel event {code} {name}: {hint}", detail=code, key=f"lke|{code}", kind="event", label=name)
        if "BlueScreen" in joined:
            return dict(cats={}, meaning="Blue screen report (see blue screen events).", detail="", key="wer|bluescreen", kind="info", label="BSOD report")
        return {"skip": True}

    # --- Application crashes ---
    if pl == "application error" and eid == 1000:
        app = props[0] if props else "?"
        module = props[3] if len(props) > 3 else ""
        exc = (props[6] if len(props) > 6 else "").lower()
        ctx["crash_apps"].add(app.lower())
        if GPU_MODULES.search(module):
            cats, why = {"GPU": 4, "APP": 1}, f"crashed inside the graphics driver ({module})"
        elif VCRT_MODULES.search(module):
            cats, why = {"APP": 2}, f"crashed in the Visual C++ runtime ({module}) - reinstall VC++ Redistributables"
        elif DOTNET_MODULES.search(module) or "e0434352" in exc:
            cats, why = {"APP": 2}, ".NET exception - update the app / .NET runtime"
        elif module.lower() in ("ntdll.dll", "kernelbase.dll"):
            cats, why = {"APP": 1}, f"crashed in a Windows core DLL ({module})"
        else:
            cats, why = {"APP": 1}, f"crashed in {module or 'unknown module'}"
        return dict(cats=cats, meaning=f"{app} {why}.", detail=f"{app} / {module}", key=f"apperr|{app.lower()}|{module.lower()}", kind="event", label=f"{app} crash")

    # --- Memory diagnostic results ---
    if pl == "microsoft-windows-memorydiagnostics-results":
        lvl = int(ev.get("lvl") or 4)
        if lvl <= 3:
            return dict(cats={"RAM": 15}, meaning="Windows Memory Diagnostic FOUND ERRORS - RAM is faulty.", detail="", key="memdiag|fail", kind="crash", label="Memory test FAILED")
        return dict(cats={}, meaning="Windows Memory Diagnostic ran and found no errors.", detail="", key="memdiag|ok", kind="info", label="Memory test passed")

    # --- Shutdown / restart initiated by a process ---
    if pl == "user32" and eid == 1074:
        proc = props[0].split("\\")[-1] if props else "?"
        kind = props[4] if len(props) > 4 else "restart"
        reason = props[2] if len(props) > 2 else ""
        return dict(cats={}, meaning=f"{kind} requested by {proc}. {reason}".strip(), detail=proc, key=f"user32|{proc.lower()}", kind="info", label=f"{kind} by {proc}")

    # --- Windows Update installs ---
    if pl == "microsoft-windows-windowsupdateclient" and eid == 19:
        title = props[0] if props else ""
        return dict(cats={}, meaning=f"Installed update: {title}", detail=title, key=f"wu19|{title[:60]}", kind="update", label="Update installed")
    if pl == "microsoft-windows-windowsupdateclient" and eid == 20:
        err = props[0] if props else ""
        title = props[1] if len(props) > 1 else ""
        return dict(cats={"UPDATE": 3}, meaning=f"Update FAILED ({err}): {title}", detail=err, key=f"wu20|{title[:60]}", kind="event", label="Update failed")

    # --- VSS matters on servers (backups) ---
    if pl == "vss" and ctx.get("server") and int(ev.get("lvl") or 4) <= 2:
        return dict(cats={"BACKUP": 2}, meaning="Volume Shadow Copy (VSS) error - backups may fail.", detail="", key=f"vss|{eid}", kind="event", label="VSS error")

    # --- Noise ---
    n = _noise(pl, eid)
    if n:
        return {"noise": n}

    # --- Service Control Manager: include service name ---
    rule = KB.get((pl, eid))
    if rule:
        detail = ""
        if pl == "service control manager" and props:
            detail = props[0]
        else:
            m = re.search(r"Harddisk(\d+)", joined, re.I)
            if m:
                detail = "Disk " + m.group(1)
        meaning = rule["meaning"] + (f" [{detail}]" if detail else "")
        kind = "crash" if pl in ("eventlog",) else "event"
        return dict(cats=rule["cats"], meaning=meaning, detail=detail, key=f"{pl}|{eid}|{detail}", kind=kind, label=f"{prov} {eid}")

    for rx, ids, cats, meaning in PROVIDER_FAMILIES:
        if re.match(rx, pl) and (ids is None or eid in ids):
            return dict(cats=cats, meaning=meaning, detail="", key=f"{pl}|{eid}", kind="event", label=f"{prov} {eid}")

    return None


# ---------------------------------------------------------------------------------
#  Main analysis
# ---------------------------------------------------------------------------------
def _recency(t, now):
    if not t:
        return 0.7
    age = (now - t).days
    if age <= 7:
        return 1.0
    if age <= 30:
        return 0.75
    return 0.5

def likelihood(score):
    if score >= 25:
        return "HIGH"
    if score >= 10:
        return "MEDIUM"
    if score >= 3:
        return "LOW"
    return None

def analyze(events, now=None, server=False):
    now = now or datetime.now()
    # de-duplicate
    seen = set()
    evs = []
    for e in events or []:
        k = (e.get("log"), e.get("rid"), e.get("t"), e.get("p"), e.get("id"))
        if k in seen:
            continue
        seen.add(k)
        evs.append(e)
    evs.sort(key=lambda e: e.get("t") or "", reverse=True)

    ctx = {"bsod_times": [], "crash_apps": set(), "server": server}
    for e in evs:
        pl = (e.get("p") or "").lower()
        if pl in ("microsoft-windows-wer-systemerrorreporting", "bugcheck") and int(e.get("id") or 0) == 1001:
            t = _parse_time(e.get("t", ""))
            if t:
                ctx["bsod_times"].append(t)

    groups = {}        # key -> dict
    unknown = {}       # (prov,id) -> dict
    noise = {}         # (prov,id) -> dict
    timeline = []
    seq = []           # every classified event (for correlation)

    for e in evs:
        c = classify(e, ctx)
        t = _parse_time(e.get("t", ""))
        prov = e.get("p") or ""
        eid = int(e.get("id") or 0)
        if c is None:
            if int(e.get("lvl") or 4) <= 2:
                k = (prov, eid)
                u = unknown.setdefault(k, {"source": prov, "id": eid, "count": 0, "last": t, "first": t, "msg": ""})
                u["count"] += 1
                u["first"] = t or u["first"]
                if not u["msg"] and e.get("msg"):
                    u["msg"] = e["msg"]
            continue
        if c.get("skip"):
            continue
        if "noise" in c:
            k = (prov, eid)
            n = noise.setdefault(k, {"source": prov, "id": eid, "count": 0, "last": t, "meaning": c["noise"]})
            n["count"] += 1
            continue
        g = groups.get(c["key"])
        if not g:
            g = groups[c["key"]] = {"source": prov, "id": eid, "count": 0, "last": t, "first": t,
                                    "cats": c["cats"], "meaning": c["meaning"], "detail": c.get("detail", ""),
                                    "kind": c.get("kind", "event"), "label": c.get("label", ""),
                                    "recent": 0, "older": 0}
            g.update(explain_for(c["key"], prov, eid, c["cats"]))
        g["count"] += 1
        if t:
            g["first"] = t
            if (now - t).days < 7:
                g["recent"] += 1
            else:
                g["older"] += 1
        lvl = int(e.get("lvl") or 4)
        seq.append({"t": t, "prov": prov, "id": eid, "key": c["key"], "meaning": c["meaning"], "cats": c["cats"],
                    "kind": c.get("kind", "event"), "lvl": lvl, "label": c.get("label", "")})
        if c.get("kind") in ("crash", "update", "info") or (c["cats"] and max(c["cats"].values()) >= 6):
            timeline.append({"time": t, "source": prov, "id": eid, "what": c["meaning"], "kind": c.get("kind"), "key": c["key"]})

    # Many different apps crashing -> system-wide hint
    if len(ctx["crash_apps"]) >= 4:
        groups["multi-app"] = {"source": "Application Error", "id": 1000, "count": len(ctx["crash_apps"]),
                               "last": None, "first": None, "cats": {"RAM": 4, "SYSTEM": 3},
                               "meaning": f"{len(ctx['crash_apps'])} DIFFERENT programs crashed - points to RAM or Windows itself rather than one app.",
                               "detail": "", "kind": "event", "label": "Many apps crashing", "recent": 0, "older": 0}
        groups["multi-app"].update(explain_for("multi-app", "Application Error", 1000, {"RAM": 4, "SYSTEM": 3}))

    # Score categories
    scores = defaultdict(float)
    evidence = defaultdict(list)
    for g in groups.values():
        if not g["cats"]:
            continue
        rec = _recency(g["last"], now)
        mult = (1 + math.log2(max(1, g["count"]))) * rec
        for cat, w in g["cats"].items():
            pts = w * mult
            scores[cat] += pts
            evidence[cat].append((pts, g))

    problems = []
    for cat, sc in sorted(scores.items(), key=lambda kv: -kv[1]):
        lk = likelihood(sc)
        if not lk:
            continue
        info = CATEGORIES.get(cat, {"name": cat, "why": "", "fix": []})
        ev_sorted = sorted(evidence[cat], key=lambda x: -x[0])
        ev_lines = []
        for _, g in ev_sorted[:6]:
            when = g["last"].strftime("%Y-%m-%d") if g["last"] else ""
            ev_lines.append(f"{g['count']}x  {g['source']} {g['id']}  -  {g['meaning']}" + (f"  (last {when})" if when else ""))
        problems.append({"cat": cat, "name": info["name"], "score": round(sc, 1), "likelihood": lk,
                         "why": info["why"], "fix": info["fix"], "evidence": ev_lines})

    # Possible trigger: update installed shortly before the first crash
    insights = []
    crash_times = sorted(g_t for g_t in (g["first"] for g in groups.values() if g["kind"] == "crash" and g["first"]))
    if crash_times:
        first_crash = crash_times[0]
        ups = [x for x in timeline if x["kind"] == "update" and x["time"] and timedelta(0) <= first_crash - x["time"] <= timedelta(days=3)]
        if ups:
            insights.append(f"The first crash in this period ({first_crash:%Y-%m-%d %H:%M}) came within 3 days after installing: "
                            + "; ".join(sorted({u['what'].replace('Installed update: ', '') for u in ups})[:3])
                            + ". If problems started then, try uninstalling that update.")
    kp_power = sum(g["count"] for k, g in groups.items() if k.startswith("kp41|0"))
    if kp_power >= 3:
        insights.append(f"{kp_power} sudden power losses without a blue screen - this pattern points to power delivery (PSU / battery / outlet) or overheating, not software.")
    bs = [g for k, g in groups.items() if k.startswith("bsod|")]
    if len(bs) >= 3:
        insights.append(f"{len(bs)} DIFFERENT blue-screen stop codes - varied stop codes usually mean hardware (RAM / CPU / PSU) rather than one bad driver.")

    matched = sorted(groups.values(), key=lambda g: (-(max(g["cats"].values()) if g["cats"] else 0) * g["count"], g["source"]))
    timeline.sort(key=lambda x: x["time"] or datetime.min, reverse=True)

    # ---- per-event details: trend, correlation with nearby events, recent updates
    span_days = 7
    ts = [x["t"] for x in seq if x["t"]]
    if ts:
        span_days = max(7, (now - min(ts)).days + 1)
    for g in groups.values():
        g["trend"] = _trend(g.get("recent", 0), g.get("older", 0), span_days)
        g["categories"] = g.get("categories") or _cat_names(g["cats"])
    seq_t = sorted([x for x in seq if x["t"]], key=lambda x: x["t"])
    updates = [x for x in seq_t if x["key"].startswith("wu19|")]

    def related(x):
        lo, hi = x["t"] - timedelta(minutes=30), x["t"] + timedelta(minutes=3)
        near = {}
        for y in seq_t:
            if y["t"] < lo:
                continue
            if y["t"] > hi:
                break
            if y["key"] == x["key"] or not (y["cats"] or y["kind"] == "crash"):
                continue
            k = y["key"]
            if k not in near:
                mins = int((y["t"] - x["t"]).total_seconds() // 60)
                when = ("%d min before" % -mins) if mins < 0 else ("%d min after" % mins if mins > 0 else "same minute")
                near[k] = {"when": when, "text": "%s %s - %s" % (y["prov"], y["id"], y["meaning"]), "n": 0, "cats": y["cats"], "prov": y["prov"]}
            near[k]["n"] += 1
        out = ["%s: %s%s" % (v["when"], v["text"], (" (x%d)" % v["n"]) if v["n"] > 1 else "") for v in near.values()][:6]
        ups = [u for u in updates if timedelta(0) <= x["t"] - u["t"] <= timedelta(hours=72)]
        upd = None
        if ups:
            u = ups[-1]
            hrs = int((x["t"] - u["t"]).total_seconds() // 3600)
            upd = u["meaning"].replace("Installed update: ", "")
            out.append("%d h after installing: %s" % (hrs, upd))
        # verdict: what the surrounding evidence points to
        rel = defaultdict(float)
        src = defaultdict(set)
        for v in near.values():
            for c, w in (v["cats"] or {}).items():
                rel[c] += w * (1 + math.log2(v["n"]))
                src[c].add(v["prov"])
        own = dict(x["cats"] or {})
        if not own and x["key"].startswith("kp41|"):
            own = explain_for(x["key"], x["prov"], x["id"], {}).get("_cats", {})
        fam = {"NVME": "storage", "DISK": "storage", "FS": "storage", "SPACE": "storage", "RAM": "hw", "CPU": "hw", "PCIE": "hw", "THERMAL": "hw", "POWER": "hw"}
        verdict = ""
        cause = None
        if rel:
            rt = max(rel, key=rel.get)
            name = CATEGORIES.get(rt, {}).get("name", rt)
            own_top = max(own, key=own.get) if own else None
            evs = ", ".join(sorted(src[rt]))
            if own_top and (rt == own_top or fam.get(rt) and fam.get(rt) == fam.get(own_top) or rt in own):
                verdict = "Most likely cause: %s - backed up by %s events logged just before/around it." % (name, evs)
                cause = rt
            elif x["kind"] == "crash":
                verdict = "Possibly triggered by: %s (%s events logged just before it)." % (name, evs)
            else:
                verdict = "Logged together with %s events (%s)." % (name, evs)
        elif x["key"].startswith("kp41|0"):
            verdict = "Nothing else was logged before it - typical of a sudden power cut, a PSU/battery problem or a hard freeze."
        elif x["kind"] == "crash":
            verdict = "No other warning events were logged in the 30 minutes before it - use the stop code / event itself to guide the fix."
        if upd and x["kind"] == "crash" and not rel:
            verdict += " It happened shortly after a Windows update - if this is new since then, the update (or a driver it installed) may be involved."
        return out, verdict.strip(), cause

    instances = []
    for x in reversed(seq_t):
        w = max(x["cats"].values()) if x["cats"] else 0
        if x["kind"] in ("info", "update"):
            continue
        if not (x["kind"] == "crash" or w >= 6 or (x["lvl"] <= 1 and w > 0)):
            continue
        g = groups.get(x["key"], {})
        sev = "CRITICAL" if (x["kind"] == "crash" or w >= 8 or x["lvl"] <= 1) else "WARNING"
        instances.append({
            "time": x["t"], "source": x["prov"], "id": x["id"], "severity": sev,
            "title": g.get("label") or "%s %s" % (x["prov"], x["id"]), "meaning": x["meaning"],
            "explain": g.get("explain", ""), "impact": g.get("impact", ""), "fix": g.get("fix", []),
            "categories": g.get("categories", []),
            "recurrence": ("This exact event occurred %d time(s) in the period. %s" % (g.get("count", 1), g.get("trend", ""))).strip(),
        })
        inst = instances[-1]
        inst["related"], inst["verdict"], cause = related(x)
        if cause and cause in CATEGORIES:
            inst["impact"] = IMPACT.get(cause, inst["impact"])
            inst["fix"] = list(CATEGORIES[cause]["fix"])
            nm = CATEGORIES[cause]["name"]
            inst["categories"] = [nm] + [c for c in inst["categories"] if c != nm]
        if len(instances) >= 300:
            break
    info_by_key = {k: g for k, g in groups.items()}
    for x in timeline:
        g = info_by_key.get(x.get("key"), {})
        x["explain"], x["impact"], x["fix"], x["categories"] = g.get("explain", ""), g.get("impact", ""), g.get("fix", []), g.get("categories", [])
    for p in problems:
        p["impact"] = IMPACT.get(p["cat"], "")

    return {
        "total_events": len(evs),
        "problems": problems,
        "insights": insights,
        "matched": matched,
        "unknown": sorted(unknown.values(), key=lambda u: -u["count"])[:40],
        "noise": sorted(noise.values(), key=lambda n: -n["count"]),
        "timeline": timeline[:200],
        "instances": instances,
    }
