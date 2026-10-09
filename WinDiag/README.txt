WinDiag 3.3 - Portable Windows Diagnostic Toolkit
==================================================

QUICK START
  1. Copy this whole WinDiag folder to a USB stick.
  2. On the PC to check, double-click WinDiag.exe and click Yes on the admin prompt.
  3. A small window shows the security check; tick "I own this PC..." and click Start scan
     (or Skip to go straight to the tools). The Dashboard opens at once and fills in while
     the scan runs in the background - you can use every page meanwhile. Esc / Stop ends it.

  Windows SmartScreen may say "Windows protected your PC" because the exe is not
  code-signed: click "More info" -> "Run anyway". Some antivirus programs flag
  unsigned PyInstaller apps - if so, use the PowerShell version (see below).

PAGES
  Dashboard          Health overview, top issues, live performance, component tiles.
  Spec Sheet         Every hardware / Windows detail on one page, exportable.
  System             Windows, activation, model, serial, BIOS, Secure Boot, TPM,
                     CPU, RAM sticks, GPU/driver, Device Manager problems.
  Disks              Drive health, SSD wear, temperature (+ drive limit), errors, free space.
                     NEW: if the Event Analyzer finds NVMe/disk resets AND the drive is hot
                     (60 C+ or near its own limit), the Summary says heat is a likely cause.
  Errors & Crashes   Blue screens, crash dumps, unexpected shutdowns, WHEA, app crashes.
  Network            Adapters, IP/DNS, router/internet/DNS tests, Wi-Fi, proxy, hosts.
  Startup            Startup programs, scheduled tasks, stopped services, top processes.
  Security           Antivirus, Defender, firewall, BitLocker, updates, battery.
  Server Roles       (NEW) Windows Server: installed roles, role services (AD DS, DNS,
                     DHCP, IIS, Hyper-V, Failover Cluster, SQL, WSUS...), IIS sites /
                     app pools, AD replication (repadmin), SYSVOL, FSMO, cluster nodes
                     and CSVs, Hyper-V VMs + old checkpoints, expiring certificates,
                     failed logons / brute force (24h), RDP NLA, SMBv1, Server Backup.
  Virtualization     (NEW) Detects Hyper-V / Azure / VMware / KVM-Proxmox / VirtualBox /
                     AWS / GCP / Xen, checks guest tools + integration services,
                     VirtIO drivers, and domain time-sync mistakes on VMs.
  EVENT ANALYZER     Reads the System + Application event logs (7/30/90 days),
                     matches event IDs and blue-screen stop codes against a
                     built-in knowledge base and ranks the LIKELY CAUSE:
                       NVMe SSD, hard drive/cable, file system, RAM, CPU/overclock,
                       PCIe, power supply/power loss, overheating, GPU, drivers,
                       USB, network, Windows Update, system files, apps, BIOS,
                       + servers: Active Directory/DNS/GPO, DFSR, Hyper-V host,
                       failover cluster, IIS, SQL Server, backups/VSS.
                     Each cause shows the evidence (which events, how many, when)
                     and what to do. Tabs: Recognised events, Timeline,
                     Unrecognised errors, Harmless noise (e.g. DCOM 10016).
                     Double-click any row for details.
  Repairs & Tools    Restore point, DISM + SFC, CHKDSK, clear temp, network reset,
                     Windows Update reset, Defender, memory test, battery/energy
                     reports + shortcuts to Windows tools. Nothing runs until clicked.

HOVER EXPLANATIONS (new in 2.2)
  Hover over any blue screen or critical event - in Errors & Crashes, in
  Event Analyzer > Critical events / Recognised events / Timeline, on the
  Summary cards and on the Likely problems cards - to see:
    - What happened and what the event actually means
    - What it correlates with: other events logged in the 30 minutes before
      (e.g. NVMe resets just before a 0x7A blue screen), a Windows update
      installed shortly before, and a "most likely cause" verdict
    - What is likely to happen if it is ignored
    - How to fix it, step by step
    - How often it happens and whether it is getting more frequent
  Double-click a row to open a copyable version. The HTML report has the
  same details for every critical event (hover or click to expand).

GUIDED FIX (new in 2.3)
  Step-by-step fixes that follow Microsoft's documented troubleshooting procedures
  (Microsoft Learn: stop-error troubleshooting, Bug Check Code Reference, Common
  Windows Update errors, PowerShell Diagnostics module).
  Guides: Blue screens | Windows Update failures | Disk / NVMe / file-system errors |
          Unexpected shutdowns | Graphics driver crashes | Hardware (WHEA/CPU/RAM) |
          Driver and device problems
  - WinDiag recommends the guides that match what it found (Summary banner,
    "Guided fix" buttons on the Event Analyzer problem cards).
  - Every step explains why, links the official Microsoft page, shows the exact
    command, runs the built-in Windows tool, and then CHECKS THE RESULT:
    SFC log, DISM/CHKDSK exit codes, CHKDSK and Memory Diagnostic results in the
    event log (Get-WinEvent), disk latency (Get-Counter), update history, etc.
  - Crash dump analysis: runs Microsoft's debugger (cdb, "!analyze -v") on your
    minidumps and names the driver that crashed. Needs WinDbg - the step has an
    "Install WinDbg" button (winget install Microsoft.WinDbg). First run downloads
    Microsoft symbols (a few minutes, needs internet). Output is saved to
    crash_dump_analysis.txt in the report folder.
  - Stop codes open their Microsoft reference page; update errors are matched to
    Microsoft's error table with the official fix.
  - Progress is saved (Reports\guided_<PC>.json). Steps that need a restart
    (memory test, CHKDSK repair) are re-checked automatically when WinDiag is
    opened again; tick "Reopen WinDiag after restart" to have it start by itself.
  - "Confirm the fix" checks the event log for NEW problems since you started.
  - Advanced steps (Driver Verifier, clean boot, System Restore) are marked and
    explained - Driver Verifier deliberately causes crashes, read its notes first.

NEW IN 4.0
  NEW USER INTERFACE (PySide6 / Qt 6) - the old toolkit crashed or froze when the window was
  moved between monitors or scaled. Qt handles per-monitor scaling natively.
    - Moving the window between screens of different scaling (100% / 150% / 200%), resizing,
      maximising and minimising no longer freezes or crashes.
    - Every slow job (PowerShell, tests, network, file work) runs in its own background thread;
      the window stays responsive while a scan, drive test, RAM test or monitor runs.
    - Closing the window while something runs stops it cleanly (no hang, no error dialog).
    - Pages are built in the background while you work, so opening a page is instant.
  NEW LOOK: dense, flat console style - Manrope text, JetBrains Mono for every number, Syne for
    titles, 1px borders, no shadows or glows. Dashboard has live CPU/memory, an issue donut and
    key/value panels. Fonts are bundled (SIL Open Font License, see source\fonts).
  Everything from 3.3 is kept: same checks, same accuracy fixes, same safety gates (PIN,
    confirmations, drive-wipe protections). Drive wipe now also asks a final danger confirmation.
  Small additions: Reports panel in Settings; "Delete items older than 30 days" in Files asks for the PIN.

NEW IN 3.3
  NO LOADING SCREEN: the full-screen start / scanning / results screens are gone.
    - A small start popup shows this PC, the security check and the permission tick box.
    - The scan runs in the background; the Dashboard and every page fill in as each check
      finishes. Progress is in the top bar ("Scanning 45%") and the status bar (what is
      running, how many checks are done, time left). Stop / Esc ends it at any time.
    - Pages you aren't looking at are drawn when you open them, and the Dashboard only
      redraws when something changed - no freezing or flicker while a scan runs.
    - A stopped scan is labelled "Scan stopped - partial results" (no false warnings).
  MORE ACCURATE ON EVERY PC (results of a full test round of every page and parser):
    - Health score: the same problem reported twice counts once, "check could not run"
      no longer lowers the score, any critical problem shows red, and the score can't hit
      0 because of a few issues.
    - Drives: worn-but-healthy SSDs are no longer CAUTION (wear only: CAUTION at 30% life
      left, CRITICAL at 10%); one NVMe media error = warning, not critical; Intel RST /
      RAID SSDs detected; Crucial/Micron and Phison/Intel SMART quirks handled; a drive
      unplugged during a read test says "disconnected", not "bad sectors".
    - Battery: fixed the "a bytes-like object..." error; unknown charge rates ignored;
      wear per year only since the last battery replacement.
    - RAM: correct DDR type names, "half speed" no longer misreported, honest PASS text,
      new address test (finds RAM where two blocks share cells).
    - Network: router that ignores ping no longer reported as packet loss; DNS check
      separates filtering (INFO) from real hijacking; Wi-Fi works on non-English Windows,
      Wi-Fi 6E (6 GHz) handled; traceroute and time-sync no longer depend on English text;
      well-known apps installed per user no longer flagged as risky firewall rules.
    - Security check: Process Explorer replacing Task Manager is fine; Defender in passive
      mode with another antivirus / on Windows Server is not "critical"; warns when WinDiag
      runs as a different user than the one signed in.
    - Locked-down PCs: works when Group Policy blocks scripts (AllSigned / disabled),
      explains Constrained Language Mode and antivirus (AMSI) blocks in plain words;
      non-English Windows and non-Gregorian calendars read correctly.
    - Windows Update: Defender definition updates shown as "Pending (auto)", not missing.
  SAFER: the technician PIN now also covers Guided Fix repairs, network fixes and
    switching the PIN protection off; privacy mode also applies to "Copy text".
  Search also finds the Guided Fix guides.

NEW IN 3.2
  SECURITY CHECK BEFORE SCANNING (start screen, ~3 s, read-only):
    - WinDiag's own files are checked against WinDiag.sha256 (shipped next to the exe).
      If WinDiag.exe was changed since release, the start screen says so in red.
      The exe's SHA-256 is also shown so you can compare it with the value you noted.
    - Windows PowerShell is Microsoft-signed and not redirected (Image File Execution
      Options hijacks of powershell/cmd/taskmgr/Defender tools are flagged).
    - Defender running, no ACTIVE threat, not disabled by policy, test-signing off.
    - "I own this PC or have permission" tick box before a scan (can be switched off).
  TECHNICIAN PIN (Settings): optional PIN to open WinDiag and/or to use risky actions
    (repairs, quarantine/restore, secure delete, tune-up changes, network fixes, drive
    wipe). Stored as a salted PBKDF2 hash in WinDiag_settings.json. Unlocks for 10 min.
  PRIVACY MODE (Settings): reports and spec-sheet exports hide serial numbers, MAC
    addresses and user names.
  STOP ANY SCAN: "Stop" button in the top bar (and Esc) ends every running check at once.
    Repairs, fixes and drive wipes are NOT stopped half-way - they run to completion.

  BATTERY page (laptops): health % (full-charge vs design capacity), charge cycles,
    chemistry, maker, wear per year, live charge % and power draw in watts, capacity
    history chart from Windows' battery report, estimated runtime now vs when new,
    charge-limit tip for your laptop brand (Lenovo, Dell, HP, ASUS, Surface...).
    Buttons: Full battery report, Sleep drain report (sleepstudy), Energy report.
    Under 80% = worn, under 50% = replace. Health above 105% = gauge needs calibrating.

  NETWORK TOOLS page (8 tabs):
    Connection    - live ping monitor: router vs internet, latency / jitter / loss, chart,
                    and what it means (home network problem vs provider problem).
    Speed & DNS   - speed test (Cloudflare speed-test servers, 50-200 MB), DNS benchmark
                    (your DNS vs Cloudflare / Google / Quad9 / OpenDNS), DNS hijack check
                    (NXDOMAIN redirection, wrong answers), public IP (off by default -
                    Settings > Allow public IP lookup).
    Route & ports - traceroute, MTU check, outgoing port check (mail servers, RDP, ...).
    Wi-Fi         - signal, band, channel, standard, link rates, channel congestion chart
                    with the quietest channel, nearby networks, Windows WLAN report.
    Adapters      - link speed, duplex, errors / dropped packets, power saving, driver age.
    Ports & firewall - listening ports with program/service, programs online now,
                    firewall profiles and risky inbound rules (programs in user/temp
                    folders, remote access open to everyone on public networks...).
    Local network - devices on THIS PC's own network (ping + neighbour table, names,
                    random-MAC hint), this PC's shares, mapped drives, SMB1, time sync.
    Fixes         - renew IP, flush DNS, restart adapter, switch DNS (Cloudflare/Google/
                    Quad9/back to automatic), clear proxy, rejoin / forget Wi-Fi, NIC
                    power saving off, Winsock + TCP/IP reset. EVERY fix measures router,
                    internet, DNS and web test BEFORE and AFTER and shows the difference.
  GUIDED FIX: three new playbooks - "No internet", "Slow internet", "Wi-Fi keeps
    dropping" - with automatic checks (connection test, Wi-Fi signal, real disconnects
    from Windows' WLAN log, adapter power saving, DNS speed) and one-click measured fixes.

  DEFENDER QUARANTINE - permanent delete (Files & Recovery > Quarantine). Only Windows'
    supported methods; WinDiag never touches Defender's protected quarantine folder:
    - Delete one item: opens Protection history -> click the item -> Actions -> Remove.
    - Remove active threats: Remove-MpThreat (threats detected but not yet removed).
    - Auto-delete quarantine after 1 / 7 / 30 / 90 days / never
      (Set-MpPreference -QuarantinePurgeItemsAfterDelay; Windows default 90 days).
      Group Policy / Intune can override this - WinDiag tells you if Windows kept the old value.

  DRIVE WIPE - SAFETY LAYERS (Drive Health > Wipe this entire drive):
    Off by default: turn it on in Settings > Drive wipe. Needs admin and the PIN if set.
    1. WHAT'S ON IT: model, serial, size, data size, every volume with its top folders,
       most recently changed files, Windows folder / user profiles found, Open in Explorer.
    2. HARD BLOCKS (the wipe can't start): Windows / boot drive, WinDiag's own drive, the
       Reports drive, page file, hibernation file, crash-dump location, Windows Recovery
       (WinRE), Hyper-V VM disks, attached VHDs, Storage Spaces pools, dynamic disks
       (software RAID), hardware RAID volumes, cluster disks, programs or services running
       from it, write-protected disks, laptop on battery.
       Warnings: failing drive, SSD (use the maker's Secure Erase too), BitLocker.
    3. IDENTITY LOCK: the drive is pinned by serial + size + model. Checked again right
       before the wipe, and a third time by the wipe window itself - if disk N is now a
       different drive (unplugged / swapped / renumbered), NOTHING is erased.
    4. CONFIRM: two tick boxes, type the last 4 characters of the serial number, the
       button stays locked for 10 seconds; optional USB unplug / re-plug check; final
       summary; then a 10-second countdown with Cancel.
    5. AFTERWARDS: WinDiag reads ~770 random blocks across the whole drive and checks they
       are all zeros, then (optional) creates one empty NTFS partition, and saves a wipe
       log + an HTML ERASURE CERTIFICATE (model, serial, method, times, verification
       result, PC, operator, certificate ID) in the Reports folder.
    Method: diskpart "clean all" (one pass of zeros, comparable to NIST SP 800-88 Clear for
    hard drives). SSDs: spare flash blocks can't be reached from Windows - use the maker's
    Secure Erase / Sanitize as well, or destroy the drive, when it really matters.

NEW IN 3.1
  START SCREEN: this PC at a glance + three choices:
    Quick scan (~1 min), Full scan (~3-5 min), Go to tools (no scan).
    Options: check Windows Update online, include the Security Scan, event history
    (7/30/90 days), "start a full scan automatically next time".
  SCANNING SCREEN: progress ring with elapsed / time left, a checklist of every step
    (waiting / running / done / failed), live issue counter, Cancel. The main pages are
    filled in once at the end - no flicker while scanning. The percentage is an honest
    estimate from how long each step usually takes (Windows doesn't report progress).
  RESULTS SCREEN: health score, the 3 most important issues in plain words, then
    View full details / Start the recommended fix / Save report / New scan.
  "Run all checks" in the top bar uses the same scanning screen.

  UPDATES & DRIVERS (checked ONLINE): asks Windows Update - Microsoft's servers, or your
    company's WSUS - which updates THIS PC is missing: important/security, optional and
    driver updates, and whether a restart is pending. "Install important updates"
    downloads and installs them through Windows Update itself (admin).
    DRIVER AGE REPORT: graphics, network, storage, audio, chipset, Bluetooth, firmware...
    with version, date and age. "Update on Windows Update" = Microsoft has a newer driver
    for that exact device. "Old" = 3+ years (hint, not proof). Double-click opens the
    maker's download page (NVIDIA, AMD, Intel, Samsung, or your PC maker's site).
    Note: there is no single online database for all drivers/BIOS - only what Windows
    Update offers is compared exactly; the rest is judged by age.

  TUNE-UP (safe, reversible, measured) - no registry cleaners or "RAM boosters":
    Windows updates, startup apps (enable/disable exactly like Task Manager), power plan,
    free disk space (temp files, Recycle Bin, Storage Sense), TRIM for SSDs, Fast Startup.
  BEFORE / AFTER: "Take measurement" records numbers Windows itself measures - boot time
    (Windows' own boot timer), disk response time, idle CPU, memory in use, processes,
    startup apps, free space, temp files, errors and crashes (7 days), missing updates.
    Every full scan and every Guided Fix records one automatically; the Tune-up page
    compares any two (better / worse / no change). Boot time only changes after a restart.
  GUIDED FIX: the final "Confirm the fix" step now also shows the before/after numbers.
    Windows Update guide: new step "Check online for missing updates" - passes only when
    Windows Update reports nothing important missing.

NEW LOOK (3.0)
  Redesigned dark interface (near-black layers, blue accent, line icons, status dots).
  Window opens at 1440x900 (minimum 1200x700). The sidebar is grouped into
  Overview / Hardware / Windows / Tools / Servers & VMs, with issue counts per page.
  Top bar: page title + description, SEARCH (pages, issues, sections and repairs -
  press Enter to jump), Report and Run all checks.
  DASHBOARD (replaces Summary):
    - Health score ring, critical / warning counts, checks completed
    - Recommended Guided Fix (or the one in progress)
    - Top issues (click to open the right page, hover for the explanation)
    - Live performance: CPU and memory, last 60 seconds
    - Component health tiles: Windows, Processor, Memory, Storage, Security, Network
    - Problem events per day for the last 30 days, and quick actions
  SPEC SHEET (new page): device, Windows, CPU, memory per slot, graphics, drives with
    health, motherboard/BIOS/TPM/Secure Boot, network adapters, security and battery.
    "Export spec sheet" saves a printable HTML (+ TXT) to the report folder;
    "Copy as text" puts it on the clipboard.
  Check pages (System, Storage, Network...) now show each section as a card: key/value
  grids and sortable tables with status dots instead of a text dump.

MEMORY (RAM) (new in 2.6)
  Checked automatically after the main checks (or click "Check RAM").
  SLOTS: a picture of every RAM slot - filled or empty, size, type (DDR4/DDR5...), speed,
    maker; hover a stick for part and serial number. Flags: RAM running below its rated
    speed (XMP/EXPO off), mixed kits, single-channel, CPU-reported memory errors (WHEA)
    and the last Windows Memory Diagnostic result.
  RAM TEST (inside Windows, no restart): takes most of the FREE memory, locks it into
    physical RAM (so nothing goes to the page file), writes patterns 00/FF/55/AA/random
    and reads them back. 1 pass, 3 passes, or until you stop it.
    Only WinDiag's own memory is used - files and other programs are not touched.
    The grid shows the tested memory as 1,200 squares: passed / testing / ERROR.
  LIMITS: memory Windows itself is using (~15-30%) can't be tested from inside Windows,
    and Windows doesn't reveal physical addresses - so an error means "RAM is faulty" but
    not WHICH stick. The page walks you through testing one stick at a time. For a full
    test with physical locations use MemTest86 from a bootable USB (button on the page).

DRIVE HEALTH (new in 2.5)
  Checks every drive automatically after the main checks (or click "Check drives").
  Health data comes straight from the drive, no extra software needed:
    NVMe SSDs   - the NVMe SMART/Health log: life used, spare blocks, media errors,
                  critical warnings, read-only mode, temperature + time spent hot,
                  unsafe shutdowns, data written/read.
    SATA SSD/HDD - SMART attributes + thresholds: reallocated / pending / uncorrectable
                  sectors, SSD life left, program/erase failures, cable CRC errors,
                  spin retries, temperature, hours.
  Each drive gets GOOD / CAUTION / CRITICAL and a health % (like CrystalDiskInfo).
  USB sticks and virtual disks usually report no health data (shown as UNKNOWN).

  FAILING DRIVES (health below 70%, CAUTION or CRITICAL): tests are switched OFF.
  Testing a weak drive for hours can finish it off. You get what was found and what to
  do instead: copy files off / clone first, recover deleted files, Guided Fix (disk),
  warranty lookup, replace.

  HEALTHY DRIVES get tests. ALL TESTS ARE READ-ONLY - your data is not touched:
    Quick read test    reads a 1 MB sample from 1,200 spots across the drive (minutes).
    Full surface scan  reads every sector (about 1-3 h per TB on HDDs; faster on SSDs);
                       you can stop it any time.
    Short/long self-test  run inside the drive itself (needs smartctl - see below).
  The disk is opened with read permission only; Windows rejects any write through it.
  If a test finds unreadable sectors, the drive is re-rated CRITICAL immediately.

  DRIVE MAP: 1,200 squares = the whole disk from start to end, with a partition bar.
    Usage view     - used / partly used / free / unpartitioned (read from the file
                     system's allocation bitmap, read-only).
    Read test view - normal / slower / very slow (weak sectors) / unreadable.
    Hover a square for its position, partition, % used and read speed.
    SSDs: this shows the logical blocks Windows sees. The physical NAND layout is hidden
    inside the SSD controller (wear levelling) and no Windows tool can show it.

  WIPE ENTIRE DRIVE: removes all partitions and overwrites every sector with zeros
    (Microsoft diskpart "clean all"), optionally creates a new empty NTFS partition.
    Refused on the Windows drive and on the drive WinDiag runs from. Needs you to type
    WIPE <disk number> to confirm. Cannot be undone. For SSDs the maker's Secure Erase
    tool also clears hidden spare areas.
  BRING BACK DELETED DATA: "Recover deleted files" on a drive opens Files & Recovery with
    that drive selected (Recycle Bin, Previous Versions, winfr).

  SMARTCTL (optional, for self-tests): click "Get smartctl" (installs smartmontools with
    winget), then "Copy smartctl to USB" - it is saved as tools\smartctl.exe next to
    WinDiag.exe and used on every PC after that.

SECURITY SCAN (new in 2.4)
  Read-only. Click "Run security scan" (1-5 minutes). Three layers - it uses
  Microsoft Defender rather than a home-made antivirus:
  1. Defender: real-time/tamper protection, disabled-by-policy, EXCLUSIONS
     (malware adds these), definition age, detection history, other AV products.
     Buttons: update definitions, quick / full / Offline scan.
  2. Persistence: every auto-start place - Run keys, Startup folders, scheduled
     tasks, services, WMI subscriptions, Winlogon, IFEO debugger hijacks (incl. the
     sticky-keys backdoor), AppInit - plus running programs, hosts file, proxy/PAC,
     DNS, admin accounts and cleared event logs. Every program's digital signature
     is checked; flags things like unsigned programs in Temp/Downloads, system
     names in the wrong folder (fake svchost.exe), encoded PowerShell, mshta/
     regsvr32/certutil tricks. Microsoft-signed items are hidden by default.
  3. Certificates & boot: trusted roots compared with Microsoft's official list
     (downloaded with certutil -generateSSTFromWU), roots WITH A PRIVATE KEY
     (Superfish-style), an HTTPS-interception test against microsoft.com, weak
     certificates; Secure Boot, test-signing, integrity checks, kernel debug,
     Memory Integrity (HVCI), vulnerable-driver blocklist, unsigned drivers.
  "Suspicious" = worth checking, not proof of malware. Hover any item for why it
  was flagged and what to do. Known antivirus / company-proxy HTTPS scanning is
  recognised and shown as info.
  QUARANTINE button: removes the item REVERSIBLY (restore point first; file is
  neutralised; the Run value / task / service / WMI / certificate is saved) - undo
  it in Files > Quarantine.
  VIRUSTOTAL (optional, off by default): paste a free API key and look up the
  flagged unsigned files. Only SHA-256 fingerprints are sent, never files. Free
  keys allow 4 lookups per minute. "Remember key" saves it in
  WinDiag_settings.json next to the exe - don't tick it on a shared USB stick.
  If critical items are found, the Summary recommends the new
  "Suspected malware / PC compromised" Guided Fix (Microsoft's malware-removal
  procedure: scan, update, full scan, MSRT, Offline scan, remove persistence,
  certificates, proxy/hosts, passwords from a clean device, re-scan, reset).

FILES & RECOVERY (new in 2.4)
  Quarantine    List / restore WinDiag quarantines (stored in
                C:\ProgramData\WinDiag\Quarantine), delete ones older than 30 days,
                and list / restore Microsoft Defender's own quarantine.
  Recover       1. Recycle Bin of ALL users on ALL drives (admin), search + restore
                   (never overwrites - makes a "(restored)" copy).
                2. Previous Versions: finds a file in the shadow copies (restore
                   points), copies an older version out, or opens a snapshot as a folder.
                3. File History, OneDrive recycle bin, Backup and Restore.
                4. Windows File Recovery (Microsoft's winfr): install with winget or the
                   Store, pick drive / destination / mode, runs in a console window.
                   Warns when the drive is an SSD (TRIM usually wipes deleted files).
                Stop using the drive as soon as you notice a file is missing.
  Secure delete Overwrites files with random data, renames, deletes (1 or 3 passes).
                Honest: reliable on hard drives, NOT guaranteed on SSDs/USB sticks -
                use BitLocker or Reset this PC with "Clean data" for those.
                Refuses Windows, Program Files, whole drives and profile roots.
                Also: free-space wipe (cipher /w), TRIM, and Reset this PC.

REPORTS
  Saved to Reports\<COMPUTERNAME>_<date>\ next to the exe (Desktop if the USB is
  read-only): WinDiag-Report.html, WinDiag-Report.txt, repair logs. The security
  scan is included in the report once it has been run.
  Fixed in 2.4: the Reports folder can now be deleted without admin rights
  (WinDiag gives normal users modify access when it runs elevated). For folders
  made by older versions: right-click > Properties > Security, or run
  icacls "Reports" /grant *S-1-5-11:(OI)(CI)M /T  in an admin prompt.

NOTES
  - Event Analyzer results are "likely" causes based on patterns - confirm with
    the suggested tests (memory test, SSD tool, etc.) before replacing hardware.
  - Server Roles / Virtualization are also used by ServerDiag fleet mode to scan
    Windows servers over SSH (see ..\ServerDiag\README.txt).
  - "PowerShell version" folder = the original lightweight tool (no exe); use it on
    PCs where the exe is blocked.
  - "source" folder = Python source. Run build.bat on a Windows PC with Python
    installed to rebuild WinDiag.exe yourself.
  - If WinDiag crashes, WinDiag-crash.log is written next to the exe.
