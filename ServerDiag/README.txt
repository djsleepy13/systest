ServerDiag 1.0 - Server health check + log analyzer (Linux, and Windows via SSH)
===============================================================================

WHAT IT IS
  One file (serverdiag.pyz) that runs on any Linux server with Python 3.6+
  (Ubuntu 18.04 and newer, Debian 10+, RHEL/Rocky/Alma 8+). Nothing to install.
  Full-screen terminal UI that works over SSH, in tmux and on VM consoles.

QUICK START (one server)
  scp serverdiag.pyz user@server:~
  ssh user@server
  sudo python3 serverdiag.pyz            # interactive dashboard
  sudo python3 serverdiag.pyz --report   # no UI: summary + HTML/TXT/JSON report
  sudo python3 serverdiag.pyz --days 30  # analyse 30 days of logs (default 7)

  Keys:  <- -> or 1-8 switch tabs | up/down PgUp/PgDn scroll | s save report
         r re-run | q quit | in Log Analyzer: p problems, m recognised,
         t timeline, u unrecognised, n noise, b boot history

  Without sudo it still runs, but SMART, firewall, SSH config, LVM and some
  logs are skipped.

TABS
  Summary        Health score + every finding (CRIT/WARN/INFO/OK) with the fix command.
  System         OS, kernel, uptime, load, RAM/swap, pressure stall (PSI), reboot
                 required, newer kernel installed, NTP sync.
  Storage        Disk usage + inodes, read-only mounts, disk latency/IOPS sample,
                 SMART (HDD/SSD/NVMe: health, bad sectors, wear, temp, CRC errors),
                 mdadm RAID, ZFS pools, LVM thin pools.
  Network        Interfaces + errors, gateway/internet/DNS tests, listening ports
                 (warns on databases open to the world), conntrack table.
  Services       Failed systemd units, services in restart loops, Docker containers
                 (unhealthy/restarting), top CPU/RAM processes, zombies, file handles.
  Security       OS end-of-life, pending (security) updates, unattended-upgrades,
                 firewall, SSH root/password login, fail2ban, UID-0 accounts,
                 empty passwords, sudo users, recent logins, TLS cert expiry.
  Platform       Hypervisor / cloud detection (Hyper-V, Azure, VMware, KVM/Proxmox,
                 Xen, AWS, GCP...), guest agent running?, CPU steal time, clock
                 offset, cloud-init errors. Physical servers: temperatures,
                 ECC memory errors (EDAC), IPMI/BMC event log.
  Log Analyzer   Reads journald (or /var/log/syslog) and matches ~80 patterns:
                 NVMe timeouts, SATA/SCSI errors, bad sectors, ext4/XFS/Btrfs
                 corruption + read-only remounts, RAID/ZFS degraded, ECC/MCE,
                 PCIe AER, thermal throttling, OOM kills, kernel panics/oops,
                 soft lockups + hung tasks, NIC timeouts, conntrack full, bond
                 failover, failing/looping services, segfaults, SSH brute force,
                 clock problems, Hyper-V/VMware/virtio driver errors, failed updates.
                 Also checks BOOT HISTORY for unclean shutdowns (power loss / host
                 reset) and correlates crashes with recent apt upgrades.
                 Ranks the likely causes HIGH/MEDIUM/LOW with evidence + fix steps.

FLEET MODE (many servers at once)
  Run from any Linux/macOS machine (or WSL) that can SSH to the servers with keys:

    python3 serverdiag.pyz fleet hosts.txt
    python3 serverdiag.pyz fleet hosts.txt --days 14 --parallel 16
    python3 serverdiag.pyz fleet hosts.txt --no-tui          # table + reports only
    python3 serverdiag.pyz fleet hosts.txt -o IdentityFile=~/.ssh/ops_key

  - See hosts.example.txt for the format.
  - Linux hosts: the tool copies itself to /tmp on each host, runs with
    `sudo -n` if passwordless sudo is allowed (else limited mode) and deletes
    itself afterwards. Only python3 is needed on the host.
  - Windows hosts (prefix win:): uses the built-in OpenSSH Server and runs the
    WinDiag PowerShell checks, including Server Roles (AD, DNS, IIS, Hyper-V,
    cluster, SQL, certificates, failed logons) and the Windows Event Analyzer.
    Enable on the server:  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
                           Start-Service sshd; Set-Service sshd -StartupType Automatic
    Log in as an administrator account for full results.
  - Result: a fleet dashboard (worst hosts first, Enter to drill into a host)
    and serverdiag-reports/fleet_<date>/report.html with every host.

AUTOMATION
  Exit code of --report is 1 when there are CRITICAL findings, so it can run
  from cron / CI. --json prints the full result for your own tooling.
  Example weekly cron:  0 7 * * 1  root  python3 /opt/serverdiag.pyz --report --out /var/log/serverdiag

SAFETY
  ServerDiag only READS. It never changes, restarts or deletes anything. Every
  finding shows the command you can run yourself to fix it.

SOURCE
  source/ contains the Python package. Rebuild the .pyz with:
    mkdir -p pkg/serverdiag && cp source/*.py pkg/serverdiag/
    printf 'import sys\nfrom serverdiag.cli import main\nsys.exit(main())\n' > pkg/__main__.py
    python3 -m zipapp pkg -o serverdiag.pyz -p "/usr/bin/env python3"
