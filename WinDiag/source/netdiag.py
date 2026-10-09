"""
Network tools (3.2): live ping monitor, traceroute, speed test (Cloudflare), DNS benchmark + hijack check, port check, MTU check,
Wi-Fi analyzer, adapter health, listening ports, firewall rule review, public IP (opt-in), LAN device map (own subnet only),
shares / mapped drives / time sync, and fixes that are measured before and after.
Everything here is read-only except FIXES, which only run when the user clicks them.
"""
import ipaddress
import os
import random
import re
import socket
import ssl
import statistics
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import core

IS_WIN = os.name == "nt"

# =====================================================================================
#  Ping (IcmpSendEcho on Windows - no admin, no console windows; ping.exe elsewhere)
# =====================================================================================
_icmp = None
_icmp_lock = threading.Lock()


def _icmp_api():
    global _icmp
    if _icmp is not None or not IS_WIN:
        return _icmp
    import ctypes
    from ctypes import wintypes

    class IPOPT(ctypes.Structure):
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

    class REPLY(ctypes.Structure):
        _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong), ("RoundTripTime", ctypes.c_ulong), ("DataSize", ctypes.c_ushort),
                    ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p), ("Options", IPOPT)]
    ip = ctypes.WinDLL("iphlpapi", use_last_error=True)
    ip.IcmpCreateFile.restype = wintypes.HANDLE
    ip.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    ip.IcmpSendEcho.restype = wintypes.DWORD
    ip.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    _icmp = (ctypes, ip, IPOPT, REPLY)
    return _icmp


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


# ---- tolerant readers for PowerShell JSON (PS 5.1 wraps strings/arrays with ETS properties: {"value": ..., "PSPath": ...})
def _s(x):
    """Plain text from a PS value (unwraps {'value': ...} objects; None -> '')."""
    if isinstance(x, dict):
        x = x.get("value", "")
    if x is None:
        return ""
    if isinstance(x, (list, tuple)):
        return ", ".join(_s(i) for i in x if i is not None)
    return x if isinstance(x, str) else str(x)


def _i(x, default=0):
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, (int, float)):
        return int(x) if x == x else default
    try:
        return int(float(_s(x).replace(",", ".")))
    except (TypeError, ValueError, OverflowError):
        return default


def _l(x):
    """Always a list (unwraps PS 5.1 {'value': [...], 'Count': n})."""
    if isinstance(x, dict) and isinstance(x.get("value"), list) and ("Count" in x or len(x) <= 2):
        x = x["value"]
    return x if isinstance(x, list) else ([] if x in (None, "") else [x])


def _dl(x):
    """List of dicts only (drops None / stray strings)."""
    return [i for i in _l(x) if isinstance(i, dict)]


def _d(x):
    if isinstance(x, list):
        x = next((i for i in x if isinstance(i, dict)), None)
    return x if isinstance(x, dict) else {}


def _icmp_send(ipaddr, timeout_ms=1000, size=32, df=False, ttl=128):
    """One IcmpSendEcho. -> (status, reply_ip, rtt_ms). status 0 = echo reply, 11009 = packet too big, 11010 = timeout,
    11013 = TTL expired in transit (reply_ip = the router that dropped it). None when the API isn't available."""
    api = _icmp_api()
    if not api:
        return None
    ctypes, ip, IPOPT, REPLY = api
    h = ip.IcmpCreateFile()
    try:
        data = ctypes.create_string_buffer(b"WinDiag" * (size // 7 + 1), size)
        opt = IPOPT(ttl, 0, 2 if df else 0, 0, None)
        rsize = ctypes.sizeof(REPLY) + size + 64
        buf = ctypes.create_string_buffer(rsize)
        addr = struct.unpack("<I", socket.inet_aton(ipaddr))[0]
        t0 = time.perf_counter()
        n = ip.IcmpSendEcho(h, addr, data, size, ctypes.byref(opt), buf, rsize, timeout_ms)
        el = (time.perf_counter() - t0) * 1000
        if n == 0:
            return ctypes.get_last_error() or 11010, "", None
        rep = REPLY.from_buffer_copy(buf)
        rip = socket.inet_ntoa(struct.pack("<I", rep.Address & 0xFFFFFFFF)) if rep.Address else ""
        rtt = float(rep.RoundTripTime) if rep.RoundTripTime else round(min(el, 0.9), 2)
        return rep.Status, rip, rtt
    finally:
        ip.IcmpCloseHandle(h)


def ping(host, timeout_ms=1000, size=32, df=False, ttl=128):
    """Round-trip ms (float), None on timeout/unreachable, or 'frag' when DF is set and the packet is too big."""
    ipaddr = host if re.match(r"^\d+\.\d+\.\d+\.\d+$", host or "") else resolve(host)
    if not ipaddr:
        return None
    try:
        r = _icmp_send(ipaddr, timeout_ms, size, df, ttl)
    except Exception:
        r = None
    if r is not None:
        st, _rip, rtt = r
        if st == 11009:
            return "frag"
        return rtt if st == 0 else None
    # fallback: ping binary
    if IS_WIN:
        args = [core.sys32("ping"), "-n", "1", "-w", str(timeout_ms), "-l", str(size)] + (["-f"] if df else []) + [ipaddr]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), "-s", str(size)] + (["-M", "do"] if df else []) + [ipaddr]
    try:
        rc, out, err = core.tracked_run(args, timeout_ms / 1000.0 + 3, "ping")
        t = (out + err).decode("utf-8", "replace")
        if re.search(r"fragmented|too long|message too long", t, re.I):
            return "frag"
        m = re.search(r"[=<]\s*([\d.]+)\s*ms", t)
        return float(m.group(1)) if m and rc == 0 else None
    except Exception:
        return None


def stats(samples):
    """samples: list of ms or None. -> dict(avg, jitter, loss, lost, n, last, max)."""
    got = [s for s in samples if isinstance(s, (int, float))]
    n = len(samples)
    out = {"n": n, "lost": n - len(got), "loss": round(100.0 * (n - len(got)) / n, 1) if n else 0.0, "avg": None, "jitter": None, "max": None,
           "last": samples[-1] if samples else None}
    if got:
        out["avg"] = round(statistics.mean(got), 1)
        out["max"] = round(max(got), 1)
        if len(got) > 1:
            out["jitter"] = round(statistics.mean(abs(a - b) for a, b in zip(got, got[1:])), 1)
    return out


class LiveMonitor(object):
    """Pings the router and the internet once a second. read() -> (router_stats, inet_stats, router_samples, inet_samples)."""
    KEEP = 120

    def __init__(self, gateway, internet="1.1.1.1"):
        self.gw, self.inet = gateway, internet
        self.r, self.i = [], []
        self.stop = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        try:
            with ThreadPoolExecutor(2) as ex:
                while not self.stop.is_set():
                    t0 = time.time()
                    fr = ex.submit(ping, self.gw, 900) if self.gw else None
                    fi = ex.submit(ping, self.inet, 900)
                    r = fr.result() if fr else None
                    i = fi.result()
                    self.r = (self.r + [r if r != "frag" else None])[-self.KEEP:]
                    self.i = (self.i + [i if i != "frag" else None])[-self.KEEP:]
                    self.stop.wait(max(0.05, 1.0 - (time.time() - t0)))
        except Exception as e:
            core.log_error("netdiag.LiveMonitor", e)
            self.stop.set()

    def read(self):
        return stats(self.r), stats(self.i), list(self.r), list(self.i)


MIN_SAMPLES = 20     # no loss verdict before this many pings
MIN_LOST = 2         # ... and never for a single lost ping


def _lossy(st):
    return st["n"] >= MIN_SAMPLES and st.get("lost", 0) >= MIN_LOST and st["loss"] >= 5


def monitor_verdict(rs, ist, has_gw=True):
    """Explain what the two lines mean."""
    if ist["n"] < 5:
        return "INFO", "Collecting samples..."
    router_silent = has_gw and rs["n"] >= 5 and rs["avg"] is None       # every router ping lost
    if router_silent and ist["avg"] is not None and not _lossy(ist):
        return "INFO", ("Your router doesn't answer ping (normal for some routers - they ignore ping for security), but the internet answers fine, "
                        "so the connection itself is working. Watch the internet line.")
    if has_gw and not router_silent and _lossy(rs):
        return "CRITICAL" if rs["loss"] >= 20 else "WARNING", ("Packets are lost between this PC and the router (%.0f%%). The problem is local: Wi-Fi signal, "
                                                               "cable, network adapter or the router itself - not your internet provider." % rs["loss"])
    if _lossy(ist) and router_silent and ist["avg"] is None:
        return "CRITICAL", "Neither the router nor the internet answer - this PC has no working connection right now (check Wi-Fi / cable, then the router)."
    if _lossy(ist):
        where = "The router answers fine but the internet" if has_gw and not router_silent else "The internet"
        return "CRITICAL" if ist["loss"] >= 20 else "WARNING", ("%s loses %.0f%% of packets. The problem is most likely between the router "
                                                                "and the internet: modem/line or your internet provider. Restart the modem; if it persists, "
                                                                "contact the provider with these numbers." % (where, ist["loss"]))
    if has_gw and rs["avg"] and rs["avg"] > 20:
        return "WARNING", "The router takes %.0f ms to answer (normal: under 5 ms on cable, under 10 ms on Wi-Fi) - weak Wi-Fi or a busy network." % rs["avg"]
    if ist["jitter"] and ist["jitter"] > 30:
        return "WARNING", "Internet latency jumps around (jitter %.0f ms). Calls and games will stutter - often Wi-Fi interference or someone downloading." % ist["jitter"]
    if ist["avg"] and ist["avg"] > 100:
        return "WARNING", "Internet latency is high (%.0f ms average)." % ist["avg"]
    lost = rs.get("lost", 0) + ist.get("lost", 0)
    if ist["n"] < MIN_SAMPLES and lost:
        return "INFO", "Collecting samples... (%d lost so far - one or two lost pings are normal; a verdict needs at least %d samples)" % (lost, MIN_SAMPLES)
    if ist["avg"] is None:
        return "INFO", "Collecting samples..."
    return "OK", "Stable: router %s, internet %s ms average, %.0f%% loss." % (("%s ms" % rs["avg"]) if rs["avg"] is not None else "--", ist["avg"], ist["loss"])


# =====================================================================================
#  Traceroute / MTU / port check
# =====================================================================================
def traceroute(host="1.1.1.1", max_hops=20):
    ipaddr = host if re.match(r"^\d+\.\d+\.\d+\.\d+$", host or "") else resolve(host)
    if IS_WIN and ipaddr and _icmp_api():
        try:
            return _trace_icmp(ipaddr, max_hops)
        except Exception as e:           # fall back to tracert.exe
            core.log_error("netdiag.traceroute (ICMP)", e)
    elif IS_WIN and not ipaddr:
        return {"error": "Can't resolve %s (DNS)." % host}
    args = [core.sys32("tracert"), "-d", "-w", "800", "-h", str(max_hops), host] if IS_WIN else ["traceroute", "-n", "-w", "1", "-m", str(max_hops), host]
    try:
        rc, out, err = core.tracked_run(args, 180, "traceroute")
    except core.Aborted:
        return {"error": "Stopped by user"}
    except Exception as e:
        return {"error": str(e)}
    return {"hops": parse_tracert(_decode_oem(out))}


def _trace_icmp(ipaddr, max_hops=20, probes=3, timeout_ms=800):
    """Traceroute with IcmpSendEcho and a growing TTL - no tracert.exe, so no localized text to parse."""
    hops = []
    for ttl in range(1, max_hops + 1):
        if core.ABORT.is_set():
            return {"error": "Stopped by user", "hops": hops}
        times, hop_ip, reached = [], "", False
        for _ in range(probes):
            st, rip, rtt = _icmp_send(ipaddr, timeout_ms, 32, False, ttl)
            if st in (0, 11013) and rip:           # 0 = destination answered, 11013 = TTL expired in transit
                times.append(rtt)
                hop_ip = hop_ip or rip
                reached = reached or (st == 0 and rip == ipaddr)
            else:
                times.append(None)
        ok = [t for t in times if t is not None]
        hops.append({"hop": ttl, "ip": hop_ip, "times": times, "avg": round(sum(ok) / len(ok), 1) if ok else None, "timeout": not ok})
        if reached:
            break
    return {"hops": hops}


def parse_tracert(text):
    hops = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        times = [None if mm.group(2) else float(mm.group(1).lstrip("<").replace(",", ".")) for mm in re.finditer(r"(<?\d+(?:[.,]\d+)?)\s*ms|(\*)", rest)]
        ipm = re.findall(r"(\d+\.\d+\.\d+\.\d+)", rest)
        ok = [t for t in times if t is not None]
        hops.append({"hop": int(m.group(1)), "ip": ipm[-1] if ipm else "", "times": times, "avg": round(sum(ok) / len(ok), 1) if ok else None,
                     "timeout": not ok})
    return hops


def trace_advice(hops):
    if not hops:
        return "No hops recorded."
    last = hops[-1]
    if last["timeout"]:
        lastok = max([h["hop"] for h in hops if not h["timeout"]] or [0])
        return "The route stops after hop %d. If that hop is your router, the problem is the modem/provider; later timeouts can also just be routers that ignore traceroute." % lastok
    jump = None
    prev = 0
    for h in hops:
        if h["avg"] is not None:
            if h["avg"] - prev > 60 and h["hop"] > 1:
                jump = h
            prev = h["avg"]
    if jump:
        return "Latency jumps by more than 60 ms at hop %d (%s). If every hop after it stays high, the delay starts there." % (jump["hop"], jump["ip"])
    return "The route reaches the destination in %d hops without big jumps." % len(hops)


def _probe(host, size, df=True, tries=3):
    """'ok' / 'frag' / 'lost' - a single lost packet is retried; only an explicit 'too big' answer means too big."""
    for _ in range(tries):
        r = ping(host, 1500, size, df=df)
        if r == "frag":
            return "frag"
        if r is not None:
            return "ok"
    return "lost"


def mtu_check(host="1.1.1.1"):
    """Largest packet that passes without fragmentation. Returns dict(mtu, note) or error."""
    if _probe(host, 32, df=False) != "ok":
        return {"error": "%s doesn't answer ping - can't measure MTU (ICMP may be blocked)." % host}
    lo, hi = 548, 1472
    silent = []
    first = _probe(host, hi)
    if first == "ok":
        best = hi
    else:
        if first == "lost":
            silent.append(hi)
        best = None
        hi -= 1
        while lo <= hi:
            mid = (lo + hi) // 2
            r = _probe(host, mid)
            if r == "ok":
                best, lo = mid, mid + 1
            else:
                # 'lost' 3 times in a row: no 'too big' reply came back (a "black hole" router or heavy loss) - treated as not passing
                if r == "lost":
                    silent.append(mid)
                hi = mid - 1
    if best is None:
        return {"error": "Even small packets with 'don't fragment' fail - can't measure."}
    mtu = best + 28
    if mtu >= 1500:
        note = "1500 - normal for Ethernet / Wi-Fi."
    elif mtu == 1492:
        note = "1492 - typical for DSL/fibre with PPPoE. Fine."
    elif mtu >= 1400:
        note = "%d - typical when a VPN or tunnel is in the path. Fine unless some sites hang while loading." % mtu
    else:
        note = "%d - unusually low. If some websites or downloads hang, a router/VPN MTU setting is the likely cause." % mtu
    if silent:
        note += (" Note: some bigger packets got no answer at all (not even 'too big'), even after 3 tries - either packets are being lost "
                 "or a router silently drops big packets (an 'MTU black hole'). Run the check again to confirm.")
    return {"mtu": mtu, "payload": best, "note": note, "uncertain": bool(silent)}


PORT_PRESETS = [("Web (HTTPS)", "www.microsoft.com", 443), ("Web (HTTP)", "www.msftconnecttest.com", 80), ("DNS over TCP", "1.1.1.1", 53),
                ("Email send (SMTP 587)", "smtp.office365.com", 587), ("Email send (SMTP 25)", "smtp.office365.com", 25), ("IMAP (993)", "outlook.office365.com", 993),
                ("Remote Desktop", "", 3389), ("SSH", "", 22)]


def port_check(host, port, timeout=4.0):
    t0 = time.perf_counter()
    try:
        ipaddr = resolve(host)
        if not ipaddr:
            return {"ok": False, "detail": "Can't resolve %s (DNS)" % host}
        s = socket.create_connection((ipaddr, int(port)), timeout=timeout)
        s.close()
        return {"ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1), "ip": ipaddr, "detail": "Open - connected in %.0f ms" % ((time.perf_counter() - t0) * 1000)}
    except socket.timeout:
        return {"ok": False, "detail": "No answer (filtered by a firewall - here, on the router, at the provider, or at the server)"}
    except ConnectionRefusedError:
        return {"ok": False, "detail": "Refused - the server is reachable but nothing listens on that port"}
    except OSError as e:
        return {"ok": False, "detail": str(e)}


# =====================================================================================
#  DNS (raw UDP queries, so each server is tested directly)
# =====================================================================================
PUBLIC_DNS = [("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Quad9", "9.9.9.9"), ("OpenDNS", "208.67.222.222")]
BENCH_DOMAINS = ["www.google.com", "www.microsoft.com", "www.youtube.com", "www.amazon.com", "www.wikipedia.org", "www.bbc.co.uk",
                 "www.reddit.com", "outlook.office365.com", "www.netflix.com", "github.com"]


def _dns_packet(name, qtype=1):
    tid = random.randint(0, 65535)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00"
    return tid, struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)


def _skip_name(b, i):
    for _ in range(128):
        ln = b[i]
        if ln == 0:
            return i + 1
        if ln & 0xC0 == 0xC0:
            return i + 2
        i += ln + 1
    raise ValueError("bad name")


def dns_query(server, name, timeout=2.0):
    """-> (ms or None, rcode (int) or 'timeout'/'error: ...', [ipv4 answers]).
    A truncated reply (TC bit) still counts as an answer: whatever records fit are returned."""
    tid, pkt = _dns_packet(name)
    s = socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t0 = time.perf_counter()
        s.sendto(pkt, (server, 53))
        while True:
            data, _ = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                break
        ms = (time.perf_counter() - t0) * 1000
    except socket.timeout:
        s.close()
        return None, "timeout", []
    except Exception as e:
        s.close()
        return None, "error: %s" % e, []
    s.close()
    flags, qd, an = struct.unpack(">HHH", data[2:8])
    rcode = flags & 0xF
    ips = []
    try:
        i = 12
        for _ in range(qd):
            i = _skip_name(data, i) + 4
        for _ in range(an):
            i = _skip_name(data, i)
            if i + 10 > len(data):
                break
            typ, cls, ttl, rdl = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            if i + rdl > len(data):
                break                                  # record cut off (truncated reply)
            if typ == 1 and rdl == 4:
                ips.append(socket.inet_ntoa(data[i:i + 4]))
            i += rdl
    except (IndexError, ValueError, struct.error):
        pass                                           # malformed / truncated: keep what was parsed
    return round(ms, 1), rcode, ips


def dns_ok(rc):
    return rc == 0


def dns_benchmark(current, progress=None, cancel=None):
    """current: list of this PC's DNS server IPs. -> list of dict(name, ip, median, fails, current) sorted fastest first.
    A reply with an error code (REFUSED, SERVFAIL...) is a failure, not a fast answer."""
    current = [c for c in _l(current) if isinstance(c, str)]
    servers = [("Your DNS (%s)" % ip, ip, True) for ip in current[:2]] + [(n, ip, False) for n, ip in PUBLIC_DNS if ip not in current]
    out = []
    total = len(servers) * len(BENCH_DOMAINS)
    done = 0
    for name, ip, cur in servers:
        times, fails, codes = [], 0, set()
        for d in BENCH_DOMAINS:
            if cancel is not None and cancel.is_set():
                return out
            for _ in range(2):                          # second = cached speed
                ms, rc, _ = dns_query(ip, d)
                if ms is None or not dns_ok(rc):
                    fails += 1
                    codes.add(rc)
                else:
                    times.append(ms)
            done += 1
            if progress:
                progress(done, total)
        out.append({"name": name, "ip": ip, "current": cur, "median": round(statistics.median(times), 1) if times else None,
                    "uncached": None, "fails": fails, "queries": 2 * len(BENCH_DOMAINS),
                    "errors": sorted(RCODE_NAMES.get(c, str(c)) for c in codes)})
    out.sort(key=lambda x: (x["median"] is None, x["fails"] > x["queries"] // 2, x["median"] or 9e9))
    return out


RCODE_NAMES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", "timeout": "timeout"}
CLOUDFLARE = {"1.1.1.1", "1.0.0.1"}


def ip_kind(ip):
    """'null' (0.0.0.0 / ::, what DNS filters answer), 'private' (LAN / router / captive portal), 'public'."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "public"
    if a.is_unspecified:
        return "null"
    if a.is_private or a.is_loopback or a.is_link_local or (a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10")):
        return "private"
    return "public"


def _known_name_verdict(who, ips, rc):
    """Judge the answer for one.one.one.one (must be 1.1.1.1 / 1.0.0.1)."""
    ips = list(ips or [])
    if ips and set(ips) & CLOUDFLARE:
        return ("OK", "%s returns correct answers" % who, "Checked against a known address.")
    if rc == 3 or (not ips and rc == 0) or (ips and all(ip_kind(x) == "null" for x in ips)):
        return ("INFO", "%s filters one.one.one.one" % who,
                "It answered %s instead of 1.1.1.1. Your DNS filters this name - normal for Pi-hole / AdGuard, family or company filters that block outside "
                "DNS services, and for hotel / guest Wi-Fi (captive portal) before you sign in. Not a sign of an attack." %
                ("'no such name'" if rc == 3 or not ips else ", ".join(ips[:2])))
    kinds = {ip_kind(x) for x in ips}
    if ips and kinds <= {"private", "null"}:
        return ("WARNING", "%s sends a known name to a local address" % who,
                "one.one.one.one must be 1.1.1.1 / 1.0.0.1, got %s (a private/local address). Usually a router, company filter or a hotel / guest Wi-Fi "
                "sign-in page (captive portal). If you're at home and didn't set up filtering, check the router's DNS settings." % ", ".join(ips[:2]))
    if ips:
        return ("CRITICAL", "%s gives a wrong address" % who,
                "one.one.one.one must be 1.1.1.1 / 1.0.0.1, got %s - a public address that isn't Cloudflare's. Answers are being changed "
                "(DNS hijacking by the router, malware or the network). Switch DNS (Fixes tab) and check the router." % ", ".join(ips[:2]))
    return ("INFO", "%s couldn't be checked" % who, "It answered with error %s." % RCODE_NAMES.get(rc, rc))


def hijack_check(current):
    """Detect DNS tampering: NXDOMAIN redirection, wrong answers for a known name, hosts-file / resolver overrides."""
    items = []
    current = [c for c in _l(current) if isinstance(c, str)]
    fake = "windiag-%012x.com" % random.getrandbits(48)
    for ip in current[:2]:
        ms, rc, ips = dns_query(ip, fake)
        if rc == "timeout":
            items.append(("WARNING", "DNS %s doesn't answer" % ip, "Timed out - this server may be down or blocked."))
            continue
        if ips:
            kinds = {ip_kind(x) for x in ips}
            if kinds == {"null"}:
                items.append(("OK", "DNS %s blocks names that don't exist" % ip, "Asked for %s (doesn't exist) and got 0.0.0.0 - a filter's 'blocked' answer." % fake))
            elif kinds <= {"private", "null"}:
                items.append(("WARNING", "DNS %s answers for names that don't exist" % ip, "Asked for %s (doesn't exist) and got %s, a local address. "
                              "Usually a router or hotel / guest Wi-Fi sign-in page (captive portal)." % (fake, ", ".join(ips[:2]))))
            else:
                items.append(("WARNING", "DNS %s answers for names that don't exist" % ip, "Asked for %s (doesn't exist) and got %s. This is NXDOMAIN redirection: "
                              "your provider/router sends typos to its own (ad) pages - or malware changed your DNS. Consider switching DNS (Fixes tab)." % (fake, ", ".join(ips[:2]))))
        elif isinstance(rc, int) and rc not in (0, 3):
            items.append(("INFO", "DNS %s refused the test question" % ip, "It answered with error %s." % RCODE_NAMES.get(rc, rc)))
        else:
            items.append(("OK", "DNS %s says 'no such name' correctly" % ip, "No redirection of mistyped addresses."))
        ms, rc, ips = dns_query(ip, "one.one.one.one")
        if rc != "timeout" and not str(rc).startswith("error"):
            items.append(_known_name_verdict("DNS %s" % ip, ips, rc))
    try:
        sysips = sorted({a[4][0] for a in socket.getaddrinfo("one.one.one.one", 443, socket.AF_INET)})
    except socket.gaierror:
        sysips = None
    except Exception:
        sysips = []
    if sysips is None:
        items.append(("INFO", "Windows can't look up one.one.one.one", "The name doesn't resolve on this PC. Normal when your DNS filters it (Pi-hole, family or "
                      "company filter), before you sign in to a hotel / guest Wi-Fi (captive portal), or when there's no connection."))
    elif sysips and not set(sysips) & CLOUDFLARE:
        st, t, dt = _known_name_verdict("Windows", sysips, 0)
        items.append((st, "Windows resolves a known name to %s" % ("a filter address" if st == "INFO" else "the wrong address"),
                      dt + " Also check the hosts file and proxy/VPN software."))
    ms, rc, ips = dns_query("1.1.1.1", "www.microsoft.com", 3)
    if rc == "timeout":
        items.append(("WARNING", "Outside DNS servers are blocked", "Queries to 1.1.1.1 time out - the network only allows its own DNS (common in offices/hotels)."))
    return items


# =====================================================================================
#  Speed test (Cloudflare speed.cloudflare.com - same endpoints its web test uses)
# =====================================================================================
SPEED_HOST = "speed.cloudflare.com"


def _conn():
    import http.client
    return http.client.HTTPSConnection(SPEED_HOST, timeout=15, context=ssl.create_default_context())


def speed_test(progress=None, cancel=None, max_seconds=8):
    """progress(phase, value_mbps_or_ms, fraction). Returns dict(ping, jitter, down, up) or error."""
    cancel = cancel or threading.Event()
    res = {"server": SPEED_HOST}
    try:
        c = _conn()
        lat = []
        for i in range(10):
            t0 = time.perf_counter()
            c.request("GET", "/__down?bytes=0")
            r = c.getresponse()
            r.read()
            lat.append((time.perf_counter() - t0) * 1000)
            if progress:
                progress("ping", min(lat), (i + 1) / 10.0)
        lat = lat[1:]
        res["ping"] = round(statistics.median(lat), 1)
        res["jitter"] = round(statistics.mean(abs(a - b) for a, b in zip(lat, lat[1:])), 1)
        # download
        results, t_start = [], time.perf_counter()
        for size in (100000, 1000000, 10000000, 25000000, 50000000, 100000000):
            if cancel.is_set():
                return {"error": "Stopped"}
            t0 = time.perf_counter()
            c.request("GET", "/__down?bytes=%d" % size)
            r = c.getresponse()
            got = 0
            while True:
                b = r.read(262144)
                if not b:
                    break
                got += len(b)
                if cancel.is_set():
                    return {"error": "Stopped"}
                if progress:
                    el = time.perf_counter() - t0
                    if el > 0.2:
                        progress("down", got * 8 / el / 1e6, min(1.0, (time.perf_counter() - t_start) / max_seconds))
            el = time.perf_counter() - t0
            if size >= 1000000:
                results.append(got * 8 / el / 1e6)
            if time.perf_counter() - t_start > max_seconds or el > 3.5:
                break
        res["down"] = round(max(results[-2:]) if results else 0, 1)
        c.close()
    except Exception as e:
        if "down" not in res:
            return dict(res, error="Speed test failed: %s" % e)
    try:
        c = _conn()
        # upload (new connection, so a download hiccup doesn't spoil it)
        results, t_start = [], time.perf_counter()
        for size in (100000, 1000000, 5000000, 10000000, 25000000):
            if cancel.is_set():
                return {"error": "Stopped"}
            body = os.urandom(min(size, 1 << 20)) * (size // (1 << 20) or 1)
            body = body[:size] if len(body) >= size else body + bytes(size - len(body))
            t0 = time.perf_counter()
            c.request("POST", "/__up", body=body, headers={"Content-Type": "application/octet-stream"})
            r = c.getresponse()
            r.read()
            el = time.perf_counter() - t0
            if size >= 1000000:
                results.append(size * 8 / el / 1e6)
                if progress:
                    progress("up", results[-1], min(1.0, (time.perf_counter() - t_start) / max_seconds))
            if time.perf_counter() - t_start > max_seconds or el > 3.5:
                break
        res["up"] = round(max(results[-2:]) if results else 0, 1)
        c.close()
    except Exception as e:
        res["up_error"] = "Upload test failed: %s" % e
    return res


def speed_advice(r, wifi=None):
    tips = []
    if r.get("down") is not None and r["down"] < 10:
        tips.append("Download under 10 Mbps is slow for streaming/video calls. Compare with a test on a cable next to the router.")
    if wifi and wifi.get("signal") and wifi["signal"] < 60:
        tips.append("Wi-Fi signal is %d%% - move closer or use 5 GHz; weak signal is the most common cause of slow speeds." % wifi["signal"])
    if wifi and wifi.get("band", "").startswith("2.4"):
        tips.append("You're on 2.4 GHz - it's slower and more crowded. Use the router's 5 GHz network if you can.")
    if r.get("ping") and r["ping"] > 60:
        tips.append("Latency %.0f ms is high for a nearby server." % r["ping"])
    if not tips:
        tips.append("Result looks normal. Compare it with the speed your plan promises; test on a cable to rule out Wi-Fi.")
    return tips


def public_ip():
    """Opt-in (Settings). Uses Cloudflare's trace endpoint."""
    import http.client
    try:
        c = http.client.HTTPSConnection("1.1.1.1", timeout=8, context=ssl.create_default_context())
        c.request("GET", "/cdn-cgi/trace")
        t = c.getresponse().read().decode("utf-8", "replace")
        kv = dict(line.split("=", 1) for line in t.splitlines() if "=" in line)
        return {"ip": kv.get("ip"), "loc": kv.get("loc"), "warp": kv.get("warp"), "colo": kv.get("colo")}
    except Exception as e:
        return {"error": str(e)}


# =====================================================================================
#  Windows data (PowerShell)
# =====================================================================================
NET_INFO_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$R = [ordered]@{}
$pm = @{}; foreach ($p in @(Get-NetAdapterPowerManagement)) { $pm[$p.Name] = "$($p.AllowComputerToTurnOffDevice)" }
$st = @{}; foreach ($s in @(Get-NetAdapterStatistics)) { $st[$s.Name] = $s }
$R.adapters = @(Get-NetAdapter | Where-Object { $_.HardwareInterface -or $_.Status -eq 'Up' } | ForEach-Object {
    $s = $st[$_.Name]
    [ordered]@{ name = $_.Name; desc = $_.InterfaceDescription; status = "$($_.Status)"; speed = "$($_.LinkSpeed)"; mac = "$($_.MacAddress)"
                media = "$($_.PhysicalMediaType)"; ndis = "$($_.NdisPhysicalMedium)"; virtual = [bool]$_.Virtual; hw = [bool]$_.HardwareInterface
                duplex = $_.FullDuplex; driver = "$($_.DriverVersion)"; driver_date = "$($_.DriverDate)"; driver_by = "$($_.DriverProvider)"; ifindex = $_.ifIndex
                power_off_allowed = $pm[$_.Name]
                rx = [int64]$s.ReceivedBytes; tx = [int64]$s.SentBytes; rx_err = [int64]$s.ReceivedPacketErrors; tx_err = [int64]$s.OutboundPacketErrors
                rx_drop = [int64]$s.ReceivedDiscardedPackets; tx_drop = [int64]$s.OutboundDiscardedPackets; rx_pkts = [int64]$s.ReceivedUnicastPackets }
})
$R.ip = @(Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | ForEach-Object {
    $a = @($_.IPv4Address)[0]
    [ordered]@{ alias = $_.InterfaceAlias; ifindex = $_.InterfaceIndex; ipv4 = "$($a.IPAddress)"; prefix = [int]$a.PrefixLength
                gateway = "$(@($_.IPv4DefaultGateway)[0].NextHop)"; dns = @($_.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
                dhcp = "$((Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).Dhcp)"
                ipv6 = [bool]($_.IPv6Address) }
})
$is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$R.proxy = [ordered]@{ enabled = ($is.ProxyEnable -eq 1); server = "$($is.ProxyServer)"; pac = "$($is.AutoConfigURL)"; winhttp = ((netsh winhttp show proxy) -join ' ') -replace '\s+', ' ' }
# [string] cast: in PS 5.1 Get-Content lines carry PSPath/ReadCount note properties and ConvertTo-Json turns each into an object
$R.hosts = @(Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*(#|$)' } | ForEach-Object { ([string]$_).Trim() })
$R | ConvertTo-Json -Depth 5 -Compress
"""

PORTS_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$pn = @{}; foreach ($p in @(Get-Process)) { $pn[[int]$p.Id] = @([string]$p.ProcessName, [string]$p.Path) }
$sg = @{}
function Sig([string]$path) {
    if (-not $path -or $path -notmatch '(?i)\\(Users|Temp|ProgramData)\\') { return '' }
    if (-not $sg.ContainsKey($path)) { $s = Get-AuthenticodeSignature -LiteralPath $path; $sg[$path] = $(if ("$($s.Status)" -eq 'Valid' -and $s.SignerCertificate) { 'Valid|' + $s.SignerCertificate.GetNameInfo('SimpleName', $false) } else { "$($s.Status)|" }) }
    return $sg[$path]
}
$svc = @{}; foreach ($s in @(Get-CimInstance Win32_Service -Filter "State='Running'")) { $k = [int]$s.ProcessId; if ($svc.ContainsKey($k)) { $svc[$k] += ", " + $s.Name } else { $svc[$k] = $s.Name } }
function P($id) { $x = $pn[[int]$id]; [ordered]@{ pid = [int]$id; proc = $(if ($x) { $x[0] } else { '?' }); path = $(if ($x) { $x[1] } else { '' }); svc = "$($svc[[int]$id])"; sig = $(if ($x) { Sig $x[1] } else { '' }) } }
$listen = @(Get-NetTCPConnection -State Listen | ForEach-Object { $o = P $_.OwningProcess; $o.proto = 'TCP'; $o.addr = "$($_.LocalAddress)"; $o.port = [int]$_.LocalPort; $o })
$udp = @(Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1)' -and $_.LocalPort -lt 49152 } | ForEach-Object { $o = P $_.OwningProcess; $o.proto = 'UDP'; $o.addr = "$($_.LocalAddress)"; $o.port = [int]$_.LocalPort; $o })
$est = @(Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' } | Group-Object OwningProcess | ForEach-Object {
    $o = P $_.Name; $o.count = $_.Count; $o.remotes = @($_.Group | Select-Object -First 5 | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" }); $o } | Sort-Object { -$_.count })
@{ listen = $listen + $udp; established = $est } | ConvertTo-Json -Depth 5 -Compress
"""

FIREWALL_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$R = [ordered]@{}
# ActiveStore = what is really in force (local rules + Group Policy + rules added by apps/services)
$R.profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [ordered]@{ name = "$($_.Name)"; enabled = "$($_.Enabled)"; inbound = "$($_.DefaultInboundAction)"; outbound = "$($_.DefaultOutboundAction)" } })
$R.active_profile = @(Get-NetConnectionProfile | ForEach-Object { "$($_.Name): $($_.NetworkCategory)" })
$app = @{}; foreach ($f in @(Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore)) { $app["$($f.InstanceID)"] = "$($f.Program)" }
$port = @{}; foreach ($f in @(Get-NetFirewallPortFilter -All -PolicyStore ActiveStore)) { $port["$($f.InstanceID)"] = @("$($f.Protocol)", "$($f.LocalPort)") }
$adr = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore)) { $adr["$($f.InstanceID)"] = "$($f.RemoteAddress)" }
$sg = @{}
function Sig([string]$prog) {
    $p = [Environment]::ExpandEnvironmentVariables($prog)
    if (-not $p -or $p -notmatch '(?i)\\(Users|Temp|ProgramData)\\') { return '' }
    if (-not $sg.ContainsKey($p)) {
        $s = Get-AuthenticodeSignature -LiteralPath $p
        $sg[$p] = $(if ("$($s.Status)" -eq 'Valid' -and $s.SignerCertificate) { 'Valid|' + $s.SignerCertificate.GetNameInfo('SimpleName', $false) } elseif (Test-Path -LiteralPath $p) { "$($s.Status)|" } else { 'Missing|' })
    }
    return $sg[$p]
}
$R.rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow | ForEach-Object {
    $id = "$($_.InstanceID)"; $prog = $app[$id]
    [ordered]@{ name = "$($_.DisplayName)"; group = "$($_.DisplayGroup)"; profile = "$($_.Profile)"; program = "$prog"; proto = "$(@($port[$id])[0])"; port = "$(@($port[$id])[1])"
                remote = "$($adr[$id])"; owner = "$($_.Owner)"; policy = ("$($_.PolicyStoreSourceType)" -ne 'Local'); edge = "$($_.EdgeTraversalPolicy)"; sig = Sig "$prog" }
})
$R | ConvertTo-Json -Depth 4 -Compress
"""

LAN_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$c = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
$a = @($c.IPv4Address)[0]
$R = [ordered]@{ alias = $c.InterfaceAlias; ipv4 = "$($a.IPAddress)"; prefix = [int]$a.PrefixLength; gateway = "$(@($c.IPv4DefaultGateway)[0].NextHop)"; mac = "$($c.NetAdapter.MacAddress)" }
$R.neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $c.InterfaceIndex | Where-Object { $_.State -notin 'Unreachable', 'Incomplete' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and $_.IPAddress -notmatch '^(22[4-9]|23\d|255)\.' } |
    ForEach-Object { [ordered]@{ ip = "$($_.IPAddress)"; mac = "$($_.LinkLayerAddress)"; state = "$($_.State)" } })
$R | ConvertTo-Json -Depth 4 -Compress
"""

SHARES_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { Remove-TypeData System.Array -ErrorAction Stop } catch {}
$R = [ordered]@{}
$R.shares = @(Get-SmbShare | ForEach-Object { [ordered]@{ name = $_.Name; path = "$($_.Path)"; desc = "$($_.Description)"; special = [bool]$_.Special } })
$R.mapped = @(Get-SmbMapping | ForEach-Object { [ordered]@{ local = "$($_.LocalPath)"; remote = "$($_.RemotePath)"; status = "$($_.Status)" } })
if (-not $R.mapped.Count) { $R.mapped = @(Get-CimInstance Win32_MappedLogicalDisk | ForEach-Object { [ordered]@{ local = $_.DeviceID; remote = $_.ProviderName; status = "$($_.Status)" } }) }
$R.sessions = @(Get-SmbSession | ForEach-Object { "$($_.ClientUserName) from $($_.ClientComputerName)" })
$R.smb1 = [bool]((Get-SmbServerConfiguration).EnableSMB1Protocol)
# Time sync - locale-proof: service state (enum name), registry config, and the measured clock offset from w32tm /stripchart (digits only)
$tp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
$src = ((w32tm /query /source) -join ' ').Trim()
$peer = $(if ($src -match '^[A-Za-z0-9][A-Za-z0-9.\-]*[A-Za-z0-9](,0x[0-9a-fA-F]+)?$' -and $src -notmatch '^(Local|Free)') { $src -replace ',0x[0-9a-fA-F]+$', '' }
          elseif ("$($tp.NtpServer)" -match '^\s*([^\s,]+)') { $Matches[1] } else { 'time.windows.com' })
$chart = ((w32tm /stripchart /computer:$peer /samples:1 /dataonly) -join "`n")
$off = $null; if ($chart -match '([+-]\d+[.,]\d+)s') { $off = [double]($Matches[1] -replace ',', '.') }
$R.w32 = [ordered]@{ service = "$((Get-Service W32Time).Status)"; status = ((w32tm /query /status) -join "`n"); source = $src; type = "$($tp.Type)"
                    ntp_server = "$($tp.NtpServer)"; peer = $peer; offset = $off; chart = $chart.Substring(0, [math]::Min(300, $chart.Length)) }
$R.clock = (Get-Date).ToString('o')
$R | ConvertTo-Json -Depth 4 -Compress
"""

WLAN_REPORT_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
netsh wlan show wlanreport | Out-Null
$f = "$env:ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html"
@{ path = $(if (Test-Path $f) { $f } else { '' }) } | ConvertTo-Json -Compress
"""


def net_info():
    r = core.run_ps_json(NET_INFO_PS, 60, "Network info")
    return normalize_info(r)


def normalize_info(r):
    """Make NET_INFO_PS output safe to use: lists are lists of dicts, strings are strings (PS 5.1 quirks)."""
    r = r if isinstance(r, dict) else {}
    r["adapters"] = _dl(r.get("adapters"))
    r["ip"] = _dl(r.get("ip"))
    r["hosts"] = [h for h in (_s(x).strip() for x in _l(r.get("hosts"))) if h]
    for i in r["ip"]:
        i["dns"] = [d for d in (_s(x) for x in _l(i.get("dns"))) if d]
        for k in ("alias", "ipv4", "gateway", "dhcp"):
            i[k] = _s(i.get(k))
    for a in r["adapters"]:
        for k in ("name", "desc", "status", "speed", "media", "ndis", "driver", "driver_date", "power_off_allowed"):
            a[k] = _s(a.get(k))
    r["proxy"] = _d(r.get("proxy"))
    return r


def primary(info):
    """The adapter that carries the default route."""
    ipl = _dl((info or {}).get("ip"))
    ips = [i for i in ipl if i.get("gateway")]
    ip = ips[0] if ips else (ipl or [{}])[0]
    ad = next((a for a in _dl((info or {}).get("adapters")) if a.get("name") == ip.get("alias")), {})
    return ip, ad


def is_wifi(ad):
    ad = ad or {}
    return "802.11" in _s(ad.get("media")) or "Wireless" in _s(ad.get("ndis")) or "Wi-Fi" in _s(ad.get("name")) or "Wireless" in _s(ad.get("desc"))


def adapter_findings(info):
    info = normalize_info(dict(info) if isinstance(info, dict) else {})
    F = []
    for a in info["adapters"]:
        if a.get("virtual") or not a.get("hw"):
            continue
        name = "%s (%s)" % (a.get("name"), a.get("desc"))
        pk = max(1, _i(a.get("rx_pkts")))
        errs = _i(a.get("rx_err")) + _i(a.get("tx_err"))
        if errs > 100 and errs * 1000 > pk:
            F.append(("WARNING", name, "%d packet errors - bad cable, port or driver. Try another cable/port and update the driver." % errs))
        if a.get("status") == "Up" and not is_wifi(a):
            sp = a.get("speed") or ""
            if sp.startswith("100 Mbps") or sp.startswith("10 Mbps"):
                F.append(("WARNING", name, "Linked at %s - a gigabit port running at 100 Mbps usually means a damaged cable or a Cat5 cable." % sp))
            if a.get("duplex") is False:
                F.append(("WARNING", name, "Half duplex - causes slow speeds and errors. Set both ends to Auto-negotiation."))
        if a.get("power_off_allowed") == "Enabled":
            F.append(("INFO", name, "Windows may turn this adapter off to save power - a common cause of drop-outs after sleep. Fix: 'NIC power saving off'."))
        m = re.search(r"(20\d\d|19\d\d)", a.get("driver_date") or "")
        if m and int(m.group(1)) < time.localtime().tm_year - 4:
            F.append(("INFO", name, "Driver is from %s. Check the PC/adapter maker for a newer one." % m.group(1)))
    ip, ad = primary(info)
    pr = info["proxy"]
    if pr.get("enabled") is True or pr.get("enabled") in (1, "True", "1") or _s(pr.get("pac")):
        F.append(("WARNING", "Proxy", "A proxy is set (%s). If you didn't set it, clear it (Fixes)." % (_s(pr.get("server")) or _s(pr.get("pac")))))
    if info["hosts"]:
        F.append(("INFO", "Hosts file", "%d custom line(s) in the hosts file: %s" % (len(info["hosts"]), "; ".join(info["hosts"][:3]))))
    if ip and _s(ip.get("ipv4")).startswith("169.254."):
        F.append(("CRITICAL", ip.get("alias"), "Self-assigned address 169.254.x.x - the router's DHCP didn't answer. Renew IP / restart the router."))
    if ip and not ip.get("gateway"):
        F.append(("CRITICAL", "Default gateway", "No default gateway - the PC doesn't know the way to the internet."))
    return F


USER_PATHS = re.compile(r"\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Temp|ProgramData\\[^\\]+\\[^\\]*temp)\\", re.I)
# Well-known apps that install per-user into AppData (and open listening ports / get firewall rules). Only trusted when the
# file is validly signed (or the signature couldn't be read - then INFO, never a warning on the name alone being odd).
KNOWN_USER_APPS = re.compile(r"(?i)\\(Microsoft\\Teams|Microsoft\\OneDrive|Microsoft\\WindowsApps|Zoom\\bin|Discord|Spotify|slack|WhatsApp|Telegram Desktop|"
                             r"Dropbox|Webex|GoToMeeting|GoTo|Signal|Viber|Skype|Figma|Postman|Programs\\Microsoft VS Code|Google\\Chrome|Mozilla Firefox|"
                             r"Steam|Epic Games|Battle\.net|Ubisoft|Plex|Roblox|Rainmeter|Loom|Notion|Obsidian|Wire|Element)\\")
KNOWN_SIGNERS = re.compile(r"(?i)microsoft|zoom|discord|spotify|slack|whatsapp|telegram|dropbox|cisco|goto|logmein|signal|viber|skype|figma|postman|"
                           r"google|mozilla|valve|epic games|blizzard|ubisoft|plex|roblox|loom|notion|obsidian|wire swiss|element")


def user_path_verdict(path, sig=""):
    """For a program in a user / temp folder: ('INFO', why) for a well-known signed app, else ('WARNING', why)."""
    sig = _s(sig)
    status, _, signer = sig.partition("|")
    if KNOWN_USER_APPS.search(path + "\\") and (status in ("", "Valid") and (not signer or KNOWN_SIGNERS.search(signer))):
        return "INFO", "per-user install of a well-known app%s" % ((" (signed by %s)" % signer) if signer else "")
    if status == "Valid" and signer:
        return "INFO", "runs from a user folder - signed by %s" % signer
    return "WARNING", "runs from a user/temp folder%s" % ((" (signature: %s)" % status) if status and status != "Valid" else "")


RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "File sharing (SMB)", 139: "NetBIOS", 3389: "Remote Desktop", 5900: "VNC", 5938: "TeamViewer",
               22: "SSH", 7070: "AnyDesk", 3306: "MySQL", 1433: "SQL Server", 5985: "WinRM", 5986: "WinRM (HTTPS)", 8080: "Web proxy/server", 1900: "UPnP"}
_SEV = {"WARNING": 0, "REVIEW": 1, "INFO": 2}


def ports_view(r):
    r = r if isinstance(r, dict) else {}
    L = []
    for x in _dl(r.get("listen")):
        port = _i(x.get("port"), None)
        addr = _s(x.get("addr"))
        path = _s(x.get("path"))
        local = addr.startswith("127.") or addr in ("::1",)
        risk = RISKY_PORTS.get(port)
        st = None if local else ("WARNING" if risk and port not in (445, 139, 1900, 5985) else ("REVIEW" if risk else None))
        if not local and path and USER_PATHS.search(path + "\\"):
            sev, why = user_path_verdict(path, x.get("sig"))
            if sev == "WARNING" or st is None:
                st = sev if st != "WARNING" else st
            risk = (risk + " - " if risk else "") + why
        L.append({"Proto": _s(x.get("proto")), "Port": port, "Address": "this PC only" if local else ("all networks" if addr in ("0.0.0.0", "::") else addr),
                  "Program": _s(x.get("proc")), "Service": _s(x.get("svc")), "What": risk or "", "Path": path, "_st": st})
    L.sort(key=lambda z: (_SEV.get(z["_st"], 3), z["Port"] if isinstance(z["Port"], int) else 0))
    E = [{"Program": _s(x.get("proc")), "Connections": _i(x.get("count")), "Examples": ", ".join(_s(v) for v in _l(x.get("remotes"))[:3]),
          "Service": _s(x.get("svc")), "Path": _s(x.get("path"))}
         for x in _dl(r.get("established"))]
    return L, E


def firewall_view(r):
    r = r if isinstance(r, dict) else {}
    F, rows = [], []
    for p in _dl(r.get("profiles")):
        if _s(p.get("enabled")) not in ("True", "1"):
            F.append(("CRITICAL", "Firewall %s profile is OFF" % _s(p.get("name")), "Turn it on in Windows Security > Firewall."))
        if _s(p.get("inbound")) == "Allow":
            F.append(("WARNING", "%s profile allows all incoming traffic by default" % _s(p.get("name")), "The default should be Block."))
    for x in _dl(r.get("rules")):
        prog = _s(x.get("program"))
        prof = _s(x.get("profile"))
        remote = _s(x.get("remote")) or "Any"
        port = _s(x.get("port")) or "Any"
        proto = _s(x.get("proto"))
        group = _s(x.get("group"))
        app_rule = bool(prog) and prog not in ("Any", "System")
        flags = []                                   # (severity, text)
        if app_rule and USER_PATHS.search(os.path.expandvars(prog) + "\\"):
            flags.append(user_path_verdict(prog, x.get("sig")))
            if flags[-1][0] == "WARNING":
                flags[-1] = ("WARNING", "program in a user/temp folder" + flags[-1][1][len("runs from a user/temp folder"):])
        public = "Public" in prof or prof in ("Any", "")
        ports = {int(p) for p in re.findall(r"\d+", port) if len(p) < 6} if port not in ("Any", "") else set()
        rp = ports & set(RISKY_PORTS)
        if public and remote == "Any" and rp:
            flags.append(("WARNING", "%s open to any address on public networks" % ", ".join(RISKY_PORTS[p] for p in sorted(rp))))
        if public and remote == "Any" and not app_rule and port in ("Any", "") and proto in ("Any", ""):
            flags.append(("WARNING", "allows ANY program, ANY port from anywhere"))
        edge = _s(x.get("edge"))
        if edge in ("Allow", "DeferToUser", "DeferToApp") and not group:
            if app_rule and edge in ("DeferToUser", "DeferToApp"):
                # what Windows itself creates when you click 'Allow' in the firewall prompt for an app
                flags.append(("INFO", "edge traversal left to the app (normal for apps you allowed)"))
            else:
                flags.append(("WARNING", "edge traversal (reachable through NAT)"))
        st = None
        if flags:
            st = min((f[0] for f in flags), key=lambda z: _SEV.get(z, 3))
        if not flags and group:
            continue   # built-in Windows rule groups without issues: hide
        rows.append({"Rule": _s(x.get("name")), "Profile": prof, "Program": prog or "Any", "Port": ("%s %s" % (proto, port)).strip(), "From": remote,
                     "Why flagged": "; ".join(f[1] for f in flags), "_st": st if st != "INFO" or flags else None})
    rows.sort(key=lambda z: (_SEV.get(z["_st"], 3), z["Rule"] or ""))
    for rw in rows:
        if rw["_st"] == "WARNING":
            F.append(("WARNING", "Firewall rule: %s" % rw["Rule"], rw["Why flagged"]))
    return F, rows


def lan_sweep(info, progress=None, cancel=None):
    """Ping every address in THIS PC's own subnet (max a /24) so the ARP table fills, then read neighbours + names."""
    ipa, pre = _s(info.get("ipv4")), _i(info.get("prefix"), 24) or 24
    if not ipa:
        return {"error": "No connected network."}
    try:
        net = ipaddress.ip_network("%s/%d" % (ipa, max(pre, 24)), strict=False)
    except ValueError:
        return {"error": "This PC's address %s couldn't be read." % ipa}
    if not net.is_private:
        return {"error": "This PC's address %s isn't a private (home/office) network - WinDiag only maps private networks." % ipa}
    hosts = [str(h) for h in net.hosts() if str(h) != ipa]
    alive = {}
    done = [0]

    def one(h):
        if cancel is not None and cancel.is_set():
            return
        r = ping(h, 400)
        if isinstance(r, float):
            alive[h] = r
        done[0] += 1
        if progress and done[0] % 8 == 0:
            progress(done[0], len(hosts))
    with ThreadPoolExecutor(48) as ex:
        list(ex.map(one, hosts))
    return {"subnet": str(net), "alive": alive, "note": "" if pre >= 24 else "Your network is larger than /24 - only %s (the part this PC is in) was mapped." % net}


def mac_kind(mac):
    try:
        first = int(mac.replace("-", ":").split(":")[0], 16)
    except (ValueError, IndexError, AttributeError):
        return ""
    return "random MAC (phone/laptop privacy)" if first & 2 else ""


def names_for(ips, timeout=2.0):
    out = {}

    def one(ip):
        try:
            out[ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
    with ThreadPoolExecutor(32) as ex:
        list(ex.map(one, ips))
    return out


def w32_parse(text):
    """'key: value' lines of w32tm output (labels are in the Windows display language - only for showing, not for decisions)."""
    d = {}
    for line in _s(text).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def _stratum(text):
    """Stratum from 'w32tm /query /status' without relying on the (localized) labels: it is the 2nd line's first number."""
    lines = [ln for ln in _s(text).splitlines() if ":" in ln]
    if len(lines) >= 2:
        m = re.search(r":\s*(\d+)", lines[1])
        if m:
            return int(m.group(1))
    return None


def time_sync(w):
    """-> (status, title, detail, ok). Uses the service state, the W32Time config and the measured clock offset - no English text."""
    w = _d(w)
    svc = _s(w.get("service"))
    typ = _s(w.get("type"))
    src = re.sub(r",0x[0-9a-fA-F]+", "", _s(w.get("source")) or _s(w.get("peer"))).strip() or "--"
    off = w.get("offset")
    try:
        off = float(off) if off is not None and _s(off) != "" else None
    except (TypeError, ValueError):
        off = None
    base = "Service %s  ·  source %s" % (svc or "--", src)
    if typ.upper() == "NOSYNC":
        return "WARNING", "Time sync: turned off", base + "  ·  Windows is set to never sync the clock (W32Time Type = NoSync). Wrong time breaks HTTPS, sign-ins and updates.", False
    if off is not None:
        a = abs(off)
        txt = base + "  ·  clock differs from %s by %s s." % (_s(w.get("peer")) or "the time server", ("%.3f" % off) if a < 10 else "%.0f" % off)
        if a <= 2:
            return "OK", "Time sync: clock is correct", txt, True
        if a <= 300:
            return "WARNING", "Time sync: clock is %.0f s off" % a, txt + " Sync it now; if it drifts again, the CMOS battery may be weak.", False
        return "CRITICAL", "Time sync: clock is %.0f minutes off" % (a / 60), txt + " Wrong time breaks HTTPS, sign-ins (Kerberos allows 5 minutes) and updates.", False
    st = _stratum(w.get("status"))
    if st == 0 or (st is None and svc and svc != "Running"):
        return "WARNING", "Time sync: not synced", base + "  ·  couldn't reach a time server to compare the clock and Windows reports no successful sync. Wrong time breaks HTTPS, sign-ins and updates.", False
    return "INFO", "Time sync: couldn't measure the clock", base + "  ·  the time server didn't answer (UDP port 123 may be blocked), so the clock couldn't be compared.%s" % (
        " Windows reports a sync source (stratum %d)." % st if st else ""), True


# =====================================================================================
#  Wi-Fi (netsh - English Windows labels; other languages show the raw text)
# =====================================================================================
def _oem_codepage():
    try:
        import ctypes
        return "cp%d" % ctypes.windll.kernel32.GetOEMCP()
    except Exception:
        return None


def _decode_oem(out):
    """Console tools (netsh, tracert, ping) print in the OEM code page (cp437/850/866/932...), or UTF-8 after 'chcp 65001'."""
    if isinstance(out, str):
        return out
    out = out or b""
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        pass
    for enc in (_oem_codepage(), "cp850"):
        if not enc:
            continue
        try:
            return out.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return out.decode("latin-1", "replace")


def _netsh(args):
    try:
        rc, out, err = core.tracked_run([core.sys32("netsh")] + args, 30, "netsh")
        return _decode_oem(out)
    except Exception as e:
        return "ERROR %s" % e


def band_of(text, channel=0):
    """'2.4 GHz' / '5 GHz' / '6 GHz' from netsh's Band field (any decimal separator); channel number only as a last resort
    (6 GHz channels 1-233 overlap the 2.4 GHz and 5 GHz numbers)."""
    t = _s(text).replace(",", ".")
    m = re.search(r"(\d+(?:\.\d+)?)\s*G", t, re.I)
    if m:
        v = float(m.group(1))
        return "2.4 GHz" if v < 3 else ("5 GHz" if v < 5.9 else "6 GHz")
    if channel:
        return "5 GHz" if channel > 14 else "2.4 GHz"
    return ""


# netsh labels are in the Windows display language: map the common translations, and fall back on the value's shape
# (percent = signal, 'GHz' = band, '802.11' = radio type, MAC = BSSID).
_K_CHANNEL = {"channel", "kanal", "canal", "canale", "kanaal", "kanał", "kanava", "kanál", "csatorna", "κανάλι", "канал", "通道", "频道", "チャネル", "채널", "kanalı"}
_K_SIGNAL = {"signal", "señal", "sinal", "segnale", "sygnał", "signaal", "signál", "jel", "сигнал", "信号", "信號", "シグナル", "신호", "sinyal", "signali", "signalstyrka"}
_K_SSID = {"ssid"}
_MAC = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
_GUID = re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$")


def _canon_key(kl, v, seen):
    """English key for a (possibly translated) netsh label."""
    if kl in ("ap bssid", "bssid") or kl.endswith(" bssid"):
        return "bssid"
    if len(seen) == 1 and not _GUID.match(v):         # 2nd line is always the adapter description
        return "description"
    if re.search(r"\((mbps|mbit/s|mb/s|mbit/с|мбит/с)\)$", kl):
        return "transmit rate (mbps)" if "receive rate (mbps)" in seen else "receive rate (mbps)"
    if kl in _K_CHANNEL:
        return "channel"
    if kl in _K_SIGNAL:
        return "signal"
    if kl in _K_SSID or kl == "name" or kl == "band" or kl == "radio type" or kl == "state" or kl == "authentication":
        return kl
    if "signal" not in seen and re.match(r"^\d{1,3}\s*%$", v):
        return "signal"
    if "band" not in seen and re.match(r"^\d+(?:[.,]\d+)?\s*GHz$", v, re.I):
        return "band"
    if "radio type" not in seen and re.match(r"^802\.11\w+$", v):
        return "radio type"
    if "bssid" not in seen and "physical address" in seen and _MAC.match(v) and v.lower() != seen["physical address"].lower():
        return "bssid"
    if "physical address" not in seen and _MAC.match(v):
        return "physical address"
    if "authentication" not in seen and re.match(r"^(WPA|WEP|OWE)", v, re.I):
        return "authentication"
    return kl


def parse_interfaces(text):
    """netsh wlan show interfaces -> list of dicts (English keys). A new interface starts at each block whose lines include a GUID."""
    blocks, cur = [], []
    for line in _s(text).splitlines():
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = []
            continue
        if ":" in line:
            cur.append([x.strip() for x in line.split(":", 1)])
    if cur:
        blocks.append(cur)
    out = []
    for b in blocks:
        if not any(_GUID.match(v) for _, v in b):
            # English-style output without blank lines between interfaces: split on 'Name'
            if not any(k.lower() == "name" for k, _ in b):
                continue
        rec = None
        for k, v in b:
            kl = k.lower()
            if kl == "name" or (rec is None):
                rec = {"name": v}
                out.append(rec)
                continue
            key = _canon_key(kl, v, rec)
            if key not in rec or key == kl:
                rec[key] = v
    out = [c for c in out if len(c) > 2]
    for c in out:
        c["signal"] = int(re.sub(r"\D", "", c.get("signal", ""))[:3] or 0) if c.get("signal") else None
        c["channel_n"] = int(re.sub(r"\D", "", c.get("channel", ""))[:3] or 0) if c.get("channel") else None
        c["band"] = band_of(c.get("band"), c.get("channel_n") or 0)
        c["connected"] = bool(c.get("ssid") and c.get("bssid")) or _s(c.get("state")).lower().startswith("connected")
    return out


def parse_networks(text):
    nets, cur, bss = [], None, None
    for line in _s(text).splitlines():
        m = re.match(r"^SSID \d+\s*:\s*(.*)$", line.strip())
        if m:
            cur = {"ssid": m.group(1) or "(hidden)", "bssids": []}
            nets.append(cur)
            bss = None
            continue
        if cur is None or ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        kl = k.lower()
        if kl.startswith("bssid"):
            bss = {"bssid": v}
            cur["bssids"].append(bss)
        elif bss is not None:
            key = "channel" if kl in _K_CHANNEL else "signal" if kl in _K_SIGNAL else kl
            if key not in bss and kl not in ("channel utilization",):
                if key in ("signal", "radio type", "channel", "band"):
                    bss[key] = v
                elif "signal" not in bss and re.match(r"^\d{1,3}\s*%$", v):
                    bss["signal"] = v
                elif "band" not in bss and re.match(r"^\d+(?:[.,]\d+)?\s*GHz$", v, re.I):
                    bss["band"] = v
                elif "radio type" not in bss and re.match(r"^802\.11\w+$", v):
                    bss["radio type"] = v
        elif kl in ("authentication", "encryption", "network type"):
            cur[kl] = v
        elif "authentication" not in cur and re.match(r"^(WPA|WEP|OWE)", v, re.I):
            cur["authentication"] = v
        elif "authentication" not in cur and v.lower() in ("open", "ouvert", "offen", "abierta", "aberta", "aperta", "otwarte", "открытая"):
            cur["authentication"] = "Open"
    rows = []
    for n in nets:
        for b in n["bssids"]:
            ch = int(re.sub(r"\D", "", b.get("channel", ""))[:3] or 0)
            rows.append({"ssid": n["ssid"], "bssid": b.get("bssid") or "", "signal": min(100, int(re.sub(r"\D", "", b.get("signal", ""))[:3] or 0)), "channel": ch,
                         "band": band_of(b.get("band"), ch), "radio": b.get("radio type", ""), "auth": n.get("authentication", "")})
    return rows


def wifi_scan():
    it = _netsh(["wlan", "show", "interfaces"])
    nt = _netsh(["wlan", "show", "networks", "mode=bssid"])
    return {"interfaces": parse_interfaces(it), "networks": parse_networks(nt), "raw": it if "SSID" not in it else ""}


def channel_advice(networks, current):
    """Recommend the least-crowded channel on the band in use. Our own network's access points (same SSID) are not neighbours."""
    current = current or {}
    cur_ch = current.get("channel_n") or 0
    band = current.get("band") or band_of("", cur_ch)
    band5 = band == "5 GHz"
    my_ssid = (current.get("ssid") or "").strip()
    my_bssid = (current.get("bssid") or "").lower()

    def neighbour(n):
        if n.get("bssid") and my_bssid and n["bssid"].lower() == my_bssid:
            return False
        return not (my_ssid and n.get("ssid") == my_ssid)
    same_band = [n for n in networks if n.get("channel") and (n.get("band") or band_of("", n["channel"])) == band]
    others = [n for n in same_band if neighbour(n)]
    if band == "6 GHz":
        return {"load": {}, "best": None, "band": band, "band5": False, "band6": True,
                "text": "You're on 6 GHz (Wi-Fi 6E/7) - it has many wide, non-overlapping channels and is rarely crowded, so no channel change is needed. "
                        "%d other network(s) nearby use 6 GHz." % len({n["ssid"] for n in others})}
    load = {}
    for n in others:
        ch = n["channel"]
        w = max(0.1, n["signal"] / 100.0)
        if band5:
            load[ch] = load.get(ch, 0) + w
        else:
            for c in range(1, 14):
                if abs(c - ch) < 5:
                    load[c] = load.get(c, 0) + w * (1 - abs(c - ch) / 5.0)
    if band5:
        cands = sorted({n["channel"] for n in same_band} | {36, 40, 44, 48, 149, 153, 157, 161})
    else:
        cands = [1, 6, 11]
    best = min(cands, key=lambda c: load.get(c, 0))
    cur_load = load.get(cur_ch, 0)
    text = ""
    if cur_ch:
        if load.get(best, 0) + 0.5 < cur_load:
            text = "Channel %d is crowded (%d nearby network(s) overlap). Channel %d is quieter - change it in the router's Wi-Fi settings." % (
                cur_ch, sum(1 for n in others if (abs(n["channel"] - cur_ch) < 5 if not band5 else n["channel"] == cur_ch)), best)
        else:
            text = "Your channel (%d) is one of the quietest here - no change needed." % cur_ch
    return {"load": load, "best": best, "text": text, "band": band, "band5": band5, "band6": False}


def wifi_findings(cur):
    F = []
    if not cur:
        return F
    s = cur.get("signal")
    if s is not None:
        if s < 40:
            F.append(("CRITICAL", "Very weak Wi-Fi signal (%d%%)" % s, "Expect drop-outs and slow speeds. Move closer, remove obstacles, or add a mesh node / access point."))
        elif s < 60:
            F.append(("WARNING", "Weak Wi-Fi signal (%d%%)" % s, "Fine for browsing but video calls may stutter."))
        else:
            F.append(("OK", "Good Wi-Fi signal (%d%%)" % s, ""))
    if (cur.get("band") or "").startswith("2.4"):
        F.append(("INFO", "Connected on 2.4 GHz", "Slower and more crowded than 5 GHz. If your router offers 5 GHz, use it when you're in the same or next room."))
    radio = cur.get("radio type") or ""
    if radio and radio.endswith(("11b", "11g")):
        F.append(("WARNING", "Old Wi-Fi standard (%s)" % radio, "Very slow. Check the router's wireless mode or the adapter driver."))
    return F


# =====================================================================================
#  Measure before/after + fixes
# =====================================================================================
def measure(gateway=None, dns=None):
    """~5 s. Router ping, internet ping, DNS time, web test."""
    m = {}
    if gateway:
        r = [ping(gateway, 800) for _ in range(4)]
        st = stats([x if x != "frag" else None for x in r])
        m["router_ms"], m["router_loss"] = st["avg"], st["loss"]
    r = [ping("1.1.1.1", 1000) for _ in range(4)]
    st = stats([x if x != "frag" else None for x in r])
    m["internet_ms"], m["internet_loss"] = st["avg"], st["loss"]
    if dns:
        ms, rc, ips = dns_query(dns[0], "www.microsoft.com")
        m["dns_ms"] = ms
    t0 = time.perf_counter()
    try:
        import http.client
        c = http.client.HTTPConnection("www.msftconnecttest.com", timeout=6)
        c.request("GET", "/connecttest.txt")
        body = c.getresponse().read()
        m["web"] = "OK" if b"Microsoft Connect Test" in body else "Blocked / captive portal"
        m["web_ms"] = round((time.perf_counter() - t0) * 1000)
    except Exception as e:
        m["web"] = "FAILED (%s)" % type(e).__name__
    return m


MEASURE_LABELS = [("router_ms", "Router latency", "ms"), ("router_loss", "Router loss", "%"), ("internet_ms", "Internet latency", "ms"),
                  ("internet_loss", "Internet loss", "%"), ("dns_ms", "DNS lookup", "ms"), ("web", "Web test", ""), ("web_ms", "Web test time", "ms")]


def compare(before, after):
    rows = []
    for k, lab, unit in MEASURE_LABELS:
        b, a = before.get(k), after.get(k)
        if b is None and a is None:
            continue
        verdict = ""
        if isinstance(b, (int, float)) and isinstance(a, (int, float)):
            if a < b * 0.8 and b - a > 2:
                verdict = "better"
            elif a > b * 1.25 and a - b > 2:
                verdict = "worse"
            else:
                verdict = "same"
        elif b != a:
            verdict = "better" if a == "OK" else ("worse" if b == "OK" else "changed")
        fmt = lambda v: "--" if v is None else ("%s %s" % (v, unit)).strip()
        rows.append((lab, fmt(b), fmt(a), verdict))
    return rows


def _q(s):
    return "'" + str(s or "").replace("'", "''") + "'"


FIXES = [
    {"id": "renew", "title": "Renew IP address", "desc": "Asks the router for a fresh address (ipconfig /release + /renew). Fixes 169.254.x.x addresses and many 'connected, no internet' cases.",
     "confirm": "The connection drops for a few seconds. Continue?", "needs": "adapter",
     "ps": "ipconfig /release {a} | Out-Null; Start-Sleep 2; $o = (ipconfig /renew {a}) -join ' '; @{ ok = ($LASTEXITCODE -eq 0); detail = ($o -replace '\\s+', ' ').Substring(0, [math]::Min(300, $o.Length)) } | ConvertTo-Json -Compress"},
    {"id": "flush", "title": "Flush DNS cache", "desc": "Forgets cached website addresses (ipconfig /flushdns). Harmless.", "confirm": None, "needs": None,
     "ps": "Clear-DnsClientCache; @{ ok = $true } | ConvertTo-Json -Compress"},
    {"id": "restart", "title": "Restart network adapter", "desc": "Turns the adapter off and on again - the software equivalent of unplugging it.",
     "confirm": "The connection drops for about 10 seconds. Continue?", "needs": "adapter",
     "ps": "Restart-NetAdapter -Name {a} -Confirm:$false; Start-Sleep 8; @{ ok = $?; detail = \"$((Get-NetAdapter -Name {a}).Status)\" } | ConvertTo-Json -Compress"},
    {"id": "dns_cf", "title": "Switch DNS to Cloudflare (1.1.1.1)", "desc": "Fast, privacy-focused public DNS. Undo with 'DNS back to automatic'.",
     "confirm": "Change this adapter's DNS servers to 1.1.1.1 / 1.0.0.1?", "needs": "adapter",
     "ps": "Set-DnsClientServerAddress -InterfaceAlias {a} -ServerAddresses ('1.1.1.1','1.0.0.1'); Clear-DnsClientCache; @{ ok = $? } | ConvertTo-Json -Compress"},
    {"id": "dns_google", "title": "Switch DNS to Google (8.8.8.8)", "desc": "Google Public DNS.", "confirm": "Change this adapter's DNS servers to 8.8.8.8 / 8.8.4.4?", "needs": "adapter",
     "ps": "Set-DnsClientServerAddress -InterfaceAlias {a} -ServerAddresses ('8.8.8.8','8.8.4.4'); Clear-DnsClientCache; @{ ok = $? } | ConvertTo-Json -Compress"},
    {"id": "dns_quad9", "title": "Switch DNS to Quad9 (9.9.9.9)", "desc": "Blocks known malware domains.", "confirm": "Change this adapter's DNS servers to 9.9.9.9 / 149.112.112.112?",
     "needs": "adapter",
     "ps": "Set-DnsClientServerAddress -InterfaceAlias {a} -ServerAddresses ('9.9.9.9','149.112.112.112'); Clear-DnsClientCache; @{ ok = $? } | ConvertTo-Json -Compress"},
    {"id": "dns_auto", "title": "DNS back to automatic", "desc": "Uses the DNS servers your router hands out (the Windows default).", "confirm": None, "needs": "adapter",
     "ps": "Set-DnsClientServerAddress -InterfaceAlias {a} -ResetServerAddresses; Clear-DnsClientCache; @{ ok = $? } | ConvertTo-Json -Compress"},
    {"id": "proxy", "title": "Clear proxy settings", "desc": "Turns off the user proxy and PAC script and resets the WinHTTP proxy. The old values are shown in the result.",
     "confirm": "Turn off the proxy for this user and reset the system (WinHTTP) proxy?", "needs": None,
     "ps": r"""$k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; $o = Get-ItemProperty $k
Set-ItemProperty $k ProxyEnable 0; Remove-ItemProperty $k AutoConfigURL -ErrorAction SilentlyContinue; netsh winhttp reset proxy | Out-Null
@{ ok = $true; detail = "Was: proxy $(if ($o.ProxyEnable) { 'ON ' + $o.ProxyServer } else { 'off' }), PAC '$($o.AutoConfigURL)'" } | ConvertTo-Json -Compress"""},
    {"id": "wifi_rejoin", "title": "Rejoin Wi-Fi", "desc": "Disconnects and reconnects to the current Wi-Fi network (keeps the saved password).",
     "confirm": "Wi-Fi disconnects for a few seconds. Continue?", "needs": "wifi",
     "ps": "netsh wlan disconnect interface={a} | Out-Null; Start-Sleep 3; $o = (netsh wlan connect name={p} interface={a}) -join ' '; Start-Sleep 6; @{ ok = ($LASTEXITCODE -eq 0); detail = $o } | ConvertTo-Json -Compress"},
    {"id": "wifi_forget", "title": "Forget this Wi-Fi network", "desc": "Deletes the saved profile. You'll need the Wi-Fi password to join again. Fixes a corrupted saved profile.",
     "confirm": "Delete the saved Wi-Fi profile? You will need the password to reconnect.", "needs": "wifi",
     "ps": "$o = (netsh wlan delete profile name={p}) -join ' '; @{ ok = ($LASTEXITCODE -eq 0); detail = $o } | ConvertTo-Json -Compress"},
    {"id": "nic_power", "title": "NIC power saving off", "desc": "Stops Windows turning the adapter off to save power, and sets Wi-Fi power saving to Maximum Performance on this power plan. "
     "Fixes drop-outs after sleep/idle.", "confirm": "Change the adapter's power-management setting?", "needs": "adapter",
     "ps": r"""Set-NetAdapterPowerManagement -Name {a} -AllowComputerToTurnOffDevice Disabled -ErrorAction SilentlyContinue
powercfg /setacvalueindex SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | Out-Null
powercfg /setdcvalueindex SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | Out-Null
powercfg /setactive SCHEME_CURRENT | Out-Null
@{ ok = $true; detail = "Allow turn-off: $((Get-NetAdapterPowerManagement -Name {a}).AllowComputerToTurnOffDevice)" } | ConvertTo-Json -Compress"""},
    {"id": "winsock", "title": "Reset Winsock + TCP/IP", "desc": "Resets Windows' network stack (netsh winsock reset / int ip reset). Fixes broken network software left by VPNs, "
     "antivirus or malware. Needs a restart; VPN software may need reinstalling.", "confirm": "Reset the network stack? You must restart the PC afterwards.", "needs": None,
     "ps": "$a = (netsh winsock reset) -join ' '; $b = (netsh int ip reset) -join ' '; @{ ok = $true; restart = $true; detail = 'Restart the PC to finish.' } | ConvertTo-Json -Compress"},
]
FIX_BY_ID = {f["id"]: f for f in FIXES}


def fix_script(fix, adapter="", profile=""):
    return "$ErrorActionPreference = 'SilentlyContinue'\n" + fix["ps"].replace("{a}", _q(adapter)).replace("{p}", _q(profile))


def run_fix(fix, adapter="", profile=""):
    """Fixes are NOT stopped by the Stop button (track=False)."""
    return core.run_ps_json(fix_script(fix, adapter, profile), 120, fix["title"], track=False)
