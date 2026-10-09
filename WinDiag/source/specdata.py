"""Spec sheet data (no UI)."""
import os
from datetime import datetime
from html import escape
import facts as fx
import ramtest as rt


def build_specs(app):
    """Return (header dict, [(section title, icon, [(label, value, status or None)])])."""
    F = fx.gather(app)
    o = F["overview"]
    head = {"name": o.get("Computer name") or os.environ.get("COMPUTERNAME", "PC"), "model": ("%s %s" % (o.get("Manufacturer") or "", o.get("Model") or "")).strip(),
            "serial": o.get("Serial number"), "os": o.get("Windows")}
    S = []
    S.append(("Device", "windows", [("Manufacturer", o.get("Manufacturer"), None), ("Model", o.get("Model"), None), ("Serial number", o.get("Serial number"), None),
                                    ("Computer name", o.get("Computer name"), None), ("Signed-in user", o.get("Signed-in user"), None),
                                    ("Platform", (F["platform"] or {}).get("Platform"), None)]))
    act = str(o.get("Activation") or "")
    S.append(("Operating system", "windows", [("Windows", o.get("Windows"), None), ("Build", o.get("Build"), None), ("Architecture", o.get("Architecture"), None),
                                              ("Installed on", o.get("Installed on"), None), ("Last boot", o.get("Last boot"), None), ("Uptime", o.get("Uptime"), None),
                                              ("Activation", act, "OK" if act.startswith("Licensed") else ("WARNING" if act else None)),
                                              ("Domain", (F["server"] or {}).get("Domain"), None)]))
    S.append(("Processor", "cpu", [("CPU", str(o.get("CPU") or "").replace("(R)", "").replace("(TM)", ""), None), ("Cores / threads", o.get("Cores / threads"), None),
                                   ("Load at scan", o.get("CPU load now"), None)]))
    ram = F["ram"]
    rows = [("Installed", o.get("RAM") or (fx.fmt_bytes(ram["total"]) if ram else None), None)]
    if ram:
        rows += [("Type", "/".join(ram["types"]), None), ("Slots", "%d of %d used" % (sum(1 for s in ram["slots"] if s), ram["nslots"]), None),
                 ("Error correction", ram["ecc"], None)]
        for k, s in enumerate(ram["slots"]):
            rows.append((s.get("slot") if s else "Slot %d" % (k + 1),
                         ("%s %s @ %s MT/s (rated %s)  ·  %s %s" % (rt._fmt(s.get("size") or 0), rt.MEM_TYPES.get(s.get("type"), ""), s.get("configured"), s.get("speed"),
                                                                        rt.maker_name(s.get("maker")), s.get("part") or "")) if s else "empty", None))
    else:
        for m in F["ram_modules"]:
            rows.append((m.get("Slot"), "%s @ %s MHz  ·  %s %s" % (m.get("Size"), m.get("Running at") or m.get("Speed MHz"), m.get("Manufacturer"), m.get("Part no.")), None))
    t = F["ramtest"]
    if t:
        rows.append(("RAM test", t.get("text"), "OK" if t.get("verdict") == "PASS" else "CRITICAL" if t.get("verdict") == "FAIL" else None))
    S.append(("Memory", "ram", rows))
    rows = []
    for g in F["gpus"]:
        rows.append((g.get("GPU"), "driver %s (%s)  ·  %s" % (g.get("Driver version"), g.get("Driver date"), g.get("Resolution")),
                     "WARNING" if "Basic Display" in (g.get("GPU") or "") else None))
    S.append(("Graphics", "gpu", rows or [("Graphics", None, None)]))
    rows = []
    if F["drives"]:
        for d in F["drives"]:
            v = d["verdict"]
            st = {"GOOD": "OK", "CAUTION": "WARNING", "CRITICAL": "CRITICAL"}.get(v["status"])
            m = v["metrics"]
            extra = []
            for k in ("Temperature", "Life left", "Power-on hours", "Data written"):
                if m.get(k) is not None:
                    extra.append("%s %s%s" % (k.lower(), m[k], {"Temperature": " C", "Life left": "%"}.get(k, "")))
            rows.append(("Disk %s" % d["number"], "%s  ·  %s  ·  %s  ·  %s%s" % (
                d.get("model"), v["kind"], fx.fmt_bytes(d.get("size")), v["status"] + ("" if v["health"] is None else " %d%%" % v["health"]),
                ("  ·  " + ", ".join(extra)) if extra else ""), st))
    else:
        for p in F["phys"]:
            rows.append((p.get("Model"), "%s  ·  %s  ·  %s  ·  %s" % (p.get("Type") or p.get("Interface"), p.get("Bus") or "", p.get("Size"), p.get("Health") or p.get("Status")),
                         "OK" if p.get("Health") == "Healthy" else None))
    for v in F["volumes"]:
        try:
            pct = float(v.get("Free %"))
        except (TypeError, ValueError):
            pct = None
        rows.append(("Volume %s" % v.get("Drive"), "%s free of %s  ·  %s %s" % (v.get("Free"), v.get("Size"), v.get("FS") or "", ("· " + v["Label"]) if v.get("Label") else ""),
                     None if pct is None else ("CRITICAL" if pct < 10 else "WARNING" if pct < 15 else "OK")))
    S.append(("Storage", "disk", rows or [("Storage", None, None)]))
    S.append(("Motherboard & firmware", "board", [("Motherboard", o.get("Motherboard"), None), ("BIOS", o.get("BIOS version"), None),
                                                   ("Firmware mode", o.get("Firmware mode"), None),
                                                   ("Secure Boot", o.get("Secure Boot"), "OK" if str(o.get("Secure Boot")) == "On" else ("WARNING" if o.get("Secure Boot") == "Off" else None)),
                                                   ("TPM", o.get("TPM"), "OK" if str(o.get("TPM", "")).startswith("Present") else None)]))
    rows = []
    for a in F["adapters"]:
        ip = next((c.get("IPv4") for c in F["ipconf"] if c.get("Interface") == a.get("Name")), "")
        rows.append((a.get("Name"), "%s  ·  %s  ·  %s%s" % (a.get("Description"), a.get("Speed") or "", a.get("MAC") or "", ("  ·  " + ip) if ip else ""),
                     "OK" if a.get("Status") == "Up" else None))
    for c in F["conn"]:
        rows.append((c.get("Test"), "%s %s" % (c.get("Result"), c.get("Detail") or ""), "OK" if c.get("Result") == "OK" else "CRITICAL"))
    S.append(("Network", "network", rows or [("Network", None, None)]))
    d = F["defender"]
    rows = [(x.get("Antivirus"), "enabled" if x.get("Enabled") == "Yes" else "disabled", "OK" if x.get("Enabled") == "Yes" else "WARNING") for x in F["av"]]
    if d:
        rows += [("Real-time protection", d.get("Real-time protection"), "OK" if str(d.get("Real-time protection")) == "True" else "CRITICAL"),
                 ("Definitions", d.get("Definitions updated"), None)]
    for x in F["firewall"]:
        rows.append(("Firewall (%s)" % x.get("Profile"), "on" if str(x.get("Enabled")) == "True" else "OFF", "OK" if str(x.get("Enabled")) == "True" else "WARNING"))
    for x in F["bitlocker"]:
        rows.append(("BitLocker %s" % x.get("Drive"), "%s, protection %s" % (x.get("Status"), x.get("Protection")), None))
    S.append(("Security", "shield", rows or [("Security", None, None)]))
    if F["battery"]:
        rows = []
        for b in F["battery"]:
            try:
                hp = int(str(b.get("Health")).split()[0])
            except (ValueError, IndexError):
                hp = None
            rows.append((b.get("Battery"), "health %s  ·  charge %s  ·  %s of %s mWh" % (b.get("Health"), b.get("Charge now"), b.get("Full charge capacity (mWh)"),
                                                                                              b.get("Design capacity (mWh)")),
                         None if hp is None else ("OK" if hp >= 75 else "WARNING" if hp >= 50 else "CRITICAL")))
        S.append(("Battery", "battery", rows))
    br = getattr(app, "battery_result", None)
    if br and br.get("present"):
        rows = []
        for b in br.get("batteries", []):
            h = b.get("health")
            rows.append((b.get("name") or "Battery", "health %s  ·  %s cycles  ·  %s / %s mWh  ·  %s" % (
                "%.0f%%" % h if h is not None else "--", b.get("cycles") if b.get("cycles") is not None else "--",
                b.get("full") or "--", b.get("design") or "--", b.get("chemistry") or ""),
                None if h is None else ("OK" if h >= 80 else "WARNING" if h >= 50 else "CRITICAL")))
        if br.get("wear_per_year") is not None:
            rows.append(("Wear rate", "%.1f%% of design capacity per year" % br["wear_per_year"], None))
        if rows:
            S = [x for x in S if x[0] != "Battery"] + [("Battery", "battery", rows)]
    return head, S
