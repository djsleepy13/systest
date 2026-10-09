"""
Settings, technician PIN and privacy redaction - no UI code (shared by the Qt UI and the logic modules).
Stored in WinDiag_settings.json next to WinDiag.exe.
"""
import base64
import hashlib
import json
import os
import re

import core


def settings_path():
    return os.path.join(core.app_dir(), "WinDiag_settings.json")


def load_settings():
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(d):
    try:
        tmp = settings_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=1)
        os.replace(tmp, settings_path())
    except Exception as e:
        core.log_error("save settings", e)


DEFAULTS = {"auto_full_scan": False, "consent_required": True, "privacy_mode": False, "wipe_enabled": False,
            "public_ip": False, "pin_startup": True, "pin_risky": True}


def get(key):
    s = load_settings()
    return s.get(key, DEFAULTS.get(key))


def put(**kw):
    s = load_settings()
    s.update(kw)
    save_settings(s)


# ---------------------------------------------------------------------------------
#  PIN (PBKDF2-SHA256, salted; stored in WinDiag_settings.json next to the exe)
# ---------------------------------------------------------------------------------
def _hash(pin, salt):
    return base64.b64encode(hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, 200000)).decode()


def pin_set():
    return bool(load_settings().get("pin_hash"))


def set_pin(pin):
    salt = os.urandom(16)
    put(pin_hash=_hash(pin, salt), pin_salt=base64.b64encode(salt).decode())


def clear_pin():
    s = load_settings()
    s.pop("pin_hash", None)
    s.pop("pin_salt", None)
    save_settings(s)


def check_pin(pin):
    s = load_settings()
    if not s.get("pin_hash"):
        return True
    try:
        return _hash(pin, base64.b64decode(s["pin_salt"])) == s["pin_hash"]
    except Exception:
        return False


# ---------------------------------------------------------------------------------
#  Privacy mode: hide serial numbers and user names in saved reports
# ---------------------------------------------------------------------------------
def secrets(app):
    a, b = secrets_split(app)
    return sorted(set(a) | set(b), key=len, reverse=True)


_JUNK = ("none", "n/a", "default string", "to be filled by o.e.m.")


def secrets_split(app):
    """(serials / MACs, user names) to hide in privacy mode."""
    out, users = set(), set()
    import facts
    try:
        F = facts.gather(app)
        o = F["overview"]
        for k in ("Serial number",):
            if o.get(k):
                out.add(str(o[k]))
        for d in F["drives"] or []:
            if d.get("serial"):
                out.add(str(d["serial"]))
        for s in ((F["ram"] or {}).get("sticks") or []):
            if s.get("serial") and s["serial"] not in ("0000", "00000000"):
                out.add(str(s["serial"]))
        for a in F["adapters"]:
            if a.get("MAC"):
                out.add(str(a["MAC"]))
        su = o.get("Signed-in user") or ""
        if "\\" in su:
            users.add(su.split("\\", 1)[1])
    except Exception:
        pass
    u = os.environ.get("USERNAME")
    if u:
        users.add(u)
    keep = lambda xs: sorted((x for x in xs if x and len(x) >= 3 and x.lower() not in _JUNK), key=len, reverse=True)
    return keep(out), keep(users)


# user names that are also everyday words: hidden only where they appear as a name (C:\Users\<name>, DOMAIN\<name>)
_COMMON_NAMES = {"user", "users", "admin", "administrator", "owner", "guest", "test", "pc", "home", "office", "student", "default", "public",
                 "support", "service", "system", "windows", "microsoft", "local", "family", "work"}


def redact_with(text, serials, users):
    """Whole words only: a user called 'admin' must not turn 'Administrator' into '••••istrator'."""
    for x in serials:
        text = re.sub(r"(?<![\w])%s(?![\w])" % re.escape(x), "••••", text, flags=re.I)
    for x in users:
        e = re.escape(x)
        text = re.sub(r"(?i)(?<=\\)%s(?![\w])" % e, "••••", text)               # C:\Users\name, DOMAIN\name
        text = re.sub(r"(?i)(?<=/)%s(?![\w])" % e, "••••", text)                  # C:/Users/name
        if x.lower() not in _COMMON_NAMES:
            text = re.sub(r"(?<![\w])%s(?![\w])" % e, "••••", text, flags=re.I)
    return text


def redact(text, app):
    if not get("privacy_mode"):
        return text
    try:
        serials, users = secrets_split(app)
        return redact_with(text, serials, users)
    except Exception as e:
        import core
        core.log_error("privacy redact", e)
        return text


