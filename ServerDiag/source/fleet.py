"""Fleet mode: scan many Linux / Windows hosts over SSH in parallel."""
import base64
import io
import json
import os
import shlex
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

from .results import convert_windows, error_result, finalize
from .win_collector import SCRIPT as WIN_SCRIPT

PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def self_bundle():
    """Bytes of a runnable .pyz of this tool (used to ship it to Linux hosts)."""
    here = os.path.abspath(__file__)
    if ".pyz" in here:
        pyz = here.split(".pyz")[0] + ".pyz"
        with open(pyz, "rb") as f:
            return f.read()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("__main__.py", "from serverdiag.cli import main\nmain()\n")
        for fn in os.listdir(PKG_DIR):
            if fn.endswith(".py"):
                z.write(os.path.join(PKG_DIR, fn), "serverdiag/" + fn)
    return buf.getvalue()


def parse_hosts(path):
    """hosts file: one per line. 'win:' prefix = Windows (OpenSSH). '#' comments. Optional ' port=2222'."""
    hosts = []
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            target, opts = parts[0], {}
            for p in parts[1:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    opts[k] = v
            family = "linux"
            if target.lower().startswith("win:"):
                family, target = "windows", target[4:]
            elif target.lower().startswith("linux:"):
                target = target[6:]
            hosts.append({"target": target, "family": family, "port": opts.get("port")})
    return hosts


def _ssh_base(h, ssh_opts, connect_timeout):
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % connect_timeout, "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ServerAliveInterval=15"]
    for o in ssh_opts or []:
        cmd += ["-o", o]
    if h.get("port"):
        cmd += ["-p", str(h["port"])]
    return cmd + [h["target"]]


def _run(cmd, data, timeout):
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        return 127, b"", str(e).encode()
    try:
        out, err = p.communicate(input=data, timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        return 124, b"", b"timed out after %d s" % timeout
    return p.returncode, out, err


def scan_linux(h, bundle, days, ssh_opts, timeout, connect_timeout):
    remote = ('f=$(mktemp /tmp/serverdiag.XXXXXX) || exit 90; cat > "$f"; '
              'PY=$(command -v python3 || command -v python3.6 || command -v python3.8 || command -v python3.9); '
              '[ -z "$PY" ] && { echo "python3 not found on host" >&2; rm -f "$f"; exit 91; }; '
              'if sudo -n true 2>/dev/null; then sudo -n "$PY" "$f" --json --days %d; else "$PY" "$f" --json --days %d; fi; '
              'rc=$?; rm -f "$f"; exit $rc') % (days, days)
    rc, out, err = _run(_ssh_base(h, ssh_opts, connect_timeout) + ["sh -c " + shlex.quote(remote)], bundle, timeout)
    if rc != 0 and not out.strip():
        return error_result(h["target"], "linux", "SSH/scan failed (rc %d): %s" % (rc, err.decode("utf-8", "replace").strip()[-300:] or "no output"))
    try:
        res = json.loads(out.decode("utf-8", "replace"))
    except ValueError:
        return error_result(h["target"], "linux", "Bad output from host: %s" % (err.decode("utf-8", "replace").strip()[-300:] or out[:200]))
    res["host"] = h["target"]
    return finalize(res)


def scan_windows(h, days, ssh_opts, timeout, connect_timeout):
    boot = "$s=[Console]::In.ReadToEnd(); . ([scriptblock]::Create($s)) -Check All -Out - -Days %d" % days
    enc = base64.b64encode(boot.encode("utf-16-le")).decode()
    remote = "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + enc
    rc, out, err = _run(_ssh_base(h, ssh_opts, connect_timeout) + [remote], WIN_SCRIPT.encode("utf-8"), timeout)
    txt = out.decode("utf-8", "replace").strip()
    start = txt.find("{")
    if start < 0:
        return error_result(h["target"], "windows", "SSH/scan failed (rc %d): %s" % (rc, (err.decode("utf-8", "replace").strip() or txt)[-300:] or "no output"))
    try:
        raw = json.loads(txt[start:])
    except ValueError as e:
        return error_result(h["target"], "windows", "Bad output from host (%s)" % e)
    raw["days"] = days
    return convert_windows(raw, h["target"])


def scan_fleet(hosts, days=7, parallel=8, ssh_opts=None, timeout=600, connect_timeout=10, progress=None):
    bundle = self_bundle()
    results = [None] * len(hosts)
    with ThreadPoolExecutor(max_workers=max(1, parallel)) as ex:
        futs = {}
        for i, h in enumerate(hosts):
            if h["family"] == "windows":
                futs[ex.submit(scan_windows, h, days, ssh_opts, timeout, connect_timeout)] = i
            else:
                futs[ex.submit(scan_linux, h, bundle, days, ssh_opts, timeout, connect_timeout)] = i
        done = 0
        for fut in as_completed(futs):
            i = futs[fut]
            try:
                results[i] = fut.result()
            except Exception as e:
                results[i] = error_result(hosts[i]["target"], hosts[i]["family"], "Internal error: %s" % e)
            done += 1
            if progress:
                progress(done, len(hosts), results[i])
    return results
