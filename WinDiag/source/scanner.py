"""
Background scan (3.3). No full-screen overlay: the app opens on the Dashboard, the scan runs in worker threads and every
page fills in as soon as its check finishes. Progress is shown in the top bar / status bar. Esc / Stop cancels.
Nothing in this module touches Tk widgets from a worker thread - results go back through app.q.
"""
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import core
import drivehealth as dh
import event_kb
import ramtest as rt
import security
import appsettings as security_ui

# typical seconds per step (used for an honest progress estimate)
EXPECT = {"System": 8, "Disks": 7, "Errors": 9, "Network": 14, "Startup": 7, "Security": 16, "Server": 5, "Virt": 4, "Events": 22,
          "drives": 6, "ram": 4, "battery": 6, "updates": 70, "secscan": 110, "snapshot": 18, "tune": 8}
LABELS = {"System": "Hardware & Windows", "Disks": "Drives & free space", "Errors": "Crashes & blue screens", "Network": "Network & internet",
          "Startup": "Startup apps", "Security": "Antivirus & firewall", "Server": "Server roles", "Virt": "Virtualization",
          "Events": "Event logs", "drives": "Drive health", "ram": "Memory (RAM)", "battery": "Battery",
          "updates": "Windows Update (online)", "secscan": "Security scan", "snapshot": "Performance measurement", "tune": "Tune-up settings"}


class Scanner(object):
    SLOW_FACTOR = 1.5

    def __init__(self, app):
        self.app = app
        self.steps = []
        self.cancel = threading.Event()
        self.running = False
        self.t_start = 0.0
        self.shown = 0.0          # progress shown so far (never goes backwards)
        self.runner = None        # optional: callable(fn) that runs fn in a background thread

    # ------------------------------------------------------------------ options (saved next to the exe)
    @staticmethod
    def options():
        s = security_ui.load_settings()
        return {"updates": bool(s.get("scan_updates", True)), "secscan": bool(s.get("scan_security", False)),
                "days": int(str(s.get("scan_days", "30 days")).split()[0] or 30)}

    @staticmethod
    def save_options(**kw):
        s = security_ui.load_settings()
        m = {"updates": "scan_updates", "secscan": "scan_security", "days": "scan_days"}
        for k, v in kw.items():
            s[m.get(k, k)] = ("%d days" % v) if k == "days" else v
        security_ui.save_settings(s)

    def build_steps(self, mode="full"):
        o = self.options()
        full = mode == "full"
        keys = ["System", "Disks", "Errors", "Network", "Security"] + (["Startup", "Server", "Virt"] if full else [])
        steps = [{"key": k, "kind": "check"} for k in keys]
        steps.append({"key": "Events", "kind": "events", "days": o["days"] if full else 7})
        steps += [{"key": "drives", "kind": "drives"}, {"key": "ram", "kind": "ram"}, {"key": "battery", "kind": "battery"}]
        if o["updates"]:
            steps.append({"key": "updates", "kind": "updates"})
        if o["secscan"]:
            steps.append({"key": "secscan", "kind": "secscan"})
        if full:
            steps.append({"key": "tune", "kind": "tune"})
            steps.append({"key": "snapshot", "kind": "snapshot"})
        for s in steps:
            s.update(state="wait", t0=None, t1=None, note="", expect=EXPECT.get(s["key"], 8))
        return steps

    # ------------------------------------------------------------------ run
    def start(self, mode="full"):
        if self.running:
            return False
        self.mode = mode
        self.steps = self.build_steps(mode)
        self.cancel.clear()
        core.reset_abort()
        self.t_start = time.time()
        self.shown = 0.0
        self.running = True
        if self.runner:
            self.runner(self._run_all)          # Qt UI: a QThread worker (qtui.tasks.run_task)
        else:
            threading.Thread(target=self._run_all, name="scan", daemon=True).start()
        return True

    def stop(self):
        self.cancel.set()

    def _run_all(self):
        try:
            steps = list(self.steps)
            first = [s for s in steps if s["key"] == "System"]
            rest = [s for s in steps if s["key"] not in ("System", "snapshot")]
            last = [s for s in steps if s["key"] == "snapshot"]
            for s in first:                       # alone first, so the CPU-load reading isn't skewed by the other checks
                self._run_step(s)
            # Windows Update (online, mostly waiting on the network) starts first on its own extra worker, so it overlaps with
            # the quick local checks; the local checks keep their order so the Dashboard fills in quickly.
            online = [s for s in rest if s["key"] == "updates"]
            rest = online + [s for s in rest if s["key"] != "updates"]
            with ThreadPoolExecutor(max_workers=3 + len(online)) as ex:
                list(ex.map(self._run_step, rest))
            for s in last:
                self._run_step(s)
        except Exception as e:
            core.log_error("scan", e)
        finally:
            self.running = False
            self.app.q.put(("guided_cb", None, lambda: self.app.scan_finished(self.cancel.is_set())))

    def _post(self, fn):
        self.app.q.put(("guided_cb", None, fn))

    def _run_step(self, s):
        if self.cancel.is_set():
            s["state"], s["note"] = "skipped", "stopped"
            return
        s["state"], s["t0"] = "run", time.time()
        app = self.app
        bad, cb = None, None
        try:
            k = s["kind"]
            if k in ("check", "events"):
                res = core.run_check(s["key"], days=s.get("days", 30))
                if k == "events":
                    res["analysis"] = event_kb.analyze(res.get("events") or [], server=app._is_server())
                    res["events"] = []
                bad = res.get("error")
                if res.get("aborted") or self.cancel.is_set():
                    cb, bad = None, "Stopped by user"         # don't turn a stopped check into a "could not run" warning
                else:
                    cb = lambda key=s["key"], res=res: app._on_result(key, res)
            elif k == "drives":
                raw = core.run_ps_json(dh.DRIVES_PS, 240, "Drive health")
                exe = dh.find_smartctl(core.app_dir())
                smart = dh.smartctl_all(exe) if exe else None
                drives = dh.build(raw, smart) if raw.get("drives") is not None else None
                cb = (lambda d=drives: app.drives.set_drives(d)) if drives is not None else None
                bad = None if drives is not None else (raw.get("detail") or "no data")
            elif k == "ram":
                raw = core.run_ps_json(rt.RAM_PS, 120, "RAM")
                info = rt.assess(raw) if (raw.get("sticks") is not None or raw.get("total")) else None
                cb = (lambda i=info: app.ram.set_info(i)) if info else None
                bad = None if info else (raw.get("detail") or "no data")
            elif k == "battery":
                import battery as bt
                raw = core.run_ps_json(bt.BATTERY_PS, 120, "Battery check")
                info = bt.assess(raw) if raw.get("status") != "error" else None
                cb = (lambda i=info: app.battery.set_info(i)) if info else None
                bad = None if info else (raw.get("detail") or "no data")
                if info and not info.get("present"):
                    s["note"] = "no battery"
            elif k == "updates":
                import updates as _up
                res = _up.fetch()
                cb = lambda r=res: app.updates.set_result(r)
                bad = None if res.get("ok") else res.get("error")
            elif k == "secscan":
                raw = core.run_ps_json(security.TRIAGE_PS, 1200, "Security scan")
                res = security.analyze(raw) if "entries" in raw else None
                cb = (lambda r=res: app.set_security_result(r)) if res else None
                bad = None if res else (raw.get("detail") or "no data")
            elif k == "tune":
                import tuneup as tu
                raw = core.run_ps_json(tu.TUNE_PS, 180, "Tune-up check")
                cb = None if raw.get("aborted") else (lambda r=raw: app.tune._checked(r))
                bad = "Stopped by user" if raw.get("aborted") else None
            elif k == "snapshot":
                import baseline
                snap = baseline.take_snapshot(app, "Full scan %s" % time.strftime("%Y-%m-%d %H:%M"))
                bad = None if snap else "could not measure"
            if self.cancel.is_set() and k not in ("check", "events"):
                cb = None                                 # stopped: keep whatever the page showed before
            if cb:
                self._post(cb)
            if bad and ("Stopped by user" in str(bad) or self.cancel.is_set()):
                s["state"], s["note"] = "skipped", "stopped"
            else:
                s["state"] = "fail" if bad else "done"
                if bad:
                    s["note"] = "could not run"
        except Exception as e:
            core.log_error("scan step %s" % s.get("key"), e)
            s["state"], s["note"] = ("skipped", "stopped") if self.cancel.is_set() else ("fail", "could not run")
        s["t1"] = time.time()

    # ------------------------------------------------------------------ progress (read from the main thread)
    def counts(self):
        done = sum(1 for s in self.steps if s["state"] in ("done", "fail", "skipped"))
        return done, len(self.steps)

    def estimate(self):
        """(fraction 0..0.99, seconds_left, slow step or None). Overrunning steps make the estimate grow instead of sticking."""
        now = time.time()
        el_total = now - self.t_start
        rem_run, slow, pending, tail = [], None, 0.0, 0.0
        for s in self.steps:
            st = s["state"]
            if st == "run":
                el = now - (s["t0"] or now)
                r = max(s["expect"] - el, 0.15 * el + 3)
                rem_run.append(r)
                if el > max(20, s["expect"] * self.SLOW_FACTOR) and (slow is None or el > slow[1]):
                    slow = (s, el)
            elif st == "wait":
                if s["key"] in ("snapshot", "System"):
                    tail += s["expect"]
                else:
                    pending += s["expect"]
        rem = max(max(rem_run, default=0.0), (sum(rem_run) + pending) / 3.0) + tail
        frac = el_total / (el_total + rem) if (el_total + rem) > 0 else 0.0
        done, total = self.counts()
        if total:
            frac = max(frac, 0.95 * done / total)          # never lags far behind the visible "x of y done"
        self.shown = max(self.shown, min(0.99, frac))
        return self.shown, rem, slow

    def status_text(self):
        """One line for the status bar."""
        if self.cancel.is_set():
            return "Stopping the scan - waiting for the running checks to end..."
        frac, rem, slow = self.estimate()
        done, total = self.counts()
        running = [LABELS.get(s["key"], s["key"]) for s in self.steps if s["state"] == "run"]
        if slow:
            s, el = slow
            doing = "%s is slow - still working (%d:%02d)" % (LABELS.get(s["key"], s["key"]), el // 60, el % 60)
        else:
            doing = ("Checking: " + ", ".join(running)) if running else "Finishing..."
        el = time.time() - self.t_start
        left = ""
        if el > 5 and rem and not slow:
            rr = int(-(-rem // 5) * 5)
            left = "  ·  ~%d:%02d left" % (rr // 60, rr % 60) if rr >= 60 else "  ·  under a minute left"
        return "Scanning %d%%  ·  %d of %d done  ·  %s%s  ·  pages fill in as results arrive  ·  Esc = stop" % (frac * 100, done, total, doing, left)
