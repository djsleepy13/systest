# Porting a WinDiag page from CustomTkinter to PySide6 (WinDiag 4)

WinDiag 4 replaces the CustomTkinter UI with PySide6 (Qt 6). Reason: CustomTkinter rescales every widget of every page
synchronously when the window moves to a monitor with a different DPI -> freezes/crashes. Qt is per-monitor DPI aware.
The diagnostic LOGIC modules stay exactly as they are (core, drivehealth, ramtest, battery, netdiag, security, filetools,
guided, updates, tuneup, baseline, event_kb, report, facts, specdata, wipesafe, prescan, scanner, appsettings, sysfacts).
Only the *_ui.py / page code is rewritten, into qtui/pages/<name>.py. The old CTk files stay in the folder as reference -
do NOT import them (no tkinter / customtkinter / theme / settings / security_ui / launcher imports anywhere in qtui).

## Hard rules (user's requirements)
1. Layout managers only (QVBoxLayout/QHBoxLayout/QGridLayout). No absolute positioning, no fixed pixel widths for text
   containers (min widths are OK). Everything must scale when dragged between 1080p and 4K monitors.
2. NOTHING slow on the GUI thread: no PowerShell, subprocess, file I/O of real size, sleeps, network, heavy parsing.
   Use `qtui.tasks.run_task(fn, on_done, on_error, on_progress=None, args=(), kwargs=None, name=...)`:
   QThread + QObject worker, callbacks run on the GUI thread (QueuedConnection), deleteLater cleanup built in.
   Call run_task only from the GUI thread. If fn needs progress, pass on_progress and fn gets `progress=` kwarg
   (call progress(obj) from the worker).
   Logic code that posts callbacks with `app.q.put(("guided_cb", None, fn))` from a worker thread still works
   (MainQueue marshals it to the GUI thread). `qtui.tasks.ui(fn)` does the same.
3. Never touch a widget from a worker thread. Never create widgets/pages in a worker thread
   (app.<page attr> raises RuntimeError off the GUI thread). Never call QMessageBox etc. from a worker.
4. Long-running loops (live monitors, tests) run in workers; the UI polls their state with a QTimer (200-1000 ms)
   that is STOPPED in on_hide() and restarted in on_show() if the page has something live. Timers must check the
   widget still exists / page visible.
5. Must not block or crash on exit: implement `shutdown()` on your page if you own threads/timers/tests
   (set cancel events, stop timers). MainWindow.closeEvent calls page.shutdown() then waits for tasks.

## Page contract
```python
from .. import theme as T, widgets as W
class DrivePage(W.Page):                  # W.Page = QWidget with request_render()/render()/on_show()/on_hide()
    def __init__(self, app): super().__init__(app); ...build the static skeleton (cheap)...
    def render(self): ...(re)build data-dependent parts...      # called only while visible (or on first show)
```
- Data setters (called by the scan, any time, page may be hidden): store data, update app-level results, call
  `self.request_render()` (draws now if visible, else on first show) and `self.app.render_summary()` when findings change.
- Keep renders cheap; skip identical redraws (compare the data object / a signature).
- `W.clear_layout(layout)` deletes old children safely.
- Status bar: `self.app.set_status(text, tone=None|"WARNING"|"CRITICAL"|"OK", hold=seconds)`.
- Busy feedback: `self.app._say_busy("start a drive test")` when refusing because something runs.
- PIN for risky actions: `if not self.app.pin.require("the drive wipe"): return`; `self.app.pin.verify(...)` for PIN changes.
- Dialogs: `W.info/W.warn/W.error(parent, text)`, `W.confirm(parent, text, danger=True)`, `W.ask_text(...)`,
  `W.text_dialog(parent, title, text)`; `self.app.text_popup(title, text)`; `self.app.copy_text(text)`.
- Open other pages: `self.app.show_page(key, tab=None)` (keys in qtui/app.py NAV/PAGE_INFO). Tabs: implement
  `open_tab(name)` on your page if it has tabs (Guided Fix uses open_page("nettools", "Fixes") etc.).
- Settings: `import appsettings as S` -> S.get(key), S.put(**kw), S.redact(text, app), PIN helpers.
- App attributes the logic reads/writes: app.results, app.findings_by, app.analysis, app.drive_result, app.ram_result
  ({"info":..., "test":...}), app.battery_result, app.security_result, app.update_result, app.baselines, app.report_dir,
  app.is_admin, app.prescan_result, app.scanner (running, counts(), steps), app.batch (scan running), app.running.
- Methods the scan calls on pages (keep these names/signatures): drives.set_drives(list), ram.set_info(info),
  battery.set_info(info), updates.set_result(res), tune._checked(raw), security.set_result(res) (via app.set_security_result),
  guided.request_render(), guided.resume_checks() -> int, guided.open_playbook(pid). Logic that used
  `app.updates.fetch()` must use `updates.fetch()` (pure module) instead.

## Design system (user's spec - follow it)
Reference look: a dense, flat IT-console / asset-inventory UI (see /root/.claude/uploads/3536ba36-0b9b-515d-aed9-2cf008e2c0d4/4559ea43-image.png):
flat panels with 1px low-alpha borders, small uppercase-free section titles, label-above-value key/value grids, compact tables,
underline tabs, blue links, small flat charts (line, donut). No drop shadows, no gradients, no glows, no purple/indigo, no
nested floating cards, no decorative icons in inputs, no entrance animations.
- Tokens: qtui/theme.py (BG, SURFACE, SURFACE2, SURFACE3, TEXT, TEXT2, MUTED, ACCENT, CRIT/WARN/OK/INFO, tint()).
- Type: T.display(size) = Syne, ONLY for page/hero titles. T.ui(size, weight) = Manrope for UI text. T.mono(size) = JetBrains
  Mono for EVERY number, time, date, size, id, serial, IP, percentage (data). QSS object names in theme.qss():
  "Value", "ValueMono", "Label", "Muted", "Body", "Big", "PanelTitle", "SectionTitle".
- Spacing: T.S1..S6 (4/8/12/16/24/32). 32 px (T.S6) between major blocks (ScrollPage default spacing), 16 px inside panels.
- Widgets (qtui/widgets.py): Panel(title, sub, actions) (.add(widget)), KeyValueGrid, DataTable(columns, widths, on_open,
  mono=[cols], max_rows_visible) (model/view, sortable, status colouring), FindingsList, Banner, Badge, Dot, StatTile,
  Ring, Donut, LineChart, BarChart, Meter, ScrollPage, button(text, slot, kind="primary|secondary|ghost|link|danger|stop",
  icon=name), label(text, role), colored(text, color), divider(), hbox(...).
  Primary buttons are inverted (off-white). Use "danger" only for destructive actions (wipe, delete).
- Icons: T.icon(name, color, size) -> QIcon (names: dashboard specs cpu disk drivehealth ram alert network startup shield server
  cloud activity wand lock folder wrench search play report refresh user gpu battery windows chevron download gauge update
  stop gear wifi copy check x info).
- Plain English for non-technical users; keep every explanation/advice text from the old page (accuracy matters more than looks).

## Testing (Linux container)
- `DISPLAY=:99` (Xvfb running at 1440x900; start with `Xvfb :99 -screen 0 1440x900x24 &` if needed), python3.12 has PySide6.
- Harness with fake Windows data: `exec(open('/tmp/claude-0/q/qbase.py').read())` -> creates `qapp`, `app` (MainWindow),
  `grab(name, widget=None)` (saves PNG to $SHOTS), `later(ms, fn)`, `dialog(cls)`. See /tmp/claude-0/q/t0.py (start popup ->
  full scan -> pages). Set SHOTS=/tmp/claude-0/q/<you>/shots. Errors go to /tmp/claude-0/q/gs/Reports/windiag_errors.log
  (each harness run: delete it first; ANY entry from your page is a bug).
- Look at your screenshots. Test resizing (app.resize(1100, 680) and 1920x1080), switching pages quickly, data arriving
  while the page is visible and while hidden, double data delivery, empty data, odd/partial data.
- Simulate a DPI change: `QApplication.instance().setStyleSheet(...)` won't do it; instead run the harness with
  `QT_SCALE_FACTOR=1.5` and with `QT_SCALE_FACTOR=2` and look at the screenshots (nothing clipped/overlapping).
- python3 -m pyflakes on your files.

## Parallel agents - isolation
- Several agents port pages at the same time. Edit ONLY your own files in qtui/pages/. Do NOT edit qtui/app.py, widgets.py,
  theme.py, tasks.py or any logic module. If you need a shared-widget change, add a small private helper in your own file and
  mention the suggested shared change in your final report.
- Use your own harness dirs: `WD_GS=/tmp/claude-0/q/<you>/gs SHOTS=/tmp/claude-0/q/<you>/shots`. Your error log is then
  $WD_GS/Reports/windiag_errors.log. Write your test scripts in /tmp/claude-0/q/<you>/ (copy t0.py as a start).
- Lint: python3.12 -m pyflakes <your files>.
