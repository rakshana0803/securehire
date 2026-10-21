"""USB, process and window monitors with fake OS backends (plus one real-psutil process test)."""
import subprocess
import sys
import time

from agent.models import ProcessInfo
from agent.monitor_base import Monitor
from agent.process_monitor import ProcessMonitor, PsutilBackend, find_new_processes
from agent.usb_monitor import UsbMonitor, classify_usb_device, diff_snapshots, parse_vid_pid
from agent.window_monitor import WindowMonitor, split_windows
from conftest import ASSESSMENT, FakeUsbBackend, FakeWindowBackend, usb, win


def wait_until(pred, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


# --------------------------------------------------------------------------- USB classification
def test_classify_usb_devices_from_windows_metadata():
    assert classify_usb_device("USBSTOR", "USB", r"USB\VID_0781&PID_5567\AA") == "storage"
    assert classify_usb_device("UASPStor", "SCSIAdapter", r"USB\VID_174C&PID_55AA\1") == "storage"
    assert classify_usb_device("HidUsb", "HIDClass", r"USB\VID_046D&PID_C077\5&1") == "input"
    assert classify_usb_device("usbvideo", "Camera", r"USB\VID_046D&PID_085B\1") == "camera"
    assert classify_usb_device("WUDFRd", "WPD", r"USB\VID_04E8&PID_6860\R58") == "portable_device"
    assert classify_usb_device("USBHUB3", "USB", r"USB\ROOT_HUB30\4&1") is None, "hubs are not reported"
    # Composite devices are classified by their child interfaces
    assert classify_usb_device("usbccgp", "USB", r"USB\VID_046D&PID_C52B\5&2", hid_vidpids={("046D", "C52B")}) == "input"
    assert classify_usb_device("usbccgp", "USB", r"USB\VID_04E8&PID_6860\R5", portable_vidpids={("04E8", "6860")}) == "portable_device"
    assert classify_usb_device("usbccgp", "USB", r"USB\VID_1111&PID_2222\1") == "composite"
    assert parse_vid_pid(r"USB\VID_046d&PID_c52b\x") == ("046D", "C52B")


def test_diff_snapshots_connect_disconnect():
    a, b = usb("A", "input"), usb("B", "storage")
    changes = diff_snapshots({"A": a}, {"B": b})
    assert [(c.kind, c.device.instance_key) for c in changes] == [("disconnected", "A"), ("connected", "B")]
    assert diff_snapshots({"A": a}, {"A": a}) == [], "identical snapshots produce nothing (repeated notifications)"


def test_usb_monitor_baseline_connect_disconnect_reconnect():
    backend = FakeUsbBackend({"KB": usb("KB", "input")})  # keyboard already connected at start
    seen = []
    m = UsbMonitor(on_change=seen.append, reconcile_seconds=0.05, backend_factory=lambda: backend)
    m.start()
    assert wait_until(lambda: m.state == "active")
    assert m.baseline_count == 1
    time.sleep(0.15)
    assert seen == [], "already-connected devices are not reported"
    stick = usb("STICK", "storage", service="USBSTOR")
    backend.plug(stick)
    assert wait_until(lambda: len(seen) == 1)
    backend.changed.set(); backend.changed.set()  # Windows sends several notifications per device
    time.sleep(0.15)
    assert len(seen) == 1, "no duplicate events from repeated notifications"
    backend.unplug("STICK")
    assert wait_until(lambda: len(seen) == 2)
    backend.plug(stick)
    assert wait_until(lambda: len(seen) == 3)
    assert [c.kind for c in seen] == ["connected", "disconnected", "connected"]
    m.stop()
    assert backend.closed and m.state == "stopped"


def test_usb_monitor_reports_unsupported_off_windows():
    if sys.platform == "win32":
        return
    states = []
    m = UsbMonitor(on_change=lambda c: None, on_health=lambda n, s, e: states.append(s))
    m.start()
    assert m.state == "unsupported" and states == ["unsupported"]


# --------------------------------------------------------------------------- monitor resilience
class Flaky(Monitor):
    name = "flaky"

    def __init__(self, on_health):
        super().__init__(on_health)
        self.calls = 0

    def poll(self):
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError("transient OS error")

    def wait(self):
        self._stop.wait(0.01)


def test_monitor_errors_are_reported_and_recover(monkeypatch):
    import agent.monitor_base as mb
    states = []
    m = Flaky(lambda n, s, e: states.append(s))
    real_wait = m._stop.wait
    monkeypatch.setattr(m._stop, "wait", lambda t=None: real_wait(min(t or 0.01, 0.02)))
    m.start()
    assert wait_until(lambda: "error" in states and states[-1] == "active")
    m.stop()
    assert states[:2] == ["starting", "active"] and "error" in states and states[-1] == "stopped"
    assert mb is not None


# --------------------------------------------------------------------------- processes
def test_find_new_processes_handles_pid_reuse_and_session_start():
    known = {(100, 50.0)}
    current = [ProcessInfo(100, "old.exe", 50.0), ProcessInfo(100, "reused.exe", 200.0), ProcessInfo(101, "before.exe", 10.0), ProcessInfo(7, "me.exe", 300.0)]
    new = find_new_processes(known, current, session_start=100.0, excluded_pids={7})
    assert [p.name for p in new] == ["reused.exe"]


class FakeProcs:
    def __init__(self, procs):
        self.procs = list(procs)

    def list_processes(self):
        return list(self.procs)


def test_process_monitor_reports_only_new_non_baseline_apps():
    t0 = 1000.0
    fake = FakeProcs([ProcessInfo(1, "chrome.exe", 500.0), ProcessInfo(2, "explorer.exe", 400.0)])
    seen = []
    m = ProcessMonitor(on_started=seen.append, poll_seconds=0.02, backend_factory=lambda: fake, clock=lambda: t0)
    m.start()
    assert wait_until(lambda: m.state == "active")
    fake.procs.append(ProcessInfo(3, "chrome.exe", t0 + 5))      # browser helper of an app already running
    fake.procs.append(ProcessInfo(4, "assist.exe", t0 + 6))      # genuinely new application
    assert wait_until(lambda: len(seen) == 1)
    time.sleep(0.1)
    assert [p.name for p in seen] == ["assist.exe"], "no repeat reports of the same process"
    m.stop()


def test_process_monitor_detects_a_real_process_launch():
    """Uses the real psutil backend on this machine: start a child process and see it reported."""
    seen = []
    m = ProcessMonitor(on_started=seen.append, poll_seconds=0.1, backend_factory=PsutilBackend)
    m.start()
    assert wait_until(lambda: m.state == "active")
    time.sleep(0.2)
    code = "import time; time.sleep(3)"
    # A copy of the interpreter under a new name, so it is not suppressed as an already-running app.
    import shutil, tempfile, os
    d = tempfile.mkdtemp()
    exe = os.path.join(d, "shtestapp" + (".exe" if sys.platform == "win32" else ""))
    shutil.copy(sys.executable, exe)
    os.chmod(exe, 0o755)
    child = subprocess.Popen([exe, "-c", code], env={**os.environ, "PYTHONHOME": sys.base_prefix})
    try:
        assert wait_until(lambda: any(p.pid == child.pid for p in seen), timeout=5.0), [p.name for p in seen]
        assert any(p.name.startswith("shtestapp") for p in seen)
    finally:
        child.kill(); m.stop(); shutil.rmtree(d, ignore_errors=True)


# --------------------------------------------------------------------------- windows
def test_split_windows_finds_assessment_and_filters_shell_ui(cfg):
    ws = [win(1, **ASSESSMENT), win(2, cls="Shell_TrayWnd"), win(3, rect=(0, 0, 30, 20)), win(4, pid=4242), win(5)]
    a_rect, cands = split_windows(ws, cfg, own_pid=4242)
    assert a_rect == ASSESSMENT["rect"]
    assert [w.hwnd for w in cands] == [5], "taskbar, tiny popups, the agent's own window and the assessment are skipped"


def test_window_monitor_stability_baseline_and_context(cfg):
    pre = win(10, rect=(1600, 100, 1900, 400), topmost=True, name="preexisting.exe")
    backend = FakeWindowBackend([win(1, **ASSESSMENT), pre])
    calls = []
    m = WindowMonitor(cfg, on_window=lambda w, c: calls.append((w.hwnd, c)), started_during_session=lambda pid: pid == 777,
                      is_allowlisted=lambda n: n == "nvda.exe", backend_factory=lambda: backend, own_pid=1)
    m.cfg.window_poll_seconds = 0.5
    m.setup(); m.state = "active"
    m.poll()
    assert calls == [], "windows must be stable for 2 polls before evaluation"
    m.poll()
    assert calls[0][0] == 10 and calls[0][1].new_window is False and calls[0][1].assessment == ASSESSMENT["rect"]
    backend.windows.append(win(11, pid=777, topmost=True, rect=(1400, 200, 1800, 600)))
    m.poll(); m.poll()
    ctx11 = [c for h, c in calls if h == 11][0]
    assert ctx11.new_window and ctx11.new_process and not ctx11.allowlisted
    assert m.assessment_window_found
