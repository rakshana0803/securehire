"""Shared fixtures. Windows APIs are replaced by in-memory fakes with the same interfaces,
so these tests run on any OS. Tests that need a real Windows machine are listed in README.md."""
from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.config import AgentConfig  # noqa: E402
from agent.event_client import SecureHireClient  # noqa: E402
from agent.models import UsbDevice, WindowInfo  # noqa: E402


@pytest.fixture
def cfg(tmp_path) -> AgentConfig:
    return AgentConfig(log_dir=str(tmp_path / "logs"), heartbeat_seconds=5, process_poll_seconds=0.5, window_poll_seconds=0.5,
                       usb_reconcile_seconds=0.5, retry_base_seconds=0.01, retry_max_seconds=0.05, api_timeout_seconds=2).validate()


class FakeClock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


# --------------------------------------------------------------------------- USB
def usb(key: str, category: str, vid="046D", pid="C52B", service=None, cls=None) -> UsbDevice:
    return UsbDevice(instance_key=key, category=category, vendor_id=vid, product_id=pid, service=service, device_class=cls)


class FakeUsbBackend:
    def __init__(self, devices: dict[str, UsbDevice] | None = None):
        self.devices = dict(devices or {})
        self.changed = threading.Event()
        self.closed = False
        self.snapshots = 0

    def snapshot(self):
        self.snapshots += 1
        return dict(self.devices)

    def plug(self, d: UsbDevice):
        self.devices[d.instance_key] = d
        self.changed.set()

    def unplug(self, key: str):
        self.devices.pop(key, None)
        self.changed.set()

    def wait_for_change(self, timeout: float) -> bool:
        fired = self.changed.wait(timeout)
        self.changed.clear()
        return fired

    def close(self):
        self.closed = True
        self.changed.set()


# --------------------------------------------------------------------------- windows
def win(hwnd: int, rect=(1500, 100, 1800, 400), pid=500, name="helper.exe", cls="HelperWnd", **kw) -> WindowInfo:
    return WindowInfo(hwnd=hwnd, pid=pid, process_name=name, class_name=cls, rect=rect, **kw)


ASSESSMENT = dict(rect=(0, 0, 1920, 1040), pid=10, name="chrome.exe", cls="Chrome_WidgetWin_1", is_assessment_window=True)


class FakeWindowBackend:
    def __init__(self, windows: list[WindowInfo] | None = None):
        self.windows = list(windows or [])

    def list_windows(self):
        return list(self.windows)

    def screen_rect_for(self, rect):
        return (0, 0, 1920, 1080)


# --------------------------------------------------------------------------- fake SecureHire API (httpx MockTransport)
class FakeSecureHire:
    """Minimal in-memory imitation of the /api/agent/* endpoints used by the client."""

    def __init__(self, session_id="AS-TEST01", token="t" * 43, status="active"):
        self.session_id, self.token, self.status = session_id, token, status
        self.events: dict[str, dict] = {}
        self.heartbeats: list[dict] = []
        self.fail_mode: str | None = None       # None | "network" | "500" | "429"
        self.fail_count = 0                     # how many requests to fail (then recover)
        self.requests = 0
        now = datetime.now(timezone.utc)
        self.started = now.isoformat()
        self.expires = (now + timedelta(hours=1)).isoformat()

    def _fail(self):
        if self.fail_mode and self.fail_count != 0:
            self.fail_count -= 1
            if self.fail_mode == "network":
                raise httpx.ConnectError("connection refused")
            return httpx.Response(int(self.fail_mode), json={"error": "temporarily unavailable"})
        return None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        failure = self._fail()
        if failure is not None:
            return failure
        if request.headers.get("authorization") != f"Bearer {self.token}":
            return httpx.Response(401, json={"error": "Invalid agent token or session."})
        path = request.url.path
        if path == "/api/agent/session":
            return httpx.Response(200, json={"sessionId": self.session_id, "status": self.status, "startedAt": self.started,
                                             "expiresAt": self.expires, "assessmentTitle": "Test assessment"})
        body = json.loads(request.content or b"{}")
        if path == "/api/agent/heartbeat":
            if self.status != "active":
                return httpx.Response(409, json={"error": "Session is not active."})
            self.heartbeats.append(body)
            return httpx.Response(200, json={"ok": True})
        if path == "/api/agent/events":
            results = []
            for e in body["events"]:
                k = e["idempotencyKey"]
                if e.get("eventType") == "BOGUS":
                    results.append({"idempotencyKey": k, "error": "not allowed"})
                elif k in self.events:
                    results.append({"idempotencyKey": k, "inserted": False, "duplicate": True})
                else:
                    self.events[k] = e
                    results.append({"idempotencyKey": k, "inserted": True, "duplicate": False})
            return httpx.Response(200, json={"results": results})
        return httpx.Response(404, json={"error": "Not found"})


@pytest.fixture
def fake_api() -> FakeSecureHire:
    return FakeSecureHire()


@pytest.fixture
def make_client(cfg, fake_api):
    def _make(token=None, session_id=None):
        return SecureHireClient(cfg, "http://127.0.0.1:4000", session_id or fake_api.session_id, token or fake_api.token,
                                transport=httpx.MockTransport(fake_api.handler))
    return _make
