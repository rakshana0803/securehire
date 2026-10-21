"""Common lifecycle for the USB, process and window monitors.

Each monitor runs in its own daemon thread only while an assessment session is active.
Errors never crash the agent: the monitor reports ``error``, backs off and retries, and
reports ``active`` again once it recovers — both transitions are surfaced transparently.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

log = logging.getLogger("securehire.monitor")

HealthCallback = Callable[[str, str, Optional[str]], None]  # (monitor name, state, error message)


class Monitor:
    name = "monitor"

    def __init__(self, on_health: Optional[HealthCallback] = None):
        self.state = "stopped"          # stopped | starting | active | error | unsupported | disabled
        self.last_error: Optional[str] = None
        self._on_health = on_health or (lambda *_: None)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ---- to implement
    def supported(self) -> tuple[bool, str]:
        return True, ""

    def setup(self) -> None:
        """Take the baseline (things already present when the assessment starts)."""

    def poll(self) -> None:
        """One unit of work. Called repeatedly until stop()."""

    def wait(self) -> None:
        """Block until the next poll is due (or stop() is called)."""
        self._stop.wait(1.0)

    def teardown(self) -> None:
        """Release OS resources."""

    # ---- lifecycle
    def _set(self, state: str, error: Optional[str] = None) -> None:
        changed = state != self.state
        self.state, self.last_error = state, error
        if changed:
            self._on_health(self.name, state, error)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        ok, why = self.supported()
        if not ok:
            self._set("unsupported", why)
            return
        self._stop.clear()
        self._set("starting")
        self._thread = threading.Thread(target=self._run, name=f"securehire-{self.name}", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout)
        self._thread = None
        if self.state not in ("unsupported", "disabled"):
            self._set("stopped")

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def _run(self) -> None:
        backoff = 2.0
        try:
            while not self._stop.is_set():
                try:
                    if self.state in ("starting", "error"):
                        self.setup()
                        self._set("active")
                        backoff = 2.0
                    self.poll()
                    self.wait()
                except Exception as e:  # noqa: BLE001 — a monitor must never take the agent down
                    log.exception("%s monitor error", self.name)
                    self._set("error", str(e)[:200])
                    self._stop.wait(backoff)
                    backoff = min(60.0, backoff * 2)
        finally:
            try:
                self.teardown()
            except Exception:  # noqa: BLE001
                log.exception("%s teardown failed", self.name)
