"""Newly launched application monitoring.

Polls the process list (psutil → CreateToolhelp32Snapshot / NtQuerySystemInformation on Windows)
at a configurable interval and reports processes that *started after the assessment began*.

Collected per process: executable name, PID and start time. Never collected: command-line
arguments, window contents, keystrokes, files, environment variables or other users' processes.
Processes are never terminated, suspended or modified.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Callable, Iterable, Optional, Protocol

from .models import ProcessInfo
from .monitor_base import HealthCallback, Monitor

log = logging.getLogger("securehire.process")


class ProcessBackend(Protocol):
    def list_processes(self) -> Iterable[ProcessInfo]: ...


class PsutilBackend:
    """Lists processes of the current user only (other users' processes are not inspected)."""

    def __init__(self) -> None:
        import psutil
        self._psutil = psutil
        try:
            self._user = psutil.Process(os.getpid()).username()
        except Exception:  # noqa: BLE001
            self._user = None

    def list_processes(self) -> Iterable[ProcessInfo]:
        ps = self._psutil
        for p in ps.process_iter(["pid", "name", "create_time", "username"]):
            info = p.info
            if not info.get("name") or info.get("create_time") is None:
                continue
            if self._user and info.get("username") and info["username"] != self._user:
                continue
            yield ProcessInfo(pid=info["pid"], name=info["name"], create_time=float(info["create_time"]))


def find_new_processes(known: set[tuple[int, float]], current: list[ProcessInfo], session_start: float,
                       excluded_pids: set[int]) -> list[ProcessInfo]:
    """Processes not seen before that started at/after the session start. Pure function.

    (pid, create_time) pairs are used so a recycled PID is still recognised as a new process.
    """
    out = []
    for p in current:
        key = (p.pid, round(p.create_time, 3))
        if key in known or p.pid in excluded_pids:
            continue
        if p.create_time + 1.0 < session_start:
            continue
        out.append(p)
    return sorted(out, key=lambda p: p.create_time)


class ProcessMonitor(Monitor):
    name = "process"

    def __init__(self, on_started: Callable[[ProcessInfo], None], poll_seconds: float = 2.0,
                 backend_factory: Callable[[], ProcessBackend] = PsutilBackend, on_health: Optional[HealthCallback] = None,
                 clock: Callable[[], float] = time.time):
        super().__init__(on_health)
        self._on_started = on_started
        self._poll = poll_seconds
        self._factory = backend_factory
        self._backend: Optional[ProcessBackend] = None
        self._clock = clock
        self._known: set[tuple[int, float]] = set()
        self._session_start = 0.0
        self._own = {os.getpid()}
        self.baseline_names: set[str] = set()

    def setup(self) -> None:
        if self._backend is None:
            self._backend = self._factory()
            self._session_start = self._clock()
            baseline = list(self._backend.list_processes())
            self._known = {(p.pid, round(p.create_time, 3)) for p in baseline}
            # Applications already running when the assessment started (e.g. the browser itself)
            # spawn helper processes constantly; their new instances are not reported.
            self.baseline_names = {p.name.lower() for p in baseline}
            log.info("Process baseline: %d processes", len(baseline))

    def poll(self) -> None:
        assert self._backend is not None
        current = list(self._backend.list_processes())
        for p in find_new_processes(self._known, current, self._session_start, self._own):
            if p.name.lower() not in self.baseline_names:
                self._on_started(p)
        # Forget exited processes so memory stays bounded.
        self._known = {(p.pid, round(p.create_time, 3)) for p in current}

    def wait(self) -> None:
        self._stop.wait(self._poll)

    def pid_started_during_session(self, pid: int) -> bool:
        """Used by the window monitor: does this PID belong to a process that started after the assessment began?"""
        try:
            import psutil
            return psutil.Process(pid).create_time() + 1.0 >= self._session_start > 0
        except Exception:  # noqa: BLE001
            return False
