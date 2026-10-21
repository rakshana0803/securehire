"""Potentially suspicious floating-window detection (metadata only — no screenshots, no window contents).

Every ``window_poll_seconds`` the visible top-level windows are enumerated (``win32_windows.py``).
For each window the agent looks at observable properties — owning process, size, position,
always-on-top, layered/transparent styles, capture exclusion — and whether it overlaps the
assessment browser window. The rules engine then combines these signals; no single property
(size, title, process name, always-on-top) is ever enough to raise a review item.

Known limits (documented in README): overlays drawn *inside* the browser by an extension, DirectX/
game-overlay hooks drawn into another process's swap chain, second devices, and windows on other
virtual desktops are not visible to this metadata-based approach.
"""
from __future__ import annotations

import logging
import sys
from typing import Callable, Optional, Protocol

from .config import AgentConfig
from .models import Rect, WindowInfo
from .monitor_base import HealthCallback, Monitor
from .rules_engine import WindowContext

log = logging.getLogger("securehire.window")


class WindowBackend(Protocol):
    def list_windows(self) -> list[WindowInfo]: ...
    def screen_rect_for(self, rect: Rect) -> Rect: ...


def default_backend() -> Optional[WindowBackend]:
    if sys.platform != "win32":
        return None
    from .win32_windows import WindowsWindowBackend
    return WindowsWindowBackend()


def split_windows(windows: list[WindowInfo], cfg: AgentConfig, own_pid: int) -> tuple[Optional[Rect], list[WindowInfo]]:
    """Return (assessment window rect, candidate windows worth evaluating). Pure function."""
    ignored = set(cfg.ignored_window_classes)
    assessment = [w for w in windows if w.is_assessment_window]
    a_rect = max(assessment, key=lambda w: w.area).rect if assessment else None
    candidates = [w for w in windows
                  if not w.is_assessment_window and w.pid != own_pid and w.class_name not in ignored
                  and w.width >= cfg.min_window_width and w.height >= cfg.min_window_height]
    return a_rect, candidates


class WindowMonitor(Monitor):
    name = "window"

    def __init__(self, cfg: AgentConfig, on_window: Callable[[WindowInfo, WindowContext], None],
                 started_during_session: Callable[[int], bool], is_allowlisted: Callable[[str], bool],
                 backend_factory: Callable[[], Optional[WindowBackend]] = default_backend,
                 on_health: Optional[HealthCallback] = None, own_pid: Optional[int] = None):
        super().__init__(on_health)
        import os
        self.cfg = cfg
        self._on_window = on_window
        self._started_during_session = started_during_session
        self._is_allowlisted = is_allowlisted
        self._factory = backend_factory
        self._backend: Optional[WindowBackend] = None
        self._own_pid = own_pid if own_pid is not None else os.getpid()
        self._baseline: set[int] = set()
        self._seen: dict[int, int] = {}
        self._new_proc_cache: dict[int, bool] = {}
        self.assessment_window_found = False

    def supported(self) -> tuple[bool, str]:
        if self._factory is default_backend and sys.platform != "win32":
            return False, "Window monitoring requires Windows."
        return True, ""

    def setup(self) -> None:
        if self._backend is None:
            self._backend = self._factory()
            if self._backend is None:
                raise RuntimeError("No window backend available on this platform.")
            _, candidates = split_windows(self._backend.list_windows(), self.cfg, self._own_pid)
            self._baseline = {w.hwnd for w in candidates}
            log.info("Window baseline: %d visible top-level windows", len(self._baseline))

    def _new_process(self, pid: int) -> bool:
        if pid not in self._new_proc_cache:
            if len(self._new_proc_cache) > 2000:
                self._new_proc_cache.clear()
            self._new_proc_cache[pid] = self._started_during_session(pid)
        return self._new_proc_cache[pid]

    def poll(self) -> None:
        assert self._backend is not None
        a_rect, candidates = split_windows(self._backend.list_windows(), self.cfg, self._own_pid)
        self.assessment_window_found = a_rect is not None
        present = set()
        for w in candidates:
            present.add(w.hwnd)
            self._seen[w.hwnd] = self._seen.get(w.hwnd, 0) + 1
            # Transient popups (tooltips, menus, toasts) vanish before they become stable.
            if self._seen[w.hwnd] < self.cfg.window_stable_polls:
                continue
            ctx = WindowContext(
                screen=self._backend.screen_rect_for(w.rect), assessment=a_rect,
                new_process=self._new_process(w.pid), new_window=w.hwnd not in self._baseline,
                allowlisted=self._is_allowlisted(w.process_name),
            )
            self._on_window(w, ctx)
        for gone in set(self._seen) - present:
            del self._seen[gone]

    def wait(self) -> None:
        self._stop.wait(self.cfg.window_poll_seconds)
