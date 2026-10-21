"""Windows top-level window metadata backend (ctypes, no admin rights).

Documented APIs used: EnumWindows, IsWindowVisible, IsIconic, GetWindowRect, GetWindowLongPtrW
(GWL_EXSTYLE), GetClassNameW, GetWindowTextW (browser windows only, to recognise the assessment
tab; the title is discarded immediately), GetWindowThreadProcessId, GetLayeredWindowAttributes,
GetWindowDisplayAffinity, DwmGetWindowAttribute(DWMWA_CLOAKED), MonitorFromRect, GetMonitorInfoW,
SetProcessDpiAwarenessContext.

No screenshots are taken and no window contents are read.

REQUIRES A REAL WINDOWS MACHINE — not exercised by the automated tests (they use a fake backend).
"""
from __future__ import annotations

import ctypes
import logging
from ctypes import wintypes
from typing import Optional

import psutil

from .models import Rect, WindowInfo

log = logging.getLogger("securehire.window.win32")

user32 = ctypes.WinDLL("user32", use_last_error=True)
dwmapi = ctypes.WinDLL("dwmapi")

GWL_EXSTYLE = -20
WS_EX_TOPMOST = 0x00000008
WS_EX_TRANSPARENT = 0x00000020
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000
LWA_ALPHA = 0x2
WDA_NONE = 0x0
DWMWA_CLOAKED = 14
MONITOR_DEFAULTTONEAREST = 2

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


class MONITORINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT), ("rcWork", wintypes.RECT), ("dwFlags", wintypes.DWORD)]


user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsIconic.argtypes = [wintypes.HWND]
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetLayeredWindowAttributes.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowDisplayAffinity.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.MonitorFromRect.argtypes = [ctypes.POINTER(wintypes.RECT), wintypes.DWORD]
user32.MonitorFromRect.restype = wintypes.HMONITOR
user32.GetMonitorInfoW.argtypes = [wintypes.HMONITOR, ctypes.POINTER(MONITORINFO)]
dwmapi.DwmGetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]

_get_long = getattr(user32, "GetWindowLongPtrW", None) or user32.GetWindowLongW
_get_long.argtypes = [wintypes.HWND, ctypes.c_int]
_get_long.restype = ctypes.c_ssize_t


def enable_dpi_awareness() -> None:
    """Use physical pixels so window and monitor rectangles are comparable on scaled displays."""
    try:
        user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))  # PER_MONITOR_AWARE_V2
    except (AttributeError, OSError):
        try:
            ctypes.WinDLL("shcore").SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            log.info("DPI awareness could not be set; overlap calculations may be approximate on scaled displays")


class WindowsWindowBackend:
    def __init__(self, title_marker: str = "SecureHire", browser_names: Optional[list[str]] = None):
        enable_dpi_awareness()
        self._marker = title_marker.lower()
        self._browsers = {b.lower() for b in (browser_names or ["chrome.exe", "msedge.exe"])}
        self._names: dict[int, str] = {}

    def configure(self, title_marker: str, browser_names: list[str]) -> None:
        self._marker = title_marker.lower()
        self._browsers = {b.lower() for b in browser_names}

    def _process_name(self, pid: int) -> str:
        name = self._names.get(pid)
        if name is None:
            try:
                name = psutil.Process(pid).name()
            except (psutil.Error, OSError):
                name = "unknown"
            if len(self._names) > 2000:
                self._names.clear()
            self._names[pid] = name
        return name

    def _info(self, hwnd: int) -> Optional[WindowInfo]:
        if not user32.IsWindowVisible(hwnd) or user32.IsIconic(hwnd):
            return None
        cloaked = wintypes.DWORD(0)
        if dwmapi.DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) == 0 and cloaked.value:
            return None  # suspended UWP app or a window on another virtual desktop
        r = wintypes.RECT()
        if not user32.GetWindowRect(hwnd, ctypes.byref(r)):
            return None
        cls_buf = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, cls_buf, 256)
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        ex = _get_long(hwnd, GWL_EXSTYLE)
        layered = bool(ex & WS_EX_LAYERED)
        alpha = None
        if layered:
            key, a, flags = wintypes.DWORD(), ctypes.c_ubyte(), wintypes.DWORD()
            if user32.GetLayeredWindowAttributes(hwnd, ctypes.byref(key), ctypes.byref(a), ctypes.byref(flags)) and flags.value & LWA_ALPHA:
                alpha = int(a.value)
        affinity = wintypes.DWORD(WDA_NONE)
        capture_excluded = bool(user32.GetWindowDisplayAffinity(hwnd, ctypes.byref(affinity)) and affinity.value != WDA_NONE)
        name = self._process_name(pid.value)
        is_assessment = False
        if name.lower() in self._browsers:
            # Read the title only to recognise the SecureHire assessment tab; it is not stored or sent.
            t = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, t, 512)
            is_assessment = self._marker in t.value.lower()
        return WindowInfo(
            hwnd=int(hwnd), pid=int(pid.value), process_name=name, class_name=cls_buf.value, rect=(r.left, r.top, r.right, r.bottom),
            topmost=bool(ex & WS_EX_TOPMOST), layered=layered, alpha=alpha, click_through=bool(ex & WS_EX_TRANSPARENT),
            tool_window=bool(ex & WS_EX_TOOLWINDOW), no_activate=bool(ex & WS_EX_NOACTIVATE), capture_excluded=capture_excluded,
            is_assessment_window=is_assessment,
        )

    def list_windows(self) -> list[WindowInfo]:
        hwnds: list[int] = []

        @WNDENUMPROC
        def collect(hwnd, _lparam):
            hwnds.append(hwnd)
            return True

        user32.EnumWindows(collect, 0)
        out = []
        for h in hwnds:
            try:
                info = self._info(h)
            except OSError:
                info = None  # the window closed while we were reading it
            if info:
                out.append(info)
        return out

    def screen_rect_for(self, rect: Rect) -> Rect:
        r = wintypes.RECT(*rect)
        mon = user32.MonitorFromRect(ctypes.byref(r), MONITOR_DEFAULTTONEAREST)
        mi = MONITORINFO()
        mi.cbSize = ctypes.sizeof(MONITORINFO)
        if mon and user32.GetMonitorInfoW(mon, ctypes.byref(mi)):
            m = mi.rcMonitor
            return (m.left, m.top, m.right, m.bottom)
        return (0, 0, 1920, 1080)
