"""USB connection / disconnection monitoring.

How it works on Windows (see ``win32_usb.py``):
  * A hidden message-only window registers for ``WM_DEVICECHANGE`` notifications
    (``RegisterDeviceNotificationW`` with the USB device interface class), so arrivals and
    removals wake the monitor immediately.
  * The monitor then takes a SetupAPI snapshot of present USB devices and diffs it with the
    previous snapshot. The diff is the source of truth: it de-duplicates the several
    notifications Windows sends per device, and a periodic reconcile catches anything missed.
  * Devices already connected when the assessment starts form the baseline and are not reported.

Privacy: only the device category, USB vendor/product IDs, Windows class/service names and a
salted per-session hash of the instance ID are reported. The agent never opens, mounts, lists,
reads, copies or modifies anything on a device, and never disables one.
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Callable, Optional, Protocol

from .models import UsbChange, UsbDevice, utcnow
from .monitor_base import HealthCallback, Monitor

log = logging.getLogger("securehire.usb")

_VIDPID = re.compile(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)

STORAGE_SERVICES = {"usbstor", "uaspstor"}
HUB_SERVICES = {"usbhub", "usbhub3", "usbhub3_ucx", "usbxhci", "usbehci", "usbohci", "usbuhci"}
HID_SERVICES = {"hidusb"}
CAMERA_SERVICES = {"usbvideo"}
AUDIO_SERVICES = {"usbaudio", "usbaudio2"}
PORTABLE_CLASSES = {"wpd", "apple mobile device usb driver"}


def parse_vid_pid(instance_id: str) -> tuple[Optional[str], Optional[str]]:
    m = _VIDPID.search(instance_id or "")
    return (m.group(1).upper(), m.group(2).upper()) if m else (None, None)


def classify_usb_device(service: Optional[str], device_class: Optional[str], instance_id: str,
                        hid_vidpids: set[tuple[str, str]] = frozenset(), camera_vidpids: set[tuple[str, str]] = frozenset(),
                        storage_vidpids: set[tuple[str, str]] = frozenset(),
                        portable_vidpids: set[tuple[str, str]] = frozenset()) -> Optional[str]:
    """Map Windows driver metadata to a coarse category. Returns None for hubs/host controllers (not reported)."""
    svc = (service or "").lower()
    cls = (device_class or "").lower()
    iid = (instance_id or "").upper()
    if svc in HUB_SERVICES or "ROOT_HUB" in iid:
        return None
    if svc in STORAGE_SERVICES or cls == "diskdrive":
        return "storage"
    if cls in PORTABLE_CLASSES:
        return "portable_device"
    if svc in HID_SERVICES or cls in ("hidclass", "keyboard", "mouse"):
        return "input"
    if svc in CAMERA_SERVICES or cls in ("camera", "image"):
        return "camera"
    if svc in AUDIO_SERVICES or cls == "media":
        return "audio"
    vp = parse_vid_pid(iid)
    if svc == "usbccgp":  # composite device: classify by its child interfaces
        if vp in storage_vidpids: return "storage"
        if vp in portable_vidpids: return "portable_device"
        if vp in camera_vidpids: return "camera"
        if vp in hid_vidpids: return "input"
        return "composite"
    return "other"


def diff_snapshots(prev: dict[str, UsbDevice], curr: dict[str, UsbDevice]) -> list[UsbChange]:
    """Connected = present now but not before; disconnected = the reverse. Pure function."""
    at = utcnow()
    changes = [UsbChange("disconnected", prev[k], at) for k in prev.keys() - curr.keys()]
    changes += [UsbChange("connected", curr[k], at) for k in curr.keys() - prev.keys()]
    return sorted(changes, key=lambda c: (c.kind != "disconnected", c.device.instance_key))


class UsbBackend(Protocol):
    def snapshot(self) -> dict[str, UsbDevice]: ...
    def wait_for_change(self, timeout: float) -> bool: ...
    def close(self) -> None: ...


def default_backend() -> Optional[UsbBackend]:
    if sys.platform != "win32":
        return None
    from .win32_usb import WindowsUsbBackend
    return WindowsUsbBackend()


class UsbMonitor(Monitor):
    name = "usb"

    def __init__(self, on_change: Callable[[UsbChange], None], reconcile_seconds: float = 5.0,
                 backend_factory: Callable[[], Optional[UsbBackend]] = default_backend, on_health: Optional[HealthCallback] = None):
        super().__init__(on_health)
        self._on_change = on_change
        self._reconcile = reconcile_seconds
        self._factory = backend_factory
        self._backend: Optional[UsbBackend] = None
        self._known: dict[str, UsbDevice] = {}
        self.baseline_count = 0

    def supported(self) -> tuple[bool, str]:
        if self._factory is default_backend and sys.platform != "win32":
            return False, "USB monitoring requires Windows."
        return True, ""

    def setup(self) -> None:
        if self._backend is None:
            self._backend = self._factory()
            if self._backend is None:
                raise RuntimeError("No USB backend available on this platform.")
            # Baseline: devices present when monitoring starts are "already connected", never reported.
            self._known = self._backend.snapshot()
            self.baseline_count = len(self._known)
            log.info("USB baseline: %d device(s) already connected", self.baseline_count)
        else:
            # Recovering from an error: reconcile silently against the last known state.
            pass

    def poll(self) -> None:
        assert self._backend is not None
        current = self._backend.snapshot()
        for change in diff_snapshots(self._known, current):
            self._on_change(change)
        self._known = current

    def wait(self) -> None:
        if self._backend is not None:
            self._backend.wait_for_change(self._reconcile)  # returns early on a device notification
        if self.stopping:
            return

    def stop(self, timeout: float = 5.0) -> None:
        b = self._backend
        if b is not None:
            try:
                b.close()  # also wakes wait_for_change
            except Exception:  # noqa: BLE001
                log.exception("USB backend close failed")
        super().stop(timeout)
        self._backend = None
