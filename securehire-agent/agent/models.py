"""Plain data types shared by the monitors, the rules engine and the event client."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Tuple


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- USB
@dataclass(frozen=True)
class UsbDevice:
    """One physical USB device as seen by Windows.

    ``instance_key`` is the Windows device instance ID. It stays on this computer: only a salted,
    per-session hash of it (``deviceId``) is ever sent to SecureHire.
    """
    instance_key: str
    category: str                  # storage | portable_device | input | camera | audio | composite | other
    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    device_class: Optional[str] = None   # Windows setup class, e.g. "HIDClass", "DiskDrive"
    service: Optional[str] = None        # Windows driver service, e.g. "USBSTOR", "HidUsb"


@dataclass(frozen=True)
class UsbChange:
    kind: str                      # "connected" | "disconnected"
    device: UsbDevice
    at: datetime


# --------------------------------------------------------------------------- processes
@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    create_time: float             # seconds since the epoch


# --------------------------------------------------------------------------- windows
Rect = Tuple[int, int, int, int]   # left, top, right, bottom (physical pixels)


@dataclass(frozen=True)
class WindowInfo:
    """Metadata of one visible top-level window. Titles are never stored here.

    ``is_assessment_window`` is computed locally by checking whether a browser window's title
    contains the SecureHire marker; the title itself is discarded immediately.
    """
    hwnd: int
    pid: int
    process_name: str
    class_name: str                # local-only, used to skip shell UI (taskbar, menus, tooltips)
    rect: Rect
    topmost: bool = False
    layered: bool = False
    alpha: Optional[int] = None    # 0–255 when the window uses a constant layered alpha
    click_through: bool = False    # WS_EX_TRANSPARENT
    tool_window: bool = False      # WS_EX_TOOLWINDOW (no taskbar button)
    no_activate: bool = False      # WS_EX_NOACTIVATE
    capture_excluded: bool = False # SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE / WDA_MONITOR)
    is_assessment_window: bool = False

    @property
    def width(self) -> int:
        return max(0, self.rect[2] - self.rect[0])

    @property
    def height(self) -> int:
        return max(0, self.rect[3] - self.rect[1])

    @property
    def area(self) -> int:
        return self.width * self.height


def intersection_area(a: Rect, b: Rect) -> int:
    w = min(a[2], b[2]) - max(a[0], b[0])
    h = min(a[3], b[3]) - max(a[1], b[1])
    return w * h if w > 0 and h > 0 else 0


# --------------------------------------------------------------------------- events
PRIORITY_INFO = "info"
PRIORITY_REVIEW = "review"


@dataclass
class SecurityEvent:
    """An explainable observation. ``priority`` is "info" or "review" — never a verdict."""
    category: str                  # usb | process | window | correlation | agent
    event_type: str
    priority: str
    rule_id: str
    explanation: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=utcnow)
    idempotency_key: str = field(default_factory=lambda: f"agt-{uuid.uuid4()}")
    local_id: int = 0              # sequence number for the local /events feed

    def to_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "eventType": self.event_type,
            "priority": self.priority,
            "ruleId": self.rule_id,
            "explanation": self.explanation,
            "details": self.details,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "idempotencyKey": self.idempotency_key,
        }
