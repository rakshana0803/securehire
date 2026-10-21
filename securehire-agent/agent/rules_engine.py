"""Explainable, rule-based classification and correlation of desktop observations.

Every output is an *observation* with a readable explanation and a review priority:
  * ``info``   — recorded for context; never needs action on its own.
  * ``review`` — a person should look at it together with other evidence.
There is no score, no probability and no verdict. A single USB device, application or window is
never treated as proof of anything; correlation only raises the review priority.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Deque, Optional

from .config import AgentConfig
from .models import (PRIORITY_INFO, PRIORITY_REVIEW, ProcessInfo, Rect, SecurityEvent, UsbChange, WindowInfo,
                     intersection_area, utcnow)

USB_CATEGORY_LABELS = {
    "storage": "USB storage device (flash drive or external disk)",
    "portable_device": "portable device (phone, tablet or camera in file-transfer mode)",
    "input": "USB input device (keyboard, mouse or similar)",
    "camera": "USB camera",
    "audio": "USB audio device",
    "composite": "multi-function USB device",
    "other": "USB device",
}
STORAGE_CATEGORIES = {"storage", "portable_device"}


def local_clock(dt: datetime) -> str:
    return dt.astimezone().strftime("%H:%M:%S")


# --------------------------------------------------------------------------- window evaluation (pure)
@dataclass(frozen=True)
class WindowContext:
    screen: Rect
    assessment: Optional[Rect]        # None when the assessment window could not be identified
    new_process: bool                 # owner process started during the assessment
    new_window: bool                  # window appeared during the assessment (not present at start)
    allowlisted: bool


@dataclass(frozen=True)
class WindowEvaluation:
    """Result of evaluating one window. ``rule_id`` is None when nothing is worth reporting."""
    signals: tuple[str, ...]
    rule_id: Optional[str]
    event_type: Optional[str]
    priority: Optional[str]
    explanation: str
    details: dict


def _join(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def evaluate_window(w: WindowInfo, ctx: WindowContext, cfg: AgentConfig) -> WindowEvaluation:
    screen_area = max(1, (ctx.screen[2] - ctx.screen[0]) * (ctx.screen[3] - ctx.screen[1]))
    screen_pct = 100.0 * w.area / screen_area
    overlap_pct: Optional[float] = None
    if ctx.assessment:
        a_area = max(1, (ctx.assessment[2] - ctx.assessment[0]) * (ctx.assessment[3] - ctx.assessment[1]))
        # Share of the window that sits on top of the assessment window.
        overlap_pct = 100.0 * intersection_area(w.rect, ctx.assessment) / max(1, w.area) if w.area else 0.0
        # Tiny assessment rect (minimised) makes overlap meaningless.
        if a_area < 10_000:
            overlap_pct = None
    transparent = w.layered and w.alpha is not None and w.alpha <= cfg.transparent_alpha_max

    signals: list[str] = []
    if w.topmost: signals.append("always_on_top")
    if screen_pct <= cfg.small_window_max_screen_percent: signals.append("small")
    if overlap_pct is not None and overlap_pct >= cfg.overlap_min_percent: signals.append("overlaps_assessment")
    if ctx.new_process: signals.append("new_process")
    if ctx.new_window: signals.append("new_window")
    if w.capture_excluded: signals.append("hidden_from_screen_capture")
    if transparent: signals.append("semi_transparent")
    if w.click_through: signals.append("click_through")
    if w.tool_window: signals.append("no_taskbar_button")
    s = set(signals)

    details = {
        "processName": w.process_name[:120], "pid": w.pid, "width": w.width, "height": w.height, "x": w.rect[0], "y": w.rect[1],
        "screenAreaPercent": round(screen_pct, 1), "overlapKnown": overlap_pct is not None, "topmost": w.topmost,
        "layered": w.layered, "clickThrough": w.click_through, "toolWindow": w.tool_window, "noActivate": w.no_activate,
        "captureExcluded": w.capture_excluded, "newProcess": ctx.new_process, "allowlisted": ctx.allowlisted, "signals": signals,
    }
    if overlap_pct is not None: details["overlapPercent"] = round(overlap_pct, 1)
    if w.alpha is not None: details["alpha"] = w.alpha

    name = f"'{w.process_name}'"
    overlap_txt = f"overlapping about {round(overlap_pct)}% of its area with the assessment window" if "overlaps_assessment" in s else None
    origin_txt = "a newly launched application" if ctx.new_process else ("an application already running" if not ctx.new_window else "an application")
    none = WindowEvaluation(tuple(signals), None, None, None, "", details)

    if ctx.allowlisted:
        if w.topmost or w.capture_excluded:
            return WindowEvaluation(tuple(signals), "window.allowlisted", "WINDOW_OBSERVED", PRIORITY_INFO,
                                     f"Always-on-top window from allowlisted application {name}. Allowlisted tools (screen readers, "
                                     f"magnifiers, approved software) are not treated as suspicious.", details)
        return none

    if w.capture_excluded and (w.topmost or "overlaps_assessment" in s):
        where = _join([p for p in ["always on top" if w.topmost else None, overlap_txt] if p])
        return WindowEvaluation(tuple(signals), "window.capture_excluded", "CAPTURE_EXCLUDED_WINDOW", PRIORITY_REVIEW,
                                 f"A window from {name} asks Windows to hide it from screenshots and screen sharing, and it is {where}. "
                                 f"Some legitimate software (password managers, protected video players) does this too. Manual review required.", details)

    if (transparent or w.click_through) and w.topmost and "overlaps_assessment" in s:
        look = _join([p for p in ["semi-transparent" if transparent else None, "click-through" if w.click_through else None] if p])
        return WindowEvaluation(tuple(signals), "window.transparent_overlay", "TRANSPARENT_OVERLAY_SUSPECTED", PRIORITY_REVIEW,
                                 f"Potential overlay activity: a {look}, always-on-top window from {name} is {overlap_txt}. "
                                 f"Manual review required.", details)

    # Four independent signals together: launched during the assessment, always on top, small, over the assessment.
    if w.topmost and "overlaps_assessment" in s and "small" in s and ctx.new_process:
        return WindowEvaluation(tuple(signals), "window.overlay_candidate", "OVERLAY_WINDOW_SUSPECTED", PRIORITY_REVIEW,
                                 f"Potential overlay activity: {origin_txt} ({name}) created a small always-on-top window "
                                 f"{overlap_txt}. Manual review required.", details)

    if w.topmost and (ctx.new_process or ctx.new_window):
        note = "" if ctx.assessment else " Overlap with the assessment window could not be determined."
        where = f", {overlap_txt}" if overlap_txt else ""
        return WindowEvaluation(tuple(signals), "window.topmost_new", "WINDOW_OBSERVED", PRIORITY_INFO,
                                 f"A new always-on-top window from {name} appeared during the assessment "
                                 f"({w.width}×{w.height} px{where}). Many tools use always-on-top windows (video calls, "
                                 f"notifications, media players); recorded for context only.{note}", details)

    if w.topmost and "overlaps_assessment" in s:
        return WindowEvaluation(tuple(signals), "window.topmost_preexisting", "WINDOW_OBSERVED", PRIORITY_INFO,
                                 f"An always-on-top window from {name}, open since before the assessment started, is {overlap_txt}. "
                                 f"Recorded for context only.", details)
    return none


# --------------------------------------------------------------------------- engine
@dataclass
class _Indicator:
    at: float
    category: str
    summary: str
    key: str


class RulesEngine:
    """Thread-safe. Monitors call the ``on_*`` methods; emitted events go to ``sink``."""

    def __init__(self, cfg: AgentConfig, session_id: str, sink: Callable[[SecurityEvent], None],
                 salt: bytes, clock: Callable[[], float] = time.monotonic):
        self.cfg = cfg
        self.session_id = session_id
        self.sink = sink
        self._salt = salt
        self._clock = clock
        self._lock = threading.RLock()
        self._last_emitted: dict[str, float] = {}
        self._indicators: Deque[_Indicator] = deque(maxlen=200)
        self._browser_focus_losses: Deque[float] = deque(maxlen=200)
        self._last_correlation: Optional[float] = None
        self._reported_process_names: set[str] = set()

    # ---- helpers
    def device_id(self, instance_key: str) -> str:
        """Per-session salted hash: lets a reviewer match connect/disconnect pairs, but cannot identify the device elsewhere."""
        return "h:" + hmac.new(self._salt, instance_key.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]

    def _dedupe(self, key: str, cooldown: Optional[float] = None) -> bool:
        """True when this key was already emitted within the cooldown (and should be skipped)."""
        now = self._clock()
        last = self._last_emitted.get(key)
        if last is not None and now - last < (self.cfg.dedupe_cooldown_seconds if cooldown is None else cooldown):
            return True
        self._last_emitted[key] = now
        if len(self._last_emitted) > 5000:  # bounded memory
            cutoff = now - 3600
            self._last_emitted = {k: v for k, v in self._last_emitted.items() if v > cutoff}
        return False

    def _emit(self, ev: SecurityEvent) -> SecurityEvent:
        self.sink(ev)
        return ev

    def _indicator(self, category: str, summary: str, key: str) -> list[SecurityEvent]:
        now = self._clock()
        self._indicators.append(_Indicator(now, category, summary, key))
        window = self.cfg.correlation_window_seconds
        recent = [i for i in self._indicators if now - i.at <= window]
        categories = {i.category for i in recent}
        if len(categories) < self.cfg.correlation_min_categories:
            return []
        if self._last_correlation is not None and now - self._last_correlation < self.cfg.correlation_cooldown_seconds:
            return []
        self._last_correlation = now
        first_per_cat: dict[str, _Indicator] = {}
        for i in recent:
            first_per_cat.setdefault(i.category, i)
        parts = [i.summary for i in sorted(first_per_cat.values(), key=lambda x: x.at)]
        focus = sum(1 for t in self._browser_focus_losses if now - t <= window)
        focus_txt = f" The assessment tab also lost focus {focus} time(s) in this period." if focus else ""
        ev = SecurityEvent(
            category="correlation", event_type="CORRELATED_ACTIVITY", priority=PRIORITY_REVIEW, rule_id="correlation.multi_indicator",
            explanation=(f"Several independent indicators occurred within {int(window)} seconds: {_join(parts)}.{focus_txt} "
                         f"Each may have an innocent explanation; together they warrant a manual review."),
            details={"categories": sorted(categories), "relatedEventKeys": [i.key for i in recent][-12:],
                     "windowSeconds": int(window), "indicatorCount": len(recent)},
        )
        return [self._emit(ev)]

    # ---- USB
    def on_usb_change(self, change: UsbChange) -> list[SecurityEvent]:
        with self._lock:
            d = change.device
            is_storage = d.category in STORAGE_CATEGORIES
            if not is_storage and not self.cfg.usb_report_peripherals:
                return []
            dev_id = self.device_id(d.instance_key)
            if self._dedupe(f"usb:{change.kind}:{dev_id}"):
                return []
            label = USB_CATEGORY_LABELS.get(d.category, "USB device")
            connected = change.kind == "connected"
            review = connected and is_storage and self.cfg.usb_storage_review
            when = local_clock(change.at)
            if connected and is_storage:
                expl = (f"A {label} was connected at {when}. The agent does not read or list its contents. "
                        f"{'Storage devices are flagged for review under the assessment policy; ' if review else ''}"
                        f"connecting one is not evidence that it was used.")
                rule = "usb.storage_connected"
            elif connected:
                expl = f"A {label} was connected at {when}. Peripherals like this are recorded for context only."
                rule = "usb.peripheral_connected"
            else:
                expl = f"A {label} was disconnected at {when}."
                rule = "usb.disconnected"
            ev = SecurityEvent(
                category="usb", event_type="USB_DEVICE_CONNECTED" if connected else "USB_DEVICE_DISCONNECTED",
                priority=PRIORITY_REVIEW if review else PRIORITY_INFO, rule_id=rule, explanation=expl, timestamp=change.at,
                details={"deviceCategory": d.category, "deviceId": dev_id, "vendorId": d.vendor_id, "productId": d.product_id,
                         "deviceClass": d.device_class, "service": d.service, "storageRule": review},
            )
            out = [self._emit(ev)]
            if connected and is_storage:
                out += self._indicator("usb", f"a {label} was connected ({when})", ev.idempotency_key)
            return out

    # ---- processes
    def is_allowlisted(self, process_name: str) -> bool:
        return process_name.lower() in self.cfg.allowlisted_processes

    def on_process_started(self, proc: ProcessInfo, at: Optional[datetime] = None) -> list[SecurityEvent]:
        with self._lock:
            name = proc.name.lower()
            if name in self.cfg.trusted_system_processes:
                return []
            if self.cfg.process_report_once_per_name:
                if name in self._reported_process_names:
                    return []
                self._reported_process_names.add(name)
            elif self._dedupe(f"proc:{name}"):
                return []
            allow = self.is_allowlisted(name)
            when = local_clock(at or utcnow())
            expl = (f"Allowlisted application '{proc.name}' started at {when}." if allow else
                    f"Application '{proc.name}' started at {when}, after the assessment began. Starting an application is "
                    f"recorded as an observation only.")
            ev = SecurityEvent(category="process", event_type="PROCESS_STARTED", priority=PRIORITY_INFO,
                               rule_id="process.allowlisted" if allow else "process.new_application", explanation=expl,
                               timestamp=at or utcnow(), details={"processName": proc.name[:120], "pid": proc.pid, "allowlisted": allow})
            out = [self._emit(ev)]
            if not allow:
                out += self._indicator("process", f"application '{proc.name}' started ({when})", ev.idempotency_key)
            return out

    # ---- windows
    def on_window(self, w: WindowInfo, ctx: WindowContext) -> list[SecurityEvent]:
        with self._lock:
            r = evaluate_window(w, ctx, self.cfg)
            if not r.rule_id:
                return []
            # Report each rule once per window; a window that escalates to a different rule is reported again.
            if self._dedupe(f"win:{w.hwnd}:{r.rule_id}", cooldown=10 ** 9):
                return []
            ev = SecurityEvent(category="window", event_type=r.event_type or "WINDOW_OBSERVED", priority=r.priority or PRIORITY_INFO,
                               rule_id=r.rule_id, explanation=r.explanation, details=r.details)
            out = [self._emit(ev)]
            if ev.priority == PRIORITY_REVIEW:
                out += self._indicator("window", f"a potential overlay window from '{w.process_name}' appeared ({local_clock(ev.timestamp)})", ev.idempotency_key)
            return out

    # ---- browser context (from the extension)
    def on_browser_event(self, event_type: str) -> None:
        with self._lock:
            if event_type in ("TAB_HIDDEN", "WINDOW_BLUR", "TAB_SWITCH", "FULLSCREEN_EXIT"):
                self._browser_focus_losses.append(self._clock())

    # ---- agent health
    def agent_event(self, event_type: str, explanation: str, priority: str = PRIORITY_INFO, **details) -> SecurityEvent:
        with self._lock:
            ev = SecurityEvent(category="agent", event_type=event_type, priority=priority, rule_id=f"agent.{event_type.lower()}",
                               explanation=explanation, details={k: v for k, v in details.items() if v is not None})
            return self._emit(ev)
