"""Rules engine: explainable observations, no verdicts."""
from datetime import datetime, timezone

from agent.models import ProcessInfo, UsbChange
from agent.rules_engine import RulesEngine, WindowContext, evaluate_window
from conftest import ASSESSMENT, usb, win

SCREEN = (0, 0, 1920, 1080)
A_RECT = (0, 0, 1920, 1040)
BANNED_WORDS = ("cheat", "cheating", "fraud", "guilty", "violation", "proof")


def engine(cfg, clock):
    out = []
    return RulesEngine(cfg, "AS-TEST01", sink=out.append, salt=b"s" * 32, clock=clock), out


def ctx(**kw):
    base = dict(screen=SCREEN, assessment=A_RECT, new_process=False, new_window=False, allowlisted=False)
    base.update(kw)
    return WindowContext(**base)


def change(kind, dev):
    return UsbChange(kind, dev, datetime.now(timezone.utc))


def no_accusation(events):
    for e in events:
        low = e.explanation.lower()
        assert not any(w in low for w in BANNED_WORDS), e.explanation


# --------------------------------------------------------------------------- USB
def test_usb_mouse_is_informational_and_never_correlates(cfg, clock):
    eng, out = engine(cfg, clock)
    eng.on_usb_change(change("connected", usb("USB\\VID_046D&PID_C077\\1", "input")))
    eng.on_process_started(ProcessInfo(1, "unknownapp.exe", 0))
    assert [e.priority for e in out] == ["info", "info"], "a mouse plus an app launch is not a review item"
    assert out[0].event_type == "USB_DEVICE_CONNECTED" and out[0].details["deviceCategory"] == "input"
    assert not any(e.event_type == "CORRELATED_ACTIVITY" for e in out)
    no_accusation(out)


def test_usb_storage_needs_review_but_says_it_is_not_evidence(cfg, clock):
    eng, out = engine(cfg, clock)
    eng.on_usb_change(change("connected", usb("USB\\VID_0781&PID_5567\\AA", "storage", service="USBSTOR")))
    assert out[0].priority == "review" and out[0].rule_id == "usb.storage_connected"
    assert "not evidence" in out[0].explanation and "does not read" in out[0].explanation
    no_accusation(out)


def test_usb_storage_review_is_configurable(cfg, clock):
    cfg.usb_storage_review = False
    eng, out = engine(cfg, clock)
    eng.on_usb_change(change("connected", usb("K", "storage")))
    assert out[0].priority == "info"


def test_usb_device_id_is_salted_hash_not_instance_id(cfg, clock):
    eng, out = engine(cfg, clock)
    key = "USB\\VID_0781&PID_5567\\4C530001230920115213"
    eng.on_usb_change(change("connected", usb(key, "storage")))
    dev_id = out[0].details["deviceId"]
    assert dev_id.startswith("h:") and "4C5300" not in dev_id and key not in str(out[0].to_payload())
    other = RulesEngine(cfg, "AS-OTHER", sink=lambda e: None, salt=b"x" * 32)
    assert other.device_id(key) != dev_id, "not linkable across sessions"


def test_repeated_usb_notifications_are_deduplicated_but_reconnect_is_reported(cfg, clock):
    eng, out = engine(cfg, clock)
    d = usb("K1", "input")
    eng.on_usb_change(change("connected", d))
    eng.on_usb_change(change("connected", d))   # duplicate notification
    assert len(out) == 1
    eng.on_usb_change(change("disconnected", d))
    clock.advance(cfg.dedupe_cooldown_seconds + 1)
    eng.on_usb_change(change("connected", d))   # genuine reconnection after the cooldown
    assert [e.event_type for e in out] == ["USB_DEVICE_CONNECTED", "USB_DEVICE_DISCONNECTED", "USB_DEVICE_CONNECTED"]


def test_peripheral_reporting_can_be_disabled_storage_still_reported(cfg, clock):
    cfg.usb_report_peripherals = False
    eng, out = engine(cfg, clock)
    eng.on_usb_change(change("connected", usb("M", "input")))
    eng.on_usb_change(change("connected", usb("S", "storage")))
    assert [e.details["deviceCategory"] for e in out] == ["storage"]


# --------------------------------------------------------------------------- processes
def test_process_trusted_system_ignored_and_names_reported_once(cfg, clock):
    eng, out = engine(cfg, clock)
    eng.on_process_started(ProcessInfo(1, "svchost.exe", 0))
    eng.on_process_started(ProcessInfo(2, "notepad.exe", 0))
    eng.on_process_started(ProcessInfo(3, "Notepad.exe", 0))
    assert [e.details["processName"] for e in out] == ["notepad.exe"]
    assert out[0].priority == "info" and "observation only" in out[0].explanation
    assert set(out[0].details) == {"processName", "pid", "allowlisted"}, "no command line or path"


def test_allowlisted_accessibility_tool_is_marked_and_never_an_indicator(cfg, clock):
    eng, out = engine(cfg, clock)
    eng.on_process_started(ProcessInfo(1, "nvda.exe", 0))
    eng.on_usb_change(change("connected", usb("S", "storage")))
    assert out[0].rule_id == "process.allowlisted" and out[0].details["allowlisted"] is True
    assert not any(e.event_type == "CORRELATED_ACTIVITY" for e in out), "screen reader + USB stick is not correlated"


# --------------------------------------------------------------------------- windows
def test_legitimate_allowlisted_topmost_window_is_not_suspicious(cfg):
    r = evaluate_window(win(1, rect=(1600, 0, 1920, 300), name="magnify.exe", topmost=True), ctx(new_window=True, new_process=True, allowlisted=True), cfg)
    assert r.priority == "info" and r.rule_id == "window.allowlisted"


def test_topmost_window_alone_is_only_context(cfg):
    # e.g. a video call's floating self-view, already running before the assessment, not over the assessment
    r = evaluate_window(win(2, rect=(1921, 0, 2300, 300), topmost=True), ctx(), cfg)
    assert r.rule_id is None, "always-on-top by itself is not reported"
    r = evaluate_window(win(2, rect=(1921, 800, 2200, 1000), topmost=True), ctx(new_window=True), cfg)
    assert r.priority == "info" and r.rule_id == "window.topmost_new"


def test_new_popup_from_app_running_before_the_assessment_is_context_only(cfg):
    # e.g. a meeting app that was already open shows a small floating window over the browser
    r = evaluate_window(win(2, rect=(1700, 800, 1900, 1000), topmost=True), ctx(new_window=True, new_process=False), cfg)
    assert r.priority == "info" and "overlapping" in r.explanation and "video calls" in r.explanation


def test_small_new_topmost_window_over_assessment_is_review_not_accusation(cfg, clock):
    w = win(3, rect=(1400, 200, 1800, 600), topmost=True)
    r = evaluate_window(w, ctx(new_process=True, new_window=True), cfg)
    assert r.priority == "review" and r.event_type == "OVERLAY_WINDOW_SUSPECTED"
    assert r.explanation.startswith("Potential overlay activity: a newly launched application")
    assert "Manual review required" in r.explanation
    assert {"always_on_top", "small", "overlaps_assessment", "new_process"} <= set(r.signals)
    eng, out = engine(cfg, clock)
    eng.on_window(w, ctx(new_process=True, new_window=True))
    eng.on_window(w, ctx(new_process=True, new_window=True))
    assert len(out) == 1, "same window/rule reported once"
    no_accusation(out)


def test_large_topmost_window_is_not_an_overlay_candidate(cfg):
    r = evaluate_window(win(4, rect=(0, 0, 1900, 1000), topmost=True), ctx(new_window=True, new_process=True), cfg)
    assert r.priority == "info", "full-screen always-on-top apps (e.g. presentation tools) are context only"


def test_capture_excluded_window_over_assessment_needs_review_with_caveat(cfg):
    r = evaluate_window(win(5, rect=(1200, 300, 1700, 700), capture_excluded=True), ctx(), cfg)
    assert r.priority == "review" and r.event_type == "CAPTURE_EXCLUDED_WINDOW"
    assert "password managers" in r.explanation


def test_transparent_click_through_overlay(cfg):
    r = evaluate_window(win(6, rect=(500, 200, 1500, 900), topmost=True, layered=True, alpha=120, click_through=True), ctx(), cfg)
    assert r.priority == "review" and r.event_type == "TRANSPARENT_OVERLAY_SUSPECTED"
    assert "semi_transparent" in r.signals and "click_through" in r.signals


def test_overlap_unknown_never_escalates(cfg):
    r = evaluate_window(win(7, rect=(1400, 200, 1800, 600), topmost=True), ctx(assessment=None, new_process=True, new_window=True), cfg)
    assert r.priority == "info" and "could not be determined" in r.explanation


def test_window_details_contain_no_title(cfg):
    r = evaluate_window(win(8, rect=(1400, 200, 1800, 600), topmost=True), ctx(new_window=True), cfg)
    assert "title" not in r.details and "class" not in str(r.details).lower()


# --------------------------------------------------------------------------- correlation
def test_multiple_independent_indicators_correlate_once_with_cooldown(cfg, clock):
    eng, out = engine(cfg, clock)
    eng.on_browser_event("WINDOW_BLUR")
    eng.on_usb_change(change("connected", usb("S", "storage")))
    clock.advance(20)
    eng.on_process_started(ProcessInfo(9, "assist.exe", 0))
    corr = [e for e in out if e.event_type == "CORRELATED_ACTIVITY"]
    assert len(corr) == 1 and corr[0].priority == "review"
    assert corr[0].details["categories"] == ["process", "usb"]
    assert "innocent explanation" in corr[0].explanation and "lost focus 1 time" in corr[0].explanation
    clock.advance(10)
    eng.on_window(win(9, rect=(1400, 200, 1800, 600), topmost=True), ctx(new_process=True, new_window=True))
    assert len([e for e in out if e.event_type == "CORRELATED_ACTIVITY"]) == 1, "cooldown prevents repeated escalation"
    no_accusation(out)


def test_indicators_outside_the_window_do_not_correlate(cfg, clock):
    eng, out = engine(cfg, clock)
    eng.on_usb_change(change("connected", usb("S", "storage")))
    clock.advance(cfg.correlation_window_seconds + 5)
    eng.on_process_started(ProcessInfo(9, "assist.exe", 0))
    assert not any(e.event_type == "CORRELATED_ACTIVITY" for e in out)


def test_payload_shape_matches_server_contract(cfg, clock):
    eng, out = engine(cfg, clock)
    eng.on_process_started(ProcessInfo(9, "assist.exe", 0))
    p = out[0].to_payload()
    assert set(p) == {"category", "eventType", "priority", "ruleId", "explanation", "details", "timestamp", "idempotencyKey"}
    assert p["timestamp"].endswith("Z") and len(p["idempotencyKey"]) >= 8


def test_assessment_window_fixture_is_consistent():
    a = win(99, **ASSESSMENT)
    assert a.is_assessment_window and a.area > 0
