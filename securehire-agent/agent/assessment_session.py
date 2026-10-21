"""Assessment-scoped monitoring lifecycle.

Monitoring exists only inside an ``AssessmentSession``:
  1. The SecureHire extension forwards {sessionId, agentToken, apiBaseUrl} to the local service.
  2. The agent checks apiBaseUrl against its allowlist and verifies the token with SecureHire
     (GET /api/agent/session). Nothing starts unless SecureHire confirms an active session.
  3. Monitors take a baseline, then report changes; a heartbeat runs every ``heartbeat_seconds``.
  4. Monitoring stops when the extension ends the session, SecureHire reports it over, it
     expires, or the candidate closes the agent (recorded as an interruption, never hidden).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import platform
import secrets
import sys
import threading
import time
from collections import deque
from datetime import datetime
from typing import Callable, Deque, Optional

from . import __version__
from .config import AgentConfig
from .event_client import ApiError, SecureHireClient
from .models import PRIORITY_INFO, PRIORITY_REVIEW, SecurityEvent
from .monitor_base import Monitor
from .process_monitor import ProcessMonitor
from .rules_engine import RulesEngine
from .usb_monitor import UsbMonitor
from .window_monitor import WindowMonitor

log = logging.getLogger("securehire.session")


class SessionError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def platform_label() -> str:
    if sys.platform == "win32":
        return f"Windows-{platform.release()}-{platform.version().split('.')[-1]}"
    return f"{platform.system()}-{platform.release()}"[:40]


MonitorFactory = Callable[["AssessmentSession"], list[Monitor]]


def default_monitors(sess: "AssessmentSession") -> list[Monitor]:
    cfg, engine = sess.cfg, sess.engine
    mons: list[Monitor] = []
    if cfg.process_monitor_enabled:
        proc = ProcessMonitor(on_started=lambda p: engine.on_process_started(p), poll_seconds=cfg.process_poll_seconds, on_health=sess.on_monitor_health)
        mons.append(proc)
    else:
        proc = None
    if cfg.usb_monitor_enabled:
        mons.append(UsbMonitor(on_change=engine.on_usb_change, reconcile_seconds=cfg.usb_reconcile_seconds, on_health=sess.on_monitor_health))
    if cfg.window_monitor_enabled:
        if sys.platform == "win32":
            from .win32_windows import WindowsWindowBackend
            factory = lambda: WindowsWindowBackend(cfg.assessment_title_marker, cfg.browser_process_names)  # noqa: E731
        else:
            from .window_monitor import default_backend as factory  # reports "unsupported" off Windows
        mons.append(WindowMonitor(cfg, on_window=engine.on_window,
                                  started_during_session=(proc.pid_started_during_session if proc else (lambda _pid: False)),
                                  is_allowlisted=engine.is_allowlisted, backend_factory=factory, on_health=sess.on_monitor_health))
    return mons


class AssessmentSession:
    def __init__(self, cfg: AgentConfig, session_id: str, agent_token: str, api_base_url: str,
                 client: SecureHireClient, monitor_factory: MonitorFactory = default_monitors,
                 on_event: Optional[Callable[[SecurityEvent], None]] = None, on_ended: Optional[Callable[["AssessmentSession", str], None]] = None):
        self.cfg = cfg
        self.session_id = session_id
        self.api_base_url = api_base_url
        self.token_hash = hashlib.sha256(agent_token.encode()).hexdigest()
        self.client = client
        self.state = "verifying"     # verifying | active | ended
        self.started_at: Optional[str] = None
        self.expires_at: Optional[float] = None
        self.assessment_title: Optional[str] = None
        self.ended_reason: Optional[str] = None
        self.connection = "connecting"   # connecting | online | offline | ended
        self.recent: Deque[SecurityEvent] = deque(maxlen=cfg.recent_events_kept)
        self._seq = 0
        self._on_event = on_event
        self._on_ended = on_ended
        self._monitor_factory = monitor_factory
        self._lock = threading.RLock()
        self._hb_stop = threading.Event()
        self._hb_thread: Optional[threading.Thread] = None
        self._monitor_prev: dict[str, str] = {}
        self.engine = RulesEngine(cfg, session_id, sink=self._sink, salt=secrets.token_bytes(32))
        self.monitors: list[Monitor] = []
        client.on_stopped = self._delivery_stopped

    # ---- events
    def _sink(self, ev: SecurityEvent) -> None:
        with self._lock:
            self._seq += 1
            ev.local_id = self._seq
            self.recent.append(ev)
        self.client.enqueue(ev)
        if self._on_event:
            self._on_event(ev)

    def on_monitor_health(self, name: str, state: str, error: Optional[str]) -> None:
        prev = self._monitor_prev.get(name)
        self._monitor_prev[name] = state
        if self.state != "active":
            return
        if state == "error":
            self.engine.agent_event("MONITOR_ERROR", f"The {name} monitor hit an error and is retrying. Activity of this type may "
                                    f"not be observed until it recovers.", PRIORITY_INFO, monitor=name, state=state, error=(error or "")[:200])
        elif state == "active" and prev == "error":
            self.engine.agent_event("MONITOR_RECOVERED", f"The {name} monitor recovered and is observing again.", PRIORITY_INFO, monitor=name, state=state)
        elif state == "unsupported":
            self.engine.agent_event("MONITOR_UNAVAILABLE", f"The {name} monitor is not available on this computer ({error}). "
                                    f"This type of activity is not observed in this session.", PRIORITY_INFO, monitor=name, state=state, reason=(error or "")[:200])

    def monitor_states(self) -> dict[str, str]:
        return {m.name: m.state for m in self.monitors}

    # ---- lifecycle
    def verify_and_start(self) -> None:
        try:
            info = self.client.verify_session()
        except ApiError as e:
            self.state = "ended"
            self.client.close()
            if e.kind == "auth":
                raise SessionError(401, "SecureHire did not accept this session token.")
            if e.kind == "session_over":
                raise SessionError(409, "This assessment session is no longer active.")
            raise SessionError(502, f"Could not verify the session with SecureHire: {e}")
        if info.get("sessionId") != self.session_id or info.get("status") != "active":
            self.state = "ended"
            self.client.close()
            raise SessionError(409, f"Assessment session is {info.get('status', 'not active')}.")
        self.started_at = info.get("startedAt")
        self.assessment_title = info.get("assessmentTitle")
        try:
            self.expires_at = datetime.fromisoformat(str(info.get("expiresAt")).replace("Z", "+00:00")).timestamp()
        except ValueError:
            self.expires_at = time.time() + 4 * 3600
        self.state = "active"
        self.connection = "online"
        self.client.start()
        self.engine.agent_event("AGENT_STARTED", f"Desktop security agent v{__version__} started monitoring for this assessment "
                                f"on {platform_label()}. The candidate was shown that the agent is active.", PRIORITY_INFO,
                                agentVersion=__version__, platform=platform_label())
        self.monitors = self._monitor_factory(self)
        for m in self.monitors:
            m.start()
        self._send_heartbeat()
        self._hb_thread = threading.Thread(target=self._heartbeat_loop, name="securehire-heartbeat", daemon=True)
        self._hb_thread.start()
        log.info("Monitoring started for session %s", self.session_id)

    def _send_heartbeat(self) -> None:
        try:
            self.client.heartbeat(self.monitor_states(), platform_label())
            self.connection = "online"
        except ApiError as e:
            if e.kind in ("auth", "session_over"):
                threading.Thread(target=self.end, args=("server_ended" if e.kind == "session_over" else "token_revoked",), daemon=True).start()
            else:
                self.connection = "offline"   # keep monitoring; events stay queued until SecureHire is reachable

    def _heartbeat_loop(self) -> None:
        while not self._hb_stop.wait(self.cfg.heartbeat_seconds):
            if self.expires_at and time.time() > self.expires_at:
                self.end("expired")
                return
            self._send_heartbeat()

    def _delivery_stopped(self, kind: str) -> None:
        if self.state == "active":
            threading.Thread(target=self.end, args=("server_ended" if kind == "session_over" else "token_revoked",), daemon=True).start()

    def end(self, reason: str, user_initiated: bool = False) -> None:
        with self._lock:
            if self.state != "active":
                return
            self.state = "ending"
            self.ended_reason = reason
        if user_initiated:
            self.engine.agent_event("AGENT_STOPPED", "The desktop agent was closed on the candidate's computer while the assessment was "
                                    "still in progress. Desktop monitoring stopped at this point; activity afterwards was not observed.",
                                    PRIORITY_REVIEW, reason=reason[:100])
        self._hb_stop.set()
        for m in self.monitors:
            m.stop()
        self.client.drain(timeout=5.0)
        self.client.close()
        self.state = "ended"
        self.connection = "ended"
        log.info("Monitoring ended for session %s (%s)", self.session_id, reason)
        if self._on_ended:
            self._on_ended(self, reason)

    def status(self) -> dict:
        s = self.client.stats
        return {
            "state": self.state, "sessionId": self.session_id, "assessmentTitle": self.assessment_title, "startedAt": self.started_at,
            "connection": self.connection, "monitors": self.monitor_states(), "endedReason": self.ended_reason,
            "delivery": {"pending": s.pending, "delivered": s.delivered, "duplicates": s.duplicates, "rejected": s.rejected,
                         "dropped": s.dropped, "lastError": s.last_error},
            "reviewItems": sum(1 for e in self.recent if e.priority == PRIORITY_REVIEW),
        }


class SessionManager:
    """Holds at most one active session and the per-session control token for the local API."""

    def __init__(self, cfg: AgentConfig, client_factory: Callable[[str, str, str], SecureHireClient] | None = None,
                 monitor_factory: MonitorFactory = default_monitors, on_event: Optional[Callable[[SecurityEvent], None]] = None):
        self.cfg = cfg
        self._client_factory = client_factory or (lambda base, sid, tok: SecureHireClient(cfg, base, sid, tok))
        self._monitor_factory = monitor_factory
        self._on_event = on_event
        self._lock = threading.Lock()
        self.session: Optional[AssessmentSession] = None
        self.last_session: Optional[AssessmentSession] = None
        self._control_hash: Optional[bytes] = None
        self.agent_started_at = time.time()

    @staticmethod
    def _hash(tok: str) -> bytes:
        return hashlib.sha256(tok.encode()).digest()

    def check_control_token(self, token: str) -> bool:
        h = self._control_hash
        return bool(token) and h is not None and hmac.compare_digest(self._hash(token), h)

    @property
    def active(self) -> bool:
        return self.session is not None and self.session.state == "active"

    def start(self, session_id: str, agent_token: str, api_base_url: str) -> tuple[str, AssessmentSession]:
        base = api_base_url.rstrip("/")
        if base not in self.cfg.allowed_api_base_urls:
            raise SessionError(400, "This SecureHire address is not on the agent's allowlist.")
        with self._lock:
            cur = self.session
            if cur and cur.state == "active":
                if cur.session_id == session_id and hmac.compare_digest(cur.token_hash, hashlib.sha256(agent_token.encode()).hexdigest()):
                    # Same session (e.g. the extension's service worker restarted): issue a fresh control token.
                    control = secrets.token_urlsafe(32)
                    self._control_hash = self._hash(control)
                    return control, cur
                raise SessionError(409, "Another assessment session is already being monitored on this computer.")
            sess = AssessmentSession(self.cfg, session_id, agent_token, base, self._client_factory(base, session_id, agent_token),
                                     monitor_factory=self._monitor_factory, on_event=self._on_event, on_ended=self._ended)
            sess.verify_and_start()   # raises SessionError if SecureHire does not confirm it
            control = secrets.token_urlsafe(32)
            self._control_hash = self._hash(control)
            self.session = sess
            return control, sess

    def _ended(self, sess: AssessmentSession, reason: str) -> None:
        if self.session is sess:
            self.last_session = sess
            self.session = None
            self._control_hash = None

    def end(self, reason: str = "ended_by_extension", user_initiated: bool = False) -> None:
        s = self.session
        if s:
            s.end(reason, user_initiated=user_initiated)

    def status(self) -> dict:
        s = self.session or self.last_session
        return {"agentVersion": __version__, "pid": os.getpid(), "active": self.active, "platform": platform_label(),
                "session": s.status() if s else None}

    def recent_events(self, since: int = 0, limit: int = 50) -> list[dict]:
        s = self.session or self.last_session
        if not s:
            return []
        out = []
        for e in list(s.recent):
            if e.local_id > since:
                p = e.to_payload()
                p.pop("idempotencyKey", None)
                p["localId"] = e.local_id
                out.append(p)
        return out[-limit:]
