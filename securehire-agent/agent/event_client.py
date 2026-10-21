"""Authenticated delivery of events and heartbeats to the SecureHire API.

* Events wait in a bounded in-memory queue until the server acknowledges them. An event counts as
  delivered only when the server answers 2xx and reports it as inserted or duplicate. Network
  errors, timeouts, 429 and 5xx keep it queued and trigger exponential backoff with jitter.
* Events the server rejects as invalid are logged and not retried (retrying would never succeed).
* 401 means the session token is no longer valid; 409/410 mean the session is over. Both stop delivery.
* The agent token is kept in memory only, never written to disk or logs.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Optional

import httpx

from . import __version__
from .config import AgentConfig
from .models import SecurityEvent

log = logging.getLogger("securehire.client")


class ApiError(Exception):
    def __init__(self, kind: str, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.kind = kind          # auth | session_over | network | server | invalid
        self.status = status


@dataclass
class DeliveryStats:
    delivered: int = 0
    duplicates: int = 0
    rejected: int = 0
    dropped: int = 0              # queue overflow (oldest dropped first) — reported, never silent
    pending: int = 0
    last_success_at: Optional[float] = None
    last_error: Optional[str] = None
    online: Optional[bool] = None
    stopped_reason: Optional[str] = None
    recent_rejections: list[str] = field(default_factory=list)


class SecureHireClient:
    def __init__(self, cfg: AgentConfig, api_base_url: str, session_id: str, agent_token: str,
                 transport: Optional[httpx.BaseTransport] = None, sleep: Callable[[float], None] = time.sleep):
        self.cfg = cfg
        self.base = api_base_url.rstrip("/")
        self.session_id = session_id
        self._token = agent_token
        self._http = httpx.Client(base_url=self.base, timeout=cfg.api_timeout_seconds, transport=transport,
                                  headers={"User-Agent": f"SecureHireAgent/{__version__}"})
        self._queue: Deque[SecurityEvent] = deque()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._closed = threading.Event()
        self._sleep = sleep
        self._thread: Optional[threading.Thread] = None
        self._failures = 0
        self.stats = DeliveryStats()
        self.on_stopped: Optional[Callable[[str], None]] = None

    # ---- low level
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def _request(self, method: str, path: str, **kw: Any) -> dict:
        try:
            r = self._http.request(method, path, headers=self._headers(), **kw)
        except httpx.HTTPError as e:
            raise ApiError("network", f"Cannot reach SecureHire ({e.__class__.__name__}).") from e
        try:
            data = r.json()
        except ValueError:
            data = {}
        if r.status_code == 401:
            raise ApiError("auth", data.get("error") or "Session token rejected.", 401)
        if r.status_code in (409, 410):
            raise ApiError("session_over", data.get("error") or "Assessment session is no longer active.", r.status_code)
        if r.status_code == 400 or r.status_code == 413:
            raise ApiError("invalid", data.get("error") or "Request rejected.", r.status_code)
        if r.status_code == 429 or r.status_code >= 500:
            raise ApiError("server", data.get("error") or f"SecureHire is temporarily unavailable ({r.status_code}).", r.status_code)
        if not r.is_success:
            raise ApiError("server", f"Unexpected response {r.status_code}.", r.status_code)
        return data

    # ---- session & heartbeat
    def verify_session(self) -> dict:
        return self._request("GET", "/api/agent/session", params={"sessionId": self.session_id})

    def heartbeat(self, monitors: dict[str, str], platform: str) -> dict:
        try:
            data = self._request("POST", "/api/agent/heartbeat", json={
                "sessionId": self.session_id, "agentVersion": __version__, "platform": platform[:40], "monitors": monitors})
            self.stats.online = True
            return data
        except ApiError as e:
            if e.kind in ("network", "server"):
                self.stats.online = False
                self.stats.last_error = str(e)
            raise

    # ---- event queue
    def enqueue(self, ev: SecurityEvent) -> None:
        with self._lock:
            if len(self._queue) >= self.cfg.queue_max_events:
                self._queue.popleft()
                self.stats.dropped += 1
                log.warning("Event queue full; oldest event dropped (%d dropped so far)", self.stats.dropped)
            self._queue.append(ev)
            self.stats.pending = len(self._queue)
        self._wake.set()

    def flush_once(self) -> bool:
        """Send one batch. Returns True when the batch was acknowledged (or there was nothing to send)."""
        with self._lock:
            batch = list(self._queue)[: self.cfg.batch_size]
        if not batch:
            return True
        try:
            data = self._request("POST", "/api/agent/events", json={"sessionId": self.session_id, "events": [e.to_payload() for e in batch]})
        except ApiError as e:
            if e.kind == "invalid":
                # The whole request was malformed (should not happen); drop it so the queue cannot jam.
                self._remove(batch, rejected=len(batch))
                self.stats.last_error = str(e)
                log.error("Batch rejected by server: %s", e)
                return True
            if e.kind in ("auth", "session_over"):
                self._stop_delivery(e.kind, str(e))
                return False
            self.stats.online = False
            self.stats.last_error = str(e)
            return False
        results = {r.get("idempotencyKey"): r for r in data.get("results", []) if isinstance(r, dict)}
        acked, rejected = [], 0
        for ev in batch:
            r = results.get(ev.idempotency_key)
            if r is None:
                continue  # not acknowledged → stays queued
            acked.append(ev)
            if r.get("inserted"):
                self.stats.delivered += 1
            elif r.get("duplicate"):
                self.stats.duplicates += 1
            elif r.get("error"):
                rejected += 1
                self.stats.recent_rejections = (self.stats.recent_rejections + [f"{ev.event_type}: {r['error']}"])[-5:]
                log.warning("Server rejected %s: %s", ev.event_type, r["error"])
        self._remove(acked, rejected=rejected)
        self.stats.online = True
        self.stats.last_success_at = time.time()
        self.stats.last_error = None
        return len(acked) == len(batch)

    def _remove(self, events: list[SecurityEvent], rejected: int = 0) -> None:
        keys = {e.idempotency_key for e in events}
        with self._lock:
            self._queue = deque(e for e in self._queue if e.idempotency_key not in keys)
            self.stats.pending = len(self._queue)
            self.stats.rejected += rejected

    def _stop_delivery(self, kind: str, message: str) -> None:
        self.stats.stopped_reason = kind
        self.stats.last_error = message
        log.warning("Event delivery stopped (%s): %s", kind, message)
        if self.on_stopped:
            self.on_stopped(kind)

    def backoff_seconds(self) -> float:
        base = min(self.cfg.retry_max_seconds, self.cfg.retry_base_seconds * (2 ** min(self._failures, 10)))
        return base * (0.75 + random.random() * 0.5)

    # ---- background sender
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._closed.clear()
        self._thread = threading.Thread(target=self._loop, name="securehire-sender", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._closed.is_set():
            if self.stats.stopped_reason:
                return
            with self._lock:
                has = bool(self._queue)
            if not has:
                self._wake.wait(1.0)
                self._wake.clear()
                continue
            if self.flush_once():
                self._failures = 0
                continue
            if self.stats.stopped_reason:
                return
            self._failures += 1
            delay = self.backoff_seconds()
            log.info("Delivery failed; retrying in %.1f s (%d pending)", delay, self.stats.pending)
            self._closed.wait(delay)

    def drain(self, timeout: float = 5.0) -> bool:
        """Best-effort final delivery (e.g. on shutdown). Returns True if the queue emptied."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self.stats.stopped_reason:
            with self._lock:
                if not self._queue:
                    return True
            if not self.flush_once():
                break
        with self._lock:
            return not self._queue

    def close(self) -> None:
        self._closed.set()
        self._wake.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(3.0)
        self._token = ""
        self._http.close()
