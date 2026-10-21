"""Local FastAPI service: the narrow bridge between the SecureHire Chrome extension and this agent.

Security design
  * Binds to 127.0.0.1 only (enforced in config validation and in ``serve``). Never on the network.
  * Host header must be 127.0.0.1:<port> or localhost:<port> — blocks DNS-rebinding attacks.
  * Browser origin must be the SecureHire extension (chrome-extension://<fixed id>). Web pages
    cannot call it: their Origin is rejected, and CORS only allows the extension origin.
    State-changing requests (POST) *require* the extension Origin header.
  * POST /session/start needs a SecureHire-issued agent token, which the agent verifies with the
    SecureHire API before anything starts; it returns a random per-session control token that all
    other endpoints require (constant-time comparison). A second, different session cannot take over.
  * Request bodies are limited to 16 KB, validated with strict schemas, and rate-limited.
  * There are no endpoints for files, processes, shell commands, settings or anything else:
    the only actions are start / end monitoring for an authorised assessment and read its status.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Deque, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .assessment_session import SessionError, SessionManager
from .config import AgentConfig

log = logging.getLogger("securehire.local_api")

MAX_BODY_BYTES = 16 * 1024
BROWSER_EVENTS = {"TAB_HIDDEN", "TAB_VISIBLE", "WINDOW_BLUR", "WINDOW_FOCUS", "TAB_SWITCH", "FULLSCREEN_EXIT", "FULLSCREEN_ENTER"}


class StartBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sessionId: str = Field(pattern=r"^[A-Za-z0-9-]{6,64}$")
    agentToken: str = Field(min_length=20, max_length=200, pattern=r"^[A-Za-z0-9_\-]+$")
    apiBaseUrl: str = Field(min_length=8, max_length=200)


class EndBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="ended_by_extension", pattern=r"^[a-z_]{3,40}$")


class BrowserEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    eventType: str = Field(max_length=40)
    timestamp: Optional[str] = Field(default=None, max_length=40)


class BrowserEventsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[BrowserEvent] = Field(min_length=1, max_length=20)


class RateLimiter:
    """Sliding-window limiter keyed by route (single local client, so per-route is enough)."""

    def __init__(self, limits: dict[str, int], default: int, window: float = 60.0):
        self.limits, self.default, self.window = limits, default, window
        self._hits: dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        limit = self.limits.get(key, self.default)
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


def build_app(manager: SessionManager, cfg: AgentConfig) -> FastAPI:
    app = FastAPI(title="SecureHire Desktop Agent (local)", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    allowed_origins = set(cfg.allowed_extension_origins)
    allowed_hosts = {f"127.0.0.1:{cfg.local_port}", f"localhost:{cfg.local_port}", f"[::1]:{cfg.local_port}"}
    limiter = RateLimiter({"/session/start": 10, "/extension/events": 240, "/session/status": 240, "/events": 240}, default=60)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Order matters: these checks run before routing, CORS and body parsing.
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"error": "Host not allowed."}, status_code=403)
        origin = request.headers.get("origin")
        if origin is not None and origin not in allowed_origins:
            return JSONResponse({"error": "Origin not allowed."}, status_code=403)
        if request.method == "OPTIONS":
            return await call_next(request)  # CORS preflight (only the extension origin gets allow headers)
        if request.method == "POST" and origin is None:
            return JSONResponse({"error": "Requests must come from the SecureHire extension."}, status_code=403)
        if request.method not in ("GET", "POST"):
            return JSONResponse({"error": "Method not allowed."}, status_code=405)
        try:
            if int(request.headers.get("content-length") or 0) > MAX_BODY_BYTES:
                return JSONResponse({"error": "Request body too large."}, status_code=413)
        except ValueError:
            return JSONResponse({"error": "Invalid Content-Length."}, status_code=400)
        if request.method == "POST":
            body = await request.body()  # also catches chunked bodies without Content-Length
            if len(body) > MAX_BODY_BYTES:
                return JSONResponse({"error": "Request body too large."}, status_code=413)
        if not limiter.allow(request.url.path):
            return JSONResponse({"error": "Too many requests."}, status_code=429)
        return await call_next(request)

    # Added after the guard so it wraps it: preflights from the extension get CORS headers; nothing else does.
    app.add_middleware(CORSMiddleware, allow_origins=sorted(allowed_origins), allow_methods=["GET", "POST"],
                       allow_headers=["Authorization", "Content-Type"], allow_credentials=False, max_age=600)

    def require_control(authorization: Optional[str]) -> None:
        token = (authorization or "").removeprefix("Bearer ").strip()
        if not manager.check_control_token(token):
            raise HTTPException(status_code=401, detail="Missing or invalid control token.")

    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def unexpected(_request: Request, exc: Exception):
        log.exception("Local API error")
        return JSONResponse({"error": "Internal error."}, status_code=500)

    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def invalid(_request: Request, exc: RequestValidationError):
        fields = sorted({".".join(str(p) for p in e.get("loc", [])[1:]) or "body" for e in exc.errors()})
        return JSONResponse({"error": "Invalid request.", "fields": fields}, status_code=422)

    @app.get("/health")
    def health():
        # Deliberately minimal: no session ids, tokens or machine details.
        return {"ok": True, "service": "securehire-agent", "version": __version__, "active": manager.active}

    @app.post("/session/start")
    async def session_start(body: StartBody):
        try:
            control, sess = await run_in_threadpool(manager.start, body.sessionId, body.agentToken, body.apiBaseUrl)
        except SessionError as e:
            raise HTTPException(status_code=e.status, detail=str(e))
        return {"ok": True, "controlToken": control, "status": sess.status()}

    @app.get("/session/status")
    def session_status(authorization: Optional[str] = Header(default=None)):
        require_control(authorization)
        return manager.status()

    @app.post("/session/end")
    async def session_end(body: EndBody, authorization: Optional[str] = Header(default=None)):
        require_control(authorization)
        await run_in_threadpool(manager.end, body.reason, False)
        return {"ok": True, "status": manager.status()}

    @app.get("/events")
    def events(since: int = 0, authorization: Optional[str] = Header(default=None)):
        require_control(authorization)
        if since < 0 or since > 10 ** 9:
            raise HTTPException(status_code=422, detail="Invalid since.")
        return {"events": manager.recent_events(since=since)}

    @app.post("/extension/events")
    def extension_events(body: BrowserEventsBody, authorization: Optional[str] = Header(default=None)):
        require_control(authorization)
        sess = manager.session
        accepted = 0
        if sess and sess.state == "active":
            for ev in body.events:
                if ev.eventType in BROWSER_EVENTS:
                    sess.engine.on_browser_event(ev.eventType)  # local correlation context only; the extension reports these to SecureHire itself
                    accepted += 1
        return {"ok": True, "accepted": accepted}

    return app


class LocalServer:
    """Runs uvicorn in a background thread, bound to loopback only."""

    def __init__(self, app: FastAPI, cfg: AgentConfig):
        import uvicorn
        if cfg.local_host not in ("127.0.0.1", "::1"):
            raise ValueError("The local service may only bind to a loopback address.")
        self._server = uvicorn.Server(uvicorn.Config(app, host=cfg.local_host, port=cfg.local_port, log_level="warning",
                                                     access_log=False, limit_concurrency=20, timeout_keep_alive=5, server_header=False))
        self._thread = threading.Thread(target=self._server.run, name="securehire-local-api", daemon=True)

    def start(self, timeout: float = 5.0) -> bool:
        self._thread.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self._server.started:
            if not self._thread.is_alive():
                return False
            time.sleep(0.05)
        return self._server.started

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(5.0)
