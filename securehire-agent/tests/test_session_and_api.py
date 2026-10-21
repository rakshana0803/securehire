"""Session lifecycle and the local FastAPI service (authentication, origins, limits, no arbitrary operations)."""
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from agent.assessment_session import SessionError, SessionManager
from agent.event_client import SecureHireClient
from agent.local_api import build_app
from agent.monitor_base import Monitor
from agent.models import ProcessInfo

EXT = "chrome-extension://mlfnbgkkkndpcbmleppgablahalkeedn"
BASE = "http://127.0.0.1:4000"


class FakeMonitor(Monitor):
    def __init__(self, name, on_health):
        super().__init__(on_health)
        self.name = name

    def wait(self):
        self._stop.wait(0.05)


@pytest.fixture
def created():
    return []


@pytest.fixture
def manager(cfg, fake_api, created):
    def client_factory(base, sid, tok):
        return SecureHireClient(cfg, base, sid, tok, transport=httpx.MockTransport(fake_api.handler))

    def monitors(sess):
        ms = [FakeMonitor("usb", sess.on_monitor_health), FakeMonitor("process", sess.on_monitor_health)]
        created.extend(ms)
        return ms
    return SessionManager(cfg, client_factory=client_factory, monitor_factory=monitors)


def wait_until(pred, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end and not pred():
        time.sleep(0.02)
    return pred()


# --------------------------------------------------------------------------- session lifecycle
def test_start_requires_server_confirmation(manager, fake_api, created):
    with pytest.raises(SessionError) as e:
        manager.start(fake_api.session_id, "x" * 43, BASE)
    assert e.value.status == 401 and created == [], "no monitoring without a valid SecureHire token"
    fake_api.status = "submitted"
    with pytest.raises(SessionError) as e:
        manager.start(fake_api.session_id, fake_api.token, BASE)
    assert e.value.status == 409 and created == []


def test_start_rejects_non_allowlisted_api(manager, fake_api):
    with pytest.raises(SessionError) as e:
        manager.start(fake_api.session_id, fake_api.token, "https://evil.example")
    assert e.value.status == 400


def test_session_start_monitors_heartbeat_and_end(manager, fake_api, created):
    control, sess = manager.start(fake_api.session_id, fake_api.token, BASE)
    assert manager.active and manager.check_control_token(control) and not manager.check_control_token("nope")
    assert wait_until(lambda: all(m.state == "active" for m in created))
    assert fake_api.heartbeats and fake_api.heartbeats[0]["sessionId"] == fake_api.session_id
    sess.engine.on_process_started(ProcessInfo(5, "assist.exe", 0))
    manager.end("ended_by_extension")
    assert not manager.active and all(m.state == "stopped" for m in created)
    types = [e["eventType"] for e in fake_api.events.values()]
    assert "AGENT_STARTED" in types and "PROCESS_STARTED" in types, "queued events drained on end"
    assert "AGENT_STOPPED" not in types, "a normal end is not an interruption"
    assert not manager.check_control_token(control), "control token invalid after the session"


def test_candidate_closing_agent_is_reported_for_review(manager, fake_api):
    manager.start(fake_api.session_id, fake_api.token, BASE)
    manager.end("candidate_closed_agent", user_initiated=True)
    stopped = [e for e in fake_api.events.values() if e["eventType"] == "AGENT_STOPPED"]
    assert len(stopped) == 1 and stopped[0]["priority"] == "review"
    assert "not observed" in stopped[0]["explanation"]


def test_second_session_cannot_take_over_but_same_session_can_reconnect(manager, fake_api):
    c1, _ = manager.start(fake_api.session_id, fake_api.token, BASE)
    with pytest.raises(SessionError) as e:
        manager.start("AS-OTHER1", fake_api.token, BASE)
    assert e.value.status == 409
    with pytest.raises(SessionError):
        manager.start(fake_api.session_id, "y" * 43, BASE)   # right session id, wrong token
    c2, _ = manager.start(fake_api.session_id, fake_api.token, BASE)  # extension service worker restarted
    assert c2 != c1 and manager.check_control_token(c2) and not manager.check_control_token(c1)
    manager.end()


def test_server_ending_the_session_stops_monitoring(cfg, manager, fake_api, created):
    _, sess = manager.start(fake_api.session_id, fake_api.token, BASE)
    fake_api.status = "submitted"
    sess._send_heartbeat()
    assert wait_until(lambda: sess.state == "ended")
    assert sess.ended_reason == "server_ended" and all(m.state == "stopped" for m in created)


def test_offline_keeps_monitoring_and_queues(manager, fake_api):
    _, sess = manager.start(fake_api.session_id, fake_api.token, BASE)
    fake_api.fail_mode, fake_api.fail_count = "network", -1     # SecureHire unreachable indefinitely
    sess._send_heartbeat()
    assert sess.connection == "offline" and manager.active
    sess.engine.on_process_started(ProcessInfo(6, "later.exe", 0))
    time.sleep(0.1)
    assert sess.client.stats.pending >= 1 and sess.client.stats.delivered >= 1
    fake_api.fail_mode = None
    assert wait_until(lambda: sess.client.stats.pending == 0, 3.0), "delivered after recovery"
    manager.end()


# --------------------------------------------------------------------------- local API
@pytest.fixture
def api(manager, cfg):
    return TestClient(build_app(manager, cfg), base_url="http://127.0.0.1:47615")


def start(api, fake_api, **kw):
    body = {"sessionId": fake_api.session_id, "agentToken": fake_api.token, "apiBaseUrl": BASE, **kw}
    return api.post("/session/start", json=body, headers={"Origin": EXT})


def test_health_is_minimal(api):
    r = api.get("/health")
    assert r.status_code == 200 and set(r.json()) == {"ok", "service", "version", "active"}


def test_dns_rebinding_and_foreign_origins_are_rejected(api, fake_api):
    assert api.get("/health", headers={"Host": "evil.example:47615"}).status_code == 403
    assert api.get("/health", headers={"Origin": "https://evil.example"}).status_code == 403
    assert api.post("/session/start", json={}, headers={"Origin": "https://securehire.evil"}).status_code == 403
    assert api.post("/session/start", json={"sessionId": fake_api.session_id, "agentToken": fake_api.token, "apiBaseUrl": BASE}).status_code == 403, "POST without the extension Origin"
    assert api.post("/session/start", json={}, headers={"Origin": "chrome-extension://someotherextensionid"}).status_code == 403


def test_cors_preflight_only_for_the_extension(api):
    ok = api.options("/session/start", headers={"Origin": EXT, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
    assert ok.headers.get("access-control-allow-origin") == EXT
    bad = api.options("/session/start", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in bad.headers
    assert api.get("/health").headers.get("access-control-allow-origin") is None


def test_full_extension_flow(api, fake_api, manager):
    r = start(api, fake_api)
    assert r.status_code == 200, r.text
    token = r.json()["controlToken"]
    auth = {"Authorization": f"Bearer {token}", "Origin": EXT}
    assert api.get("/session/status").status_code == 401
    assert api.get("/session/status", headers={"Authorization": "Bearer wrong"}).status_code == 401
    st = api.get("/session/status", headers=auth).json()
    assert st["active"] and st["session"]["sessionId"] == fake_api.session_id
    assert "agentToken" not in str(st) and fake_api.token not in str(st)
    r = api.post("/extension/events", json={"events": [{"eventType": "WINDOW_BLUR"}, {"eventType": "RUN_SHELL"}]}, headers=auth)
    assert r.json()["accepted"] == 1
    evs = api.get("/events?since=0", headers=auth).json()["events"]
    assert evs and evs[0]["eventType"] == "AGENT_STARTED" and "idempotencyKey" not in evs[0]
    assert api.post("/session/end", json={"reason": "assessment_submitted"}, headers=auth).json()["status"]["active"] is False
    assert api.get("/session/status", headers=auth).status_code == 401, "token dies with the session"


def test_invalid_and_oversized_requests(api, fake_api):
    h = {"Origin": EXT}
    assert api.post("/session/start", json={"sessionId": "x", "agentToken": "short", "apiBaseUrl": BASE}, headers=h).status_code == 422
    assert api.post("/session/start", json={"sessionId": fake_api.session_id, "agentToken": fake_api.token, "apiBaseUrl": BASE, "extra": 1}, headers=h).status_code == 422
    assert api.post("/session/start", content=b"{" + b" " * 20000 + b"}", headers={**h, "Content-Type": "application/json"}).status_code == 413
    assert start(api, fake_api, apiBaseUrl="https://attacker.example").status_code == 400
    assert start(api, fake_api, agentToken="z" * 43).status_code == 401


def test_rate_limit_on_session_start(api, fake_api):
    codes = [api.post("/session/start", json={"sessionId": "AS-RATE01", "agentToken": "q" * 43, "apiBaseUrl": "https://nope.example"}, headers={"Origin": EXT}).status_code for _ in range(12)]
    assert codes[:10] == [400] * 10 and codes[-1] == 429


def test_no_arbitrary_operations_exist(api, fake_api):
    token = start(api, fake_api).json()["controlToken"]
    auth = {"Authorization": f"Bearer {token}", "Origin": EXT}
    for path in ("/exec", "/run", "/shell", "/files", "/process/kill", "/admin", "/docs", "/openapi.json", "/config"):
        assert api.post(path, json={"cmd": "whoami"}, headers=auth).status_code in (404, 405), path
        assert api.get(path, headers=auth).status_code in (404, 405), path
    assert api.put("/session/start", headers=auth).status_code == 405
    assert api.delete("/session/status", headers=auth).status_code == 405
    api.post("/session/end", json={}, headers=auth)
