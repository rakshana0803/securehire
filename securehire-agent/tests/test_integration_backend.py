"""End-to-end: real SecureHire Node backend + real agent session manager / rules engine / delivery client.

Only the operating-system layer is faked (USB and window backends); everything else — token
verification, heartbeats, event validation, storage, recruiter API and review — is the real code.
Skipped automatically if Node.js or the server's node_modules are not available.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
import pytest

from agent.assessment_session import SessionManager
from agent.models import ProcessInfo, UsbChange, utcnow
from agent.rules_engine import WindowContext
from conftest import usb, win

SERVER = Path(__file__).resolve().parents[2] / "server"
pytestmark = pytest.mark.skipif(not shutil.which("node") or not (SERVER / "node_modules").exists(), reason="Node.js backend not available")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def backend():
    tmp = tempfile.mkdtemp(prefix="securehire-int-")
    port = free_port()
    env = {**os.environ, "PORT": str(port), "DB_FILE": f"{tmp}/int.db", "UPLOAD_DIR": f"{tmp}/uploads", "GEO_PROVIDER": "none",
           "ENABLE_SEMANTIC_MODEL": "false", "DEMO_MODE": "true", "JWT_SECRET": "int-jwt", "AADHAAR_HMAC_KEY": "int-hmac",
           "DATA_ENCRYPTION_KEY": "int-enc", "OFFER_SIGNING_KEY": "int-offer", "ANTHROPIC_API_KEY": ""}
    proc = subprocess.Popen(["node", "--no-warnings", "src/index.js"], cwd=SERVER, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/api/health", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.3)
    else:
        proc.kill()
        raise RuntimeError("backend did not start: " + proc.stdout.read().decode(errors="replace")[-2000:])
    yield base
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(tmp, ignore_errors=True)


def login(base, email):
    c = httpx.Client(base_url=base, timeout=10)
    r = c.post("/api/auth/login", json={"email": email, "password": "Demo@1234"})
    assert r.status_code == 200, r.text
    return c


def test_agent_to_backend_to_recruiter(backend, cfg):
    cfg.allowed_api_base_urls = [backend]
    candidate = login(backend, "arjun@demo.securehire.dev")
    r = candidate.post("/api/assessment/sessions", json={"assessmentId": 1, "consent": True, "extensionVersion": "1.1.0"})
    assert r.status_code == 201, r.text
    s = r.json()
    assert s["agentToken"] and s["agentToken"] != s["sessionToken"]

    manager = SessionManager(cfg, monitor_factory=lambda sess: [])   # monitors replaced; we drive the engine directly
    control, sess = manager.start(s["sessionId"], s["agentToken"], backend)
    assert manager.check_control_token(control) and sess.connection == "online"

    # Observations as the real monitors would produce them
    sess.engine.on_usb_change(UsbChange("connected", usb(r"USB\VID_046D&PID_C077\1", "input"), utcnow()))             # mouse → info
    sess.engine.on_usb_change(UsbChange("connected", usb(r"USB\VID_0781&PID_5567\AA", "storage", service="USBSTOR"), utcnow()))  # → review
    sess.engine.on_process_started(ProcessInfo(4242, "assist.exe", time.time()))                                          # → info + correlation
    sess.engine.on_window(win(77, rect=(1400, 200, 1800, 600), topmost=True, name="assist.exe"),
                          WindowContext(screen=(0, 0, 1920, 1080), assessment=(0, 0, 1920, 1040), new_process=True, new_window=True, allowlisted=False))
    assert sess.client.drain(5.0), sess.client.stats
    assert sess.client.stats.delivered >= 6 and sess.client.stats.rejected == 0, sess.client.stats

    recruiter = login(backend, "recruiter@securehire.dev")
    panel = recruiter.get(f"/api/recruiter/sessions/{s['sessionId']}/security").json()
    types = {e["eventType"]: e for e in panel["events"]}
    assert panel["agent"]["state"] == "connected"
    assert types["USB_DEVICE_CONNECTED"]["reviewStatus"] in ("informational", "needs_review")
    mouse = [e for e in panel["events"] if e["eventType"] == "USB_DEVICE_CONNECTED" and e["details"]["deviceCategory"] == "input"][0]
    assert mouse["reviewStatus"] == "informational"
    assert types["OVERLAY_WINDOW_SUSPECTED"]["reviewStatus"] == "needs_review"
    assert types["CORRELATED_ACTIVITY"]["reviewStatus"] == "needs_review"
    assert "AGENT_STARTED" in types and "AGENT_CONNECTED" in types
    assert all("instance" not in str(e["details"]).lower() and "VID_0781&PID_5567\\AA" not in str(e) for e in panel["events"])

    # Exactly one pending review item in the existing review queue, 0 points until a human decides
    queue = recruiter.get("/api/recruiter/review-queue").json()["items"]
    mine = [i for i in queue if i["name"] == "desktop_activity_review"]
    assert len(mine) == 1

    # Human review with a reason
    overlay = types["OVERLAY_WINDOW_SUSPECTED"]
    rv = recruiter.post(f"/api/recruiter/security-events/{overlay['id']}/review", json={"decision": "reviewed", "reason": "Watched recording; it was the candidate's approved screen magnifier settings panel."})
    assert rv.status_code == 200 and rv.json()["event"]["reviewStatus"] == "reviewed"

    # Candidate can see their own agent status, not other people's
    mine_status = candidate.get(f"/api/assessment/sessions/{s['sessionId']}/desktop").json()
    assert mine_status["agent"]["state"] == "connected"

    # Submitting ends the session server-side; the agent notices on its next heartbeat and stops
    sub = candidate.post(f"/api/assessment/sessions/{s['sessionId']}/submit", json={"answers": {}, "timings": {}})
    assert sub.status_code == 200
    sess._send_heartbeat()
    deadline = time.time() + 5
    while time.time() < deadline and sess.state != "ended":
        time.sleep(0.05)
    assert sess.state == "ended" and sess.ended_reason == "server_ended"
    final = recruiter.get(f"/api/recruiter/sessions/{s['sessionId']}/security").json()
    assert final["agent"]["state"] == "stopped"
    assert not any(e["eventType"] == "AGENT_DISCONNECTED" for e in final["events"]), "normal end is not a disconnection"
