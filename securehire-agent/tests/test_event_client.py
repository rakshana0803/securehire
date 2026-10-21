"""Delivery client: acknowledgement-based delivery, retries, network loss, auth loss, bounded queue."""
import logging
import time

import httpx

from agent.event_client import ApiError, SecureHireClient
from agent.models import SecurityEvent
from agent.security_logger import redact


def ev(t="PROCESS_STARTED", cat="process"):
    return SecurityEvent(category=cat, event_type=t, priority="info", rule_id="r", explanation="x")


def test_successful_delivery_counts_only_acknowledged_events(make_client, fake_api):
    c = make_client()
    for _ in range(3):
        c.enqueue(ev())
    assert c.flush_once() is True
    assert c.stats.delivered == 3 and c.stats.pending == 0 and len(fake_api.events) == 3


def test_network_interruption_keeps_events_and_never_reports_false_success(make_client, fake_api):
    c = make_client()
    c.enqueue(ev())
    fake_api.fail_mode, fake_api.fail_count = "network", 2
    assert c.flush_once() is False
    assert c.stats.delivered == 0 and c.stats.pending == 1 and c.stats.online is False
    assert "Cannot reach SecureHire" in c.stats.last_error
    assert c.flush_once() is False
    assert c.flush_once() is True, "recovers once the network is back"
    assert c.stats.delivered == 1 and c.stats.pending == 0 and c.stats.online is True


def test_server_errors_and_rate_limits_are_retried_in_background(make_client, fake_api):
    c = make_client()
    fake_api.fail_mode, fake_api.fail_count = "500", 3
    c.enqueue(ev())
    c.start()
    end = time.time() + 3
    while time.time() < end and c.stats.delivered == 0:
        time.sleep(0.02)
    c.close()
    assert c.stats.delivered == 1 and fake_api.requests >= 4


def test_duplicates_from_retries_are_harmless(make_client, fake_api):
    c = make_client()
    e = ev()
    c.enqueue(e)
    c.flush_once()
    c.enqueue(e)            # e.g. resent after a timeout whose response was lost
    c.flush_once()
    assert len(fake_api.events) == 1 and c.stats.duplicates == 1


def test_rejected_events_are_not_retried(make_client, fake_api):
    c = make_client()
    c.enqueue(ev("BOGUS"))
    c.enqueue(ev())
    c.flush_once()
    assert c.stats.rejected == 1 and c.stats.delivered == 1 and c.stats.pending == 0
    assert "BOGUS" in c.stats.recent_rejections[0]


def test_unauthorised_token_stops_delivery(cfg, fake_api):
    stopped = []
    c = SecureHireClient(cfg, "http://127.0.0.1:4000", fake_api.session_id, "wrong-token-xxxxxxxxxxxxxxxx", transport=httpx.MockTransport(fake_api.handler))
    c.on_stopped = stopped.append
    c.enqueue(ev())
    assert c.flush_once() is False
    assert stopped == ["auth"] and c.stats.delivered == 0
    try:
        c.verify_session()
        assert False
    except ApiError as e:
        assert e.kind == "auth"


def test_queue_is_bounded_and_overflow_is_counted(cfg, make_client):
    cfg.queue_max_events = 5
    c = make_client()
    for _ in range(8):
        c.enqueue(ev())
    assert c.stats.pending == 5 and c.stats.dropped == 3


def test_backoff_grows_and_is_capped(make_client, cfg):
    c = make_client()
    c._failures = 0
    first = c.backoff_seconds()
    c._failures = 20
    assert first <= cfg.retry_base_seconds * 1.25 and c.backoff_seconds() <= cfg.retry_max_seconds * 1.25


def test_tokens_are_redacted_from_logs(caplog):
    assert "abc123" not in redact("Authorization: Bearer abc123def456")
    assert "s3cretvalue" not in redact('{"agentToken": "s3cretvalue99"}')
    assert "[redacted]" in redact("controlToken=AAAABBBBCCCC")
    logging.getLogger("x").info("ok")
