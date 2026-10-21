// Desktop security agent API tests (USB / process / overlay-window events, agent heartbeats, recruiter review).
// Runs against a throwaway SQLite database. Run: npm test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'securehire-sec-test-'));
process.env.DB_FILE = path.join(tmp, 'test.db');
process.env.UPLOAD_DIR = path.join(tmp, 'uploads');
process.env.GEO_PROVIDER = 'none';
process.env.DEMO_MODE = 'true';
process.env.ENABLE_SEMANTIC_MODEL = 'false';
process.env.JWT_SECRET = 'test-jwt'; process.env.AADHAAR_HMAC_KEY = 'test-hmac'; process.env.DATA_ENCRYPTION_KEY = 'test-enc'; process.env.OFFER_SIGNING_KEY = 'test-offer';

const { createApp } = await import('../src/app.js');
const { q, db } = await import('../src/db.js');
const { verhoeffDigit } = await import('../src/security.js');
const { sweepStaleAgents, validateAgentEvent, HEARTBEAT_STALE_MS } = await import('../src/services/desktopSecurity.js');
const bcrypt = (await import('bcryptjs')).default;
const http = await import('node:http');

let server, base;
const validAadhaar = (b11) => b11 + verhoeffDigit(b11);
let keySeq = 0;
const key = () => `evt-${Date.now()}-${++keySeq}`;

function client() {
  let cookie = '';
  const call = async (method, url, body, headers = {}) => {
    const res = await fetch(base + url, { method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
    const sc = res.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
    const type = res.headers.get('content-type') || '';
    return { status: res.status, data: type.includes('json') ? await res.json() : await res.text() };
  };
  return { get: (u, h) => call('GET', u, null, h), post: (u, b, h) => call('POST', u, b ?? {}, h) };
}

before(async () => {
  server = http.createServer(createApp());
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;
  const hash = await bcrypt.hash('Recruit@123', 4);
  q.run("INSERT INTO organizations (name, created_at) VALUES ('Test Org', datetime('now'))");
  q.run("INSERT INTO users (org_id, email, password_hash, role, name, email_verified, created_at) VALUES (1, 'rec@test.dev', ?, 'recruiter', 'Rita Recruiter', 1, datetime('now'))", hash);
  q.run("INSERT INTO jobs (org_id, title, created_at) VALUES (1, 'Engineer', datetime('now'))");
  const a = q.run("INSERT INTO assessments (job_id, title, duration_sec, created_at) VALUES (1, 'Quiz', 600, datetime('now'))").lastInsertRowid;
  q.run(`INSERT INTO assessment_questions (assessment_id, position, type, prompt, options, answer, points) VALUES (?, 1, 'mcq', 'Q1', '["a","b"]', '1', 1)`, a);
});
after(() => {
  server?.closeAllConnections?.(); server?.close();
  try { db.close(); } catch {}
  try { fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {}
});

/** Register a candidate, pass Apply, jump to the assessment stage and start a session. */
async function candidateWithSession(email, aadhaarBase) {
  const c = client();
  const reg = await c.post('/api/auth/register', { name: email.split('@')[0], email, password: 'Passw0rd!', phone: '+919999988888' });
  assert.equal(reg.status, 201, JSON.stringify(reg.data));
  await c.post('/api/me/apply/email/verify', { code: reg.data.devOtp });
  await c.post('/api/me/apply/aadhaar/request', { aadhaar: validAadhaar(aadhaarBase), consent: true });
  await c.post('/api/me/apply/aadhaar/verify', { otp: '123456' });
  const id = (await c.get('/api/auth/me')).data.user.id;
  q.run('UPDATE candidates SET stage_index = 3 WHERE user_id = ?', id);
  const s = await c.post('/api/assessment/sessions', { assessmentId: 1, consent: true, extensionVersion: '1.1.0' });
  assert.equal(s.status, 201, JSON.stringify(s.data));
  return { c, id, s: s.data };
}
async function recruiter() {
  const r = client();
  assert.equal((await r.post('/api/auth/login', { email: 'rec@test.dev', password: 'Recruit@123' })).status, 200);
  return r;
}
const agentHeaders = (s) => ({ authorization: `Bearer ${s.agentToken}` });
const ev = (category, eventType, extra = {}) => ({ category, eventType, timestamp: new Date().toISOString(), idempotencyKey: key(), priority: 'info', ...extra });

test('session start issues a separate agent token; extension token cannot act as agent and vice versa', async () => {
  const { s } = await candidateWithSession('tok@test.dev', '69876543211');
  assert.ok(s.agentToken && s.agentToken !== s.sessionToken, 'distinct agent token');
  const anon = client();
  assert.equal((await anon.get(`/api/agent/session?sessionId=${s.sessionId}`)).status, 401, 'no token');
  assert.equal((await anon.get(`/api/agent/session?sessionId=${s.sessionId}`, { authorization: `Bearer ${s.sessionToken}` })).status, 401, 'extension token rejected');
  assert.equal((await anon.post('/api/events', { sessionId: s.sessionId, eventType: 'TAB_HIDDEN' }, agentHeaders(s))).status, 401, 'agent token rejected by extension endpoint');
  const ok = await anon.get(`/api/agent/session?sessionId=${s.sessionId}`, agentHeaders(s));
  assert.equal(ok.status, 200);
  assert.equal(ok.data.status, 'active');
  assert.ok(!('agentToken' in ok.data) && !JSON.stringify(ok.data).includes(s.agentToken), 'token never echoed');
});

test('heartbeat records connection; USB mouse is informational and never creates a review item', async () => {
  const { s, id } = await candidateWithSession('mouse@test.dev', '69876543212');
  const anon = client();
  const hb = await anon.post('/api/agent/heartbeat', { sessionId: s.sessionId, agentVersion: '1.0.0', platform: 'Windows-11', monitors: { usb: 'active', process: 'active', window: 'active', bogus: 'x' } }, agentHeaders(s));
  assert.equal(hb.status, 200);
  assert.equal(hb.data.agent.state, 'connected');
  assert.deepEqual(hb.data.agent.monitors, { usb: 'active', process: 'active', window: 'active' }, 'unknown monitor keys dropped');
  const r = await anon.post('/api/agent/events', { sessionId: s.sessionId, events: [ev('usb', 'USB_DEVICE_CONNECTED', { ruleId: 'usb.peripheral', explanation: 'A USB input device (mouse/keyboard class) was connected.', details: { deviceCategory: 'input', deviceId: 'h:abc123', vendorId: '046D', productId: 'C52B', path: 'C:\\secret' } })] }, agentHeaders(s));
  assert.equal(r.data.accepted, 1);
  const row = q.get("SELECT * FROM security_events WHERE session_id = ? AND event_type = 'USB_DEVICE_CONNECTED'", s.sessionId);
  assert.equal(row.review_status, 'informational');
  assert.ok(!row.details.includes('secret'), 'unknown detail fields (paths) are dropped');
  assert.equal(q.get("SELECT COUNT(*) AS n FROM trust_signals WHERE candidate_id = ? AND signal_name = 'desktop_activity_review'", id).n, 0, 'no review item, no verdict');
  assert.ok(q.get("SELECT 1 FROM security_events WHERE session_id = ? AND event_type = 'AGENT_CONNECTED'", s.sessionId), 'connection is recorded');
});

test('validation: unknown types, bad categories, oversized batches, replays and out-of-session timestamps are rejected', async () => {
  const { s } = await candidateWithSession('valid@test.dev', '69876543213');
  const anon = client();
  const post = (events) => anon.post('/api/agent/events', { sessionId: s.sessionId, events }, agentHeaders(s));
  const bad = await post([ev('usb', 'RUN_COMMAND'), ev('shell', 'PROCESS_STARTED'), ev('process', 'PROCESS_STARTED', { idempotencyKey: 'x' }), ev('process', 'PROCESS_STARTED', { priority: 'critical' }), ev('process', 'PROCESS_STARTED', { timestamp: '2001-01-01T00:00:00Z' }), ev('agent', 'AGENT_DISCONNECTED')]);
  assert.equal(bad.status, 200);
  assert.equal(bad.data.accepted, 0);
  assert.equal(bad.data.rejected, 6, JSON.stringify(bad.data));
  const tooMany = await post(Array.from({ length: 51 }, () => ev('process', 'PROCESS_STARTED')));
  assert.equal(tooMany.status, 400);
  assert.equal((await post([])).status, 400);
  const oversized = await anon.post('/api/agent/events', { sessionId: s.sessionId, events: [ev('process', 'PROCESS_STARTED', { explanation: 'x'.repeat(300_000) })] }, agentHeaders(s));
  assert.equal(oversized.status, 413, 'body over the JSON limit');
  const one = ev('process', 'PROCESS_STARTED', { details: { processName: 'notepad.exe', pid: 4242, commandLine: 'notepad secret.txt' } });
  assert.equal((await post([one])).data.accepted, 1);
  const replay = await post([one]);
  assert.equal(replay.data.accepted, 0); assert.equal(replay.data.duplicates, 1, 'replayed idempotency key is a duplicate');
  const stored = q.get('SELECT details FROM security_events WHERE idempotency_key = ?', one.idempotencyKey);
  assert.ok(!stored.details.includes('secret'), 'command lines are never stored');
});

test('suspicious window → review item (pending, 0 points) with browser context; legitimate topmost window stays informational', async () => {
  const { s, id } = await candidateWithSession('window@test.dev', '69876543214');
  const anon = client();
  // A legitimate always-on-top window (allowlisted screen reader) — informational only.
  await anon.post('/api/agent/events', { sessionId: s.sessionId, events: [ev('window', 'WINDOW_OBSERVED', { ruleId: 'window.topmost_allowlisted', explanation: 'Always-on-top window from an allowlisted application.', details: { processName: 'nvda.exe', topmost: true, allowlisted: true } })] }, agentHeaders(s));
  assert.equal(q.get("SELECT COUNT(*) AS n FROM trust_signals WHERE candidate_id = ? AND signal_name = 'desktop_activity_review'", id).n, 0);
  // Browser focus loss right before the overlay appears is attached as context.
  await anon.post('/api/events', { sessionId: s.sessionId, events: [{ sessionId: s.sessionId, eventType: 'WINDOW_BLUR', timestamp: new Date().toISOString(), idempotencyKey: key() }] }, { authorization: `Bearer ${s.sessionToken}` });
  const r = await anon.post('/api/agent/events', { sessionId: s.sessionId, events: [ev('window', 'OVERLAY_WINDOW_SUSPECTED', { priority: 'review', ruleId: 'window.overlay_candidate', explanation: 'Potential overlay activity: a newly launched application created a small always-on-top window overlapping the assessment. Manual review required.', details: { processName: 'helper.exe', topmost: true, newProcess: true, overlapPercent: 64, screenAreaPercent: 8 } })] }, agentHeaders(s));
  assert.equal(r.data.accepted, 1);
  const row = q.get("SELECT * FROM security_events WHERE session_id = ? AND event_type = 'OVERLAY_WINDOW_SUSPECTED'", s.sessionId);
  assert.equal(row.review_status, 'needs_review', 'observation for review, not a verdict');
  assert.equal(JSON.parse(row.details).browserFocusEventsWithin30s, 1);
  const sig = q.get("SELECT * FROM trust_signals WHERE candidate_id = ? AND signal_name = 'desktop_activity_review'", id);
  assert.equal(sig.status, 'pending_review'); assert.equal(sig.session_ref, s.sessionId);
  const scores = (await (await recruiter()).get(`/api/recruiter/candidates/${id}`)).data.scores;
  assert.equal(scores.stages.assessment.confirmed, 0, 'nothing confirmed automatically');
  // A second review event in the same session does not create a second review item.
  await anon.post('/api/agent/events', { sessionId: s.sessionId, events: [ev('correlation', 'CORRELATED_ACTIVITY', { priority: 'review', details: { categories: ['usb', 'window'] } })] }, agentHeaders(s));
  assert.equal(q.get("SELECT COUNT(*) AS n FROM trust_signals WHERE candidate_id = ? AND signal_name = 'desktop_activity_review'", id).n, 1);
});

test('agent disconnection is reported transparently; reconnection is recorded; session end is not a disconnection', async () => {
  const { s, c } = await candidateWithSession('disc@test.dev', '69876543215');
  const anon = client();
  await anon.post('/api/agent/heartbeat', { sessionId: s.sessionId, agentVersion: '1.0.0' }, agentHeaders(s));
  q.run('UPDATE agent_status SET last_heartbeat_at = ? WHERE session_id = ?', new Date(Date.now() - HEARTBEAT_STALE_MS - 5000).toISOString(), s.sessionId);
  sweepStaleAgents();
  const disc = q.get("SELECT * FROM security_events WHERE session_id = ? AND event_type = 'AGENT_DISCONNECTED'", s.sessionId);
  assert.equal(disc.review_status, 'needs_review');
  assert.match(disc.explanation, /network loss|sleeping|closed/);
  sweepStaleAgents();
  assert.equal(q.get("SELECT COUNT(*) AS n FROM security_events WHERE session_id = ? AND event_type = 'AGENT_DISCONNECTED'", s.sessionId).n, 1, 'reported once');
  const mine = await c.get(`/api/assessment/sessions/${s.sessionId}/desktop`);
  assert.equal(mine.data.agent.state, 'disconnected', 'candidate sees the disconnection too');
  await anon.post('/api/agent/heartbeat', { sessionId: s.sessionId }, agentHeaders(s));
  assert.ok(q.get("SELECT 1 FROM security_events WHERE session_id = ? AND event_type = 'AGENT_RECONNECTED'", s.sessionId));
  await c.post(`/api/assessment/sessions/${s.sessionId}/submit`, { answers: {}, timings: {} });
  assert.equal(q.get('SELECT state FROM agent_status WHERE session_id = ?', s.sessionId).state, 'stopped');
  q.run('UPDATE agent_status SET last_heartbeat_at = ? WHERE session_id = ?', new Date(Date.now() - 600_000).toISOString(), s.sessionId);
  sweepStaleAgents();
  assert.equal(q.get("SELECT COUNT(*) AS n FROM security_events WHERE session_id = ? AND event_type = 'AGENT_DISCONNECTED'", s.sessionId).n, 1, 'no new disconnection after the session ended');
  assert.equal((await anon.post('/api/agent/heartbeat', { sessionId: s.sessionId }, agentHeaders(s))).status, 409, 'ended session rejects heartbeats');
  // Queued events from before the end are still accepted during the grace period.
  const late = await anon.post('/api/agent/events', { sessionId: s.sessionId, events: [ev('process', 'PROCESS_STARTED', { timestamp: new Date(Date.now() - 2000).toISOString() })] }, agentHeaders(s));
  assert.equal(late.data.accepted, 1);
});

test('authorization: candidates cannot read other sessions or recruiter data; recruiters review with reasons', async () => {
  const a = await candidateWithSession('alice@test.dev', '69876543216');
  const b = await candidateWithSession('bob@test.dev', '69876543217');
  const anon = client();
  await anon.post('/api/agent/events', { sessionId: a.s.sessionId, events: [ev('usb', 'USB_DEVICE_CONNECTED', { priority: 'review', ruleId: 'usb.storage', details: { deviceCategory: 'storage' } })] }, agentHeaders(a.s));
  // Agent token for session B cannot write into session A.
  assert.equal((await anon.post('/api/agent/events', { sessionId: a.s.sessionId, events: [ev('process', 'PROCESS_STARTED')] }, agentHeaders(b.s))).status, 401);
  assert.equal((await b.c.get(`/api/assessment/sessions/${a.s.sessionId}/desktop`)).status, 404, 'other candidate session hidden');
  assert.equal((await b.c.get(`/api/recruiter/sessions/${a.s.sessionId}/security`)).status, 403);
  const evId = q.get("SELECT id FROM security_events WHERE session_id = ? AND event_type = 'USB_DEVICE_CONNECTED'", a.s.sessionId).id;
  assert.equal((await b.c.post(`/api/recruiter/security-events/${evId}/review`, { decision: 'dismissed', reason: 'trying to hide it' })).status, 403, 'candidate cannot review');
  const rec = await recruiter();
  const panel = await rec.get(`/api/recruiter/sessions/${a.s.sessionId}/security`);
  assert.equal(panel.status, 200);
  assert.equal(panel.data.candidate.name, 'alice');
  assert.ok(panel.data.events.some((e) => e.eventType === 'USB_DEVICE_CONNECTED'));
  assert.equal((await rec.post(`/api/recruiter/security-events/${evId}/review`, { decision: 'confirmed_violation', reason: 'short' })).status, 400, 'violation needs a real explanation');
  assert.equal((await rec.post(`/api/recruiter/security-events/${evId}/review`, { decision: 'approve', reason: 'whatever reason' })).status, 400);
  const ok = await rec.post(`/api/recruiter/security-events/${evId}/review`, { decision: 'dismissed', reason: 'Candidate said it was a charging cable for their phone; confirmed on camera.' });
  assert.equal(ok.status, 200);
  assert.equal(ok.data.event.reviewStatus, 'dismissed');
  assert.equal(ok.data.event.reviewerName, 'Rita Recruiter');
  assert.equal((await rec.post(`/api/recruiter/security-events/${evId}/review`, { decision: 'reviewed', reason: 'again please' })).status, 409, 'decisions are final');
  assert.ok(q.get("SELECT 1 FROM audit_logs WHERE action = 'security.dismissed'"), 'review is audit-logged');
  const live = await rec.get('/api/recruiter/live');
  const row = live.data.sessions.find((x) => x.id === a.s.sessionId);
  assert.ok(row.agent && row.security, 'live monitor includes agent status and counts');
});

test('validateAgentEvent is pure and strips non-whitelisted details', () => {
  const session = { started_at: new Date(Date.now() - 60_000).toISOString(), ended_at: null };
  const v = validateAgentEvent({ category: 'window', eventType: 'WINDOW_OBSERVED', timestamp: new Date().toISOString(), idempotencyKey: 'abcdefgh1', details: { title: 'Bank – Personal', topmost: true, width: 300, signals: ['topmost', 7] } }, session);
  assert.ok(v.value);
  assert.deepEqual(v.value.details, { width: 300, topmost: true, signals: ['topmost'] }, 'titles never stored');
});
