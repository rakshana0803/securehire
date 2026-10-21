// End-to-end API tests against a throwaway SQLite database. Run: npm test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'securehire-test-'));
process.env.DB_FILE = path.join(tmp, 'test.db');
process.env.UPLOAD_DIR = path.join(tmp, 'uploads');
process.env.GEO_PROVIDER = 'none';
process.env.DEMO_MODE = 'true';
process.env.JWT_SECRET = 'test-jwt'; process.env.AADHAAR_HMAC_KEY = 'test-hmac'; process.env.DATA_ENCRYPTION_KEY = 'test-enc'; process.env.OFFER_SIGNING_KEY = 'test-offer';
process.env.ENABLE_SEMANTIC_MODEL = process.env.ENABLE_SEMANTIC_MODEL || 'true';

const { createApp } = await import('../src/app.js');
const { q, db } = await import('../src/db.js');
const { verhoeffDigit } = await import('../src/security.js');
const { attachRealtime } = await import('../src/realtime.js');
const bcrypt = (await import('bcryptjs')).default;
const http = await import('node:http');

let server, base;
const validAadhaar = (b11) => b11 + verhoeffDigit(b11);
const descriptor = (seed, jitter = 0) => Array.from({ length: 128 }, (_, i) => Math.sin(seed * 13.37 + i) * 0.2 + (jitter ? Math.cos(i * 7 + seed) * jitter : 0));

/** Minimal cookie-jar client */
function client() {
  let cookie = '';
  const call = async (method, url, body, headers = {}) => {
    const isForm = body instanceof FormData;
    const res = await fetch(base + url, { method, headers: { ...(body && !isForm ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...headers }, body: body ? (isForm ? body : JSON.stringify(body)) : undefined });
    const sc = res.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
    const type = res.headers.get('content-type') || '';
    const data = type.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer());
    return { status: res.status, data };
  };
  return { get: (u, h) => call('GET', u, null, h), post: (u, b, h) => call('POST', u, b ?? {}, h), put: (u, b) => call('PUT', u, b) };
}

before(async () => {
  const app = createApp();
  server = http.createServer(app); attachRealtime(server);
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;
  const hash = await bcrypt.hash('Recruit@123', 4);
  q.run("INSERT INTO organizations (name, created_at) VALUES ('Test Org', datetime('now'))");
  q.run("INSERT INTO users (org_id, email, password_hash, role, name, email_verified, created_at) VALUES (1, 'rec@test.dev', ?, 'recruiter', 'Rita Recruiter', 1, datetime('now'))", hash);
  q.run("INSERT INTO users (org_id, email, password_hash, role, name, email_verified, created_at) VALUES (1, 'admin@test.dev', ?, 'admin', 'Adam Admin', 1, datetime('now'))", hash);
  q.run("INSERT INTO jobs (org_id, title, created_at) VALUES (1, 'Engineer', datetime('now'))");
  const a = q.run("INSERT INTO assessments (job_id, title, duration_sec, created_at) VALUES (1, 'Quiz', 600, datetime('now'))").lastInsertRowid;
  q.run(`INSERT INTO assessment_questions (assessment_id, position, type, prompt, options, answer, points) VALUES (?, 1, 'mcq', 'Q1', '["a","b"]', '1', 1)`, a);
  q.run(`INSERT INTO assessment_questions (assessment_id, position, type, prompt, options, answer, points) VALUES (?, 2, 'mcq', 'Q2', '["a","b"]', '0', 1)`, a);
});
   after(() => {
     server?.closeAllConnections?.();
     server?.close();
     try { db.close(); } catch {}
     try { fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {}
   });
async function registerCandidate(email, name = 'Test Candidate') {
  const c = client();
  const r = await c.post('/api/auth/register', { name, email, password: 'Passw0rd!', phone: '+919999988888' });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return { c, user: r.data.user, devOtp: r.data.devOtp };
}
async function completeApply(c, devOtp, aadhaar) {
  assert.equal((await c.post('/api/me/apply/email/verify', { code: devOtp })).status, 200);
  const req = await c.post('/api/me/apply/aadhaar/request', { aadhaar, consent: true });
  assert.equal(req.status, 200, JSON.stringify(req.data));
  assert.equal((await c.post('/api/me/apply/aadhaar/verify', { otp: '123456' })).status, 200);
}

test('auth: register, login, role-based access', async () => {
  const { c } = await registerCandidate('auth@test.dev');
  assert.equal((await c.get('/api/auth/me')).data.user.role, 'candidate');
  assert.equal((await c.get('/api/recruiter/candidates')).status, 403, 'candidate cannot reach recruiter API');
  const anon = client();
  assert.equal((await anon.get('/api/me/overview')).status, 401);
  assert.equal((await anon.post('/api/auth/login', { email: 'rec@test.dev', password: 'wrong' })).status, 401);
  assert.equal((await anon.post('/api/auth/login', { email: 'rec@test.dev', password: 'Recruit@123' })).status, 200);
  assert.equal((await anon.get('/api/recruiter/candidates')).status, 200);
  assert.equal((await anon.get('/api/admin/settings')).status, 403, 'recruiter is not admin');
});

test('apply: email OTP + mock Aadhaar; plaintext Aadhaar never stored; duplicate identity blocked and flagged', async () => {
  const aadhaar = validAadhaar('28765432101');
  const a = await registerCandidate('apply1@test.dev', 'Asha One');
  assert.equal((await a.c.post('/api/me/apply/email/verify', { code: '000000' })).status, 400);
  await completeApply(a.c, a.devOtp, aadhaar);
  const ov = (await a.c.get('/api/me/overview')).data;
  assert.equal(ov.profile.stageIndex, 1, 'apply stage completed');
  assert.ok(ov.signals.some((s) => s.name === 'email_verified' && s.status === 'verified'));
  assert.ok(ov.signals.some((s) => s.name === 'aadhaar_verified' && s.status === 'verified'));
  const dbText = fs.readFileSync(process.env.DB_FILE).toString('latin1') + (fs.existsSync(process.env.DB_FILE + '-wal') ? fs.readFileSync(process.env.DB_FILE + '-wal').toString('latin1') : '');
  assert.ok(!dbText.includes(aadhaar), 'full Aadhaar number must not appear anywhere in the database');
  assert.equal(ov.identity.aadhaar_masked, `XXXX-XXXX-${aadhaar.slice(-4)}`);

  const b = await registerCandidate('apply2@test.dev', 'Bala Two');
  await b.c.post('/api/me/apply/email/verify', { code: b.devOtp });
  const dup = await b.c.post('/api/me/apply/aadhaar/request', { aadhaar, consent: true });
  assert.equal(dup.status, 409);
  const ovb = (await b.c.get('/api/me/overview')).data;
  const flag = ovb.signals.find((s) => s.name === 'duplicate_identity');
  assert.equal(flag.status, 'pending_review');
  assert.equal(ovb.scores.overall, ovb.scores.overall, 'score unaffected by pending flag');
  assert.equal(ovb.profile.stageIndex, 0);
  assert.equal(q.get('SELECT status FROM users WHERE id = ?', ovb.profile.id).status, 'active', 'never auto-rejected');
  assert.equal((await b.c.post('/api/me/apply/aadhaar/request', { aadhaar: '123456789012', consent: true })).status, 400, 'checksum enforced');
});

test('trust engine: pending = 0 points; confirm applies; dismiss does not; contextual never', async () => {
  const { addSignal, computeScores, reviewSignal } = await import('../src/trust.js');
  const { user } = await registerCandidate('trust@test.dev');
  const id = user.id;
  addSignal(id, 'email_verified'); addSignal(id, 'aadhaar_verified');
  const s0 = computeScores(id);
  assert.equal(s0.stages.apply.score, 100);
  const flag = addSignal(id, 'duplicate_identity');
  addSignal(id, 'ip_change', { stage: 'apply' });
  assert.equal(computeScores(id).stages.apply.score, 100, 'pending and contextual signals do not change the score');
  assert.ok(computeScores(id).ifConfirmed < 100, 'projection shows impact if confirmed');
  assert.equal(computeScores(id).reviewStatus, 'review_required');
  reviewSignal(flag.id, { id: 1 }, 'confirm', 'verified duplicate');
  assert.equal(computeScores(id).stages.apply.score, 70, 'confirmed risk subtracts its weight');
  const flag2 = addSignal(id, 'application_pattern');
  reviewSignal(flag2.id, { id: 1 }, 'dismiss', 'benign');
  assert.equal(computeScores(id).stages.apply.score, 70);
  assert.throws(() => reviewSignal(flag2.id, { id: 1 }, 'confirm', 'again'), /pending/);
  assert.ok(q.get('SELECT COUNT(*) AS n FROM score_history WHERE candidate_id = ?', id).n >= 3, 'history recorded');
});

test('identity: anchor enrolment, duplicate face search, continuity rule raises review after 2 mismatches', async () => {
  const { c, devOtp } = await registerCandidate('face@test.dev', 'Farah Face');
  await completeApply(c, devOtp, validAadhaar('39876543210'));
  const d = descriptor(1);
  const bad = await c.post('/api/me/identity/enroll', { descriptor: d, faces: 1, liveness: { passed: false, challenges: [] }, consent: true });
  assert.equal(bad.status, 400);
  const ok = await c.post('/api/me/identity/enroll', { descriptor: d, idPhotoDescriptor: descriptor(1, 0.005), faces: 1, liveness: { passed: true, challenges: ['blink'], durationMs: 5000 }, consent: true });
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  assert.equal(ok.data.idMatch.result, 'match');
  const row = q.get('SELECT descriptor_enc FROM face_anchors WHERE user_id = ?', (await c.get('/api/auth/me')).data.user.id);
  assert.ok(!row.descriptor_enc.includes('0.'), 'descriptor is encrypted at rest');
  // a second person enrolling with a near-identical face → possible duplicate flag
  const other = await registerCandidate('face2@test.dev', 'Twin Two');
  await completeApply(other.c, other.devOtp, validAadhaar('49876543210'));
  await other.c.post('/api/me/identity/enroll', { descriptor: descriptor(1, 0.003), faces: 1, liveness: { passed: true, challenges: [] }, consent: true });
  const ov = (await other.c.get('/api/me/overview')).data;
  assert.ok(ov.signals.some((s) => s.name === 'possible_duplicate_face' && s.status === 'pending_review'));
  // continuity during assessment
  const me = (await c.get('/api/auth/me')).data.user.id;
  q.run('UPDATE candidates SET stage_index = 3 WHERE user_id = ?', me);
  const r1 = await c.post('/api/me/face/verify', { stage: 'assessment', sessionRef: 'AS-TEST', faces: 1, descriptor: descriptor(1) });
  assert.equal(r1.data.result, 'match');
  await c.post('/api/me/face/verify', { stage: 'assessment', sessionRef: 'AS-TEST', faces: 1, descriptor: descriptor(99) });
  const r3 = await c.post('/api/me/face/verify', { stage: 'assessment', sessionRef: 'AS-TEST', faces: 1, descriptor: descriptor(77) });
  assert.equal(r3.data.result, 'mismatch');
  assert.equal(r3.data.flagged, true);
  const flags = q.all("SELECT * FROM trust_signals WHERE candidate_id = ? AND signal_name = 'assessment_face_mismatch'", me);
  assert.equal(flags.length, 1); assert.equal(flags[0].status, 'pending_review');
});

test('resume: extraction + APAAR comparison yields explainable graduation-year mismatch', async () => {
  const { c, devOtp } = await registerCandidate('resume@test.dev', 'Arjun Kumar');
  await completeApply(c, devOtp, validAadhaar('59876543210'));
  const me = (await c.get('/api/auth/me')).data.user.id;
  q.run('UPDATE candidates SET stage_index = 2 WHERE user_id = ?', me);
  const form = new FormData();
  form.append('file', new Blob([fs.readFileSync(new URL('../../docs/sample-resumes/arjun_kumar.txt', import.meta.url))], { type: 'text/plain' }), 'arjun.txt');
  form.append('apaarId', '100000000002'); form.append('consent', 'true');
  const r = await c.post('/api/me/resume', form);
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const year = r.data.claims.find((x) => x.field === 'Graduation year');
  assert.equal(year.status, 'MISMATCH'); assert.equal(year.resume_value, '2024'); assert.equal(year.verified_value, '2026');
  assert.match(year.explanation, /differs from the verified academic record/);
  const degree = r.data.claims.find((x) => x.field === 'Degree');
  assert.equal(degree.status, 'MATCH', `degree similarity ${degree.similarity} via ${degree.method}`);
  const ov = (await c.get('/api/me/overview')).data;
  assert.ok(ov.signals.some((s) => s.name === 'credential_mismatch' && s.status === 'pending_review'));
  assert.equal(ov.profile.stageIndex, 3);
});

test('assessment + extension endpoint: token auth, idempotency, integrity rule, submit', async () => {
  const { c, devOtp } = await registerCandidate('assess@test.dev', 'Esha Exam');
  await completeApply(c, devOtp, validAadhaar('69876543210'));
  const me = (await c.get('/api/auth/me')).data.user.id;
  q.run('UPDATE candidates SET stage_index = 3 WHERE user_id = ?', me);
  assert.equal((await c.post('/api/assessment/sessions', { assessmentId: 1, consent: false })).status, 428, 'consent required');
  const s = (await c.post('/api/assessment/sessions', { assessmentId: 1, consent: true, extensionVersion: '1.0.0' })).data;
  assert.ok(s.sessionToken && s.sessionId); assert.ok(!('answer' in s.questions[0]), 'answers not leaked');
  const anon = client();
  assert.equal((await anon.post('/api/events', { sessionId: s.sessionId, eventType: 'TAB_HIDDEN' })).status, 401);
  assert.equal((await anon.post('/api/events', { sessionId: s.sessionId, eventType: 'TAB_HIDDEN' }, { authorization: 'Bearer wrong' })).status, 401);
  const auth = { authorization: `Bearer ${s.sessionToken}` };
  const ev = (t, k) => ({ sessionId: s.sessionId, eventType: t, timestamp: new Date().toISOString(), idempotencyKey: k, details: { clipboard: 'SECRET' } });
  const r1 = await anon.post('/api/events', { sessionId: s.sessionId, events: [ev('TAB_HIDDEN', 'k1'), ev('TAB_HIDDEN', 'k1')] }, auth);
  assert.equal(r1.data.accepted, 1); assert.equal(r1.data.duplicates, 1);
  const stored = q.get("SELECT details FROM monitoring_events WHERE idempotency_key = 'k1'");
  assert.ok(!stored.details.includes('SECRET'), 'clipboard contents are dropped');
  await anon.post('/api/events', { sessionId: s.sessionId, events: [ev('WINDOW_BLUR', 'k2'), ev('FULLSCREEN_EXIT', 'k3')] }, auth);
  const flag = q.get("SELECT * FROM trust_signals WHERE candidate_id = ? AND signal_name = 'assessment_integrity_review'", me);
  assert.equal(flag?.status, 'pending_review', 'three focus events in 2 minutes raise a review item');
  assert.equal((await anon.post('/api/events', { sessionId: s.sessionId, eventType: 'BOGUS' }, auth)).data.errors.length, 1);
  const st = await anon.get(`/api/assessment/sessions/${s.sessionId}/status`, auth);
  assert.equal(st.data.counts.TAB_HIDDEN, 1);
  const qs = s.questions;
  const sub = await c.post(`/api/assessment/sessions/${s.sessionId}/submit`, { answers: { [qs[0].id]: '1', [qs[1].id]: '0' }, timings: { [qs[0].id]: 9000, [qs[1].id]: 15000 } });
  assert.equal(sub.data.score, 2);
  assert.equal((await anon.post('/api/events', { sessionId: s.sessionId, eventType: 'TAB_HIDDEN' }, auth)).status, 409, 'closed session rejects events');
});

test('location: denial is neutral; >200 km jump is contextual only', async () => {
  const { c, devOtp } = await registerCandidate('geo@test.dev', 'Gita Geo');
  await completeApply(c, devOtp, validAadhaar('79876543210'));
  const me = (await c.get('/api/auth/me')).data.user.id;
  const before = (await c.get('/api/me/overview')).data.scores.overall;
  await c.post('/api/me/location/denied', { stage: 'interview' });
  assert.equal((await c.post('/api/me/location', { stage: 'assessment', lat: 13.08, lng: 80.27, accuracy: 20 })).status, 428, 'location needs consent');
  await c.post('/api/me/consents', { purpose: 'location', granted: true });
  await c.post('/api/me/location', { stage: 'assessment', lat: 13.08, lng: 80.27, accuracy: 20 });
  await c.post('/api/me/location', { stage: 'interview', lat: 28.61, lng: 77.2, accuracy: 30 });
  const sig = q.get("SELECT * FROM trust_signals WHERE candidate_id = ? AND signal_name = 'location_change'", me);
  assert.equal(sig.status, 'contextual');
  assert.equal((await c.get('/api/me/overview')).data.scores.overall, before, 'score unchanged');
});

test('offer: signed record, QR verification, tamper detection, identity-checked acceptance, PDF report', async () => {
  const { c, devOtp } = await registerCandidate('offer@test.dev', 'Omar Offer');
  const aadhaar = validAadhaar('89876543210');
  await completeApply(c, devOtp, aadhaar);
  await c.post('/api/me/identity/enroll', { descriptor: descriptor(5), faces: 1, liveness: { passed: true, challenges: [] }, consent: true });
  const me = (await c.get('/api/auth/me')).data.user.id;
  q.run('UPDATE candidates SET stage_index = 5 WHERE user_id = ?', me);
  const rec = client(); await rec.post('/api/auth/login', { email: 'rec@test.dev', password: 'Recruit@123' });
  const o = await rec.post('/api/offers', { candidateId: me, title: 'Engineer', salary: '10 LPA' });
  assert.equal(o.status, 201, JSON.stringify(o.data));
  const pub = client();
  const sigFrag = new URL(o.data.verifyUrl).searchParams.get('s');
  assert.equal((await pub.get(`/api/public/offers/${o.data.id}?s=${sigFrag}`)).data.verification.status, 'issued');
  assert.equal((await pub.get(`/api/public/offers/${o.data.id}?s=deadbeefdeadbeef`)).data.verification.status, 'tampered');
  assert.equal((await pub.get('/api/public/offers/OFR-NOPE')).data.verification.status, 'unknown');
  q.run("UPDATE offers SET salary = '99 LPA' WHERE id = ?", o.data.id);
  assert.equal((await pub.get(`/api/public/offers/${o.data.id}`)).data.verification.status, 'tampered', 'edited DB record detected');
  q.run("UPDATE offers SET salary = '10 LPA' WHERE id = ?", o.data.id);
  // a different face at acceptance → held for review (not rejected)
  const held = await c.post(`/api/me/offer/${o.data.id}/accept`, { descriptor: descriptor(42), faces: 1, livenessPassed: true, aadhaar, aadhaarOtp: '123456' });
  assert.equal(held.status, 202); assert.equal(held.data.heldForReview, true);
  assert.ok(q.get("SELECT 1 FROM trust_signals WHERE candidate_id = ? AND signal_name = 'identity_substitution' AND status = 'pending_review'", me));
  await rec.post(`/api/offers/${o.data.id}/release-hold`, { decision: 'retry', comment: 'Lighting issue, retry' });
  const okAcc = await c.post(`/api/me/offer/${o.data.id}/accept`, { descriptor: descriptor(5, 0.002), faces: 1, livenessPassed: true, aadhaar, aadhaarOtp: '123456' });
  assert.equal(okAcc.data.accepted, true);
  const pdf = await rec.get(`/api/reports/${me}.pdf`);
  assert.equal(pdf.status, 200); assert.equal(pdf.data.subarray(0, 4).toString(), '%PDF');
  assert.equal((await client().get(`/api/reports/${me}.pdf`)).status, 401);
});

test('admin: weights validation, retention deletes expired biometrics with audit trail', async () => {
  const adm = client(); await adm.post('/api/auth/login', { email: 'admin@test.dev', password: 'Recruit@123' });
  assert.equal((await adm.put('/api/admin/settings', { weights: [{ signal_name: 'face_mismatch', delta: 10 }] })).status, 400, 'risk weight cannot be positive');
  assert.equal((await adm.put('/api/admin/settings', { weights: [{ signal_name: 'email_verified', delta: 6 }] })).status, 200);
  q.run("UPDATE face_anchors SET retention_until = '2000-01-01T00:00:00.000Z'");
  const r = await adm.post('/api/admin/retention/run');
  assert.ok(r.data.deleted.faceAnchors >= 1);
  assert.ok(q.get("SELECT 1 FROM audit_logs WHERE action = 'retention.delete'"));
});
