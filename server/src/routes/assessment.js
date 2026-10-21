import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { q, now, json, parse, getSetting } from '../db.js';
import { requireAuth, randomToken, sha256, randomId, audit } from '../security.js';
import { ah, bad, HttpError, advanceStage, requireStage, grantConsent, needConsent, STAGE_INDEX } from '../helpers.js';
import { addSignal } from '../trust.js';
import { observeIp } from '../services/network.js';
import { logEvent } from '../services/continuity.js';
import { toStaff } from '../realtime.js';
import { desktopPolicy, onSessionEnded } from '../services/desktopSecurity.js';

const r = Router();

// Event vocabulary accepted from the SecureHire extension and the assessment page.
export const EXTENSION_EVENTS = ['SESSION_START', 'SESSION_END', 'TAB_HIDDEN', 'TAB_VISIBLE', 'WINDOW_BLUR', 'WINDOW_FOCUS',
  'FULLSCREEN_ENTER', 'FULLSCREEN_EXIT', 'COPY_ATTEMPT', 'CUT_ATTEMPT', 'PASTE_ATTEMPT', 'CONTEXT_MENU', 'NEW_TAB_OPENED',
  'TAB_SWITCH', 'SESSION_INTERRUPTED', 'DEVTOOLS_SHORTCUT', 'PRINT_ATTEMPT'];
const PAGE_EVENTS = [...EXTENSION_EVENTS, 'CAMERA_OFF', 'MIC_OFF', 'CAMERA_ON'];
const FOCUS_TYPES = ['TAB_HIDDEN', 'WINDOW_BLUR', 'FULLSCREEN_EXIT', 'NEW_TAB_OPENED', 'TAB_SWITCH'];

const sessionTokenOk = (session, token) => session && token && sha256(token) === session.token_hash;

function sessionCounts(sessionId) {
  const rows = q.all('SELECT event_type, COUNT(*) AS n FROM monitoring_events WHERE session_id = ? GROUP BY event_type', sessionId);
  return Object.fromEntries(rows.map(x => [x.event_type, x.n]));
}

/** Rule: ≥3 tab/focus/fullscreen events within 2 minutes → one review flag per session (never automatic penalty). */
function applyIntegrityRules(session) {
  const since = new Date(Date.now() - 120_000).toISOString();
  const n = q.get(`SELECT COUNT(*) AS n FROM monitoring_events WHERE session_id = ? AND created_at >= ? AND event_type IN (${FOCUS_TYPES.map(() => '?').join(',')})`, session.id, since, ...FOCUS_TYPES).n;
  const pastes = q.get("SELECT COUNT(*) AS n FROM monitoring_events WHERE session_id = ? AND event_type = 'PASTE_ATTEMPT'", session.id).n;
  if (n >= 3 || pastes >= 3) {
    addSignal(session.user_id, 'assessment_integrity_review', { sessionRef: session.id, source: 'assessment-monitor',
      label: n >= 3 ? `${n} tab/focus changes within 2 minutes` : `${pastes} paste attempts during assessment`,
      evidence: { counts: sessionCounts(session.id), note: 'Needs review — could be notifications, accessibility tools or connectivity. Not a cheating finding.' } });
  }
}

async function ingestEvent(req, session, ev, source) {
  const type = String(ev.eventType || ev.type || '').toUpperCase();
  const allowed = source === 'extension' ? EXTENSION_EVENTS : PAGE_EVENTS;
  if (!allowed.includes(type)) return { error: `Unsupported event type ${type}` };
  const details = ev.details && typeof ev.details === 'object' ? Object.fromEntries(Object.entries(ev.details).slice(0, 10).map(([k, v]) => [k, typeof v === 'string' ? v.slice(0, 200) : v])) : {};
  delete details.clipboard; delete details.text; // never store clipboard contents
  const out = logEvent({ sessionId: session.id, userId: session.user_id, stage: 'assessment', source, type, details,
    idempotencyKey: ev.idempotencyKey ? String(ev.idempotencyKey).slice(0, 100) : null, clientTs: ev.timestamp ? String(ev.timestamp).slice(0, 40) : null });
  if (out.inserted && (FOCUS_TYPES.includes(type) || type === 'PASTE_ATTEMPT')) applyIntegrityRules(session);
  return out;
}

// ------------------------------------------------------------------ candidate: list & start
r.get('/assessments', requireAuth('candidate'), ah(async (req, res) => {
  const list = q.all('SELECT a.id, a.title, a.duration_sec, (SELECT COUNT(*) FROM assessment_questions WHERE assessment_id = a.id) AS questions FROM assessments a ORDER BY a.id');
  const sessions = q.all('SELECT id, assessment_id, status, score, max_score, started_at, ended_at FROM assessment_sessions WHERE user_id = ? ORDER BY started_at DESC', req.user.id);
  res.json({ assessments: list, sessions, allowlist: getSetting('assessment_allowlist', []), desktopAgent: desktopPolicy() });
}));

r.post('/assessment/sessions', requireAuth('candidate'), ah(async (req, res) => {
  requireStage(req.user.id, STAGE_INDEX.assessment);
  const { assessmentId, consent, extensionVersion } = req.body || {};
  if (consent !== true) throw new HttpError(428, 'Monitoring consent is required to start this assessment.');
  grantConsent(req.user.id, 'monitoring'); grantConsent(req.user.id, 'camera_mic');
  const a = q.get('SELECT * FROM assessments WHERE id = ?', assessmentId);
  if (!a) throw bad('Assessment not found.');
  const done = q.get("SELECT id FROM assessment_sessions WHERE user_id = ? AND assessment_id = ? AND status = 'submitted'", req.user.id, a.id);
  if (done) throw new HttpError(409, 'You have already completed this assessment.');
  // close any abandoned active session
  q.run("UPDATE assessment_sessions SET status = 'abandoned', ended_at = ? WHERE user_id = ? AND status = 'active'", now(), req.user.id);
  const id = randomId('AS-', 6);
  const token = randomToken(32);
  // Separate token for the optional Windows desktop agent: scoped to this session, accepted only by /api/agent/*.
  const agentToken = randomToken(32);
  q.run(`INSERT INTO assessment_sessions (id, user_id, assessment_id, token_hash, agent_token_hash, status, consent, started_at, expires_at, extension_version)
         VALUES (?,?,?,?,?,?,?,?,?,?)`, id, req.user.id, a.id, sha256(token), sha256(agentToken), 'active', 1, now(), new Date(Date.now() + (a.duration_sec + 900) * 1000).toISOString(), extensionVersion || null);
  const ip = await observeIp(req, req.user.id, 'assessment', id);
  q.run('UPDATE assessment_sessions SET ip_hash = (SELECT ip_hash FROM ip_observations WHERE user_id = ? ORDER BY id DESC LIMIT 1) WHERE id = ?', req.user.id, id);
  logEvent({ sessionId: id, userId: req.user.id, stage: 'assessment', source: 'server', type: 'SESSION_START', details: { extensionVersion: extensionVersion || null, ip: ip.ipMasked } });
  const questions = q.all('SELECT id, position, type, prompt, options, points FROM assessment_questions WHERE assessment_id = ? ORDER BY position', a.id).map(x => ({ ...x, options: parse(x.options, null) }));
  audit(req, 'assessment.start', `session:${id}`);
  toStaff({ type: 'session', action: 'started', sessionId: id, candidateId: req.user.id });
  // sessionToken is short-lived and scoped to this one session; it is handed to the extension, never a shared key.
  res.status(201).json({ sessionId: id, sessionToken: token, agentToken, desktopAgentPolicy: desktopPolicy(), expiresAt: new Date(Date.now() + (a.duration_sec + 900) * 1000).toISOString(), assessment: { id: a.id, title: a.title, durationSec: a.duration_sec }, questions });
}));

// Page-side events (face, camera, fullscreen from the page itself) — authenticated with the candidate session.
r.post('/assessment/sessions/:id/client-event', requireAuth('candidate'), ah(async (req, res) => {
  const s = q.get('SELECT * FROM assessment_sessions WHERE id = ? AND user_id = ?', req.params.id, req.user.id);
  if (!s || s.status !== 'active') throw new HttpError(409, 'Session is not active.');
  const out = await ingestEvent(req, s, req.body || {}, 'page');
  if (out.error) throw bad(out.error);
  res.json({ ok: true, duplicate: !!out.duplicate });
}));

// ------------------------------------------------------------------ EXTENSION ENDPOINT (compatible: POST /api/events)
const eventsLimiter = rateLimit({ windowMs: 60_000, limit: 240, standardHeaders: true, legacyHeaders: false });
r.post('/events', eventsLimiter, ah(async (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const body = req.body || {};
  const events = Array.isArray(body.events) ? body.events.slice(0, 50) : [body];
  const sessionId = body.sessionId || events[0]?.sessionId;
  const s = q.get('SELECT * FROM assessment_sessions WHERE id = ?', sessionId || '');
  if (!sessionTokenOk(s, token)) return res.status(401).json({ error: 'Invalid or missing session token.' });
  if (s.status !== 'active' && !events.every(e => (e.eventType || e.type) === 'SESSION_END')) return res.status(409).json({ error: 'Session is not active.' });
  if (Date.parse(s.expires_at) < Date.now()) return res.status(410).json({ error: 'Session expired.' });
  const ipCheck = await observeIp(req, s.user_id, 'assessment', s.id, { onlyIfChanged: true }); // IP_CHANGE detection (contextual)
  if (ipCheck.changed) logEvent({ sessionId: s.id, userId: s.user_id, stage: 'assessment', source: 'server', type: 'IP_CHANGE', details: { current: ipCheck.ipMasked } });
  const results = [];
  for (const ev of events) {
    if (ev.sessionId && ev.sessionId !== s.id) { results.push({ error: 'sessionId mismatch' }); continue; }
    results.push(await ingestEvent(req, s, ev, 'extension'));
  }
  res.json({ accepted: results.filter(x => x.inserted).length, duplicates: results.filter(x => x.duplicate).length, errors: results.filter(x => x.error).map(x => x.error), counts: sessionCounts(s.id) });
}));

// Status: usable by extension (Bearer session token) or the candidate page.
r.get('/assessment/sessions/:id/status', ah(async (req, res) => {
  const s = q.get('SELECT * FROM assessment_sessions WHERE id = ?', req.params.id);
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!s || !(sessionTokenOk(s, token) || (req.user && (req.user.id === s.user_id || req.user.role !== 'candidate')))) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ sessionId: s.id, status: s.status, counts: sessionCounts(s.id), expiresAt: s.expires_at });
}));

// ------------------------------------------------------------------ submit & end
function scoreAnswers(assessmentId, answers) {
  let score = 0, max = 0;
  const detail = [];
  for (const qn of q.all('SELECT * FROM assessment_questions WHERE assessment_id = ? ORDER BY position', assessmentId)) {
    max += qn.points;
    const a = answers?.[qn.id];
    let got = 0;
    if (qn.type === 'mcq') got = String(a) === String(qn.answer) ? qn.points : 0;
    else if (qn.type === 'code') {
      const keywords = parse(qn.answer, []);
      const text = String(a || '').toLowerCase();
      const hits = keywords.filter(k => text.includes(k.toLowerCase())).length;
      got = keywords.length ? Math.round((hits / keywords.length) * qn.points * 10) / 10 : 0;
    }
    score += got;
    detail.push({ questionId: qn.id, correct: got >= qn.points, points: got });
  }
  return { score, max, detail };
}

r.post('/assessment/sessions/:id/submit', requireAuth('candidate'), ah(async (req, res) => {
  const s = q.get('SELECT * FROM assessment_sessions WHERE id = ? AND user_id = ?', req.params.id, req.user.id);
  if (!s) throw new HttpError(404, 'Session not found.');
  if (s.status !== 'active') throw new HttpError(409, 'This session has already ended.');
  const { answers = {}, timings = {}, autoSubmitted = false } = req.body || {};
  const { score, max, detail } = scoreAnswers(s.assessment_id, answers);
  q.run("UPDATE assessment_sessions SET status = 'submitted', ended_at = ?, score = ?, max_score = ?, answers = ?, timings = ? WHERE id = ?",
    now(), score, max, json(answers), json(timings), s.id);
  logEvent({ sessionId: s.id, userId: s.user_id, stage: 'assessment', source: 'server', type: 'SESSION_END', details: { autoSubmitted, score, max } });
  onSessionEnded(s.id);

  // Behaviour analytics (rule-based). High performance alone is never treated as cheating.
  const times = detail.map(d => Number(timings[d.questionId]) || null).filter(Boolean);
  const fastCorrect = detail.filter(d => d.correct && Number(timings[d.questionId]) > 0 && Number(timings[d.questionId]) < 3000).length;
  const sorted = [...times].sort((a, b) => a - b);
  const median = sorted.length ? sorted[Math.floor(sorted.length / 2)] : null;
  const variance = times.length > 2 ? times.reduce((a, t) => a + (t - times.reduce((x, y) => x + y, 0) / times.length) ** 2, 0) / times.length : null;
  const anomalies = [];
  if (fastCorrect >= 3) anomalies.push(`${fastCorrect} correct answers in under 3 seconds each`);
  if (variance !== null && median && Math.sqrt(variance) / median < 0.08 && times.length >= 4) anomalies.push('Near-identical time spent on every question');
  if (anomalies.length) addSignal(s.user_id, 'assessment_behavior_anomaly', { sessionRef: s.id, source: 'assessment-analytics', evidence: { anomalies, medianMs: median, score, max, note: 'Timing patterns only — review together with other evidence.' } });

  const counts = sessionCounts(s.id);
  const totalEvents = Object.entries(counts).filter(([k]) => !['SESSION_START', 'SESSION_END'].includes(k)).reduce((a, [, n]) => a + n, 0);
  addSignal(s.user_id, 'monitoring_event', { sessionRef: s.id, source: 'assessment-monitor', label: `Assessment monitoring summary: ${totalEvents} event(s)`, evidence: { counts } });
  const risks = q.get("SELECT COUNT(*) AS n FROM trust_signals WHERE candidate_id = ? AND session_ref = ? AND status IN ('pending_review','confirmed')", s.user_id, s.id).n;
  const faceOk = q.get("SELECT COUNT(*) AS n FROM face_checks WHERE user_id = ? AND session_ref = ? AND result = 'match'", s.user_id, s.id).n;
  if (!risks && faceOk >= 1) addSignal(s.user_id, 'clean_session', { sessionRef: null, source: 'assessment-monitor', evidence: { sessionId: s.id, faceChecksMatched: faceOk, events: counts, score: `${score}/${max}` } });
  advanceStage(s.user_id, STAGE_INDEX.interview);
  toStaff({ type: 'session', action: 'submitted', sessionId: s.id, candidateId: s.user_id });
  res.json({ score, max, percent: max ? Math.round((score / max) * 100) : 0, flagsRaised: risks + (anomalies.length ? 1 : 0), counts });
}));

export default r;
