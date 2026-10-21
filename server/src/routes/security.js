// Desktop security agent routes.
//   /api/agent/*                        — the Windows agent, authenticated with the session-scoped agent token
//   /api/assessment/sessions/:id/desktop — the candidate's own agent status (cookie auth)
//   /api/recruiter/...security...        — staff timeline, status and review decisions (cookie auth, staff roles)
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { q, parse } from '../db.js';
import { requireAuth, audit } from '../security.js';
import { ah, bad, HttpError } from '../helpers.js';
import {
  sessionForAgentToken, ingestAgentEvents, recordHeartbeat, agentStatusFor, securityCounts,
  reviewSecurityEvent, formatSecurityEvent, desktopPolicy, REVIEW_DECISIONS,
} from '../services/desktopSecurity.js';

const r = Router();
const staff = requireAuth('recruiter', 'admin');
const agentLimiter = rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false });

/** Agent auth: `Authorization: Bearer <agentToken>` plus the session id. The token never identifies anything else. */
function agentAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const sessionId = req.body?.sessionId || req.query.sessionId;
  const s = sessionForAgentToken(sessionId, token);
  if (!s) return res.status(401).json({ error: 'Invalid agent token or session.' });
  req.agentSession = s;
  next();
}
const isLive = (s) => s.status === 'active' && Date.parse(s.expires_at) > Date.now();

// ---------------------------------------------------------------- agent
r.get('/agent/session', agentLimiter, agentAuth, ah(async (req, res) => {
  const s = req.agentSession;
  const a = q.get('SELECT title, duration_sec FROM assessments WHERE id = ?', s.assessment_id);
  res.json({
    sessionId: s.id, status: isLive(s) ? 'active' : s.status === 'active' ? 'expired' : s.status,
    startedAt: s.started_at, endedAt: s.ended_at, expiresAt: s.expires_at, assessmentTitle: a?.title || null,
    policy: desktopPolicy(), serverTime: new Date().toISOString(),
  });
}));

r.post('/agent/heartbeat', agentLimiter, agentAuth, ah(async (req, res) => {
  const s = req.agentSession;
  if (!isLive(s)) return res.status(409).json({ error: 'Session is not active.', status: s.status });
  res.json({ ok: true, status: 'active', agent: recordHeartbeat(s, req.body || {}), serverTime: new Date().toISOString() });
}));

r.post('/agent/events', agentLimiter, agentAuth, ah(async (req, res) => {
  const s = req.agentSession;
  const events = req.body?.events;
  if (!Array.isArray(events) || events.length === 0) throw bad('events must be a non-empty array.');
  if (events.length > 50) throw bad('At most 50 events per request.');
  // Ended sessions still accept queued events for a short grace period (validated per event).
  if (s.status === 'active' && Date.parse(s.expires_at) < Date.now()) return res.status(410).json({ error: 'Session expired.' });
  res.json(ingestAgentEvents(s, events));
}));

// ---------------------------------------------------------------- candidate (own session only)
r.get('/assessment/sessions/:id/desktop', requireAuth('candidate'), ah(async (req, res) => {
  const s = q.get('SELECT id, user_id FROM assessment_sessions WHERE id = ?', req.params.id);
  if (!s || s.user_id !== req.user.id) throw new HttpError(404, 'Session not found.');
  // Candidates see their agent's connection state and counts — transparency about what was recorded.
  res.json({ agent: agentStatusFor(s.id), counts: securityCounts(s.id), policy: desktopPolicy() });
}));

// ---------------------------------------------------------------- recruiter
r.get('/recruiter/sessions/:id/security', staff, ah(async (req, res) => {
  const s = q.get(`SELECT s.id, s.user_id, s.status, s.started_at, s.ended_at, s.expires_at, s.extension_version, s.score, s.max_score,
                          u.name AS candidate_name, u.email AS candidate_email, a.title
                   FROM assessment_sessions s JOIN users u ON u.id = s.user_id JOIN assessments a ON a.id = s.assessment_id WHERE s.id = ?`, req.params.id);
  if (!s) throw new HttpError(404, 'Session not found.');
  audit(req, 'security.view_session', `user:${s.user_id}`, { sessionId: s.id });
  const events = q.all('SELECT e.*, u.name AS reviewer_name FROM security_events e LEFT JOIN users u ON u.id = e.reviewed_by WHERE e.session_id = ? ORDER BY COALESCE(e.client_ts, e.received_at), e.id', s.id).map(formatSecurityEvent);
  const browser = q.all('SELECT id, source, event_type, details, client_ts, created_at FROM monitoring_events WHERE session_id = ? ORDER BY id', s.id).map((e) => ({ ...e, details: parse(e.details, {}) }));
  res.json({
    session: { id: s.id, status: s.status, startedAt: s.started_at, endedAt: s.ended_at, expiresAt: s.expires_at, title: s.title, extensionVersion: s.extension_version, score: s.score, maxScore: s.max_score },
    candidate: { id: s.user_id, name: s.candidate_name, email: s.candidate_email },
    agent: agentStatusFor(s.id), counts: securityCounts(s.id), events, browserEvents: browser,
  });
}));

r.post('/recruiter/security-events/:id/review', staff, ah(async (req, res) => {
  const { decision, reason } = req.body || {};
  if (!REVIEW_DECISIONS.includes(decision)) throw bad('Decision must be reviewed, dismissed or confirmed_violation.');
  const event = reviewSecurityEvent(Number(req.params.id), req.user, decision, reason);
  audit(req, `security.${decision}`, `user:${event.userId}`, { securityEventId: event.id, eventType: event.eventType, sessionId: event.sessionId, reason: event.reviewReason });
  res.json({ event });
}));

export default r;
