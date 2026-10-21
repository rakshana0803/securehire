import { Router } from 'express';
import { q, now, parse, getSetting, setSetting } from '../db.js';
import { requireAuth, audit } from '../security.js';
import { ah, bad, HttpError, candidateRow } from '../helpers.js';
import { computeScores, signalsFor, reviewSignal, STAGES, DEFAULT_STAGE_WEIGHTS } from '../trust.js';
import { latestResumeReport } from '../services/resumeVerify.js';
import { interviewSummary } from './interview.js';
import { buildReport } from '../services/report.js';
import { semanticStatus } from '../services/semantic.js';
import { runRetention } from '../services/retention.js';
import { agentStatusFor, securityCounts } from '../services/desktopSecurity.js';

const r = Router();
const staff = requireAuth('recruiter', 'admin');

function candidateCard(c) {
  const scores = computeScores(c.user_id);
  return {
    id: c.user_id, name: c.name, email: c.email, jobTitle: c.job_title, stageIndex: c.stage_index,
    stage: c.stage_index >= 7 ? 'hired' : STAGES[c.stage_index], overall: scores.overall, band: scores.band,
    pendingReview: scores.pendingReview, stageScores: Object.fromEntries(STAGES.map(s => [s, scores.stages[s].score])),
    lastActivity: q.get('SELECT MAX(created_at) AS t FROM trust_signals WHERE candidate_id = ?', c.user_id)?.t || c.updated_at, isDemo: !!c.is_demo,
  };
}
const allCandidates = () => q.all('SELECT c.*, u.name, u.email, u.is_demo, j.title AS job_title FROM candidates c JOIN users u ON u.id = c.user_id LEFT JOIN jobs j ON j.id = c.job_id ORDER BY c.updated_at DESC').map(candidateCard);

r.get('/recruiter/overview', staff, ah(async (req, res) => {
  const cands = allCandidates();
  const byStage = STAGES.map((s, i) => ({ stage: s, count: cands.filter(c => c.stageIndex === i).length })).concat([{ stage: 'hired', count: cands.filter(c => c.stageIndex >= 7).length }]);
  const bands = ['high', 'moderate', 'review', 'risk'].map(b => ({ band: b, count: cands.filter(c => c.band.key === b).length }));
  const alerts = q.all(`SELECT s.*, u.name AS candidate_name FROM trust_signals s JOIN users u ON u.id = s.candidate_id WHERE s.status = 'pending_review' ORDER BY s.created_at DESC LIMIT 8`);
  const events = q.all(`SELECT e.*, u.name AS candidate_name FROM monitoring_events e JOIN users u ON u.id = e.user_id ORDER BY e.id DESC LIMIT 10`).map(e => ({ ...e, details: parse(e.details, {}) }));
  const stageAvg = Object.fromEntries(STAGES.map(s => { const v = cands.map(c => c.stageScores[s]).filter(x => x != null); return [s, v.length ? Math.round(v.reduce((a, b) => a + b, 0) / v.length) : null]; }));
  res.json({
    kpis: {
      totalCandidates: cands.length,
      averageTrust: cands.length ? Math.round(cands.reduce((a, c) => a + c.overall, 0) / cands.length) : 0,
      openAlerts: q.get("SELECT COUNT(*) AS n FROM trust_signals WHERE status = 'pending_review'").n,
      activeAssessments: q.get("SELECT COUNT(*) AS n FROM assessment_sessions WHERE status = 'active'").n,
      desktopReview: q.get("SELECT COUNT(*) AS n FROM security_events WHERE review_status = 'needs_review'").n,
      liveInterviews: q.get("SELECT COUNT(*) AS n FROM interviews WHERE status = 'live'").n,
      openAppeals: q.get("SELECT COUNT(*) AS n FROM appeals WHERE status = 'open'").n,
    },
    byStage, bands, stageAvg, alerts, events, needsReview: cands.filter(c => c.pendingReview > 0).slice(0, 6),
  });
}));

r.get('/recruiter/candidates', staff, ah(async (req, res) => res.json({ candidates: allCandidates() })));

r.get('/recruiter/candidates/:id', staff, ah(async (req, res) => {
  const id = Number(req.params.id);
  const c = candidateRow(id);
  if (!c) throw new HttpError(404, 'Candidate not found.');
  audit(req, 'candidate.view', `user:${id}`);
  const anchor = q.get('SELECT model, liveness, created_at, retention_until, id_photo_descriptor_enc IS NOT NULL AS has_id_photo FROM face_anchors WHERE user_id = ?', id);
  const interviews = q.all('SELECT * FROM interviews WHERE candidate_id = ? ORDER BY id DESC', id).map(iv => ({ ...iv, rubric: parse(iv.rubric), verification: parse(iv.verification), summary: interviewSummary(iv) }));
  const sessions = q.all('SELECT id, assessment_id, status, score, max_score, started_at, ended_at, extension_version FROM assessment_sessions WHERE user_id = ? ORDER BY started_at DESC', id)
    .map(s => ({ ...s, agent: agentStatusFor(s.id), security: securityCounts(s.id), events: q.all('SELECT id, source, event_type, details, client_ts, created_at FROM monitoring_events WHERE session_id = ? ORDER BY id', s.id).map(e => ({ ...e, details: parse(e.details, {}) })) }));
  res.json({
    profile: { id, name: c.name, email: c.email, phone: c.phone, emailVerified: !!c.email_verified, stageIndex: c.stage_index, appliedAt: c.applied_at, appliedEmail: c.applied_email, appliedPhone: c.applied_phone, holdReason: c.hold_reason, isDemo: !!c.is_demo, job: q.get('SELECT title, location FROM jobs WHERE id = ?', c.job_id) },
    scores: computeScores(id),
    history: q.all('SELECT overall, stage_scores, reason, created_at FROM score_history WHERE candidate_id = ? ORDER BY id', id).map(h => ({ ...h, stage_scores: parse(h.stage_scores, {}) })),
    signals: signalsFor(id),
    identity: q.get('SELECT aadhaar_masked, provider, record_name, record_dob, verified_at FROM identities WHERE user_id = ?', id),
    anchor: anchor ? { ...anchor, liveness: parse(anchor.liveness) } : null,
    faceChecks: q.all('SELECT stage, session_ref, distance, faces, result, created_at FROM face_checks WHERE user_id = ? ORDER BY id DESC LIMIT 60', id),
    resume: latestResumeReport(id),
    sessions, interviews,
    ip: q.all('SELECT stage, session_ref, ip_masked, city, region, country, lat, lng, geo_source, changed, created_at FROM ip_observations WHERE user_id = ? ORDER BY id', id),
    locations: q.all('SELECT stage, session_ref, source, lat, lng, accuracy, place, created_at FROM location_events WHERE user_id = ? ORDER BY id', id).map(l => ({ ...l, place: parse(l.place) })),
    offers: q.all('SELECT id, title, salary, status, issued_at, expires_at, accepted_at, acceptance FROM offers WHERE candidate_id = ? ORDER BY issued_at DESC', id).map(o => ({ ...o, acceptance: parse(o.acceptance) })),
    onboarding: (() => { const ob = q.get('SELECT * FROM onboarding WHERE candidate_id = ?', id); return ob ? { ...ob, checklist: parse(ob.checklist, {}) } : null; })(),
    documents: q.all('SELECT id, kind, filename, status, verification, created_at FROM documents WHERE user_id = ?', id).map(d => ({ ...d, verification: parse(d.verification) })),
    consents: q.all('SELECT purpose, granted, created_at, withdrawn_at FROM consents WHERE user_id = ? ORDER BY id', id),
    appeals: q.all('SELECT * FROM appeals WHERE candidate_id = ? ORDER BY id DESC', id),
    audit: q.all('SELECT a.*, u.name AS actor_name FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id WHERE a.target = ? ORDER BY a.id DESC LIMIT 100', `user:${id}`).map(a => ({ ...a, details: parse(a.details) })),
  });
}));

r.get('/recruiter/review-queue', staff, ah(async (req, res) => {
  const items = q.all(`SELECT s.*, u.name AS candidate_name FROM trust_signals s JOIN users u ON u.id = s.candidate_id WHERE s.status = 'pending_review' ORDER BY s.score_delta ASC, s.created_at DESC`)
    .map(s => ({ id: s.id, candidateId: s.candidate_id, candidateName: s.candidate_name, stage: s.stage, name: s.signal_name, label: s.label, weight: s.score_delta, evidence: parse(s.evidence, {}), createdAt: s.created_at, source: s.source }));
  const recent = q.all(`SELECT s.*, u.name AS candidate_name, r.name AS reviewer_name FROM trust_signals s JOIN users u ON u.id = s.candidate_id LEFT JOIN users r ON r.id = s.reviewed_by WHERE s.status IN ('confirmed','dismissed') ORDER BY s.reviewed_at DESC LIMIT 20`);
  const appeals = q.all(`SELECT a.*, u.name AS candidate_name, s.label AS signal_label FROM appeals a JOIN users u ON u.id = a.candidate_id LEFT JOIN trust_signals s ON s.id = a.signal_id ORDER BY a.status = 'open' DESC, a.id DESC LIMIT 50`);
  const heldOffers = q.all(`SELECT o.id, o.title, o.candidate_id, u.name AS candidate_name, o.acceptance FROM offers o JOIN users u ON u.id = o.candidate_id WHERE o.status = 'held_for_review'`).map(o => ({ ...o, acceptance: parse(o.acceptance) }));
  res.json({ items, recent, appeals, heldOffers });
}));

r.post('/recruiter/signals/:id/review', staff, ah(async (req, res) => {
  const { decision, comment } = req.body || {};
  if (!['confirm', 'dismiss'].includes(decision)) throw bad('Decision must be confirm or dismiss.');
  if (!comment || comment.trim().length < 5) throw bad('Please add a short comment explaining your decision.');
  const out = reviewSignal(Number(req.params.id), req.user, decision, comment.trim());
  audit(req, `signal.${decision}`, `user:${out.signal.candidateId}`, { signalId: out.signal.id, label: out.signal.label, comment });
  res.json(out);
}));

r.post('/recruiter/candidates/:id/clarification', staff, ah(async (req, res) => {
  const { message, signalId } = req.body || {};
  if (!message || message.length < 5) throw bad('Write the clarification request.');
  const a = q.run("INSERT INTO appeals (candidate_id, signal_id, message, status, created_at) VALUES (?,?,?,?,?)", Number(req.params.id), signalId || null, `[Recruiter request] ${message}`, 'clarification_requested', now());
  audit(req, 'candidate.request_clarification', `user:${req.params.id}`, { message, signalId });
  res.status(201).json({ id: a.lastInsertRowid });
}));

r.post('/recruiter/appeals/:id/respond', staff, ah(async (req, res) => {
  const { response, status = 'resolved' } = req.body || {};
  const a = q.get('SELECT * FROM appeals WHERE id = ?', req.params.id);
  if (!a) throw new HttpError(404, 'Not found');
  q.run('UPDATE appeals SET response = ?, status = ?, resolved_at = ? WHERE id = ?', response || null, status, now(), a.id);
  audit(req, 'appeal.respond', `user:${a.candidate_id}`, { appealId: a.id, status });
  res.json({ ok: true });
}));

// Live assessment monitoring (polling or ws 'monitoring' events)
r.get('/recruiter/live', staff, ah(async (req, res) => {
  const sessions = q.all(`SELECT s.id, s.user_id, s.status, s.started_at, s.ended_at, s.extension_version, s.score, s.max_score, u.name AS candidate_name, a.title
    FROM assessment_sessions s JOIN users u ON u.id = s.user_id JOIN assessments a ON a.id = s.assessment_id ORDER BY s.started_at DESC LIMIT 30`).map(s => {
    const counts = Object.fromEntries(q.all('SELECT event_type, COUNT(*) AS n FROM monitoring_events WHERE session_id = ? GROUP BY event_type', s.id).map(x => [x.event_type, x.n]));
    const lastFace = q.get('SELECT result, distance, created_at FROM face_checks WHERE session_ref = ? ORDER BY id DESC LIMIT 1', s.id);
    const flags = q.all("SELECT id, label, status FROM trust_signals WHERE session_ref = ? AND status IN ('pending_review','confirmed')", s.id);
    return { ...s, counts, lastFace, flags, agent: agentStatusFor(s.id), security: securityCounts(s.id) };
  });
  const interviews = q.all(`SELECT i.id, i.status, i.room_id, i.scheduled_at, u.name AS candidate_name, i.candidate_id FROM interviews i JOIN users u ON u.id = i.candidate_id WHERE i.status != 'completed' ORDER BY i.scheduled_at`);
  res.json({ sessions, interviews });
}));
r.get('/recruiter/sessions/:id/events', staff, ah(async (req, res) => {
  res.json({ events: q.all('SELECT * FROM monitoring_events WHERE session_id = ? ORDER BY id', req.params.id).map(e => ({ ...e, details: parse(e.details, {}) })) });
}));
// Compatibility alias used by the standalone extension dashboard
r.get('/alerts', staff, ah(async (req, res) => {
  res.json({ alerts: q.all("SELECT s.id, s.candidate_id, u.name AS candidate, s.label, s.status, s.created_at, s.session_ref FROM trust_signals s JOIN users u ON u.id = s.candidate_id WHERE s.status = 'pending_review' ORDER BY s.created_at DESC") });
}));

r.get('/reports/:id.pdf', requireAuth(), ah(async (req, res) => {
  const id = Number(req.params.id);
  if (req.user.role === 'candidate' && req.user.id !== id) throw new HttpError(403, 'Not allowed.');
  if (!candidateRow(id)) throw new HttpError(404, 'Candidate not found.');
  audit(req, 'report.download', `user:${id}`);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="securehire-report-${id}.pdf"`);
  buildReport(id, res);
}));

r.get('/jobs', requireAuth(), ah(async (req, res) => res.json({ jobs: q.all('SELECT * FROM jobs ORDER BY id') })));
r.post('/jobs', staff, ah(async (req, res) => {
  const { title, location, description, hiringType } = req.body || {};
  if (!title) throw bad('Title is required.');
  const rr = q.run('INSERT INTO jobs (org_id, title, location, description, hiring_type, created_by, created_at) VALUES (1,?,?,?,?,?,?)', title, location || null, description || null, hiringType || 'remote', req.user.id, now());
  audit(req, 'job.create', `job:${rr.lastInsertRowid}`);
  res.status(201).json({ id: rr.lastInsertRowid });
}));

// ------------------------------------------------------------------ admin
const admin = requireAuth('admin');
r.get('/admin/settings', admin, ah(async (req, res) => {
  res.json({
    weights: q.all('SELECT * FROM signal_weights ORDER BY stage, kind DESC, signal_name'),
    stageWeights: getSetting('stage_weights', DEFAULT_STAGE_WEIGHTS),
    retention: getSetting('retention_days', {}),
    allowlist: getSetting('assessment_allowlist', []),
    monitoring: getSetting('monitoring_policy', {}),
    requiredChecks: getSetting('required_checks', {}),
    integrations: { aadhaar: 'mock', digilocker: 'mock', apaar: 'mock', employment: 'mock', semanticModel: semanticStatus() },
  });
}));
r.put('/admin/settings', admin, ah(async (req, res) => {
  const { weights, stageWeights, retention, allowlist, monitoring, requiredChecks } = req.body || {};
  if (Array.isArray(weights)) for (const w of weights) {
    const d = Number(w.delta);
    if (!Number.isInteger(d) || Math.abs(d) > 100) throw bad(`Invalid weight for ${w.signal_name}`);
    const cur = q.get('SELECT kind FROM signal_weights WHERE signal_name = ?', w.signal_name);
    if (!cur) continue;
    if ((cur.kind === 'positive' && d < 0) || (cur.kind === 'risk' && d > 0) || (cur.kind === 'context' && d !== 0)) throw bad(`${w.signal_name}: sign does not match its kind`);
    q.run('UPDATE signal_weights SET delta = ? WHERE signal_name = ?', d, w.signal_name);
  }
  if (stageWeights) setSetting('stage_weights', Object.fromEntries(STAGES.map(s => [s, Math.max(0, Number(stageWeights[s]) || 0)])));
  if (retention) setSetting('retention_days', retention);
  if (Array.isArray(allowlist)) setSetting('assessment_allowlist', allowlist.map(String).slice(0, 20));
  if (monitoring) setSetting('monitoring_policy', monitoring);
  if (requiredChecks) setSetting('required_checks', requiredChecks);
  audit(req, 'admin.settings_update', 'settings', { keys: Object.keys(req.body || {}) });
  res.json({ ok: true });
}));
r.get('/admin/users', admin, ah(async (req, res) => res.json({ users: q.all('SELECT id, email, name, role, status, email_verified, is_demo, created_at FROM users ORDER BY id') })));
r.patch('/admin/users/:id', admin, ah(async (req, res) => {
  const { role, status } = req.body || {};
  if (Number(req.params.id) === req.user.id) throw bad('You cannot change your own account here.');
  if (role && !['candidate', 'recruiter', 'admin'].includes(role)) throw bad('Invalid role.');
  if (status && !['active', 'disabled'].includes(status)) throw bad('Invalid status.');
  if (role) q.run('UPDATE users SET role = ? WHERE id = ?', role, req.params.id);
  if (status) q.run('UPDATE users SET status = ? WHERE id = ?', status, req.params.id);
  audit(req, 'admin.user_update', `user:${req.params.id}`, { role, status });
  res.json({ ok: true });
}));
r.get('/admin/audit', admin, ah(async (req, res) => {
  res.json({ logs: q.all('SELECT a.*, u.name AS actor_name FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id ORDER BY a.id DESC LIMIT 300').map(a => ({ ...a, details: parse(a.details) })) });
}));
r.post('/admin/retention/run', admin, ah(async (req, res) => {
  const out = runRetention();
  audit(req, 'admin.retention_run', 'retention', out);
  res.json(out);
}));
r.get('/admin/system', admin, ah(async (req, res) => {
  const count = (t) => q.get(`SELECT COUNT(*) AS n FROM ${t}`).n;
  res.json({ semanticModel: semanticStatus(), counts: Object.fromEntries(['users', 'trust_signals', 'monitoring_events', 'face_anchors', 'resumes', 'ip_observations', 'location_events', 'audit_logs'].map(t => [t, count(t)])) });
}));

export default r;
