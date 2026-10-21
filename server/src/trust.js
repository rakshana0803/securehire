import { q, now, json, parse, getSetting, setSetting } from './db.js';
import { toStaff, toUser } from './realtime.js';

export const STAGES = ['apply', 'identity', 'resume', 'assessment', 'interview', 'offer', 'onboarding'];
export const STAGE_LABELS = {
  apply: 'Application', identity: 'Identity', resume: 'Resume', assessment: 'Assessment',
  interview: 'Interview', offer: 'Offer', onboarding: 'Onboarding',
};

/** Default signal catalogue (admin-editable). kind: positive → verified, risk → pending_review, context → contextual. */
export const DEFAULT_WEIGHTS = [
  // Apply
  ['email_verified', 'apply', 'positive', 5, 'Email ownership verified'],
  ['aadhaar_verified', 'apply', 'positive', 15, 'Aadhaar OTP verified (MOCK provider)'],
  ['duplicate_identity', 'apply', 'risk', -30, 'Identity already linked to another account'],
  ['application_pattern', 'apply', 'risk', -5, 'Unusual application pattern'],
  ['ip_observed', 'apply', 'context', 0, 'Network observation'],
  // Identity
  ['liveness_passed', 'identity', 'positive', 10, 'Basic liveness challenge passed'],
  ['face_match', 'identity', 'positive', 10, 'Live face matches ID photo'],
  ['digilocker_verified', 'identity', 'positive', 10, 'DigiLocker document verified (MOCK)'],
  ['face_mismatch', 'identity', 'risk', -25, 'Live face does not match ID photo'],
  ['possible_duplicate_face', 'identity', 'risk', -30, 'Face similar to another candidate'],
  ['liveness_failed', 'identity', 'risk', -10, 'Liveness challenge not completed'],
  ['identity_data_mismatch', 'identity', 'risk', -10, 'Name/DOB differs from identity record'],
  // Resume
  ['academic_verified', 'resume', 'positive', 10, 'Academic record matches resume'],
  ['employment_verified', 'resume', 'positive', 5, 'Employment confirmed (MOCK provider)'],
  ['credential_mismatch', 'resume', 'risk', -20, 'Credential conflicts with verified record'],
  ['date_conflict', 'resume', 'risk', -10, 'Impossible or conflicting dates'],
  ['duplicate_resume', 'resume', 'risk', -20, 'Resume highly similar to another candidate'],
  // Assessment
  ['clean_session', 'assessment', 'positive', 10, 'Assessment completed with consistent identity'],
  ['assessment_face_mismatch', 'assessment', 'risk', -30, 'Different face detected during assessment'],
  ['multiple_faces', 'assessment', 'risk', -10, 'More than one face in frame'],
  ['assessment_integrity_review', 'assessment', 'risk', -10, 'Repeated tab/focus changes during assessment'],
  ['assessment_behavior_anomaly', 'assessment', 'risk', -10, 'Unusual answer timing pattern'],
  ['desktop_activity_review', 'assessment', 'risk', -10, 'Desktop activity needs review (USB / app / overlay window)'],
  ['monitoring_event', 'assessment', 'context', 0, 'Assessment monitoring event'],
  ['ip_change', 'assessment', 'context', 0, 'IP address changed'],
  ['location_change', 'assessment', 'context', 0, 'Location changed between checkpoints'],
  // Interview
  ['interview_identity_consistent', 'interview', 'positive', 10, 'Face and voice consistent during interview'],
  ['interview_identity_inconsistent', 'interview', 'risk', -25, 'Face inconsistent with identity anchor'],
  ['voice_mismatch', 'interview', 'risk', -15, 'Voice differs from enrolled sample (EXPERIMENTAL)'],
  ['screen_share_stopped', 'interview', 'risk', -5, 'Screen sharing stopped during interview'],
  ['interview_multiple_faces', 'interview', 'risk', -10, 'More than one face during interview'],
  // Offer
  ['offer_identity_consistent', 'offer', 'positive', 10, 'Fresh identity check passed at offer acceptance'],
  ['identity_substitution', 'offer', 'risk', -40, 'Possible identity substitution at offer'],
  ['contact_change', 'offer', 'risk', -10, 'Contact details changed since application'],
  // Onboarding
  ['onboarding_verified', 'onboarding', 'positive', 10, 'Day-one identity verified'],
  ['onboarding_documents_verified', 'onboarding', 'positive', 5, 'Joining documents verified (MOCK)'],
  ['onboarding_identity_inconsistent', 'onboarding', 'risk', -40, 'Joining person inconsistent with hired candidate'],
];
const REPEATABLE = new Set(['employment_verified', 'monitoring_event', 'ip_change', 'location_change', 'ip_observed']);

export const DEFAULT_STAGE_WEIGHTS = { apply: 10, identity: 20, resume: 15, assessment: 20, interview: 15, offer: 10, onboarding: 10 };

export function ensureWeights() {
  for (const [name, stage, kind, delta, label] of DEFAULT_WEIGHTS) {
    q.run('INSERT OR IGNORE INTO signal_weights (signal_name, stage, kind, delta, label, repeatable) VALUES (?,?,?,?,?,?)',
      name, stage, kind, delta, label, REPEATABLE.has(name) ? 1 : 0);
  }
  if (!getSetting('stage_weights')) setSetting('stage_weights', DEFAULT_STAGE_WEIGHTS);
}

export function band(score) {
  if (score >= 80) return { key: 'high', label: 'High Trust' };
  if (score >= 60) return { key: 'moderate', label: 'Moderate Trust' };
  if (score >= 40) return { key: 'review', label: 'Needs Review' };
  return { key: 'risk', label: 'High Risk — Human Review Required' };
}

export function appliedDelta(sig) {
  if (sig.status === 'verified') return sig.score_delta;
  if (sig.status === 'confirmed') return sig.score_delta;
  return 0; // pending_review, dismissed, contextual
}

/** Max achievable positive points per stage (non-repeatable positives + one of each repeatable). */
function stageMax() {
  const max = Object.fromEntries(STAGES.map(s => [s, 0]));
  for (const w of q.all("SELECT stage, delta FROM signal_weights WHERE kind = 'positive'")) max[w.stage] += w.delta;
  return max;
}

/**
 * Stage score = clamp(50 + 50 × appliedPoints / maxPositivePoints).
 * A stage with no scored evidence is "pending" (null) — never a failure.
 * Overall = weighted average of stages that have evidence, normalised by their weights.
 */
export function computeScores(candidateId) {
  return computeFromSignals(q.all('SELECT * FROM trust_signals WHERE candidate_id = ?', candidateId));
}

/** Pure scoring over a list of signal rows (used for live scores and for replaying history). */
export function computeFromSignals(signals, { projection = true } = {}) {
  const max = stageMax();
  const stageWeights = getSetting('stage_weights', DEFAULT_STAGE_WEIGHTS);
  const stages = {};
  for (const s of STAGES) {
    const own = signals.filter(x => x.stage === s && x.status !== 'contextual');
    const positive = Math.min(own.filter(x => x.status === 'verified').reduce((a, x) => a + x.score_delta, 0), max[s] || 1);
    const negative = own.filter(x => x.status === 'confirmed').reduce((a, x) => a + x.score_delta, 0);
    const points = positive + negative;
    const hasEvidence = own.some(x => x.status === 'verified' || x.status === 'confirmed');
    // positives scale the stage from 50 → 100; reviewer-confirmed risks subtract their full weight
    const raw = 50 + 50 * (positive / (max[s] || 1)) + negative;
    stages[s] = {
      score: hasEvidence ? Math.round(Math.max(0, Math.min(100, raw))) : null,
      points,
      verified: own.filter(x => x.status === 'verified').length,
      pending: own.filter(x => x.status === 'pending_review').length,
      confirmed: own.filter(x => x.status === 'confirmed').length,
      contextual: signals.filter(x => x.stage === s && x.status === 'contextual').length,
    };
  }
  let num = 0, den = 0;
  for (const s of STAGES) if (stages[s].score !== null) { num += stages[s].score * stageWeights[s]; den += stageWeights[s]; }
  const overall = den ? Math.round(num / den) : 50;
  const pendingReview = signals.filter(x => x.status === 'pending_review').length;
  const highRiskPending = signals.filter(x => x.status === 'pending_review' && x.score_delta <= -20).length;
  // "If confirmed" projection: what the score would become if every open flag were confirmed by a reviewer.
  const ifConfirmed = projection && pendingReview
    ? computeFromSignals(signals.map(x => (x.status === 'pending_review' ? { ...x, status: 'confirmed' } : x)), { projection: false }).overall
    : overall;
  return {
    overall,
    band: band(overall),
    // Open high-severity flags put the candidate in review regardless of the numeric score (nothing is auto-decided).
    reviewStatus: highRiskPending ? 'review_required' : pendingReview ? 'open_items' : 'clear',
    ifConfirmed,
    highRiskPending,
    stages,
    pendingReview,
    evidenceCompleteness: Math.round((STAGES.filter(s => stages[s].score !== null).length / STAGES.length) * 100),
  };
}

export function recordHistory(candidateId, reason) {
  const s = computeScores(candidateId);
  const last = q.get('SELECT overall, stage_scores FROM score_history WHERE candidate_id = ? ORDER BY id DESC LIMIT 1', candidateId);
  const stageScores = Object.fromEntries(STAGES.map(k => [k, s.stages[k].score]));
  if (!last || last.overall !== s.overall || last.stage_scores !== JSON.stringify(stageScores)) {
    q.run('INSERT INTO score_history (candidate_id, overall, stage_scores, reason, created_at) VALUES (?,?,?,?,?)',
      candidateId, s.overall, JSON.stringify(stageScores), reason, now());
  }
  return s;
}

function broadcast(candidateId, signal, scores) {
  const msg = { type: 'trust', candidateId, signal, scores };
  toStaff(msg);
  toUser(candidateId, msg);
  if (signal?.status === 'pending_review') toStaff({ type: 'alert', candidateId, signal });
}

/**
 * Emit a trust signal. Positive signals are de-duplicated per candidate unless repeatable.
 * Risk signals default to pending_review (0 points until a human confirms).
 */
export function addSignal(candidateId, signalName, opts = {}) {
  const w = q.get('SELECT * FROM signal_weights WHERE signal_name = ?', signalName);
  if (!w) throw new Error(`Unknown signal ${signalName}`);
  const status = opts.status || (w.kind === 'positive' ? 'verified' : w.kind === 'risk' ? 'pending_review' : 'contextual');
  if (!w.repeatable && !opts.allowRepeat) {
    const existing = q.get(
      "SELECT id FROM trust_signals WHERE candidate_id = ? AND signal_name = ? AND status IN ('verified','pending_review','confirmed') AND COALESCE(session_ref,'') = COALESCE(?, '')",
      candidateId, signalName, opts.sessionRef ?? null);
    if (existing) return { id: existing.id, duplicate: true };
  }
  const createdAt = opts.at || now();
  const r = q.run(
    'INSERT INTO trust_signals (candidate_id, stage, signal_name, label, status, score_delta, evidence, source, session_ref, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
    candidateId, opts.stage || w.stage, signalName, opts.label || w.label, status, w.delta, json(opts.evidence || {}), opts.source || 'system', opts.sessionRef ?? null, createdAt);
  const signal = q.get('SELECT * FROM trust_signals WHERE id = ?', r.lastInsertRowid);
  if (opts.silent) return signal;
  const scores = recordHistory(candidateId, `${status === 'verified' ? '+' : ''}${w.label}`);
  broadcast(candidateId, formatSignal(signal), scores);
  return signal;
}

export function reviewSignal(signalId, reviewer, decision, comment) {
  const sig = q.get('SELECT * FROM trust_signals WHERE id = ?', signalId);
  if (!sig) throw Object.assign(new Error('Signal not found'), { status: 404 });
  if (sig.status !== 'pending_review') throw Object.assign(new Error('Only signals pending review can be decided'), { status: 409 });
  const status = decision === 'confirm' ? 'confirmed' : 'dismissed';
  q.run('UPDATE trust_signals SET status = ?, reviewed_by = ?, review_comment = ?, reviewed_at = ? WHERE id = ?',
    status, reviewer.id, comment, now(), signalId);
  const updated = q.get('SELECT * FROM trust_signals WHERE id = ?', signalId);
  const scores = recordHistory(sig.candidate_id, `${status === 'confirmed' ? 'Confirmed' : 'Dismissed'}: ${sig.label}`);
  broadcast(sig.candidate_id, formatSignal(updated), scores);
  return { signal: formatSignal(updated), scores };
}

export function formatSignal(s) {
  return {
    id: s.id, candidateId: s.candidate_id, stage: s.stage, name: s.signal_name, label: s.label, status: s.status,
    weight: s.score_delta, applied: appliedDelta(s), evidence: parse(s.evidence, {}), source: s.source,
    sessionRef: s.session_ref, createdAt: s.created_at, reviewedBy: s.reviewed_by, reviewComment: s.review_comment, reviewedAt: s.reviewed_at,
  };
}

export function signalsFor(candidateId) {
  return q.all('SELECT * FROM trust_signals WHERE candidate_id = ? ORDER BY created_at DESC, id DESC', candidateId).map(formatSignal);
}

/** Rebuild score history by replaying signal creation and review events in time order (used by seeding). */
export function rebuildHistory(candidateId) {
  const rows = q.all('SELECT * FROM trust_signals WHERE candidate_id = ?', candidateId);
  const events = [];
  for (const s of rows) {
    const initial = s.status === 'confirmed' || s.status === 'dismissed' ? 'pending_review' : s.status;
    events.push({ at: s.created_at, id: s.id, status: initial, reason: `${initial === 'verified' ? '+' : ''}${s.label}` });
    if (s.reviewed_at) events.push({ at: s.reviewed_at, id: s.id, status: s.status, reason: `${s.status === 'confirmed' ? 'Confirmed' : 'Dismissed'}: ${s.label}` });
  }
  events.sort((a, b) => a.at.localeCompare(b.at));
  q.run('DELETE FROM score_history WHERE candidate_id = ?', candidateId);
  const state = new Map();
  let last = null;
  if (events.length) {
    const t0 = new Date(Date.parse(events[0].at) - 60_000).toISOString();
    const empty = JSON.stringify(Object.fromEntries(STAGES.map(k => [k, null])));
    q.run('INSERT INTO score_history (candidate_id, overall, stage_scores, reason, created_at) VALUES (?,?,?,?,?)', candidateId, 50, empty, 'Application started (unverified baseline)', t0);
  }
  for (const e of events) {
    const base = rows.find(r => r.id === e.id);
    state.set(e.id, { ...base, status: e.status });
    const s = computeFromSignals([...state.values()]);
    const stageScores = JSON.stringify(Object.fromEntries(STAGES.map(k => [k, s.stages[k].score])));
    const key = `${s.overall}|${stageScores}`;
    if (key !== last) {
      q.run('INSERT INTO score_history (candidate_id, overall, stage_scores, reason, created_at) VALUES (?,?,?,?,?)', candidateId, s.overall, stageScores, e.reason, e.at);
      last = key;
    }
  }
  if (!events.length) recordHistory(candidateId, 'Application started');
}
