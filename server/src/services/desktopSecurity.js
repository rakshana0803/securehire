// Desktop security agent integration (USB / newly launched apps / potential overlay windows).
//
// The Windows agent observes local activity during an assessment and reports *observations*.
// Nothing here decides misconduct: events are either "informational" or "needs_review", and only a
// human reviewer can mark one as a confirmed policy violation (with a written reason).
import crypto from 'node:crypto';
import { q, now, json, parse, getSetting } from '../db.js';
import { sha256 } from '../security.js';
import { addSignal } from '../trust.js';
import { toStaff, toUser } from '../realtime.js';

export const HEARTBEAT_STALE_MS = 45_000;
const CLOCK_SKEW_MS = 5 * 60_000;     // accepted difference between agent clock and server clock
const LATE_DELIVERY_MS = 10 * 60_000; // queued events may still arrive this long after a session ends

// Event vocabulary the agent may send, per category. Server-only types are listed separately.
export const AGENT_EVENT_TYPES = {
  usb: ['USB_DEVICE_CONNECTED', 'USB_DEVICE_DISCONNECTED'],
  process: ['PROCESS_STARTED'],
  window: ['WINDOW_OBSERVED', 'OVERLAY_WINDOW_SUSPECTED', 'CAPTURE_EXCLUDED_WINDOW', 'TRANSPARENT_OVERLAY_SUSPECTED'],
  correlation: ['CORRELATED_ACTIVITY'],
  agent: ['AGENT_STARTED', 'AGENT_STOPPED', 'MONITOR_ERROR', 'MONITOR_UNAVAILABLE', 'MONITOR_RECOVERED'],
};
const SERVER_EVENT_TYPES = ['AGENT_CONNECTED', 'AGENT_DISCONNECTED', 'AGENT_RECONNECTED'];

// Only these detail fields are stored. Everything else the agent sends is dropped.
// Deliberately absent: window titles, file names, command lines, drive contents, usernames, paths.
const DETAIL_FIELDS = {
  usb: { deviceCategory: 'str', deviceId: 'str', vendorId: 'str', productId: 'str', deviceClass: 'str', service: 'str', storageRule: 'bool' },
  process: { processName: 'str', pid: 'int', allowlisted: 'bool' },
  window: {
    processName: 'str', pid: 'int', width: 'int', height: 'int', x: 'int', y: 'int', screenAreaPercent: 'num',
    overlapPercent: 'num', overlapKnown: 'bool', topmost: 'bool', layered: 'bool', alpha: 'int', clickThrough: 'bool',
    toolWindow: 'bool', noActivate: 'bool', captureExcluded: 'bool', newProcess: 'bool', allowlisted: 'bool', signals: 'strlist',
  },
  correlation: { categories: 'strlist', relatedEventKeys: 'strlist', windowSeconds: 'int', indicatorCount: 'int' },
  agent: { monitor: 'str', state: 'str', reason: 'str', error: 'str', agentVersion: 'str', platform: 'str' },
};

const IDEMPOTENCY_RE = /^[A-Za-z0-9_:.-]{8,100}$/;

function cleanDetails(category, details) {
  const spec = DETAIL_FIELDS[category] || {};
  const out = {};
  if (!details || typeof details !== 'object' || Array.isArray(details)) return out;
  for (const [key, type] of Object.entries(spec)) {
    const v = details[key];
    if (v === undefined || v === null) continue;
    if (type === 'str' && typeof v === 'string') out[key] = v.slice(0, 120);
    else if (type === 'int' && Number.isInteger(v) && Math.abs(v) < 1e9) out[key] = v;
    else if (type === 'num' && typeof v === 'number' && Number.isFinite(v)) out[key] = Math.round(v * 10) / 10;
    else if (type === 'bool' && typeof v === 'boolean') out[key] = v;
    else if (type === 'strlist' && Array.isArray(v)) out[key] = v.filter((x) => typeof x === 'string').slice(0, 12).map((x) => x.slice(0, 60));
  }
  return out;
}

/** Validate one agent event. Returns { value } or { error }. Pure — no database access. */
export function validateAgentEvent(ev, session, nowMs = Date.now()) {
  if (!ev || typeof ev !== 'object' || Array.isArray(ev)) return { error: 'Event must be an object.' };
  const category = String(ev.category || '');
  const type = String(ev.eventType || '').toUpperCase();
  if (!AGENT_EVENT_TYPES[category]) return { error: `Unknown category "${category.slice(0, 30)}".` };
  if (!AGENT_EVENT_TYPES[category].includes(type)) return { error: `Event type "${type.slice(0, 40)}" is not allowed for category ${category}.` };
  if (!IDEMPOTENCY_RE.test(String(ev.idempotencyKey || ''))) return { error: 'idempotencyKey is required (8–100 safe characters).' };
  const priority = ev.priority === 'review' ? 'review' : ev.priority === 'info' || ev.priority === undefined ? 'info' : null;
  if (!priority) return { error: 'priority must be "info" or "review".' };
  const ts = Date.parse(ev.timestamp);
  if (!Number.isFinite(ts)) return { error: 'timestamp must be an ISO-8601 date.' };
  const started = Date.parse(session.started_at);
  if (ts < started - CLOCK_SKEW_MS || ts > nowMs + CLOCK_SKEW_MS) return { error: 'timestamp is outside this assessment session.' };
  if (session.ended_at) {
    const ended = Date.parse(session.ended_at);
    if (nowMs > ended + LATE_DELIVERY_MS) return { error: 'Session ended too long ago to accept new events.' };
    if (ts > ended + 60_000) return { error: 'Event happened after the session ended.' };
  }
  const explanation = typeof ev.explanation === 'string' && ev.explanation.trim()
    ? ev.explanation.trim().slice(0, 500)
    : `${type.replace(/_/g, ' ').toLowerCase()} observed by the desktop agent.`;
  return {
    value: {
      category, type, priority, explanation,
      ruleId: typeof ev.ruleId === 'string' ? ev.ruleId.slice(0, 60) : null,
      details: cleanDetails(category, ev.details),
      idempotencyKey: String(ev.idempotencyKey),
      clientTs: new Date(ts).toISOString(),
    },
  };
}

export const formatSecurityEvent = (e) => ({
  id: e.id, sessionId: e.session_id, userId: e.user_id, source: e.source, category: e.category, eventType: e.event_type,
  priority: e.priority, reviewStatus: e.review_status, ruleId: e.rule_id, explanation: e.explanation, details: parse(e.details, {}),
  clientTs: e.client_ts, receivedAt: e.received_at, reviewedBy: e.reviewed_by, reviewerName: e.reviewer_name ?? undefined,
  reviewReason: e.review_reason, reviewedAt: e.reviewed_at,
});

function insertEvent(session, { source, category, type, priority, explanation, ruleId = null, details = {}, idempotencyKey = null, clientTs = null }) {
  try {
    const r = q.run(`INSERT INTO security_events (session_id, user_id, source, category, event_type, priority, review_status, rule_id, explanation, details, idempotency_key, client_ts, received_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    session.id, session.user_id, source, category, type, priority, priority === 'review' ? 'needs_review' : 'informational',
    ruleId, explanation, json(details), idempotencyKey, clientTs, now());
    const row = q.get('SELECT * FROM security_events WHERE id = ?', r.lastInsertRowid);
    const event = formatSecurityEvent(row);
    toStaff({ type: 'security', event });
    return { inserted: true, event };
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return { inserted: false, duplicate: true };
    throw e;
  }
}

/** Browser focus/tab events close in time to a desktop event — shown to the reviewer as context only. */
const FOCUS_TYPES = ['TAB_HIDDEN', 'WINDOW_BLUR', 'TAB_SWITCH', 'FULLSCREEN_EXIT'];
function browserContext(sessionId, atIso) {
  const at = Date.parse(atIso);
  const from = new Date(at - 30_000).toISOString(), to = new Date(at + 30_000).toISOString();
  const rows = q.all(`SELECT event_type FROM monitoring_events WHERE session_id = ? AND created_at BETWEEN ? AND ? AND event_type IN (${FOCUS_TYPES.map(() => '?').join(',')})`, sessionId, from, to, ...FOCUS_TYPES);
  return rows.length;
}

/** Ingest a batch from the agent. The session has already been authenticated by agent token. */
export function ingestAgentEvents(session, events, nowMs = Date.now()) {
  const results = [];
  for (const raw of events) {
    const v = validateAgentEvent(raw, session, nowMs);
    if (v.error) { results.push({ idempotencyKey: raw?.idempotencyKey ?? null, error: v.error }); continue; }
    const ev = v.value;
    if (ev.priority === 'review') ev.details.browserFocusEventsWithin30s = browserContext(session.id, ev.clientTs);
    const out = insertEvent(session, { source: 'agent', ...ev });
    results.push({ idempotencyKey: ev.idempotencyKey, inserted: !!out.inserted, duplicate: !!out.duplicate });
    if (out.inserted && ev.type === 'AGENT_STOPPED') markAgent(session, 'stopped');
    if (out.inserted && ev.priority === 'review' && ev.category !== 'agent') {
      // One review item per session in the existing Review Queue (0 points until a human confirms it).
      addSignal(session.user_id, 'desktop_activity_review', {
        sessionRef: session.id, source: 'desktop-agent',
        evidence: {
          firstEvent: ev.type, rule: ev.ruleId, explanation: ev.explanation,
          note: 'Observation from the desktop agent, not a finding. Open the Desktop security panel for this session to see every event and its context before deciding.',
        },
      });
    }
  }
  return {
    accepted: results.filter((r) => r.inserted).length,
    duplicates: results.filter((r) => r.duplicate).length,
    rejected: results.filter((r) => r.error).length,
    results,
  };
}

function markAgent(session, state) {
  q.run('UPDATE agent_status SET state = ?, disconnected_at = CASE WHEN ? = \'connected\' THEN NULL ELSE ? END WHERE session_id = ?', state, state, now(), session.id);
  toStaff({ type: 'agent', sessionId: session.id, candidateId: session.user_id, state });
  toUser(session.user_id, { type: 'agent', sessionId: session.id, state });
}

const MONITOR_STATES = ['active', 'starting', 'unsupported', 'error', 'disabled', 'stopped'];
/** Heartbeat from the agent. Records connection, reconnection and monitor health. */
export function recordHeartbeat(session, body = {}) {
  const version = typeof body.agentVersion === 'string' ? body.agentVersion.slice(0, 30) : null;
  const platform = typeof body.platform === 'string' ? body.platform.slice(0, 40) : null;
  const monitors = {};
  if (body.monitors && typeof body.monitors === 'object') {
    for (const k of ['usb', 'process', 'window']) if (MONITOR_STATES.includes(body.monitors[k])) monitors[k] = body.monitors[k];
  }
  const existing = q.get('SELECT * FROM agent_status WHERE session_id = ?', session.id);
  const t = now();
  if (!existing) {
    q.run('INSERT INTO agent_status (session_id, user_id, agent_version, platform, state, monitors, connected_at, last_heartbeat_at) VALUES (?,?,?,?,?,?,?,?)',
      session.id, session.user_id, version, platform, 'connected', json(monitors), t, t);
    insertEvent(session, { source: 'server', category: 'agent', type: 'AGENT_CONNECTED', priority: 'info',
      explanation: `Desktop agent ${version ? `v${version} ` : ''}connected${platform ? ` on ${platform}` : ''}.`, details: { agentVersion: version, platform } });
    toStaff({ type: 'agent', sessionId: session.id, candidateId: session.user_id, state: 'connected' });
  } else {
    q.run('UPDATE agent_status SET last_heartbeat_at = ?, agent_version = COALESCE(?, agent_version), platform = COALESCE(?, platform), monitors = ? WHERE session_id = ?',
      t, version, platform, json(monitors), session.id);
    if (existing.state === 'disconnected') {
      const gapSec = Math.round((Date.parse(t) - Date.parse(existing.last_heartbeat_at)) / 1000);
      markAgent(session, 'connected');
      insertEvent(session, { source: 'server', category: 'agent', type: 'AGENT_RECONNECTED', priority: 'info',
        explanation: `Desktop agent reconnected after about ${gapSec} s without contact. Activity during the gap may not have been observed.`, details: { reason: `gap ${gapSec}s` } });
    }
  }
  return agentStatusFor(session.id);
}

/** Mark agents that stopped sending heartbeats during an active session. Called on a timer. */
export function sweepStaleAgents(nowMs = Date.now()) {
  const cutoff = new Date(nowMs - HEARTBEAT_STALE_MS).toISOString();
  const stale = q.all(`SELECT a.*, s.status AS session_status, s.started_at, s.ended_at FROM agent_status a JOIN assessment_sessions s ON s.id = a.session_id
                       WHERE a.state = 'connected' AND a.last_heartbeat_at < ?`, cutoff);
  for (const a of stale) {
    const session = { id: a.session_id, user_id: a.user_id };
    if (a.session_status !== 'active') { markAgent(session, 'stopped'); continue; }
    markAgent(session, 'disconnected');
    insertEvent(session, {
      source: 'server', category: 'agent', type: 'AGENT_DISCONNECTED', priority: 'review',
      explanation: `No heartbeat from the desktop agent for over ${HEARTBEAT_STALE_MS / 1000} s during an active assessment. Possible causes include network loss, the computer sleeping, or the agent being closed. Desktop activity during this gap was not observed.`,
      details: { reason: 'heartbeat timeout' },
    });
  }
  return stale.length;
}

/** When an assessment ends, a still-connected agent is simply finished — not a disconnection. */
export function onSessionEnded(sessionId) {
  const a = q.get("SELECT * FROM agent_status WHERE session_id = ? AND state = 'connected'", sessionId);
  if (a) markAgent({ id: sessionId, user_id: a.user_id }, 'stopped');
}

export function agentStatusFor(sessionId) {
  const a = q.get('SELECT * FROM agent_status WHERE session_id = ?', sessionId);
  if (!a) return { state: 'not_connected', lastHeartbeatAt: null, monitors: {}, agentVersion: null, platform: null };
  return { state: a.state, lastHeartbeatAt: a.last_heartbeat_at, connectedAt: a.connected_at, disconnectedAt: a.disconnected_at, monitors: parse(a.monitors, {}), agentVersion: a.agent_version, platform: a.platform };
}

export function securityCounts(sessionId) {
  const rows = q.all('SELECT category, review_status, COUNT(*) AS n FROM security_events WHERE session_id = ? GROUP BY category, review_status', sessionId);
  const out = { total: 0, needsReview: 0, byCategory: {} };
  for (const r of rows) {
    out.total += r.n;
    if (r.review_status === 'needs_review') out.needsReview += r.n;
    out.byCategory[r.category] = (out.byCategory[r.category] || 0) + r.n;
  }
  return out;
}

export const REVIEW_DECISIONS = ['reviewed', 'dismissed', 'confirmed_violation'];
/** Human review of one security event. Only a reviewer can set these statuses. */
export function reviewSecurityEvent(eventId, reviewer, decision, reason) {
  if (!REVIEW_DECISIONS.includes(decision)) throw Object.assign(new Error('Decision must be reviewed, dismissed or confirmed_violation.'), { status: 400 });
  const text = String(reason || '').trim();
  const min = decision === 'confirmed_violation' ? 15 : 5;
  if (text.length < min) throw Object.assign(new Error(decision === 'confirmed_violation'
    ? 'Confirming a policy violation needs an explanation of at least 15 characters.' : 'Please add a short reason (at least 5 characters).'), { status: 400 });
  const ev = q.get('SELECT * FROM security_events WHERE id = ?', eventId);
  if (!ev) throw Object.assign(new Error('Security event not found.'), { status: 404 });
  if (!['informational', 'needs_review'].includes(ev.review_status)) throw Object.assign(new Error('This event has already been reviewed.'), { status: 409 });
  q.run('UPDATE security_events SET review_status = ?, reviewed_by = ?, review_reason = ?, reviewed_at = ? WHERE id = ?', decision, reviewer.id, text.slice(0, 1000), now(), ev.id);
  const updated = formatSecurityEvent(q.get('SELECT e.*, u.name AS reviewer_name FROM security_events e LEFT JOIN users u ON u.id = e.reviewed_by WHERE e.id = ?', ev.id));
  toStaff({ type: 'security', event: updated, reviewed: true });
  return updated;
}

/** Agent-token authentication. Returns the session row or null. Constant-time hash comparison. */
export function sessionForAgentToken(sessionId, token) {
  if (typeof sessionId !== 'string' || !/^[A-Za-z0-9-]{6,64}$/.test(sessionId) || typeof token !== 'string' || token.length < 20) return null;
  const s = q.get('SELECT * FROM assessment_sessions WHERE id = ?', sessionId);
  if (!s?.agent_token_hash) return null;
  const a = Buffer.from(sha256(token), 'hex'), b = Buffer.from(s.agent_token_hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? s : null;
}

export function desktopPolicy() {
  const p = getSetting('monitoring_policy', {}) || {};
  return { required: p.requireDesktopAgent === true, heartbeatSeconds: 15 };
}
