import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';

export const db = new DatabaseSync(config.dbFile);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

// ---------------------------------------------------------------------------
// Schema (migration v1). Idempotent: safe to run on every start.
// ---------------------------------------------------------------------------
const SCHEMA = `
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS organizations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  org_id INTEGER REFERENCES organizations(id),
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('candidate','recruiter','admin')),
  name TEXT NOT NULL,
  phone TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  is_demo INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY, org_id INTEGER REFERENCES organizations(id),
  title TEXT NOT NULL, location TEXT, description TEXT, hiring_type TEXT DEFAULT 'remote',
  created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  job_id INTEGER REFERENCES jobs(id),
  stage_index INTEGER NOT NULL DEFAULT 0,
  dob TEXT,
  city TEXT,
  applied_email TEXT,
  applied_phone TEXT,
  applied_at TEXT,
  hold_reason TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consents (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL, granted INTEGER NOT NULL, version TEXT NOT NULL DEFAULT 'v1',
  created_at TEXT NOT NULL, withdrawn_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_consents_user ON consents(user_id, purpose);

CREATE TABLE IF NOT EXISTS email_otps (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, sent_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  aadhaar_hmac TEXT NOT NULL UNIQUE,
  aadhaar_masked TEXT NOT NULL,
  provider TEXT NOT NULL,
  record_name TEXT, record_dob TEXT,
  verified_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_aadhaar (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  aadhaar_hmac TEXT NOT NULL, aadhaar_masked TEXT NOT NULL, txn_id TEXT NOT NULL, expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS face_anchors (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  descriptor_enc TEXT NOT NULL,
  id_photo_descriptor_enc TEXT,
  model TEXT NOT NULL,
  liveness TEXT,
  consent_id INTEGER REFERENCES consents(id),
  created_at TEXT NOT NULL,
  retention_until TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS face_checks (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stage TEXT NOT NULL, session_ref TEXT, distance REAL, faces INTEGER, result TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_face_checks_user ON face_checks(user_id, stage, created_at);

CREATE TABLE IF NOT EXISTS voice_prints (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  vector_enc TEXT NOT NULL, method TEXT NOT NULL, created_at TEXT NOT NULL, retention_until TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, filename TEXT NOT NULL, stored_name TEXT NOT NULL, mime TEXT, size INTEGER,
  status TEXT NOT NULL DEFAULT 'submitted', verification TEXT, created_at TEXT NOT NULL, retention_until TEXT
);

CREATE TABLE IF NOT EXISTS resumes (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  document_id INTEGER REFERENCES documents(id), version INTEGER NOT NULL,
  text_enc TEXT, parsed TEXT NOT NULL, shingles TEXT, apaar_id_masked TEXT, summary TEXT, created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resume_claims (
  id INTEGER PRIMARY KEY, resume_id INTEGER NOT NULL REFERENCES resumes(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category TEXT NOT NULL, field TEXT NOT NULL, resume_value TEXT, verified_value TEXT,
  source TEXT, method TEXT, similarity REAL, status TEXT NOT NULL, explanation TEXT
);

CREATE TABLE IF NOT EXISTS employment_verifications (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  employer TEXT NOT NULL, title TEXT, start_date TEXT, end_date TEXT,
  status TEXT NOT NULL, source TEXT, evidence TEXT, reviewer_note TEXT, updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessments (
  id INTEGER PRIMARY KEY, job_id INTEGER REFERENCES jobs(id), title TEXT NOT NULL,
  duration_sec INTEGER NOT NULL, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assessment_questions (
  id INTEGER PRIMARY KEY, assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  position INTEGER NOT NULL, type TEXT NOT NULL, prompt TEXT NOT NULL, options TEXT, answer TEXT, points INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS assessment_sessions (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  assessment_id INTEGER NOT NULL REFERENCES assessments(id),
  token_hash TEXT NOT NULL, status TEXT NOT NULL, consent INTEGER NOT NULL,
  started_at TEXT NOT NULL, ended_at TEXT, expires_at TEXT NOT NULL,
  ip_hash TEXT, extension_version TEXT, score REAL, max_score REAL, answers TEXT, timings TEXT, flags TEXT
);
CREATE TABLE IF NOT EXISTS monitoring_events (
  id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stage TEXT NOT NULL, source TEXT NOT NULL, event_type TEXT NOT NULL, details TEXT,
  idempotency_key TEXT UNIQUE, client_ts TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON monitoring_events(session_id, created_at);

CREATE TABLE IF NOT EXISTS ip_observations (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stage TEXT NOT NULL, session_ref TEXT, ip_hash TEXT NOT NULL, ip_masked TEXT NOT NULL,
  city TEXT, region TEXT, country TEXT, lat REAL, lng REAL, geo_source TEXT, changed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_user ON ip_observations(user_id, created_at);

CREATE TABLE IF NOT EXISTS location_events (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stage TEXT NOT NULL, session_ref TEXT, source TEXT NOT NULL, lat REAL, lng REAL, accuracy REAL,
  place TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loc_user ON location_events(user_id, created_at);

CREATE TABLE IF NOT EXISTS interviews (
  id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recruiter_id INTEGER REFERENCES users(id), scheduled_at TEXT NOT NULL, room_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL, started_at TEXT, ended_at TEXT, notes TEXT, rubric TEXT, verification TEXT
);

CREATE TABLE IF NOT EXISTS offers (
  id TEXT PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_name TEXT NOT NULL, title TEXT NOT NULL, salary TEXT, start_date TEXT,
  issued_by INTEGER REFERENCES users(id), issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  status TEXT NOT NULL, content_hash TEXT NOT NULL, signature TEXT NOT NULL,
  accepted_at TEXT, revoked_at TEXT, acceptance TEXT
);

CREATE TABLE IF NOT EXISTS onboarding (
  candidate_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL, checklist TEXT NOT NULL, joined_at TEXT, approved_by INTEGER REFERENCES users(id), updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signal_weights (
  signal_name TEXT PRIMARY KEY, stage TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('positive','risk','context')),
  delta INTEGER NOT NULL, label TEXT NOT NULL, repeatable INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS trust_signals (
  id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stage TEXT NOT NULL, signal_name TEXT NOT NULL, label TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('verified','pending_review','confirmed','dismissed','contextual')),
  score_delta INTEGER NOT NULL, evidence TEXT, source TEXT, session_ref TEXT,
  created_at TEXT NOT NULL, reviewed_by INTEGER REFERENCES users(id), review_comment TEXT, reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_signals_candidate ON trust_signals(candidate_id, created_at);
CREATE INDEX IF NOT EXISTS idx_signals_status ON trust_signals(status);

CREATE TABLE IF NOT EXISTS score_history (
  id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  overall REAL NOT NULL, stage_scores TEXT NOT NULL, reason TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_candidate ON score_history(candidate_id, created_at);

CREATE TABLE IF NOT EXISTS appeals (
  id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  signal_id INTEGER REFERENCES trust_signals(id) ON DELETE SET NULL, message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open', response TEXT, created_at TEXT NOT NULL, resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY, actor_id INTEGER, actor_role TEXT, action TEXT NOT NULL, target TEXT,
  details TEXT, ip_masked TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
`;

db.exec(SCHEMA);
if (!db.prepare('SELECT 1 FROM schema_migrations WHERE version = 1').get()) {
  db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)').run(new Date().toISOString());
}

// ---------------------------------------------------------------------------
// Migration v2 — Desktop security agent (USB / app launch / overlay-window monitoring).
// Idempotent: safe to run on every start, including on databases created before v2.
// ---------------------------------------------------------------------------
const hasColumn = (table, col) => db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === col);
if (!hasColumn('assessment_sessions', 'agent_token_hash')) {
  // A second session-scoped token, separate from the extension's, handed to the local desktop agent.
  db.exec('ALTER TABLE assessment_sessions ADD COLUMN agent_token_hash TEXT');
}
db.exec(`
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES assessment_sessions(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source TEXT NOT NULL CHECK (source IN ('agent','server')),
  category TEXT NOT NULL CHECK (category IN ('usb','process','window','correlation','agent')),
  event_type TEXT NOT NULL,
  priority TEXT NOT NULL CHECK (priority IN ('info','review')),
  -- informational → needs_review → reviewed | dismissed | confirmed_violation (only a human sets the last three)
  review_status TEXT NOT NULL CHECK (review_status IN ('informational','needs_review','reviewed','dismissed','confirmed_violation')),
  rule_id TEXT,
  explanation TEXT NOT NULL,
  details TEXT,
  idempotency_key TEXT UNIQUE,
  client_ts TEXT,
  received_at TEXT NOT NULL,
  reviewed_by INTEGER REFERENCES users(id),
  review_reason TEXT,
  reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_secevents_session ON security_events(session_id, received_at);
CREATE INDEX IF NOT EXISTS idx_secevents_status ON security_events(review_status);

CREATE TABLE IF NOT EXISTS agent_status (
  session_id TEXT PRIMARY KEY REFERENCES assessment_sessions(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agent_version TEXT,
  platform TEXT,
  state TEXT NOT NULL,           -- connected | disconnected | stopped
  monitors TEXT,                 -- {"usb":"active","process":"active","window":"unsupported"}
  connected_at TEXT NOT NULL,
  last_heartbeat_at TEXT NOT NULL,
  disconnected_at TEXT
);
`);
if (!db.prepare('SELECT 1 FROM schema_migrations WHERE version = 2').get()) {
  db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (2, ?)').run(new Date().toISOString());
}

// ---------------------------------------------------------------------------
// Tiny query helpers
// ---------------------------------------------------------------------------
const cache = new Map();
function stmt(sql) {
  let s = cache.get(sql);
  if (!s) { s = db.prepare(sql); cache.set(sql, s); }
  return s;
}
export const q = {
  get: (sql, ...p) => stmt(sql).get(...p),
  all: (sql, ...p) => stmt(sql).all(...p),
  run: (sql, ...p) => stmt(sql).run(...p),
};
export const now = () => new Date().toISOString();
export const json = (v) => (v === undefined ? null : JSON.stringify(v));
export const parse = (s, fallback = null) => { try { return s ? JSON.parse(s) : fallback; } catch { return fallback; } };

export function tx(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
}

export function getSetting(key, fallback) {
  const row = q.get('SELECT value FROM settings WHERE key = ?', key);
  return row ? parse(row.value, fallback) : fallback;
}
export function setSetting(key, value) {
  q.run('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, JSON.stringify(value));
}
