import fs from 'node:fs';
import path from 'node:path';
import { q, now, getSetting } from '../db.js';
import { config } from '../config.js';

export const DEFAULT_RETENTION = { face: 180, voice: 90, documents: 365, ip: 90, location: 30, monitoring: 180, faceChecks: 180 };

/** Apply configured retention. Every deletion batch is written to the audit log. */
export function runRetention() {
  const days = { ...DEFAULT_RETENTION, ...getSetting('retention_days', {}) };
  const cutoff = (d) => new Date(Date.now() - d * 86400_000).toISOString();
  const out = {};
  out.faceAnchors = q.run('DELETE FROM face_anchors WHERE retention_until < ?', now()).changes;
  out.voicePrints = q.run('DELETE FROM voice_prints WHERE retention_until < ?', now()).changes;
  const docs = q.all('SELECT id, stored_name FROM documents WHERE retention_until IS NOT NULL AND retention_until < ?', now());
  for (const d of docs) { try { fs.unlinkSync(path.join(config.uploadDir, d.stored_name)); } catch { /* already gone */ } q.run('DELETE FROM documents WHERE id = ?', d.id); }
  out.documents = docs.length;
  out.ipObservations = q.run('DELETE FROM ip_observations WHERE created_at < ?', cutoff(days.ip)).changes;
  out.locationEvents = q.run('DELETE FROM location_events WHERE created_at < ?', cutoff(days.location)).changes;
  out.monitoringEvents = q.run('DELETE FROM monitoring_events WHERE created_at < ?', cutoff(days.monitoring)).changes;
  out.faceChecks = q.run('DELETE FROM face_checks WHERE created_at < ?', cutoff(days.faceChecks)).changes;
  // Desktop agent observations follow the monitoring retention period.
  out.securityEvents = q.run('DELETE FROM security_events WHERE received_at < ?', cutoff(days.monitoring)).changes;
  out.agentStatus = q.run('DELETE FROM agent_status WHERE last_heartbeat_at < ?', cutoff(days.monitoring)).changes;
  const total = Object.values(out).reduce((a, b) => a + b, 0);
  if (total) q.run('INSERT INTO audit_logs (actor_id, actor_role, action, target, details, created_at) VALUES (NULL, ?, ?, ?, ?, ?)', 'system', 'retention.delete', 'retention', JSON.stringify(out), now());
  return { deleted: out, policyDays: days, ranAt: now() };
}
