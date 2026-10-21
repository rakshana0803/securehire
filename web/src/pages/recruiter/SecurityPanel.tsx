import React, { useMemo, useState } from 'react';
import { Usb, AppWindow, Layers, Globe, Monitor, GitMerge, ShieldAlert, Info } from 'lucide-react';
import { Card, Pill, Button, Modal, Textarea, Callout, Skeleton, Empty, useAsync, useToast, cx } from '../../components/ui';
import { api, fmtDate, timeAgo, humanize } from '../../lib/api';
import { useRealtime } from '../../lib/realtime';

// Desktop security panel: agent status + one chronological timeline of desktop-agent observations
// (USB, apps, windows) and browser events, with human review. Nothing here is a verdict.

const CATEGORIES: { key: string; label: string; icon: React.ReactNode }[] = [
  { key: 'all', label: 'All', icon: null },
  { key: 'usb', label: 'USB', icon: <Usb className="h-3.5 w-3.5" /> },
  { key: 'process', label: 'Apps', icon: <AppWindow className="h-3.5 w-3.5" /> },
  { key: 'window', label: 'Windows', icon: <Layers className="h-3.5 w-3.5" /> },
  { key: 'browser', label: 'Browser', icon: <Globe className="h-3.5 w-3.5" /> },
  { key: 'correlation', label: 'Correlated', icon: <GitMerge className="h-3.5 w-3.5" /> },
  { key: 'agent', label: 'Agent', icon: <Monitor className="h-3.5 w-3.5" /> },
];
const STATUS_FILTERS = [
  { key: 'all', label: 'Any status' }, { key: 'needs_review', label: 'Needs review' }, { key: 'informational', label: 'Informational' },
  { key: 'decided', label: 'Reviewed / dismissed / confirmed' },
];
export const REVIEW_STATUS: Record<string, { label: string; tone: string }> = {
  informational: { label: 'Informational', tone: 'info' }, needs_review: { label: 'Needs review', tone: 'review' },
  reviewed: { label: 'Reviewed', tone: 'ok' }, dismissed: { label: 'Dismissed', tone: 'neutral' },
  confirmed_violation: { label: 'Confirmed violation (by reviewer)', tone: 'risk' },
};
const AGENT_STATE: Record<string, { label: string; tone: string }> = {
  connected: { label: 'Agent connected', tone: 'ok' }, disconnected: { label: 'Agent disconnected', tone: 'review' },
  stopped: { label: 'Agent finished', tone: 'neutral' }, not_connected: { label: 'No desktop agent', tone: 'neutral' },
};
const CAT_ICON: Record<string, React.ReactNode> = Object.fromEntries(CATEGORIES.map((c) => [c.key, c.icon]));
const BROWSER_NOTEWORTHY = new Set(['TAB_HIDDEN', 'WINDOW_BLUR', 'TAB_SWITCH', 'FULLSCREEN_EXIT', 'NEW_TAB_OPENED', 'PASTE_ATTEMPT', 'COPY_ATTEMPT', 'SESSION_START', 'SESSION_END', 'SESSION_INTERRUPTED', 'IP_CHANGE', 'FACE_MISMATCH', 'MULTIPLE_FACES']);

/** Short, human-readable detail line; only the fields a reviewer needs. */
function detailLine(e: any): string {
  const d = e.details || {};
  const parts: string[] = [];
  if (d.deviceCategory) parts.push(`type: ${d.deviceCategory}`);
  if (d.vendorId) parts.push(`VID ${d.vendorId}${d.productId ? `/PID ${d.productId}` : ''}`);
  if (d.deviceId) parts.push(`device ${d.deviceId}`);
  if (d.processName) parts.push(d.processName);
  if (d.width && d.height) parts.push(`${d.width}×${d.height}px`);
  if (d.overlapPercent != null) parts.push(`${d.overlapPercent}% over assessment`);
  if (Array.isArray(d.signals) && d.signals.length) parts.push(`signals: ${d.signals.map(humanize).join(', ')}`);
  if (d.browserFocusEventsWithin30s) parts.push(`${d.browserFocusEventsWithin30s} browser focus change(s) within 30 s`);
  if (d.monitor) parts.push(`monitor: ${d.monitor}`);
  if (Array.isArray(d.categories)) parts.push(`indicators: ${d.categories.join(', ')}`);
  return parts.join(' · ');
}

export function SecurityPanel({ sessionId, compact = false }: { sessionId: string; compact?: boolean }) {
  const { data, reload, error } = useAsync(() => api.get(`/api/recruiter/sessions/${sessionId}/security`), [sessionId]);
  const [cat, setCat] = useState('all');
  const [status, setStatus] = useState('all');
  const [reviewing, setReviewing] = useState<any>(null);
  useRealtime((m) => {
    if ((m.type === 'security' && m.event?.sessionId === sessionId) || (m.type === 'agent' && m.sessionId === sessionId) || (m.type === 'monitoring' && m.event?.sessionId === sessionId)) reload();
  }, [sessionId]);

  const timeline = useMemo(() => {
    if (!data) return [];
    const sec = data.events.map((e: any) => ({ ...e, kind: 'security', at: e.clientTs || e.receivedAt }));
    const browser = data.browserEvents.filter((b: any) => b.source !== 'face-monitor' || BROWSER_NOTEWORTHY.has(b.event_type)).map((b: any) => ({
      id: `b${b.id}`, kind: 'browser', category: 'browser', eventType: b.event_type, at: b.client_ts || b.created_at, source: b.source,
      explanation: `${humanize(b.event_type.toLowerCase())} (${b.source})`, details: b.details, reviewStatus: 'informational', priority: 'info',
    }));
    return [...sec, ...browser].sort((a, b) => String(a.at).localeCompare(String(b.at)));
  }, [data]);

  if (error) return <Callout tone="risk">{error}</Callout>;
  if (!data) return <Skeleton className="h-64" />;
  const filtered = timeline.filter((e: any) => (cat === 'all' || e.category === cat) &&
    (status === 'all' || (status === 'decided' ? ['reviewed', 'dismissed', 'confirmed_violation'].includes(e.reviewStatus) : e.reviewStatus === status)));
  const a = data.agent;
  const agentMeta = AGENT_STATE[a.state] || { label: a.state, tone: 'neutral' };
  const by = data.counts.byCategory || {};

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-ink">{data.candidate.name} <span className="font-normal text-muted">· {data.candidate.email}</span></p>
          <p className="text-xs text-muted">{data.session.title} · session {data.session.id} · {data.session.status === 'active' ? 'in progress' : data.session.status} · started {fmtDate(data.session.startedAt)}</p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Pill tone={agentMeta.tone} dot>{agentMeta.label}</Pill>
          {a.lastHeartbeatAt && <span className="text-xs text-muted">last heartbeat {timeAgo(a.lastHeartbeatAt)}</span>}
        </div>
      </div>
      {a.state !== 'not_connected' && Object.keys(a.monitors || {}).length > 0 && (
        <div className="flex flex-wrap gap-1.5 text-xs">
          {Object.entries(a.monitors).map(([k, v]: any) => <Pill key={k} tone={v === 'active' ? 'ok' : v === 'error' ? 'review' : 'neutral'}>{k}: {v}</Pill>)}
          {a.platform && <Pill>{a.platform}</Pill>}{a.agentVersion && <Pill>agent v{a.agentVersion}</Pill>}
        </div>
      )}
      {a.state === 'not_connected' && <Callout tone="info">The desktop agent did not connect for this session (it is optional unless your admin requires it). Browser events from the extension are still shown below.</Callout>}

      {!compact && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[['USB events', by.usb || 0], ['App launches', by.process || 0], ['Window observations', by.window || 0], ['Needs review', data.counts.needsReview]].map(([l, n]: any) => (
            <div key={l} className="rounded-lg bg-page p-3"><p className="text-xs text-muted">{l}</p><p className={cx('text-lg font-semibold tnum', n ? 'text-ink' : 'text-muted')}>{n}</p></div>
          ))}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-1.5">
        {CATEGORIES.map((c) => (
          <button key={c.key} onClick={() => setCat(c.key)} className={cx('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition', cat === c.key ? 'border-primary bg-primary-soft text-primary' : 'border-line bg-white text-body hover:text-ink')}>
            {c.icon}{c.label}
          </button>
        ))}
        <select aria-label="Filter by review status" value={status} onChange={(e) => setStatus(e.target.value)} className="ml-auto h-7 rounded-lg border border-line bg-white px-2 text-xs text-ink">
          {STATUS_FILTERS.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
        </select>
      </div>

      {filtered.length === 0 ? <Empty icon={<Info className="h-5 w-5" />} title="No events match these filters" /> : (
        <ol className={cx('relative space-y-3 border-l border-line pl-5', compact ? 'max-h-[440px]' : 'max-h-[560px]', 'overflow-y-auto pr-2')}>
          {filtered.map((e: any) => {
            const st = REVIEW_STATUS[e.reviewStatus] || { label: e.reviewStatus, tone: 'neutral' };
            const review = e.reviewStatus === 'needs_review';
            return (
              <li key={e.id} className="relative">
                <span className={cx('absolute -left-[25px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-white', review ? 'bg-review' : e.kind === 'browser' ? 'bg-neutral' : e.reviewStatus === 'confirmed_violation' ? 'bg-risk' : 'bg-info')} />
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-muted">{CAT_ICON[e.category]}</span>
                  <span className="text-xs text-muted tnum">{new Date(e.at).toLocaleTimeString('en-IN')}</span>
                  <span className="text-sm font-medium text-ink">{humanize(String(e.eventType).toLowerCase())}</span>
                  {e.kind === 'security' && <Pill tone={st.tone}>{st.label}</Pill>}
                  {e.ruleId && <span className="text-[11px] text-muted">{e.ruleId}</span>}
                </div>
                {e.kind === 'security' && <p className="mt-0.5 text-sm text-body">{e.explanation}</p>}
                {detailLine(e) && <p className="text-xs text-muted">{detailLine(e)}</p>}
                {e.reviewReason && <p className="mt-1 text-xs text-ink"><b>{st.label}</b>{e.reviewerName ? ` by ${e.reviewerName}` : ''}{e.reviewedAt ? ` · ${fmtDate(e.reviewedAt)}` : ''}: {e.reviewReason}</p>}
                {e.kind === 'security' && ['needs_review', 'informational'].includes(e.reviewStatus) && (review || !compact) && (
                  <div className="mt-1.5"><Button size="sm" variant={review ? 'primary' : 'ghost'} onClick={() => setReviewing(e)}>{review ? 'Review' : 'Add note'}</Button></div>
                )}
              </li>
            );
          })}
        </ol>
      )}
      <p className="text-xs text-muted">Desktop observations are indicators for a person to assess — a USB device, application or window is never proof on its own. Accessibility tools and normal peripherals are expected. Only a reviewer can record a policy violation, with a written reason.</p>
      <SecurityReviewModal event={reviewing} onClose={() => setReviewing(null)} onDone={reload} />
    </div>
  );
}

const DECISIONS = [
  { key: 'reviewed', label: 'Reviewed — no issue', tone: 'secondary', hint: 'You looked at it and it needs no further action.' },
  { key: 'dismissed', label: 'Dismiss', tone: 'secondary', hint: 'Not relevant (e.g. an approved device or tool).' },
  { key: 'confirmed_violation', label: 'Confirm policy violation', tone: 'danger', hint: 'Only after considering all evidence and any candidate response. Explain why (15+ characters).' },
] as const;

export function SecurityReviewModal({ event, onClose, onDone }: { event: any; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const toast = useToast();
  const decide = async (decision: string) => {
    setBusy(decision);
    try {
      await api.post(`/api/recruiter/security-events/${event.id}/review`, { decision, reason });
      toast(decision === 'confirmed_violation' ? 'Recorded as a confirmed policy violation' : 'Review recorded');
      setReason(''); onDone(); onClose();
    } catch (e: any) { toast(e.message, 'risk'); } finally { setBusy(null); }
  };
  const len = reason.trim().length;
  return (
    <Modal open={!!event} onClose={onClose} title="Review desktop observation" width="max-w-xl"
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button>{DECISIONS.map((d) => (
        <Button key={d.key} variant={d.tone as any} loading={busy === d.key} disabled={len < (d.key === 'confirmed_violation' ? 15 : 5) || !!busy} onClick={() => decide(d.key)}>{d.label}</Button>
      ))}</>}>
      {event && (
        <div className="space-y-4">
          <div>
            <div className="flex items-center gap-2"><Pill>{humanize(event.category)}</Pill><span className="text-xs text-muted">{fmtDate(event.clientTs || event.receivedAt)} · {event.ruleId}</span></div>
            <p className="mt-2 text-sm text-ink">{event.explanation}</p>
            {detailLine(event) && <p className="mt-1 text-xs text-muted">{detailLine(event)}</p>}
          </div>
          <Callout tone="info" icon={<ShieldAlert className="h-4 w-4" />}>This is an observation, not a finding. Consider the recording, other events, accessibility needs and the candidate's explanation. Your decision and reason are audit-logged; nothing rejects the candidate automatically.</Callout>
          <ul className="space-y-1 text-xs text-muted">{DECISIONS.map((d) => <li key={d.key}><b className="text-ink">{d.label}:</b> {d.hint}</li>)}</ul>
          <label className="block"><span className="mb-1.5 block text-xs font-medium text-ink">Reason (required)</span>
            <Textarea rows={3} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="What did you check, and what did you conclude?" /></label>
        </div>
      )}
    </Modal>
  );
}

/** Card wrapper used on the candidate page. */
export function SecurityCard({ sessionId }: { sessionId: string }) {
  return <Card title={<span className="flex items-center gap-2"><Monitor className="h-4 w-4 text-primary" />Desktop security</span>} description="USB, application and window observations from the desktop agent, merged with browser events.">
    <SecurityPanel sessionId={sessionId} />
  </Card>;
}
