import React, { useMemo, useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { Download, CalendarPlus, BadgeCheck, MessageSquare, Video, ArrowLeft, MapPin, Network, ScanFace, CheckCircle2, ExternalLink } from 'lucide-react';
import { Card, PageHeader, Button, Pill, Tabs, Skeleton, Modal, Field, Input, Textarea, Callout, useToast, useAsync, StatusPill, MockTag, Empty, cx } from '../../components/ui';
import { TrustScoreCard, StageStepper, StageScoreGrid, ScoreHistoryChart, SignalTable, ScoreDisclaimer, Evidence } from '../../components/trust';
import { ResumeReport } from '../candidate/Resume';
import { ReviewModal } from './shared';
import { SecurityCard } from './SecurityPanel';
import { api, fmtDate, STAGE_LABELS, timeAgo, humanize } from '../../lib/api';
import { useRealtime } from '../../lib/realtime';

export default function CandidateDetail() {
  const { id } = useParams();
  const { data, reload } = useAsync(() => api.get(`/api/recruiter/candidates/${id}`), [id]);
  const [tab, setTab] = useState('signals');
  const [review, setReview] = useState<any>(null);
  const [modal, setModal] = useState<string | null>(null);
  const toast = useToast();
  const nav = useNavigate();
  useRealtime((m) => { if ((m.type === 'trust' || m.type === 'monitoring' || m.type === 'security' || m.type === 'agent') && String(m.candidateId ?? m.event?.userId) === String(id)) reload(); }, [id]);
  if (!data) return <div className="space-y-4"><Skeleton className="h-32" /><Skeleton className="h-72" /></div>;
  const p = data.profile, s = data.scores;
  const flagged: Record<string, number> = {};
  data.signals.filter((x: any) => x.status === 'pending_review').forEach((x: any) => { flagged[x.stage] = (flagged[x.stage] || 0) + 1; });
  const openInterview = data.interviews.find((i: any) => i.status !== 'completed');
  const offer = data.offers[0];

  return (
    <div>
      <button onClick={() => nav('/recruiter/candidates')} className="mb-4 inline-flex items-center gap-1.5 text-sm text-body hover:text-ink"><ArrowLeft className="h-4 w-4" />Candidates</button>
      <div className="card mb-6 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary-soft font-semibold text-primary">{p.name.split(' ').map((x: string) => x[0]).slice(0, 2).join('')}</div>
            <div>
              <h1 className="flex items-center gap-2 text-xl font-semibold text-ink">{p.name}{p.isDemo && <MockTag label="SYNTHETIC" />}</h1>
              <p className="text-sm text-body">{p.job?.title} · {p.email}{p.phone ? ` · ${p.phone}` : ''}</p>
              <p className="text-xs text-muted">Applied {fmtDate(p.appliedAt, false)}{p.holdReason ? ` · On hold: ${p.holdReason}` : ''}</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" size="sm" icon={<MessageSquare className="h-3.5 w-3.5" />} onClick={() => setModal('clarify')}>Request clarification</Button>
            {p.stageIndex >= 4 && !openInterview && p.stageIndex < 5 && <Button variant="secondary" size="sm" icon={<CalendarPlus className="h-3.5 w-3.5" />} onClick={() => setModal('schedule')}>Schedule interview</Button>}
            {openInterview && <Button size="sm" icon={<Video className="h-3.5 w-3.5" />} onClick={() => nav(`/recruiter/interview/${openInterview.id}`)}>Join interview room</Button>}
            {p.stageIndex >= 5 && (!offer || offer.status === 'revoked') && <Button size="sm" icon={<BadgeCheck className="h-3.5 w-3.5" />} onClick={() => setModal('offer')}>Issue offer</Button>}
            <a href={`/api/reports/${p.id}.pdf`}><Button variant="secondary" size="sm" icon={<Download className="h-3.5 w-3.5" />}>Report</Button></a>
          </div>
        </div>
        <div className="mt-6"><StageStepper stageIndex={p.stageIndex} stageScores={Object.fromEntries(Object.entries(s.stages).map(([k, v]: any) => [k, v.score]))} flagged={flagged} /></div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
        <TrustScoreCard scores={s} signals={data.signals} />
        <div className="space-y-6">
          <StageScoreGrid scores={s} />
          <Card title="Trust score history" description="Every change links to the signal that caused it."><ScoreHistoryChart history={data.history} /></Card>
        </div>
      </div>

      <div className="mt-8">
        <Tabs value={tab} onChange={setTab} tabs={[
          { key: 'signals', label: 'Signals', badge: s.pendingReview }, { key: 'identity', label: 'Identity' }, { key: 'resume', label: 'Resume' },
          { key: 'assessment', label: 'Assessment' }, { key: 'interview', label: 'Interview' }, { key: 'network', label: 'Network & location' },
          { key: 'offer', label: 'Offer & onboarding' }, { key: 'audit', label: 'Audit & consent', badge: data.appeals.filter((a: any) => a.status === 'open').length },
        ]} />
        <div className="mt-6">
          {tab === 'signals' && <Card pad={false}><SignalTable signals={data.signals} onReview={setReview} /><div className="px-6 pb-5"><ScoreDisclaimer /></div></Card>}
          {tab === 'identity' && <IdentityTab data={data} />}
          {tab === 'resume' && (data.resume ? <ResumeReport report={data.resume} /> : <Card><Empty title="No resume yet" /></Card>)}
          {tab === 'assessment' && <AssessmentTab data={data} />}
          {tab === 'interview' && <InterviewTab data={data} />}
          {tab === 'network' && <NetworkTab data={data} />}
          {tab === 'offer' && <OfferTab data={data} reload={reload} />}
          {tab === 'audit' && <AuditTab data={data} reload={reload} />}
        </div>
      </div>

      <ReviewModal signal={review} onClose={() => setReview(null)} onDone={reload} />
      <ScheduleModal open={modal === 'schedule'} onClose={() => setModal(null)} candidateId={p.id} onDone={() => { reload(); toast('Interview scheduled'); }} />
      <OfferModal open={modal === 'offer'} onClose={() => setModal(null)} candidateId={p.id} onDone={() => { reload(); toast('Offer issued'); }} />
      <ClarifyModal open={modal === 'clarify'} onClose={() => setModal(null)} candidateId={p.id} onDone={() => { reload(); toast('Request sent to the candidate'); }} />
    </div>
  );
}

function IdentityTab({ data }: { data: any }) {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title={<span className="flex items-center gap-2">Identity record <MockTag /></span>}>
        {data.identity ? <dl className="grid grid-cols-2 gap-4 text-sm">
          <div><dt className="label">Aadhaar</dt><dd className="mt-1 text-ink tnum">{data.identity.aadhaar_masked}</dd></div>
          <div><dt className="label">Provider</dt><dd className="mt-1 text-ink">{data.identity.provider}</dd></div>
          <div><dt className="label">Name on record</dt><dd className="mt-1 text-ink">{data.identity.record_name || '—'}</dd></div>
          <div><dt className="label">Verified</dt><dd className="mt-1 text-ink">{fmtDate(data.identity.verified_at)}</dd></div>
        </dl> : <p className="text-sm text-muted">Not verified yet.</p>}
      </Card>
      <Card title="Identity anchor" description="Encrypted face embedding reused at every later stage.">
        {data.anchor ? <div className="space-y-2 text-sm">
          <p className="text-ink">{data.anchor.model}</p>
          <p className="text-body">Liveness: {data.anchor.liveness?.challenges?.map((c: any) => typeof c === 'string' ? c : c.name).join(', ')}</p>
          <p className="text-xs text-muted">Enrolled {fmtDate(data.anchor.created_at)} · retained until {fmtDate(data.anchor.retention_until, false)} · ID photo {data.anchor.has_id_photo ? 'compared' : 'not provided'}</p>
        </div> : <p className="text-sm text-muted">Not enrolled.</p>}
      </Card>
      <Card className="lg:col-span-2" title="Face continuity checks" description="Distance to the identity anchor (lower is more similar · < 0.50 match · > 0.60 mismatch)." pad={false}>
        <FaceChecks checks={data.faceChecks} />
      </Card>
    </div>
  );
}

function FaceChecks({ checks }: { checks: any[] }) {
  if (!checks.length) return <p className="px-6 pb-6 text-sm text-muted">No checks yet.</p>;
  return (
    <div className="overflow-x-auto"><table className="w-full"><thead className="border-y border-divider"><tr><th className="th">Stage</th><th className="th">Session</th><th className="th">Faces</th><th className="th">Distance</th><th className="th">Result</th><th className="th">When</th></tr></thead>
      <tbody>{checks.slice(0, 25).map((c, i) => <tr key={i} className="border-b border-divider last:border-0"><td className="td">{STAGE_LABELS[c.stage]}</td><td className="td text-xs text-muted">{c.session_ref || '—'}</td><td className="td tnum">{c.faces ?? '—'}</td><td className="td tnum">{c.distance != null ? Number(c.distance).toFixed(3) : '—'}</td><td className="td"><Pill tone={c.result === 'match' ? 'ok' : c.result === 'uncertain' ? 'warn' : 'review'}>{humanize(c.result)}</Pill></td><td className="td text-xs text-muted">{fmtDate(c.created_at)}</td></tr>)}</tbody>
    </table></div>
  );
}

const EVENT_TONE: Record<string, string> = { FACE_MISMATCH: 'risk', MULTIPLE_FACES: 'review', NO_FACE: 'warn', PASTE_ATTEMPT: 'review', COPY_ATTEMPT: 'warn', TAB_HIDDEN: 'warn', WINDOW_BLUR: 'warn', FULLSCREEN_EXIT: 'warn', IP_CHANGE: 'info', SESSION_START: 'primary', SESSION_END: 'primary', NEW_TAB_OPENED: 'warn', VOICE_MISMATCH: 'review', VOICE_MATCH: 'ok', SCREEN_SHARE_STOPPED: 'review', LIP_SYNC_LOW: 'warn' };

export function EventTimeline({ events }: { events: any[] }) {
  if (!events.length) return <p className="text-sm text-muted">No events.</p>;
  return (
    <ol className="relative space-y-3 border-l border-line pl-5">
      {events.map((e: any) => (
        <li key={e.id} className="relative">
          <span className={cx('absolute -left-[25px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-white', `bg-${EVENT_TONE[e.event_type] === 'primary' ? 'neutral' : EVENT_TONE[e.event_type] || 'neutral'}`)} />
          <div className="flex flex-wrap items-center gap-2"><span className="text-sm font-medium text-ink">{humanize(e.event_type.toLowerCase())}</span><Pill>{e.source}</Pill><span className="text-xs text-muted tnum">{new Date(e.created_at).toLocaleTimeString('en-IN')}</span></div>
          {e.details && Object.keys(e.details).length > 0 && <p className="text-xs text-muted">{Object.entries(e.details).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · ')}</p>}
        </li>
      ))}
    </ol>
  );
}

function AssessmentTab({ data }: { data: any }) {
  if (!data.sessions.length) return <Card><Empty title="No assessment sessions" /></Card>;
  return (
    <div className="space-y-6">
      {data.sessions.map((s: any) => {
        const counts = s.events.reduce((a: any, e: any) => ({ ...a, [e.event_type]: (a[e.event_type] || 0) + 1 }), {});
        return (
          <Card key={s.id} title={`Session ${s.id}`} description={`${fmtDate(s.started_at)} → ${s.ended_at ? fmtDate(s.ended_at) : 'in progress'} · extension ${s.extension_version || 'not used'}`} action={<Pill tone={s.status === 'submitted' ? 'ok' : s.status === 'active' ? 'primary' : 'neutral'}>{s.status}{s.score != null ? ` · ${s.score}/${s.max_score}` : ''}</Pill>}>
            <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
              <div className="grid grid-cols-2 gap-3 self-start">
                {[['Tab switches', (counts.TAB_HIDDEN || 0) + (counts.TAB_SWITCH || 0)], ['Focus lost', counts.WINDOW_BLUR || 0], ['Fullscreen exits', counts.FULLSCREEN_EXIT || 0], ['Paste attempts', counts.PASTE_ATTEMPT || 0], ['Copy attempts', counts.COPY_ATTEMPT || 0], ['Face mismatches', counts.FACE_MISMATCH || 0], ['IP changes', counts.IP_CHANGE || 0], ['New tabs', counts.NEW_TAB_OPENED || 0]].map(([l, n]: any) => (
                  <div key={l} className="rounded-lg bg-page p-3"><p className="text-xs text-muted">{l}</p><p className={cx('text-lg font-semibold tnum', n ? 'text-ink' : 'text-muted')}>{n}</p></div>
                ))}
              </div>
              <div className="max-h-96 overflow-y-auto pr-2"><EventTimeline events={s.events} /></div>
            </div>
            {(s.agent?.state !== 'not_connected' || s.security?.total > 0) && (
              <div className="mt-6 border-t border-divider pt-5"><SecurityCardInline sessionId={s.id} needsReview={s.security?.needsReview || 0} /></div>
            )}
          </Card>
        );
      })}
      <Card title="Face checks during assessments" pad={false}><FaceChecks checks={data.faceChecks.filter((c: any) => c.stage === 'assessment')} /></Card>
    </div>
  );
}

function SecurityCardInline({ sessionId, needsReview }: { sessionId: string; needsReview: number }) {
  const [open, setOpen] = useState(needsReview > 0);
  return open ? <SecurityCard sessionId={sessionId} /> : (
    <button onClick={() => setOpen(true)} className="link text-sm">Show desktop security timeline{needsReview ? ` (${needsReview} to review)` : ''}</button>
  );
}

function InterviewTab({ data }: { data: any }) {
  const nav = useNavigate();
  if (!data.interviews.length) return <Card><Empty title="No interviews yet" text="Schedule one once the assessment is complete." /></Card>;
  return (
    <div className="space-y-6">
      {data.interviews.map((iv: any) => (
        <Card key={iv.id} title={`Interview · ${fmtDate(iv.scheduled_at)}`} description={`Room ${iv.room_id}`} action={<div className="flex items-center gap-2"><Pill tone={iv.status === 'completed' ? 'ok' : 'primary'}>{iv.status}</Pill>{iv.status !== 'completed' && <Button size="sm" onClick={() => nav(`/recruiter/interview/${iv.id}`)}>Join</Button>}</div>}>
          <div className="grid gap-6 lg:grid-cols-3">
            <div><p className="label">Face continuity</p><div className="mt-2 flex flex-wrap gap-1.5">{Object.entries(iv.summary.face).map(([k, n]: any) => <Pill key={k} tone={k === 'match' ? 'ok' : 'review'}>{humanize(k)}: {n}</Pill>)}{!Object.keys(iv.summary.face).length && <span className="text-sm text-muted">—</span>}</div>
              <p className="label mt-4">Voice <span className="normal-case">(experimental)</span></p><div className="mt-2 flex flex-wrap gap-1.5">{Object.entries(iv.summary.voice).map(([k, n]: any) => <Pill key={k} tone={k === 'VOICE_MATCH' ? 'ok' : k === 'VOICE_MISMATCH' ? 'review' : 'warn'}>{humanize(k.replace('VOICE_', '').toLowerCase())}: {n}</Pill>)}{!Object.keys(iv.summary.voice).length && <span className="text-sm text-muted">—</span>}</div></div>
            <div><p className="label">Evaluation</p>{iv.rubric ? <dl className="mt-2 space-y-1 text-sm">{Object.entries(iv.rubric).map(([k, v]: any) => <div key={k} className="flex justify-between"><dt className="text-body">{humanize(k.replace(/([A-Z])/g, ' $1').toLowerCase())}</dt><dd className="font-medium text-ink tnum">{v}/5</dd></div>)}</dl> : <p className="mt-2 text-sm text-muted">Not submitted.</p>}{iv.notes && <p className="mt-3 text-sm text-body">“{iv.notes}”</p>}</div>
            <div><p className="label">Assessment ↔ interview comparison</p>{iv.verification?.comparison ? <div className="mt-2 space-y-1.5 text-sm text-body"><p>Network: {iv.verification.comparison.network.sameNetwork == null ? '—' : iv.verification.comparison.network.sameNetwork ? 'same network' : `${iv.verification.comparison.network.assessment} → ${iv.verification.comparison.network.interview}`}</p><p>Location: {iv.verification.comparison.location ? `${iv.verification.comparison.location.distanceKm} km apart` : '—'}</p><p className="text-xs text-muted">{iv.verification.comparison.note}</p></div> : <p className="mt-2 text-sm text-muted">Available after the interview is completed.</p>}</div>
          </div>
          <div className="mt-6 max-h-72 overflow-y-auto"><EventTimeline events={[...iv.summary.events].reverse()} /></div>
        </Card>
      ))}
    </div>
  );
}

function NetworkTab({ data }: { data: any }) {
  const points = [...data.locations.map((l: any) => ({ ...l, kind: 'device' })), ...data.ip.filter((i: any) => i.lat).map((i: any) => ({ ...i, kind: 'ip', source: 'ip' }))].sort((a, b) => a.created_at.localeCompare(b.created_at));
  const [sel, setSel] = useState<any>(points[points.length - 1] || null);
  const bbox = sel ? `${sel.lng - 0.08},${sel.lat - 0.05},${sel.lng + 0.08},${sel.lat + 0.05}` : null;
  return (
    <div className="space-y-6">
      <Callout tone="info">IP and location changes are context for reviewers — travel, mobile data and VPNs are common. They never reduce the trust score on their own.</Callout>
      <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
        <Card title={<span className="flex items-center gap-2"><MapPin className="h-4 w-4 text-primary" />Location consistency</span>} description="Consented device locations and approximate IP regions by stage." pad={false}>
          <div className="divide-y divide-divider">
            {points.length === 0 && <p className="px-6 pb-6 text-sm text-muted">No location observations.</p>}
            {points.map((pt, i) => (
              <button key={i} onClick={() => setSel(pt)} className={cx('flex w-full items-center justify-between gap-3 px-6 py-3 text-left hover:bg-page', sel === pt && 'bg-primary-soft/50')}>
                <div><p className="text-sm text-ink">{pt.place?.city || pt.city || '—'}{pt.place?.region || pt.region ? `, ${pt.place?.region || pt.region}` : ''}</p><p className="text-xs text-muted">{STAGE_LABELS[pt.stage]} · {fmtDate(pt.created_at)}</p></div>
                <Pill tone={pt.kind === 'device' ? 'primary' : 'neutral'}>{pt.kind === 'device' ? `GPS ±${Math.round(pt.accuracy || 0)} m` : 'IP (approx.)'}</Pill>
              </button>
            ))}
          </div>
        </Card>
        <Card title="Map" description={sel ? `${sel.lat.toFixed(4)}, ${sel.lng.toFixed(4)} · ${sel.kind === 'ip' ? 'city-level approximation' : 'device location'}` : undefined}>
          {sel ? <iframe title="map" className="h-72 w-full rounded-lg border border-line" loading="lazy" src={`https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${sel.lat},${sel.lng}`} /> : <Empty title="No location selected" />}
        </Card>
      </div>
      <Card title={<span className="flex items-center gap-2"><Network className="h-4 w-4 text-primary" />IP observation timeline</span>} description="Masked by default. Captured server-side." pad={false}>
        <div className="overflow-x-auto"><table className="w-full"><thead className="border-y border-divider"><tr><th className="th">When</th><th className="th">Stage</th><th className="th">IP</th><th className="th">Approx. region</th><th className="th">Change</th></tr></thead>
          <tbody>{data.ip.map((o: any, i: number) => <tr key={i} className="border-b border-divider last:border-0"><td className="td text-xs text-muted">{fmtDate(o.created_at)}</td><td className="td">{STAGE_LABELS[o.stage]}</td><td className="td tnum">{o.ip_masked}</td><td className="td text-xs">{[o.city, o.region].filter(Boolean).join(', ') || o.geo_source}</td><td className="td">{o.changed ? <Pill tone="info">changed</Pill> : <span className="text-xs text-muted">—</span>}</td></tr>)}</tbody>
        </table></div>
      </Card>
    </div>
  );
}

function OfferTab({ data, reload }: { data: any; reload: () => void }) {
  const toast = useToast();
  const [comment, setComment] = useState('');
  const act = async (url: string, body: any, msg: string) => { try { await api.post(url, body); toast(msg); reload(); } catch (e: any) { toast(e.message, 'risk'); } };
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="Offers">
        {data.offers.length === 0 ? <p className="text-sm text-muted">No offers issued.</p> : data.offers.map((o: any) => (
          <div key={o.id} className="border-b border-divider py-3 first:pt-0 last:border-0">
            <div className="flex items-center justify-between"><p className="font-medium text-ink">{o.title}</p><Pill tone={o.status === 'accepted' ? 'ok' : o.status === 'held_for_review' ? 'review' : o.status === 'revoked' ? 'risk' : 'primary'}>{o.status.replace(/_/g, ' ')}</Pill></div>
            <p className="text-xs text-muted">{o.id} · issued {fmtDate(o.issued_at)} · {o.salary}</p>
            {o.acceptance && <p className="mt-2 text-xs text-body">Acceptance check: face {o.acceptance.face?.result} (distance {o.acceptance.face?.distance}) · same Aadhaar: {String(o.acceptance.sameIdentity)}{o.acceptance.contactChanges?.length ? ` · contact changed: ${o.acceptance.contactChanges.join(', ')}` : ''}</p>}
            <div className="mt-3 flex flex-wrap gap-2">
              <Link to={`/verify/${o.id}`} target="_blank" className="link inline-flex items-center gap-1 text-xs"><ExternalLink className="h-3 w-3" />Public verification page</Link>
              {o.status === 'held_for_review' && <>
                <Input placeholder="Review comment" value={comment} onChange={(e) => setComment(e.target.value)} className="h-8 max-w-xs text-xs" />
                <Button size="sm" variant="secondary" disabled={comment.length < 5} onClick={() => act(`/api/offers/${o.id}/release-hold`, { decision: 'accept', comment }, 'Acceptance approved')}>Approve acceptance</Button>
                <Button size="sm" variant="ghost" disabled={comment.length < 5} onClick={() => act(`/api/offers/${o.id}/release-hold`, { decision: 'retry', comment }, 'Candidate can retry')}>Ask to retry</Button>
              </>}
              {['issued', 'held_for_review'].includes(o.status) && <Button size="sm" variant="danger" onClick={() => act(`/api/offers/${o.id}/revoke`, { reason: 'Revoked by recruiter' }, 'Offer revoked')}>Revoke</Button>}
            </div>
          </div>
        ))}
      </Card>
      <Card title="Onboarding">
        {!data.onboarding ? <p className="text-sm text-muted">Starts after offer acceptance.</p> : (
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between"><span className="text-body">Status</span><Pill tone={data.onboarding.status === 'completed' ? 'ok' : data.onboarding.status === 'paused_for_review' ? 'review' : 'primary'}>{data.onboarding.status.replace(/_/g, ' ')}</Pill></div>
            <div className="flex items-center justify-between"><span className="text-body">Day-one identity</span>{data.onboarding.checklist.identity ? <CheckCircle2 className="h-4 w-4 text-ok" /> : <span className="text-xs text-muted">pending</span>}</div>
            <div className="flex items-center justify-between"><span className="text-body">DigiLocker documents</span>{data.onboarding.checklist.digilocker ? <CheckCircle2 className="h-4 w-4 text-ok" /> : <span className="text-xs text-muted">pending</span>}</div>
            {data.documents.filter((d: any) => d.kind.startsWith('joining')).map((d: any) => <div key={d.id} className="flex justify-between text-xs"><span className="text-body">{d.filename}</span><span className="text-muted">{d.status}</span></div>)}
            {data.onboarding.status !== 'completed' && <div className="pt-2"><Textarea rows={2} placeholder="Approval comment (required if review items are open)" value={comment} onChange={(e) => setComment(e.target.value)} /><Button className="mt-2" size="sm" onClick={() => act(`/api/onboarding/${data.profile.id}/approve`, { comment }, 'Onboarding approved')}>Approve joining</Button></div>}
            {data.onboarding.joined_at && <p className="text-xs text-muted">Joined {fmtDate(data.onboarding.joined_at)}</p>}
          </div>
        )}
      </Card>
    </div>
  );
}

function AuditTab({ data, reload }: { data: any; reload: () => void }) {
  const toast = useToast();
  const [resp, setResp] = useState<Record<number, string>>({});
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="Candidate responses & appeals">
        {data.appeals.length === 0 ? <p className="text-sm text-muted">None.</p> : data.appeals.map((a: any) => (
          <div key={a.id} className="border-b border-divider py-3 first:pt-0 last:border-0">
            <div className="flex items-center justify-between"><Pill tone={a.status === 'open' ? 'warn' : 'neutral'}>{a.status.replace('_', ' ')}</Pill><span className="text-xs text-muted">{fmtDate(a.created_at)}</span></div>
            <p className="mt-2 text-sm text-ink">{a.message}</p>
            {a.response ? <p className="mt-1 text-xs text-body">Response: {a.response}</p> : a.status === 'open' && (
              <div className="mt-2 flex gap-2"><Input className="h-8 text-xs" placeholder="Reply" value={resp[a.id] || ''} onChange={(e) => setResp({ ...resp, [a.id]: e.target.value })} /><Button size="sm" onClick={async () => { await api.post(`/api/recruiter/appeals/${a.id}/respond`, { response: resp[a.id] }); toast('Reply sent'); reload(); }}>Reply</Button></div>
            )}
          </div>
        ))}
      </Card>
      <Card title="Consent records">
        <div className="space-y-1.5 text-sm">{data.consents.map((c: any, i: number) => <div key={i} className="flex justify-between"><span className="capitalize text-body">{c.purpose.replace('_', ' ')}</span><span className="text-xs text-muted">{c.withdrawn_at ? `withdrawn ${fmtDate(c.withdrawn_at)}` : `granted ${fmtDate(c.created_at)}`}</span></div>)}{!data.consents.length && <p className="text-muted">None.</p>}</div>
      </Card>
      <Card className="lg:col-span-2" title="Audit history" pad={false}>
        <div className="max-h-96 overflow-y-auto"><table className="w-full"><thead className="sticky top-0 border-y border-divider bg-white"><tr><th className="th">When</th><th className="th">Actor</th><th className="th">Action</th><th className="th">Details</th></tr></thead>
          <tbody>{data.audit.map((a: any) => <tr key={a.id} className="border-b border-divider last:border-0"><td className="td text-xs text-muted">{fmtDate(a.created_at)}</td><td className="td text-sm">{a.actor_name || a.actor_role}</td><td className="td"><code className="text-xs">{a.action}</code></td><td className="td max-w-md truncate text-xs text-muted">{a.details ? JSON.stringify(a.details) : ''}</td></tr>)}</tbody>
        </table></div>
      </Card>
    </div>
  );
}

function ScheduleModal({ open, onClose, candidateId, onDone }: any) {
  const [at, setAt] = useState(() => new Date(Date.now() + 10 * 60000).toISOString().slice(0, 16));
  const [busy, setBusy] = useState(false); const toast = useToast();
  return <Modal open={open} onClose={onClose} title="Schedule interview" footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button loading={busy} onClick={async () => { setBusy(true); try { await api.post('/api/interviews', { candidateId, scheduledAt: new Date(at).toISOString() }); onDone(); onClose(); } catch (e: any) { toast(e.message, 'risk'); } finally { setBusy(false); } }}>Schedule</Button></>}>
    <Field label="Date & time"><Input type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} /></Field>
    <p className="mt-3 text-xs text-muted">The candidate sees the interview in their portal and joins with camera, mandatory screen share and optional location.</p>
  </Modal>;
}

function OfferModal({ open, onClose, candidateId, onDone }: any) {
  const [f, setF] = useState({ title: 'Software Engineer — Platform', salary: '₹ 24,00,000 per annum', startDate: new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10), expiresInDays: 14, overrideComment: '' });
  const [blocked, setBlocked] = useState<any>(null); const [busy, setBusy] = useState(false); const toast = useToast();
  const submit = async () => { setBusy(true); try { await api.post('/api/offers', { candidateId, ...f }); onDone(); onClose(); } catch (e: any) { if (e.data?.unresolved) setBlocked(e.data.unresolved); else toast(e.message, 'risk'); } finally { setBusy(false); } };
  return <Modal open={open} onClose={onClose} title="Issue offer" footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button loading={busy} onClick={submit}>Issue signed offer</Button></>}>
    <div className="space-y-4">
      <Field label="Role"><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></Field>
      <div className="grid grid-cols-2 gap-3"><Field label="Compensation"><Input value={f.salary} onChange={(e) => setF({ ...f, salary: e.target.value })} /></Field><Field label="Start date"><Input type="date" value={f.startDate} onChange={(e) => setF({ ...f, startDate: e.target.value })} /></Field></div>
      <Field label="Valid for (days)"><Input type="number" value={f.expiresInDays} onChange={(e) => setF({ ...f, expiresInDays: Number(e.target.value) })} /></Field>
      {blocked && <Callout tone="review" title="Unresolved high-risk review items">{blocked.map((b: any) => <p key={b.id}>• {b.label}</p>)}<p className="mt-2">Review them first, or add an override reason (audit-logged).</p></Callout>}
      {blocked && <Field label="Override reason"><Textarea rows={2} value={f.overrideComment} onChange={(e) => setF({ ...f, overrideComment: e.target.value })} /></Field>}
      <p className="text-xs text-muted">The offer is hashed and signed; a QR code lets anyone verify it hasn't been altered.</p>
    </div>
  </Modal>;
}

function ClarifyModal({ open, onClose, candidateId, onDone }: any) {
  const [msg, setMsg] = useState(''); const toast = useToast();
  return <Modal open={open} onClose={onClose} title="Request clarification" footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button disabled={msg.length < 5} onClick={async () => { try { await api.post(`/api/recruiter/candidates/${candidateId}/clarification`, { message: msg }); onDone(); onClose(); setMsg(''); } catch (e: any) { toast(e.message, 'risk'); } }}>Send</Button></>}>
    <Textarea rows={4} value={msg} onChange={(e) => setMsg(e.target.value)} placeholder="e.g. Could you confirm your expected graduation year and upload a provisional certificate?" />
    <p className="mt-2 text-xs text-muted">Shown on the candidate's dashboard. Use neutral wording — flags are not conclusions.</p>
  </Modal>;
}
