import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Radio, Video, Monitor } from 'lucide-react';
import { Card, PageHeader, Pill, Button, Skeleton, useAsync, Empty, Tabs, cx } from '../../components/ui';
import { SecurityPanel } from './SecurityPanel';
import { EventTimeline } from './CandidateDetail';
import { api, fmtDate, timeAgo } from '../../lib/api';
import { useRealtime } from '../../lib/realtime';

export default function LiveMonitor() {
  const { data, reload } = useAsync(() => api.get('/api/recruiter/live'), []);
  const [sel, setSel] = useState<string | null>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [pane, setPane] = useState('browser');
  const nav = useNavigate();
  useRealtime((m) => {
    if (m.type === 'monitoring' || m.type === 'session' || m.type === 'trust' || m.type === 'security' || m.type === 'agent') reload();
    if (m.type === 'monitoring' && m.event.sessionId === sel) setEvents((e) => [...e, { id: m.event.id, event_type: m.event.type, source: m.event.source, details: m.event.details, created_at: m.event.createdAt }]);
  }, [sel]);
  useEffect(() => { const t = setInterval(reload, 5000); return () => clearInterval(t); }, []);
  useEffect(() => { if (sel) api.get(`/api/recruiter/sessions/${sel}/events`).then((r) => setEvents(r.events)); }, [sel]);
  if (!data) return <Skeleton className="h-96" />;
  const current = data.sessions.find((s: any) => s.id === sel);
  return (
    <div>
      <PageHeader title="Live monitoring" description="Assessment sessions and interviews, updated in real time." />
      {data.interviews.length > 0 && (
        <Card className="mb-6" title="Interviews" pad={false}>
          <div className="divide-y divide-divider">{data.interviews.map((i: any) => (
            <div key={i.id} className="flex items-center justify-between px-6 py-3"><div><p className="text-sm font-medium text-ink">{i.candidate_name}</p><p className="text-xs text-muted">{fmtDate(i.scheduled_at)} · {i.room_id}</p></div><div className="flex items-center gap-2"><Pill tone={i.status === 'live' ? 'risk' : 'primary'} dot>{i.status}</Pill><Button size="sm" icon={<Video className="h-3.5 w-3.5" />} onClick={() => nav(`/recruiter/interview/${i.id}`)}>Open room</Button></div></div>
          ))}</div>
        </Card>
      )}
      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <Card title="Assessment sessions" pad={false}>
          {data.sessions.length === 0 ? <Empty icon={<Radio className="h-5 w-5" />} title="No sessions yet" /> : (
            <div className="overflow-x-auto"><table className="w-full min-w-[640px]">
              <thead className="border-y border-divider"><tr><th className="th">Candidate</th><th className="th">Status</th><th className="th text-right">Tab</th><th className="th text-right">Focus</th><th className="th text-right">Paste</th><th className="th text-right">FS exit</th><th className="th">Identity</th><th className="th">Desktop agent</th><th className="th">Flags</th></tr></thead>
              <tbody>{data.sessions.map((s: any) => (
                <tr key={s.id} onClick={() => setSel(s.id)} className={cx('h-14 cursor-pointer border-b border-divider last:border-0 hover:bg-page', sel === s.id && 'bg-primary-soft/40')}>
                  <td className="td"><p className="font-medium text-ink">{s.candidate_name}</p><p className="text-xs text-muted">{s.id} · {timeAgo(s.started_at)}</p></td>
                  <td className="td"><Pill tone={s.status === 'active' ? 'risk' : s.status === 'submitted' ? 'ok' : 'neutral'} dot>{s.status === 'active' ? 'live' : s.status}</Pill></td>
                  <td className="td text-right tnum">{(s.counts.TAB_HIDDEN || 0) + (s.counts.TAB_SWITCH || 0)}</td>
                  <td className="td text-right tnum">{s.counts.WINDOW_BLUR || 0}</td>
                  <td className="td text-right tnum">{s.counts.PASTE_ATTEMPT || 0}</td>
                  <td className="td text-right tnum">{s.counts.FULLSCREEN_EXIT || 0}</td>
                  <td className="td">{s.lastFace ? <Pill tone={s.lastFace.result === 'match' ? 'ok' : 'review'}>{s.lastFace.result.replace('_', ' ')}</Pill> : <span className="text-xs text-muted">—</span>}</td>
                  <td className="td">{s.agent?.state === 'not_connected' || !s.agent ? <span className="text-xs text-muted">—</span> : (
                    <span className="flex items-center gap-1.5"><Pill tone={s.agent.state === 'connected' ? 'ok' : s.agent.state === 'disconnected' ? 'review' : 'neutral'} dot>{s.agent.state}</Pill>{s.security?.needsReview ? <Pill tone="review">{s.security.needsReview} to review</Pill> : null}</span>)}</td>
                  <td className="td">{s.flags.length ? <Pill tone="review">{s.flags.length}</Pill> : <span className="text-xs text-muted">0</span>}</td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
        </Card>
        <Card title={current ? `${current.candidate_name} · ${current.title}` : 'Event timeline'} description={current ? `Session ${current.id} · extension ${current.extension_version || 'not used'}` : 'Select a session to follow its events live.'} action={current && <Link className="link text-xs" to={`/recruiter/candidates/${current.user_id}`}>Candidate</Link>}>
          {current ? <>
            {current.flags.length > 0 && <div className="mb-4 space-y-1.5">{current.flags.map((f: any) => <p key={f.id} className="flex items-center gap-2 text-sm text-review"><span className="h-1.5 w-1.5 rounded-full bg-review" />{f.label}</p>)}</div>}
            <Tabs value={pane} onChange={setPane} tabs={[{ key: 'browser', label: 'Browser events' }, { key: 'desktop', label: <span className="flex items-center gap-1.5"><Monitor className="h-3.5 w-3.5" />Desktop security</span>, badge: current.security?.needsReview }]} />
            <div className="mt-4">
              {pane === 'browser' ? <div className="max-h-[480px] overflow-y-auto pr-2"><EventTimeline events={[...events].reverse()} /></div> : <SecurityPanel sessionId={current.id} compact />}
            </div>
          </> : <Empty title="No session selected" />}
        </Card>
      </div>
    </div>
  );
}
