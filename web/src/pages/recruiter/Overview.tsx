import React from 'react';
import { Link } from 'react-router-dom';
import { Users, ShieldAlert, Gauge as GaugeIcon, Radio, Video, MessageSquare, ArrowRight } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { Card, PageHeader, Stat, Pill, Skeleton, useAsync, Empty } from '../../components/ui';
import { ScoreDisclaimer } from '../../components/trust';
import { api, STAGES, STAGE_LABELS, timeAgo, bandTone, scoreTone } from '../../lib/api';
import { useRealtime } from '../../lib/realtime';

const BAND_META: Record<string, { label: string; color: string }> = { high: { label: 'High trust', color: '#16A34A' }, moderate: { label: 'Moderate', color: '#D97706' }, review: { label: 'Needs review', color: '#EA580C' }, risk: { label: 'High risk', color: '#DC2626' } };

export default function Overview() {
  const { data, reload } = useAsync(() => api.get('/api/recruiter/overview'), []);
  useRealtime((m) => { if (['trust', 'session', 'interview'].includes(m.type)) reload(); }, []);
  if (!data) return <div className="grid gap-4 sm:grid-cols-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-28" />)}</div>;
  const k = data.kpis;
  const stageData = data.byStage.map((s: any) => ({ name: STAGE_LABELS[s.stage], count: s.count }));
  const totalBands = data.bands.reduce((a: number, b: any) => a + b.count, 0) || 1;
  return (
    <div>
      <PageHeader title="Overview" description="Trust across your hiring pipeline, updated live." />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Candidates" value={k.totalCandidates} icon={<Users className="h-4 w-4" />} sub={`${k.liveInterviews} live interview${k.liveInterviews === 1 ? '' : 's'}`} />
        <Stat label="Average trust" value={k.averageTrust} icon={<GaugeIcon className="h-4 w-4" />} tone={scoreTone(k.averageTrust)} sub="Weighted across completed stages" />
        <Stat label="Open review items" value={k.openAlerts} icon={<ShieldAlert className="h-4 w-4" />} tone={k.openAlerts ? 'review' : undefined} sub={`${k.openAppeals} candidate response${k.openAppeals === 1 ? '' : 's'} waiting`} />
        <Stat label="Active assessments" value={k.activeAssessments} icon={<Radio className="h-4 w-4" />} sub={<><Link to="/recruiter/live" className="link">Open live monitoring</Link>{k.desktopReview ? <span className="text-review"> · {k.desktopReview} desktop item{k.desktopReview === 1 ? '' : 's'} to review</span> : null}</>} />
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Candidates by stage" description="Where people are in the seven-stage journey.">
          <div className="h-64"><ResponsiveContainer><BarChart data={stageData} margin={{ left: -20, right: 8 }}><XAxis dataKey="name" tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} /><Tooltip cursor={{ fill: '#F8FAFC' }} contentStyle={{ borderRadius: 8, border: '1px solid #E2E8F0', fontSize: 12 }} /><Bar dataKey="count" radius={[6, 6, 0, 0]} fill="#4F46E5" maxBarSize={36} /></BarChart></ResponsiveContainer></div>
        </Card>
        <Card title="Trust bands">
          <div className="flex h-3 overflow-hidden rounded-full bg-subtle">{data.bands.map((b: any) => b.count > 0 && <div key={b.band} style={{ width: `${(b.count / totalBands) * 100}%`, background: BAND_META[b.band].color }} />)}</div>
          <div className="mt-5 space-y-3">{data.bands.map((b: any) => <div key={b.band} className="flex items-center justify-between text-sm"><span className="flex items-center gap-2 text-body"><span className="h-2.5 w-2.5 rounded-full" style={{ background: BAND_META[b.band].color }} />{BAND_META[b.band].label}</span><span className="font-medium text-ink tnum">{b.count}</span></div>)}</div>
          <div className="mt-5 border-t border-divider pt-4"><p className="label mb-2">Average by stage</p><div className="grid grid-cols-4 gap-2 text-center">{STAGES.map((s) => <div key={s}><p className="text-[10px] text-muted">{STAGE_LABELS[s].slice(0, 5)}</p><p className={`text-sm font-semibold tnum text-${scoreTone(data.stageAvg[s])}`}>{data.stageAvg[s] ?? '—'}</p></div>)}</div></div>
        </Card>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Needs review" action={<Link to="/recruiter/review" className="link text-xs">Open review queue</Link>} pad={false}>
          {data.alerts.length === 0 ? <Empty title="All clear" text="No open review items." /> : (
            <div className="divide-y divide-divider">
              {data.alerts.map((a: any) => (
                <Link key={a.id} to={`/recruiter/candidates/${a.candidate_id}`} className="flex items-center gap-4 px-6 py-3.5 hover:bg-page">
                  <span className="h-8 w-1 rounded-full bg-review" />
                  <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium text-ink">{a.label}</p><p className="text-xs text-muted">{a.candidate_name} · {STAGE_LABELS[a.stage]} · {timeAgo(a.created_at)}</p></div>
                  <span className="text-xs text-muted tnum">{a.score_delta} if confirmed</span><ArrowRight className="h-4 w-4 text-muted" />
                </Link>
              ))}
            </div>
          )}
        </Card>
        <Card title="Recent security events" pad={false}>
          <div className="max-h-[380px] divide-y divide-divider overflow-y-auto">
            {data.events.map((e: any) => (
              <div key={e.id} className="px-6 py-3"><p className="text-sm text-ink">{e.event_type.replace(/_/g, ' ').toLowerCase()}</p><p className="text-xs text-muted">{e.candidate_name} · {e.stage} · {timeAgo(e.created_at)}</p></div>
            ))}
          </div>
        </Card>
      </div>
      <div className="mt-6"><ScoreDisclaimer /></div>
    </div>
  );
}
