import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Puzzle, RefreshCw, Camera, Mic, Sun, Users, Plug, Server, Clock, ShieldCheck, ArrowRight, ArrowLeft, CheckCircle2, AlertTriangle, Download, Monitor } from 'lucide-react';
import { Card, PageHeader, Button, Callout, Pill, useToast, Skeleton, Textarea, cx } from '../../components/ui';
import { CameraView, Check, type LiveState } from '../../components/camera';
import { ConsentModal } from '../../components/consent';
import { useCandidate } from '../../lib/candidate';
import { api } from '../../lib/api';
import { pingExtension, startExtensionSession, endExtensionSession, extensionStatus, desktopAgentHealth, EXTENSION_ID, type AgentState } from '../../lib/extension';
import { describe, stopStream, loadFaceApi } from '../../lib/ai/face';
import { useStageLocation } from '../../components/location';

type Phase = 'list' | 'extension' | 'checks' | 'running' | 'done';

export default function Assessment() {
  const { data, reload } = useCandidate();
  const [list, setList] = useState<any>(null);
  const [phase, setPhase] = useState<Phase>('list');
  const [ext, setExt] = useState<any>(null);
  const [extBypass, setExtBypass] = useState(false);
  const [consentOpen, setConsentOpen] = useState(false);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [live, setLive] = useState<LiveState | null>(null);
  const [server, setServer] = useState<boolean | null>(null);
  const [agent, setAgent] = useState<{ reachable: boolean; version?: string } | null>(null);
  const [session, setSession] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<any>(null);
  const toast = useToast();
  const nav = useNavigate();

  useEffect(() => { api.get('/api/assessments').then(setList).catch(() => {}); }, []);
  useEffect(() => () => stopStream(stream), [stream]);

  const checkExtension = async () => { setExt('checking'); const r = await pingExtension(); setExt(r?.ok ? r : false); };
  // The optional Windows desktop agent is reached through the extension (web pages cannot call localhost services).
  const checkAgent = async () => { setAgent(null); const r = await desktopAgentHealth(); setAgent({ reachable: !!r?.reachable, version: r?.version }); };
  useEffect(() => { if (phase === 'extension') checkExtension(); }, [phase]);

  const openChecks = async () => {
    setConsentOpen(false); setErr(null);
    try {
      const s = await navigator.mediaDevices.getUserMedia({ video: { width: 1280, height: 720 }, audio: true });
      setStream(s); setPhase('checks'); loadFaceApi();
      api.get('/api/health').then(() => setServer(true)).catch(() => setServer(false));
      checkAgent();
    } catch { setErr('Camera and microphone are required for this assessment. Allow access in your browser settings and try again.'); }
  };

  const start = async () => {
    setErr(null);
    try {
      const s = await api.post('/api/assessment/sessions', { assessmentId: selected.id, consent: true, extensionVersion: ext?.version });
      if (ext?.ok) {
        const r = await startExtensionSession({ sessionId: s.sessionId, candidateId: data.profile.id, sessionToken: s.sessionToken, apiBaseUrl: location.origin, agentToken: s.agentToken });
        if (!r?.ok) toast(`Extension did not start monitoring: ${r?.error || 'no response'}`, 'review');
      }
      setSession(s); setPhase('running');
      document.documentElement.requestFullscreen?.().catch(() => {});
    } catch (e: any) { setErr(e.message); }
  };

  if (!data || !list) return <Skeleton className="h-96" />;
  if (data.profile.stageIndex < 3) return <div className="max-w-3xl"><PageHeader title="Assessment" /><Callout tone="info">Complete the resume step first.</Callout></div>;

  if (phase === 'running' && session) return <Runner session={session} stream={stream!} extActive={!!ext?.ok} onDone={(r) => { setResult(r); setPhase('done'); stopStream(stream); setStream(null); reload(); api.get('/api/assessments').then(setList); }} />;

  const camOk = !!stream?.getVideoTracks()[0]?.enabled, micOk = !!stream?.getAudioTracks()[0];
  const lightOk = (live?.light ?? 0) >= 60, faceOk = live?.faces === 1, extOk = !!ext?.ok || extBypass;
  const agentRequired = !!list?.desktopAgent?.required;
  const agentOk = !!agent?.reachable || !agentRequired;
  const allOk = camOk && micOk && lightOk && faceOk && extOk && server === true && agentOk;

  return (
    <div>
      <PageHeader title="Assessment" description="Stage 4 · A monitored screening test. Monitoring covers this browser tab only and starts only after you agree." />
      {phase === 'list' && (
        <div className="grid gap-6 lg:grid-cols-3">
          <div className="space-y-4 lg:col-span-2">
            {list.assessments.map((a: any) => {
              const done = list.sessions.find((s: any) => s.assessment_id === a.id && s.status === 'submitted');
              return (
                <div key={a.id} className="card flex flex-wrap items-center justify-between gap-4 p-6">
                  <div><h3 className="font-semibold text-ink">{a.title}</h3><p className="mt-1 text-sm text-body">{a.questions} questions · {Math.round(a.duration_sec / 60)} minutes · camera, microphone and SecureHire extension required</p></div>
                  {done ? <Pill tone="ok" dot>Completed · {done.score}/{done.max_score}</Pill> : <Button onClick={() => { setSelected(a); setPhase('extension'); }} icon={<ArrowRight className="h-4 w-4" />}>Begin</Button>}
                </div>
              );
            })}
            {result && <Callout tone="ok" title="Submitted">You scored {result.score}/{result.max}. {result.flagsRaised ? 'Some events will be reviewed by a recruiter — you can add context from your dashboard.' : 'No review items were raised.'}</Callout>}
            {list.sessions.some((s: any) => s.status === 'submitted') && <Button variant="secondary" onClick={() => nav('/candidate')}>Back to my journey</Button>}
          </div>
          <Card title="What is monitored">
            <ul className="space-y-2.5 text-sm text-body">
              {['Switching tabs or windows, leaving fullscreen', 'Copy, paste and right-click attempts (never what you copied)', 'Your face is compared with your identity anchor every 10 seconds', 'Your network address at checkpoints (changes are context only)', 'If the SecureHire desktop agent is running (Windows): USB devices connected, apps started and always-on-top windows — metadata only, never files, keystrokes or your screen'].map((t) => <li key={t} className="flex gap-2"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" />{t}</li>)}
            </ul>
            <p className="mt-4 text-xs text-muted">Notifications, accessibility tools or a flaky connection can cause events — a person reviews context before anything is decided.</p>
          </Card>
        </div>
      )}

      {phase === 'extension' && (
        <Card className="max-w-2xl" title={<span className="flex items-center gap-2"><Puzzle className="h-4 w-4 text-primary" />SecureHire extension</span>}>
          {ext === 'checking' ? <p className="text-sm text-body">Checking for the extension…</p> : ext?.ok ? (
            <div className="space-y-4"><Callout tone="ok" title="Extension connected">SecureHire Assessment Monitor v{ext.version} is installed and ready.</Callout><Button onClick={() => setConsentOpen(true)}>Continue</Button></div>
          ) : (
            <div className="space-y-4">
              <Callout tone="review" title="Install SecureHire to continue">The assessment can only start when the SecureHire Assessment Monitor extension is installed in this Chrome browser.</Callout>
              <ol className="list-decimal space-y-1.5 pl-5 text-sm text-body">
                <li>Download the <code>extension</code> folder from the SecureHire project (or the provided zip) and unzip it.</li>
                <li>Open <code>chrome://extensions</code> and switch on <b>Developer mode</b>.</li>
                <li>Click <b>Load unpacked</b> and select the <code>extension</code> folder.</li>
                <li>Come back here and click <b>Check again</b>.</li>
              </ol>
              <p className="text-xs text-muted">Expected extension ID: <code>{EXTENSION_ID}</code></p>
              <div className="flex flex-wrap gap-2">
                <Button icon={<RefreshCw className="h-4 w-4" />} onClick={checkExtension}>Check again</Button>
                {data.demoMode && <Button variant="ghost" onClick={() => { setExtBypass(true); setConsentOpen(true); }}>Continue without extension (demo only)</Button>}
              </div>
            </div>
          )}
        </Card>
      )}

      {phase === 'checks' && (
        <div className="grid gap-6 lg:grid-cols-[1.5fr_1fr]">
          <CameraView stream={stream} className="aspect-video" onFrame={setLive} />
          <Card title="Pre-test checks" description="All checks must pass before you can start.">
            <Check ok={camOk} label="Camera on" icon={<Camera className="h-3.5 w-3.5" />} />
            <Check ok={micOk} label="Microphone on" icon={<Mic className="h-3.5 w-3.5" />} />
            <Check ok={live ? lightOk : null} label="Good lighting" icon={<Sun className="h-3.5 w-3.5" />} detail={live && !lightOk ? 'Face a window or lamp' : undefined} />
            <Check ok={live ? faceOk : null} label="Exactly one face" icon={<Users className="h-3.5 w-3.5" />} detail={live && live.faces !== 1 ? `${live.faces} faces detected` : undefined} />
            <Check ok={extOk} label="Extension connected" icon={<Plug className="h-3.5 w-3.5" />} detail={extBypass ? 'Demo bypass — page-level monitoring only' : undefined} />
            <Check ok={server} label="Server connected" icon={<Server className="h-3.5 w-3.5" />} />
            <Check ok={agent === null ? null : agent.reachable ? true : agentRequired ? false : null}
              label={`Desktop security agent${agentRequired ? '' : ' (optional)'}`} icon={<Monitor className="h-3.5 w-3.5" />}
              detail={agent === null ? 'Checking…' : agent.reachable ? `Running (v${agent.version}) — it will show that monitoring is active` : ext?.ok
                ? `Not detected. ${agentRequired ? 'Required by this employer: start “SecureHire Security Agent” on this Windows PC, then' : 'If your employer provided it, start “SecureHire Security Agent”, then'} re-check.`
                : 'Needs the SecureHire extension.'} />
            {agent && !agent.reachable && ext?.ok && <button className="link mt-1 text-xs" onClick={checkAgent}>Re-check desktop agent</button>}
            {err && <div className="mt-3"><Callout tone="risk">{err}</Callout></div>}
            <Button className="mt-5 w-full" disabled={!allOk} onClick={start}>Start assessment</Button>
          </Card>
        </div>
      )}
      {err && phase !== 'checks' && <div className="mt-4"><Callout tone="risk">{err}</Callout></div>}

      <ConsentModal open={consentOpen} onClose={() => setConsentOpen(false)} onAgree={openChecks} title="Consent for assessment monitoring" agreeLabel="I agree — start checks"
        what={<>During this session only: tab visibility, window focus, fullscreen exits, copy/paste/right-click attempts (never clipboard contents), periodic face comparison with your identity anchor, and your IP address at checkpoints. If the SecureHire desktop agent is running on your Windows PC, it also records USB devices being connected or removed (device type only — never their contents), applications started during the test (name only), and the size, position and style of always-on-top windows. It never records keystrokes, passwords, files, window contents or screenshots, and it shows a visible status window the whole time.</>}
        why="To help ensure the assessment reflects your own work. Events are context for a human reviewer, not automatic findings. Accessibility tools (screen readers, magnifiers) and ordinary peripherals are expected and are not treated as suspicious."
        retention="Monitoring events are kept for 180 days (employer policy) and then deleted." />
    </div>
  );
}

function Runner({ session, stream, extActive, onDone }: { session: any; stream: MediaStream; extActive: boolean; onDone: (r: any) => void }) {
  const qs = session.questions;
  const [i, setI] = useState(0);
  const [answers, setAnswers] = useState<Record<number, any>>({});
  const timings = useRef<Record<number, number>>({});
  const qStart = useRef(performance.now());
  const [left, setLeft] = useState(session.assessment.durationSec);
  const [face, setFace] = useState<any>(null);
  const [extCounts, setExtCounts] = useState<any>(null);
  const [agentState, setAgentState] = useState<AgentState | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const toast = useToast();
  useStageLocation({ stage: 'assessment', sessionRef: session.sessionId, enabled: true, consented: false });

  const logPage = (type: string, details: any = {}) => api.post(`/api/assessment/sessions/${session.sessionId}/client-event`, { eventType: type, details, idempotencyKey: crypto.randomUUID(), timestamp: new Date().toISOString() }).catch(() => {});

  const markTime = () => { const now = performance.now(); const q = qs[i]; timings.current[q.id] = (timings.current[q.id] || 0) + (now - qStart.current); qStart.current = now; };

  const submit = async (auto = false) => {
    if (submitting) return;
    setSubmitting(true); markTime();
    try {
      const r = await api.post(`/api/assessment/sessions/${session.sessionId}/submit`, { answers, timings: Object.fromEntries(Object.entries(timings.current).map(([k, v]) => [k, Math.round(v)])), autoSubmitted: auto });
      await endExtensionSession();
      if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
      onDone(r);
    } catch (e: any) { toast(e.message, 'risk'); setSubmitting(false); }
  };

  // timer + auto-submit
  useEffect(() => { const t = setInterval(() => setLeft((x: number) => x - 1), 1000); return () => clearInterval(t); }, []);
  useEffect(() => { if (left <= 0) submit(true); }, [left]);

  // page-level lockdown (always) + page-level logging when the extension isn't active (avoids double counting)
  useEffect(() => {
    const block = (type: string) => (e: Event) => { e.preventDefault(); if (!extActive) logPage(type); };
    const onCopy = block('COPY_ATTEMPT'), onPaste = block('PASTE_ATTEMPT'), onCut = block('CUT_ATTEMPT'), onCtx = block('CONTEXT_MENU');
    const onKey = (e: KeyboardEvent) => { if (e.key === 'F12' || ((e.ctrlKey || e.metaKey) && e.shiftKey && ['I', 'J', 'C'].includes(e.key.toUpperCase())) || ((e.ctrlKey || e.metaKey) && ['P', 'U', 'S'].includes(e.key.toUpperCase()))) { e.preventDefault(); if (!extActive) logPage(e.key.toUpperCase() === 'P' ? 'PRINT_ATTEMPT' : 'DEVTOOLS_SHORTCUT'); } };
    const onVis = () => { if (!extActive) logPage(document.hidden ? 'TAB_HIDDEN' : 'TAB_VISIBLE'); };
    const onBlur = () => { if (!extActive) logPage('WINDOW_BLUR'); };
    const onFs = () => { if (!document.fullscreenElement && !extActive) logPage('FULLSCREEN_EXIT'); };
    document.addEventListener('copy', onCopy); document.addEventListener('paste', onPaste); document.addEventListener('cut', onCut); document.addEventListener('contextmenu', onCtx);
    document.addEventListener('keydown', onKey); document.addEventListener('visibilitychange', onVis); window.addEventListener('blur', onBlur); document.addEventListener('fullscreenchange', onFs);
    const track = stream.getVideoTracks()[0];
    const onEnded = () => logPage('CAMERA_OFF');
    track?.addEventListener('ended', onEnded);
    return () => {
      document.removeEventListener('copy', onCopy); document.removeEventListener('paste', onPaste); document.removeEventListener('cut', onCut); document.removeEventListener('contextmenu', onCtx);
      document.removeEventListener('keydown', onKey); document.removeEventListener('visibilitychange', onVis); window.removeEventListener('blur', onBlur); document.removeEventListener('fullscreenchange', onFs);
      track?.removeEventListener('ended', onEnded);
    };
  }, [extActive]);

  // continuous face continuity every 10 s
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      if (!alive || !videoRef.current) return;
      try {
        const d = await describe(videoRef.current);
        const r = await api.post('/api/me/face/verify', { stage: 'assessment', sessionRef: session.sessionId, faces: d.faces, descriptor: d.descriptor });
        if (alive) setFace(r);
      } catch { /* transient */ }
    };
    const first = setTimeout(tick, 2500);
    const t = setInterval(tick, 10_000);
    const s = setInterval(async () => { if (extActive) { const st = await extensionStatus(); setExtCounts(st?.counts || null); setAgentState(st?.agent || null); } }, 5000);
    return () => { alive = false; clearTimeout(first); clearInterval(t); clearInterval(s); };
  }, [session.sessionId, extActive]);

  const q = qs[i];
  const mm = Math.max(0, Math.floor(left / 60)), ss = Math.max(0, left % 60);
  const go = (n: number) => { markTime(); setI(n); };
  const faceTone = !face ? 'neutral' : face.result === 'match' ? 'ok' : face.result === 'uncertain' ? 'warn' : 'review';

  return (
    <div className="fixed inset-0 z-40 flex flex-col bg-page select-none">
      <header className="flex h-16 items-center justify-between border-b border-line bg-white px-6">
        <div><p className="font-semibold text-ink">{session.assessment.title}</p><p className="text-xs text-muted">Session {session.sessionId}{extActive ? ' · SecureHire extension active' : ' · page monitoring'}</p></div>
        <div className={cx('flex items-center gap-2 rounded-lg px-3 py-1.5 font-semibold tnum', left < 120 ? 'bg-red-50 text-risk' : 'bg-subtle text-ink')}><Clock className="h-4 w-4" />{String(mm).padStart(2, '0')}:{String(ss).padStart(2, '0')}</div>
      </header>
      <div className="mx-auto flex w-full max-w-3xl flex-1 flex-col px-4 py-8">
        <Callout tone="info">Copy, paste and new tabs are monitored during this test. Stay in fullscreen.</Callout>
        <div className="card mt-6 p-8">
          <p className="text-xs font-medium text-muted">Question {i + 1} of {qs.length}</p>
          <h2 className="mt-2 text-lg font-semibold leading-snug text-ink">{q.prompt}</h2>
          {q.type === 'mcq' ? (
            <div className="mt-6 space-y-2.5">
              {q.options.map((o: string, k: number) => (
                <button key={k} onClick={() => setAnswers({ ...answers, [q.id]: String(k) })} className={cx('flex w-full items-center gap-3 rounded-lg border px-4 py-3 text-left text-sm transition', answers[q.id] === String(k) ? 'border-primary bg-primary-soft text-ink' : 'border-line bg-white hover:border-slate-300')}>
                  <span className={cx('flex h-5 w-5 items-center justify-center rounded-full border text-[11px]', answers[q.id] === String(k) ? 'border-primary bg-primary text-white' : 'border-line text-muted')}>{String.fromCharCode(65 + k)}</span>{o}
                </button>
              ))}
            </div>
          ) : <Textarea className="mt-6 font-mono" rows={8} value={answers[q.id] || ''} onChange={(e) => setAnswers({ ...answers, [q.id]: e.target.value })} placeholder="function isPalindrome(s) { … }" />}
          <div className="mt-8 flex justify-between">
            <Button variant="secondary" disabled={i === 0} onClick={() => go(i - 1)} icon={<ArrowLeft className="h-4 w-4" />}>Previous</Button>
            {i < qs.length - 1 ? <Button onClick={() => go(i + 1)}>Next</Button> : <Button onClick={() => submit(false)} loading={submitting}>Submit assessment</Button>}
          </div>
        </div>
        <div className="mt-4 flex justify-center gap-1.5">{qs.map((x: any, k: number) => <span key={x.id} className={cx('h-1.5 w-6 rounded-full', k === i ? 'bg-primary' : answers[x.id] != null ? 'bg-primary/40' : 'bg-line')} />)}</div>
      </div>
      <div className="fixed bottom-5 right-5 w-56 overflow-hidden rounded-card border border-line bg-white shadow-pop">
        <CameraView stream={stream} videoRef={videoRef} mesh className="aspect-video" />
        <div className="space-y-1 px-3 py-2 text-xs">
          <div className="flex items-center gap-2"><span className={cx('h-2 w-2 rounded-full', faceTone === 'ok' ? 'bg-ok' : faceTone === 'review' ? 'bg-review' : faceTone === 'warn' ? 'bg-warn' : 'bg-neutral')} /><span className="text-ink">{!face ? 'Checking identity…' : face.result === 'match' ? 'Identity verified' : face.result === 'no_face' ? 'Face not visible' : face.result === 'multiple_faces' ? 'Multiple faces' : face.result === 'uncertain' ? 'Re-checking…' : 'Identity mismatch'}</span></div>
          {extCounts && <p className="text-muted">Events: {Object.entries(extCounts).filter(([k]) => !k.startsWith('SESSION')).reduce((a, [, n]: any) => a + n, 0)}</p>}
          {agentState && agentState.status !== 'not_used' && (
            <p className="flex items-center gap-1.5 text-muted"><Monitor className="h-3 w-3" />Desktop agent: {agentState.status === 'monitoring' ? 'monitoring' : agentState.status === 'not_running' ? 'not running' : agentState.status === 'connecting' ? 'connecting…' : agentState.status}</p>
          )}
        </div>
      </div>
    </div>
  );
}
