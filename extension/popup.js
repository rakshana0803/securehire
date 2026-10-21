// Popup UI: reads state from the background worker. No network access of its own.
const $ = (id) => document.getElementById(id);
$('version').textContent = 'v' + chrome.runtime.getManifest().version;

function render(s) {
  if (!s) return;
  const st = $('status');
  st.textContent = s.active ? (s.localTest ? 'Local test' : 'Monitoring') : 'Idle';
  st.className = 'pill ' + (s.active ? (s.localTest ? 'test' : 'active') : 'idle');
  $('session').textContent = s.sessionId || '—';
  $('started').textContent = s.startedAt ? new Date(s.startedAt).toLocaleTimeString() : '—';
  $('backend').textContent = s.backend || '—';
  $('queued').textContent = s.queued ?? 0;
  const c = s.counts || {};
  $('c-tab').textContent = (c.TAB_HIDDEN || 0) + (c.TAB_SWITCH || 0) + (c.NEW_TAB_OPENED || 0);
  $('c-focus').textContent = c.WINDOW_BLUR || 0;
  $('c-fs').textContent = c.FULLSCREEN_EXIT || 0;
  $('c-clip').textContent = (c.COPY_ATTEMPT || 0) + (c.PASTE_ATTEMPT || 0) + (c.CUT_ATTEMPT || 0);
  $('allowlist').textContent = (s.allowlist || []).join(', ');
  $('stop').hidden = !s.active;
  renderAgent(s.agent || { status: 'not_used' });
  $('test').hidden = !!s.active;
}
const AGENT_PILL = { not_used: ['Not used', 'idle'], connecting: ['Connecting…', 'warn'], monitoring: ['Monitoring', 'active'], idle: ['Idle', 'idle'],
  ended: ['Ended', 'idle'], not_running: ['Not running', 'warn'], error: ['Problem', 'err'] };
function renderAgent(a) {
  const [label, cls] = AGENT_PILL[a.status] || [a.status, 'idle'];
  const pill = $('agent-status');
  pill.textContent = label; pill.className = 'pill ' + cls;
  $('agent-message').textContent = a.status === 'not_used' ? 'Not requested for this session.' : (a.message || '');
  const mons = $('agent-monitors');
  mons.replaceChildren(...Object.entries(a.monitors || {}).map(([k, v]) => {
    const el = document.createElement('span');
    el.textContent = `${k}: ${v}`;
    el.className = v === 'active' ? 'on' : v === 'error' ? 'err' : '';
    return el;
  }));
  const alerts = $('agent-alerts');
  alerts.replaceChildren(...(a.alerts || []).slice().reverse().map((x) => {
    const li = document.createElement('li');
    li.textContent = `${new Date(x.at).toLocaleTimeString()} · ${x.text}`; // textContent only — never HTML
    return li;
  }));
}
const refresh = () => chrome.runtime.sendMessage({ type: 'POPUP_STATUS' }, render);
$('retry').onclick = () => chrome.runtime.sendMessage({ type: 'POPUP_RETRY' }, refresh);
$('stop').onclick = () => chrome.runtime.sendMessage({ type: 'POPUP_STOP' }, refresh);
$('test').onclick = () => chrome.runtime.sendMessage({ type: 'POPUP_LOCAL_TEST_START' }, (r) => { if (r && !r.ok) alert(r.error); refresh(); });
refresh();
setInterval(refresh, 1000);
