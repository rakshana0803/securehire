// SecureHire Assessment Monitor — background service worker (Manifest V3).
// Monitors ONLY during an explicitly started, consented session on an allowlisted SecureHire page.
// Records event types + timestamps; never reads page content, URLs of other tabs, or clipboard contents.
// No remotely hosted code: everything the extension runs ships in this folder.

const VERSION = chrome.runtime.getManifest().version;
const ALLOWED_ORIGINS = (chrome.runtime.getManifest().externally_connectable?.matches || []).map((m) => m.replace(/\/\*$/, ''));
const EVENT_TYPES = new Set(['SESSION_START', 'SESSION_END', 'TAB_HIDDEN', 'TAB_VISIBLE', 'WINDOW_BLUR', 'WINDOW_FOCUS', 'FULLSCREEN_ENTER', 'FULLSCREEN_EXIT',
  'COPY_ATTEMPT', 'CUT_ATTEMPT', 'PASTE_ATTEMPT', 'CONTEXT_MENU', 'NEW_TAB_OPENED', 'TAB_SWITCH', 'SESSION_INTERRUPTED', 'DEVTOOLS_SHORTCUT', 'PRINT_ATTEMPT']);
const MAX_QUEUE = 500;
const RETRY_ALARM = 'securehire-retry';

// ---------------------------------------------------------------- state (persisted: the worker can be suspended)
async function getState() {
  const { state } = await chrome.storage.local.get('state');
  return state || { active: false, counts: {}, backend: 'idle' };
}
async function setState(patch) {
  const s = { ...(await getState()), ...patch };
  await chrome.storage.local.set({ state: s });
  await chrome.action.setBadgeText({ text: s.active ? 'ON' : '' });
  await chrome.action.setBadgeBackgroundColor({ color: '#4F46E5' });
  return s;
}
async function getQueue() { return (await chrome.storage.local.get('queue')).queue || []; }
async function setQueue(q) { await chrome.storage.local.set({ queue: q.slice(-MAX_QUEUE) }); }

const isAllowedOrigin = (origin) => !!origin && ALLOWED_ORIGINS.includes(origin);
const publicState = (s, q = []) => ({ ok: true, version: VERSION, active: !!s.active, sessionId: s.sessionId || null, counts: s.counts || {}, backend: s.backend, queued: q.length, startedAt: s.startedAt || null, localTest: !!s.localTest, agent: s.agent || { status: 'not_used' } });

// ---------------------------------------------------------------- desktop security agent bridge
// The optional Windows agent listens on 127.0.0.1 only. The extension relays the session-scoped agent token
// from the SecureHire page; the agent verifies it with SecureHire itself and returns a control token that
// lives only in chrome.storage.session (memory, never written to disk). No other data is exchanged.
const AGENT_BASE = 'http://127.0.0.1:47615';
const AGENT_ALARM = 'securehire-agent';
const AGENT_FOCUS_EVENTS = new Set(['TAB_HIDDEN', 'TAB_VISIBLE', 'WINDOW_BLUR', 'WINDOW_FOCUS', 'TAB_SWITCH', 'FULLSCREEN_EXIT', 'FULLSCREEN_ENTER']);

async function agentSecrets() { return (await chrome.storage.session.get('agent')).agent || {}; }
async function setAgentSecrets(v) { if (v) await chrome.storage.session.set({ agent: v }); else await chrome.storage.session.remove('agent'); }
async function setAgent(patch) { const s = await getState(); return setState({ agent: { ...(s.agent || {}), ...patch, checkedAt: new Date().toISOString() } }); }

async function agentFetch(path, { method = 'GET', body, auth = true, timeoutMs = 4000 } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const headers = { 'Content-Type': 'application/json' };
  if (auth) { const { controlToken } = await agentSecrets(); if (!controlToken) throw Object.assign(new Error('no control token'), { status: 401 }); headers.Authorization = `Bearer ${controlToken}`; }
  try {
    const res = await fetch(AGENT_BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: ctrl.signal });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(data.error || `agent error ${res.status}`), { status: res.status });
    return data;
  } catch (e) {
    if (e.status) throw e;
    throw Object.assign(new Error('Desktop agent is not running on this computer.'), { status: 0 });
  } finally { clearTimeout(timer); }
}

async function agentHealth() {
  try { const h = await agentFetch('/health', { auth: false, timeoutMs: 1500 }); return { reachable: true, version: h.version, active: h.active }; }
  catch { return { reachable: false }; }
}

const AGENT_MESSAGES = { 0: 'Desktop agent is not running on this computer.', 400: 'The desktop agent does not allow this SecureHire address (check its allowlist).', 401: 'The desktop agent could not verify this session with SecureHire.', 409: 'The desktop agent is busy with another assessment session.', 502: 'The desktop agent cannot reach SecureHire right now.' };

async function startAgent({ sessionId, agentToken, apiBaseUrl }) {
  await setAgentSecrets({ sessionId, agentToken, apiBaseUrl });
  await setAgent({ status: 'connecting', message: 'Connecting to the desktop agent…', alerts: [], lastLocalId: 0 });
  try {
    const r = await agentFetch('/session/start', { method: 'POST', auth: false, body: { sessionId, agentToken, apiBaseUrl }, timeoutMs: 15000 });
    await setAgentSecrets({ sessionId, agentToken, apiBaseUrl, controlToken: r.controlToken });
    await applyAgentStatus({ active: true, session: r.status });
    chrome.alarms.create(AGENT_ALARM, { periodInMinutes: 0.5 });
  } catch (e) {
    await setAgent({ status: e.status === 0 ? 'not_running' : 'error', message: AGENT_MESSAGES[e.status] || e.message });
    chrome.alarms.create(AGENT_ALARM, { periodInMinutes: 0.5 }); // keep trying: the candidate may start the agent now
  }
}

async function applyAgentStatus(st) {
  const sess = st.session || {};
  const status = st.active ? 'monitoring' : sess.state === 'ended' ? 'ended' : 'idle';
  await setAgent({ status, message: status === 'monitoring' ? (sess.connection === 'offline' ? 'Monitoring — offline, events queued' : 'Desktop monitoring active') : status === 'ended' ? 'Desktop monitoring ended' : 'Agent idle',
    monitors: sess.monitors || {}, connection: sess.connection || null, reviewItems: sess.reviewItems || 0, pending: sess.delivery?.pending || 0 });
}

let agentRefreshAt = 0;
async function refreshAgent(force = false) {
  const s = await getState();
  const secrets = await agentSecrets();
  if (!s.active || s.localTest || !secrets.agentToken) return;
  if (!force && Date.now() - agentRefreshAt < 3000) return;
  agentRefreshAt = Date.now();
  try {
    const st = await agentFetch('/session/status');
    await applyAgentStatus(st);
    const prev = s.agent?.lastLocalId || 0;
    const { events = [] } = await agentFetch(`/events?since=${prev}`);
    if (events.length) {
      const review = events.filter((e) => e.priority === 'review').map((e) => ({ at: e.timestamp, text: e.explanation.slice(0, 220) }));
      await setAgent({ lastLocalId: events[events.length - 1].localId, alerts: [...(s.agent?.alerts || []), ...review].slice(-5) });
    }
  } catch (e) {
    if (e.status === 401) return startAgent(secrets); // agent or service worker restarted: re-pair with the same session token
    await setAgent({ status: e.status === 0 ? 'not_running' : 'error', message: AGENT_MESSAGES[e.status] || e.message });
  }
}

async function stopAgent(reason) {
  chrome.alarms.clear(AGENT_ALARM);
  const { controlToken } = await agentSecrets();
  if (controlToken) { try { await agentFetch('/session/end', { method: 'POST', body: { reason } }); } catch { /* agent already gone */ } }
  await setAgentSecrets(null);
  const s = await getState();
  if (s.agent && s.agent.status !== 'not_used') await setAgent({ status: 'ended', message: 'Desktop monitoring ended' });
}

async function forwardToAgent(eventType) {
  if (!AGENT_FOCUS_EVENTS.has(eventType)) return;
  const { controlToken } = await agentSecrets();
  if (!controlToken) return;
  agentFetch('/extension/events', { method: 'POST', body: { events: [{ eventType, timestamp: new Date().toISOString() }] }, timeoutMs: 2000 }).catch(() => {});
}

// ---------------------------------------------------------------- recording & delivery
async function record(eventType, details = {}) {
  const s = await getState();
  if (!s.active || !EVENT_TYPES.has(eventType)) return;
  const ev = { sessionId: s.sessionId, eventType, timestamp: new Date().toISOString(), details, idempotencyKey: crypto.randomUUID() };
  s.counts = { ...(s.counts || {}), [eventType]: ((s.counts || {})[eventType] || 0) + 1 };
  await setState({ counts: s.counts });
  if (s.localTest) return; // popup test mode: count locally, send nothing
  forwardToAgent(eventType);
  const q = await getQueue();
  q.push(ev);
  await setQueue(q);
  flush();
}

let flushing = false;
async function flush() {
  if (flushing) return;
  flushing = true;
  try {
    const s = await getState();
    let q = await getQueue();
    // Events from an ended session can still be delivered; use the token stored with them.
    const target = s.apiBaseUrl ? s : (await chrome.storage.local.get('lastSession')).lastSession;
    if (!q.length || !target?.apiBaseUrl || !target?.token) return;
    while (q.length) {
      const batch = q.slice(0, 25);
      let res;
      try {
        res = await fetch(`${target.apiBaseUrl}/api/events`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${target.token}` },
          body: JSON.stringify({ sessionId: batch[0].sessionId, events: batch }),
        });
      } catch {
        await setState({ backend: 'offline — retrying' });
        chrome.alarms.create(RETRY_ALARM, { delayInMinutes: 0.5 });
        return;
      }
      if (res.status === 401 || res.status === 410) { await setState({ backend: res.status === 401 ? 'unauthorized' : 'session expired' }); await setQueue([]); return; }
      if (res.status === 409) { q = q.slice(batch.length); await setQueue(q); continue; } // session closed server-side
      if (!res.ok) { await setState({ backend: `error ${res.status} — retrying` }); chrome.alarms.create(RETRY_ALARM, { delayInMinutes: 0.5 }); return; }
      q = (await getQueue()).filter((e) => !batch.some((b) => b.idempotencyKey === e.idempotencyKey));
      await setQueue(q);
      await setState({ backend: 'connected', lastSyncAt: new Date().toISOString() });
    }
  } finally { flushing = false; }
}
chrome.alarms.onAlarm.addListener((a) => { if (a.name === RETRY_ALARM) flush(); if (a.name === AGENT_ALARM) refreshAgent(true); });

async function notifyTab(tabId, msg) { if (tabId == null) return; try { await chrome.tabs.sendMessage(tabId, msg); } catch { /* tab may be gone */ } }

// ---------------------------------------------------------------- messages from the SecureHire web app
chrome.runtime.onMessageExternal.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (!isAllowedOrigin(sender.origin)) return sendResponse({ ok: false, error: 'origin not allowed' });
    const s = await getState();
    switch (msg?.type) {
      case 'PING': return sendResponse(publicState(s, await getQueue()));
      case 'GET_STATUS': await refreshAgent(); return sendResponse(publicState(await getState(), await getQueue()));
      case 'AGENT_HEALTH': return sendResponse({ ok: true, ...(await agentHealth()) });
      case 'START_SESSION': {
        const { sessionId, sessionToken, apiBaseUrl, candidateId, consentGiven, agentToken } = msg;
        if (consentGiven !== true) return sendResponse({ ok: false, error: 'consent required' });
        if (!/^[A-Za-z0-9-]{6,64}$/.test(String(sessionId || '')) || typeof sessionToken !== 'string' || sessionToken.length < 20) return sendResponse({ ok: false, error: 'invalid session' });
        if (!isAllowedOrigin(apiBaseUrl)) return sendResponse({ ok: false, error: 'apiBaseUrl not allowlisted' });
        if (s.active && s.sessionId !== sessionId) await endSession('replaced');
        await chrome.storage.local.set({ lastSession: { apiBaseUrl, token: sessionToken, sessionId } });
        const useAgent = typeof agentToken === 'string' && /^[A-Za-z0-9_-]{20,200}$/.test(agentToken);
        await setState({ active: true, sessionId, token: sessionToken, apiBaseUrl, candidateId, tabId: sender.tab?.id ?? null, windowId: sender.tab?.windowId ?? null, startedAt: new Date().toISOString(), counts: {}, backend: 'connecting', localTest: false, agent: { status: useAgent ? 'connecting' : 'not_used' } });
        await notifyTab(sender.tab?.id, { type: 'MONITOR_ON' });
        await record('SESSION_START', { extensionVersion: VERSION });
        if (useAgent) startAgent({ sessionId, agentToken, apiBaseUrl }); // async: the page polls GET_STATUS for the result
        return sendResponse({ ok: true, version: VERSION });
      }
      case 'END_SESSION': await endSession('ended by page'); return sendResponse({ ok: true });
      default: return sendResponse({ ok: false, error: 'unknown message' });
    }
  })();
  return true; // async response
});

async function endSession(reason) {
  const s = await getState();
  if (!s.active) return;
  await record('SESSION_END', { reason });
  await stopAgent('assessment_ended');
  await notifyTab(s.tabId, { type: 'MONITOR_OFF' });
  await setState({ active: false, tabId: null, windowId: null, endedAt: new Date().toISOString(), token: null, apiBaseUrl: null });
  flush();
}

// ---------------------------------------------------------------- messages from content script / popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const s = await getState();
    if (msg?.type === 'CONTENT_EVENT') {
      if (s.active && sender.tab?.id === s.tabId && EVENT_TYPES.has(msg.eventType)) await record(msg.eventType, msg.details || {});
      return sendResponse({ ok: true });
    }
    if (msg?.type === 'IS_MONITORED_TAB') return sendResponse({ monitored: !!(s.active && sender.tab?.id === s.tabId) });
    if (msg?.type === 'POPUP_STATUS') { await refreshAgent(); const fresh = await getState(); return sendResponse({ ...publicState(fresh, await getQueue()), allowlist: ALLOWED_ORIGINS, lastSyncAt: fresh.lastSyncAt || null }); }
    if (msg?.type === 'POPUP_LOCAL_TEST_START') {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !ALLOWED_ORIGINS.some((o) => (tab.url || '').startsWith(o))) return sendResponse({ ok: false, error: 'Open an allowlisted SecureHire page first.' });
      await setState({ active: true, localTest: true, sessionId: `LOCAL-${Date.now().toString(36).toUpperCase()}`, tabId: tab.id, windowId: tab.windowId, startedAt: new Date().toISOString(), counts: {}, backend: 'local test (not sent)' });
      await notifyTab(tab.id, { type: 'MONITOR_ON' });
      return sendResponse({ ok: true });
    }
    if (msg?.type === 'POPUP_STOP') { if (s.localTest) { await notifyTab(s.tabId, { type: 'MONITOR_OFF' }); await setState({ active: false, localTest: false, tabId: null }); } else await endSession('stopped from popup'); return sendResponse({ ok: true }); }
    if (msg?.type === 'POPUP_RETRY') { flush(); return sendResponse({ ok: true }); }
    sendResponse({ ok: false });
  })();
  return true;
});

// ---------------------------------------------------------------- browser-level signals (no URLs collected)
chrome.tabs.onCreated.addListener(async (tab) => {
  const s = await getState();
  if (s.active) record('NEW_TAB_OPENED', { windowSame: tab.windowId === s.windowId });
});
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const s = await getState();
  if (s.active && tabId !== s.tabId) record('TAB_SWITCH', {});
});
chrome.tabs.onRemoved.addListener(async (tabId) => {
  const s = await getState();
  if (s.active && tabId === s.tabId) { await record('SESSION_INTERRUPTED', { reason: 'assessment tab closed' }); await endSession('tab closed'); }
});
chrome.runtime.onStartup.addListener(async () => {
  // A browser restart ends any session that was in progress.
  const s = await getState();
  if (s.active) { await record('SESSION_INTERRUPTED', { reason: 'browser restarted' }); await endSession('browser restart'); }
  flush();
});
chrome.runtime.onInstalled.addListener(async () => { await setState({ active: false, counts: {}, backend: 'idle' }); });
