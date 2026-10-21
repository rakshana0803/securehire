// Extension ↔ desktop agent bridge tests. Loads the real background.js with an in-memory Chrome API mock
// and mocked HTTP endpoints for the local agent (127.0.0.1:47615) and the SecureHire API.
// Run: node --test extension/tests/
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(fs.readFileSync(path.join(dir, '..', 'manifest.json'), 'utf8'));
const ORIGIN = 'http://localhost:5173';
const AGENT = 'http://127.0.0.1:47615';

// ------------------------------------------------------------------ chrome mock
const listeners = { external: null, internal: null, alarm: [], startup: [], installed: [], tabCreated: [], tabActivated: [], tabRemoved: [] };
const store = { local: {}, session: {} };
const area = (name) => ({
  get: async (k) => (typeof k === 'string' ? { [k]: store[name][k] } : { ...store[name] }),
  set: async (o) => { Object.assign(store[name], structuredClone(o)); },
  remove: async (k) => { delete store[name][k]; },
});
const alarms = new Map();
globalThis.chrome = {
  runtime: {
    getManifest: () => manifest,
    onMessageExternal: { addListener: (f) => { listeners.external = f; } },
    onMessage: { addListener: (f) => { listeners.internal = f; } },
    onStartup: { addListener: (f) => listeners.startup.push(f) },
    onInstalled: { addListener: (f) => listeners.installed.push(f) },
  },
  storage: { local: area('local'), session: area('session') },
  action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
  alarms: { create: (n, o) => alarms.set(n, o), clear: async (n) => alarms.delete(n), onAlarm: { addListener: (f) => listeners.alarm.push(f) } },
  tabs: {
    sendMessage: async () => {}, query: async () => [],
    onCreated: { addListener: (f) => listeners.tabCreated.push(f) },
    onActivated: { addListener: (f) => listeners.tabActivated.push(f) },
    onRemoved: { addListener: (f) => listeners.tabRemoved.push(f) },
  },
};

// ------------------------------------------------------------------ HTTP mock
const calls = [];
const agent = { running: true, control: 'CTRL-1', controlCount: 0, startStatus: 200, statusCode: 200, events: [] };
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
globalThis.fetch = async (url, opts = {}) => {
  const u = new URL(url);
  const body = opts.body ? JSON.parse(opts.body) : null;
  calls.push({ url: String(url), method: opts.method || 'GET', headers: opts.headers || {}, body });
  if (u.origin === AGENT) {
    if (!agent.running) throw new TypeError('fetch failed');
    const authed = (opts.headers || {}).Authorization === `Bearer ${agent.control}`;
    if (u.pathname === '/health') return json(200, { ok: true, version: '1.0.0', active: false });
    if (u.pathname === '/session/start') {
      if (agent.startStatus !== 200) return json(agent.startStatus, { error: 'nope' });
      agent.control = `CTRL-${++agent.controlCount}`;
      return json(200, { ok: true, controlToken: agent.control, status: { state: 'active', connection: 'online', monitors: { usb: 'active', process: 'active', window: 'active' }, reviewItems: 0, delivery: { pending: 0 } } });
    }
    if (!authed) return json(401, { error: 'Missing or invalid control token.' });
    if (u.pathname === '/session/status') return json(agent.statusCode, { active: true, session: { state: 'active', connection: 'online', monitors: { usb: 'active', process: 'active', window: 'active' }, reviewItems: agent.events.filter((e) => e.priority === 'review').length, delivery: { pending: 0 } } });
    if (u.pathname === '/events') return json(200, { events: agent.events.filter((e) => e.localId > Number(u.searchParams.get('since') || 0)) });
    if (u.pathname === '/session/end') return json(200, { ok: true, status: { active: false } });
    if (u.pathname === '/extension/events') return json(200, { ok: true, accepted: body.events.length });
    return json(404, { error: 'Not found' });
  }
  if (u.pathname === '/api/events') return json(200, { accepted: body.events.length, duplicates: 0, errors: [] });
  return json(404, {});
};

await import('../background.js');
const ext = (msg) => new Promise((resolve) => listeners.external(msg, { origin: ORIGIN, tab: { id: 7, windowId: 1 } }, resolve));
const internal = (msg, tabId = 7) => new Promise((resolve) => listeners.internal(msg, { tab: { id: tabId } }, resolve));
const tick = (ms = 30) => new Promise((r) => setTimeout(r, ms));
const until = async (pred, ms = 1500) => { const end = Date.now() + ms; while (Date.now() < end) { if (await pred()) return true; await tick(10); } return pred(); };
const agentCalls = (p) => calls.filter((c) => c.url.startsWith(AGENT + p));
const START = { type: 'START_SESSION', consentGiven: true, sessionId: 'AS-ABC123', sessionToken: 's'.repeat(43), apiBaseUrl: ORIGIN, candidateId: 1, agentToken: 'a'.repeat(43) };

beforeEach(async () => {
  await ext({ type: 'END_SESSION' });
  calls.length = 0; agent.running = true; agent.startStatus = 200; agent.statusCode = 200; agent.events = [];
  store.session = {};
});

test('START_SESSION relays the agent token to the local agent and keeps the control token out of persistent storage', async () => {
  const r = await ext(START);
  assert.equal(r.ok, true);
  await until(async () => (await ext({ type: 'GET_STATUS' })).agent.status === 'monitoring');
  const start = agentCalls('/session/start')[0];
  assert.deepEqual(start.body, { sessionId: 'AS-ABC123', agentToken: 'a'.repeat(43), apiBaseUrl: ORIGIN });
  assert.equal(store.session.agent.controlToken, agent.control, 'control token in chrome.storage.session (memory)');
  assert.ok(!JSON.stringify(store.local).includes(agent.control) && !JSON.stringify(store.local).includes('a'.repeat(43)), 'never in chrome.storage.local');
  const st = await ext({ type: 'GET_STATUS' });
  assert.deepEqual(st.agent.monitors, { usb: 'active', process: 'active', window: 'active' });
  assert.ok(!JSON.stringify(st).includes(agent.control), 'page never sees the control token');
  assert.ok(alarms.has('securehire-agent'), 'periodic agent status refresh scheduled');
});

test('browser focus events are forwarded to the agent with the control token; copy/paste are not', async () => {
  await ext(START);
  await until(() => store.session.agent?.controlToken);
  await internal({ type: 'CONTENT_EVENT', eventType: 'WINDOW_BLUR' });
  await internal({ type: 'CONTENT_EVENT', eventType: 'PASTE_ATTEMPT' });
  await until(() => agentCalls('/extension/events').length >= 1);
  await tick();
  const fwd = agentCalls('/extension/events');
  assert.equal(fwd.length, 1);
  assert.deepEqual(fwd[0].body.events.map((e) => e.eventType), ['WINDOW_BLUR']);
  assert.equal(fwd[0].headers.Authorization, `Bearer ${agent.control}`);
});

test('review alerts from the agent appear in status; END_SESSION ends agent monitoring', async () => {
  await ext(START);
  await until(() => store.session.agent?.controlToken);
  agent.events = [{ localId: 1, priority: 'info', explanation: 'App started', timestamp: new Date().toISOString() },
    { localId: 2, priority: 'review', explanation: 'Potential overlay activity: … Manual review required.', timestamp: new Date().toISOString() }];
  await tick(3100); // status refresh is throttled to every 3 s
  const st = await ext({ type: 'GET_STATUS' });
  assert.equal(st.agent.alerts.length, 1);
  assert.match(st.agent.alerts[0].text, /Potential overlay activity/);
  await ext({ type: 'END_SESSION' });
  const end = agentCalls('/session/end')[0];
  assert.ok(end && end.headers.Authorization === `Bearer ${agent.control}`);
  assert.deepEqual(end.body, { reason: 'assessment_ended' });
  assert.equal(store.session.agent, undefined, 'control token discarded');
});

test('agent not running is reported clearly and monitoring in the browser continues', async () => {
  agent.running = false;
  const r = await ext(START);
  assert.equal(r.ok, true, 'assessment is not blocked by the extension');
  await until(async () => (await ext({ type: 'GET_STATUS' })).agent.status === 'not_running');
  const st = await ext({ type: 'GET_STATUS' });
  assert.equal(st.active, true);
  assert.match(st.agent.message, /not running/);
  assert.deepEqual(await ext({ type: 'AGENT_HEALTH' }), { ok: true, reachable: false });
});

test('a rejected token is surfaced as a permission error', async () => {
  agent.startStatus = 401;
  await ext(START);
  await until(async () => (await ext({ type: 'GET_STATUS' })).agent.status === 'error');
  assert.match((await ext({ type: 'GET_STATUS' })).agent.message, /could not verify/);
});

test('after an agent restart (401 on status) the extension re-pairs with the same session token', async () => {
  await ext(START);
  await until(() => store.session.agent?.controlToken);
  const before = agentCalls('/session/start').length;
  agent.control = 'CTRL-AGENT-RESTARTED-UNKNOWN';   // agent forgot our control token
  for (const f of listeners.alarm) f({ name: 'securehire-agent' });
  await until(() => agentCalls('/session/start').length > before);
  assert.equal(agentCalls('/session/start').at(-1).body.agentToken, 'a'.repeat(43));
});

test('sessions without an agent token never contact the agent; foreign origins are refused', async () => {
  const { agentToken, ...noAgent } = START;
  await ext(noAgent);
  await tick(50);
  assert.equal(agentCalls('/session/start').length, 0);
  assert.equal((await ext({ type: 'GET_STATUS' })).agent.status, 'not_used');
  const refused = await new Promise((resolve) => listeners.external({ type: 'AGENT_HEALTH' }, { origin: 'https://evil.example' }, resolve));
  assert.equal(refused.ok, false);
});

test('manifest grants only the loopback agent port in addition to SecureHire origins', () => {
  assert.ok(manifest.host_permissions.includes('http://127.0.0.1:47615/*'));
  assert.ok(!manifest.host_permissions.some((h) => h.includes('<all_urls>') || h.startsWith('*://') || h.startsWith('https://*')));
  assert.deepEqual(manifest.permissions.sort(), ['alarms', 'storage']);
  assert.ok(!manifest.content_scripts[0].matches.some((m) => m.includes('47615')), 'no content script on the agent port');
});
