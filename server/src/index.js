import http from 'node:http';
import { config } from './config.js';
import { createApp } from './app.js';
import { attachRealtime } from './realtime.js';
import { warmUp, semanticStatus } from './services/semantic.js';
import { runRetention } from './services/retention.js';
import { q } from './db.js';
import { seedDemo } from './seed.js';
import { sweepStaleAgents } from './services/desktopSecurity.js';

const app = createApp();
if (!q.get('SELECT 1 FROM users LIMIT 1')) {
  console.log('[seed] empty database — loading synthetic demo data');
  await seedDemo();
}
const server = http.createServer(app);
attachRealtime(server);
server.listen(config.port, () => {
  console.log(`SecureHire API on http://localhost:${config.port}  (demo mode: ${config.demoMode})`);
  warmUp().then(() => console.log(`[ai] semantic model: ${semanticStatus().loaded ? semanticStatus().model : 'unavailable — ' + semanticStatus().error}`));
});
runRetention();
setInterval(runRetention, 3600_000).unref();
// Desktop agent: record a transparent AGENT_DISCONNECTED event when heartbeats stop during an active assessment.
setInterval(() => { try { sweepStaleAgents(); } catch (e) { console.error('[agent-sweep]', e); } }, 15_000).unref();
