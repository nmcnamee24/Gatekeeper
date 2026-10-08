import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Store } from '../src/store.js';
import { DatabaseSync } from 'node:sqlite';
import { createApp } from '../src/server.js';
const request = () => ({ requestId: randomUUID(), purpose: 'Reply to my friend about tomorrow', exitPlan: 'Close Instagram once the reply is sent' });
function fixture(t) {
  let now = 1000000000000;
  const store = new Store(':memory:', () => now);
  t.after(() => store.close());
  return { store, advance: n => { now += n * 1000; } };
}
test('approval is pending, one-use, and cannot be replayed', t => {
  const { store } = fixture(t);
  const pass = store.approve(request());
  assert.equal(pass.status, 'awaiting_phone');
  assert.equal(store.status().lastDeviceReport, null);
  assert.equal(store.redeem(pass.grantId).windowSeconds, 900);
  assert.throws(() => store.redeem(pass.grantId), /used/);
});
test('identical request retry is idempotent and altered retry is rejected', t => {
  const { store } = fixture(t); const req = request();
  assert.deepEqual(store.approve(req), store.approve(req));
  assert.throws(() => store.approve({ ...req, purpose: 'Browse an endless feed' }), /different request/);
  assert.throws(() => store.approve(request()), /already exists/);
});
test('pass expires at five minutes, and replaying approval cannot refresh it', t => {
  const { store, advance } = fixture(t); const req = request(); const pass = store.approve(req);
  advance(300);
  assert.equal(store.approve(req).status, 'expired');
  assert.throws(() => store.redeem(pass.grantId), /expired/);
});
test('cooldown survives early ending and ends at the precise boundary', t => {
  const { store, advance } = fixture(t); const pass = store.approve(request());
  store.redeem(pass.grantId); store.endAccess(); advance(2699);
  assert.throws(() => store.approve(request()), /Cooldown/);
  advance(1); assert.equal(store.approve(request()).status, 'awaiting_phone');
});
test('requested duration survives approval, redemption, retries, and cooldown', t => {
  const { store, advance } = fixture(t);
  const req = { ...request(), durationMinutes: 5 };
  const pass = store.approve(req);
  assert.equal(pass.windowSeconds, 300);
  assert.deepEqual(store.approve(req), pass);
  assert.throws(() => store.approve({ ...req, durationMinutes: 15 }), /different request/);
  advance(20);
  const lease = store.redeem(pass.grantId);
  assert.equal(lease.windowSeconds, 300);
  assert.equal(Date.parse(lease.endsAt) - 1000000020000, 300000);
  store.endAccess(); advance(2099);
  assert.throws(() => store.approve(request()), /Cooldown/);
  advance(1); assert.equal(store.approve(request()).status, 'awaiting_phone');
});
test('duration is restricted to whole minutes from one through fifteen', t => {
  const { store } = fixture(t);
  for (const durationMinutes of [0, -1, 16, 1.5, '5', null, Infinity, NaN]) {
    assert.throws(() => store.approve({ ...request(), durationMinutes }), /duration/i);
  }
  const pass = store.approve({ ...request(), durationMinutes: 1 });
  assert.equal(store.redeem(pass.grantId).windowSeconds, 60);
});
test('duration persists across a server restart', t => {
  const dir = mkdtempSync(join(tmpdir(), 'gatekeeper-duration-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'db.sqlite');
  const req = { ...request(), durationMinutes: 7 };
  const first = new Store(path); const pass = first.approve(req); first.close();
  const second = new Store(path); t.after(() => second.close());
  assert.equal(second.approve(req).windowSeconds, 420);
  assert.equal(second.redeem(pass.grantId).windowSeconds, 420);
});
test('legacy database migration caps pending passes', t => {
  const dir = mkdtempSync(join(tmpdir(), 'gatekeeper-migrate-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'db.sqlite'); const now = 1000000000000;
  const db = new DatabaseSync(path);
  db.exec(`CREATE TABLE grants (id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
    purpose TEXT NOT NULL, exit_plan TEXT NOT NULL, created INTEGER NOT NULL,
    valid_until INTEGER NOT NULL, redeemed INTEGER, ends INTEGER, revoked INTEGER)`);
  db.prepare('INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?)').run('old', randomUUID(), 'A concrete purpose', 'A concrete exit plan', now, now + 300000, null, null, null);
  db.close();
  const store = new Store(path, () => now); t.after(() => store.close());
  assert.equal(store.status().pendingPass.windowSeconds, 900);
  assert.equal(store.redeem('old').windowSeconds, 900);
});
test('legacy redeemed windows retain their original duration and cooldown on migration', t => {
  const dir = mkdtempSync(join(tmpdir(), 'gatekeeper-migrate-active-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'db.sqlite'); let now = 1000000000000;
  const db = new DatabaseSync(path);
  db.exec(`CREATE TABLE grants (id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
    purpose TEXT NOT NULL, exit_plan TEXT NOT NULL, created INTEGER NOT NULL,
    valid_until INTEGER NOT NULL, redeemed INTEGER, ends INTEGER, revoked INTEGER)`);
  db.prepare('INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?)').run('old', randomUUID(), 'A concrete purpose', 'A concrete exit plan', now, now + 300000, now, now + 960000, null);
  db.close();
  const store = new Store(path, () => now); t.after(() => store.close());
  assert.equal(store.status().latestGrant.windowSeconds, 960);
  assert.equal(Date.parse(store.status().nextEligibleAt), now + 2760000);
  now += 2759000; assert.throws(() => store.approve(request()), /Cooldown/);
  now += 1000; assert.equal(store.approve(request()).windowSeconds, 900);
});
test('revocation prevents redemption and remains an unacknowledged request', t => {
  const { store } = fixture(t); const pass = store.approve(request());
  assert.equal(store.endAccess().status, 'end_requested');
  assert.equal(store.deviceState().lastGrantRevoked, true);
  assert.throws(() => store.redeem(pass.grantId), /revoked/);
  assert.equal(store.status().lastDeviceReport, null);
});
test('device reports never bypass grant eligibility or change server timers', t => {
  const { store } = fixture(t); store.redeem(store.approve(request()).grantId);
  store.report({ state: 'shielded', localExpiry: '1970-01-01T00:00:00Z' });
  assert.throws(() => store.approve(request()), /Cooldown/);
});
test('cooldown persists across process restarts', t => {
  const dir = mkdtempSync(join(tmpdir(), 'gatekeeper-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'db.sqlite');
  const first = new Store(path); first.redeem(first.approve(request()).grantId); first.close();
  const second = new Store(path); t.after(() => second.close());
  assert.throws(() => second.approve(request()), /Cooldown/);
});
test('real MCP client can discover and use the connector; auth roles are isolated', async t => {
  const { store } = fixture(t);
  const museToken = 'm'.repeat(64), deviceToken = 'd'.repeat(64);
  let app;
  const http = createServer((req, res) => app(req, res));
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${http.address().port}`;
  app = createApp({ store, museToken, deviceToken, publicOrigin: origin });
  t.after(() => { http.closeAllConnections(); http.close(); });
  const client = new Client({ name: 'gatekeeper-test', version: '1.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${museToken}` } } }));
  t.after(() => client.close());
  assert.deepEqual((await client.listTools()).tools.map(t => t.name), ['gatekeeper_status', 'gatekeeper_approve', 'gatekeeper_end_access']);
  assert.equal((await client.listPrompts()).prompts[0].name, 'gatekeeper-role');
  const decoded = r => JSON.parse(r.content[0].text);
  assert.equal(decoded(await client.callTool({ name: 'gatekeeper_status', arguments: {} })).lastDeviceReport, null);
  const tools = (await client.listTools()).tools;
  assert.equal(tools.find(t => t.name === 'gatekeeper_approve').inputSchema.properties.durationMinutes.maximum, 15);
  for (const durationMinutes of [0, 16, 1.5]) {
    assert.equal((await client.callTool({ name: 'gatekeeper_approve', arguments: { ...request(), durationMinutes } })).isError, true);
  }
  const pass = decoded(await client.callTool({ name: 'gatekeeper_approve', arguments: { ...request(), durationMinutes: 5 } }));
  assert.equal(pass.status, 'awaiting_phone');
  assert.equal(pass.windowSeconds, 300);
  const invalid = await client.callTool({ name: 'gatekeeper_approve', arguments: { ...request(), purpose: 'x' } });
  assert.equal(invalid.isError, true);
  assert.equal((await fetch(`${origin}/mcp`, { method: 'POST' })).status, 401);
  assert.equal((await fetch(`${origin}/mcp`, { method: 'POST', headers: { Authorization: `Bearer ${deviceToken}` } })).status, 401);
  assert.equal((await fetch(`${origin}/device/state`, { headers: { Authorization: `Bearer ${museToken}` } })).status, 401);
  assert.equal((await fetch(`${origin}/device/state`, { headers: { Authorization: `Bearer ${deviceToken}`, Origin: 'https://evil.example' } })).status, 403);
  const deviceHeaders = { Authorization: `Bearer ${deviceToken}`, 'Content-Type': 'application/json' };
  const state = await (await fetch(`${origin}/device/state`, { headers: deviceHeaders })).json();
  assert.equal(state.pendingGrantId, pass.grantId);
  const redeem = () => fetch(`${origin}/device/redeem`, { method: 'POST', headers: deviceHeaders, body: JSON.stringify({ grantId: pass.grantId }) });
  const attempts = await Promise.all([redeem(), redeem()]);
  assert.deepEqual(attempts.map(r => r.status).sort(), [200, 409]);
  assert.equal((await attempts.find(r => r.status === 200).json()).windowSeconds, 300);
  assert.equal((await fetch(`${origin}/device/report`, { method: 'POST', headers: deviceHeaders, body: JSON.stringify({ state: 'window_open', grantId: pass.grantId }) })).status, 200);
  assert.equal(decoded(await client.callTool({ name: 'gatekeeper_status', arguments: {} })).lastDeviceReport.state, 'window_open');
  const ended = decoded(await client.callTool({ name: 'gatekeeper_end_access', arguments: {} }));
  assert.equal(ended.status, 'end_requested');
  const denied = await client.callTool({ name: 'gatekeeper_approve', arguments: request() });
  assert.equal(denied.isError, true);
});
test('Railway health checks do not grant access to protected endpoints', async t => {
  const { store } = fixture(t);
  const app = createApp({ store, museToken: 'm'.repeat(64), deviceToken: 'd'.repeat(64), publicOrigin: 'https://gatekeeper.example' });
  const http = createServer(app);
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve));
  t.after(() => { http.closeAllConnections(); http.close(); });
  const origin = `http://127.0.0.1:${http.address().port}`;
  // Native HTTP preserves the explicit Host header used by Railway's probes.
  const probe = (url, options) => new Promise((resolve, reject) => {
    const req = httpRequest(url, options, res => { res.resume(); resolve({ status: res.statusCode }); });
    req.on('error', reject); req.end();
  });
  const headers = { Host: 'healthcheck.railway.app' };
  assert.equal((await probe(`${origin}/health`, { headers })).status, 200);
  assert.equal((await probe(`${origin}/device/state`, { headers })).status, 403);
  assert.equal((await probe(`${origin}/mcp`, { method: 'POST', headers })).status, 403);
  assert.equal((await probe(`${origin}/health`, { headers: { ...headers, Origin: 'https://evil.example' } })).status, 403);
  assert.equal((await probe(`${origin}/device/state`, { headers: { Host: 'gatekeeper.example' } })).status, 401);
});
