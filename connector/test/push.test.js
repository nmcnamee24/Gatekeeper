import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Store } from '../src/store.js';
import { PushDelivery, createAPNs } from '../src/push.js';

test('outbox deduplicates concurrent wakeups and sends fallback only while pending', async () => {
  const store = new Store(':memory:');
  const calls = [];
  const push = new PushDelivery(store, async (_, alert) => { calls.push(alert); return { accepted: true }; });
  push.register('a'.repeat(64), 'sandbox');
  const a = store.approve({ requestId: randomUUID(), purpose: 'Reply to a specific message', exitPlan: 'Close after sending the reply' });
  push.enqueue(a.grantId, 'approve'); push.enqueue(a.grantId, 'approve');
  await Promise.all([push.tick(), push.tick()]);
  assert.deepEqual(calls, [false]);
  store.db.prepare('UPDATE push_jobs SET created=?').run(Date.now() - 20000);
  await push.tick(); await push.tick();
  assert.deepEqual(calls, [false, true]);
  store.redeem(a.grantId); await push.tick();
  assert.equal(store.db.prepare('SELECT count(*) AS n FROM push_jobs').get().n, 0);
  store.close();
});
test('revocation cancels pending approval notifications', async () => {
  const store = new Store(':memory:'); let sends = 0;
  const push = new PushDelivery(store, async () => { sends++; return { accepted: true }; });
  push.register('a'.repeat(64), 'sandbox');
  const a = store.approve({ requestId: randomUUID(), purpose: 'Reply to a specific message', exitPlan: 'Close after sending the reply' });
  push.enqueue(a.grantId, 'approve'); store.endAccess(); await push.tick();
  assert.equal(sends, 0); store.close();
});
test('missing provider configuration retains work without claiming delivery', async () => {
  assert.equal(createAPNs({}), null);
  const store = new Store(':memory:'); const push = new PushDelivery(store, null);
  const result = push.enqueue(randomUUID(), 'revoke');
  assert.equal(result.configured, false); assert.equal(result.registered, false);
  await push.tick(); assert.equal(store.db.prepare('SELECT count(*) AS n FROM push_jobs').get().n, 1);
  store.close();
});
test('push configuration requires the deploying app bundle identifier', () => {
  assert.throws(() => createAPNs({ APNS_KEY_ID: 'test', APNS_TEAM_ID: 'test', APNS_PRIVATE_KEY: 'unused' }), /APNS_TOPIC/);
});
