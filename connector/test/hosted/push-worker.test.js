import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { database, account } from "./helpers.js";
import { HostedPushWorker } from "../../src/hosted/push-worker.js";
test("durable push worker sends silent wakeup then alert fallback, never redeems", async (t) => {
  const { store } = await database(t);
  const a = await account(store);
  await store.registerPush(a.user.id, a.device.id, {
    token: "a".repeat(64),
    environment: "sandbox",
  });
  const pass = await store.approve(a.user.id, {
    requestId: randomUUID(),
    purpose: "Reply to my friend",
    exitPlan: "Close after replying",
    durationMinutes: 5,
    deviceId: a.device.id,
  });
  const sent = [];
  const worker = new HostedPushWorker({
    store,
    send: async (device, alert) => {
      sent.push({ device, alert });
      return { accepted: true, status: 200 };
    },
  });
  await worker.init();
  await worker.tick();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].alert, false);
  assert.equal(
    (await store.status(a.user.id)).pendingPass.grantId,
    pass.grantId,
  );
  await store.pool.query(
    "UPDATE gk_push_jobs SET available_at=NOW()-INTERVAL '1 second'",
  );
  await worker.tick();
  assert.equal(sent.length, 2);
  assert.equal(sent[1].alert, true);
  await worker.tick();
  assert.equal(sent.length, 2);
});
test("missing provider retains outbox; invalid device token is cleared, provider errors retry", async (t) => {
  const { store } = await database(t);
  const a = await account(store);
  await store.registerPush(a.user.id, a.device.id, {
    token: "a".repeat(64),
    environment: "sandbox",
  });
  await store.endAccess(a.user.id, a.device.id);
  const off = new HostedPushWorker({ store, send: null });
  await off.init();
  await off.tick();
  assert.equal(
    (await store.pool.query("SELECT completed_at FROM gk_push_jobs")).rows[0]
      .completed_at,
    null,
  );
  const retry = new HostedPushWorker({
    store,
    send: async () => ({ accepted: false, status: 403 }),
  });
  await retry.tick();
  assert.equal(
    (await store.pool.query("SELECT apns_token FROM gk_devices")).rows[0]
      .apns_token,
    "a".repeat(64),
  );
  await store.pool.query(
    "UPDATE gk_push_jobs SET available_at=NOW()-INTERVAL '1 second'",
  );
  const invalid = new HostedPushWorker({
    store,
    send: async () => ({ accepted: false, status: 410 }),
  });
  await invalid.tick();
  assert.equal(
    (await store.pool.query("SELECT apns_token FROM gk_devices")).rows[0]
      .apns_token,
    null,
  );
});
test("APNs payload configuration errors preserve device registrations for retry", async (t) => {
  const { store } = await database(t);
  const a = await account(store);
  await store.registerPush(a.user.id, a.device.id, {
    token: "a".repeat(64),
    environment: "sandbox",
  });
  await store.endAccess(a.user.id, a.device.id);
  const worker = new HostedPushWorker({
    store,
    send: async () => ({ accepted: false, status: 400, reason: "BadTopic" }),
  });
  await worker.init();
  await worker.tick();
  assert.equal(
    (await store.pool.query("SELECT apns_token FROM gk_devices")).rows[0]
      .apns_token,
    "a".repeat(64),
  );
  assert.equal(
    (await store.pool.query("SELECT completed_at FROM gk_push_jobs")).rows[0]
      .completed_at,
    null,
  );
  await store.pool.query(
    "UPDATE gk_push_jobs SET available_at=NOW()-INTERVAL '1 second'",
  );
  worker.send = async () => ({
    accepted: false,
    status: 400,
    reason: "BadDeviceToken",
  });
  await worker.tick();
  assert.equal(
    (await store.pool.query("SELECT apns_token FROM gk_devices")).rows[0]
      .apns_token,
    null,
  );
});
