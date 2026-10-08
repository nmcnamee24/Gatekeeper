import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { database, account } from "./helpers.js";
import { HostedConversation } from "../../src/hosted/conversation.js";
import { createHostedApp } from "../../src/hosted/app.js";
const approve = {
  decision: "approve",
  reply: "Okay.",
  purpose: "Reply to my specific friend",
  exitPlan: "Close the app after sending the reply",
  durationMinutes: 5,
};
async function service(t, configured = true) {
  const { pool, store } = await database(t);
  const a = await account(store, "a"),
    b = await account(store, "b");
  let calls = 0;
  const coach = {
    configured,
    judge: async () => {
      calls++;
      return approve;
    },
  };
  const billing = {
    entitlement: async () => ({ active: true, betaAccess: true }),
    requireAccess: async () => {},
    products: () => ({ productIds: [], betaAccess: true }),
  };
  const conversation = new HostedConversation({ store, coach, billing });
  await conversation.init();
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  server.on(
    "request",
    createHostedApp({
      store,
      conversation,
      identity: {},
      billing,
      publicOrigin: origin,
      coach,
    }),
  );
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const call = (path, token, body, method) =>
    fetch(origin + path, {
      method: method ?? (body ? "POST" : "GET"),
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  return { a, b, pool, store, call, calls: () => calls };
}
test("hosted HTTP roles and user isolation survive actual authenticated requests", async (t) => {
  const { a, b, call } = await service(t);
  assert.equal((await call("/v1/account", a.device.token)).status, 401);
  assert.equal(
    (await call("/device/state", a.session.accountToken)).status,
    401,
  );
  assert.equal((await call("/v1/account", a.session.accountToken)).status, 200);
  assert.equal(
    (
      await call(
        "/v1/devices/" + b.device.id,
        a.session.accountToken,
        null,
        "DELETE",
      )
    ).status,
    404,
  );
  const devices = await (
    await call("/v1/devices", a.session.accountToken)
  ).json();
  assert.equal(devices.devices.length, 1);
  assert.equal(devices.devices[0].id, a.device.id);
  assert.equal(
    (
      await call("/v1/account/consent", a.session.accountToken, {
        version: "2026-10-08",
      })
    ).status,
    200,
  );
  const r = await call("/v1/conversation", a.session.accountToken, {
    requestId: randomUUID(),
    message: "Five minutes to reply to Sam then close the app.",
    durationMinutes: 5,
    deviceId: a.device.id,
  });
  assert.equal(r.status, 200);
  const pass = (await r.json()).approval;
  assert.equal(
    (await call("/device/redeem", b.device.token, { grantId: pass.grantId }))
      .status,
    409,
  );
  const redeemed = await call("/device/redeem", a.device.token, {
    grantId: pass.grantId,
  });
  assert.equal(redeemed.status, 200);
  assert.equal((await redeemed.json()).windowSeconds, 300);
  assert.equal(
    (
      await call("/v1/access/end", a.session.accountToken, {
        deviceId: a.device.id,
      })
    ).status,
    200,
  );
  assert.equal(
    (await call("/v1/account/consent", a.session.accountToken, null, "DELETE"))
      .status,
    200,
  );
  assert.equal(
    (
      await call("/v1/conversation", a.session.accountToken, {
        requestId: randomUUID(),
        message: "Another request",
        durationMinutes: 1,
        deviceId: a.device.id,
      })
    ).status,
    403,
  );
});
test("account deletion removes credentials and all owned data", async (t) => {
  const { a, call, pool } = await service(t);
  await call("/v1/account/consent", a.session.accountToken, {
    version: "2026-10-08",
  });
  await call("/v1/conversation", a.session.accountToken, {
    requestId: randomUUID(),
    message: "Reply to Sam then close the app.",
    durationMinutes: 5,
    deviceId: a.device.id,
  });
  assert.equal(
    (await call("/v1/account", a.session.accountToken, null, "DELETE")).status,
    200,
  );
  assert.equal((await call("/v1/account", a.session.accountToken)).status, 401);
  assert.equal((await call("/device/state", a.device.token)).status, 401);
  assert.equal(
    (await pool.query("SELECT * FROM gk_users WHERE id=$1", [a.user.id]))
      .rowCount,
    0,
  );
  for (const table of ["gk_messages", "gk_exchanges", "gk_ai_usage"])
    assert.equal(
      (await pool.query(`SELECT * FROM ${table} WHERE user_id=$1`, [a.user.id]))
        .rowCount,
      0,
    );
});
test("unconfigured AI is exposed as unavailable readiness and does not create grants", async (t) => {
  const { a, call, store, calls } = await service(t, false);
  assert.equal((await call("/health")).status, 200);
  assert.equal((await call("/ready")).status, 503);
  await store.setConsent(a.user.id, "2026-10-08");
  assert.equal(
    (
      await call("/v1/conversation", a.session.accountToken, {
        requestId: randomUUID(),
        message: "Reply to Sam then close the app.",
        durationMinutes: 5,
        deviceId: a.device.id,
      })
    ).status,
    503,
  );
  assert.equal(calls(), 0);
  assert.equal((await store.status(a.user.id)).pendingPass, null);
  assert.equal((await call("/privacy")).status, 200);
  assert.equal((await call("/support")).status, 200);
  assert.equal(
    (await call("/v1/conversation", null, { message: "request" })).status,
    401,
  );
});
