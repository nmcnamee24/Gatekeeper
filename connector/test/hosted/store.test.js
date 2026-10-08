import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import pg from "pg";
const module = await import("../../src/hosted/store.js").catch(() => ({}));
const { HostedStore } = module;
const db = process.env.TEST_DATABASE_URL;
async function fixture(t) {
  assert.equal(
    typeof HostedStore,
    "function",
    "HostedStore must implement the hosted PostgreSQL contract",
  );
  const schema = `test_${randomUUID().replaceAll("-", "")}`;
  const admin = new pg.Pool({ connectionString: db });
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({
    connectionString: db,
    options: `-c search_path=${schema}`,
  });
  let now = Date.UTC(2026, 9, 8);
  const store = new HostedStore({ pool, clock: () => now });
  t.after(async () => {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });
  await Promise.all([store.migrate(), store.migrate()]);
  const user = await store.upsertUser({
    appleSub: "apple-a",
    displayName: "A",
  });
  const other = await store.upsertUser({ appleSub: "apple-b" });
  const device = await store.registerDevice(user.id, {
    installationId: "install",
    name: "Phone",
  });
  const otherDevice = await store.registerDevice(other.id, {
    installationId: "install",
    name: "Other phone",
  });
  const input = {
    requestId: "r1",
    purpose: "Reply to Alex",
    exitPlan: "Close after replying",
    durationMinutes: 3,
    deviceId: device.id,
  };
  return {
    pool,
    store,
    user,
    other,
    device,
    otherDevice,
    input,
    advance: (ms) => {
      now += ms;
    },
  };
}
const opts = { skip: !db };
test(
  "account sessions rotate once and opaque credentials are hashed",
  opts,
  async (t) => {
    const { store, pool, user, device } = await fixture(t);
    const session = await store.createSession(user.id, { deviceId: device.id });
    assert.equal(
      (await store.authenticate(session.accountToken, "account")).userId,
      user.id,
    );
    const row = (await pool.query("SELECT * FROM gk_sessions")).rows[0];
    assert.notEqual(row.token_hash, session.accountToken);
    assert.notEqual(row.refresh_hash, session.refreshToken);
    const results = await Promise.allSettled([
      store.refreshSession(session.refreshToken),
      store.refreshSession(session.refreshToken),
    ]);
    assert.equal(results.filter((x) => x.status === "fulfilled").length, 1);
    await assert.rejects(store.authenticate(session.accountToken));
    const next = results.find((x) => x.status === "fulfilled").value;
    assert.equal(
      (await store.authenticate(next.device.token, "device")).deviceId,
      device.id,
    );
    await assert.rejects(store.authenticate(device.token));
  },
);
test(
  "cross-worker grants serialize per account while other accounts remain independent",
  opts,
  async (t) => {
    const { store, pool, user, other, device, otherDevice, input } =
      await fixture(t);
    const worker = new HostedStore({ pool, clock: store.clock });
    const results = await Promise.allSettled([
      store.approve(user.id, input),
      worker.approve(user.id, { ...input, requestId: "r2" }),
    ]);
    assert.equal(results.filter((x) => x.status === "fulfilled").length, 1);
    await store.approve(other.id, { ...input, deviceId: otherDevice.id });
    const granted = results.find((x) => x.status === "fulfilled").value;
    await assert.rejects(
      store.redeem(user.id, otherDevice.id, granted.grantId),
    );
    const redeem = await Promise.allSettled([
      store.redeem(user.id, device.id, granted.grantId),
      worker.redeem(user.id, device.id, granted.grantId),
    ]);
    assert.equal(redeem.filter((x) => x.status === "fulfilled").length, 1);
  },
);
test(
  "identical retries match duration and device; early end and retention preserve cooldown",
  opts,
  async (t) => {
    const { store, user, device, input, advance } = await fixture(t);
    const pass = await store.approve(user.id, input);
    assert.deepEqual(await store.approve(user.id, input), pass);
    await assert.rejects(
      store.approve(user.id, { ...input, durationMinutes: 4 }),
    );
    const redeemed = await store.redeem(user.id, device.id, pass.grantId);
    assert.equal(redeemed.endsAt, "2026-10-08T00:03:00.000Z");
    await store.endAccess(user.id, device.id);
    assert.equal(
      (await store.status(user.id)).nextEligibleAt,
      "2026-10-08T00:33:00.000Z",
    );
    await store.pruneHistory(0);
    await assert.rejects(store.approve(user.id, { ...input, requestId: "r2" }));
    advance(33 * 60 * 1000);
    await store.approve(user.id, { ...input, requestId: "r2" });
  },
);
test(
  "pending expiration does not start cooldown; boundary and invalid duration fail closed",
  opts,
  async (t) => {
    const { store, user, device, input, advance } = await fixture(t);
    for (const durationMinutes of [0, 16, 1.5, NaN, undefined])
      await assert.rejects(
        store.approve(user.id, { ...input, durationMinutes }),
      );
    const pass = await store.approve(user.id, input);
    advance(5 * 60 * 1000);
    await assert.rejects(store.redeem(user.id, device.id, pass.grantId));
    assert.equal((await store.status(user.id)).nextEligibleAt, null);
    await store.approve(user.id, { ...input, requestId: "r2" });
  },
);
test(
  "device reports and revocation cannot cross accounts and delete cascades",
  opts,
  async (t) => {
    const { store, pool, user, other, device, input } = await fixture(t);
    const pass = await store.approve(user.id, input);
    await assert.rejects(
      store.report(other.id, device.id, { state: "blocked" }),
    );
    await store.report(user.id, device.id, {
      state: "blocked",
      grantId: pass.grantId,
    });
    assert.equal(
      (await store.status(user.id, device.id)).lastDeviceReport.state,
      "blocked",
    );
    await store.setConsent(user.id, "2026-10-08");
    assert.equal((await store.account(user.id)).aiConsentVersion, "2026-10-08");
    await store.revokeDevice(user.id, device.id);
    await assert.rejects(store.authenticate(device.token));
    await assert.rejects(store.redeem(user.id, device.id, pass.grantId));
    await store.deleteAccount(user.id);
    assert.equal(
      (await pool.query("SELECT count(*)::int n FROM gk_grants")).rows[0].n,
      0,
    );
    assert.equal((await store.account(other.id)).user.id, other.id);
  },
);
test(
  "push jobs are transactionally created, leased once, retried and stale completions ignored",
  opts,
  async (t) => {
    const { store, user, device, input, advance } = await fixture(t);
    await store.registerPush(user.id, device.id, {
      token: "ab".repeat(32),
      environment: "sandbox",
    });
    await store.approve(user.id, input);
    const claims = await Promise.all([
      store.claimPushJobs(10),
      store.claimPushJobs(10),
    ]);
    assert.equal(claims.flat().length, 1);
    const first = claims.flat()[0];
    await store.retryPushJob(first);
    advance(120000);
    const [second] = await store.claimPushJobs(10);
    assert.notEqual(second.lease_token, first.lease_token);
    await store.completePushJob(first);
    advance(61000);
    assert.equal((await store.claimPushJobs(10)).length, 1);
  },
);
test(
  "native phone report states remain compatible and cross-account grants cannot be reported",
  opts,
  async (t) => {
    const { store, user, other, device, otherDevice, input } = await fixture(t);
    for (const state of [
      "shielded",
      "window_open",
      "permission_missing",
      "selection_missing",
    ])
      await store.report(user.id, device.id, { state });
    const pass = await store.approve(other.id, {
      ...input,
      deviceId: otherDevice.id,
    });
    await assert.rejects(
      store.report(user.id, device.id, {
        state: "window_open",
        grantId: pass.grantId,
      }),
    );
  },
);
test(
  "approval within a caller transaction rolls back the grant and push together",
  opts,
  async (t) => {
    const { store, pool, user, device, input } = await fixture(t);
    await store.registerPush(user.id, device.id, {
      token: "ab".repeat(32),
      environment: "sandbox",
    });
    await assert.rejects(
      store.withUserLock(user.id, async (client, row) => {
        await store.approveInTransaction(client, row, input);
        throw Error("conversation failed");
      }),
      /conversation failed/,
    );
    assert.equal(
      (await pool.query("SELECT count(*)::int n FROM gk_grants")).rows[0].n,
      0,
    );
    assert.equal(
      (await pool.query("SELECT count(*)::int n FROM gk_push_jobs")).rows[0].n,
      0,
    );
    await store.withUserLock(user.id, (client, row) =>
      store.approveInTransaction(client, row, input),
    );
    assert.ok((await store.deviceState(user.id, device.id)).pendingGrantId);
  },
);
test(
  "latest device grant follows insertion order when timestamps tie",
  opts,
  async (t) => {
    const { store, pool, user, device, input } = await fixture(t);
    const first = await store.approve(user.id, input);
    await pool.query(
      "UPDATE gk_grants SET id='ffffffff-ffff-4fff-afff-ffffffffffff' WHERE id=$1",
      [first.grantId],
    );
    await store.endAccess(user.id, device.id);
    const next = await store.approve(user.id, { ...input, requestId: "next" });
    const state = await store.deviceState(user.id, device.id);
    assert.equal(state.lastGrantId, next.grantId);
    assert.equal(state.lastGrantRevoked, false);
  },
);
test(
  "expired access fails while refresh remains usable; device revocation invalidates its session",
  opts,
  async (t) => {
    const { store, user, device, advance } = await fixture(t);
    const session = await store.createSession(user.id, {
      deviceId: device.id,
      ttlSeconds: 60,
    });
    advance(60000);
    await assert.rejects(store.authenticate(session.accountToken, "account"));
    const next = await store.refreshSession(session.refreshToken);
    assert.equal(
      (await store.authenticate(next.accountToken, "account")).deviceId,
      device.id,
    );
    await store.revokeDevice(user.id, device.id);
    await assert.rejects(store.refreshSession(next.refreshToken));
    await assert.rejects(store.authenticate(next.accountToken));
  },
);

test(
  "privacy pruning removes expired push work and old phone reports while preserving a live pending grant",
  opts,
  async (t) => {
    const { store, pool, user, device, input, advance } = await fixture(t);
    await store.registerPush(user.id, device.id, {
      token: "ab".repeat(32),
      environment: "sandbox",
    });
    await store.approve(user.id, input);
    await store.report(user.id, device.id, { state: "shielded" });
    advance(31 * 86400000);
    const current = await store.approve(user.id, {
      ...input,
      requestId: "new",
    });
    await store.pruneHistory();
    assert.equal(
      (await pool.query("SELECT count(*)::int n FROM gk_push_jobs")).rows[0].n,
      1,
    );
    assert.equal(
      (await pool.query("SELECT count(*)::int n FROM gk_device_reports"))
        .rows[0].n,
      0,
    );
    assert.equal(
      (await store.deviceState(user.id, device.id)).pendingGrantId,
      current.grantId,
    );
  },
);
test(
  "re-registering a revoked installation never revives its old refresh credentials or resets cooldown",
  opts,
  async (t) => {
    const { store, pool, user, device, input } = await fixture(t);
    const session = await store.createSession(user.id, { deviceId: device.id });
    const pass = await store.approve(user.id, input);
    await store.redeem(user.id, device.id, pass.grantId);
    await store.revokeDevice(user.id, device.id);
    const reconnected = await store.registerDevice(user.id, {
      installationId: "install",
      name: "Phone again",
    });
    assert.equal(reconnected.id, device.id);
    await assert.rejects(store.refreshSession(session.refreshToken));
    await assert.rejects(store.authenticate(session.accountToken));
    await assert.rejects(store.authenticate(device.token));
    assert.ok(
      (
        await pool.query("SELECT revoked_at FROM gk_sessions WHERE id=$1", [
          session.sessionId,
        ])
      ).rows[0].revoked_at,
    );
    await assert.rejects(
      store.approve(user.id, { ...input, requestId: "again" }),
    );
  },
);

test(
  "account deletion cascades through conversation, agent and billing schemas without deleting another account",
  opts,
  async (t) => {
    const { HostedConversation } = await import(
      "../../src/hosted/conversation.js"
    );
    const { HostedBilling } = await import("../../src/hosted/billing.js");
    const { HostedOAuth } = await import("../../src/hosted/oauth.js");
    const { store, pool, user, other, device, input } = await fixture(t);
    const billing = new HostedBilling({
      pool,
      betaAccess: true,
      bundleId: "test.gatekeeper",
      environment: "Sandbox",
      productIds: ["test.subscription"],
      verifier: {
        verifyAndDecodeTransaction: async (value) => JSON.parse(value),
      },
    });
    await billing.init();
    const conversation = new HostedConversation({
      store,
      billing,
      coach: {
        configured: true,
        judge: async () => ({ decision: "ask", reply: "What will you do?" }),
      },
    });
    await conversation.init();
    const oauth = new HostedOAuth({
      store,
      billing,
      publicOrigin: "https://test.example",
      encryptionKey: Buffer.alloc(32, 4),
    });
    await oauth.init();
    await store.setConsent(user.id, "2026-10-08");
    await conversation.respond(user.id, {
      requestId: randomUUID(),
      message: "Reply to Alex then close",
      durationMinutes: 3,
      deviceId: device.id,
    });
    const client = await oauth.registerClient({
      client_name: "Agent",
      redirect_uris: ["https://agent.example/callback"],
      token_endpoint_auth_method: "none",
    });
    const connectionId = randomUUID(),
      requestId = randomUUID();
    await pool.query(
      "INSERT INTO gk_oauth_connections(id,user_id,client_id,scopes,issuer,resource,created_at) VALUES($1,$2,$3,$4,$5,$5,$6)",
      [
        connectionId,
        user.id,
        client.client_id,
        ["gatekeeper:status"],
        oauth.resource,
        new Date(store.clock()),
      ],
    );
    await pool.query(
      "INSERT INTO gk_oauth_requests(id,client_id,user_id,connection_id,redirect_uri,scopes,code_challenge,issuer,resource,poll_hash,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10,$11)",
      [
        requestId,
        client.client_id,
        user.id,
        connectionId,
        "https://agent.example/callback",
        ["gatekeeper:status"],
        "challenge",
        oauth.resource,
        "poll",
        new Date(store.clock() + 600000),
        new Date(store.clock()),
      ],
    );
    const agent = await oauth.transaction((c) =>
      oauth.issueTokens(c, { id: connectionId, user_id: user.id }, [
        "gatekeeper:status",
      ]),
    );
    const now = Date.now();
    await billing.recordTransaction(
      user.id,
      JSON.stringify({
        transactionId: "test-tx",
        originalTransactionId: "test-original",
        productId: "test.subscription",
        bundleId: "test.gatekeeper",
        environment: "Sandbox",
        appAccountToken: user.id,
        type: "Auto-Renewable Subscription",
        purchaseDate: now - 1000,
        expiresDate: now + 3600000,
        signedDate: now,
      }),
    );
    await store.createSession(user.id, { deviceId: device.id });
    await store.registerPush(user.id, device.id, {
      token: "ab".repeat(32),
      environment: "sandbox",
    });
    const pass = await store.approve(user.id, input);
    await store.report(user.id, device.id, {
      state: "shielded",
      grantId: pass.grantId,
    });
    const tables = [
      "gk_devices",
      "gk_sessions",
      "gk_grants",
      "gk_device_reports",
      "gk_push_jobs",
      "gk_messages",
      "gk_exchanges",
      "gk_ai_usage",
      "gk_oauth_connections",
      "gk_oauth_requests",
      "gk_oauth_tokens",
      "gk_subscriptions",
      "gk_billing_events",
    ];
    for (const table of tables) {
      assert.ok(
        (
          await pool.query(
            `SELECT count(*)::int n FROM ${table} WHERE user_id=$1`,
            [user.id],
          )
        ).rows[0].n > 0,
        `${table} fixture must be populated`,
      );
    }
    await store.deleteAccount(user.id);
    for (const table of tables) {
      assert.equal(
        (
          await pool.query(
            `SELECT count(*)::int n FROM ${table} WHERE user_id=$1`,
            [user.id],
          )
        ).rows[0].n,
        0,
        table,
      );
    }
    await assert.rejects(oauth.verifyAccessToken(agent.access_token));
    assert.equal(
      (
        await pool.query(
          "SELECT count(*)::int n FROM gk_ai_usage WHERE subject='global'",
        )
      ).rows[0].n,
      1,
    );
    assert.equal((await store.account(other.id)).user.id, other.id);
  },
);

test(
  "end access within a caller transaction rolls back revocation and push together",
  opts,
  async (t) => {
    const { store, pool, user, device, input } = await fixture(t);
    await store.registerPush(user.id, device.id, {
      token: "ab".repeat(32),
      environment: "sandbox",
    });
    const pass = await store.approve(user.id, input);
    await assert.rejects(
      store.withUserLock(user.id, async (c, row) => {
        await store.endAccessInTransaction(c, row, device.id);
        throw Error("agent revoked");
      }),
      /agent revoked/,
    );
    assert.equal(
      (await store.deviceState(user.id, device.id)).lastGrantRevoked,
      false,
    );
    assert.equal(
      (
        await pool.query(
          "SELECT count(*)::int n FROM gk_push_jobs WHERE event='end'",
        )
      ).rows[0].n,
      0,
    );
    await store.withUserLock(user.id, (c, row) =>
      store.endAccessInTransaction(c, row, device.id),
    );
    assert.equal(
      (await store.deviceState(user.id, device.id)).lastGrantId,
      pass.grantId,
    );
    assert.equal(
      (await store.deviceState(user.id, device.id)).lastGrantRevoked,
      true,
    );
  },
);
test(
  "rotated sessions retain an absolute lifetime and cap access at the family expiry",
  opts,
  async (t) => {
    const { store, user, device, advance } = await fixture(t);
    const first = await store.createSession(user.id, { deviceId: device.id });
    advance(30 * 86400000 - 60000);
    const next = await store.refreshSession(first.refreshToken);
    assert.equal(next.expiresAt, "2026-11-07T00:00:00.000Z");
    advance(60000);
    await assert.rejects(store.refreshSession(next.refreshToken));
    await assert.rejects(store.authenticate(next.accountToken));
  },
);
test(
  "refresh replay revokes its whole family without revoking another login or the independent device credential",
  opts,
  async (t) => {
    const { store, user, device } = await fixture(t);
    const first = await store.createSession(user.id, { deviceId: device.id });
    const independent = await store.createSession(user.id, {
      deviceId: device.id,
    });
    const rotated = await store.refreshSession(first.refreshToken);
    await assert.rejects(store.refreshSession(first.refreshToken));
    await assert.rejects(store.authenticate(rotated.accountToken));
    await assert.rejects(store.refreshSession(rotated.refreshToken));
    assert.equal(
      (await store.authenticate(independent.accountToken, "account")).userId,
      user.id,
    );
    assert.equal(
      (await store.authenticate(rotated.device.token, "device")).deviceId,
      device.id,
    );
  },
);

test(
  "push lease completion and retry cannot mutate a job attributed to another account",
  opts,
  async (t) => {
    const { store, pool, user, other, device, input } = await fixture(t);
    await store.registerPush(user.id, device.id, {
      token: "ab".repeat(32),
      environment: "sandbox",
    });
    await store.approve(user.id, input);
    const [job] = await store.claimPushJobs(1);
    const wrong = { ...job, user_id: other.id };
    assert.deepEqual(await store.completePushJob(wrong), { completed: false });
    await store.retryPushJob(wrong);
    const row = (
      await pool.query(
        "SELECT completed_at,lease_token FROM gk_push_jobs WHERE id=$1",
        [job.id],
      )
    ).rows[0];
    assert.equal(row.completed_at, null);
    assert.equal(row.lease_token, job.lease_token);
    await store.completePushJob(job);
  },
);
