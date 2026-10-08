import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import pg from "pg";
import { generateKeyPair, SignJWT, jwtVerify } from "jose";
import { HostedStore } from "../../src/hosted/store.js";
const { HostedIdentity, AppleAuthProvider } = await import(
  "../../src/hosted/identity.js"
).catch(() => ({}));
const db = process.env.TEST_DATABASE_URL;
const opts = { skip: !db };
const keys = await generateKeyPair("RS256");
async function fixture(t, extra = {}) {
  assert.equal(
    typeof HostedIdentity,
    "function",
    "HostedIdentity must implement Apple identity verification",
  );
  const schema = `identity_${randomUUID().replaceAll("-", "")}`;
  const admin = new pg.Pool({ connectionString: db });
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({
    connectionString: db,
    options: `-c search_path=${schema}`,
  });
  t.after(async () => {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });
  let now = Date.now();
  const store = new HostedStore({ pool, clock: () => now });
  await store.migrate();
  const verifyIdentityToken = async (token, options) =>
    (
      await jwtVerify(token, keys.publicKey, {
        issuer: options.issuer,
        audience: options.audience,
        currentDate: new Date(now),
        algorithms: ["RS256"],
      })
    ).payload;
  const identity = new HostedIdentity({
    store,
    apiOrigin: "https://api.example.test",
    appleAudience: "app.gatekeeper",
    verifyIdentityToken,
    purchaseBindingKey: Buffer.alloc(32, 17),
    ...extra,
  });
  async function signed(challenge, claims = {}) {
    return new SignJWT({
      nonce: createHash("sha256").update(challenge.nonce).digest("hex"),
      ...claims,
    })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(claims.iss ?? "https://appleid.apple.com")
      .setAudience(claims.aud ?? "app.gatekeeper")
      .setSubject(claims.sub ?? "apple-a")
      .setExpirationTime(claims.exp ?? Math.floor(now / 1000) + 300)
      .sign(keys.privateKey);
  }
  const login = async (challenge, claims = {}, installationId = "install") =>
    identity.login({
      challengeId: challenge.challengeId,
      identityToken: await signed(challenge, claims),
      installationId,
      deviceName: "Phone",
      authorizationCode: "valid-code",
    });
  return {
    identity,
    store,
    pool,
    signed,
    login,
    advance: (ms) => {
      now += ms;
    },
  };
}
test(
  "signed identity creates scoped credentials, refresh rotates them, and concurrent challenge replay fails",
  opts,
  async (t) => {
    const { identity, store, login } = await fixture(t);
    const challenge = await identity.challenge();
    const result = await Promise.allSettled([
      login(challenge),
      login(challenge),
    ]);
    assert.equal(result.filter((x) => x.status === "fulfilled").length, 1);
    const session = result.find((x) => x.status === "fulfilled").value;
    assert.deepEqual(
      Object.keys(session).sort(),
      [
        "accountToken",
        "apiOrigin",
        "device",
        "expiresAt",
        "refreshToken",
        "user",
      ].sort(),
    );
    assert.equal(
      (await store.authenticate(session.accountToken, "account")).userId,
      session.user.id,
    );
    assert.equal(
      (await store.authenticate(session.device.token, "device")).deviceId,
      session.device.id,
    );
    const refresh = await identity.refresh(session.refreshToken);
    assert.equal(refresh.user.id, session.user.id);
    assert.equal(refresh.device.id, session.device.id);
    assert.notEqual(refresh.device.token, session.device.token);
    await assert.rejects(identity.refresh(session.refreshToken));
    const second = await login(await identity.challenge());
    assert.equal(second.device.id, session.device.id);
  },
);
test(
  "issuer, audience, expiry, nonce and signature mismatch fail without consuming valid challenge",
  opts,
  async (t) => {
    const { identity, login, pool, signed } = await fixture(t);
    const challenge = await identity.challenge();
    for (const claims of [
      { iss: "https://attacker.test" },
      { aud: "other.app" },
      { exp: 1 },
      { nonce: "wrong" },
    ])
      await assert.rejects(login(challenge, claims));
    const token = await signed(challenge);
    const parts = token.split(".");
    parts[2] = "A".repeat(parts[2].length);
    await assert.rejects(
      identity.login({
        challengeId: challenge.challengeId,
        identityToken: parts.join("."),
        installationId: "install",
      }),
    );
    assert.equal(
      (await pool.query("SELECT consumed_at FROM gk_auth_challenges")).rows[0]
        .consumed_at,
      null,
    );
    await login(challenge);
  },
);
test(
  "challenge expires exactly at five minutes and account deletion invalidates all credentials",
  opts,
  async (t) => {
    const { identity, store, login, advance } = await fixture(t);
    const challenge = await identity.challenge();
    advance(300000);
    await assert.rejects(login(challenge));
    const session = await login(await identity.challenge());
    await identity.delete(session.user.id);
    await assert.rejects(store.authenticate(session.accountToken));
    await assert.rejects(store.authenticate(session.device.token));
  },
);
test(
  "Apple code exchange stores encrypted revocable token and provider failure leaves account intact",
  opts,
  async (t) => {
    let failRevoke = true;
    let revoked;
    const appleProvider = {
      exchange: async () => ({ refreshToken: "apple-refresh-secret" }),
      revoke: async (token) => {
        if (failRevoke) throw Error("upstream down");
        revoked = token;
      },
    };
    const { identity, pool, login, store } = await fixture(t, {
      appleProvider,
      tokenEncryptionKey: Buffer.alloc(32, 7),
    });
    const session = await login(await identity.challenge());
    const row = (
      await pool.query("SELECT apple_refresh_ciphertext FROM gk_users")
    ).rows[0];
    assert.ok(row.apple_refresh_ciphertext);
    assert.ok(!row.apple_refresh_ciphertext.includes("apple-refresh-secret"));
    await assert.rejects(identity.delete(session.user.id));
    assert.equal(
      (await store.account(session.user.id)).user.id,
      session.user.id,
    );
    failRevoke = false;
    await identity.delete(session.user.id);
    assert.equal(revoked, "apple-refresh-secret");
  },
);
test("production Apple provider sends code and revocation to Apple and fails closed on HTTP errors", async () => {
  assert.equal(typeof AppleAuthProvider, "function");
  const calls = [];
  const provider = new AppleAuthProvider({
    clientId: "app.gatekeeper",
    clientSecret: async () => "secret-jwt",
    fetch: async (url, input) => {
      calls.push({ url, body: new URLSearchParams(input.body) });
      return {
        ok: true,
        json: async () => ({ refresh_token: "refresh", id_token: "id" }),
      };
    },
  });
  assert.deepEqual(await provider.exchange("code"), {
    refreshToken: "refresh",
    identityToken: "id",
  });
  await provider.revoke("refresh");
  assert.equal(calls[0].url, "https://appleid.apple.com/auth/token");
  assert.equal(calls[0].body.get("grant_type"), "authorization_code");
  assert.equal(calls[0].body.get("code"), "code");
  assert.equal(calls[1].body.get("token_type_hint"), "refresh_token");
  const failing = new AppleAuthProvider({
    clientId: "app",
    clientSecret: "secret",
    fetch: async () => ({ ok: false }),
  });
  await assert.rejects(failing.exchange("code"));
});
test("verified Apple identity recreates its purchase binding without retaining deleted account rows", opts, async (t) => {
  const f = await fixture(t);
  const before = await f.login(await f.identity.challenge());
  assert.match(before.user.purchaseAccountToken ?? "", /^[0-9a-f-]{36}$/);
  await f.identity.delete(before.user.id);
  assert.equal(Number((await f.pool.query("SELECT count(*) FROM gk_users")).rows[0].count), 0);
  const after = await f.login(await f.identity.challenge());
  assert.notEqual(after.user.id, before.user.id);
  assert.equal(after.user.purchaseAccountToken, before.user.purchaseAccountToken);
});
test(
  "account refresh cannot rotate or consume an agent refresh credential",
  opts,
  async (t) => {
    const { store, identity } = await fixture(t);
    const user = await store.upsertUser({ appleSub: "external-agent" });
    const session = await store.createSession(user.id, {
      kind: "agent",
      scopes: ["gatekeeper:status"],
    });
    await assert.rejects(identity.refresh(session.refreshToken));
    assert.equal(
      (await store.authenticate(session.accountToken, "agent")).userId,
      user.id,
    );
    const rotated = await store.refreshSession(session.refreshToken);
    assert.equal(rotated.kind, "agent");
  },
);

async function appleFixture(t, behavior = {}) {
  let f;
  const provider = new AppleAuthProvider({
    clientId: "app.gatekeeper",
    clientSecret: "secret",
    fetch: async (_url, input) => {
      const fields = new URLSearchParams(input.body);
      if (fields.get("grant_type") === "authorization_code")
        return {
          ok: true,
          status: 200,
          json: async () => ({
            refresh_token: "apple-secret",
            id_token: behavior.loginIdentityToken,
          }),
        };
      if (fields.get("grant_type") === "refresh_token") {
        behavior.calls = (behavior.calls ?? 0) + 1;
        if (behavior.started) behavior.started();
        if (behavior.wait) await behavior.wait;
        if (behavior.network) throw Error("network");
        if (behavior.malformed)
          return {
            ok: true,
            status: 200,
            json: async () => {
              throw Error("invalid body");
            },
          };
        if (behavior.error)
          return {
            ok: false,
            status: behavior.status ?? 400,
            json: async () => ({ error: behavior.error }),
          };
        let identityToken = await f.signedRefresh(behavior.claims);
        if (behavior.tampered)
          identityToken =
            identityToken.split(".").slice(0, 2).join(".") + ".AAAA";
        return {
          ok: true,
          status: 200,
          json: async () => ({
            id_token: identityToken,
            ...(behavior.rotatedAppleToken
              ? { refresh_token: behavior.rotatedAppleToken }
              : {}),
          }),
        };
      }
      if (fields.get("token_type_hint") === "refresh_token") {
        if (behavior.revokeStarted) behavior.revokeStarted();
        if (behavior.revokeWait) await behavior.revokeWait;
      }
      return { ok: true, status: 200 };
    },
  });
  f = await fixture(t, {
    appleProvider: provider,
    tokenEncryptionKey: Buffer.alloc(32, 9),
  });
  f.signedRefresh = async (claims = {}) =>
    new SignJWT({ ...claims })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(claims.iss ?? "https://appleid.apple.com")
      .setAudience(claims.aud ?? "app.gatekeeper")
      .setSubject(claims.sub ?? "apple-a")
      .setExpirationTime(claims.exp ?? Math.floor(f.store.clock() / 1000) + 300)
      .sign(keys.privateKey);
  const challenge = await f.identity.challenge();
  behavior.loginIdentityToken = await f.signed(challenge);
  f.session = await f.identity.login({
    challengeId: challenge.challengeId,
    identityToken: behavior.loginIdentityToken,
    authorizationCode: "valid-code",
    installationId: "install",
    deviceName: "Phone",
  });
  return { ...f, behavior, provider };
}
test(
  "hosted refresh validates Apple authorization and caches success for at most one day",
  opts,
  async (t) => {
    const f = await appleFixture(t);
    const next = await f.identity.refresh(f.session.refreshToken);
    assert.equal(f.behavior.calls, 1);
    assert.equal(next.user.id, f.session.user.id);
    const cached = await f.identity.refresh(next.refreshToken);
    assert.equal(f.behavior.calls, 1);
    f.advance(86400000);
    await f.identity.refresh(cached.refreshToken);
    assert.equal(f.behavior.calls, 2);
  },
);
test(
  "authoritative Apple invalid_grant commits revocation of every user session and agent connection",
  opts,
  async (t) => {
    const { HostedOAuth } = await import("../../src/hosted/oauth.js");
    const f = await appleFixture(t, { error: "invalid_grant" });
    const otherUser = await f.store.upsertUser({
      appleSub: "apple-independent",
    });
    const otherSession = await f.store.createSession(otherUser.id);
    const extra = await f.store.createSession(f.session.user.id, {
      deviceId: f.session.device.id,
    });
    const oauth = new HostedOAuth({
      store: f.store,
      publicOrigin: "https://api.example.test",
      encryptionKey: Buffer.alloc(32, 3),
    });
    await oauth.init();
    const client = await oauth.registerClient({
      client_name: "Agent",
      redirect_uris: ["https://agent.test/callback"],
      token_endpoint_auth_method: "none",
    });
    const connectionId = randomUUID();
    await f.pool.query(
      "INSERT INTO gk_oauth_connections(id,user_id,client_id,scopes,issuer,resource,created_at) VALUES($1,$2,$3,$4,$5,$5,$6)",
      [
        connectionId,
        f.session.user.id,
        client.client_id,
        ["gatekeeper:status"],
        oauth.resource,
        new Date(f.store.clock()),
      ],
    );
    const token = await oauth.transaction((c) =>
      oauth.issueTokens(c, { id: connectionId, user_id: f.session.user.id }, [
        "gatekeeper:status",
      ]),
    );
    await assert.rejects(
      f.identity.refresh(f.session.refreshToken),
      (e) => e.status === 401 && e.code === "apple_authorization_revoked",
    );
    await assert.rejects(f.store.authenticate(extra.accountToken));
    await assert.rejects(f.identity.refresh(extra.refreshToken));
    await assert.rejects(oauth.verifyAccessToken(token.access_token));
    assert.equal(
      (await f.store.account(f.session.user.id)).user.id,
      f.session.user.id,
    );
    assert.equal(
      (await f.store.authenticate(otherSession.accountToken)).userId,
      otherUser.id,
    );
  },
);
test(
  "Apple outages and malformed or non-authoritative errors return503 without consuming local refresh credentials",
  opts,
  async (t) => {
    for (const behavior of [
      { network: true },
      { malformed: true },
      { tampered: true },
      { error: "invalid_client" },
      { error: "invalid_grant", status: 500 },
      { error: "temporarily_unavailable", status: 429 },
    ]) {
      const f = await appleFixture(t, behavior);
      await assert.rejects(
        f.identity.refresh(f.session.refreshToken),
        (e) => e.status === 503,
      );
      assert.equal(
        (await f.store.authenticate(f.session.accountToken)).userId,
        f.session.user.id,
      );
      delete behavior.error;
      delete behavior.network;
      delete behavior.malformed;
      delete behavior.tampered;
      f.advance(60000); // The shared retry schedule preserves the credential without hammering Apple.
      assert.equal(
        (await f.identity.refresh(f.session.refreshToken)).user.id,
        f.session.user.id,
      );
    }
  },
);
test(
  "refresh ID tokens bind signature, issuer, audience, subject and expiry while allowing an absent nonce",
  opts,
  async (t) => {
    for (const claims of [
      { sub: "apple-other" },
      { iss: "https://other.test" },
      { aud: "other.app" },
      { exp: 1 },
    ]) {
      const behavior = { claims };
      const f = await appleFixture(t, behavior);
      await assert.rejects(
        f.identity.refresh(f.session.refreshToken),
        (e) => e.status === 503,
      );
      assert.equal(
        (await f.store.authenticate(f.session.accountToken)).userId,
        f.session.user.id,
      );
      behavior.claims = {};
      f.advance(60000);
      assert.equal(
        (await f.identity.refresh(f.session.refreshToken)).user.id,
        f.session.user.id,
      );
    }
  },
);
test(
  "changed Apple client configuration fails honestly without revoking stored credentials",
  opts,
  async (t) => {
    const f = await appleFixture(t);
    const changed = new HostedIdentity({
      store: f.store,
      apiOrigin: "https://api.example.test",
      appleAudience: "another.app",
      appleProvider: f.provider,
      tokenEncryptionKey: Buffer.alloc(32, 9),
    });
    await assert.rejects(
      changed.refresh(f.session.refreshToken),
      (e) => e.status === 503 && e.code === "configuration_error",
    );
    assert.equal(f.behavior.calls ?? 0, 0);
    assert.equal(
      (await f.store.authenticate(f.session.accountToken)).userId,
      f.session.user.id,
    );
  },
);
test(
  "account deletion waits for refresh authorization check and cannot resurrect the deleted account",
  opts,
  async (t) => {
    let start;
    let release;
    const entered = new Promise((resolve) => {
      start = resolve;
    });
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const f = await appleFixture(t, { started: start, wait: gate });
    const refreshing = f.identity.refresh(f.session.refreshToken);
    await Promise.race([
      entered,
      refreshing.then(() => {
        throw Error("Refresh rotated without checking Apple authorization");
      }),
    ]);
    const deleting = f.identity.delete(f.session.user.id);
    release();
    const results = await Promise.allSettled([refreshing, deleting]);
    assert.equal(results[1].status, "fulfilled");
    assert.equal(
      (await f.pool.query("SELECT count(*)::int n FROM gk_users")).rows[0].n,
      0,
    );
    if (results[0].status === "fulfilled")
      await assert.rejects(f.store.authenticate(results[0].value.accountToken));
  },
);

test(
  "parallel independent session refreshes share one successful daily Apple authorization check",
  opts,
  async (t) => {
    let start;
    let release;
    const entered = new Promise((r) => {
      start = r;
    });
    const gate = new Promise((r) => {
      release = r;
    });
    const f = await appleFixture(t, { started: start, wait: gate });
    const second = await f.store.createSession(f.session.user.id, {
      deviceId: f.session.device.id,
    });
    const firstRefresh = f.identity.refresh(f.session.refreshToken);
    await entered;
    const secondRefresh = f.identity.refresh(second.refreshToken);
    release();
    const values = await Promise.all([firstRefresh, secondRefresh]);
    assert.equal(f.behavior.calls, 1);
    for (const value of values)
      assert.equal(
        (await f.store.authenticate(value.accountToken)).userId,
        f.session.user.id,
      );
  },
);
test(
  "missing stored client binding, disabled provider and corrupt encryption key preserve credentials",
  opts,
  async (t) => {
    const f = await appleFixture(t);
    const disabled = new HostedIdentity({
      store: f.store,
      apiOrigin: "https://api.example.test",
      appleAudience: "app.gatekeeper",
    });
    await assert.rejects(
      disabled.refresh(f.session.refreshToken),
      (e) => e.status === 503 && e.code === "configuration_error",
    );
    const wrongKey = new HostedIdentity({
      store: f.store,
      apiOrigin: "https://api.example.test",
      appleAudience: "app.gatekeeper",
      appleProvider: f.provider,
      tokenEncryptionKey: Buffer.alloc(32, 1),
    });
    await assert.rejects(
      wrongKey.refresh(f.session.refreshToken),
      (e) => e.status === 503 && e.code === "configuration_error",
    );
    await f.pool.query(
      "UPDATE gk_users SET apple_refresh_client_id=NULL WHERE id=$1",
      [f.session.user.id],
    );
    await assert.rejects(
      f.identity.refresh(f.session.refreshToken),
      (e) => e.status === 503 && e.code === "configuration_error",
    );
    assert.equal(f.behavior.calls ?? 0, 0);
    assert.equal(
      (await f.store.authenticate(f.session.accountToken)).userId,
      f.session.user.id,
    );
  },
);
test(
  "an untyped invalid_grant-shaped failure cannot revoke a user session",
  opts,
  async (t) => {
    const f = await appleFixture(t);
    f.provider.refresh = async () => {
      throw Object.assign(Error("invalid_grant"), {
        code: "invalid_grant",
        status: 400,
      });
    };
    await assert.rejects(
      f.identity.refresh(f.session.refreshToken),
      (e) => e.status === 503,
    );
    assert.equal(
      (await f.store.authenticate(f.session.accountToken)).userId,
      f.session.user.id,
    );
  },
);
test(
  "a rotated Apple refresh token is encrypted and retained only after a matching signed identity",
  opts,
  async (t) => {
    const f = await appleFixture(t, {
      rotatedAppleToken: "replacement-apple-secret",
    });
    await f.identity.refresh(f.session.refreshToken);
    const row = (
      await f.pool.query(
        "SELECT apple_refresh_ciphertext FROM gk_users WHERE id=$1",
        [f.session.user.id],
      )
    ).rows[0];
    assert.equal(
      f.identity.decrypt(row.apple_refresh_ciphertext),
      "replacement-apple-secret",
    );
    assert.ok(
      !row.apple_refresh_ciphertext.includes("replacement-apple-secret"),
    );
  },
);

test("production Apple refresh sends the exact bound client and refresh grant fields", async () => {
  let fields;
  let url;
  const provider = new AppleAuthProvider({
    clientId: "app.gatekeeper",
    clientSecret: "secret-jwt",
    fetch: async (target, input) => {
      url = target;
      fields = new URLSearchParams(input.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({ id_token: "signed-id" }),
      };
    },
  });
  assert.deepEqual(await provider.refresh("apple-refresh"), {
    identityToken: "signed-id",
  });
  assert.equal(url, "https://appleid.apple.com/auth/token");
  assert.equal(fields.get("client_id"), "app.gatekeeper");
  assert.equal(fields.get("client_secret"), "secret-jwt");
  assert.equal(fields.get("grant_type"), "refresh_token");
  assert.equal(fields.get("refresh_token"), "apple-refresh");
  assert.equal(fields.has("code"), false);
});

test(
  "a deletion that holds the account lock makes a concurrent refresh fail401 without recreating credentials",
  opts,
  async (t) => {
    let start;
    let release;
    const entered = new Promise((r) => {
      start = r;
    });
    const gate = new Promise((r) => {
      release = r;
    });
    const f = await appleFixture(t, { revokeStarted: start, revokeWait: gate });
    const deleting = f.identity.delete(f.session.user.id);
    await entered;
    const refreshing = f.identity.refresh(f.session.refreshToken);
    release();
    const results = await Promise.allSettled([deleting, refreshing]);
    assert.equal(results[0].status, "fulfilled");
    assert.equal(results[1].status, "rejected");
    assert.equal(results[1].reason.status, 401);
    assert.equal(
      (await f.pool.query("SELECT count(*)::int n FROM gk_sessions")).rows[0].n,
      0,
    );
    assert.equal(f.behavior.calls ?? 0, 0);
  },
);

async function agentFor(f) {
  const { HostedOAuth } = await import("../../src/hosted/oauth.js");
  const oauth = new HostedOAuth({
    store: f.store,
    publicOrigin: "https://api.example.test",
    encryptionKey: Buffer.alloc(32, 3),
  });
  await oauth.init();
  const client = await oauth.registerClient({
    client_name: "Copied agent",
    redirect_uris: ["https://agent.test/callback"],
    token_endpoint_auth_method: "none",
  });
  const id = randomUUID();
  await f.pool.query(
    "INSERT INTO gk_oauth_connections(id,user_id,client_id,scopes,issuer,resource,created_at) VALUES($1,$2,$3,$4,$5,$5,$6)",
    [
      id,
      f.session.user.id,
      client.client_id,
      ["gatekeeper:status", "gatekeeper:approve"],
      oauth.resource,
      new Date(f.store.clock()),
    ],
  );
  const tokens = await oauth.transaction((c) =>
    oauth.issueTokens(c, { id, user_id: f.session.user.id }, [
      "gatekeeper:status",
      "gatekeeper:approve",
    ]),
  );
  return { oauth, client, tokens };
}
test(
  "daily sweep independently rejects copied phone and agent credentials, revokes grants and preserves cooldown",
  opts,
  async (t) => {
    for (const active of [false, true]) {
      const f = await appleFixture(t, { error: "invalid_grant" });
      assert.equal(typeof f.identity.sweepAppleAuthorizations, "function");
      const agent = await agentFor(f);
      const other = await f.store.upsertUser({ appleSub: "apple-unaffected" });
      const otherDevice = await f.store.registerDevice(other.id, {
        installationId: "other",
        name: "Other",
      });
      const otherSession = await f.store.createSession(other.id, {
        deviceId: otherDevice.id,
      });
      f.advance(86400000);
      const copied = await agent.oauth.exchangeRefreshToken(
        agent.client,
        agent.tokens.refresh_token,
        undefined,
        new URL(agent.oauth.resource),
      );
      assert.equal(
        (await agent.oauth.verifyAccessToken(copied.access_token)).extra.userId,
        f.session.user.id,
      );
      assert.equal(
        (await f.store.authenticate(f.session.device.token, "device")).deviceId,
        f.session.device.id,
      );
      const pass = await f.store.approve(f.session.user.id, {
        requestId: "grant",
        purpose: "Reply to Alex",
        exitPlan: "Close after replying",
        durationMinutes: 3,
        deviceId: f.session.device.id,
      });
      if (active)
        await f.store.redeem(
          f.session.user.id,
          f.session.device.id,
          pass.grantId,
        );
      const cooldown = (await f.store.status(f.session.user.id)).nextEligibleAt;
      const result = await f.identity.sweepAppleAuthorizations();
      assert.equal(result.revoked, 1);
      await assert.rejects(f.store.authenticate(f.session.device.token));
      await assert.rejects(agent.oauth.verifyAccessToken(copied.access_token));
      const state = await f.store.status(f.session.user.id);
      assert.equal(state.latestGrant.status, "revoked");
      assert.equal(state.nextEligibleAt, cooldown);
      assert.equal(
        (await f.store.authenticate(otherDevice.token, "device")).userId,
        other.id,
      );
      const row = (
        await f.pool.query("SELECT revoked_at FROM gk_sessions WHERE id=$1", [
          otherSession.sessionId,
        ])
      ).rows[0];
      assert.equal(row.revoked_at, null);
      delete f.behavior.error;
      const challenge = await f.identity.challenge();
      f.behavior.loginIdentityToken = await f.signed(challenge);
      const recovered = await f.identity.login({
        challengeId: challenge.challengeId,
        identityToken: f.behavior.loginIdentityToken,
        authorizationCode: "fresh-code",
        installationId: "install",
        deviceName: "Phone",
      });
      assert.equal(recovered.device.id, f.session.device.id);
      assert.equal(
        (await f.store.authenticate(recovered.device.token)).userId,
        f.session.user.id,
      );
      if (active)
        await assert.rejects(
          f.store.approve(f.session.user.id, {
            requestId: "after-recovery",
            purpose: "Reply to Alex",
            exitPlan: "Close after replying",
            durationMinutes: 3,
            deviceId: recovered.device.id,
          }),
        );
    }
  },
);
test(
  "sweep transient failures persist backoff and keep copied device and agent credentials until verification succeeds",
  opts,
  async (t) => {
    const f = await appleFixture(t, { network: true });
    assert.equal(typeof f.identity.sweepAppleAuthorizations, "function");
    const agent = await agentFor(f);
    const first = await f.identity.sweepAppleAuthorizations();
    assert.equal(first.retried, 1);
    assert.equal(f.behavior.calls, 1);
    const repeated = await f.identity.sweepAppleAuthorizations();
    assert.equal(repeated.claimed, 0);
    assert.equal(f.behavior.calls, 1);
    await assert.rejects(
      f.identity.refresh(f.session.refreshToken),
      (e) => e.status === 503,
    );
    assert.equal(f.behavior.calls, 1);
    assert.equal(
      (await f.store.authenticate(f.session.device.token)).userId,
      f.session.user.id,
    );
    assert.equal(
      (await agent.oauth.verifyAccessToken(agent.tokens.access_token)).extra
        .userId,
      f.session.user.id,
    );
    delete f.behavior.network;
    f.advance(60000);
    const retried = await f.identity.sweepAppleAuthorizations();
    assert.equal(retried.checked, 1);
    assert.equal(f.behavior.calls, 2);
    assert.equal(
      (await f.identity.refresh(f.session.refreshToken)).user.id,
      f.session.user.id,
    );
    assert.equal(f.behavior.calls, 2);
  },
);
test(
  "two replicas claim one due account and never repeat a successful check inside one day",
  opts,
  async (t) => {
    let start;
    let release;
    const entered = new Promise((r) => {
      start = r;
    });
    const gate = new Promise((r) => {
      release = r;
    });
    const f = await appleFixture(t, { started: start, wait: gate });
    assert.equal(typeof f.identity.sweepAppleAuthorizations, "function");
    const replica = new HostedIdentity({
      store: f.store,
      apiOrigin: "https://api.example.test",
      appleAudience: "app.gatekeeper",
      appleProvider: f.provider,
      tokenEncryptionKey: Buffer.alloc(32, 9),
      verifyIdentityToken: f.identity.verifyIdentityToken,
    });
    const first = f.identity.sweepAppleAuthorizations();
    await Promise.race([
      entered,
      first.then(() => {
        throw Error("Sweep skipped the due Apple authorization");
      }),
    ]);
    const second = await replica.sweepAppleAuthorizations();
    assert.equal(second.claimed, 0);
    release();
    const done = await first;
    assert.equal(done.checked, 1);
    assert.equal(f.behavior.calls, 1);
    assert.equal((await replica.sweepAppleAuthorizations()).claimed, 0);
    f.advance(86400000);
    assert.equal((await replica.sweepAppleAuthorizations()).checked, 1);
    assert.equal(f.behavior.calls, 2);
  },
);
test(
  "expired sweep claims recover after worker loss and batch sizes stay bounded",
  opts,
  async (t) => {
    const f = await appleFixture(t);
    assert.equal(typeof f.identity.sweepAppleAuthorizations, "function");
    await f.pool.query(
      "UPDATE gk_users SET apple_check_lease_token=$1,apple_check_lease_until=$2 WHERE id=$3",
      [randomUUID(), new Date(f.store.clock() + 300000), f.session.user.id],
    );
    assert.equal((await f.identity.sweepAppleAuthorizations()).claimed, 0);
    f.advance(300000);
    assert.equal((await f.identity.sweepAppleAuthorizations()).checked, 1);
    for (const limit of [0, 21, 1.5])
      await assert.rejects(f.identity.sweepAppleAuthorizations({ limit }));
  },
);

test(
  "known Apple revocation cannot be bypassed by device re-registration or a stale active credential row",
  opts,
  async (t) => {
    const f = await appleFixture(t, { error: "invalid_grant" });
    await f.identity.sweepAppleAuthorizations();
    await assert.rejects(
      f.store.registerDevice(f.session.user.id, {
        installationId: "copied-installation",
        name: "Copied phone",
      }),
    );
    await assert.rejects(f.store.createSession(f.session.user.id));
    // Simulate an older worker restoring child-row flags after the durable account revocation.
    await f.pool.query(
      "UPDATE gk_devices SET revoked_at=NULL WHERE user_id=$1",
      [f.session.user.id],
    );
    await f.pool.query(
      "UPDATE gk_sessions SET revoked_at=NULL WHERE user_id=$1",
      [f.session.user.id],
    );
    await assert.rejects(f.store.authenticate(f.session.device.token));
    await assert.rejects(f.store.authenticate(f.session.accountToken));
  },
);
test(
  "reauthentication while authorization is cached does not schedule another successful Apple check inside the day",
  opts,
  async (t) => {
    const f = await appleFixture(t);
    await f.identity.sweepAppleAuthorizations();
    assert.equal(f.behavior.calls, 1);
    const challenge = await f.identity.challenge();
    f.behavior.loginIdentityToken = await f.signed(challenge);
    const login = await f.identity.login({
      challengeId: challenge.challengeId,
      identityToken: f.behavior.loginIdentityToken,
      authorizationCode: "new-code",
      installationId: "install",
      deviceName: "Phone",
    });
    assert.equal((await f.identity.sweepAppleAuthorizations()).claimed, 0);
    await f.identity.refresh(login.refreshToken);
    assert.equal(f.behavior.calls, 1);
  },
);
