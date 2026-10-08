import { createHash, randomBytes, randomUUID } from "node:crypto";
import { POLICY } from "../policy.js";
import { HostedError, PolicyError } from "./errors.js";
import { migrateHosted } from "./migrations.js";
export { HostedError, PolicyError } from "./errors.js";
export const tokenHash = (value) =>
  createHash("sha256").update(value).digest("hex");
const opaque = () => randomBytes(32).toString("base64url");
const iso = (value) => (value == null ? null : new Date(value).toISOString());
const credential = () => {
  const token = opaque();
  return { token, hash: tokenHash(token) };
};
const required = (value, name, max = 2000) => {
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new HostedError(
      `${name} is required and must be at most ${max} characters.`,
    );
  return value;
};
const unauthorized = () =>
  new HostedError(
    "Credential is invalid, expired or revoked.",
    "unauthorized",
    401,
  );
export class HostedStore {
  constructor(options) {
    this.pool = options.pool ?? options;
    this.clock = options.clock ?? (() => Date.now());
  }
  async migrate() {
    await migrateHosted(this.pool);
  }
  async withUserLock(userId, fn) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const user = (
        await client.query("SELECT * FROM gk_users WHERE id=$1 FOR UPDATE", [
          userId,
        ])
      ).rows[0];
      if (!user)
        throw new HostedError("Account was not found.", "not_found", 404);
      const result = await fn(client, user);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  async upsertUser({ appleSub, displayName }) {
    required(appleSub, "Apple subject", 255);
    if (displayName != null) required(displayName, "Display name", 200);
    const row = (
      await this.pool.query(
        `INSERT INTO gk_users(id,apple_sub,display_name) VALUES($1,$2,$3)
   ON CONFLICT(apple_sub) DO UPDATE SET display_name=COALESCE(EXCLUDED.display_name,gk_users.display_name) RETURNING *`,
        [randomUUID(), appleSub, displayName ?? null],
      )
    ).rows[0];
    return this.userView(row);
  }
  userView(row) {
    return {
      id: row.id,
      ...(row.purchase_account_token ? { purchaseAccountToken: row.purchase_account_token } : {}),
      ...(row.display_name ? { displayName: row.display_name } : {}),
    };
  }
  async assertUserAuthorized(client, userId) {
    const row = (
      await client.query(
        "SELECT id FROM gk_users WHERE id=$1 AND apple_authorization_revoked_at IS NULL",
        [userId],
      )
    ).rows[0];
    if (!row) throw unauthorized();
  }
  async device(client, userId, deviceId) {
    const row = (
      await client.query(
        "SELECT d.* FROM gk_devices d JOIN gk_users u ON u.id=d.user_id WHERE d.id=$1 AND d.user_id=$2 AND d.revoked_at IS NULL AND u.apple_authorization_revoked_at IS NULL",
        [deviceId, userId],
      )
    ).rows[0];
    if (!row) throw new HostedError("Device was not found.", "not_found", 404);
    return row;
  }
  async registerDevice(userId, input) {
    return this.withUserLock(userId, (client) =>
      this.registerDeviceInTransaction(client, userId, input),
    );
  }
  async registerDeviceInTransaction(
    client,
    userId,
    { installationId, name = "iPhone" },
  ) {
    required(installationId, "Installation ID", 200);
    required(name, "Device name", 200);
    await this.assertUserAuthorized(client, userId);
    const c = credential();
    const row = (
      await client.query(
        `INSERT INTO gk_devices(id,user_id,name,installation_id,token_hash,last_seen_at) VALUES($1,$2,$3,$4,$5,$6)
   ON CONFLICT(user_id,installation_id) DO UPDATE SET token_hash=EXCLUDED.token_hash,name=EXCLUDED.name,revoked_at=NULL,last_seen_at=EXCLUDED.last_seen_at RETURNING *`,
        [
          randomUUID(),
          userId,
          name,
          installationId,
          c.hash,
          new Date(this.clock()),
        ],
      )
    ).rows[0];
    return { id: row.id, name: row.name, token: c.token };
  }
  async authenticate(token, kind) {
    if (typeof token !== "string" || token.length < 20 || token.length > 512)
      throw unauthorized();
    const hash = tokenHash(token);
    const now = new Date(this.clock());
    if (!kind || kind === "device") {
      const row = (
        await this.pool.query(
          "SELECT d.* FROM gk_devices d JOIN gk_users u ON u.id=d.user_id WHERE d.token_hash=$1 AND d.revoked_at IS NULL AND u.apple_authorization_revoked_at IS NULL",
          [hash],
        )
      ).rows[0];
      if (row)
        return {
          userId: row.user_id,
          deviceId: row.id,
          kind: "device",
          sessionId: null,
          scopes: [],
        };
    }
    const row = (
      await this.pool.query(
        `SELECT s.* FROM gk_sessions s JOIN gk_users u ON u.id=s.user_id LEFT JOIN gk_devices d ON s.device_id=d.id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>$2 AND u.apple_authorization_revoked_at IS NULL AND (s.device_id IS NULL OR d.revoked_at IS NULL)`,
        [hash, now],
      )
    ).rows[0];
    if (!row || (kind && row.kind !== kind)) throw unauthorized();
    return {
      userId: row.user_id,
      deviceId: row.device_id,
      kind: row.kind,
      sessionId: row.id,
      scopes: row.scopes,
    };
  }
  async createSession(userId, options = {}) {
    return this.withUserLock(userId, (client) =>
      this.createSessionInTransaction(client, userId, options),
    );
  }
  async createSessionInTransaction(
    client,
    userId,
    {
      kind = "account",
      deviceId = null,
      scopes = [],
      ttlSeconds = 3600,
      familyId = randomUUID(),
      refreshExpiresAt,
    } = {},
  ) {
    if (
      !["account", "agent"].includes(kind) ||
      !Array.isArray(scopes) ||
      scopes.some((x) => typeof x !== "string") ||
      !Number.isInteger(ttlSeconds) ||
      ttlSeconds <= 0 ||
      ttlSeconds > 86400
    )
      throw new HostedError("Invalid session options.");
    await this.assertUserAuthorized(client, userId);
    if (deviceId) await this.device(client, userId, deviceId);
    const access = credential(),
      refresh = credential(),
      id = randomUUID();
    const now = this.clock();
    const refreshExpiry =
      refreshExpiresAt == null
        ? new Date(now + 30 * 86400000)
        : new Date(refreshExpiresAt);
    if (
      !Number.isFinite(refreshExpiry.getTime()) ||
      refreshExpiry.getTime() <= now
    )
      throw unauthorized();
    const expiry = new Date(
      Math.min(now + ttlSeconds * 1000, refreshExpiry.getTime()),
    );
    await client.query(
      "INSERT INTO gk_sessions(id,user_id,device_id,token_hash,refresh_hash,kind,scopes,expires_at,refresh_expires_at,family_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
      [
        id,
        userId,
        deviceId,
        access.hash,
        refresh.hash,
        kind,
        scopes,
        expiry,
        refreshExpiry,
        familyId,
      ],
    );
    return {
      accountToken: access.token,
      refreshToken: refresh.token,
      expiresAt: iso(expiry),
      sessionId: id,
      userId,
      deviceId,
      kind,
      scopes,
    };
  }
  async refreshSession(refreshToken, requiredKind, beforeRotate) {
    if (
      typeof refreshToken !== "string" ||
      refreshToken.length < 20 ||
      refreshToken.length > 512
    )
      throw unauthorized();
    const hash = tokenHash(refreshToken);
    const found = (
      await this.pool.query(
        "SELECT user_id FROM gk_sessions WHERE refresh_hash=$1",
        [hash],
      )
    ).rows[0];
    if (!found) throw unauthorized();
    const result = await this.withUserLock(
      found.user_id,
      async (client, user) => {
        const row = (
          await client.query(
            "SELECT * FROM gk_sessions WHERE refresh_hash=$1 AND refresh_expires_at>$2 FOR UPDATE",
            [hash, new Date(this.clock())],
          )
        ).rows[0];
        if (!row || (requiredKind && row.kind !== requiredKind))
          throw unauthorized();
        if (row.refresh_used_at) {
          // Commit replay revocation before returning an authentication error.
          await client.query(
            "UPDATE gk_sessions SET revoked_at=$1 WHERE user_id=$2 AND family_id=$3 AND kind=$4",
            [new Date(this.clock()), row.user_id, row.family_id, row.kind],
          );
          return null;
        }
        if (row.revoked_at || (requiredKind === "account" && !row.device_id))
          throw unauthorized();
        if (beforeRotate) {
          const validation = await beforeRotate(client, user, row);
          // Authoritative provider revocation must commit before the caller sees401.
          if (validation instanceof HostedError) return validation;
        }
        let device;
        if (row.device_id) {
          const d = await this.device(client, row.user_id, row.device_id);
          const c = credential();
          await client.query(
            "UPDATE gk_devices SET token_hash=$1 WHERE id=$2",
            [c.hash, d.id],
          );
          device = { id: d.id, name: d.name, token: c.token };
        }
        await client.query(
          "UPDATE gk_sessions SET revoked_at=$1,refresh_used_at=$1 WHERE id=$2",
          [new Date(this.clock()), row.id],
        );
        return {
          ...(await this.createSessionInTransaction(client, row.user_id, {
            deviceId: row.device_id,
            kind: row.kind,
            scopes: row.scopes,
            familyId: row.family_id,
            refreshExpiresAt: row.refresh_expires_at,
          })),
          ...(device ? { device } : {}),
        };
      },
    ).catch((error) => {
      if (error.code === "not_found") throw unauthorized();
      throw error;
    });
    if (result instanceof HostedError) throw result;
    if (!result) throw unauthorized();
    return result;
  }
  async listDevices(userId) {
    const rows = (
      await this.pool.query(
        "SELECT * FROM gk_devices WHERE user_id=$1 ORDER BY last_seen_at DESC",
        [userId],
      )
    ).rows;
    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      lastSeenAt: iso(row.last_seen_at),
      revokedAt: iso(row.revoked_at),
    }));
  }
  async account(userId) {
    const row = (
      await this.pool.query("SELECT * FROM gk_users WHERE id=$1", [userId])
    ).rows[0];
    if (!row) throw new HostedError("Account was not found.", "not_found", 404);
    return {
      user: this.userView(row),
      devices: await this.listDevices(userId),
      aiConsentVersion: row.consent_version,
      entitlement: null,
    };
  }
  async setConsent(userId, version) {
    required(version, "Consent version", 64);
    return this.withUserLock(userId, async (client) => {
      await client.query("UPDATE gk_users SET consent_version=$1 WHERE id=$2", [
        version,
        userId,
      ]);
      return { received: true };
    });
  }
  async deleteAccount(userId) {
    return this.withUserLock(userId, async (client) => {
      await client.query("DELETE FROM gk_users WHERE id=$1", [userId]);
      return { deleted: true };
    });
  }
  async revokeDevice(userId, deviceId) {
    return this.withUserLock(userId, async (client) => {
      await this.device(client, userId, deviceId);
      const now = new Date(this.clock());
      await this.enqueue(client, userId, deviceId, "end", null);
      await client.query("UPDATE gk_devices SET revoked_at=$1 WHERE id=$2", [
        now,
        deviceId,
      ]);
      await client.query(
        "UPDATE gk_sessions SET revoked_at=$1 WHERE device_id=$2 AND user_id=$3",
        [now, deviceId, userId],
      );
      await client.query(
        "UPDATE gk_grants SET revoked_at=$1 WHERE device_id=$2 AND user_id=$3 AND revoked_at IS NULL",
        [now, deviceId, userId],
      );
      return { revoked: true };
    });
  }
  approvalView(row) {
    return {
      grantId: row.id,
      status: row.revoked_at
        ? "revoked"
        : row.redeemed_at
          ? "redeemed"
          : new Date(row.valid_until).getTime() <= this.clock()
            ? "expired"
            : "awaiting_phone",
      redeemBy: iso(row.valid_until),
      windowSeconds: row.window_seconds,
      openAppURL: "gatekeeper://sync",
      instruction:
        "Open Gatekeeper on the paired iPhone. This response does not mean apps are unlocked.",
    };
  }
  async approve(userId, input) {
    return this.withUserLock(userId, (client, user) =>
      this.approveInTransaction(client, user, input),
    );
  }
  async approveInTransaction(
    client,
    user,
    { requestId, purpose, exitPlan, durationMinutes, deviceId },
    accessSource = "legacy_beta",
  ) {
    const userId = user.id;
    if (!["legacy_beta", "beta", "production_paid", "sandbox_test"].includes(accessSource))
      throw new HostedError("Invalid access source.");
    required(requestId, "Request ID", 200);
    required(purpose, "Purpose");
    required(exitPlan, "Exit plan");
    if (
      !Number.isInteger(durationMinutes) ||
      durationMinutes < 1 ||
      durationMinutes > 15
    )
      throw new PolicyError(
        "Requested duration must be a whole number of minutes from 1 through 15.",
      );
    const fingerprint = tokenHash(
      JSON.stringify([purpose, exitPlan, durationMinutes, deviceId]),
    );
    await this.device(client, userId, deviceId);
    const previous = (
      await client.query(
        "SELECT * FROM gk_grants WHERE user_id=$1 AND request_id=$2",
        [userId, requestId],
      )
    ).rows[0];
    if (previous) {
      if (previous.request_fingerprint !== fingerprint)
        throw new PolicyError(
          "This request ID was already used for a different request.",
        );
      return this.approvalView(previous);
    }
    const now = this.clock();
    if (user.cooldown_until && now < new Date(user.cooldown_until).getTime())
      throw new PolicyError(
        `Cooldown lasts until ${iso(user.cooldown_until)}.`,
      );
    const pending = (
      await client.query(
        "SELECT id FROM gk_grants WHERE user_id=$1 AND revoked_at IS NULL AND ((redeemed_at IS NULL AND valid_until>$2) OR ends_at>$2) LIMIT 1",
        [userId, new Date(now)],
      )
    ).rows[0];
    if (pending)
      throw new PolicyError("An active or unredeemed pass already exists.");
    const row = (
      await client.query(
        "INSERT INTO gk_grants(id,user_id,device_id,request_id,request_fingerprint,purpose,exit_plan,window_seconds,created_at,valid_until,access_source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *",
        [
          randomUUID(),
          userId,
          deviceId,
          requestId,
          fingerprint,
          purpose,
          exitPlan,
          durationMinutes * 60,
          new Date(now),
          new Date(now + 300000),
          accessSource,
        ],
      )
    ).rows[0];
    await this.enqueue(client, userId, deviceId, "approve", row.id);
    return this.approvalView(row);
  }
  async redeem(userId, deviceId, grantId, checkAccess) {
    return this.withUserLock(userId, async (client, user) => {
      await this.device(client, userId, deviceId);
      const row = (
        await client.query(
          "SELECT * FROM gk_grants WHERE id=$1 AND user_id=$2 AND device_id=$3",
          [grantId, userId, deviceId],
        )
      ).rows[0];
      const now = this.clock();
      if (
        !row ||
        row.revoked_at ||
        row.redeemed_at ||
        now >= new Date(row.valid_until).getTime()
      )
        throw new PolicyError("Pass is missing, used, revoked, or expired.");
      if (user.cooldown_until && now < new Date(user.cooldown_until).getTime())
        throw new PolicyError("Cooldown is still active.");
      if (checkAccess) await checkAccess(client, row);
      const ends = now + row.window_seconds * 1000;
      await client.query(
        "UPDATE gk_grants SET redeemed_at=$1,ends_at=$2 WHERE id=$3",
        [new Date(now), new Date(ends), grantId],
      );
      await client.query("UPDATE gk_users SET cooldown_until=$1 WHERE id=$2", [
        new Date(ends + 1800000),
        userId,
      ]);
      return { grantId, windowSeconds: row.window_seconds, endsAt: iso(ends) };
    });
  }
  async status(userId, deviceId) {
    return this.withUserLock(userId, async (client, user) => {
      if (deviceId) await this.device(client, userId, deviceId);
      const params = [userId, new Date(this.clock())];
      const filter = deviceId ? " AND device_id=$3" : "";
      if (deviceId) params.push(deviceId);
      const latest = (
        await client.query(
          `SELECT * FROM gk_grants WHERE user_id=$1${deviceId ? " AND device_id=$2" : ""} ORDER BY created_at DESC,ordinal DESC LIMIT 1`,
          deviceId ? [userId, deviceId] : [userId],
        )
      ).rows[0];
      const pending = (
        await client.query(
          `SELECT * FROM gk_grants WHERE user_id=$1 AND redeemed_at IS NULL AND revoked_at IS NULL AND valid_until>$2${filter} ORDER BY created_at DESC LIMIT 1`,
          params,
        )
      ).rows[0];
      const report = (
        await client.query(
          `SELECT * FROM gk_device_reports WHERE user_id=$1${deviceId ? " AND device_id=$2" : ""} ORDER BY received_at DESC LIMIT 1`,
          deviceId ? [userId, deviceId] : [userId],
        )
      ).rows[0];
      return {
        policy: POLICY,
        serverTime: iso(this.clock()),
        pendingPass: pending ? this.approvalView(pending) : null,
        nextEligibleAt: iso(user.cooldown_until),
        latestGrant: latest ? this.approvalView(latest) : null,
        lastDeviceReport: report
          ? {
              state: report.state,
              grantId: report.grant_id,
              localExpiry: iso(report.local_expiry),
              receivedAt: iso(report.received_at),
              ageSeconds: Math.max(
                0,
                Math.floor(
                  (this.clock() - new Date(report.received_at).getTime()) /
                    1000,
                ),
              ),
            }
          : null,
        note: "Server approvals and device reports are distinct. A report is historical and does not establish the current iPhone state.",
      };
    });
  }
  async deviceState(userId, deviceId) {
    const s = await this.status(userId, deviceId);
    return {
      pendingGrantId: s.pendingPass?.grantId ?? null,
      lastGrantId: s.latestGrant?.grantId ?? null,
      lastGrantRevoked: s.latestGrant?.status === "revoked",
    };
  }
  async report(
    userId,
    deviceId,
    { state, grantId = null, localExpiry = null },
  ) {
    if (
      ![
        "blocked",
        "unlocked",
        "unconfigured",
        "expired",
        "error",
        "locked",
        "active",
        "shielded",
        "unknown",
        "window_open",
        "permission_missing",
        "selection_missing",
      ].includes(state)
    )
      throw new HostedError("Invalid device state.");
    if (localExpiry != null && !Number.isFinite(Date.parse(localExpiry)))
      throw new HostedError("Invalid local expiry.");
    return this.withUserLock(userId, async (client) => {
      await this.device(client, userId, deviceId);
      if (
        grantId &&
        !(
          await client.query(
            "SELECT id FROM gk_grants WHERE id=$1 AND user_id=$2 AND device_id=$3",
            [grantId, userId, deviceId],
          )
        ).rows[0]
      )
        throw new HostedError("Grant was not found.", "not_found", 404);
      const now = new Date(this.clock());
      await client.query(
        `INSERT INTO gk_device_reports(device_id,user_id,received_at,state,grant_id,local_expiry) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(device_id) DO UPDATE SET received_at=EXCLUDED.received_at,state=EXCLUDED.state,grant_id=EXCLUDED.grant_id,local_expiry=EXCLUDED.local_expiry`,
        [deviceId, userId, now, state, grantId, localExpiry],
      );
      await client.query("UPDATE gk_devices SET last_seen_at=$1 WHERE id=$2", [
        now,
        deviceId,
      ]);
      return { received: true };
    });
  }
  async endAccess(userId, deviceId) {
    return this.withUserLock(userId, (client, user) =>
      this.endAccessInTransaction(client, user, deviceId),
    );
  }
  async endAccessInTransaction(client, user, deviceId) {
    const userId = user.id;
    if (deviceId) await this.device(client, userId, deviceId);
    const rows = (
      await client.query(
        `UPDATE gk_grants SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL${deviceId ? " AND device_id=$3" : ""} RETURNING *`,
        deviceId
          ? [new Date(this.clock()), userId, deviceId]
          : [new Date(this.clock()), userId],
      )
    ).rows;
    const targets = new Set(rows.map((row) => row.device_id));
    if (deviceId) targets.add(deviceId);
    for (const id of targets)
      await this.enqueue(client, userId, id, "end", null);
    return {
      status: "end_requested",
      openAppURL: "gatekeeper://sync",
      instruction:
        "Open Gatekeeper to apply now. A closed or offline iPhone app has not acknowledged this request. The existing local timer still applies.",
    };
  }
  async registerPush(userId, deviceId, { token, environment }) {
    if (
      typeof token !== "string" ||
      !/^[0-9a-f]{64,200}$/i.test(token) ||
      !["sandbox", "production"].includes(environment)
    )
      throw new HostedError("Invalid APNs registration.");
    return this.withUserLock(userId, async (client) => {
      await this.device(client, userId, deviceId);
      await client.query(
        "UPDATE gk_devices SET apns_token=$1,apns_environment=$2 WHERE id=$3",
        [token, environment, deviceId],
      );
      return { received: true };
    });
  }
  async enqueue(client, userId, deviceId, event, grantId) {
    const now = new Date(this.clock());
    await client.query(
      "INSERT INTO gk_push_jobs(id,user_id,device_id,grant_id,event,created_at,available_at) SELECT $1,$2,id,$4,$5,$6,$6 FROM gk_devices WHERE id=$3 AND user_id=$2 AND apns_token IS NOT NULL",
      [randomUUID(), userId, deviceId, grantId, event, now],
    );
  }
  async claimPushJobs(limit = 20) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100)
      throw new HostedError("Invalid push batch size.");
    const now = new Date(this.clock());
    const lease = randomUUID();
    return (
      await this.pool.query(
        `WITH jobs AS (SELECT j.id FROM gk_push_jobs j JOIN gk_devices d ON d.id=j.device_id WHERE j.completed_at IS NULL AND j.available_at<=$1 AND (j.lease_until IS NULL OR j.lease_until<=$1) AND d.apns_token IS NOT NULL ORDER BY j.available_at FOR UPDATE OF j SKIP LOCKED LIMIT $2), leased AS (UPDATE gk_push_jobs j SET lease_until=$3,lease_token=$4,attempts=attempts+1 FROM jobs WHERE j.id=jobs.id RETURNING j.*) SELECT l.*,d.apns_token,d.apns_environment FROM leased l JOIN gk_devices d ON d.id=l.device_id`,
        [now, limit, new Date(this.clock() + 60000), lease],
      )
    ).rows;
  }
  async completePushJob(job, result = {}) {
    return this.withUserLock(job.user_id, async (client) => {
      const row = (
        await client.query(
          "UPDATE gk_push_jobs SET completed_at=$1,lease_until=NULL WHERE id=$2 AND lease_token=$3 AND user_id=$4 AND device_id=$5 AND completed_at IS NULL RETURNING *",
          [
            new Date(this.clock()),
            job.id,
            job.lease_token,
            job.user_id,
            job.device_id,
          ],
        )
      ).rows[0];
      if (row && result.invalidToken)
        await client.query(
          "UPDATE gk_devices SET apns_token=NULL WHERE id=$1 AND apns_token=$2",
          [row.device_id, job.apns_token],
        );
      return { completed: !!row };
    });
  }
  async retryPushJob(job) {
    await this.pool.query(
      "UPDATE gk_push_jobs SET lease_until=NULL,lease_token=NULL,available_at=$1 WHERE id=$2 AND lease_token=$3 AND user_id=$4 AND device_id=$5 AND completed_at IS NULL",
      [
        new Date(
          this.clock() +
            Math.min(3600000, 1000 * 2 ** Math.min(job.attempts, 12)),
        ),
        job.id,
        job.lease_token,
        job.user_id,
        job.device_id,
      ],
    );
  }
  async pruneHistory(retentionDays = 30) {
    if (!Number.isFinite(retentionDays) || retentionDays < 0)
      throw new HostedError("Invalid retention.");
    const before = new Date(this.clock() - retentionDays * 86400000);
    await this.pool.query(
      "UPDATE gk_grants SET purpose=NULL,exit_plan=NULL WHERE created_at<=$1 AND (purpose IS NOT NULL OR exit_plan IS NOT NULL)",
      [before],
    );
    await this.pool.query(
      "DELETE FROM gk_sessions WHERE refresh_expires_at<=$1",
      [new Date(this.clock())],
    );
    await this.pool.query(
      "DELETE FROM gk_auth_challenges WHERE expires_at<=$1",
      [new Date(this.clock())],
    );
    const now = new Date(this.clock());
    await this.pool.query(
      `DELETE FROM gk_push_jobs j WHERE j.completed_at<=$1 OR (
        j.created_at<=$1 AND j.created_at + INTERVAL '5 minutes'<=$2
        AND (j.lease_until IS NULL OR j.lease_until<=$2)
        AND NOT EXISTS (SELECT 1 FROM gk_grants g WHERE g.id=j.grant_id
          AND g.user_id=j.user_id AND g.device_id=j.device_id
          AND g.revoked_at IS NULL AND g.redeemed_at IS NULL AND g.valid_until>$2)
      )`,
      [before, now],
    );
    await this.pool.query(
      "DELETE FROM gk_device_reports WHERE received_at<$1",
      [before],
    );
    await this.pool.query(
      "UPDATE gk_devices SET apns_token=NULL,apns_environment=NULL WHERE revoked_at<$1",
      [before],
    );
  }
}
