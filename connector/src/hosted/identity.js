import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { HostedError, AppleTokenError } from "./errors.js";
import { purchaseAccountToken } from "./purchase-binding.js";
export { AppleTokenError } from "./errors.js";
import { tokenHash } from "./store.js";
const issuer = "https://appleid.apple.com";
const appleJWKS = createRemoteJWKSet(new URL(`${issuer}/auth/keys`));
const invalidIdentity = () =>
  new HostedError(
    "Apple identity or challenge is invalid, expired or already used.",
    "invalid_identity",
    401,
  );
const required = (value, name, max = 2000) => {
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new HostedError(`${name} is required.`);
};
export class AppleAuthProvider {
  constructor({ clientId, clientSecret, fetch: fetchImpl = globalThis.fetch }) {
    required(clientId, "Apple client ID");
    if (!clientSecret)
      throw new HostedError(
        "Apple client secret is required.",
        "configuration_error",
        503,
      );
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.fetch = fetchImpl;
  }
  async request(path, fields) {
    let secret;
    try {
      secret =
        typeof this.clientSecret === "function"
          ? await this.clientSecret()
          : this.clientSecret;
    } catch {
      throw new HostedError(
        "Apple client secret is unavailable.",
        "configuration_error",
        503,
      );
    }
    if (typeof secret !== "string" || !secret)
      throw new HostedError(
        "Apple client secret is unavailable.",
        "configuration_error",
        503,
      );
    const body = new URLSearchParams({
      client_id: this.clientId,
      client_secret: secret,
      ...fields,
    });
    let response;
    try {
      response = await this.fetch(`${issuer}/auth/${path}`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body,
        signal: AbortSignal.timeout(10000),
      });
    } catch {
      throw new HostedError(
        "Apple authentication service is unavailable.",
        "apple_unavailable",
        503,
      );
    }
    if (!response.ok) {
      let value;
      try {
        value = await response.json();
      } catch {
        /* An invalid body is never authoritative revocation. */
      }
      const appleError =
        typeof value?.error === "string" ? value.error : "invalid_response";
      const revoked =
        path === "token" &&
        fields.grant_type === "refresh_token" &&
        response.status === 400 &&
        appleError === "invalid_grant";
      throw new AppleTokenError(appleError, revoked);
    }
    return response;
  }
  async exchange(code) {
    required(code, "Authorization code", 4096);
    const response = await this.request("token", {
      grant_type: "authorization_code",
      code,
    });
    const value = await response.json();
    if (
      typeof value.refresh_token !== "string" ||
      typeof value.id_token !== "string"
    )
      throw new HostedError(
        "Apple returned an incomplete token response.",
        "apple_auth_failed",
        502,
      );
    return { refreshToken: value.refresh_token, identityToken: value.id_token };
  }
  async revoke(token) {
    await this.request("revoke", { token, token_type_hint: "refresh_token" });
  }
  async refresh(token) {
    required(token, "Apple refresh token", 4096);
    const response = await this.request("token", {
      grant_type: "refresh_token",
      refresh_token: token,
    });
    let value;
    try {
      value = await response.json();
    } catch {
      throw new HostedError(
        "Apple returned an invalid token response.",
        "apple_unavailable",
        503,
      );
    }
    if (
      typeof value?.id_token !== "string" ||
      !value.id_token ||
      (value.refresh_token != null &&
        (typeof value.refresh_token !== "string" || !value.refresh_token))
    )
      throw new HostedError(
        "Apple returned an incomplete token response.",
        "apple_unavailable",
        503,
      );
    return {
      identityToken: value.id_token,
      ...(value.refresh_token ? { refreshToken: value.refresh_token } : {}),
    };
  }
}
export class HostedIdentity {
  constructor({
    store,
    apiOrigin,
    appleAudience,
    verifyIdentityToken,
    appleProvider,
    appleClientSecret,
    tokenEncryptionKey,
    purchaseBindingKey,
  }) {
    this.store = store;
    this.apiOrigin = apiOrigin;
    this.appleAudience = appleAudience;
    this.purchaseBindingKey = purchaseBindingKey;
    if (purchaseBindingKey !== undefined && (!Buffer.isBuffer(purchaseBindingKey) || purchaseBindingKey.length !== 32))
      throw new Error("Purchase binding requires a durable 32-byte key");
    this.verifyIdentityToken =
      verifyIdentityToken ??
      (async (token, options) =>
        (
          await jwtVerify(token, appleJWKS, {
            issuer,
            audience: options.audience,
            algorithms: ["RS256"],
            currentDate: new Date(this.store.clock()),
          })
        ).payload);
    this.appleProvider =
      appleProvider ??
      (appleClientSecret
        ? new AppleAuthProvider({
            clientId: appleAudience,
            clientSecret: appleClientSecret,
          })
        : null);
    this.tokenEncryptionKey = tokenEncryptionKey
      ? Buffer.isBuffer(tokenEncryptionKey)
        ? tokenEncryptionKey
        : Buffer.from(tokenEncryptionKey, "base64")
      : null;
    if (this.appleProvider && this.tokenEncryptionKey?.length !== 32)
      throw new HostedError(
        "Apple token encryption requires a 32-byte key.",
        "configuration_error",
        503,
      );
  }
  assertConfigured() {
    if (
      typeof this.appleAudience !== "string" ||
      !this.appleAudience ||
      typeof this.apiOrigin !== "string" ||
      !this.apiOrigin
    )
      throw new HostedError(
        "Apple identity is not configured.",
        "configuration_error",
        503,
      );
  }
  async challenge() {
    this.assertConfigured();
    const challengeId = randomUUID(),
      nonce = randomBytes(32).toString("base64url"),
      expiresAt = new Date(this.store.clock() + 300000).toISOString();
    await this.store.pool.query(
      "INSERT INTO gk_auth_challenges(id,nonce_hash,expires_at) VALUES($1,$2,$3)",
      [challengeId, tokenHash(nonce), expiresAt],
    );
    return { challengeId, nonce, expiresAt };
  }
  async verified(token, nonce) {
    required(token, "Identity token", 16384);
    let claims;
    try {
      claims = await this.verifyIdentityToken(token, {
        audience: this.appleAudience,
        issuer,
        nonce,
        currentDate: new Date(this.store.clock()),
      });
    } catch {
      throw invalidIdentity();
    }
    const audiences = Array.isArray(claims?.aud) ? claims.aud : [claims?.aud];
    if (
      claims?.iss !== issuer ||
      !audiences.includes(this.appleAudience) ||
      typeof claims.sub !== "string" ||
      !claims.sub ||
      claims.sub.length > 255 ||
      !Number.isFinite(claims.exp) ||
      claims.exp * 1000 <= this.store.clock() ||
      (nonce !== undefined && claims.nonce !== nonce) ||
      (claims.nbf != null &&
        (!Number.isFinite(claims.nbf) ||
          claims.nbf * 1000 > this.store.clock()))
    )
      throw invalidIdentity();
    return claims;
  }
  encrypt(token) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.tokenEncryptionKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(token, "utf8"),
      cipher.final(),
    ]);
    return [iv, cipher.getAuthTag(), encrypted]
      .map((x) => x.toString("base64url"))
      .join(".");
  }
  decrypt(value) {
    const [iv, tag, encrypted] = value
      .split(".")
      .map((x) => Buffer.from(x, "base64url"));
    const cipher = createDecipheriv("aes-256-gcm", this.tokenEncryptionKey, iv);
    cipher.setAuthTag(tag);
    return Buffer.concat([cipher.update(encrypted), cipher.final()]).toString(
      "utf8",
    );
  }
  async login({
    challengeId,
    identityToken,
    authorizationCode,
    deviceName = "iPhone",
    installationId,
    displayName,
  }) {
    this.assertConfigured();
    required(challengeId, "Challenge ID", 64);
    required(installationId, "Installation ID", 200);
    required(deviceName, "Device name", 200);
    if (displayName != null) required(displayName, "Display name", 200);
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        challengeId,
      )
    )
      throw invalidIdentity();
    const challenge = (
      await this.store.pool.query(
        "SELECT * FROM gk_auth_challenges WHERE id=$1",
        [challengeId],
      )
    ).rows[0];
    if (
      !challenge ||
      challenge.consumed_at ||
      new Date(challenge.expires_at).getTime() <= this.store.clock()
    )
      throw invalidIdentity();
    const claims = await this.verified(identityToken, challenge.nonce_hash);
    let appleToken = null;
    if (this.appleProvider) {
      required(authorizationCode, "Authorization code", 4096);
      let exchanged;
      try {
        exchanged = await this.appleProvider.exchange(authorizationCode);
      } catch (error) {
        if (error instanceof HostedError) throw error;
        throw new HostedError(
          "Apple authentication service is unavailable.",
          "apple_unavailable",
          503,
        );
      }
      if (typeof exchanged.refreshToken !== "string" || !exchanged.refreshToken)
        throw new HostedError(
          "Apple returned an incomplete token response.",
          "apple_auth_failed",
          502,
        );
      if (exchanged.identityToken) {
        const other = await this.verified(
          exchanged.identityToken,
          challenge.nonce_hash,
        );
        if (other.sub !== claims.sub) throw invalidIdentity();
      }
      appleToken = this.encrypt(exchanged.refreshToken);
    }
    const client = await this.store.pool.connect();
    try {
      await client.query("BEGIN");
      const used = (
        await client.query(
          "UPDATE gk_auth_challenges SET consumed_at=$1 WHERE id=$2 AND consumed_at IS NULL AND expires_at>$1 RETURNING id",
          [new Date(this.store.clock()), challengeId],
        )
      ).rows[0];
      if (!used) throw invalidIdentity();
      const user = (
        await client.query(
          `INSERT INTO gk_users(id,apple_sub,display_name,apple_refresh_ciphertext,apple_refresh_client_id,apple_next_check_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(apple_sub) DO UPDATE SET display_name=COALESCE(EXCLUDED.display_name,gk_users.display_name),apple_refresh_ciphertext=COALESCE(EXCLUDED.apple_refresh_ciphertext,gk_users.apple_refresh_ciphertext),apple_refresh_client_id=COALESCE(EXCLUDED.apple_refresh_client_id,gk_users.apple_refresh_client_id),apple_verified_at=CASE WHEN EXCLUDED.apple_refresh_ciphertext IS NOT NULL AND gk_users.apple_authorization_revoked_at IS NOT NULL THEN NULL ELSE gk_users.apple_verified_at END,apple_next_check_at=CASE WHEN EXCLUDED.apple_refresh_ciphertext IS NOT NULL THEN COALESCE(gk_users.apple_verified_at + INTERVAL '1 day',EXCLUDED.apple_next_check_at) ELSE gk_users.apple_next_check_at END,apple_check_lease_token=CASE WHEN EXCLUDED.apple_refresh_ciphertext IS NOT NULL THEN NULL ELSE gk_users.apple_check_lease_token END,apple_check_lease_until=CASE WHEN EXCLUDED.apple_refresh_ciphertext IS NOT NULL THEN NULL ELSE gk_users.apple_check_lease_until END,apple_check_attempts=CASE WHEN EXCLUDED.apple_refresh_ciphertext IS NOT NULL THEN 0 ELSE gk_users.apple_check_attempts END,apple_authorization_revoked_at=CASE WHEN EXCLUDED.apple_refresh_ciphertext IS NOT NULL THEN NULL ELSE gk_users.apple_authorization_revoked_at END RETURNING *`,
          [
            randomUUID(),
            claims.sub,
            displayName ?? null,
            appleToken,
            appleToken ? this.appleAudience : null,
            appleToken ? new Date(this.store.clock()) : null,
          ],
        )
      ).rows[0];
      await client.query("SELECT id FROM gk_users WHERE id=$1 FOR UPDATE", [
        user.id,
      ]);
      if (this.purchaseBindingKey) {
        const token = purchaseAccountToken(this.purchaseBindingKey, this.appleAudience, claims.sub);
        if (user.purchase_account_token && user.purchase_account_token !== token)
          throw new Error("Purchase binding key changed; authenticated migration is required");
        await client.query("UPDATE gk_users SET purchase_account_token=$1 WHERE id=$2", [token, user.id]);
        user.purchase_account_token = token;
      }
      const device = await this.store.registerDeviceInTransaction(
        client,
        user.id,
        { installationId, name: deviceName },
      );
      const session = await this.store.createSessionInTransaction(
        client,
        user.id,
        { deviceId: device.id },
      );
      await client.query("COMMIT");
      return this.sessionView(this.store.userView(user), session, device);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  sessionView(user, session, device) {
    return {
      user,
      accountToken: session.accountToken,
      refreshToken: session.refreshToken,
      expiresAt: session.expiresAt,
      device,
      apiOrigin: this.apiOrigin,
    };
  }
  async refresh(refreshToken) {
    this.assertConfigured();
    const row = await this.store.refreshSession(
      refreshToken,
      "account",
      (client, user) => this.validateAppleAuthorization(client, user),
    );
    if (row.kind !== "account" || !row.device)
      throw new HostedError(
        "Account session is required.",
        "unauthorized",
        401,
      );
    const account = await this.store.account(row.userId);
    return this.sessionView(account.user, row, row.device);
  }
  async validateAppleAuthorization(client, user) {
    try {
      return await this.performAppleAuthorizationCheck(client, user);
    } catch (error) {
      await this.deferAppleCheck(client, user);
      return error instanceof HostedError && error.status === 503
        ? error
        : new HostedError(
            "Apple authorization verification is unavailable. Please retry.",
            "apple_unavailable",
            503,
          );
    }
  }
  async deferAppleCheck(client, user) {
    const now = this.store.clock();
    if (
      user.apple_check_attempts > 0 &&
      new Date(user.apple_next_check_at).getTime() > now
    )
      return;
    const attempts = Math.min(20, (user.apple_check_attempts ?? 0) + 1);
    const delay = Math.min(
      6 * 3600000,
      60000 * 2 ** Math.min(attempts - 1, 12),
    );
    await client.query(
      "UPDATE gk_users SET apple_next_check_at=$1,apple_check_attempts=$2,apple_check_lease_token=NULL,apple_check_lease_until=NULL WHERE id=$3",
      [new Date(now + delay), attempts, user.id],
    );
  }
  async performAppleAuthorizationCheck(client, user) {
    if (user.apple_authorization_revoked_at)
      return new HostedError(
        "Apple authorization is no longer valid. Sign in again.",
        "apple_authorization_revoked",
        401,
      );
    if (!this.appleProvider && !user.apple_refresh_ciphertext) return;
    if (
      !this.appleProvider ||
      typeof this.appleProvider.refresh !== "function" ||
      this.tokenEncryptionKey?.length !== 32 ||
      !user.apple_refresh_ciphertext ||
      user.apple_refresh_client_id !== this.appleAudience ||
      (this.appleProvider.clientId &&
        this.appleProvider.clientId !== this.appleAudience)
    )
      throw new HostedError(
        "Apple authorization validation is not configured for this account. Sign in again after configuration is restored.",
        "configuration_error",
        503,
      );
    let token;
    try {
      token = this.decrypt(user.apple_refresh_ciphertext);
    } catch {
      throw new HostedError(
        "Apple authorization encryption key is unavailable.",
        "configuration_error",
        503,
      );
    }
    const now = this.store.clock();
    const checked =
      user.apple_verified_at == null
        ? NaN
        : new Date(user.apple_verified_at).getTime();
    // Apple's server may throttle checks made more than once per day.
    if (
      Number.isFinite(checked) &&
      checked <= now &&
      now - checked < 86400000
    ) {
      if (
        user.apple_check_lease_token ||
        new Date(user.apple_next_check_at).getTime() !== checked + 86400000
      )
        await client.query(
          "UPDATE gk_users SET apple_next_check_at=$1,apple_check_attempts=0,apple_check_lease_token=NULL,apple_check_lease_until=NULL WHERE id=$2",
          [new Date(checked + 86400000), user.id],
        );
      return;
    }
    if (
      user.apple_check_attempts > 0 &&
      new Date(user.apple_next_check_at).getTime() > now
    )
      throw new HostedError(
        "Apple authorization verification is waiting to retry.",
        "apple_unavailable",
        503,
      );
    let value;
    try {
      value = await this.appleProvider.refresh(token);
    } catch (error) {
      if (
        error instanceof AppleTokenError &&
        error.authoritativeRevocation &&
        error.appleError === "invalid_grant"
      ) {
        const date = new Date(this.store.clock());
        const devices = (
          await client.query(
            "SELECT id FROM gk_devices WHERE user_id=$1 AND revoked_at IS NULL",
            [user.id],
          )
        ).rows;
        for (const device of devices)
          await this.store.enqueue(client, user.id, device.id, "end", null);
        await client.query(
          "UPDATE gk_devices SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL",
          [date, user.id],
        );
        await client.query(
          "UPDATE gk_grants SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL",
          [date, user.id],
        );
        await client.query(
          "UPDATE gk_sessions SET revoked_at=$1 WHERE user_id=$2",
          [date, user.id],
        );
        const table = (
          await client.query(
            "SELECT to_regclass('gk_oauth_connections') AS connections,to_regclass('gk_oauth_tokens') AS tokens",
          )
        ).rows[0];
        if (table.connections)
          await client.query(
            "UPDATE gk_oauth_connections SET revoked_at=$1 WHERE user_id=$2",
            [date, user.id],
          );
        if (table.tokens)
          await client.query(
            "UPDATE gk_oauth_tokens SET revoked_at=$1 WHERE user_id=$2",
            [date, user.id],
          );
        await client.query(
          "UPDATE gk_users SET apple_verified_at=NULL,apple_authorization_revoked_at=$1,apple_next_check_at=NULL,apple_check_lease_token=NULL,apple_check_lease_until=NULL,apple_check_attempts=0 WHERE id=$2",
          [date, user.id],
        );
        return new HostedError(
          "Apple authorization is no longer valid. Sign in again.",
          "apple_authorization_revoked",
          401,
        );
      }
      throw new HostedError(
        "Apple authorization verification is unavailable. Please retry.",
        "apple_unavailable",
        503,
      );
    }
    let claims;
    try {
      claims = await this.verified(value?.identityToken);
    } catch {
      throw new HostedError(
        "Apple returned an invalid refreshed identity.",
        "apple_unavailable",
        503,
      );
    }
    if (claims.sub !== user.apple_sub)
      throw new HostedError(
        "Apple returned an identity for another account.",
        "apple_unavailable",
        503,
      );
    if (
      value.refreshToken != null &&
      (typeof value.refreshToken !== "string" || !value.refreshToken)
    )
      throw new HostedError(
        "Apple returned an invalid refresh token.",
        "apple_unavailable",
        503,
      );
    await client.query(
      "UPDATE gk_users SET apple_verified_at=$1,apple_refresh_ciphertext=COALESCE($2,apple_refresh_ciphertext),apple_next_check_at=$4,apple_check_attempts=0,apple_check_lease_token=NULL,apple_check_lease_until=NULL WHERE id=$3",
      [
        new Date(this.store.clock()),
        value.refreshToken ? this.encrypt(value.refreshToken) : null,
        user.id,
        new Date(this.store.clock() + 86400000),
      ],
    );
  }
  async sweepAppleAuthorizations({ limit = 20 } = {}) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 20)
      throw new HostedError(
        "Apple sweep limit must be a whole number from 1 through 20.",
      );
    const configured = Boolean(
      this.appleProvider &&
        typeof this.appleProvider.refresh === "function" &&
        this.tokenEncryptionKey?.length === 32 &&
        this.appleAudience,
    );
    const result = {
      configured,
      claimed: 0,
      checked: 0,
      revoked: 0,
      retried: 0,
      skipped: 0,
    };
    if (!configured) return result;
    const now = this.store.clock(),
      lease = randomUUID();
    const claims = (
      await this.store.pool.query(
        `WITH due AS (
      SELECT id FROM gk_users WHERE apple_refresh_ciphertext IS NOT NULL
       AND apple_authorization_revoked_at IS NULL AND apple_next_check_at<=$1
       AND (apple_check_lease_until IS NULL OR apple_check_lease_until<=$1)
       ORDER BY apple_next_check_at,id FOR UPDATE SKIP LOCKED LIMIT $2
     ) UPDATE gk_users u SET apple_check_lease_token=$3,apple_check_lease_until=$4
       FROM due WHERE u.id=due.id RETURNING u.id,u.apple_check_lease_token`,
        [new Date(now), limit, lease, new Date(now + 300000)],
      )
    ).rows;
    result.claimed = claims.length;
    for (const claim of claims) {
      try {
        const status = await this.store.withUserLock(
          claim.id,
          async (client, user) => {
            if (
              user.apple_check_lease_token !== claim.apple_check_lease_token ||
              new Date(user.apple_check_lease_until).getTime() <=
                this.store.clock()
            )
              return "skipped";
            const error = await this.validateAppleAuthorization(client, user);
            return error?.status === 401
              ? "revoked"
              : error
                ? "retried"
                : "checked";
          },
        );
        result[status]++;
      } catch (error) {
        if (error.code === "not_found") result.skipped++;
        else throw error; // A database failure leaves an expiring claim for recovery.
      }
    }
    return result;
  }
  async delete(userId) {
    return this.store.withUserLock(userId, async (client, user) => {
      if (user.apple_refresh_ciphertext) {
        if (!this.appleProvider || !this.tokenEncryptionKey)
          throw new HostedError(
            "Apple revocation is not configured.",
            "configuration_error",
            503,
          );
        try {
          await this.appleProvider.revoke(
            this.decrypt(user.apple_refresh_ciphertext),
          );
        } catch {
          throw new HostedError(
            "Apple revocation is unavailable. Please retry account deletion.",
            "apple_unavailable",
            503,
          );
        }
      }
      await client.query("DELETE FROM gk_users WHERE id=$1", [userId]);
      return { deleted: true };
    });
  }
}
