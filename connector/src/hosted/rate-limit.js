import { createHmac } from "node:crypto";
import { HostedError } from "./errors.js";
// Shared across replicas. Retain keyed digests briefly, never raw IP addresses.
export class HostedRateLimit {
  constructor({ pool, key, limit = 120, clock = () => Date.now() }) {
    this.pool = pool;
    this.key = key;
    this.limit = limit;
    this.clock = clock;
  }
  async init() {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      await c.query(
        "SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('gatekeeper-http-migration'))",
      );
      await c.query(
        "CREATE TABLE IF NOT EXISTS gk_http_limits(subject text NOT NULL,window_start timestamptz NOT NULL,count integer NOT NULL,PRIMARY KEY(subject,window_start))",
      );
      await c.query(
        "CREATE INDEX IF NOT EXISTS gk_http_limits_expiry ON gk_http_limits(window_start)",
      );
      await c.query("COMMIT");
    } catch (error) {
      await c.query("ROLLBACK");
      throw error;
    } finally {
      c.release();
    }
  }
  async consume(req) {
    if (!["POST", "DELETE"].includes(req.method)) return;
    if (
      !req.path.startsWith("/v1/auth/") &&
      ![
        "/register",
        "/token",
        "/revoke",
        "/authorize",
        "/v1/billing/notifications",
      ].includes(req.path)
    )
      return;
    const subject = createHmac("sha256", this.key)
      .update(req.ip ?? "unknown")
      .digest("hex");
    const window = new Date(Math.floor(this.clock() / 60000) * 60000);
    const r = await this.pool.query(
      "INSERT INTO gk_http_limits(subject,window_start,count) VALUES($1,$2,1) ON CONFLICT(subject,window_start) DO UPDATE SET count=gk_http_limits.count+1 WHERE gk_http_limits.count<$3 RETURNING count",
      [subject, window, this.limit],
    );
    if (!r.rowCount)
      throw new HostedError(
        "Too many requests. Try again in a minute.",
        "rate_limit",
        429,
      );
  }
  async prune() {
    await this.pool.query(
      "DELETE FROM gk_http_limits WHERE window_start<NOW()-INTERVAL '1 day'",
    );
  }
}
