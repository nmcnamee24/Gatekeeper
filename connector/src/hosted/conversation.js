import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { HostedError } from "./errors.js";
export const CONSENT_VERSION = "2026-10-08-openai-v1";
const requestSchema = z
  .object({
    requestId: z.string().uuid(),
    message: z.string().trim().min(1).max(1000),
    durationMinutes: z.number().int().min(1).max(15),
    deviceId: z.string().uuid(),
  })
  .strict();
const hash = (input) =>
  createHash("sha256").update(JSON.stringify(input)).digest("hex");
export class HostedConversation {
  constructor({
    store,
    coach,
    billing,
    perDay = 20,
    perMinute = 5,
    globalPerDay = 500,
    clock = () => Date.now(),
  }) {
    this.store = store;
    this.coach = coach;
    this.billing = billing;
    this.perDay = perDay;
    this.perMinute = perMinute;
    this.globalPerDay = globalPerDay;
    this.clock = clock;
    for (const count of [perDay, perMinute, globalPerDay])
      if (!Number.isInteger(count) || count < 1 || count > 100000)
        throw new Error("Invalid AI request budget");
  }
  async init() {
    const c = await this.store.pool.connect();
    try {
      await c.query("BEGIN");
      await c.query(
        "SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('gatekeeper-conversation-migration'))",
      );
      await c.query(`CREATE TABLE IF NOT EXISTS gk_messages(id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,role text NOT NULL CHECK(role IN ('user','assistant')),content text NOT NULL,created_at timestamptz NOT NULL);
    CREATE INDEX IF NOT EXISTS gk_messages_user_time ON gk_messages(user_id,created_at);
    CREATE TABLE IF NOT EXISTS gk_exchanges(user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,request_id uuid NOT NULL,request_hash text NOT NULL,status text NOT NULL,lease_token uuid,lease_until timestamptz,response jsonb,created_at timestamptz NOT NULL,PRIMARY KEY(user_id,request_id));
    CREATE TABLE IF NOT EXISTS gk_ai_usage(subject text NOT NULL,bucket text NOT NULL,window_start timestamptz NOT NULL,count integer NOT NULL,user_id uuid REFERENCES gk_users(id) ON DELETE CASCADE,PRIMARY KEY(subject,bucket,window_start));
    ALTER TABLE gk_ai_usage ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES gk_users(id) ON DELETE CASCADE;
    UPDATE gk_ai_usage SET user_id=gk_users.id FROM gk_users WHERE subject=gk_users.id::text AND gk_ai_usage.user_id IS NULL;`);
      await c.query("COMMIT");
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
  }
  async reserveBudget(c, userId, now) {
    await c.query(
      "SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('gatekeeper-ai-budget'))",
    );
    for (const [subject, bucket, span, limit] of [
      [userId, "day", 86400000, this.perDay],
      [userId, "minute", 60000, this.perMinute],
      ["global", "day", 86400000, this.globalPerDay],
    ]) {
      const start = new Date(Math.floor(now / span) * span);
      const row = (
        await c.query(
          `INSERT INTO gk_ai_usage(subject,bucket,window_start,count,user_id) VALUES($1,$2,$3,1,$5) ON CONFLICT(subject,bucket,window_start) DO UPDATE SET count=gk_ai_usage.count+1 WHERE gk_ai_usage.count<$4 RETURNING count`,
          [subject, bucket, start, limit, subject === "global" ? null : userId],
        )
      ).rows[0];
      if (!row)
        throw new HostedError(
          "Conversation usage limit reached. Try again later.",
          "usage_limit",
          429,
        );
    }
  }
  async respond(userId, raw) {
    const parsed = requestSchema.safeParse(raw);
    if (!parsed.success)
      throw new HostedError(
        "Use a message and a duration from 1 through 15 whole minutes.",
        "invalid_conversation",
        400,
      );
    const input = parsed.data;
    if (this.coach.configured === false)
      throw new HostedError(
        "The in-app coach is not configured yet. Apps remain protected.",
        "coach_unavailable",
        503,
      );
    await this.billing?.requireAccess(userId);
    const now = this.clock(),
      lease = randomUUID();
    const reserved = await this.store.withUserLock(userId, async (c, user) => {
      if (user.consent_version !== CONSENT_VERSION)
        throw new HostedError(
          "Accept AI processing consent before talking to Rook.",
          "consent_required",
          403,
        );
      await this.store.device(c, userId, input.deviceId);
      const existing = (
        await c.query(
          "SELECT * FROM gk_exchanges WHERE user_id=$1 AND request_id=$2",
          [userId, input.requestId],
        )
      ).rows[0];
      if (existing) {
        if (existing.request_hash !== hash(input))
          throw new HostedError(
            "This request ID belongs to a different conversation request.",
            "request_conflict",
            409,
          );
        if (existing.status === "complete")
          return { cached: existing.response };
        if (existing.status === "cleared")
          throw new HostedError(
            "This conversation was cleared. Start a new request.",
            "request_cleared",
            409,
          );
      }
      const running = (
        await c.query(
          "SELECT request_id FROM gk_exchanges WHERE user_id=$1 AND status='working' AND lease_until>$2",
          [userId, new Date(now)],
        )
      ).rows[0];
      if (running)
        throw new HostedError(
          "A conversation request is already in progress.",
          "request_in_progress",
          409,
        );
      await this.reserveBudget(c, userId, now);
      await c.query(
        `INSERT INTO gk_exchanges(user_id,request_id,request_hash,status,lease_token,lease_until,created_at) VALUES($1,$2,$3,'working',$4,$5,$6) ON CONFLICT(user_id,request_id) DO UPDATE SET status='working',lease_token=EXCLUDED.lease_token,lease_until=EXCLUDED.lease_until`, // gitleaks:allow -- SQL column references contain no credential.
        [
          userId,
          input.requestId,
          hash(input),
          lease,
          new Date(now + 45000),
          new Date(now),
        ],
      );
      return {};
    });
    if (reserved.cached) return reserved.cached;
    try {
      const status = await this.store.status(userId, input.deviceId);
      const history = await this.context(userId);
      const decision = await this.coach.judge({
        message: input.message,
        durationMinutes: input.durationMinutes,
        history,
        status,
      });
      return await this.store.withUserLock(userId, async (c, user) => {
        const row = (
          await c.query(
            "SELECT * FROM gk_exchanges WHERE user_id=$1 AND request_id=$2",
            [userId, input.requestId],
          )
        ).rows[0];
        if (
          !row ||
          row.status !== "working" ||
          row.lease_token !== lease ||
          new Date(row.lease_until).getTime() <= this.clock()
        )
          throw new HostedError(
            "The conversation expired or was cleared. Start a new request.",
            "request_expired",
            409,
          );
        if (user.consent_version !== CONSENT_VERSION)
          throw new HostedError(
            "AI processing consent changed.",
            "consent_required",
            403,
          );
        let response = { reply: decision.reply, decision: decision.decision };
        if (decision.decision === "approve") {
          if (
            !Number.isInteger(decision.durationMinutes) ||
            decision.durationMinutes < 1 ||
            decision.durationMinutes > input.durationMinutes
          )
            throw new HostedError(
              "Invalid approved duration. Apps remain protected.",
              "invalid_coach_decision",
              503,
            );
          const approval = await this.store.approveInTransaction(c, user, {
            requestId: input.requestId,
            purpose: decision.purpose,
            exitPlan: decision.exitPlan,
            durationMinutes: decision.durationMinutes,
            deviceId: input.deviceId,
          });
          response = {
            decision: "approve",
            reply: `Approved for ${decision.durationMinutes} ${decision.durationMinutes === 1 ? "minute" : "minutes"}. Your phone must redeem the pass and confirm access; an approval alone does not unlock apps.`,
            approval,
          };
        } else if (!["ask", "deny"].includes(decision.decision))
          throw new HostedError(
            "Invalid coach decision.",
            "invalid_coach_decision",
            503,
          );
        const date = new Date(this.clock());
        await c.query(
          "INSERT INTO gk_messages(id,user_id,role,content,created_at) VALUES($1,$2,$3,$4,$5),($6,$2,$7,$8,$9)",
          [
            randomUUID(),
            userId,
            "user",
            input.message,
            date,
            randomUUID(),
            "assistant",
            response.reply,
            new Date(date.getTime() + 1),
          ],
        );
        await c.query(
          "UPDATE gk_exchanges SET status='complete',response=$1,lease_until=NULL WHERE user_id=$2 AND request_id=$3",
          [response, userId, input.requestId],
        );
        return response;
      });
    } catch (error) {
      await this.store.pool.query(
        "UPDATE gk_exchanges SET status='failed',lease_until=NULL WHERE user_id=$1 AND request_id=$2 AND lease_token=$3 AND status='working'",
        [userId, input.requestId, lease],
      );
      throw error;
    }
  }
  async history(userId) {
    return {
      messages: (
        await this.store.pool.query(
          "SELECT id,role,content,created_at FROM gk_messages WHERE user_id=$1 AND created_at>NOW()-INTERVAL '30 days' ORDER BY created_at DESC LIMIT 100",
          [userId],
        )
      ).rows
        .reverse()
        .map((r) => ({
          id: r.id,
          role: r.role,
          content: r.content,
          createdAt: r.created_at.toISOString(),
        })),
    };
  }
  async context(userId) {
    return (
      await this.store.pool.query(
        "SELECT role,content FROM gk_messages WHERE user_id=$1 AND created_at>NOW()-INTERVAL '30 days' ORDER BY created_at DESC LIMIT 12",
        [userId],
      )
    ).rows.reverse();
  }
  async clear(userId) {
    return this.store.withUserLock(userId, async (c) => {
      await c.query("DELETE FROM gk_messages WHERE user_id=$1", [userId]);
      await c.query(
        "UPDATE gk_exchanges SET response=NULL,status='cleared',lease_until=NULL WHERE user_id=$1",
        [userId],
      );
      await c.query(
        "UPDATE gk_grants SET purpose='',exit_plan='' WHERE user_id=$1 AND (purpose<>'' OR exit_plan<>'')",
        [userId],
      );
      return { deleted: true };
    });
  }
  async prune() {
    await this.store.pool.query(
      "DELETE FROM gk_messages WHERE created_at<NOW()-INTERVAL '30 days'",
    );
    await this.store.pool.query(
      "UPDATE gk_exchanges SET response=NULL,status='cleared',lease_until=NULL WHERE created_at<NOW()-INTERVAL '30 days' AND status<>'cleared'",
    );
    await this.store.pool.query(
      "DELETE FROM gk_ai_usage WHERE window_start<NOW()-INTERVAL '2 days'",
    );
  }
}
