import express from "express";
import { z } from "zod";
import { HostedError } from "./errors.js";
import { publicDocuments } from "./public-documents.js";
import { CONSENT_VERSION } from "./conversation.js";
const uuid = z.string().uuid();
function body(schema, req) {
  const value = schema.safeParse(req.body);
  if (!value.success)
    throw new HostedError("Invalid request body.", "invalid_request", 400);
  return value.data;
}
const bearer = (req) =>
  /^Bearer ([^\s]+)$/.exec(req.headers.authorization ?? "")?.[1];
export function createHostedApp({
  store,
  identity,
  conversation,
  billing,
  publicOrigin,
  coach,
  oauth,
  readiness,
  supportEmail,
  rateLimit,
}) {
  const origin = new URL(publicOrigin);
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  const invoke = (fn) => async (req, res, next) => {
    try {
      await fn(req, res);
    } catch (e) {
      next(e);
    }
  };
  app.use((req, res, next) => {
    res.set({
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    });
    const healthHost =
      req.method === "GET" &&
      req.path === "/health" &&
      req.headers.host === "healthcheck.railway.app";
    if (!healthHost && req.headers.host !== origin.host)
      return res.sendStatus(403);
    const browserAgent =
      req.path === "/mcp" ||
      req.path.startsWith("/.well-known/") ||
      ["/authorize", "/token", "/register", "/revoke"].includes(req.path) ||
      req.path.startsWith("/oauth/");
    if (
      req.headers.origin &&
      !browserAgent &&
      req.headers.origin !== origin.origin
    )
      return res.sendStatus(403);
    next();
  });
  app.get("/health", (_req, res) => res.json({ status: "ok" }));
  app.get(
    "/ready",
    invoke(async (_req, res) => {
      await store.pool.query("SELECT 1");
      const checks = readiness
        ? await readiness()
        : { database: true, coach: coach?.configured !== false };
      const ready = Object.values(checks).every(Boolean);
      res
        .status(ready ? 200 : 503)
        .json({ status: ready ? "ready" : "configuration_required", checks });
    }),
  );
  publicDocuments(app, supportEmail);
  if (rateLimit)
    app.use(async (req, res, next) => {
      try {
        await rateLimit.consume(req);
        next();
      } catch (error) {
        if (error.status === 429) res.set("Retry-After", "60");
        next(error);
      }
    });
  app.use(express.json({ limit: "64kb" }));
  if (oauth) app.use(oauth.router());
  const authenticate = (kind) => async (req, res, next) => {
    try {
      req.principal = await store.authenticate(bearer(req), kind);
      next();
    } catch (e) {
      next(e);
    }
  };
  const accountAuth = authenticate("account"),
    deviceAuth = authenticate("device");
  app.post(
    "/v1/auth/challenge",
    invoke(async (_req, res) => res.json(await identity.challenge())),
  );
  app.post(
    "/v1/auth/apple",
    invoke(async (req, res) =>
      res.json(
        await identity.login(
          body(
            z
              .object({
                challengeId: uuid,
                identityToken: z.string().min(1).max(16000),
                authorizationCode: z.string().max(4000).optional(),
                deviceName: z.string().min(1).max(200),
                installationId: z.string().min(1).max(200),
                displayName: z.string().max(200).optional(),
              })
              .strict(),
            req,
          ),
        ),
      ),
    ),
  );
  app.post(
    "/v1/auth/refresh",
    invoke(async (req, res) =>
      res.json(
        await identity.refresh(
          body(
            z.object({ refreshToken: z.string().min(20).max(512) }).strict(),
            req,
          ).refreshToken,
        ),
      ),
    ),
  );
  app.use("/v1/account", accountAuth);
  app.use("/v1/devices", accountAuth);
  app.use("/v1/conversation", accountAuth);
  app.use("/v1/access", accountAuth);
  app.use("/v1/agents", accountAuth);
  app.get(
    "/v1/account",
    invoke(async (req, res) =>
      res.json({
        ...(await store.account(req.principal.userId)),
        entitlement: await billing.entitlement(req.principal.userId),
      }),
    ),
  );
  app.delete(
    "/v1/account",
    invoke(async (req, res) =>
      res.json(
        typeof identity.delete === "function"
          ? await identity.delete(req.principal.userId)
          : await store.deleteAccount(req.principal.userId),
      ),
    ),
  );
  app.post(
    "/v1/account/consent",
    invoke(async (req, res) => {
      body(z.object({ version: z.literal(CONSENT_VERSION) }).strict(), req);
      res.json(await store.setConsent(req.principal.userId, CONSENT_VERSION));
    }),
  );
  app.delete(
    "/v1/account/consent",
    invoke(async (req, res) =>
      res.json(
        await store.withUserLock(req.principal.userId, async (c) => {
          await c.query(
            "UPDATE gk_users SET consent_version=NULL WHERE id=$1",
            [req.principal.userId],
          );
          await c.query(
            "UPDATE gk_exchanges SET status='cleared',response=NULL,lease_until=NULL WHERE user_id=$1 AND status='working'",
            [req.principal.userId],
          );
          return { received: true };
        }),
      ),
    ),
  );
  app.get(
    "/v1/devices",
    invoke(async (req, res) =>
      res.json({ devices: await store.listDevices(req.principal.userId) }),
    ),
  );
  app.delete(
    "/v1/devices/:id",
    invoke(async (req, res) =>
      res.json(
        await store.revokeDevice(
          req.principal.userId,
          uuid.parse(req.params.id),
        ),
      ),
    ),
  );
  app.get(
    "/v1/conversation",
    invoke(async (req, res) =>
      res.json(await conversation.history(req.principal.userId)),
    ),
  );
  app.delete(
    "/v1/conversation",
    invoke(async (req, res) =>
      res.json(await conversation.clear(req.principal.userId)),
    ),
  );
  app.post(
    "/v1/conversation",
    invoke(async (req, res) =>
      res.json(await conversation.respond(req.principal.userId, req.body)),
    ),
  );
  app.post(
    "/v1/access/end",
    invoke(async (req, res) =>
      res.json(
        await store.endAccess(
          req.principal.userId,
          body(z.object({ deviceId: uuid }).strict(), req).deviceId,
        ),
      ),
    ),
  );
  app.get("/v1/billing/products", accountAuth, (_req, res) =>
    res.json(billing.products()),
  );
  app.post(
    "/v1/billing/transaction",
    accountAuth,
    invoke(async (req, res) =>
      res.json(
        await billing.recordTransaction(
          req.principal.userId,
          body(
            z
              .object({ signedTransaction: z.string().min(1).max(60000) })
              .strict(),
            req,
          ).signedTransaction,
        ),
      ),
    ),
  );
  app.post(
    "/v1/billing/notifications",
    invoke(async (req, res) =>
      res.json(
        await billing.handleNotification(
          body(
            z.object({ signedPayload: z.string().min(1).max(60000) }).strict(),
            req,
          ).signedPayload,
        ),
      ),
    ),
  );
  if (oauth) {
    app.get(
      "/v1/agents",
      invoke(async (req, res) =>
        res.json({
          connections: await oauth.connections(req.principal.userId),
        }),
      ),
    );
    app.delete(
      "/v1/agents/:id",
      invoke(async (req, res) =>
        res.json(
          await oauth.disconnect(
            req.principal.userId,
            uuid.parse(req.params.id),
          ),
        ),
      ),
    );
    app.get(
      "/v1/agents/requests/:id",
      invoke(async (req, res) =>
        res.json(await oauth.request(uuid.parse(req.params.id))),
      ),
    );
    app.post(
      "/v1/agents/requests/:id/decision",
      invoke(async (req, res) =>
        res.json(
          await oauth.decide(
            req.principal.userId,
            uuid.parse(req.params.id),
            body(z.object({ approve: z.boolean() }).strict(), req).approve,
          ),
        ),
      ),
    );
  }
  app.use("/device", deviceAuth);
  app.get(
    "/device/state",
    invoke(async (req, res) =>
      res.json(
        await store.deviceState(req.principal.userId, req.principal.deviceId),
      ),
    ),
  );
  app.post(
    "/device/redeem",
    invoke(async (req, res) =>
      res.json(
        await store.redeem(
          req.principal.userId,
          req.principal.deviceId,
          body(z.object({ grantId: uuid }).strict(), req).grantId,
        ),
      ),
    ),
  );
  app.post(
    "/device/report",
    invoke(async (req, res) =>
      res.json(
        await store.report(
          req.principal.userId,
          req.principal.deviceId,
          body(
            z
              .object({
                state: z.enum([
                  "shielded",
                  "window_open",
                  "permission_missing",
                  "selection_missing",
                ]),
                grantId: uuid.nullable().optional(),
                localExpiry: z.string().datetime().nullable().optional(),
              })
              .strict(),
            req,
          ),
        ),
      ),
    ),
  );
  app.post(
    "/device/push",
    invoke(async (req, res) =>
      res.json(
        await store.registerPush(
          req.principal.userId,
          req.principal.deviceId,
          body(
            z
              .object({
                token: z.string().regex(/^[a-f0-9]{64,200}$/i),
                environment: z.enum(["sandbox", "production"]),
              })
              .strict(),
            req,
          ),
        ),
      ),
    ),
  );
  app.use((_req, res) =>
    res.status(404).json({ error: "Endpoint not found.", code: "not_found" }),
  );
  app.use((error, _req, res, _next) => {
    if (
      error instanceof z.ZodError ||
      error instanceof SyntaxError ||
      error.type === "entity.too.large"
    )
      return res
        .status(400)
        .json({ error: "Invalid request body.", code: "invalid_request" });
    const status =
      Number.isInteger(error.status) &&
      error.status >= 400 &&
      error.status < 600
        ? error.status
        : 500;
    res
      .status(status)
      .json({
        error: status === 500 ? "Request failed." : error.message,
        code: error.code ?? "request_failed",
      });
  });
  return app;
}
