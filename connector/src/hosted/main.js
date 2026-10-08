import pg from "pg";
import { importPKCS8, SignJWT } from "jose";
import { HostedStore } from "./store.js";
import { HostedIdentity } from "./identity.js";
import { HostedBilling } from "./billing.js";
import { HostedCoach } from "./coach.js";
import { HostedConversation } from "./conversation.js";
import { HostedOAuth } from "./oauth.js";
import { HostedPushWorker } from "./push-worker.js";
import { createHostedApp } from "./app.js";
import { hostedConfiguration } from "./config.js";
import { HostedRateLimit } from "./rate-limit.js";
import { createHostedAPNs } from "./apns.js";
const config = hostedConfiguration();
const pool = new pg.Pool({
  connectionString: config.databaseURL,
  max: 10,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  query_timeout: 15000,
  application_name: "rook-hosted",
});
pool.on("error", () => console.error("Database connection unavailable."));
const store = new HostedStore(pool);
await store.migrate();
let appleClientSecret = config.appleClientSecret;
if (!appleClientSecret && config.appleExchangeConfigured) {
  const key = await importPKCS8(
    config.applePrivateKey.replace(/\\n/g, "\n"),
    "ES256",
  );
  appleClientSecret = () =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: config.appleKeyId })
      .setIssuer(config.appleTeamId)
      .setSubject(config.appleAudience)
      .setAudience("https://appleid.apple.com")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(key);
}
const identity = new HostedIdentity({
  store,
  apiOrigin: config.publicOrigin,
  appleAudience: config.appleAudience,
  appleClientSecret,
  tokenEncryptionKey: config.encryptionKey,
});
const billing = new HostedBilling({
  pool,
  bundleId: config.bundleId,
  appAppleId: config.appAppleId,
  environment: config.storeEnvironment,
  productIds: config.productIds,
  betaAccess: config.betaAccess,
});
await billing.init();
const coach = new HostedCoach({ apiKey: config.aiKey, model: config.aiModel });
const conversation = new HostedConversation({
  store,
  coach,
  billing,
  perDay: config.perDay,
  perMinute: config.perMinute,
  globalPerDay: config.globalPerDay,
});
await conversation.init();
const oauth = new HostedOAuth({
  store,
  billing,
  publicOrigin: config.publicOrigin,
  encryptionKey: config.encryptionKey,
});
await oauth.init();
const pushSender = createHostedAPNs();
const push = new HostedPushWorker({ store, send: pushSender });
await push.init();
const rateLimit = new HostedRateLimit({ pool, key: config.encryptionKey });
await rateLimit.init();
const app = createHostedApp({
  store,
  identity,
  conversation,
  billing,
  coach,
  oauth,
  rateLimit,
  supportEmail: config.supportEmail,
  publicOrigin: config.publicOrigin,
  readiness: () => ({
    database: true,
    coach: coach.configured,
    appleIdentity: Boolean(config.appleAudience),
    appleRevocation: config.appleExchangeConfigured,
    supportContact: Boolean(config.supportEmail),
    productionPush: Boolean(pushSender?.configured.production),
    billing: config.betaAccess || !billing.configurationError,
  }),
});
await Promise.all([
  store.pruneHistory(),
  conversation.prune(),
  rateLimit.prune(),
  oauth.prune(),
]);
const server = app.listen(config.port, config.host, () =>
  console.log(
    "Rook hosted API started. Credentials and request content are not logged.",
  ),
);
server.requestTimeout = 30000;
server.headersTimeout = 10000;
let checkingAppleAuthorizations = false;
async function checkAppleAuthorizations() {
  if (checkingAppleAuthorizations) return;
  checkingAppleAuthorizations = true;
  try {
    await identity.sweepAppleAuthorizations();
  } catch {
    console.error("Apple authorization checks will retry.");
  } finally {
    checkingAppleAuthorizations = false;
  }
}
void checkAppleAuthorizations();
const appleAuthorizations = setInterval(() => {
  void checkAppleAuthorizations();
}, 60000);
const worker = setInterval(() => {
  void push.tick().catch(() => console.error("Push worker will retry."));
}, 5000);
const retention = setInterval(() => {
  void Promise.all([
    store.pruneHistory(),
    conversation.prune(),
    rateLimit.prune(),
    oauth.prune(),
  ]).catch(() => console.error("Retention worker will retry."));
}, 3600000);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => {
    clearInterval(worker);
    clearInterval(appleAuthorizations);
    clearInterval(retention);
    server.close(() => {
      void pool.end().then(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 20000).unref();
  });
