function integer(value, fallback, max = 100000) {
  const n = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max)
    throw new Error("Invalid positive configuration limit");
  return n;
}
export function hostedConfiguration(env = process.env) {
  if (!env.DATABASE_URL) throw new Error("DATABASE_URL is required");
  const db = new URL(env.DATABASE_URL);
  if (!["postgres:", "postgresql:"].includes(db.protocol))
    throw new Error("DATABASE_URL must use PostgreSQL");
  const origin = new URL(env.PUBLIC_ORIGIN ?? "");
  if (
    origin.protocol !== "https:" &&
    !["127.0.0.1", "localhost"].includes(origin.hostname)
  )
    throw new Error("PUBLIC_ORIGIN must use HTTPS");
  if (
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  )
    throw new Error("PUBLIC_ORIGIN must be an origin only");
  const encryptionKey = Buffer.from(
    env.CREDENTIAL_ENCRYPTION_KEY ?? "",
    "base64",
  );
  if (encryptionKey.length !== 32)
    throw new Error(
      "CREDENTIAL_ENCRYPTION_KEY must be a durable 32-byte base64 key",
    );
  if (
    env.BETA_ACCESS !== undefined &&
    !["true", "false"].includes(env.BETA_ACCESS)
  )
    throw new Error("BETA_ACCESS must be true or false");
  const purchaseBindingKey = env.PURCHASE_BINDING_KEY ? Buffer.from(env.PURCHASE_BINDING_KEY, "base64") : undefined;
  if ((purchaseBindingKey && purchaseBindingKey.length !== 32) || (env.BETA_ACCESS === "false" && !purchaseBindingKey))
    throw new Error("PURCHASE_BINDING_KEY must be a separate durable 32-byte base64 key before paid launch");
  const config = {
    databaseURL: env.DATABASE_URL,
    publicOrigin: origin.origin,
    encryptionKey,
    purchaseBindingKey,
    appleAudience: env.APPLE_AUDIENCE,
    appleClientSecret: env.APPLE_CLIENT_SECRET,
    appleTeamId: env.APPLE_TEAM_ID,
    appleKeyId: env.APPLE_SIGNIN_KEY_ID,
    applePrivateKey: env.APPLE_SIGNIN_PRIVATE_KEY,
    aiKey: env.AI_GATEWAY_API_KEY,
    aiModel: env.AI_MODEL ?? "openai/gpt-4.1-mini",
    perDay: integer(env.AI_MAX_REQUESTS_PER_DAY, 20),
    perMinute: integer(env.AI_MAX_REQUESTS_PER_MINUTE, 5),
    globalPerDay: integer(env.AI_GLOBAL_REQUESTS_PER_DAY, 500),
    betaAccess: env.BETA_ACCESS !== "false",
    productIds: (env.STOREKIT_PRODUCT_IDS ?? "")
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean),
    bundleId: env.APPLE_BUNDLE_ID ?? env.APPLE_AUDIENCE,
    appAppleId: env.APPLE_APP_ID
      ? integer(env.APPLE_APP_ID, undefined, Number.MAX_SAFE_INTEGER)
      : undefined,
    storeEnvironment: env.STOREKIT_ENVIRONMENT ?? "Sandbox",
    supportEmail: env.SUPPORT_EMAIL,
    port: integer(env.PORT, 8787, 65535),
    host: env.HOST ?? "127.0.0.1",
  };
  config.coachConfigured = Boolean(config.aiKey && config.aiModel);
  config.appleExchangeConfigured = Boolean(
    config.appleClientSecret ||
    (config.appleTeamId && config.appleKeyId && config.applePrivateKey),
  );
  return config;
}
