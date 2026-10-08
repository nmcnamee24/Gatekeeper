import { createHmac, createHash } from "node:crypto";

// Only call with a subject previously verified by the server's Apple identity flow.
// Keep this dedicated key durable across account deletion and encryption rotations.
export function purchaseAccountToken(key, appIdentity, appleSubject) {
  if (!Buffer.isBuffer(key) || key.length !== 32 ||
      typeof appIdentity !== "string" || !appIdentity.trim() ||
      typeof appleSubject !== "string" || !appleSubject.trim()) {
    throw new Error("Purchase binding requires a durable 32-byte key and verified app/Apple identity");
  }
  const bytes = createHmac("sha256", key)
    .update(JSON.stringify(["rook.purchase-binding.v1", appIdentity, appleSubject]))
    .digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const h = bytes.toString("hex");
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

export async function initializePurchaseBindings(pool, key, appIdentity) {
  purchaseAccountToken(key, appIdentity, "configuration-validation");
  const fingerprint = createHash("sha256").update(key).digest("hex");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('rook-purchase-binding:' || current_schema(),0))");
    await client.query(`CREATE TABLE IF NOT EXISTS gk_purchase_binding_configuration (
      app_identity text PRIMARY KEY, key_fingerprint text NOT NULL)`);
    const pinned = (await client.query("SELECT key_fingerprint FROM gk_purchase_binding_configuration WHERE app_identity=$1", [appIdentity])).rows[0];
    if (pinned && pinned.key_fingerprint !== fingerprint)
      throw new Error("Purchase binding key changed; authenticated migration is required");
    // The configuration pin is not an account ledger. It remains when all users
    // delete accounts, preventing accidental loss of their future restore binding.
    await client.query("INSERT INTO gk_purchase_binding_configuration(app_identity,key_fingerprint) VALUES($1,$2) ON CONFLICT DO NOTHING", [appIdentity,fingerprint]);
    const hasBilling = (await client.query("SELECT to_regclass('gk_subscriptions') AS name")).rows[0].name;
    if (hasBilling && (await client.query(`SELECT 1 FROM gk_subscriptions s JOIN gk_users u ON u.id=s.user_id
      WHERE u.purchase_account_token IS NULL LIMIT 1`)).rows.length)
      throw new Error("Existing purchases require authenticated purchase-token migration before binding initialization");
    const users = (await client.query("SELECT id,apple_sub FROM gk_users WHERE purchase_account_token IS NULL FOR UPDATE")).rows;
    for (const user of users) {
      await client.query("UPDATE gk_users SET purchase_account_token=$1 WHERE id=$2", [purchaseAccountToken(key,appIdentity,user.apple_sub),user.id]);
    }
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
}
