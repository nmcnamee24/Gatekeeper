import test from "node:test";
import assert from "node:assert/strict";
import { database } from "./helpers.js";
const { purchaseAccountToken, initializePurchaseBindings } = await import("../../src/hosted/purchase-binding.js").catch(() => ({}));

test("purchase binding survives account recreation but separates identities and apps", () => {
  assert.equal(typeof purchaseAccountToken, "function");
  const key = Buffer.alloc(32, 17);
  const token = purchaseAccountToken(key, "com.noah.gatekeeper", "verified-apple-subject");
  assert.match(token, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(purchaseAccountToken(key, "com.noah.gatekeeper", "verified-apple-subject"), token);
  assert.notEqual(purchaseAccountToken(key, "com.noah.gatekeeper", "another-subject"), token);
  assert.notEqual(purchaseAccountToken(key, "another.app", "verified-apple-subject"), token);
  assert.notEqual(purchaseAccountToken(Buffer.alloc(32, 18), "com.noah.gatekeeper", "verified-apple-subject"), token);
  assert.throws(() => purchaseAccountToken(Buffer.alloc(16), "com.noah.gatekeeper", "subject"));
  assert.throws(() => purchaseAccountToken(key, "", "subject"));
});
test("prelaunch migration binds existing verified identities and pins the key beyond account deletion", async t => {
  const {pool,store} = await database(t);
  const user = await store.upsertUser({appleSub:"verified-existing-subject"});
  assert.equal(typeof initializePurchaseBindings,"function");
  await initializePurchaseBindings(pool,Buffer.alloc(32,17),"com.noah.gatekeeper");
  assert.equal((await store.account(user.id)).user.purchaseAccountToken,
    purchaseAccountToken(Buffer.alloc(32,17),"com.noah.gatekeeper","verified-existing-subject"));
  await store.deleteAccount(user.id);
  await assert.rejects(initializePurchaseBindings(pool,Buffer.alloc(32,18),"com.noah.gatekeeper"),/key changed/);
});
