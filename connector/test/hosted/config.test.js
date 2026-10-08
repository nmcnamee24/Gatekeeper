import test from "node:test";
import assert from "node:assert/strict";
import { hostedConfiguration } from "../../src/hosted/config.js";
const valid = {
  DATABASE_URL: "postgresql://user:password@db.example/gatekeeper",
  PUBLIC_ORIGIN: "https://gatekeeper.example",
  CREDENTIAL_ENCRYPTION_KEY: Buffer.alloc(32, 1).toString("base64"),
  APPLE_AUDIENCE: "com.example.gatekeeper",
  AI_GATEWAY_API_KEY: "private-key",
  AI_MODEL: "fixture/model",
  BETA_ACCESS: "true",
};
test("configuration enforces HTTPS, a durable encryption key and bounded AI quotas", () => {
  assert.equal(hostedConfiguration(valid).betaAccess, true);
  for (const env of [
    { ...valid, PUBLIC_ORIGIN: "http://public.example" },
    { ...valid, CREDENTIAL_ENCRYPTION_KEY: "" },
    { ...valid, AI_MAX_REQUESTS_PER_DAY: "0" },
    { ...valid, PUBLIC_ORIGIN: "https://x.example/path" },
    { ...valid, BETA_ACCESS: "maybe" },
  ])
    assert.throws(() => hostedConfiguration(env));
});
test("free beta has honest readiness gates and no fabricated paid products", () => {
  const config = hostedConfiguration({ ...valid, AI_GATEWAY_API_KEY: "" });
  assert.equal(config.coachConfigured, false);
  assert.equal(config.appleExchangeConfigured, false);
  assert.deepEqual(config.productIds, []);
  assert.equal(config.aiModel, "fixture/model");
});
test("paid launch requires a separate durable purchase-binding key", () => {
  assert.throws(() => hostedConfiguration({...valid,BETA_ACCESS:"false"}),/PURCHASE_BINDING_KEY/);
  assert.throws(() => hostedConfiguration({...valid,PURCHASE_BINDING_KEY:"invalid"}),/PURCHASE_BINDING_KEY/);
  const key=Buffer.alloc(32,17).toString("base64");
  assert.deepEqual(hostedConfiguration({...valid,BETA_ACCESS:"false",PURCHASE_BINDING_KEY:key}).purchaseBindingKey,Buffer.alloc(32,17));
});
