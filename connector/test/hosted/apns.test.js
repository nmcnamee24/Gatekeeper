import test from "node:test";
import assert from "node:assert/strict";
import { createHostedAPNs } from "../../src/hosted/apns.js";
test("production tokens never use a sandbox-only Apple key", async () => {
  const calls = [];
  const factory = (env) =>
    env.APNS_KEY_ID
      ? async (device) => {
          calls.push({ key: env.APNS_KEY_ID, environment: device.environment });
          return { accepted: true, status: 200 };
        }
      : null;
  const sandbox = createHostedAPNs(
    { APNS_KEY_ID: "sandbox-key", APNS_ENVIRONMENT: "sandbox" },
    factory,
  );
  assert.equal((await sandbox({ environment: "production" })).accepted, false);
  assert.equal(calls.length, 0);
  assert.deepEqual(sandbox.configured, { sandbox: true, production: false });
  const both = createHostedAPNs(
    {
      APNS_KEY_ID: "sandbox-key",
      APNS_ENVIRONMENT: "sandbox",
      APNS_PRODUCTION_KEY_ID: "production-key",
      APNS_PRODUCTION_TEAM_ID: "team",
      APNS_PRODUCTION_PRIVATE_KEY: "private",
    },
    factory,
  );
  await both({ environment: "production" });
  await both({ environment: "sandbox" });
  assert.deepEqual(calls, [
    { key: "production-key", environment: "production" },
    { key: "sandbox-key", environment: "sandbox" },
  ]);
  assert.deepEqual(both.configured, { sandbox: true, production: true });
  assert.throws(
    () => createHostedAPNs({ APNS_PRODUCTION_KEY_ID: "partial" }, factory),
    /every production/,
  );
  assert.equal(createHostedAPNs({}, factory), null);
});
