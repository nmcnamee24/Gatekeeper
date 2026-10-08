import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { randomBytes } from "node:crypto";
import { database } from "./helpers.js";
test("production entrypoint boots real migrations, OAuth, privacy and truthful readiness", async (t) => {
  const { pool } = await database(t);
  const schema = (await pool.query("SELECT current_schema() AS name")).rows[0]
    .name;
  const portServer = createServer();
  await new Promise((resolve) => portServer.listen(0, "127.0.0.1", resolve));
  const port = portServer.address().port;
  await new Promise((resolve) => portServer.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const url = new URL(process.env.TEST_DATABASE_URL);
  url.searchParams.set("options", `-c search_path=${schema}`);
  const child = spawn(process.execPath, ["src/hosted/main.js"], {
    env: {
      PATH: process.env.PATH,
      DATABASE_URL: url.href,
      PUBLIC_ORIGIN: origin,
      CREDENTIAL_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
      PORT: String(port),
      SUPPORT_EMAIL: "noah@rooklayer.com",
      BETA_ACCESS: "true",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let logs = "";
  child.stdout.on("data", (x) => (logs += x));
  child.stderr.on("data", (x) => (logs += x));
  t.after(async () => {
    child.kill("SIGTERM");
    if (child.exitCode === null)
      await new Promise((resolve) => child.once("exit", resolve));
  });
  let up = false;
  for (let i = 0; i < 100; i++) {
    try {
      up = (await fetch(origin + "/health")).status === 200;
      if (up) break;
    } catch {}
    if (child.exitCode !== null) throw new Error("Startup failed: " + logs);
    await new Promise((resolve) => setTimeout(resolve, 30));
  }
  assert.ok(up, logs);
  const ready = await fetch(origin + "/ready");
  assert.equal(ready.status, 503);
  const checks = (await ready.json()).checks;
  assert.equal(checks.coach, false);
  assert.equal(checks.appleRevocation, false);
  assert.equal(checks.supportContact, true);
  assert.ok(
    (await (await fetch(origin + "/privacy")).text()).includes(
      "noah@rooklayer.com",
    ),
  );
  assert.equal((await fetch(origin + "/support")).status, 200);
  const metadata = await fetch(
    origin + "/.well-known/oauth-protected-resource/mcp",
  );
  assert.equal(metadata.status, 200);
  assert.equal((await metadata.json()).resource, origin + "/mcp");
  const challenge = await fetch(origin + "/v1/auth/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  assert.equal(challenge.status, 503);
  assert.equal((await fetch(origin + "/v1/account")).status, 401);
  assert.ok(!logs.includes("postgresql://"));
});
