import test from "node:test";
import assert from "node:assert/strict";
import { database } from "./helpers.js";
import { HostedRateLimit } from "../../src/hosted/rate-limit.js";
test("anonymous auth rate budgets are atomic across replicas without storing client IP", async (t) => {
  const { pool } = await database(t);
  let now = Date.now();
  const a = new HostedRateLimit({
      pool,
      key: "private-test-key",
      limit: 2,
      clock: () => now,
    }),
    b = new HostedRateLimit({
      pool,
      key: "private-test-key",
      limit: 2,
      clock: () => now,
    });
  await a.init();
  const req = { method: "POST", path: "/v1/auth/challenge", ip: "192.0.2.55" };
  const results = await Promise.allSettled([
    a.consume(req),
    b.consume(req),
    a.consume(req),
  ]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 2);
  assert.equal(results.find((r) => r.status === "rejected").reason.status, 429);
  const rows = (await pool.query("SELECT subject,count FROM gk_http_limits"))
    .rows;
  assert.equal(rows[0].count, 2);
  assert.equal(rows[0].subject.length, 64);
  assert.ok(!rows[0].subject.includes(req.ip));
  now += 60000;
  await b.consume(req);
  await a.consume({ ...req, path: "/v1/conversation" });
  await a.consume({ ...req, method: "GET" });
});
