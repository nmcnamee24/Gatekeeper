import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { HostedConversation } from "../../src/hosted/conversation.js";
import { database, account } from "./helpers.js";
const approved = {
  decision: "approve",
  reply: "You may reply now.",
  purpose: "Reply to a specific friend",
  exitPlan: "Close the app after sending the reply",
  durationMinutes: 5,
};
const input = (deviceId) => ({
  requestId: randomUUID(),
  message: "Five minutes to reply to Sam, then close the app.",
  durationMinutes: 5,
  deviceId,
});
test("consent and device ownership are required before any provider request", async (t) => {
  const { store } = await database(t);
  const a = await account(store);
  const b = await account(store);
  let calls = 0;
  const chat = new HostedConversation({
    store,
    coach: {
      configured: true,
      judge: async () => {
        calls++;
        return approved;
      },
    },
  });
  await chat.init();
  await assert.rejects(chat.respond(a.user.id, input(a.device.id)), /consent/i);
  await store.setConsent(a.user.id, "2026-10-08");
  await assert.rejects(chat.respond(a.user.id, input(b.device.id)), /device/i);
  assert.equal(calls, 0);
});
test("approved conversation creates one bound pending pass and retries do not bill or reapprove", async (t) => {
  const { store } = await database(t);
  const a = await account(store);
  await store.setConsent(a.user.id, "2026-10-08");
  let calls = 0;
  const chat = new HostedConversation({
    store,
    coach: {
      configured: true,
      judge: async () => {
        calls++;
        return approved;
      },
    },
  });
  await chat.init();
  const req = input(a.device.id);
  const reply = await chat.respond(a.user.id, req);
  assert.equal(reply.decision, "approve");
  assert.equal(reply.approval.windowSeconds, 300);
  assert.equal(reply.approval.status, "awaiting_phone");
  assert.ok(reply.reply.includes("phone"));
  assert.ok(!reply.reply.includes("You may reply now"));
  assert.deepEqual(await chat.respond(a.user.id, req), reply);
  assert.equal(calls, 1);
  await assert.rejects(
    chat.respond(a.user.id, { ...req, message: "A changed request" }),
    /different/i,
  );
  assert.equal((await chat.history(a.user.id)).messages.length, 2);
  await chat.clear(a.user.id);
  assert.equal((await chat.history(a.user.id)).messages.length, 0);
  await assert.rejects(chat.respond(a.user.id, req), /cleared/i);
  assert.equal(
    (await store.status(a.user.id)).pendingPass.grantId,
    reply.approval.grantId,
  );
});
test("parallel workers serialize a user conversation and enforce distributed quotas", async (t) => {
  const { store } = await database(t);
  const a = await account(store);
  await store.setConsent(a.user.id, "2026-10-08");
  let finish;
  const waiting = new Promise((resolve) => {
    finish = resolve;
  });
  const coach = {
    configured: true,
    judge: async () => {
      await waiting;
      return {
        ...approved,
        decision: "ask",
        purpose: null,
        exitPlan: null,
        durationMinutes: null,
      };
    },
  };
  const first = new HostedConversation({ store, coach, perDay: 1 });
  const second = new HostedConversation({ store, coach, perDay: 1 });
  await first.init();
  const one = first.respond(a.user.id, input(a.device.id));
  await new Promise((resolve) => setTimeout(resolve, 50));
  await assert.rejects(
    second.respond(a.user.id, input(a.device.id)),
    /progress|limit/i,
  );
  finish();
  await one;
  await assert.rejects(second.respond(a.user.id, input(a.device.id)), /limit/i);
});
test("a provider error never issues a pass or stores a claimed approval", async (t) => {
  const { store } = await database(t);
  const a = await account(store);
  await store.setConsent(a.user.id, "2026-10-08");
  const chat = new HostedConversation({
    store,
    coach: {
      configured: true,
      judge: async () => {
        throw new Error("provider down");
      },
    },
  });
  await chat.init();
  await assert.rejects(
    chat.respond(a.user.id, input(a.device.id)),
    /provider down/,
  );
  assert.equal((await store.status(a.user.id)).pendingPass, null);
  assert.equal((await chat.history(a.user.id)).messages.length, 0);
});
test("clearing history erases grant text while preserving active access and another account", async (t) => {
  const { store, pool } = await database(t);
  const a = await account(store);
  const b = await account(store);
  for (const user of [a, b]) await store.setConsent(user.user.id, "2026-10-08");
  const chat = new HostedConversation({ store, coach: { configured: true, judge: async () => approved } });
  await chat.init();
  const req = input(a.device.id);
  const own = await chat.respond(a.user.id, req);
  const other = await chat.respond(b.user.id, input(b.device.id));
  await store.redeem(a.user.id, a.device.id, own.approval.grantId);
  const before = (await pool.query("SELECT * FROM gk_grants WHERE id=$1", [own.approval.grantId])).rows[0];
  const cooldown = (await pool.query("SELECT cooldown_until FROM gk_users WHERE id=$1", [a.user.id])).rows[0].cooldown_until;
  await chat.clear(a.user.id);
  const after = (await pool.query("SELECT * FROM gk_grants WHERE id=$1", [own.approval.grantId])).rows[0];
  assert.equal(after.purpose, "", "The cleared request's grant must not keep a purpose copy");
  assert.equal(after.exit_plan, "", "The cleared request's grant must not keep an exit-plan copy");
  const { purpose, exit_plan, ...beforeTiming } = before;
  const { purpose: clearedPurpose, exit_plan: clearedExit, ...afterTiming } = after;
  assert.deepEqual(afterTiming, beforeTiming);
  assert.deepEqual((await pool.query("SELECT cooldown_until FROM gk_users WHERE id=$1", [a.user.id])).rows[0].cooldown_until, cooldown);
  assert.equal((await chat.history(a.user.id)).messages.length, 0);
  assert.equal((await chat.history(b.user.id)).messages.length, 2);
  const untouched = (await pool.query("SELECT purpose,exit_plan FROM gk_grants WHERE id=$1", [other.approval.grantId])).rows[0];
  assert.equal(untouched.purpose, approved.purpose);
  assert.equal(untouched.exit_plan, approved.exitPlan);
  await assert.rejects(chat.respond(a.user.id, req), /cleared/i);
  await assert.rejects(store.approve(a.user.id, {requestId: randomUUID(),purpose: "New purpose",exitPlan: "Close after completion",durationMinutes: 1,deviceId: a.device.id}), /cooldown/i);
});
