import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { HostedBilling } from "../../src/hosted/billing.js";
import { database, account } from "./helpers.js";
const { HostedBillingRouter } = await import("../../src/hosted/billing-router.js").catch(() => ({}));
const product="com.test.rook.monthly", bundleId="com.test.rook", appAppleId=123456789;
async function setup(t) {
  const {pool,store}=await database(t);
  const a=await account(store), b=await account(store);
  const second=await store.registerDevice(a.user.id,{installationId:randomUUID(),name:"Production phone"});
  await pool.query("UPDATE gk_users SET purchase_account_token=id");
  const verified=new Map(), environments=new Map();
  const sign=(value)=> {const jws="e30."+Buffer.from(JSON.stringify(value)).toString("base64url")+".signature";verified.set(jws,value);return jws;};
  const verifier={verifyAndDecodeTransaction:async jws=>{if(!verified.has(jws))throw new Error("invalid signature");return verified.get(jws);},verifyAndDecodeNotification:async jws=>{if(!verified.has(jws))throw new Error("invalid signature");return verified.get(jws);}};
  const production=new HostedBilling({pool,bundleId,appAppleId,environment:"Production",productIds:[product],betaAccess:false,verifier});
  const sandbox=new HostedBilling({pool,bundleId,appAppleId,environment:"Sandbox",productIds:[product],betaAccess:false,verifier});
  await production.init(); await sandbox.init();
  assert.equal(typeof HostedBillingRouter,"function");
  const proof={accessEnvironment:async(userId,deviceId)=>environments.get(userId+":"+deviceId)};
  const billing=new HostedBillingRouter({production,sandbox,deviceProof:proof});
  const transaction=(environment,extra={})=>({bundleId,environment,productId:product,type:"Auto-Renewable Subscription",appAccountToken:a.user.id,originalTransactionId:randomUUID(),transactionId:randomUUID(),purchaseDate:Date.now()-1000,signedDate:Date.now(),expiresDate:Date.now()+3600000,...extra});
  return {pool,store,a,b,second,production,sandbox,billing,environments,sign,transaction};
}
test("sandbox purchases cannot grant production paid access or another device access",async t=>{
  const f=await setup(t), signed=f.sign(f.transaction("Sandbox"));
  await assert.rejects(f.billing.recordTransaction(f.a.user.id,signed,f.a.device.id),{code:"store_device_verification_required"});
  f.environments.set(f.a.user.id+":"+f.a.device.id,"Sandbox");
  const result=await f.billing.recordTransaction(f.a.user.id,signed,f.a.device.id);
  assert.equal(result.active,false); assert.equal(result.subscriptionActive,false);
  assert.equal(result.access.available,true); assert.equal(result.access.mode,"sandbox_test");
  assert.equal((await f.billing.entitlement(f.a.user.id)).active,false);
  await assert.rejects(f.billing.requireAccess(f.a.user.id,f.pool,f.second.id),{code:"subscription_required"});
  await assert.rejects(f.billing.requireAccess(f.b.user.id,f.pool,f.a.device.id),{code:"subscription_required"});
  f.environments.set(f.a.user.id+":"+f.a.device.id,"Production");
  await assert.rejects(f.billing.assertRedemption(f.a.user.id,f.pool,f.a.device.id,"sandbox_test"),{code:"store_device_verification_required"});
});
test("production transactions grant account access while routing hints still require verification",async t=>{
  const f=await setup(t), signed=f.sign(f.transaction("Production"));
  const result=await f.billing.recordTransaction(f.a.user.id,signed,f.a.device.id);
  assert.equal(result.active,true); assert.equal(result.access.mode,"production_paid");
  assert.equal((await f.billing.requireAccess(f.a.user.id,f.pool,f.second.id)).active,true);
  const tampered="e30."+Buffer.from(JSON.stringify(f.transaction("Production"))).toString("base64url")+".forged";
  await assert.rejects(f.billing.recordTransaction(f.a.user.id,tampered,f.a.device.id),{code:"invalid_signed_data"});
  await assert.rejects(f.billing.recordTransaction(f.a.user.id,f.sign(f.transaction("LocalTesting")),f.a.device.id),{code:"invalid_signed_data"});
  await assert.rejects(f.billing.recordTransaction(f.b.user.id,signed,f.b.device.id),{code:"transaction_account_mismatch"});
});
test("sandbox notifications update only sandbox ownership without classifying devices",async t=>{
  const f=await setup(t), tx=f.transaction("Sandbox"), transaction=f.sign(tx);
  const notification=f.sign({notificationUUID:randomUUID(),signedDate:Date.now(),data:{bundleId,environment:"Sandbox",signedTransactionInfo:transaction}});
  await f.billing.handleNotification(notification);
  assert.equal((await f.production.entitlement(f.a.user.id)).active,false);
  assert.equal((await f.sandbox.entitlement(f.a.user.id)).active,true);
  assert.equal((await f.billing.entitlement(f.a.user.id,f.pool,f.a.device.id)).access.available,false);
});
test("redemption rechecks the device lane under the grant transaction",async t=>{
  const f=await setup(t);
  f.environments.set(f.a.user.id+":"+f.a.device.id,"Sandbox");
  await f.billing.recordTransaction(f.a.user.id,f.sign(f.transaction("Sandbox")),f.a.device.id);
  const approval=await f.store.withUserLock(f.a.user.id,async(c,user)=>{
    const access=await f.billing.requireAccess(user.id,c,f.a.device.id);
    return f.store.approveInTransaction(c,user,{requestId:randomUUID(),purpose:"Reply to Alex about dinner",exitPlan:"Close after sending the message",durationMinutes:1,deviceId:f.a.device.id},access.access.mode);
  });
  f.environments.set(f.a.user.id+":"+f.a.device.id,"Production");
  await assert.rejects(f.store.redeem(f.a.user.id,f.a.device.id,approval.grantId,(c,row)=>f.billing.assertRedemption(f.a.user.id,c,f.a.device.id,row.access_source)),{code:"store_device_verification_required"});
  assert.equal((await f.pool.query("SELECT redeemed_at FROM gk_grants WHERE id=$1",[approval.grantId])).rows[0].redeemed_at,null);
  assert.equal((await f.pool.query("SELECT access_source FROM gk_grants WHERE id=$1",[approval.grantId])).rows[0].access_source,"sandbox_test");
});
