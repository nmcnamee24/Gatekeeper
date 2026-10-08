import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, sign, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import pg from 'pg';
import { SignedDataVerifier, Environment } from '@apple/app-store-server-library';
import { HostedBilling } from '../../src/hosted/billing.js';

const databaseUrl = process.env.TEST_DATABASE_URL || 'postgresql://gatekeeper@127.0.0.1:55439/gatekeeper_test';
const product = 'test.gatekeeper.subscription';
const bundleId = 'test.gatekeeper';
const now = Date.now();
const users = [randomUUID(), randomUUID()];
function transaction(overrides = {}) {
  return {transactionId:'100', originalTransactionId:'100', productId:product, bundleId,
    environment:'Sandbox', appAccountToken:users[0], type:'Auto-Renewable Subscription',
    purchaseDate:now - 1000, expiresDate:now + 3600000, signedDate:now, ...overrides};
}
// Semantic fixtures substitute ONLY Apple's external verifier. Database operations are real.
const semanticVerifier = {
  async verifyAndDecodeTransaction(value) { return JSON.parse(value); },
  async verifyAndDecodeNotification(value) { return JSON.parse(value); },
};
async function setup(t, options = {}) {
  const schema = 'billing_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({connectionString:databaseUrl});
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({connectionString:databaseUrl, options:`-c search_path=${schema}`});
  t.after(async () => {await pool.end(); await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end();});
  await pool.query('CREATE TABLE gk_users(id uuid PRIMARY KEY)');
  await pool.query('INSERT INTO gk_users(id) VALUES ($1),($2)', users);
  const billing = new HostedBilling({pool, bundleId, environment:'Sandbox', productIds:[product], betaAccess:false, verifier:semanticVerifier, ...options});
  await billing.init();
  return {billing, pool};
}
const encode = value => JSON.stringify(value);
function notification(tx, overrides={}) {
  return {notificationUUID:randomUUID(), notificationType:'DID_RENEW', signedDate:tx.signedDate,
    data:{bundleId, environment:'Sandbox', signedTransactionInfo:encode(tx)}, ...overrides};
}

test('free beta grants access while unconfigured paid verification fails closed', async t => {
  const {billing} = await setup(t, {bundleId:undefined, productIds:[], verifier:undefined, betaAccess:true});
  assert.deepEqual(billing.products(), {productIds:[], betaAccess:true});
  assert.deepEqual(await billing.entitlement(users[0]), {active:true, betaAccess:true, subscriptionActive:false});
  await billing.requireAccess(users[0]);
  await assert.rejects(billing.recordTransaction(users[0], 'a.b.c'), {code:'billing_unconfigured'});
});

test('verified entitlement expires, revocation removes access, and account deletion cascades', async t => {
  const {billing,pool} = await setup(t);
  assert.equal((await billing.recordTransaction(users[0], encode(transaction()))).subscriptionActive, true);
  assert.equal((await billing.entitlement(users[1])).active, false);
  await assert.rejects(billing.requireAccess(users[1]), {code:'subscription_required'});
  await billing.recordTransaction(users[0], encode(transaction({revocationDate:now, signedDate:now+1})));
  assert.equal((await billing.entitlement(users[0])).active, false);
  await pool.query('DELETE FROM gk_users WHERE id=$1', [users[0]]);
  assert.equal(Number((await pool.query('SELECT count(*) FROM gk_subscriptions')).rows[0].count),0);
  assert.equal(Number((await pool.query('SELECT count(*) FROM gk_billing_events')).rows[0].count),0);
  const expired = transaction({appAccountToken:users[1], originalTransactionId:'200', transactionId:'200', expiresDate:now-1, purchaseDate:now-10000});
  assert.equal((await billing.recordTransaction(users[1], encode(expired))).active,false);
});

test('rejects cross-account, unconfigured product, malformed dates and non-subscription transactions', async t => {
  const {billing,pool} = await setup(t);
  for (const tx of [transaction({appAccountToken:users[1]}),transaction({productId:'other'}),
    transaction({expiresDate:null}),transaction({purchaseDate:now+7200000}),
    transaction({signedDate:now+86400000}),transaction({type:'Consumable'}), transaction({bundleId:'other'})]) {
    await assert.rejects(billing.recordTransaction(users[0],encode(tx)));
  }
  assert.equal(Number((await pool.query('SELECT count(*) FROM gk_subscriptions')).rows[0].count),0);
});

test('same original subscription cannot be claimed by another user under concurrent workers', async t => {
  const {billing,pool} = await setup(t);
  const second = new HostedBilling({pool, bundleId, environment:'Sandbox', productIds:[product], betaAccess:false, verifier:semanticVerifier});
  const results = await Promise.allSettled([
    billing.recordTransaction(users[0], encode(transaction())),
    second.recordTransaction(users[1], encode(transaction({appAccountToken:users[1]}))),
  ]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  assert.equal(results.find(r=>r.status==='rejected').reason.code,'subscription_owned');
  assert.equal(Number((await pool.query('SELECT count(*) FROM gk_subscriptions')).rows[0].count),1);
});

test('duplicate and old notifications cannot replace newer renewal, and refund revokes latest transaction', async t => {
  const {billing,pool} = await setup(t);
  await billing.recordTransaction(users[0],encode(transaction()));
  const renewed = transaction({transactionId:'101', purchaseDate:now+1000, signedDate:now+1001, expiresDate:now+7200000});
  const renewal = notification(renewed);
  await billing.handleNotification(encode(renewal));
  assert.equal((await billing.handleNotification(encode(renewal))).duplicate,true);
  await billing.handleNotification(encode(notification(transaction({signedDate:now+2000, revocationDate:now+2000}),{notificationType:'REFUND'})));
  assert.equal((await billing.entitlement(users[0])).transactionId,'101');
  assert.equal((await billing.entitlement(users[0])).active,true);
  await billing.handleNotification(encode(notification({...renewed,signedDate:now+3000,revocationDate:now+3000},{notificationType:'REFUND'})));
  assert.equal((await billing.entitlement(users[0])).active,false);
  // Equal signedDate conflicting unrevoked data must never undo revocation.
  await billing.recordTransaction(users[0],encode({...renewed,signedDate:now+3000}));
  assert.equal((await billing.entitlement(users[0])).active,false);
  assert.equal(Number((await pool.query('SELECT count(*) FROM gk_subscriptions')).rows[0].count),1);
});

test('notifications associate only known accounts, validate envelope and transaction environment', async t => {
  const {billing,pool} = await setup(t);
  const unknown = notification(transaction({appAccountToken:randomUUID()}));
  assert.equal((await billing.handleNotification(encode(unknown))).ignored,true);
  const known = notification(transaction());
  await billing.handleNotification(encode(known));
  assert.equal((await billing.entitlement(users[0])).active,true);
  await assert.rejects(billing.handleNotification(encode(notification(transaction(),{data:{...known.data,environment:'Production'}}))));
  await assert.rejects(billing.recordTransaction(users[0],encode(transaction({environment:'Production'}))));
  assert.equal(Number((await pool.query('SELECT count(*) FROM gk_subscriptions')).rows[0].count),1);
});

test('notification without token may update an already verified owner but never assign an unknown subscription', async t => {
  const {billing} = await setup(t);
  await billing.recordTransaction(users[0],encode(transaction()));
  const noToken = transaction({appAccountToken:undefined,signedDate:now+1,revocationDate:now});
  await billing.handleNotification(encode(notification(noToken,{notificationType:'REFUND'})));
  assert.equal((await billing.entitlement(users[0])).active,false);
  assert.equal((await billing.handleNotification(encode(notification({...noToken,originalTransactionId:'unknown'})))).ignored,true);
});

test('production never reads sandbox entitlements and local verification environments are disabled', async t => {
  const {billing,pool} = await setup(t);
  await billing.recordTransaction(users[0],encode(transaction()));
  const prod = new HostedBilling({pool,bundleId,appAppleId:123,environment:'Production',productIds:[product],betaAccess:false,verifier:semanticVerifier});
  assert.equal((await prod.entitlement(users[0])).active,false);
  await assert.rejects(prod.recordTransaction(users[0],encode(transaction())),{code:'invalid_transaction'});
  for (const environment of ['Xcode','LocalTesting','unknown']) {
    const local = new HostedBilling({pool,bundleId,environment,productIds:[product],betaAccess:false,verifier:semanticVerifier});
    await assert.rejects(local.recordTransaction(users[0],encode(transaction({environment}))),{code:'billing_unconfigured'});
  }
});

// Real ES256 signatures and a test-only certificate chain with Apple's purpose OIDs.
// This establishes rejection behavior, not a verified App Store purchase/provider integration.
function makeCryptographicFixture(t) {
  const dir = mkdtempSync(join(tmpdir(),'gk-billing-certs-'));
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const openssl = args => execFileSync('openssl',args,{cwd:dir,stdio:'pipe'});
  for (const name of ['root','issuer','leaf']) openssl(['ecparam','-name','prime256v1','-genkey','-noout','-out',name+'.key']);
  openssl(['req','-x509','-new','-key','root.key','-out','root.pem','-days','2','-subj','/CN=Gatekeeper TEST root','-addext','basicConstraints=critical,CA:TRUE']);
  for (const name of ['issuer','leaf']) {
    openssl(['req','-new','-key',name+'.key','-out',name+'.csr','-subj','/CN=Gatekeeper TEST '+name]);
    writeFileSync(join(dir,name+'.ext'), name==='issuer' ? 'basicConstraints=critical,CA:TRUE\n1.2.840.113635.100.6.2.1=DER:05:00\n' : 'basicConstraints=critical,CA:FALSE\n1.2.840.113635.100.6.11.1=DER:05:00\n');
    const issuer = name==='issuer' ? 'root' : 'issuer';
    openssl(['x509','-req','-in',name+'.csr','-CA',issuer+'.pem','-CAkey',issuer+'.key','-CAcreateserial','-out',name+'.pem','-days','2','-extfile',name+'.ext']);
  }
  const root = readFileSync(join(dir,'root.pem'));
  const chain = ['leaf','issuer','root'].map(name=>new X509Certificate(readFileSync(join(dir,name+'.pem'))).raw.toString('base64'));
  const privateKey = readFileSync(join(dir,'leaf.key'));
  const jws = payload => {
    const body = [Buffer.from(JSON.stringify({alg:'ES256',x5c:chain})).toString('base64url'),Buffer.from(JSON.stringify(payload)).toString('base64url')].join('.');
    return body+'.'+sign('sha256',Buffer.from(body),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
  };
  return {root,jws};
}

test('real cryptography rejects forged/tampered signatures, wrong bundle and sandbox at production', async t => {
  const fixture = makeCryptographicFixture(t);
  const verifier = new SignedDataVerifier([fixture.root],false,Environment.SANDBOX,bundleId);
  const {billing,pool} = await setup(t,{verifier});
  const valid = fixture.jws(transaction());
  assert.equal((await billing.recordTransaction(users[0],valid)).active,true);
  const parts = valid.split('.');
  const badSignature = [...parts.slice(0,2),Buffer.alloc(64).toString('base64url')].join('.');
  const tampered = [parts[0],Buffer.from(JSON.stringify(transaction({expiresDate:now+999999999}))).toString('base64url'),parts[2]].join('.');
  const unsigned = [Buffer.from('{"alg":"none"}').toString('base64url'),parts[1],''].join('.');
  for (const bad of [badSignature,tampered,unsigned,fixture.jws(transaction({bundleId:'attacker'}))]) {
    await assert.rejects(billing.recordTransaction(users[0],bad),{code:'invalid_signed_data'});
  }
  const prodVerifier = new SignedDataVerifier([fixture.root],false,Environment.PRODUCTION,bundleId,123);
  const prod = new HostedBilling({pool,bundleId,appAppleId:123,environment:'Production',productIds:[product],betaAccess:false,verifier:prodVerifier});
  await assert.rejects(prod.recordTransaction(users[0],valid),{code:'invalid_signed_data'});
  // Official production trust rejects the fully signed but attacker-owned chain.
  const official = new HostedBilling({pool,bundleId,environment:'Sandbox',productIds:[product],betaAccess:false});
  await official.init();
  await assert.rejects(official.recordTransaction(users[0],valid),{code:'invalid_signed_data'});
});

test('active configured subscription remains available when another product has a later expiry', async t => {
  const {billing,pool} = await setup(t);
  await billing.recordTransaction(users[0],encode(transaction()));
  const other = new HostedBilling({pool,bundleId,environment:'Sandbox',productIds:['other'],betaAccess:false,verifier:semanticVerifier});
  await other.recordTransaction(users[0],encode(transaction({originalTransactionId:'300',transactionId:'300',productId:'other',expiresDate:now+7200000})));
  assert.equal((await billing.entitlement(users[0])).active,true);
  assert.equal((await billing.entitlement(users[0])).productId,product);
});

test('concurrent migration initialization is safe across HTTP replicas', async t => {
  const schema = 'billing_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({connectionString:databaseUrl});
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({connectionString:databaseUrl, options:`-c search_path=${schema}`});
  t.after(async () => {await pool.end(); await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end();});
  await pool.query('CREATE TABLE gk_users(id uuid PRIMARY KEY)');
  const replicas = Array.from({length:8},()=>new HostedBilling({pool}));
  await Promise.all(replicas.map(billing=>billing.init()));
  assert.equal(Number((await pool.query('SELECT count(*) FROM gk_subscriptions')).rows[0].count),0);
});

test('real cryptography validates both notification and nested transaction before changing access', async t => {
  const fixture = makeCryptographicFixture(t);
  const verifier = new SignedDataVerifier([fixture.root],false,Environment.SANDBOX,bundleId);
  const {billing} = await setup(t,{verifier});
  const tx = fixture.jws(transaction());
  const envelope = {notificationUUID:randomUUID(),notificationType:'SUBSCRIBED',version:'2.0',signedDate:now,
    data:{bundleId,environment:'Sandbox',signedTransactionInfo:tx}};
  const signed = fixture.jws(envelope);
  const parts = signed.split('.');
  await assert.rejects(billing.handleNotification([...parts.slice(0,2),Buffer.alloc(64).toString('base64url')].join('.')),{code:'invalid_signed_data'});
  assert.equal((await billing.entitlement(users[0])).active,false);
  const badNested = {...envelope,data:{...envelope.data,signedTransactionInfo:tx.split('.').slice(0,2).join('.')+'.'+Buffer.alloc(64).toString('base64url')}};
  await assert.rejects(billing.handleNotification(fixture.jws(badNested)),{code:'invalid_signed_data'});
  assert.equal((await billing.entitlement(users[0])).active,false);
  await billing.handleNotification(signed);
  assert.equal((await billing.entitlement(users[0])).active,true);
});

test('retryable external verification failure never creates an entitlement', async t => {
  const {billing,pool} = await setup(t,{verifier:{async verifyAndDecodeTransaction() {throw Object.assign(new Error('OCSP unavailable'),{status:2});}}});
  await assert.rejects(billing.recordTransaction(users[0],encode(transaction())),{code:'billing_verification_unavailable',status:503});
  assert.equal((await billing.entitlement(users[0])).active,false);
  assert.equal(Number((await pool.query('SELECT count(*) FROM gk_billing_events')).rows[0].count),0);
});

async function blockedWorker(pool,applicationName) {
  for(let attempt=0;attempt<200;attempt++) {
    if((await pool.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'",[applicationName])).rows.length)return;
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  throw new Error('Billing worker never reached the concurrent account lock');
}

test('account deletion and billing update use account-first locks without deadlocks',async t=>{
  const {billing,pool}=await setup(t);
  await billing.recordTransaction(users[0],encode(transaction()));
  const applicationName='billing_delete_'+randomUUID();
  const workerPool=new pg.Pool({...pool.options,application_name:applicationName});t.after(()=>workerPool.end());
  const worker=new HostedBilling({pool:workerPool,bundleId,environment:'Sandbox',productIds:[product],betaAccess:false,verifier:semanticVerifier});
  const deleter=await pool.connect();
  try {
    await deleter.query('BEGIN');await deleter.query('SELECT id FROM gk_users WHERE id=$1 FOR UPDATE',[users[0]]);
    const operation=worker.recordTransaction(users[0],encode(transaction({signedDate:now+1}))).then(value=>({value}),error=>({error}));
    await blockedWorker(pool,applicationName);
    await deleter.query('DELETE FROM gk_users WHERE id=$1',[users[0]]);await deleter.query('COMMIT');
    const outcome=await operation;assert.ok(outcome.error);assert.equal(outcome.error.code,'account_not_found');
    assert.equal(Number((await pool.query('SELECT count(*) FROM gk_subscriptions')).rows[0].count),0);
  }finally{await deleter.query('ROLLBACK');deleter.release();}
});
