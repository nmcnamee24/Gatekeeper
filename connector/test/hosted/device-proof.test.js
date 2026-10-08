import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import cbor from 'cbor';
import { HostedDeviceProof } from '../../src/hosted/device-proof.js';
import { database, account } from './helpers.js';

const origin = 'https://rook.example';
const teamId = 'ABCDE12345';
const bundleId = 'com.example.rook';
const sha256 = value => createHash('sha256').update(value).digest();
const deviceVerificationId = 'B12112B7-0626-4DBF-A2F5-D281A333AE20';
const deviceVerificationNonce = '912D5DA1-4E64-452F-A0D9-EFCEEDB153EE';
const deviceVerification = createHash('sha384').update(deviceVerificationNonce.toLowerCase() + deviceVerificationId.toLowerCase()).digest('base64');
const transaction = receiptType => ({ receiptType, bundleId, appAppleId: 123, deviceVerificationNonce, deviceVerification });

// AppTransaction signature/OCSP validation and Apple issuance are external. Only
// that boundary is replaced; PostgreSQL ownership/leases and assertion crypto run.
async function fixture(t, overrides = {}) {
  const { pool, store } = await database(t);
  const owner = await account(store);
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = keys.publicKey.export({ format: 'jwk' });
  const keyId = sha256(Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')])).toString('base64');
  let now = Date.parse('2026-10-08T16:00:00Z');
  const options = { pool, teamId, bundleId, publicOrigin: origin,
    clock: () => now,
    appTransactionVerifiers: Object.fromEntries(['Production', 'Sandbox'].map(environment => [environment, {
      async verifyAndDecodeAppTransaction(jws) {
        if (jws !== `signed-${environment}`) throw new Error('signature or OCSP rejected');
        return transaction(environment);
      },
    }])),
    attestationVerifier: ({ attestation, challenge, keyId: claimedKeyId, allowDevelopmentEnvironment, teamIdentifier, bundleIdentifier }) => {
      // Require the same exact bytes as the hardware issuance boundary expects.
      assert.equal(allowDevelopmentEnvironment, false);
      assert.equal(teamIdentifier, teamId); assert.equal(bundleIdentifier, bundleId);
      assert.deepEqual(attestation, sha256(challenge));
      if (claimedKeyId !== keyId) throw new Error('key mismatch');
      return { keyId, environment: 'production', publicKey: keys.publicKey.export({format:'pem',type:'spki'}) };
    }, ...overrides };
  const proof = new HostedDeviceProof(options); await proof.init();
  function payload(challenge, jws = 'signed-Sandbox', deviceId = owner.device.id) {
    return Buffer.from(JSON.stringify(['rook.store-proof.v1', origin, challenge.challengeId, challenge.nonce,
      owner.user.id, deviceId, keyId, sha256(jws).toString('hex'), deviceVerificationId.toLowerCase()]));
  }
  async function registration(environment = 'Sandbox') {
    const challenge = await proof.challenge(owner.user.id, owner.device.id, { keyId });
    const jws = `signed-${environment}`;
    return { challenge, body: { challengeId: challenge.challengeId, keyId, signedAppTransaction: jws, deviceVerificationId,
      attestation: sha256(payload(challenge, jws)).toString('base64') } };
  }
  function assertion(challenge, count = 1, { appId = `${teamId}.${bundleId}`, data = payload(challenge), signer = keys.privateKey, authLength = 37 } = {}) {
    const auth = Buffer.alloc(authLength); sha256(appId).copy(auth); auth.writeUInt32BE(count, 33);
    const nonce = sha256(Buffer.concat([auth, sha256(data)]));
    return cbor.encode({ authenticatorData: auth, signature: sign('sha256', nonce, signer) }).toString('base64');
  }
  return { pool, store, proof, owner, keyId, registration, assertion, payload, options, advance: ms => { now += ms; } };
}
const denied = /proof|device|challenge|attest|verification/i;

test('fresh hardware-bound Sandbox registration grants only a 15 minute device lease and stores no raw JWS or UUID', async t => {
  const f = await fixture(t); const { challenge, body } = await f.registration();
  assert.equal(challenge.keyRegistered, false); assert.equal(new Date(challenge.expiresAt).getTime(), Date.parse('2026-10-08T16:05:00Z'));
  assert.equal(await f.proof.accessEnvironment(f.owner.user.id, f.owner.device.id), null);
  const result = await f.proof.prove(f.owner.user.id, f.owner.device.id, body);
  assert.deepEqual(result, {environment:'Sandbox',expiresAt:'2026-10-08T16:15:00.000Z'});
  assert.equal(await f.proof.accessEnvironment(f.owner.user.id, f.owner.device.id), 'Sandbox');
  const row = (await f.pool.query('SELECT * FROM gk_device_store_proofs')).rows[0];
  assert.equal(row.app_transaction_hash, sha256(body.signedAppTransaction).toString('hex'));
  assert.equal(JSON.stringify(row).includes(body.signedAppTransaction), false);
  assert.equal(JSON.stringify(row).includes(deviceVerificationId.toLowerCase()), false);
  f.advance(15 * 60_000); assert.equal(await f.proof.accessEnvironment(f.owner.user.id, f.owner.device.id), null);
});

test('registered key renews with a real increasing-counter signature over the full canonical proof', async t => {
  const f = await fixture(t); const {body} = await f.registration(); await f.proof.prove(f.owner.user.id,f.owner.device.id,body);
  f.advance(60_000); const challenge=await f.proof.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId});
  assert.equal(challenge.keyRegistered,true);
  await f.proof.prove(f.owner.user.id,f.owner.device.id,{...body,challengeId:challenge.challengeId,attestation:undefined,assertion:f.assertion(challenge)});
  assert.equal((await f.pool.query('SELECT sign_count FROM gk_device_attest_keys')).rows[0].sign_count, '1');
  assert.equal(await f.proof.accessEnvironment(f.owner.user.id,f.owner.device.id), 'Sandbox');
});

test('App Store Production is accepted only after its signed transaction verifier succeeds', async t => {
  const f=await fixture(t);const {body}=await f.registration('Production');
  assert.equal((await f.proof.prove(f.owner.user.id,f.owner.device.id,body)).environment,'Production');
});

test('one-time challenges reject replay, expiry, and forged nonce proof', async t => {
  const f=await fixture(t);let {body}=await f.registration();
  await f.proof.prove(f.owner.user.id,f.owner.device.id,body);
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,body),denied);
  const next=await f.registration(); f.advance(5*60_000);
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,next.body),denied);
  const fresh=await f.registration(); fresh.body.attestation=Buffer.alloc(32).toString('base64');
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,fresh.body),denied);
});

test('caller UUID, invalid device hash, provider failure and LocalTesting cannot establish a device environment', async t => {
  const f=await fixture(t); const {body}=await f.registration();
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,{...body,attestation:undefined}),denied);
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,{...body,deviceVerificationId:randomUUID()}),denied);
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,{...body,signedAppTransaction:'forged-JWS'}),denied);
  const local=new HostedDeviceProof({...f.options,appTransactionVerifiers:{Sandbox:{verifyAndDecodeAppTransaction:async()=>transaction('LocalTesting')}}});
  await assert.rejects(local.prove(f.owner.user.id,f.owner.device.id,body),denied);
  assert.equal(await f.proof.accessEnvironment(f.owner.user.id,f.owner.device.id),null);
});

test('transaction verifier output must match the configured bundle and exact UUID hash', async t => {
  const f=await fixture(t); const {body}=await f.registration();
  for(const bad of [{bundleId:'other.app'},{deviceVerificationNonce:'not-a-uuid'},{deviceVerification:'invalid-base64'},{receiptType:'Production'}]) {
    const service=new HostedDeviceProof({...f.options,appTransactionVerifiers:{Sandbox:{verifyAndDecodeAppTransaction:async()=>({...transaction('Sandbox'),...bad})}}});
    await assert.rejects(service.prove(f.owner.user.id,f.owner.device.id,body),denied);
  }
});

test('cross-account and cross-device challenge/key reuse is rejected', async t => {
  const f=await fixture(t);const other=await account(f.store,'other'); const {body}=await f.registration();
  await assert.rejects(f.proof.prove(other.user.id,other.device.id,body),denied);
  await assert.rejects(f.proof.challenge(other.user.id,f.owner.device.id,{keyId:f.keyId}),denied);
  await f.proof.prove(f.owner.user.id,f.owner.device.id,body);
  await assert.rejects(f.proof.challenge(other.user.id,other.device.id,{keyId:f.keyId}),denied);
  assert.equal(await f.proof.accessEnvironment(other.user.id,f.owner.device.id),null);
});

test('development App Attest output is rejected even with Sandbox StoreKit', async t => {
  const f=await fixture(t,{attestationVerifier:()=>({environment:'development',keyId:'bad',publicKey:'bad'})});
  const {body}=await f.registration();await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,body),denied);
});

test('assertions reject changed payload, wrong app, wrong signing key and repeated counter', async t => {
  const f=await fixture(t);const {body}=await f.registration();await f.proof.prove(f.owner.user.id,f.owner.device.id,body);
  const ch=await f.proof.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId});
  const request={...body,challengeId:ch.challengeId,attestation:undefined};
  for(const opts of [{data:Buffer.from('different')},{appId:'OTHER.com.attacker'},{signer:generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey}])
    await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,{...request,assertion:f.assertion(ch,1,opts)}),denied);
  await f.proof.prove(f.owner.user.id,f.owner.device.id,{...request,assertion:f.assertion(ch,1)});
  const next=await f.proof.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId});
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,{...request,challengeId:next.challengeId,assertion:f.assertion(next,1)}),denied);
});

test('replicas serialize challenge consumption and counter advancement', async t => {
  const f=await fixture(t);const {body}=await f.registration();
  const replica=new HostedDeviceProof(f.options);
  const results=await Promise.allSettled([f.proof.prove(f.owner.user.id,f.owner.device.id,body),replica.prove(f.owner.user.id,f.owner.device.id,body)]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  const ch1=await f.proof.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId});
  const ch2=await replica.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId});
  const run=(p,ch)=>p.prove(f.owner.user.id,f.owner.device.id,{...body,challengeId:ch.challengeId,attestation:undefined,assertion:f.assertion(ch,1)});
  const counters=await Promise.allSettled([run(f.proof,ch1),run(replica,ch2)]);
  assert.equal(counters.filter(r=>r.status==='fulfilled').length,1);
});

test('revocation immediately stops proof access and account deletion cascades all device proof data', async t => {
  const f=await fixture(t);const {body}=await f.registration();await f.proof.prove(f.owner.user.id,f.owner.device.id,body);
  await f.proof.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId});
  await f.pool.query('UPDATE gk_devices SET revoked_at=now() WHERE id=$1',[f.owner.device.id]);
  assert.equal(await f.proof.accessEnvironment(f.owner.user.id,f.owner.device.id),null);
  await assert.rejects(f.proof.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId}),denied);
  await f.pool.query('DELETE FROM gk_users WHERE id=$1',[f.owner.user.id]);
  for(const table of ['gk_device_attest_keys','gk_device_proof_challenges','gk_device_store_proofs'])
    assert.equal((await f.pool.query(`SELECT count(*) FROM ${table}`)).rows[0].count,'0');
});

test('default verifier rejects malformed or untrusted attestation without creating a key', async t => {
  const f=await fixture(t,{attestationVerifier:undefined});const {body}=await f.registration();
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,body),denied);
  assert.equal((await f.pool.query('SELECT count(*) FROM gk_device_attest_keys')).rows[0].count,'0');
});


test('assertions reject appended CBOR objects', async t => {
  const f=await fixture(t);const {body}=await f.registration();await f.proof.prove(f.owner.user.id,f.owner.device.id,body);
  const challenge=await f.proof.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId});
  const request={...body,challengeId:challenge.challengeId,attestation:undefined};
  const valid=Buffer.from(f.assertion(challenge),'base64');
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,{...request,assertion:Buffer.concat([valid,cbor.encode({extra:'object'})]).toString('base64')}),denied);
});


test('assertions reject noncanonical authenticator bytes even with a valid signature', async t => {
  const f=await fixture(t);const {body}=await f.registration();await f.proof.prove(f.owner.user.id,f.owner.device.id,body);
  const challenge=await f.proof.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId});
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,{...body,challengeId:challenge.challengeId,attestation:undefined,
    assertion:f.assertion(challenge,1,{authLength:38})}),denied);
});

test('a fresh classification challenge clears an old Sandbox lease even if the new proof fails', async t => {
  const f=await fixture(t);const {body}=await f.registration();await f.proof.prove(f.owner.user.id,f.owner.device.id,body);
  const challenge=await f.proof.challenge(f.owner.user.id,f.owner.device.id,{keyId:f.keyId});
  assert.equal(await f.proof.accessEnvironment(f.owner.user.id,f.owner.device.id),null);
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,{...body,challengeId:challenge.challengeId,attestation:undefined,
    signedAppTransaction:'forged-JWS',assertion:f.assertion(challenge)}),denied);
  assert.equal(await f.proof.accessEnvironment(f.owner.user.id,f.owner.device.id),null);
});

test('Apple retryable verification failure preserves a 503 response and never grants a lease', async t => {
  const {VerificationException,VerificationStatus}=await import('@apple/app-store-server-library');
  const f=await fixture(t,{appTransactionVerifiers:{Sandbox:{verifyAndDecodeAppTransaction:async()=>{
    throw new VerificationException(VerificationStatus.RETRYABLE_VERIFICATION_FAILURE);
  }}}}); const {body}=await f.registration();
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,body),error=>error.status===503);
  assert.equal(await f.proof.accessEnvironment(f.owner.user.id,f.owner.device.id),null);
});

test('pruning removes expired challenges and leases while preserving active state and key counters', async t => {
  const f=await fixture(t);const {body}=await f.registration();await f.proof.prove(f.owner.user.id,f.owner.device.id,body);
  // Insert an expired sibling challenge without reducing the still-current lease.
  await f.pool.query(`INSERT INTO gk_device_proof_challenges(id,user_id,device_id,key_id,nonce,expires_at)
    VALUES($1,$2,$3,$4,'old',$5)`,[randomUUID(),f.owner.user.id,f.owner.device.id,f.keyId,'2026-10-08T15:59:59Z']);
  assert.equal(typeof f.proof.prune,'function','device proof service must prune expired state');
  assert.deepEqual(await f.proof.prune(),{challenges:1,proofs:0});
  assert.equal(await f.proof.accessEnvironment(f.owner.user.id,f.owner.device.id),'Sandbox');
  f.advance(15*60_000); assert.deepEqual(await f.proof.prune(),{challenges:0,proofs:1});
  assert.equal((await f.pool.query('SELECT count(*) FROM gk_device_attest_keys')).rows[0].count,'1');
});
test('delayed distinct-key Sandbox proof cannot overwrite a newer Production classification',async t=>{
  const f=await fixture(t);const old=await f.registration('Sandbox');
  const keys=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=keys.publicKey.export({format:'jwk'});
  const keyId=sha256(Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')])).toString('base64');
  const replica=new HostedDeviceProof({...f.options,attestationVerifier:({attestation,challenge})=>{
    assert.deepEqual(attestation,sha256(challenge));
    return {keyId,environment:'production',publicKey:keys.publicKey.export({format:'pem',type:'spki'})};
  }});
  const ch=await replica.challenge(f.owner.user.id,f.owner.device.id,{keyId});
  const payload=Buffer.from(JSON.stringify(['rook.store-proof.v1',origin,ch.challengeId,ch.nonce,f.owner.user.id,f.owner.device.id,keyId,sha256('signed-Production').toString('hex'),deviceVerificationId.toLowerCase()]));
  await replica.prove(f.owner.user.id,f.owner.device.id,{challengeId:ch.challengeId,keyId,signedAppTransaction:'signed-Production',deviceVerificationId,attestation:sha256(payload).toString('base64')});
  assert.equal(await replica.accessEnvironment(f.owner.user.id,f.owner.device.id),'Production');
  await assert.rejects(f.proof.prove(f.owner.user.id,f.owner.device.id,old.body),denied);
  assert.equal(await replica.accessEnvironment(f.owner.user.id,f.owner.device.id),'Production');
});
