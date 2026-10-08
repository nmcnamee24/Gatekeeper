import { createHash, createPublicKey, randomBytes, randomUUID, timingSafeEqual, X509Certificate } from 'node:crypto';
import cbor from 'cbor';
import { verifyAttestation, verifyAssertion } from 'node-app-attest';
import { VerificationException, VerificationStatus } from '@apple/app-store-server-library';
import { HostedError } from './errors.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hash = (algorithm, value) => createHash(algorithm).update(value).digest();
const denied = () => new HostedError('Device proof verification rejected.', 'device_proof_rejected', 403);
function base64(value, maxBytes, exactBytes) {
  if (typeof value !== 'string' || !value.length || value.length > Math.ceil(maxBytes / 3) * 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw denied();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > maxBytes || (exactBytes !== undefined && bytes.length !== exactBytes) || bytes.toString('base64') !== value) throw denied();
  return bytes;
}
function decodedObject(bytes) {
  const objects = cbor.decodeAllSync(bytes, { max_depth: 12, preventDuplicateKeys: true });
  if (objects.length !== 1 || !objects[0] || typeof objects[0] !== 'object') throw denied();
  return objects[0];
}
function checkedAttestation(params, now) {
  const obj = decodedObject(params.attestation);
  if (!Buffer.isBuffer(obj.authData) || obj.authData.length < 87 || obj.attStmt?.x5c?.length !== 2) throw denied();
  const [leaf, intermediate] = obj.attStmt.x5c.map(cert => new X509Certificate(cert));
  for (const cert of [leaf, intermediate]) {
    if (now < Date.parse(cert.validFrom) || now >= Date.parse(cert.validTo)) throw denied();
  }
  if (leaf.ca || !intermediate.ca || !leaf.checkIssued(intermediate)) throw denied();
  const result = verifyAttestation(params); // Pinned official Apple root, nonce, rpID, counter, AAGUID and credentialID.
  return result;
}
function checkedAssertion(params) {
  const obj = decodedObject(params.assertion);
  if (!Buffer.isBuffer(obj.authenticatorData) || obj.authenticatorData.length !== 37 ||
      !Buffer.isBuffer(obj.signature) || !obj.signature.length) throw denied();
  return verifyAssertion(params);
}

// Call init after HostedStore.migrate. Only verified AppTransaction + fresh
// production App Attest establishes a lease; caller UUIDs alone never do.
export class HostedDeviceProof {
  constructor({ pool, teamId, bundleId, publicOrigin, appTransactionVerifiers,
    attestationVerifier, assertionVerifier = checkedAssertion, clock = Date.now }) {
    if (!pool || !/^[A-Z0-9]{10}$/.test(teamId ?? '') || !bundleId || !publicOrigin || !appTransactionVerifiers) throw new Error('Device proof configuration is incomplete');
    const url = new URL(publicOrigin);
    if (url.protocol !== 'https:' || url.origin !== publicOrigin) throw new Error('Device proof requires a canonical HTTPS public origin');
    Object.assign(this, { pool, teamId, bundleId, publicOrigin, appTransactionVerifiers, attestationVerifier, assertionVerifier, clock });
  }
  now() { const now = Number(this.clock()); if (!Number.isFinite(now)) throw denied(); return now; }
  async init() {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended('rook-device-proof-schema:' || current_schema(),0))");
      await client.query(`CREATE TABLE IF NOT EXISTS gk_device_attest_keys (
        key_id text PRIMARY KEY, user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
        device_id uuid NOT NULL, public_key text NOT NULL, sign_count bigint NOT NULL DEFAULT 0 CHECK(sign_count>=0 AND sign_count<=4294967295),
        UNIQUE(key_id,device_id,user_id), FOREIGN KEY(device_id,user_id) REFERENCES gk_devices(id,user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS gk_device_proof_challenges (
        id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
        device_id uuid NOT NULL, key_id text NOT NULL, nonce text NOT NULL, expires_at timestamptz NOT NULL,
        FOREIGN KEY(device_id,user_id) REFERENCES gk_devices(id,user_id) ON DELETE CASCADE);
        CREATE INDEX IF NOT EXISTS gk_device_proof_challenge_expiry ON gk_device_proof_challenges(expires_at);
        CREATE TABLE IF NOT EXISTS gk_device_store_proofs (
        device_id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
        key_id text NOT NULL, app_transaction_hash text NOT NULL,
        environment text NOT NULL CHECK(environment IN ('Sandbox','Production')), expires_at timestamptz NOT NULL,
        FOREIGN KEY(device_id,user_id) REFERENCES gk_devices(id,user_id) ON DELETE CASCADE,
        FOREIGN KEY(key_id,device_id,user_id) REFERENCES gk_device_attest_keys(key_id,device_id,user_id) ON DELETE CASCADE)`);
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }
  async transaction(action) {
    const client = await this.pool.connect();
    try { await client.query('BEGIN'); const result = await action(client); await client.query('COMMIT'); return result; }
    catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }
  async lockDevice(client, userId, deviceId) {
    if (!UUID.test(userId ?? '') || !UUID.test(deviceId ?? '')) throw denied();
    const user = (await client.query('SELECT id,apple_authorization_revoked_at FROM gk_users WHERE id=$1 FOR UPDATE', [userId])).rows[0];
    if (!user || user.apple_authorization_revoked_at) throw denied();
    const device = (await client.query('SELECT id,revoked_at FROM gk_devices WHERE id=$1 AND user_id=$2 FOR UPDATE',[deviceId,userId])).rows[0];
    if (!device || device.revoked_at) throw denied();
  }
  async lockKey(client, keyId, userId, deviceId) {
    // Covers the absent-row registration race across accounts and replicas.
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('rook-attest-key:' || current_schema() || ':' || $1,0))",[keyId]);
    const key = (await client.query('SELECT * FROM gk_device_attest_keys WHERE key_id=$1 FOR UPDATE',[keyId])).rows[0];
    if (key && (key.user_id !== userId || key.device_id !== deviceId)) throw denied();
    return key;
  }
  async challenge(userId, deviceId, { keyId } = {}) {
    base64(keyId,32,32);
    return this.transaction(async client => {
      await this.lockDevice(client,userId,deviceId);
      const key = await this.lockKey(client,keyId,userId,deviceId);
      const now = this.now(); const challengeId = randomUUID(); const nonce = randomBytes(32).toString('base64');
      const expiresAt = new Date(now + 5*60_000).toISOString();
      // Starting a new classification must immediately retire a previous Sandbox lease.
      await client.query('DELETE FROM gk_device_store_proofs WHERE device_id=$1 AND user_id=$2',[deviceId,userId]);
      // A newer classification attempt supersedes every earlier challenge,
      // including those issued for another legitimate key on the same device.
      await client.query('DELETE FROM gk_device_proof_challenges WHERE device_id=$1',[deviceId]);
      await client.query('INSERT INTO gk_device_proof_challenges(id,user_id,device_id,key_id,nonce,expires_at) VALUES($1,$2,$3,$4,$5,$6)',[challengeId,userId,deviceId,keyId,nonce,expiresAt]);
      return { challengeId,nonce,expiresAt,keyRegistered:!!key };
    });
  }
  async verifyAppTransaction(signedAppTransaction, deviceVerificationId) {
    let retryable = false;
    for (const environment of ['Production','Sandbox']) {
      const verifier = this.appTransactionVerifiers[environment];
      if (!verifier) continue;
      let decoded;
      try { decoded = await verifier.verifyAndDecodeAppTransaction(signedAppTransaction); }
      catch (error) {
        if (error instanceof VerificationException && error.status === VerificationStatus.RETRYABLE_VERIFICATION_FAILURE) retryable = true;
        continue; // No decoded environment is trusted before verification.
      }
      if (decoded.receiptType !== environment || decoded.bundleId !== this.bundleId ||
          !UUID.test(decoded.deviceVerificationNonce ?? '')) throw denied();
      const expected = hash('sha384',decoded.deviceVerificationNonce.toLowerCase() + deviceVerificationId.toLowerCase());
      const actual = base64(decoded.deviceVerification,48,48);
      if (!timingSafeEqual(expected,actual)) throw denied();
      return environment;
    }
    if (retryable) throw new HostedError('Apple device proof verification is temporarily unavailable.', 'device_proof_unavailable', 503);
    throw denied();
  }
  async prune() {
    return this.transaction(async client => {
      const now = new Date(this.now());
      const challenges = await client.query('DELETE FROM gk_device_proof_challenges WHERE expires_at<=$1',[now]);
      const proofs = await client.query('DELETE FROM gk_device_store_proofs WHERE expires_at<=$1',[now]);
      return {challenges:challenges.rowCount,proofs:proofs.rowCount};
    });
  }
  async prove(userId, deviceId, { challengeId,keyId,signedAppTransaction,deviceVerificationId,attestation,assertion } = {}) {
    base64(keyId,32,32);
    if (!UUID.test(challengeId ?? '') || !UUID.test(deviceVerificationId ?? '') ||
        typeof signedAppTransaction !== 'string' || !signedAppTransaction.length || signedAppTransaction.length > 100_000 ||
        (!!attestation === !!assertion)) throw denied();
    return this.transaction(async client => {
      await this.lockDevice(client,userId,deviceId);
      const challenge = (await client.query('SELECT * FROM gk_device_proof_challenges WHERE id=$1 FOR UPDATE',[challengeId])).rows[0];
      if (!challenge || challenge.user_id !== userId || challenge.device_id !== deviceId || challenge.key_id !== keyId ||
          Number(challenge.expires_at) <= this.now()) throw denied();
      const key = await this.lockKey(client,keyId,userId,deviceId);
      const environment = await this.verifyAppTransaction(signedAppTransaction,deviceVerificationId);
      const transactionHash = hash('sha256',signedAppTransaction).toString('hex');
      const payload = Buffer.from(JSON.stringify(['rook.store-proof.v1',this.publicOrigin,challengeId,challenge.nonce,
        userId,deviceId,keyId,transactionHash,deviceVerificationId.toLowerCase()]));
      const shared = { keyId,bundleIdentifier:this.bundleId,teamIdentifier:this.teamId };
      try {
        if (!key) {
          if (!attestation) throw denied();
          const params = {...shared,attestation:base64(attestation,32_768),challenge:payload,allowDevelopmentEnvironment:false};
          const verified = await (this.attestationVerifier ? this.attestationVerifier(params) : checkedAttestation(params,this.now()));
          if (verified?.environment !== 'production' || verified.keyId !== keyId || !verified.publicKey) throw denied();
          const publicKey = createPublicKey(verified.publicKey);
          if (publicKey.asymmetricKeyType !== 'ec' || publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw denied();
          const jwk = publicKey.export({format:'jwk'});
          const publicKeyHash = hash('sha256',Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]));
          if (!timingSafeEqual(publicKeyHash,base64(keyId,32,32))) throw denied();
          await client.query('INSERT INTO gk_device_attest_keys(key_id,user_id,device_id,public_key) VALUES($1,$2,$3,$4)',[keyId,userId,deviceId,publicKey.export({format:'pem',type:'spki'})]);
        } else {
          if (!assertion) throw denied();
          const verified = await this.assertionVerifier({...shared,assertion:base64(assertion,4096),payload,publicKey:key.public_key,signCount:Number(key.sign_count)});
          if (!Number.isInteger(verified?.signCount) || verified.signCount<=Number(key.sign_count) || verified.signCount>4294967295) throw denied();
          await client.query('UPDATE gk_device_attest_keys SET sign_count=$2 WHERE key_id=$1',[keyId,verified.signCount]);
        }
      } catch { throw denied(); }
      // Expensive external verification must not extend an already expired challenge.
      const now = this.now(); if (Number(challenge.expires_at)<=now) throw denied();
      const expiresAt = new Date(now+15*60_000).toISOString();
      await client.query(`INSERT INTO gk_device_store_proofs(device_id,user_id,key_id,app_transaction_hash,environment,expires_at)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(device_id) DO UPDATE SET key_id=EXCLUDED.key_id,
        app_transaction_hash=EXCLUDED.app_transaction_hash,environment=EXCLUDED.environment,expires_at=EXCLUDED.expires_at`,[deviceId,userId,keyId,transactionHash,environment,expiresAt]);
      await client.query('DELETE FROM gk_device_proof_challenges WHERE id=$1',[challengeId]);
      return {environment,expiresAt};
    });
  }
  async accessEnvironment(userId,deviceId,executor=this.pool) {
    if (!UUID.test(userId ?? '') || !UUID.test(deviceId ?? '')) return null;
    const row=(await executor.query(`SELECT p.environment FROM gk_device_store_proofs p
      JOIN gk_devices d ON d.id=p.device_id AND d.user_id=p.user_id JOIN gk_users u ON u.id=p.user_id
      WHERE p.user_id=$1 AND p.device_id=$2 AND p.expires_at>$3 AND d.revoked_at IS NULL
      AND u.apple_authorization_revoked_at IS NULL`,[userId,deviceId,new Date(this.now())])).rows[0];
    return ['Sandbox','Production'].includes(row?.environment) ? row.environment : null;
  }
}
