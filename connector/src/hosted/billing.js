import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { SignedDataVerifier, Environment, VerificationStatus } from '@apple/app-store-server-library';

const roots = [
  ['AppleIncRootCertificate.cer','b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024'],
  ['AppleRootCA-G2.cer','c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050'],
  ['AppleRootCA-G3.cer','63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179'],
];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const milliseconds = value => Number.isSafeInteger(value) && value > 0 && value < 8640000000000000;
function fail(code, message, status=400) {
  return Object.assign(new Error(message), {code, status, statusCode:status});
}
function trustedCertificates() {
  return roots.map(([name,hash]) => {
    const certificate = readFileSync(new URL(`../../config/apple-root-certificates/${name}`, import.meta.url));
    if (createHash('sha256').update(certificate).digest('hex') !== hash) throw new Error('Apple root certificate pin mismatch');
    return certificate;
  });
}

/** PostgreSQL-backed entitlement state. The verifier option is solely an in-process test seam. */
export class HostedBilling {
  constructor({pool, bundleId, appAppleId, environment='Production', productIds=[], betaAccess=true, verifier}={}) {
    this.pool = pool;
    this.bundleId = bundleId;
    this.appAppleId = appAppleId;
    this.environment = /^(sandbox|production)$/i.test(environment) ? (environment.toLowerCase()==='sandbox' ? Environment.SANDBOX : Environment.PRODUCTION) : environment;
    this.productIds = [...new Set(Array.isArray(productIds) ? productIds.filter(value=>typeof value==='string' && value.trim()).map(value=>value.trim()) : [])];
    this.betaAccess = betaAccess === true;
    this.verifier = undefined;
    this.configurationError = undefined;
    try {
      if (![Environment.PRODUCTION,Environment.SANDBOX].includes(this.environment) ||
          typeof this.bundleId !== 'string' || !this.bundleId.trim() || !this.productIds.length ||
          (this.environment===Environment.PRODUCTION && (!Number.isSafeInteger(appAppleId) || appAppleId<=0))) {
        throw new Error('Configure bundleId, subscription product IDs, environment and production appAppleId');
      }
      // Online certificate revocation checks are mandatory on the hosted paid path.
      this.verifier = verifier ?? new SignedDataVerifier(trustedCertificates(),true,this.environment,this.bundleId,this.appAppleId);
    } catch (error) { this.configurationError = error.message; }
  }

  async init() {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended('gatekeeper-billing-migrations:' || current_schema(),0))");
      await client.query(`
      CREATE TABLE IF NOT EXISTS gk_subscriptions (
        environment text NOT NULL CHECK (environment IN ('Production','Sandbox')),
        original_transaction_id text NOT NULL,
        user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
        transaction_id text NOT NULL,
        product_id text NOT NULL,
        purchase_date bigint NOT NULL,
        signed_date bigint NOT NULL,
        expires_at timestamptz NOT NULL,
        revoked_at timestamptz,
        updated_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY(environment,original_transaction_id)
      );
      CREATE INDEX IF NOT EXISTS gk_subscriptions_user ON gk_subscriptions(user_id,environment);
      CREATE TABLE IF NOT EXISTS gk_billing_events (
        environment text NOT NULL CHECK (environment IN ('Production','Sandbox')),
        event_id text NOT NULL,
        user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
        original_transaction_id text NOT NULL,
        transaction_id text NOT NULL,
        signed_date bigint NOT NULL,
        received_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY(environment,event_id)
      );
      CREATE INDEX IF NOT EXISTS gk_billing_events_user ON gk_billing_events(user_id);
    `);
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }

  products() { return {productIds:[...this.productIds], betaAccess:this.betaAccess}; }

  async entitlement(userId,executor=this.pool) {
    const {rows} = await executor.query(`SELECT * FROM gk_subscriptions
      WHERE user_id=$1 AND environment=$2 AND product_id=ANY($3::text[])
      ORDER BY (revoked_at IS NULL AND expires_at > now()) DESC, expires_at DESC LIMIT 1`, [userId,this.environment,this.productIds]);
    const row = rows[0];
    const subscriptionActive = Boolean(this.verifier && row && this.productIds.includes(row.product_id) && !row.revoked_at && row.expires_at.getTime()>Date.now());
    return {active:this.betaAccess || subscriptionActive, betaAccess:this.betaAccess, subscriptionActive,
      ...(row ? {productId:row.product_id, transactionId:row.transaction_id,
        expiresAt:row.expires_at.toISOString(), ...(row.revoked_at ? {revokedAt:row.revoked_at.toISOString()} : {})} : {})};
  }

  async requireAccess(userId,executor=this.pool) {
    const entitlement = await this.entitlement(userId,executor);
    if (!entitlement.active) throw fail('subscription_required','An active subscription is required',402);
    return entitlement;
  }

  async verify(method, signedData) {
    if (!this.verifier) throw fail('billing_unconfigured','Paid billing verification is not configured',503);
    if (typeof signedData !== 'string' || !signedData.length || signedData.length>100000) throw fail('invalid_signed_data','Invalid Apple signed data');
    try { return await this.verifier[method](signedData); }
    catch (error) {
      if (error.status===VerificationStatus.RETRYABLE_VERIFICATION_FAILURE) throw fail('billing_verification_unavailable','Apple verification is temporarily unavailable',503);
      throw fail('invalid_signed_data','Apple signed data could not be verified');
    }
  }

  validateTransaction(tx) {
    if (!tx || tx.bundleId!==this.bundleId || tx.environment!==this.environment ||
      !this.productIds.includes(tx.productId) || tx.type!=='Auto-Renewable Subscription' ||
      typeof tx.transactionId!=='string' || !tx.transactionId.length || tx.transactionId.length>128 ||
      typeof tx.originalTransactionId!=='string' || !tx.originalTransactionId.length || tx.originalTransactionId.length>128 ||
      !milliseconds(tx.signedDate) || !milliseconds(tx.purchaseDate) || !milliseconds(tx.expiresDate) ||
      tx.signedDate>Date.now()+300000 || tx.purchaseDate>Date.now()+300000 || tx.expiresDate<=tx.purchaseDate ||
      (tx.revocationDate!==undefined && !milliseconds(tx.revocationDate)) ||
      (tx.appAccountToken!==undefined && (typeof tx.appAccountToken!=='string' || !uuid.test(tx.appAccountToken)))) {
      throw fail('invalid_transaction','Transaction does not match the configured subscription');
    }
  }

  async recordTransaction(userId, signedTransaction) {
    const tx = await this.verify('verifyAndDecodeTransaction',signedTransaction);
    this.validateTransaction(tx);
    if (typeof userId!=='string' || !uuid.test(userId) || !tx.appAccountToken) {
      throw fail('transaction_account_mismatch','Transaction belongs to a different account',403);
    }
    const eventId = 'transaction:' + createHash('sha256').update(signedTransaction).digest('hex');
    await this.applyTransaction(tx,eventId,userId.toLowerCase());
    return this.entitlement(userId);
  }

  async handleNotification(signedPayload) {
    const notification = await this.verify('verifyAndDecodeNotification',signedPayload);
    if (typeof notification?.notificationUUID!=='string' || !uuid.test(notification.notificationUUID) ||
      !milliseconds(notification.signedDate) || notification.signedDate>Date.now()+300000 ||
      notification.data?.environment!==this.environment || notification.data?.bundleId!==this.bundleId ||
      (this.environment===Environment.PRODUCTION && notification.data?.appAppleId!==this.appAppleId)) {
      throw fail('invalid_notification','Notification does not match the configured app');
    }
    if (!notification.data.signedTransactionInfo) return {received:true, ignored:true};
    const tx = await this.verify('verifyAndDecodeTransaction',notification.data.signedTransactionInfo);
    this.validateTransaction(tx);
    return this.applyTransaction(tx,'notification:'+notification.notificationUUID);
  }

  async applyTransaction(tx,eventId,requestedUserId) {
    const token = tx.appAccountToken?.toLowerCase();
    const tokenOwner = token ? (await this.pool.query('SELECT id FROM gk_users WHERE purchase_account_token=$1',[token])).rows[0]?.id : undefined;
    const discoveredOwner = requestedUserId ?? tokenOwner ?? (!token ? (await this.pool.query(
      'SELECT user_id FROM gk_subscriptions WHERE environment=$1 AND original_transaction_id=$2',
      [this.environment,tx.originalTransactionId],
    )).rows[0]?.user_id : undefined);
    if (!discoveredOwner) return {received:true,ignored:true};
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Match deletion and every account mutation: user first, then child rows.
      const known = await client.query('SELECT id,purchase_account_token FROM gk_users WHERE id=$1 FOR UPDATE',[discoveredOwner]);
      if (!known.rows.length) {
        if (requestedUserId) throw fail('account_not_found','Account no longer exists',404);
        await client.query('COMMIT');
        return {received:true,ignored:true};
      }
      if (token && token!==known.rows[0].purchase_account_token)
        throw fail('transaction_account_mismatch','Transaction belongs to a different account',403);
      // Locks the subscription identity even before a row exists, across all HTTP workers.
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[this.environment+':'+tx.originalTransactionId]);
      const {rows} = await client.query('SELECT * FROM gk_subscriptions WHERE environment=$1 AND original_transaction_id=$2 FOR UPDATE',[this.environment,tx.originalTransactionId]);
      const previous = rows[0];
      if (previous && discoveredOwner!==previous.user_id) {
        throw fail('subscription_owned','Subscription belongs to another account',403);
      }
      const userId = discoveredOwner;
      const event = await client.query(`INSERT INTO gk_billing_events(environment,event_id,user_id,original_transaction_id,transaction_id,signed_date)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(environment,event_id) DO NOTHING RETURNING event_id`,
        [this.environment,eventId,userId,tx.originalTransactionId,tx.transactionId,tx.signedDate]);
      if (!event.rows.length) {
        await client.query('COMMIT');
        return {received:true,duplicate:true};
      }
      // Apple can send a newly signed refund for an OLD billing period after a renewal.
      // Purchase date dominates signed date; equal snapshots cannot undo a revocation.
      const newer = !previous || tx.purchaseDate>Number(previous.purchase_date) ||
        (tx.purchaseDate===Number(previous.purchase_date) && (tx.signedDate>Number(previous.signed_date) ||
          (tx.signedDate===Number(previous.signed_date) && tx.revocationDate!==undefined && !previous.revoked_at)));
      if (newer) {
        await client.query(`INSERT INTO gk_subscriptions(environment,original_transaction_id,user_id,transaction_id,product_id,purchase_date,signed_date,expires_at,revoked_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
          ON CONFLICT(environment,original_transaction_id) DO UPDATE SET transaction_id=EXCLUDED.transaction_id,
            product_id=EXCLUDED.product_id,purchase_date=EXCLUDED.purchase_date,signed_date=EXCLUDED.signed_date,
            expires_at=EXCLUDED.expires_at,revoked_at=EXCLUDED.revoked_at,updated_at=now()`,
          [this.environment,tx.originalTransactionId,userId,tx.transactionId,tx.productId,tx.purchaseDate,tx.signedDate,new Date(tx.expiresDate),tx.revocationDate===undefined ? null : new Date(tx.revocationDate)]);
      }
      await client.query('COMMIT');
      return {received:true,updated:newer};
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }
}
