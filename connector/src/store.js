import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { POLICY } from './policy.js';

export class PolicyError extends Error {}
export class Store {
  constructor(path, clock = () => Date.now()) {
    this.clock = clock;
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS grants (
        id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, purpose TEXT NOT NULL,
        exit_plan TEXT NOT NULL, created INTEGER NOT NULL, valid_until INTEGER NOT NULL,
        redeemed INTEGER, ends INTEGER, revoked INTEGER);
      CREATE TABLE IF NOT EXISTS device_report (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), received INTEGER NOT NULL, state TEXT NOT NULL,
        grant_id TEXT, local_expiry TEXT);
    `);
  }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const value = fn(); this.db.exec('COMMIT'); return value; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  latest() { return this.db.prepare('SELECT * FROM grants ORDER BY created DESC, rowid DESC LIMIT 1').get(); }
  cooldownUntil() {
    const row = this.db.prepare('SELECT MAX(ends) AS ends FROM grants WHERE redeemed IS NOT NULL').get();
    return row.ends == null ? null : row.ends + POLICY.cooldownSeconds * 1000;
  }
  pending() {
    return this.db.prepare('SELECT * FROM grants WHERE redeemed IS NULL AND revoked IS NULL AND valid_until > ? ORDER BY created DESC LIMIT 1').get(this.clock());
  }
  approvalView(row) {
    return { grantId: row.id, status: row.revoked != null ? 'revoked' : row.redeemed != null ? 'redeemed' : row.valid_until <= this.clock() ? 'expired' : 'awaiting_phone',
      redeemBy: new Date(row.valid_until).toISOString(), windowSeconds: POLICY.windowSeconds,
      openAppURL: 'gatekeeper://sync', instruction: 'Open Gatekeeper on the paired iPhone. This response does not mean apps are unlocked.' };
  }
  approve({ requestId, purpose, exitPlan }) {
    return this.transaction(() => {
      const previous = this.db.prepare('SELECT * FROM grants WHERE request_id=?').get(requestId);
      if (previous) {
        if (previous.purpose !== purpose || previous.exit_plan !== exitPlan) throw new PolicyError('This request ID was already used for a different request.');
        return this.approvalView(previous);
      }
      const now = this.clock();
      const cooldown = this.cooldownUntil();
      if (cooldown != null && now < cooldown) throw new PolicyError(`Cooldown lasts until ${new Date(cooldown).toISOString()}.`);
      if (this.pending()) throw new PolicyError('An unredeemed pass already exists. Open Gatekeeper to use it or let it expire.');
      const row = { id: randomUUID(), requestId, purpose, exitPlan, created: now, validUntil: now + POLICY.passLifetimeSeconds * 1000 };
      this.db.prepare('INSERT INTO grants(id, request_id, purpose, exit_plan, created, valid_until) VALUES(?,?,?,?,?,?)')
        .run(row.id, requestId, purpose, exitPlan, row.created, row.validUntil);
      return this.approvalView(this.latest());
    });
  }
  redeem(id) {
    return this.transaction(() => {
      const row = this.db.prepare('SELECT * FROM grants WHERE id=?').get(id);
      const now = this.clock();
      if (!row || row.revoked != null || row.redeemed != null || now >= row.valid_until) throw new PolicyError('Pass is missing, used, revoked, or expired.');
      const cooldown = this.cooldownUntil();
      if (cooldown != null && now < cooldown) throw new PolicyError('Cooldown is still active.');
      const end = now + POLICY.windowSeconds * 1000;
      this.db.prepare('UPDATE grants SET redeemed=?, ends=? WHERE id=?').run(now, end, id);
      return { grantId: id, windowSeconds: POLICY.windowSeconds, endsAt: new Date(end).toISOString() };
    });
  }
  endAccess() {
    return this.transaction(() => {
      this.db.prepare('UPDATE grants SET revoked=? WHERE revoked IS NULL').run(this.clock());
      return { status: 'end_requested', openAppURL: 'gatekeeper://sync', instruction: 'Open Gatekeeper to apply now. A closed or offline iPhone app has not acknowledged this request. The existing local timer still applies.' };
    });
  }
  deviceState() {
    const row = this.latest();
    return { pendingGrantId: this.pending()?.id ?? null, lastGrantId: row?.id ?? null,
      lastGrantRevoked: row?.revoked != null };
  }
  report({ state, grantId = null, localExpiry = null }) {
    this.db.prepare(`INSERT INTO device_report(singleton,received,state,grant_id,local_expiry) VALUES(1,?,?,?,?)
      ON CONFLICT(singleton) DO UPDATE SET received=excluded.received,state=excluded.state,grant_id=excluded.grant_id,local_expiry=excluded.local_expiry`)
      .run(this.clock(), state, grantId, localExpiry);
    return { received: true };
  }
  status() {
    const report = this.db.prepare('SELECT * FROM device_report WHERE singleton=1').get();
    return { policy: POLICY, serverTime: new Date(this.clock()).toISOString(),
      pendingPass: this.pending() ? this.approvalView(this.pending()) : null,
      nextEligibleAt: this.cooldownUntil() == null ? null : new Date(this.cooldownUntil()).toISOString(),
      latestGrant: this.latest() ? this.approvalView(this.latest()) : null,
      lastDeviceReport: report ? { state: report.state, grantId: report.grant_id, localExpiry: report.local_expiry,
        receivedAt: new Date(report.received).toISOString(), ageSeconds: Math.max(0, Math.floor((this.clock() - report.received) / 1000)) } : null,
      note: 'Server approvals and device reports are distinct. A report is historical and does not establish the current iPhone state.' };
  }
  close() { this.db.close(); }
}
