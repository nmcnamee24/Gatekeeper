import { connect } from 'node:http2';
import { createPrivateKey, sign } from 'node:crypto';

export function createAPNs(env = process.env) {
  if (!env.APNS_KEY_ID || !env.APNS_TEAM_ID || !env.APNS_PRIVATE_KEY) return null;
  if (!env.APNS_TOPIC) throw new Error('Set APNS_TOPIC to the iPhone app bundle identifier when enabling push.');
  const key = createPrivateKey(env.APNS_PRIVATE_KEY.replace(/\\n/g, '\n'));
  let cached, issued = 0;
  return async ({ token, environment }, alert = false, expires = Date.now() + 300000) => {
    const now = Math.floor(Date.now() / 1000);
    if (!cached || now - issued > 3000) {
      const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: env.APNS_KEY_ID })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ iss: env.APNS_TEAM_ID, iat: now })).toString('base64url');
      const data = `${header}.${payload}`;
      cached = `${data}.${sign('sha256', Buffer.from(data), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
      issued = now;
    }
    return await new Promise((resolve, reject) => {
      const session = connect(environment === 'sandbox' ? 'https://api.sandbox.push.apple.com' : 'https://api.push.apple.com');
      let finished = false;
      const finish = (error, value) => {
        if (finished) return; finished = true; clearTimeout(timeout); session.destroy();
        error ? reject(error) : resolve(value);
      };
      const timeout = setTimeout(() => finish(new Error('APNs timeout')), 8000);
      session.on('error', () => finish(new Error('APNs connection failed')));
      const req = session.request({ ':method': 'POST', ':path': `/3/device/${token}`,
        authorization: `bearer ${cached}`, 'apns-topic': env.APNS_TOPIC,
        'apns-push-type': alert ? 'alert' : 'background', 'apns-priority': alert ? '10' : '5',
        'apns-expiration': String(Math.floor(expires / 1000)), 'apns-collapse-id': alert ? 'gatekeeper-action' : 'gatekeeper-sync' });
      let status;
      req.on('response', headers => { status = headers[':status']; });
      req.on('data', () => {});
      req.on('error', () => finish(new Error('APNs request failed')));
      req.on('end', () => finish(null, { accepted: status === 200, status }));
      req.end(JSON.stringify({ aps: alert ? {
        alert: { title: 'Muse approved your request', body: 'If access hasn’t started, hold this notification and choose Start access.' },
        category: 'GATEKEEPER_APPROVAL', sound: 'default'
      } : { 'content-available': 1 } }));
    });
  };
}

// A durable outbox survives deploys. Payloads only wake the phone; they never carry grants or credentials.
export class PushDelivery {
  constructor(store, send) {
    this.store = store; this.send = send; this.running = false; this.nextAttempt = 0;
    store.db.exec(`CREATE TABLE IF NOT EXISTS push_device (id INTEGER PRIMARY KEY CHECK(id=1), token TEXT NOT NULL, environment TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS push_jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, silent INTEGER NOT NULL DEFAULT 0, alert INTEGER NOT NULL DEFAULT 0);`);
  }
  register(token, environment) {
    this.store.db.prepare('INSERT INTO push_device VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET token=excluded.token, environment=excluded.environment').run(token, environment); // gitleaks:allow -- SQL column names, not a credential.
    return { received: true };
  }
  enqueue(id, kind, expires = Date.now() + 300000) {
    this.store.db.prepare('INSERT OR IGNORE INTO push_jobs(id,kind,created,expires) VALUES(?,?,?,?)').run(id, kind, Date.now(), expires);
    return { configured: Boolean(this.send), registered: Boolean(this.store.db.prepare('SELECT id FROM push_device').get()), delivery: 'queued_not_confirmed' };
  }
  status() {
    return { configured: Boolean(this.send), deviceRegistered: Boolean(this.store.db.prepare('SELECT id FROM push_device').get()) };
  }
  async tick() {
    if (this.running || !this.send || Date.now() < this.nextAttempt) return;
    const device = this.store.db.prepare('SELECT token,environment FROM push_device').get();
    if (!device) return;
    this.running = true;
    try {
      this.store.db.prepare('DELETE FROM push_jobs WHERE expires <= ?').run(Date.now());
      for (const job of this.store.db.prepare('SELECT * FROM push_jobs ORDER BY created LIMIT 10').all()) {
        const pending = this.store.pending();
        if (job.kind === 'approve' && pending?.id !== job.id) {
          this.store.db.prepare('DELETE FROM push_jobs WHERE id=?').run(job.id); continue;
        }
        const alert = job.silent === 1 && job.kind === 'approve' && Date.now() - job.created >= 15000;
        if (job.silent && (!alert || job.alert)) continue;
        try {
          const result = await this.send(device, alert, job.expires);
          if (result.accepted) this.store.db.prepare(`UPDATE push_jobs SET ${alert ? 'alert' : 'silent'}=1 WHERE id=?`).run(job.id);
          else if ([400, 403, 410].includes(result.status)) {
            // Invalid provider credentials or device registration must be fixed before retrying.
            console.error(`APNs rejected delivery (${result.status}); check push configuration.`);
            this.store.db.prepare('DELETE FROM push_jobs WHERE id=?').run(job.id);
          } else { this.nextAttempt = Date.now() + 30000; break; }
        } catch { this.nextAttempt = Date.now() + 30000; break; }
      }
    } finally { this.running = false; }
  }
}
