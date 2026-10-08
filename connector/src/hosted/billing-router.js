import { HostedError } from "./errors.js";

// This hint chooses a strict verifier, never authority. The selected verifier
// must independently verify the entire JWS and its configured environment.
function environmentHint(jws, notification = false) {
  try {
    if (typeof jws !== "string" || jws.length > 100000) throw new Error();
    const parts = jws.split(".");
    if (parts.length !== 3 || !parts.every(p => /^[A-Za-z0-9_-]+$/.test(p))) throw new Error();
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    const environment = notification ? payload.data?.environment : payload.environment;
    if (!["Production", "Sandbox"].includes(environment)) throw new Error();
    return environment;
  } catch { throw new HostedError("Invalid Apple signed data.", "invalid_signed_data", 400); }
}
export class HostedBillingRouter {
  constructor({production,sandbox,deviceProof}) {
    if (production.environment !== "Production" || sandbox.environment !== "Sandbox" || sandbox.betaAccess)
      throw new Error("Billing requires strict Production and non-beta Sandbox lanes");
    this.production=production; this.sandbox=sandbox; this.deviceProof=deviceProof;
    this.pool=production.pool;
  }
  get configurationError() { return this.production.configurationError ?? this.sandbox.configurationError; }
  products() { return this.production.products(); }
  async entitlement(userId, executor=this.pool, deviceId) {
    const paid=await this.production.entitlement(userId,executor);
    let access={available:paid.active,mode:paid.betaAccess ? "beta" : paid.subscriptionActive ? "production_paid" : null,deviceId:deviceId ?? null};
    if (!paid.active && deviceId && await this.deviceProof?.accessEnvironment(userId,deviceId,executor)==="Sandbox") {
      const test=await this.sandbox.entitlement(userId,executor);
      if (test.subscriptionActive) access={available:true,mode:"sandbox_test",deviceId,expiresAt:test.expiresAt};
    }
    return {...paid,access};
  }
  async requireAccess(userId,executor=this.pool,deviceId) {
    const entitlement=await this.entitlement(userId,executor,deviceId);
    if (!entitlement.access.available) throw new HostedError("An active subscription is required.","subscription_required",402);
    return entitlement;
  }
  async requireSandboxDevice(userId,deviceId,executor=this.pool) {
    if (!deviceId || await this.deviceProof?.accessEnvironment(userId,deviceId,executor)!=="Sandbox")
      throw new HostedError("Verify this test installation before using sandbox purchases.","store_device_verification_required",403);
  }
  async recordTransaction(userId,signedTransaction,deviceId) {
    const environment=environmentHint(signedTransaction);
    if (environment==="Sandbox") await this.requireSandboxDevice(userId,deviceId);
    await (environment==="Production" ? this.production : this.sandbox).recordTransaction(userId,signedTransaction);
    return this.entitlement(userId,this.pool,deviceId);
  }
  async handleNotification(signedPayload) {
    const environment=environmentHint(signedPayload,true);
    return (environment==="Production" ? this.production : this.sandbox).handleNotification(signedPayload);
  }
  async assertRedemption(userId,executor,deviceId,source) {
    if (source==="sandbox_test") await this.requireSandboxDevice(userId,deviceId,executor);
    return this.requireAccess(userId,executor,deviceId);
  }
}
