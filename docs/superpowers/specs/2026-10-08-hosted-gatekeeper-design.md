# Hosted Gatekeeper

Build the consumer iOS product approved in the conversation: install, sign in,
select apps, explain a concrete purpose and exit plan, ask for 1–15 whole minutes,
and automatically relock. Keep the personal SQLite/Muse deployment working.

## Product and invariants

- Built-in conversational approval is the default. External MCP agents connect
  through OAuth with explicit per-user consent and revocable scopes.
- The model never owns timing or device permissions. Server and device enforce
  one-use grants, 1–15 minutes, a five-minute redemption deadline, and 30-minute
  cooldown from the approved end, including after early close.
- Approvals remain distinct from phone-confirmed access. No remote response may
  falsely claim that shielding changed. Offline phones retain their local timer.
- Use real PostgreSQL, with transactions and per-account locking across workers.
  All credentials, grants, reports, conversation records, jobs and billing rows
  are scoped to user identity. Device redemption is bound to the selected phone.
- Initial beta can be free; paid access uses StoreKit verified on the server.
  Subscription products and AI configuration come from provider accounts.
- Identity uses native Sign in with Apple with a server-issued nonce challenge,
  JWKS verification and opaque access/rotating refresh sessions. Device tokens
  are registered automatically and stored in Keychain. Never expose model keys.
- Delete accounts and their records, revoke sessions and agent connections,
  support clearing conversation history, and disclose AI processing consent.
- Keep app selection tokens on the phone. Retain minimal request history with
  bounded retention; retain timing facts long enough to preserve cooldown.

## HTTP contract, version 1

All JSON uses camelCase. Errors are {error:string,code:string}; 200 for success.
Production API origin is a build setting (GATEKEEPER_API_ORIGIN), not typed by
customers. Existing /device/* shapes are retained on the hosted origin.

Public:
- POST /v1/auth/challenge -> {challengeId,nonce,expiresAt}
- POST /v1/auth/apple {challengeId,identityToken,authorizationCode,deviceName,
  installationId} -> HostedSession (below).
- POST /v1/auth/refresh {refreshToken} -> HostedSession; rotates both credentials.
- GET /health: liveness; GET /ready: database and configuration readiness.

HostedSession = {user:{id,displayName?},accountToken,refreshToken,expiresAt,
  device:{id,token,name},apiOrigin}. Re-auth registers/reuses the account's
  installationId. The device's token authorizes only device endpoints.

Account bearer:
- GET /v1/account -> {user,devices,aiConsentVersion,entitlement}
- DELETE /v1/account -> {deleted:true}; native client removes local credentials.
- POST /v1/account/consent {version:"2026-10-08"} -> {received:true}
- DELETE /v1/conversation -> {deleted:true}
- GET /v1/conversation -> {messages:[{id,role,content,createdAt}]}
- POST /v1/conversation {requestId,message,durationMinutes,deviceId} ->
  {reply,decision:"ask"|"deny"|"approve",approval?:existingApprovalView}.
  Only approve after concrete purpose and exit plan; duration is never longer
  than the user-selected value. Missing provider configuration fails closed.
- GET /v1/devices -> {devices:[{id,name,lastSeenAt,revokedAt}]}
- DELETE /v1/devices/:id -> {revoked:true}; revoke device credential and passes.
- POST /v1/access/end {deviceId} -> {status:"end_requested"}; native app also
  immediately shields locally. Cooldown persists.
- GET /v1/billing/products -> {productIds:[string],betaAccess:boolean}
- POST /v1/billing/transaction {signedTransaction} -> entitlement. Validate
  Apple's certificate chain, bundle, product, environment and appAccountToken.

Device bearer:
- GET /device/state -> {pendingGrantId,lastGrantId,lastGrantRevoked}
- POST /device/redeem {grantId} -> {grantId,windowSeconds,endsAt}
- POST /device/report {state,grantId?,localExpiry?} -> {received:true}
- POST /device/push {token,environment} -> {received:true}

MCP: /mcp uses OAuth agent-scoped bearer tokens, not account/device tokens.
Advertise protected-resource and authorization-server metadata. PKCE S256,
redirect URI validation, resource/audience binding, single-use codes, rotating
refresh credentials and disconnect/revoke are required. Approval carries the
selected deviceId, purpose, exitPlan, durationMinutes and requestId.

## Deployment and release

New hosted service and managed Postgres; do not replace personal SQLite service.
HTTP replicas + durable Postgres push outbox claimed with SKIP LOCKED; retry
transient APNs errors, invalidate stale device tokens, never treat push as unlock.
Add Docker Compose for reproducible development and CI with Postgres integration
and native simulator builds. Provide account-isolation/concurrency tests and
provider failure tests. Document restore, deletion and release acceptance.

Release gates: real Apple identity/account configuration; AI key; Family Controls
and app-extension distribution entitlement; real-phone relock evidence; StoreKit
product configuration before paid launch; privacy/support URLs and review notes.
No mocks, unsigned builds, test JWTs or Apple approval requests prove release.
