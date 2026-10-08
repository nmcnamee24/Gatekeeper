# Hosted store and identity contract

`HostedStore(pool | {pool, clock?})` exposes `.pool`, `migrate()` and
`withUserLock(userId, fn(client))`. The latter begins a transaction and locks the
user row; every grant/device/session mutation takes that same account lock.
UUID identifiers and all children reference `gk_users(id)` with deletion cascade.
Migration calls are safe across workers. Time is milliseconds internally and ISO
strings in public responses; PostgreSQL timestamps store the durable facts.

`authenticate(token, kind?)` returns `{userId,deviceId,kind,sessionId,scopes}` or
throws `HostedError` with `.status` and `.code`. Device credentials return kind
`device`, null sessionId, scopes `[]`. Session kinds are `account` and `agent`.
Opaque credentials are SHA-256 hashed at rest. `createSession(userId, options)`
returns `{accountToken,refreshToken,expiresAt,sessionId,userId,deviceId,kind,scopes}`.
`refreshSession` rotates both tokens once and returns the same shape plus `device`
when device-bound. Refresh also rotates the installation credential so the exact
HostedSession can be reconstructed without storing plaintext credentials. Any
client must atomically persist all refreshed credentials. Default access lifetime
is one hour and refresh lifetime is 30 days. Revoked devices revoke bound sessions.

`registerDevice(userId,{installationId,name})` creates/reuses only that account's
installation and rotates its independent credential; returns `{id,token,name}`.
`account()` returns `{user,devices,aiConsentVersion,entitlement}` with entitlement
null until the billing adapter supplies it. `upsertUser` returns `{id,displayName}`.
`deleteAccount` cascades every user-owned record. All device-targeted operations
validate account ownership and revocation.

Policy APIs retain the existing legacy JSON views: `approve(userId,input)`,
`redeem(userId,deviceId,grantId)`, `status(userId,deviceId?)`,
`deviceState(userId,deviceId)`, `report(userId,deviceId,input)`,
`endAccess(userId,deviceId?)`. Approval requires explicit `deviceId`; request IDs
are unique per account and retries must match purpose, exitPlan, device and whole
minute duration. One pending/active pass spans all account devices. Cooldown is a
separate durable user timing column, advanced only on redemption and retained
through grant retention, revocation and early end.

`registerPush(userId,deviceId,{token,environment})` accepts sandbox/production.
Approvals and early-end enqueue `gk_push_jobs` atomically. `claimPushJobs(limit)`
returns rows `{id,user_id,device_id,event,grant_id,apns_token,apns_environment,
lease_token,...}`. Jobs use expiring 60 second leases and SKIP LOCKED.
`completePushJob(job,result?)` accepts `{invalidToken:true}` to clear the matching
APNs token. `retryPushJob(job)` releases a lease with bounded exponential backoff.
Both require the returned lease_token and ignore stale completions. Push never
changes redemption or reports. `pruneHistory(retentionDays=30)` erases old grant
purpose/exit plan and expired challenge/session rows while preserving cooldown.

`HostedIdentity({store,apiOrigin,appleAudience,verifyIdentityToken?,appleProvider?})`
exposes `challenge`, `login`, `refresh`, `delete`. Challenges return
`{challengeId,nonce,expiresAt}` and expire after five minutes. Native Apple login
sends the SHA-256 nonce in the ID token. An injected verifier takes
`(identityToken,{audience,issuer,nonce})` and must return verified claims; identity
still enforces issuer, audience, expiry and nonce. Default uses Apple's remote
JWKS with jose. Challenge consumption and account/session creation are atomic;
verified replay cannot create another session. Optional `appleProvider` exchanges
an authorization code and revokes stored Apple refresh credentials on deletion.
The configured provider needs an Apple client ID/client secret; secrets are not
returned by API responses. HostedSession is exactly
`{user,accountToken,refreshToken,expiresAt,device:{id,token,name},apiOrigin}`.

For conversation transactions, `approveInTransaction(client,user,input)` performs
all approval validation and outbox creation using the already-locked user row
(`user.id`). Call it only inside `withUserLock`; never nest the public `approve`
in that transaction. A failed conversation write rolls back both grant and push.
Grant `ordinal` provides insertion order when timestamps tie, so device state
reports the most recently inserted pass.

The identity constructor also accepts `appleClientSecret` (string or async secret
factory), creating the production `AppleAuthProvider`, and `tokenEncryptionKey`
(32-byte Buffer or base64 string). Apple refresh tokens are encrypted with AES-256
GCM. Configure a durable, backed-up encryption key; losing it prevents token
revocation. Revocation failure preserves the account and credentials for retry.
Without a provider, token signature/JWKS validation still works, but deletion
cannot revoke Apple authorization; this is a release configuration gate.
`AppleAuthProvider({clientId,clientSecret,fetch?})` exposes `exchange(code)` and
`revoke(refreshToken)`. The exchange token, when present, is independently verified
and must have the same Apple subject and nonce as the submitted identity token.

Identity references: [Apple user verification](https://developer.apple.com/documentation/signinwithapple/verifying-a-user),
[authorization-code exchange](https://developer.apple.com/documentation/signinwithapplerestapi/generate-and-validate-tokens),
and [token revocation](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens).
Tests use real PostgreSQL and cryptographically signed JWTs, plus an injected
Apple HTTP boundary. They establish local behavior, not Apple account setup,
production revocation, APNs delivery or native shielding/relocking.

The matching end hook is `endAccessInTransaction(client,user,deviceId?)`.
Revalidate the acting credential while holding the account lock, then invoke this
hook or `approveInTransaction` using that same transaction client. A credential
check before waiting for the account lock does not prevent a concurrent disconnect
from committing before the action.

Account sessions have an absolute 30-day family lifetime. Rotation preserves kind,
scopes and the original family expiry, and caps access expiry at that deadline.
Reusing a successfully consumed refresh credential commits revocation of every
session in that family before returning `unauthorized`; other login families and
the independent device credential remain valid. Phone revocation revokes every
bound session regardless of family. Re-registering a revoked installation creates
fresh credentials and never revives its old sessions or refunds cooldown.

Privacy pruning also deletes old device reports and expired uncompleted push work,
clears APNs credentials on long-revoked devices, and removes credentials/challenges
at their exact expiry boundary. Active push leases and current pending passes are
preserved. Minimal grant timing, request identifiers and retry fingerprints remain
for policy/idempotence; text is removed once. PostgreSQL indexes support per-user
cascade/revocation and retention without repeatedly rewriting scrubbed rows.

A cross-schema integration regression initializes real conversation, OAuth and
billing schemas, then verifies account deletion removes devices, sessions, grants,
reports, push work, messages, exchanges, user AI usage, OAuth connections/requests/
tokens, subscriptions and billing events. It preserves another account and the
anonymous global usage aggregate. Account-first locking must also be maintained
by OAuth and billing mutations to avoid lock inversions during deletion.

Account refresh validates stored Apple authorization through
`AppleAuthProvider.refresh(appleRefreshToken)` before rotating local credentials.
The provider sends `grant_type=refresh_token` with the bound client ID and secret.
The returned ID token must pass signature, issuer, audience, subject and current
expiry validation; the refresh response can omit the original login nonce. Login
continues to require the server challenge nonce.

Apple explicitly permits refresh-token verification up to once per day and may
throttle more frequent requests. The first hosted account refresh checks Apple;
a successful result is cached on the account for at most 24 hours. The next
account refresh after that interval validates again. A recurring authorization sweep also validates due accounts independently of
native refresh. Native credential-state checking handles local changes
independently. Server-to-server Apple event handling is not implemented.

`gk_users.apple_refresh_client_id` binds the stored encrypted token to its issued
client ID, and `apple_verified_at` records the last successful refresh validation.
A changed/missing client binding, disabled provider, or unavailable encryption key
returns a configuration 503 and preserves credentials. Existing stored tokens with
no client binding require a new Apple sign-in; migration does not guess identity.
Provider-free injected identities with no stored Apple token remain usable locally.

Only a typed `AppleTokenError` for HTTP 400 `invalid_grant` from a correctly bound
refresh-token request causes revocation. In the account transaction, all user
sessions, devices, outstanding grants and OAuth connections/tokens are marked
revoked, then 401
`apple_authorization_revoked` is returned after commit. The account and its data
remain for reauthentication or deletion. Network failures, throttling, server
errors, `invalid_client`, malformed responses and wrong/tampered identities return 503
without rotating or consuming the local refresh credential. A supplied replacement
Apple refresh token is stored encrypted only after its ID token verifies.

Refresh validation, local rotation, deletion and connection revocation share the
account-first lock order. `refreshSession(token,kind,beforeRotate?)` exposes the
in-transaction validation hook; a returned `HostedError` commits its intentional
revocation or retry-scheduling changes before surfacing the authentication error.
Transient failures update only scheduling; local credentials stay intact. Tests cover both refresh/deletion lock orders and
parallel independent session families sharing one daily Apple check.

Sources: [Apple session verification and daily limit](https://developer.apple.com/documentation/signinwithapple/verifying-a-user),
[refresh validation request/response](https://developer.apple.com/documentation/signinwithapplerestapi/generate-and-validate-tokens),
[Apple response-error guidance](https://developer.apple.com/documentation/technotes/tn3107-resolving-sign-in-with-apple-response-errors).
Live Apple refresh validation, throttling behavior and revoked-authorization tests
with the production App ID remain release acceptance work; local JWT/HTTP fixtures
do not establish those provider outcomes.

`HostedIdentity.sweepAppleAuthorizations({limit=20}={})` returns
`{configured,claimed,checked,revoked,retried,skipped}`. The batch limit is 1–20;
provider/key configuration must be available before work is claimed. The root
service calls this nonblockingly at startup and every 60 seconds with a local
in-flight guard. An index on `apple_next_check_at` selects oldest due accounts.
`FOR UPDATE SKIP LOCKED` claims them across replicas with a five-minute lease;
each claim is revalidated under the same account lock used by native refresh,
policy changes and deletion. Expired claims recover after worker loss. Cached
successful checks, including reauthentication, preserve the daily schedule.

Success schedules the next check 24 hours later. Transient/configuration failures
commit a persisted retry schedule starting at 60 seconds, doubling to a six-hour
cap. Native refresh shares that schedule, and retries during backoff do not
consume credentials, increment attempts or contact Apple again. Successful retry
resets attempts. Authoritative revocation stops future sweeps until a fresh Apple
sign-in establishes authorization again. No provider failure is treated as proof
of revocation.

Authoritative `invalid_grant` atomically marks the account's devices, pending and
active grants, sessions and agent connections/tokens revoked and queues a best-
effort end notification. Approved end/cooldown timestamps remain unchanged. A
copied phone/agent credential cannot avoid these checks by remaining outside the
native refresh flow. The durable `apple_authorization_revoked_at` marker also
blocks stale restored credential rows, device registration and session issuance.
The OAuth layer checks that marker when consent, token exchange and token
verification occur. Fresh verified Apple sign-in clears it, rotates the native
credentials, and reuses that account's installation; old sessions/connections and
revoked grants remain revoked. This does not confirm an offline phone relocked;
its existing local timer and native credential-state handling still apply.

With healthy providers, available workers and no backlog, server detection takes
at most the 24-hour verification cache plus the 60-second scheduling interval and
provider/queue processing time. Worker loss can add lease recovery time. Provider
outages, configuration errors or a growing backlog remove a guaranteed bound;
monitor sweep counters/due-age and scale batch workers as needed. Live Apple
revoked-authorization and throttling validation remain release acceptance gates.
