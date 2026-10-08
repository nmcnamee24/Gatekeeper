# Hosted subscriptions and the free beta

Gatekeeper starts with free beta access. `HostedBilling` defaults `betaAccess` to
`true`; the account response reports `active: true`, `betaAccess: true` and
`subscriptionActive: false` until a verified current subscription exists. This
is beta access, not a purchased product. No App Store Connect product, price,
subscription approval, TestFlight purchase or payment delivery has been verified
by these local changes.

## Server contract

Create `HostedBilling({pool,bundleId,appAppleId,environment,productIds,betaAccess})`
after running the hosted user schema, including its unique
`purchase_account_token uuid` column. `await billing.init()`
creates `gk_subscriptions` and `gk_billing_events`; migrations serialize across
replicas using a PostgreSQL advisory lock. Both tables reference the user with
`ON DELETE CASCADE`. Billing retains identifiers and timing facts, without
storing full JWS payloads or payment details.

- `products()` returns `{productIds,betaAccess}`. Product IDs must come from the
  actual App Store Connect configuration. The empty default asserts no product.
- `entitlement(userId)` returns `{active,betaAccess,subscriptionActive}` and, when
  available, `productId`, `transactionId`, ISO `expiresAt` and ISO `revokedAt`.
- `recordTransaction(userId,signedTransaction)` verifies the Apple JWS, binds its
  `appAccountToken` to that user's stable `purchaseAccountToken`, applies it atomically, and returns the
  current entitlement. The authenticated HTTP route must supply its session's
  user ID; callers cannot select another account in their JSON request.
- `handleNotification(signedPayload)` verifies the notification and its nested
  transaction, returning `{received:true,updated?:boolean,duplicate?:boolean,
  ignored?:boolean}`. The public HTTP callback passes only the signed payload.
  Notifications without a transaction are acknowledged without changing access.
- `requireAccess(userId)` returns the entitlement or throws
  `subscription_required` with HTTP status 402.

The server supports only `Production` and `Sandbox`. `Xcode` and `LocalTesting`
are disabled because Apple's library skips App Store signature verification in
those environments. The production entrypoint creates both strict verifiers
behind `HostedBillingRouter` on one API origin. An untrusted JWS environment hint
only selects a verifier; it never supplies authority. Production entitlement
reads only Production rows. Sandbox access additionally requires a current
15-minute, hardware-bound device proof and is labeled `sandbox_test`.
Both notification environments use `/v1/billing/notifications`; notifications
cannot classify a device. AI/MCP approvals and device redemption recheck access
under the account lock. Sandbox grants cannot redeem after reclassification.

`HostedDeviceProof` checks Apple's signed AppTransaction and its current-device
SHA-384 binding, plus Production App Attest over a fresh server challenge and
canonical payload. TestFlight uses Production App Attest with Sandbox StoreKit.
Every new challenge retires earlier device challenges and its previous lease;
assertion counters and PostgreSQL locks prevent replay across replicas. Raw
AppTransaction payloads and device-verification UUIDs are not retained.

`PURCHASE_BINDING_KEY` is a separate durable 32-byte base64 secret. The server
derives the purchase UUID from the verified Apple subject and app identity with
a versioned HMAC namespace. A non-user configuration fingerprint pins this key
even after all accounts are deleted; ordinary encryption-key rotation must not
change it. Recreating the same verified Apple identity restores the same token
with a new random database ID. No per-account recovery ledger survives deletion.
Existing purchases issued with random account IDs require an authenticated
migration before initializing this new binding; startup fails rather than
silently replacing them. Do not rotate this key or app identity casually.

Paid verification requires the exact bundle ID, configured subscription product
IDs, and a numeric App Store app Apple ID in Production. Missing configuration or
unreadable/mismatched pinned certificates leaves `configurationError` set;
transaction/notification verification throws `billing_unconfigured` with status
503. Free beta access remains available. Set `betaAccess: false` only once the
paid configuration and purchase flow have passed the external acceptance gates.
Existing paid rows cannot grant access when verification configuration is absent.

## Verification and durable ownership

Production code uses Apple's `@apple/app-store-server-library` `SignedDataVerifier`
with the locally pinned [Apple root certificates](../connector/config/apple-root-certificates/README.md)
and online OCSP checks enabled. It verifies chain signatures, Apple purpose
extensions, certificate dates, bundle ID and environment. Production notification
verification also checks the expected app Apple ID. There is no unsigned JWS
fallback. Retryable provider/OCSP failures return
`billing_verification_unavailable` with status 503; they never record a new
entitlement. Already verified access continues only through its stored expiry.

Only configured auto-renewable subscription transactions are eligible. Dates and
identifiers are validated. Revoked or expired subscriptions provide no paid
access. Grace periods and billing retry do not extend access in this initial
implementation; entitlement remains conservative at the verified expiry.

The original transaction ID belongs to one account per environment. A
transaction-scoped advisory lock protects even the first insert across workers;
the account row is locked first, matching account deletion and preventing
deletion/update deadlocks. Ownership found before locking is checked again under
that lock. Other accounts cannot reassign that row. Client uploads always require their
matching account token. A verified notification can find the previous verified
owner when its transaction omits the token, or associate a token with an existing
Gatekeeper account. Unknown accounts are acknowledged and ignored. Account
deletion erases the billing records as part of the database cascade.

Transaction event hashes and notification UUIDs provide idempotency. The current
subscription snapshot orders by purchase date, then signed date. A late refund
for an older billing period cannot replace a more recent renewal. Equal snapshots
cannot undo a revocation. Notifications that disable automatic renewal preserve
access through the verified current expiry; they do not imply an immediate
cancellation of paid access.

## Local evidence and external release gates

Run from the repository root with a real test PostgreSQL instance:

```sh
TEST_DATABASE_URL=postgresql://gatekeeper@127.0.0.1:55439/gatekeeper_test node --test connector/test/hosted/billing.test.js
```

Each test uses a unique schema and cleans up after itself. Tests cover account
isolation, parallel ownership claims, parallel schema initialization, deletion,
expiry/revocation, environment separation and out-of-order/idempotent callbacks.
Concurrent account deletion tests reproduce the child/account lock inversion
and verify that updates now terminate without deadlocks or recreated records.
Decoded semantic fixtures replace only the external verifier and do not prove an
Apple purchase. Additional tests generate a real ES256 certificate chain and
signed JWS, exercise the actual Apple verifier, and reject signature tampering,
unsigned tokens, bundle mismatches, sandbox data at a Production verifier, and a
foreign trust chain against the official pinned roots. Their custom roots are
passed only through an in-process test seam; runtime/environment configuration
cannot select them. The tests require Node, PostgreSQL and OpenSSL.

An Xcode `.storekit` configuration is useful for native purchase UI development,
but its locally signed transactions do not satisfy the hosted Production or
Sandbox verifier. Before charging consumers, configure the actual subscription
group/products and app in App Store Connect, supply the server's matching
configuration, set the signed server-notification URLs, and test on a real
TestFlight/sandbox account with StoreKit purchase, restore, renewal, expiry,
refund/revocation, cancellation and callback retry. Purchase must include the
server-issued stable `purchaseAccountToken` as StoreKit's `appAccountToken`. Confirm
renewals still update after the app is closed and that notifications cannot grant
access across accounts or environments. Verify storefront pricing and required
subscription disclosures from live `Product` metadata; do not hardcode a price.

Gatekeeper account deletion does not cancel an App Store subscription. The native
account flow must explain this and provide Apple's subscription management UI.
Also verify Family Controls distribution entitlements, real-phone relocking,
privacy/support URLs, billing disclosure, account deletion and App Review notes.
Local tests and simulator purchase UI are not proof of those release gates.

The initial release does not offer promoted purchases, win-back/contingent
offers, offer/promo codes or Family Sharing. Unknown unbound transactions are
rejected; possession of a signed receipt does not authorize moving a purchase
to a Rook account. Test these additional purchase routes and ownership linking
before enabling them. Streamlined Purchasing's default ON state alone does not
enable such promotions; OFF requires an already approved PurchaseIntent binary.
