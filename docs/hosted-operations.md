# Rook hosted beta

Rook is the consumer app name. The existing Gatekeeper bundle IDs and technical
identifiers remain stable. The personal SQLite/Muse server is separate and is not
migrated into the hosted service.

## Development

Use Node 24.4 or newer, Docker, Xcode, and XcodeGen. From the repository root:

```sh
node scripts/InitHostedConfig.mjs
docker compose -f connector/compose.hosted.yml up -d postgres
npm --prefix connector ci
TEST_DATABASE_URL=postgresql://rook:local-development-only@127.0.0.1:55440/rook npm --prefix connector run test:all
```

The script creates a private, mode-0600 configuration with separate fresh encryption and purchase-binding keys,
and preserves an existing file. Set the local DATABASE_URL to the database above
for a process running on the Mac. Configure Apple and AI privately in
`connector/.env.hosted`. Start locally with `npm --prefix connector run start:hosted`,
or `docker compose -f connector/compose.hosted.yml up --build api`. The container
uses the Compose database's private hostname. Local database credentials are
for development only. Compose binds ports to loopback; `down` retains its volume.

The hosted local API uses port 8788 so it can coexist with the personal server on 8787.

There is no public mock login. Tests use fixtures inside disposable database
schemas; these fixtures cannot authenticate against the deployed server. Missing
provider configuration returns a clear unavailable response and grants no access.

```sh
xcodegen generate
swift test
swiftc App/HostedClient.swift scripts/VerifyHostedClient.swift -o /tmp/rook-client-check
/tmp/rook-client-check
xcodebuild test -project Gatekeeper.xcodeproj -scheme Gatekeeper -destination 'platform=iOS Simulator,name=iPhone 17' CODE_SIGNING_ALLOWED=NO
```

Choose an installed iPhone simulator if its name differs. Debug previews are
explicitly labeled fixtures and cannot authenticate, register push or change
protection. Release excludes them.

## Hosted infrastructure

Use an isolated hosted project with managed PostgreSQL and a separate service.
Do not deploy Dockerfile.hosted over the existing personal Gatekeeper service.
The hosted container copies `src` plus pinned Apple root certificates in `config`,
uses an unprivileged Node user, and starts `src/hosted/main.js`.
Railway deployment health checks and restart limits are service settings. Current
Railway rejects configuring the deprecated railway.json/railway.toml path; the
hosted helper uploads a Dockerfile without relying on those files. For a new
hosted service, use the current official Railway CLI's public API to configure
`healthcheckPath=/health`, `healthcheckTimeout=120`, `restartPolicyType=ON_FAILURE`
and `restartPolicyMaxRetries=3`, then confirm the next deployment's resolved
service manifest includes them. See https://docs.railway.com/infrastructure-as-code
if adopting a reproducible infrastructure configuration later.

Verified beta infrastructure created on 2026-10-08:

- Railway project Rook-beta: `ff0eb59d-3864-498d-8e7f-b89aac071a7a`
- Environment: `8d5e44db-d2c1-4652-9973-50dd5353e057` (Railway calls it production;
  this is the isolated beta project, not the personal production project)
- Hosted service: `6b11bf45-57d9-44f4-a7be-e3d68cd60e55`
- PostgreSQL service: `31bd7b8b-e1db-41cd-90d0-e09c11fd11c4`
- API hostname: `api.rooklayer.com`, CNAME `w9wwkaks.up.railway.app`
- Railway ownership TXT at `_railway-verify.api` is verified. HTTPS, process
  liveness, privacy/support pages, OAuth metadata and unauthenticated rejection
  were checked through normal certificate validation.
- Vercel keeps the existing rooklayer.com website and Google Workspace MX records.
- Google Workspace alias support@rooklayer.com belongs to noah@rooklayer.com.
  The alias assignment is verified; an end-to-end email delivery test was not sent.

Deploy with an explicit verified project, service, and environment. The helper
uploads an isolated source-only build context with the hosted Dockerfile, never
local env files, the SQLite database, or the personal server's Dockerfile:

```sh
railway link --project ff0eb59d-3864-498d-8e7f-b89aac071a7a --environment 8d5e44db-d2c1-4652-9973-50dd5353e057 --service 6b11bf45-57d9-44f4-a7be-e3d68cd60e55
node scripts/DeployHosted.mjs --project ff0eb59d-3864-498d-8e7f-b89aac071a7a --service 6b11bf45-57d9-44f4-a7be-e3d68cd60e55 --environment 8d5e44db-d2c1-4652-9973-50dd5353e057
```

The database reference is `${{Postgres.DATABASE_URL}}`. Preserve the private
CREDENTIAL_ENCRYPTION_KEY across replicas and restarts; replacing it makes stored
Apple refresh tokens and pending OAuth decisions unreadable. Back it up with your
other production secrets. Never include secrets in CLI output, commits or reports.

The original Gatekeeper push key is sandbox-only. The hosted sender routes sandbox
and production tokens to separate credentials; missing production credentials do
not fall back to the sandbox key. APNS_ENVIRONMENT declares the base key scope.
APNS_PRODUCTION_KEY_ID/TEAM_ID/PRIVATE_KEY configure the production-only key.

Required configuration is listed in connector/.env.hosted.example. The free beta
uses BETA_ACCESS=true and no invented StoreKit products. The dedicated AI Gateway
key created for this beta has a $5 total spend cap, no replenishment, and a 90-day
expiry. GPT-4.1 mini was checked live through the gateway; GPT-5.4 mini was rejected
by the account's free-credit restrictions. The public candidate restricts model selection and Gateway routing to the disclosed OpenAI provider. Provider changes require new disclosure review.
Four initial live decision cases passed; these are a smoke test, not a model-safety
guarantee or large-scale evaluation.

`/health` reports process liveness. `/ready` checks database and provider/account
configuration and returns 503 until required setup is present. Liveness is not
Apple authentication, model availability, APNs delivery, or subscription proof.
No request content or credentials are written to application logs.

## Scaling, retention and recovery

Account-row transactions serialize grants, device revocation, billing/OAuth
writes and deletion. Quotas live in PostgreSQL and work across replicas. HTTP
workers have no durable local account state. Push jobs use leased SKIP LOCKED
claims; APNs acceptance is a wakeup attempt, never proof of access. Expired or
redeemed approvals are not delivered. Credential/payload errors retain valid
device registrations for retry; only explicit invalid-token responses clear them.

Conversation context/history is bounded to 30 days. Clear history removes text,
including grant purpose/exit-plan copies, and cached replies while preserving
cooldown, idempotency tombstones and quota.
Startup/hourly maintenance scrubs old grant text, reports, session families,
expired OAuth secrets/tokens and request-budget digests. Account deletion cascades
owned rows; aggregate global counts remain without an account identifier. A phone
can keep enforcing its already-started local timer while offline.

Before production, enable database backups in Railway and perform a restore
rehearsal into an isolated database with the original encryption and purchase-binding keys. Check row
counts, read-only status and expired-pass rejection before any traffic switch.
Disable outgoing APNs during the rehearsal. Do not restore erased accounts into
a live service: maintain a deletion ledger outside ordinary backup snapshots or
reconcile deletions before switching traffic. Backup retention and deletion
reconciliation require an operator policy before public launch.

## Release acceptance

Apple approved Family Controls distribution on 2026-10-08. The capability is
enabled for both com.noah.gatekeeper and com.noah.gatekeeper.monitor. App Store
export succeeded with regenerated distribution profiles: both include Family
Controls, the app includes production APNs, and neither permits debugging.
The first upload identified missing orientation declarations and an extension
display name; these metadata values are now declared in the plists and project
generator configuration. Export success alone does not establish TestFlight
processing or beta readiness. Version 1.0 (1) subsequently uploaded successfully,
finished processing, and has its encryption declaration saved. The manual
Rook Internal QA group lists it as Ready to Test, with no testers invited yet.
Physical TestFlight installation and external beta review remain pending.
See Apple's official guidance:
https://developer.apple.com/documentation/familycontrols/requesting-the-family-controls-entitlement

Before TestFlight, verify all of these with actual provider/device evidence:

1. Apple Sign in private key/client-secret configuration, real nonce login, refresh,
   authorization revocation, account deletion and token revocation.
2. Distribution Family Controls capability, App Store signing/export, app listing,
   privacy disclosures and export-compliance answers, then TestFlight processing.
3. Available physical iPhone: select apps, approve 1 minute and 15 minutes, confirm
   local access, background/kill Rook, observe automatic relock and 30-minute
   cooldown, test offline expiry and reboot/selection/permission changes.
4. Real APNs background delivery and alert-action redemption. Push acceptance
   alone does not satisfy this check; foreground sync remains a recovery path.
5. Public privacy/support URLs in the signed app and a working support inbox.
6. Before paid launch only: real StoreKit products/agreements, production app ID,
   purchase/restore/refund/renewal notifications and server-verified ownership;
   standard license/subscription terms and accurate pricing disclosures.

On 2026-10-08, the isolated beta at https://api.rooklayer.com returned HTTP 200
from `/health`, `/ready` with every configuration check true, and the Apple
sign-in challenge endpoint. The replacement Apple key was saved privately and
configured on that service. These checks establish service configuration.

The signed development build subsequently completed native Sign in with Apple
on a physical iPhone 17 Pro on 2026-10-08 and loaded the paired hosted account.
This exposed stale personal-server grant reporting; the phone now attaches a
persisted grant ID only when authenticated state confirms it belongs to the
current connection. Thirty native tests cover this and the credential rejection
paths. A one-minute pass was redeemed; after force-quitting Rook before expiry,
the local expiry cleared, its main process was absent, and Instagram was
restricted again. Live refresh/revocation, account deletion, longer/offline/reboot
tests and APNs delivery still require their own live acceptance evidence.

The app uses individual Screen Time authorization. It is voluntary: permission
revocation or uninstallation can remove the boundary. Avoid marketing it as a
parental-control or tamper-proof enforcement product.

## Public-release candidate boundary

The public hardening branch prepares version 1.0 (2), provider-specific consent
`2026-10-08-openai-v1`, stable purchase binding and dual StoreKit environment
verification. These changes require a coordinated native/server rollout: old
clients cannot grant the new provider consent. Do not claim the hosted service
has this code merely because the branch or signed archive exists.

Set a dedicated durable `PURCHASE_BINDING_KEY` before enabling paid access. Its
fingerprint is pinned by the database, including after accounts are deleted.
Do not rotate it with the encryption key or reconstruct it from random user IDs.
Keep both StoreKit verification lanes configured on the one API origin; test
access requires account/device-bound production App Attest and a short lease.
Remove obsolete `STOREKIT_ENVIRONMENT` configuration; it is not a routing control.

Before switching `BETA_ACCESS=false`, configure approved product IDs and prices,
complete genuine purchase/restore/refund/renewal testing, fund the AI service,
verify readiness and the named-provider request, and rehearse backup restore with
erasure reconciliation. Paid Apps Agreement, banking/tax and EU trader setup
remain user-owned Apple Business steps. App Store submission remains pending.
