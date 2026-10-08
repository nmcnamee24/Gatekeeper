# Hosted Gatekeeper Implementation Plan

> For agentic workers: Implement the approved hosted product in the attached
> worktree; preserve legacy deployment and unrelated changes. Work from the
> API contract in ../specs/2026-10-08-hosted-gatekeeper-design.md.

1. PostgreSQL identity and policy foundation: write failing real-database tests,
   implement migrations, Apple nonce verification, rotating sessions, per-user
   device registration, isolated policy transactions and account deletion.
2. Conversational API: test real HTTP onboarding/device contracts, consent,
   bounded history and provider failure; implement structured AI decisions,
   persisted idempotency, user-specific limits and durable push jobs.
3. Native hosted experience: implement automatic pairing, native Apple login,
   consent, in-app conversation/duration selection, history and device settings,
   deletion, and StoreKit purchase/restore with testable transport models.
4. Billing verification: test signed-transaction ownership/expiry/revocation,
   implement Apple server library verification and notification handling.
5. External agent OAuth: implement and test metadata, PKCE, consent, audience,
   redirect validation, rotating refresh/revocation and account-scoped MCP.
6. Operations: runnable local Postgres stack, staging deployment, production
   configuration checks, CI, monitoring and backup/restore guidance. Verify
   existing personal server and complete hosted API on the real deployment.
7. Release: signed device build and physical acceptance where a phone is
   available; Apple entitlement/App Store configuration, review materials,
   subscriptions and TestFlight upload when the account allows. Keep each
   external gate explicit and the goal active while any requirement is unproven.

Independent components may be dispatched after their contracts are established.
Each owner writes failing tests first and reports exact evidence and limitations.
Root integrates, runs cross-component verification and audits the full objective.
