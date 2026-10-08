# Rook Public Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair audited launch defects and prepare an accurate public submission.

**Architecture:** Preserve the hosted/native boundaries and existing timing
policy. Fix transient identity gating separately from durable purchase identity
and environment isolation, then validate the signed public candidate.

**Tech Stack:** SwiftUI, AuthenticationServices, StoreKit 2, Node 24, PostgreSQL 18.

**Spec:** `docs/superpowers/specs/2026-10-08-public-release-hardening.md`

## Global Constraints

- 1–15-minute windows; cooldown 30 minutes after the approved end.
- Definitive Apple revocation closes protection; network failures block new work.
- Consent version `2026-10-08-openai-v1`; Vercel AI Gateway and OpenAI named.
- Sandbox transactions must never create production paid entitlement.
- Preserve the personal deployment and unrelated work; keep secrets private.

## Review Focus

- Temporary verification failure during a running pass preserves its expiry.
- Definitive revocation racing a successful callback cannot reopen access.
- A provider configuration change cannot silently send content to an unnamed AI.
- Delete/recreate cannot strand a paid purchase or transfer it to another identity.
- A sandbox transaction cannot make a production installation paid.

### Task 1: Preserve an existing timer during transient verification

**Files:** `App/AppleCredentialGate.swift`,
`Tests/HostedAppTests/AppleCredentialGateTests.swift`.

**Interfaces:** `requireAuthorization(force:)` continues to throw on transient
failure; only `block(_:definitive: true)` invokes the protection-close callback.

- [x] Change `testNetworkFailureRetainsCredentialsButBlocksUntilVerified` to
  assert zero close callbacks while unauthorized, then successful recovery.
- [x] Add a test for a previously authorized gate followed by network failure:
  the local expiry survives, new authorization fails, then revocation clears it.
- [x] Run the focused Xcode tests and observe failure caused by early closure.
- [x] Restrict the close callback to definitive failures; clarify temporary-error
  copy without weakening authorization or the revocation race guard.
- [x] Run all native hosted tests; commit the repair with its regressions.

### Task 2: Provider disclosure and Terms

**Files:** `App/HostedViews.swift`, `App/HostedAccount.swift`, `project.yml`,
`Gatekeeper.xcodeproj/project.pbxproj`, `connector/src/hosted/conversation.js`,
`connector/src/hosted/coach.js`, `connector/src/hosted/public-documents.js`,
and existing corresponding tests/docs.

**Interfaces:** Existing consent endpoint and `hasConsent` use
`2026-10-08-openai-v1`. `HostedCoach.configured` requires an `openai/` model.

- [x] Add coach tests rejecting non-OpenAI configuration before transmission;
  observe RED, enforce the disclosed provider, and verify GREEN.
- [x] Update both consent versions and explicit provider/message disclosure.
- [x] Configure the standard Apple EULA URL and public privacy wording, including
  purchase identifiers and the separate Apple subscription-cancellation flow.
- [x] Run the complete connector and native suites; verify generated configuration
  retains the Terms URL; commit the change.

### Task 3: Purchase identity and environment isolation

**Files:** Billing/identity migrations, HTTP/native billing contracts and tests.

**Interfaces:** Final design must specify verified environment selection,
device/session ownership and stable purchase binding before implementation.

- [ ] Complete a concrete design against Apple's official verification contract.
- [ ] Write regressions for sandbox isolation and delete/recreate restoration,
  observe failures, implement the smallest secure repair, then run both suites.
- [ ] Verify real sandbox purchase/restore and production configuration with the
  configured products; document remaining provider checks honestly.

### Task 4: Prepare and validate the public submission

**Files:** `docs/rook-app-store-draft.md`, `docs/device-testing.md`, release artifacts.

- [ ] Configure approved subscription prices and products, privacy purchase data,
  review contact, screenshots and automatic post-approval release.
- [ ] Perform the required physical timer/offline checks with the candidate.
- [ ] Build/sign/upload the next version build, verify CI and hosted health.
- [ ] Review the final candidate and submit only when required fields and tests
  are complete; report actual Apple status, not an assumed release.
