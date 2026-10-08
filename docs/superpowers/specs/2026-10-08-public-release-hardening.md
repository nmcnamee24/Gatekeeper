# Rook public release hardening

The user requests a direct public App Store release. The previously approved
hosted design remains authoritative: 1–15-minute device-confirmed windows,
30-minute cooldown from the approved end, optional AI consent, and subscriptions
at launch. TestFlight is a validation tool, not a required public release stage.

## Repairs within the approved product

- Temporary Apple credential verification failures block new authenticated work,
  retain credentials, and preserve the local timer of an existing window.
  Definitive revocation/not-found/transfer closes protection and signs out.
- Before sending conversation content, consent explicitly names Vercel AI Gateway
  and OpenAI. Version `2026-10-08-openai-v1` invalidates earlier generic consent.
  The hosted coach rejects non-OpenAI model configuration under this disclosure;
  no provider fallback is configured. Provider/model changes must be reviewed
  against the disclosure before deployment. Do not assert zero data retention.
- In-app privacy and Terms links are always configured in distribution builds.
  Use Apple's standard EULA, with actual localized subscription price and period
  displayed from StoreKit. Deleting a Rook account does not cancel Apple billing.
- Paid production entitlements must never be created by a sandbox purchase.
  Apple review sandbox purchases must be testable through an explicit isolated
  environment path. Final routing design requires verified Apple semantics;
  untrusted request headers are not environment proof.
- A fresh server-verified Sign in with Apple identity must recover the same
  purchase binding after account deletion/recreation, without preserving a
  hidden per-account purchase ledger. Use a dedicated durable derivation secret;
  random database account IDs remain independent of the purchase token.

## Release acceptance

Required: subscription prices/products; verified purchase/restore lifecycle;
funded AI service; privacy accurately including purchase data and provider terms;
App Review contact; screenshots of the actual app for supported device classes;
15-minute/offline/production device verification; updated signed build and green
CI; accurate reviewer instructions; Apple submission and approval status clearly
distinguished. Do not submit an incomplete candidate or claim it is live.
