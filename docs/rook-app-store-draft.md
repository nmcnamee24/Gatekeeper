# Rook listing and Apple capability request draft

App Store Connect name: Rook: Intentional Access
App record: https://appstoreconnect.apple.com/apps/6820658945/distribution
Apple app ID: 6820658945
SKU: rook-ios-001
Saved subtitle: Make room for your attention
Saved primary category: Productivity
Support contact: support@rooklayer.com (Google Workspace alias of noah@rooklayer.com)
Privacy/support URLs: https://api.rooklayer.com/privacy and /support, after live verification.
The app record was created on 2026-10-08. Version 1.0 (1) finished Apple
processing and is Ready to Test in the internal QA group, with no testers
invited. Public candidate 1.0 (2) has passed 50 hosted-native tests and 149
connector tests. Its App Store export verifies Family Controls on both targets,
production APNs and App Attest on the app, team NHQ952894A, debugging disabled,
and matching version/build numbers. Upload succeeded on 2026-10-08; Apple processing and build selection are
separate gates.

The public description, promotional text and review instructions below are saved
in App Store Connect. **Automatically release after approval** is selected. Apple
still shows **Prepare for Submission**; the app has not been submitted or released.
Paid Apps Agreement remains unsigned; banking/tax and EU trader setup, subscription
prices/products, App Review phone number, screenshots and real device acceptance
are pending. The current hosted deployment remains the earlier free beta until a
coordinated client/server update is verified.

## Description

Rook creates a pause before you open the apps that pull at your attention.

Choose the apps you want to protect with Apple’s private Screen Time picker.
When you need access, explain what you want to do, choose 1–15 minutes, and make
an exit plan. Rook can ask a follow-up, decline open-ended scrolling, or approve
a short pass. Your device confirms access and keeps the timer. Apps block again
at the end, with a 30-minute cooldown after the approved window ends.

Ask Rook uses AI with your permission. Your messages and limited recent
conversation context are processed through Vercel AI Gateway by OpenAI. Your
Screen Time app selection stays on your device. You can clear your conversation,
withdraw AI consent, disconnect connected agents, or delete your account in Settings.

Rook is a voluntary boundary using individual Screen Time authorization. You
remain in control of your device permissions.

Privacy: https://api.rooklayer.com/privacy
Terms of Use: https://www.apple.com/legal/internet-services/itunes/dev/stdeula/

Promotional text: Make a plan before you open distracting apps. Choose a short
window, explain your purpose, and let Rook help you return to what matters.

## Family Controls distribution purpose

Rook is a voluntary focus app for adults using individual Screen Time
authorization. It uses FamilyControls for user authorization and private app
selection, ManagedSettings to shield the selected apps, and a DeviceActivity
monitor extension to restore shields when a locally enforced access window ends.
The user requests a specific purpose, exit plan, and duration of 1–15 minutes;
the service may issue a one-use approval, which the phone must redeem before
access starts. The AI cannot modify the maximum duration or cooldown. App
selection tokens stay in the shared app group on the phone and are never sent
to the service or model provider. Users can withdraw AI consent, remove Screen
Time authorization, or uninstall the app. The product is not marketed as parental
control, mandatory enforcement, or prevention of uninstallation.

Apple team: NHQ952894A
App bundle: com.noah.gatekeeper
Screen Time extension: com.noah.gatekeeper.monitor

Apple granted Family Controls distribution on 2026-10-08. It is enabled on both
identifiers, and regenerated distribution profiles include the entitlement.
The app's profile includes production APNs. App Store export and upload succeeded
after adding supported orientations and a monitor-extension display name.

## App privacy draft from code

Data used for app functionality and linked to the account: optional display name,
Apple/internal account identifiers and stable purchase binding, device
installation identifiers, App Attest public-key IDs/counters, temporary store-proof
hashes/environment/expiry and push registrations, user-chosen conversation/access-purpose text, access timing/status,
and verified purchase history when subscriptions are enabled. Anonymous keyed
network-address digests are retained briefly for abuse limits. App selections
remain local. There is no advertising tracking or analytics SDK in the app.

The saved App Store privacy draft declares optional name, other user content,
user/device identifiers, product interaction, and other data for abuse prevention.
All are declared as account-linked and used for app functionality, without
advertising tracking. Purchase History was added and fully configured in the
saved, unpublished privacy draft on 2026-10-08; no products are currently configured. The public candidate includes purchase
history in its bundled privacy manifest. Do not publish the final privacy answers
until the paid configuration and actual collection have been reconciled.

The bundled manifests declare UserDefaults for app preferences (CA92.1) and
sharing timer/selection state with the app-group extension (1C8F.1). The app
manifest includes the hosted collection categories; the monitor sends no data
outside the device. Reconcile the final App Store privacy answers with the live
AI Gateway/model and hosting retention settings before submission.

## Review notes to finish after validation

Document an actual test account/review sign-in flow, approved distribution
capabilities, on-device timer evidence, current product IDs/prices if paid access
is enabled, and instructions for reviewing app selection, consent, approvals,
early end, cooldown and deletion. Do not present preview fixtures as live accounts
or a simulator build as evidence of Screen Time enforcement.

## Saved App Review instructions

Rook uses native Sign in with Apple. There is no separate username or password;
reviewers create a review account with their own Apple account. Sign-in required
is selected. Review contact fields remain blank pending the requested phone number.
Do not invent password credentials or imply a supplied demo account exists.

Review notes explain individual Family Controls, local picker tokens, approved
distribution entitlement, a one-minute purpose/exit-plan request, explicit provider
consent, device confirmation, timer relock, cooldown and in-app deletion/consent
controls. Add product IDs and actual purchase/restore instructions after successful
provider validation. Sandbox purchases grant only account/device-bound test access;
they never create a production subscription.

Initial launch excludes promoted purchases, win-back/contingent offers, promo codes
and Family Sharing until their ownership/reconciliation paths are supported and
validated. Do not change Streamlined Purchasing based on an unverified assumption.
