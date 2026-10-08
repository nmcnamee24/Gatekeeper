# Rook listing and Apple capability request draft

App Store Connect name: Rook: Intentional Access
App record: https://appstoreconnect.apple.com/apps/6820658945/distribution
Apple app ID: 6820658945
SKU: rook-ios-001
Subtitle candidate: Make room for your attention
Support contact: support@rooklayer.com (Google Workspace alias of noah@rooklayer.com)
Privacy/support URLs: https://api.rooklayer.com/privacy and /support, after live verification.
The app record was created on 2026-10-08. The listing text below is a draft;
no build was uploaded and no version was submitted for review.

## Description

Rook creates a pause before you open the apps that pull at your attention.

Choose the apps you want to protect with Apple's private Screen Time picker.
When you need access, explain what you want to do, choose 1–15 minutes, and make
an exit plan. Rook can ask a follow-up, decline open-ended scrolling, or approve
a short pass. Your iPhone confirms access and keeps the timer. Apps block again
at the end, with a 30-minute cooldown.

AI processing is optional and requires your consent. Your app selection stays
on your phone. You can clear your conversation, disconnect connected agents,
withdraw consent, or delete your account in Settings.

Rook is a voluntary boundary using individual Screen Time authorization. You
remain in control of your device permissions. Initial beta access is free.

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

The app and extension require Family Controls distribution approval. The current
App Store export fails because the distribution profiles omit that entitlement.
Apple confirmed receipt of the approved request on 2026-10-08; review is pending.

## App privacy draft from code

Data used for app functionality and linked to the account: optional display name,
Apple/internal account identifiers, device installation identifiers and push
registrations, user-chosen conversation/access-purpose text, access timing/status,
and verified purchase history when subscriptions are enabled. Anonymous keyed
network-address digests are retained briefly for abuse limits. App selections
remain local. There is no advertising tracking or analytics SDK in the app.

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
