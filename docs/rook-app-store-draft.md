# Rook listing and Apple capability request draft

App Store Connect name: Rook: Intentional Access
App record: https://appstoreconnect.apple.com/apps/6820658945/distribution
Apple app ID: 6820658945
SKU: rook-ios-001
Saved subtitle: Make room for your attention
Saved primary category: Productivity
Support contact: support@rooklayer.com (Google Workspace alias of noah@rooklayer.com)
Privacy/support URLs: https://api.rooklayer.com/privacy and /support, after live verification.
The app record was created on 2026-10-08. Version 1.0 (1) uploaded successfully,
finished Apple processing, and has its encryption declaration saved. The manual
Rook Internal QA group lists it as Ready to Test, with no testers invited yet.
The listing text remains a draft; no external beta or App Store review was
submitted. Build-specific test instructions and beta description are saved.

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

Apple granted Family Controls distribution on 2026-10-08. It is enabled on both
identifiers, and regenerated distribution profiles include the entitlement.
The app's profile includes production APNs. App Store export and upload succeeded
after adding supported orientations and a monitor-extension display name.

## App privacy draft from code

Data used for app functionality and linked to the account: optional display name,
Apple/internal account identifiers, device installation identifiers and push
registrations, user-chosen conversation/access-purpose text, access timing/status,
and verified purchase history when subscriptions are enabled. Anonymous keyed
network-address digests are retained briefly for abuse limits. App selections
remain local. There is no advertising tracking or analytics SDK in the app.

The saved App Store privacy draft declares optional name, other user content,
user/device identifiers, product interaction, and other data for abuse prevention.
All are declared as account-linked and used for app functionality, without
advertising tracking. Purchase-history disclosure must be enabled alongside
paid subscriptions; no products are offered in this free beta.

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
