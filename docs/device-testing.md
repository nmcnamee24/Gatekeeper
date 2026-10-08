# Physical-device acceptance checklist

Automated tests and unsigned builds do not establish real Screen Time behavior.
Test with your signed app and monitor extension on a real iPhone:

- Selected apps/sites show shields; unselected apps remain usable.
- Approval, redemption, local unshielding, and the matching phone report are distinct.
- Relocking works at expiry while foregrounded, suspended, or force-quit; test
  across lock, reboot, midnight, and time-zone changes and record actual timing.
- Test 1-, 5-, and 15-minute grants separately. The ongoing Device Activity
  interval should end and relock at the approved expiry while the app is
  suspended. Record any iOS callback delay or monitoring-registration failure.
- Muse confirms the requested duration; 0, 16, and fractional minutes are
  rejected. The countdown reflects that duration, and cooldown ends 30 minutes
  after the approved end, including after early close or app relaunch.
- Wrong credentials, expired/replayed/revoked passes, and invalid endpoints fail.
- Both cooldowns survive relaunch, server restart, and early close.
- Lost redemption responses and failed local scheduling leave apps blocked.
- Early-end requests apply after sync and are not described as instant remote locks.
- Optional APNs works with your signing environment; denied notifications,
  delayed delivery, and offline operation have a working foreground fallback.
- Dynamic Type, VoiceOver, revoked permissions, and absent connectivity are usable.

Record iOS and Xcode versions, signing configuration, steps, and observed results
without including credentials, selected-app tokens, or private request content.

## Public candidate 1.0 (2)

Fifty hosted-native tests pass, and the signed archive builds. The earlier
one-minute force-quit test used a development build; it does not establish
acceptance of this distribution candidate. The intended iPhone is currently
unavailable to Xcode. Keep the following checks pending until it is connected:

- Genuine production App Attest plus Apple-verified Sandbox AppTransaction in
  TestFlight; no simulator fixture may substitute for issuance. Confirm review
  installation environment classification with Apple's review workflow.
- Paid purchase/restore, renewal/refund notifications, and delete/recreate restore
  with the same Apple identity; a different identity must not adopt the receipt.
- Purchase after waiting longer than the 15-minute proof lease; foreground test
  access renews without closing an existing local pass.
- Fifteen-minute access, expiry while offline and while the selected app remains
  foregrounded, suspended/force-quit behavior, and reboot recovery.
- Production APNs delivery, notification denial/foreground fallback, revocation,
  consent withdrawal and authenticated account deletion. Use disposable owned QA
  identities for destructive tests with explicit approval at execution time.

Capture actual iPhone and iPad app screens for App Store assets. App Store
screenshots must represent the shipping UI; admin proof screenshots and Debug
preview fixtures are not release screenshots or device-enforcement evidence.
