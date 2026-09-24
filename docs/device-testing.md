# Physical-device acceptance checklist

Automated tests and unsigned builds do not establish real Screen Time behavior.
Test with your signed app and monitor extension on a real iPhone:

- Selected apps/sites show shields; unselected apps remain usable.
- Approval, redemption, local unshielding, and the matching phone report are distinct.
- Relocking works at expiry while foregrounded, suspended, or force-quit; test
  across lock, reboot, midnight, and time-zone changes and record actual timing.
- Wrong credentials, expired/replayed/revoked passes, and invalid endpoints fail.
- Both cooldowns survive relaunch, server restart, and early close.
- Lost redemption responses and failed local scheduling leave apps blocked.
- Early-end requests apply after sync and are not described as instant remote locks.
- Optional APNs works with your signing environment; denied notifications,
  delayed delivery, and offline operation have a working foreground fallback.
- Dynamic Type, VoiceOver, revoked permissions, and absent connectivity are usable.

Record iOS and Xcode versions, signing configuration, steps, and observed results
without including credentials, selected-app tokens, or private request content.
