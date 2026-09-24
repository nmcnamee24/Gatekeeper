# Security

Gatekeeper is a single-user prototype. Do not treat it as tamper-proof control
or expose a shared deployment to multiple users.

## Credentials

- Configure the server through environment variables. `npm run init` creates
  two independent random secrets in a mode-0600 `.env` and never overwrites it.
- The agent receives only `MUSE_TOKEN`; the phone receives only `DEVICE_TOKEN`.
- The iPhone saves its credential in Keychain after authenticating over HTTPS.
  Runtime pairing is intentional: credentials must not be compiled into an app.
- Keep APNs signing keys on the server. The public repository contains no
  credential defaults, personal deployment configuration, or SQLite data.
- `.gitignore` protects untracked files only. It cannot revoke leaked keys or
  remove material already in history.

## Rotate a suspected exposed key

1. Generate a fresh random replacement and save it securely outside the repo.
2. Update the relevant Railway variable and redeploy. Keep the same database
   volume; do not reset cooldown or grant history.
3. Update that role's consumer: agent secure connector settings for `MUSE_TOKEN`,
   or the app's connection settings for `DEVICE_TOKEN`. Update local services
   and private environment files if they use the same credential.
4. Verify the old key returns HTTP 401 and the new key can read status. Never
   issue an approval just to test authentication.
5. If the old value was committed elsewhere, sanitize that repository's history
   before publishing it. Rotation is still necessary even after history cleanup.

Rotation briefly disconnects consumers until their saved credentials are updated.
Do not publish either the previous or replacement key in an issue.

## Reporting

Use GitHub's private vulnerability reporting when enabled. Otherwise contact the
maintainer through their GitHub profile to arrange private disclosure. Do not
post credentials, exploit details involving a live personal deployment, or
private request records in a public issue.
