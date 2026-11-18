# Security policy

CyberVault holds people's passwords and ID documents, so security reports are very welcome.

## Reporting a problem

Please report it **privately**, not in a public issue:
on GitHub, open the **Security** tab → **Report a vulnerability**.

It helps to include what's affected, the steps to reproduce it, and what an attacker could do with it.
I'll reply as soon as I can, and credit you in the fix if you'd like.

## What's in scope

- The web app (`public/`), the single-file build (`dist/cybervault.html`, `dist/sw.js`)
  and the Android app (`android/`, `tools/build-apk.sh`).
- The encryption in [`public/vault-crypto.js`](public/vault-crypto.js) and the
  Firestore rules in [`firestore.rules`](firestore.rules).

Not in scope: how someone set up their own Firebase project (for example, not publishing the rules),
and bugs in Google's or Firebase's own services.

## Supported versions

Only the [latest release](https://github.com/TymonBitesTheDust/CyberVault/releases/latest) gets security fixes.

## How your data is protected

See [How your data is protected](README.md#how-your-data-is-protected) in the README. In short: everything is
encrypted on your device with AES-256-GCM before upload, with a key derived from your master password
(PBKDF2-SHA256, 600,000 rounds). The code hasn't been independently audited.
