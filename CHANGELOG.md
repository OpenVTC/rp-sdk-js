# Changelog

## 0.1.1 — 2026-05-28

### Fixed

- **`package.json` repository URL** now points at
  `https://github.com/OpenVTC/rp-sdk-js.git` instead of the
  non-existent `OpenVTC/rp-sdk`. The "Repository" link on the
  [npmjs.com landing page](https://www.npmjs.com/package/@openvtc/rp-sdk)
  now resolves; the 0.1.0 link 404'd.

### Added (to tarball)

- `CHANGELOG.md` — present in the source tree since shortly after
  the 0.1.0 publish but never shipped to the registry. 0.1.0's
  release notes are captured below.

### Unchanged

Runtime code (`src/`, generated `dist/`) is byte-identical to the
0.1.0 release. This is a metadata-only patch — consumers of the
verification API see no behaviour change.

## 0.1.0 — 2026-05-24

### Added

Initial release. Server-side SDK for Relying Parties consuming
SIOPv2 `id_token`s from the OpenVTC browser plugin.

- **`verifyIdToken({ idToken, audience, nonce, resolver })`** —
  SIOPv2 verification with the OIDC Core §3.1.3.7 + SIOPv2 §6
  checks:
  - `alg` pinned to `EdDSA` (no `none`, no algorithm
    substitution).
  - Self-issued constraint (`iss === sub`).
  - Audience pinned (exact match, no leniency).
  - Nonce pinned, constant-time match.
  - `iat` / `exp` within configurable clock-skew window.
  - DID-resolved Ed25519 JWS signature.
- **`IdTokenVerificationError`** with typed `reason` —
  `malformed` / `wrong_algorithm` / `self_issued_check_failed`
  / `audience_mismatch` / `nonce_mismatch` / `issued_in_future`
  / `expired` / `iat_after_exp` / `resolver_failed` /
  `signature_invalid`. Log the `reason` so audit pipelines
  can distinguish misconfigured audience from forged tokens.
- **`KeyResolver`** — in-process `did:key:z6Mk…` (Ed25519
  multikey) resolver. No network round-trip, no cache
  invalidation concern.
- **`DidResolver`** interface — bring-your-own for `did:peer:2`,
  `did:webvh`, `did:web`. Typical impl wraps
  `affinidi-did-resolver-cache-sdk`.
- **`establishSession(verified, accessToken)`** — returns the
  subject DID + a `SessionCookieDescriptor` with HttpOnly +
  Secure + SameSite=Strict applied by default. Pass to
  `res.cookie(name, value, opts)` or your framework's
  equivalent.
- **`buildSessionCookie`** — lower-level cookie helper for
  callers that need to override the defaults.

### Why this exists

The browser-plugin demo accepts whatever the wallet POSTs
without verifying the `id_token` signature. Production RPs
that copy-paste from the demo inherit the gap. This SDK is the
audited path — every login goes through `verifyIdToken`.

Closes H2 from the May 2026 cross-system auth security review
of the OpenVTC stack.

### Roadmap

Planned for follow-up minor versions:

- `requireStepUp()` middleware — gates routes behind `acr=aal2`.
- `refreshProxy()` middleware — drop-in `/auth/refresh` proxy.
- Express + Fastify + Hono framework adapters.
- DIDComm-transport variant for RPs that prefer the wallet's
  authcrypt flow over the REST SIOPv2 flow.
