# Changelog

## Unreleased

### Added

- **`confirm/{request,response}/0.1` support** — the RP side of the
  wallet consent protocol (trusttasks-tf). `verifyConfirmResponse`
  verifies the wallet's `eddsa-jcs-2022` Data Integrity proof (the
  proof *is* the consent record) and enforces the spec's consumer
  checks: `subject === issuer === signer`, the challenge echo, and an
  optional `recipient` audience binding. Failures surface as the typed
  `ConfirmVerificationError`.
- **`buildConfirmRequest` / `signConfirmRequest`** — construct a
  spec-shaped `confirm/request` document and attach an `eddsa-jcs-2022`
  proof via a caller-supplied `ConfirmSigner` (key management stays out
  of the SDK).
- **`verifyDataIntegrityProof`** and a `jcsCanonicalize` (RFC 8785)
  helper — the byte-exact canonicalization the wallet and VTA use, so
  proofs round-trip across implementations (covered by a
  cross-implementation fixture signed by `@openvtc/pnm-core`).

## 0.2.0 — 2026-06-07

### Security

- **Resolved all 4 open Dependabot advisories** (1 critical, 3
  moderate) in the dev-dependency tree by upgrading `vitest`
  `1.x → 4.1.8`, which pulls in patched `vite`/`vite-node`/`esbuild`:
  - `GHSA-5xrq-8626-4rwp` (critical) — Vitest UI arbitrary file
    read / exec.
  - `GHSA-4w7w-66w2-5vf9` (moderate) — Vite `.map` path traversal.
  - `GHSA-67mh-4wv8-2f99` (moderate) — esbuild dev-server CORS.
  - `npm audit` now reports 0 vulnerabilities.

### Changed

- **BREAKING (packaging): removed the `./express` subpath export.**
  It pointed at `dist/express.js`, which never existed — any
  `import … from "@openvtc/rp-sdk/express"` failed with
  module-not-found. The Express adapter remains on the roadmap; the
  export will return when the adapter ships. The orphaned `express`
  peer dependency and `@types/express` dev dependency were removed
  with it.
- **Updated runtime dependencies to v2**: `@noble/curves`,
  `@noble/hashes`, and `@scure/base` `1.x → 2.x`. The verification
  API and behaviour are unchanged; v2 only altered the import
  subpaths (`@noble/hashes/sha256` → `@noble/hashes/sha2.js`).
- `verifyIdToken` now decodes JWS segments with `@scure/base`'s
  vetted `base64urlnopad` codec instead of hand-rolled base64url +
  `Buffer`/`atob` branching. Behaviour is identical; the audited
  path carries less custom code.
- Updated dev toolchain: `typescript 5.x → 6.x`,
  `@types/node 20.x → 25.x`, `prettier 3.x → latest`.

### Added

- Direct test coverage for `KeyResolver` (`did-resolver.ts`) and the
  session-cookie helpers (`session.ts`) — including the load-bearing
  `HttpOnly` / `Secure` / `SameSite=Strict` cookie flags, which were
  previously untested.

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
