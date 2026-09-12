# Changelog

## Unreleased

### Security

- **`jcsCanonicalize` now bounds its input.** Canonicalization
  recurses once per nesting level, so a `confirm/response` body of
  ~6 KB nested a few thousand levels deep made verification throw
  `RangeError: Maximum call stack size exceeded` — an untyped crash of
  the RP's verify call on a pre-authentication, attacker-influenced
  document. Nesting deeper than `JCS_MAX_DEPTH` (100) or a canonical
  form larger than `JCS_MAX_BYTES` (1 MiB) is now rejected with the
  typed `JcsLimitExceededError`; both bounds are overridable per call
  (`jcsCanonicalize(value, { maxDepth, maxBytes })`). Inside
  `verifyConfirmResponse` / `verifyDataIntegrityProof` the rejection
  surfaces as `ConfirmVerificationError` with the new
  `document_too_complex` reason. Canonical output for every
  in-spec document is byte-identical to before.

- **Audience binding is now enforced whenever `audience` is passed.**
  `verifyConfirmResponse` skipped the `recipient` cross-check when the
  document carried no `recipient` at all, so a response bound to no RP
  was accepted — and could be re-presented to a different RP that does
  not bind the challenge server-side. Passing `audience` now requires a
  `recipient` equal to it; a missing or different `recipient` fails with
  the existing `audience_mismatch` reason. Callers that omit `audience`
  are unaffected, and should start passing it.
- **`expiresAt` / `issuedAt` are now checked.** Both fields were part
  of the document type and signed by the wallet, but never read during
  verification, so an indefinitely old decision verified fine.
  `verifyConfirmResponse` now rejects a document whose `expiresAt` has
  passed with the new `expired` reason, and takes two optional
  parameters: `maxAgeSecs`, which bounds how far `issuedAt` may lie
  behind now, and `now`, the clock reading to compare against
  (defaults to the current time). Both checks run after the proof
  verifies. They are defense in depth only — single use and the
  authoritative freshness window still come from the caller's
  server-side challenge binding, as the API docs say.
- **The `confirm/response` challenge echo is compared in constant
  time.** `verifyConfirmResponse` used `!==` while the SIOPv2 nonce
  check already used `constantTimeEqual`, leaving one byte-timing
  oracle on a secret the RP issued. The challenge is single-use and
  ≥128 bits, so this was not meaningfully exploitable — the two
  comparisons are now simply consistent.

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
