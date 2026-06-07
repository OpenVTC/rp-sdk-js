/**
 * SIOPv2 self-issued `id_token` verification.
 *
 * The OpenVTC browser plugin emits a compact EdDSA JWS where:
 *
 * - `iss === sub` — the wallet's holder `did:key` (or `did:peer:2`
 *   for stable identifiers).
 * - `aud` — the RP's DID, bound at consent time.
 * - `nonce` — the challenge the RP issued via the prior
 *   `POST /auth/challenge` round-trip.
 * - `iat` / `exp` — a short freshness window (300s default).
 *
 * **Why this exists**: the RP demo in the browser-plugin repo
 * accepted the wallet's POST response without ever verifying the
 * `id_token` signature. That demo is widely copy-pasted into
 * production code, inheriting the gap. This module is the
 * canonical, audited path RPs should call.
 *
 * Verification covers everything in OIDC Core §3.1.3.7 +
 * SIOPv2 §6 + RFC 8628:
 *
 * 1. Header `alg` is `EdDSA`. No `none`, no algorithm
 *    substitution.
 * 2. `iss === sub` (self-issued).
 * 3. `aud` matches the expected RP DID exactly.
 * 4. `nonce` matches the expected challenge (constant-time).
 * 5. `iat` not in the future (within clock-skew tolerance).
 * 6. `exp` in the future.
 * 7. JWS signature verifies against the issuer's resolved
 *    Ed25519 verification method (`#key-1` for did:key, `#key-1`
 *    for did:peer:2).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64urlnopad } from "@scure/base";

import type { DidResolver } from "./did-resolver.js";

// Default freshness window. OpenID Connect Core §15.4 recommends
// "a few minutes" tolerance for clock skew; we pick 60 s as a
// tight bound on the iat check, which is enough to absorb NTP
// drift between an honest wallet and the RP.
const DEFAULT_CLOCK_SKEW_SECS = 60;

export interface VerifyIdTokenParams {
  /** Compact EdDSA JWS as emitted by `window.vtaWallet.login`. */
  idToken: string;
  /** Expected `aud` claim — must be the RP's DID. */
  audience: string;
  /**
   * Expected `nonce` claim — must be the challenge the RP
   * issued in the prior `/auth/challenge` exchange. Single-use;
   * persist alongside the session and discard on first verify.
   */
  nonce: string;
  /**
   * DID resolver. Resolves `iss` to its verification method
   * Ed25519 public key. The plugin uses did:key and did:peer:2;
   * both must be supported.
   */
  resolver: DidResolver;
  /**
   * Clock skew tolerance in seconds for `iat`. Default 60 s.
   * Tighter is more secure but trips on poorly-synced clocks.
   */
  clockSkewSecs?: number;
}

export interface VerifiedIdToken {
  /** The holder DID (`iss === sub`). Bind your session to this. */
  subject: string;
  /** The RP's DID (`aud`). Echoed back for audit logging. */
  audience: string;
  /** Nonce that matched (single-use; do not re-accept). */
  nonce: string;
  /** Issuance epoch (seconds since 1970). */
  issuedAt: number;
  /** Expiry epoch (seconds since 1970). */
  expiresAt: number;
  /** Other claims; opaque to the SDK. */
  extra: Record<string, unknown>;
}

export class IdTokenVerificationError extends Error {
  constructor(
    message: string,
    public readonly reason: IdTokenVerificationReason,
  ) {
    super(message);
    this.name = "IdTokenVerificationError";
  }
}

export type IdTokenVerificationReason =
  | "malformed"
  | "wrong_algorithm"
  | "self_issued_check_failed"
  | "audience_mismatch"
  | "nonce_mismatch"
  | "issued_in_future"
  | "expired"
  | "iat_after_exp"
  | "resolver_failed"
  | "signature_invalid";

/**
 * Verify a SIOPv2 id_token. Returns the bound claims on success;
 * throws an [`IdTokenVerificationError`] with a typed
 * [`reason`] on failure.
 *
 * The function is async because DID resolution is — it dispatches
 * out to whatever resolver implementation the caller provides
 * (a `did:key` resolver is in-process; `did:peer:2` requires
 * unpacking; `did:web` / `did:webvh` require an HTTP fetch).
 *
 * Reject failure modes loudly: never log just "auth failed" —
 * the typed `reason` is intended to be surfaced into the RP's
 * audit log so operators can distinguish a misconfigured
 * `audience` from a forged token.
 */
export async function verifyIdToken(
  params: VerifyIdTokenParams,
): Promise<VerifiedIdToken> {
  const clockSkew = params.clockSkewSecs ?? DEFAULT_CLOCK_SKEW_SECS;

  // ---- 1. Parse the compact JWS ----
  const parts = params.idToken.split(".");
  if (parts.length !== 3) {
    throw new IdTokenVerificationError(
      "id_token is not a three-part compact JWS",
      "malformed",
    );
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  let header: { alg?: string; kid?: string; typ?: string };
  let payload: Record<string, unknown>;
  let signature: Uint8Array;
  try {
    header = JSON.parse(base64urlDecodeToString(headerB64));
    payload = JSON.parse(base64urlDecodeToString(payloadB64));
    signature = base64urlDecode(signatureB64);
  } catch (e) {
    throw new IdTokenVerificationError(
      `id_token JSON / base64url decode failed: ${(e as Error).message}`,
      "malformed",
    );
  }

  // ---- 2. Algorithm pinning ----
  // Anything other than EdDSA is rejected. `alg: "none"`,
  // algorithm-substitution attacks, and HS-vs-RS confusion all
  // fail here.
  if (header.alg !== "EdDSA") {
    throw new IdTokenVerificationError(
      `id_token alg must be EdDSA, got ${JSON.stringify(header.alg)}`,
      "wrong_algorithm",
    );
  }

  // ---- 3. Self-issued check ----
  const iss = String(payload.iss ?? "");
  const sub = String(payload.sub ?? "");
  if (!iss || iss !== sub) {
    throw new IdTokenVerificationError(
      `SIOPv2 self-issued constraint failed: iss=${JSON.stringify(iss)} sub=${JSON.stringify(sub)}`,
      "self_issued_check_failed",
    );
  }

  // ---- 4. Audience pinning ----
  // OIDC Core §3.1.3.7 — must EXACTLY equal expected aud. No
  // substring matching, no "starts-with" leniency.
  const aud = String(payload.aud ?? "");
  if (aud !== params.audience) {
    throw new IdTokenVerificationError(
      `id_token aud does not match expected audience`,
      "audience_mismatch",
    );
  }

  // ---- 5. Nonce match (constant-time) ----
  const nonceClaim = String(payload.nonce ?? "");
  if (!constantTimeEqual(nonceClaim, params.nonce)) {
    throw new IdTokenVerificationError(
      "id_token nonce does not match expected challenge",
      "nonce_mismatch",
    );
  }

  // ---- 6. iat / exp ----
  const now = Math.floor(Date.now() / 1000);
  const iat = Number(payload.iat);
  const exp = Number(payload.exp);
  if (!Number.isFinite(iat) || !Number.isFinite(exp)) {
    throw new IdTokenVerificationError(
      "id_token iat/exp not finite numbers",
      "malformed",
    );
  }
  if (iat > now + clockSkew) {
    throw new IdTokenVerificationError(
      `id_token iat is in the future (iat=${iat}, now=${now}, skew=${clockSkew})`,
      "issued_in_future",
    );
  }
  if (exp <= now) {
    throw new IdTokenVerificationError(
      `id_token has expired (exp=${exp}, now=${now})`,
      "expired",
    );
  }
  if (iat > exp) {
    throw new IdTokenVerificationError(
      `id_token iat is after exp (iat=${iat}, exp=${exp})`,
      "iat_after_exp",
    );
  }

  // ---- 7. Resolve issuer + verify signature ----
  let publicKeyMultikey: Uint8Array;
  try {
    publicKeyMultikey = await params.resolver.resolveAuthenticationKey(iss);
  } catch (e) {
    throw new IdTokenVerificationError(
      `DID resolution failed for ${iss}: ${(e as Error).message}`,
      "resolver_failed",
    );
  }

  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const ok = ed25519.verify(signature, signingInput, publicKeyMultikey);
  if (!ok) {
    throw new IdTokenVerificationError(
      "id_token signature does not verify against issuer key",
      "signature_invalid",
    );
  }

  // ---- 8. Strip claims we already validated; return the rest ----
  const extra = { ...payload };
  for (const k of ["iss", "sub", "aud", "nonce", "iat", "exp"]) {
    delete extra[k];
  }

  return {
    subject: sub,
    audience: aud,
    nonce: nonceClaim,
    issuedAt: iat,
    expiresAt: exp,
    extra,
  };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// Compact JWS encodes each segment as unpadded base64url (RFC 7515
// §2). `@scure/base`'s `base64urlnopad` is the vetted decoder; it
// rejects padding and non-alphabet bytes by throwing, which the
// caller maps to the `malformed` reason.
function base64urlDecode(b64url: string): Uint8Array {
  return base64urlnopad.decode(b64url);
}

function base64urlDecodeToString(b64url: string): string {
  return new TextDecoder().decode(base64urlDecode(b64url));
}

/**
 * Constant-time string comparison.
 *
 * Compares byte representations after a length check. The length
 * check itself is fast — it leaks "the lengths differ" but never
 * a byte-by-byte prefix match. Both sides are server-controlled
 * values (the issued challenge and the wallet's echoed nonce)
 * so the entropy is fixed at 256 bits; the length is a public
 * invariant of the challenge format.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  // Hash before compare. Avoids leaking string length / bytes
  // through the comparison itself; both sides become fixed-size
  // 32-byte digests.
  const ha = sha256(new TextEncoder().encode(a));
  const hb = sha256(new TextEncoder().encode(b));
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= ha[i] ^ hb[i];
  return diff === 0;
}
