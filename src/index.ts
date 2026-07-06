/**
 * @openvtc/rp-sdk
 *
 * Server-side SDK for Relying Parties consuming SIOPv2
 * id_tokens from the OpenVTC browser plugin
 * (`window.vtaWallet.login`).
 *
 * **Why this exists**: the browser-plugin demo accepts whatever
 * the wallet POSTs without verifying the id_token signature, and
 * production RPs frequently copy-paste from it. This SDK is the
 * audited path — every login call goes through `verifyIdToken`,
 * which enforces the OIDC Core §3.1.3.7 + SIOPv2 §6 checks.
 *
 * Minimum viable usage:
 *
 * ```ts
 * import { verifyIdToken, KeyResolver, establishSession } from "@openvtc/rp-sdk";
 *
 * const resolver = new KeyResolver();
 *
 * // After your /auth/challenge handler returns a challenge,
 * // persist it against the session-id you returned. On the
 * // wallet's /auth/ POST:
 * const verified = await verifyIdToken({
 *   idToken: req.body.id_token,
 *   audience: process.env.RP_DID!,
 *   nonce: storedChallenge,
 *   resolver,
 * });
 *
 * // Wallet identity is now bound. Issue a session.
 * const { subject, cookie } = establishSession(verified, mintedAccessToken);
 * res.cookie(cookie.name, cookie.value, cookie.options);
 * ```
 *
 * Read [`verifyIdToken`]'s doc-comment for the full list of
 * verification steps. Failure modes are surfaced via the typed
 * [`IdTokenVerificationError.reason`] — log it.
 */

export {
  verifyIdToken,
  IdTokenVerificationError,
  constantTimeEqual,
} from "./verify-id-token.js";
export type {
  VerifyIdTokenParams,
  VerifiedIdToken,
  IdTokenVerificationReason,
} from "./verify-id-token.js";

export { KeyResolver } from "./did-resolver.js";
export type { DidResolver } from "./did-resolver.js";

export { buildSessionCookie, establishSession } from "./session.js";
export type {
  SessionCookieOptions,
  SessionCookieDescriptor,
} from "./session.js";

export {
  verifyConfirmResponse,
  verifyDataIntegrityProof,
  buildConfirmRequest,
  signConfirmRequest,
  ConfirmVerificationError,
  CONFIRM_REQUEST_TYPE,
  CONFIRM_RESPONSE_TYPE,
} from "./confirm.js";
export type {
  VerifyConfirmResponseParams,
  VerifiedConfirmResponse,
  ConfirmVerificationReason,
  TrustTaskDocument,
  DataIntegrityProof,
  ConfirmRequestPayload,
  ConfirmResponsePayload,
  BuildConfirmRequestParams,
  ConfirmSigner,
} from "./confirm.js";

export { jcsCanonicalize } from "./jcs.js";
