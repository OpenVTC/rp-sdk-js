/**
 * @openvtc/rp-sdk
 *
 * SDK for Relying Parties. Its main job is wallet sign-in with a
 * trigger link (`auth/oob/*`): the browser starter lives in
 * `@openvtc/rp-sdk/browser`, and this entry point carries the
 * server-side verification helpers and a reference state machine
 * (`OobSignInService`).
 *
 * **Legacy (deprecated):** SIOPv2 `id_token` verification for the
 * OpenVTC browser plugin's `window.vtaWallet.login`. It still works;
 * new sites should use the `auth/oob` flow.
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

export {
  jcsCanonicalize,
  JcsLimitExceededError,
  JCS_MAX_DEPTH,
  JCS_MAX_BYTES,
} from "./jcs.js";
export type { JcsCanonicalizeOptions, JcsLimit } from "./jcs.js";

// ---- Wallet sign-in with a trigger link (`auth/oob/*`), server side ----
// The browser starter lives in `@openvtc/rp-sdk/browser`.

export * from "./oob/types.js";
export * from "./oob/link.js";
// QR rendering without a bundled encoder: pass `encoder`. The default
// encoder (`qrcode-generator`) is only in `@openvtc/rp-sdk/browser`, so
// this entry point loads no QR library and no DOM API.
export { renderQrSvg, renderTriggerLinkHtml } from "./oob/qr.js";
export type {
  QrEncoder,
  QrMatrix,
  QrRenderOptions,
  QrRenderOptionsWithEncoder,
} from "./oob/qr.js";
export {
  ed25519DidKey,
  ed25519KeyFromDidKey,
  didKeyVerificationMethod,
} from "./oob/did-key.js";
export {
  DidKeyDocumentResolver,
  resolveRelationshipKey,
  trustTaskEndpoint,
  signInPortalOrigin,
  TRUST_TASK_HTTPS_SERVICE_TYPE,
  TRUST_TASK_HTTPS_PATH,
  SIGN_IN_PORTAL_SERVICE_TYPE,
} from "./oob/did-document.js";
export type {
  DidDocument,
  DidDocumentResolver,
  VerificationMethod,
  VerificationRelationship,
} from "./oob/did-document.js";
export {
  buildOobDocument,
  signOobDocument,
  CREATED_BACKDATE_MS,
} from "./oob/document.js";
export type { BuildOobDocumentParams } from "./oob/document.js";
export {
  OobVerificationError,
  verifyDidKeyDocument,
  verifyOobClaim,
  verifyOobIdentify,
  verifyOobGrant,
  computeContextDigest,
  contextDigestsEqual,
} from "./oob/verify.js";
export type {
  OobVerificationReason,
  OobVerifyCommon,
  VerifiedOobDocument,
  VerifiedClaim,
  VerifiedGrant,
  VerifyIdentifyParams,
  VerifyGrantParams,
} from "./oob/verify.js";
export {
  OobSignInService,
  MemoryOobRequestStore,
  OobError,
} from "./oob/service.js";
export type {
  OobRequestRecord,
  OobRequestStore,
  OobConnection,
  OobSession,
  OobSignInServiceOptions,
  OobHandleResult,
} from "./oob/service.js";
export { attachEddsaJcsProof, eddsaJcsHashInput, isoSeconds } from "./proof.js";
export type { EddsaJcsSigner } from "./proof.js";
