/**
 * @openvtc/rp-sdk/browser
 *
 * The starter side of wallet sign-in with a trigger link (`auth/oob/*`):
 * the browser key `K_b`, `auth/oob/request`, the clickable QR code and the
 * `auth/oob/redeem` long poll. No UI framework; no Node APIs.
 *
 * ```ts
 * import { createSignIn } from "@openvtc/rp-sdk/browser";
 *
 * const signIn = createSignIn({
 *   // The TrustTaskHTTPS serviceEndpoint, exactly as published.
 *   endpoint: "https://members.example.org/v1/trust-tasks",
 *   serviceDid: "did:webvh:…:members.example.org",
 *   container: document.getElementById("code")!,
 *   onStateChange: render,
 * });
 * showCodeButton.onclick = () => signIn.start();
 * ```
 */

export {
  createSignIn,
  SignInController,
  SignInError,
} from "./browser/starter.js";
export type { SignInOptions, SignInState } from "./browser/starter.js";

export {
  generateStarterKey,
  starterKeyFromPair,
  isEd25519Available,
  Ed25519UnavailableError,
  MemoryStarterKeyStore,
  IndexedDbStarterKeyStore,
} from "./browser/key.js";
export type {
  StarterKey,
  StarterKeyStore,
  GenerateStarterKeyOptions,
} from "./browser/key.js";

export * from "./oob/link.js";
export {
  renderQrSvg,
  renderTriggerLinkHtml,
  createTriggerLinkElement,
  defaultQrEncoder,
} from "./oob/qr.js";
export type { QrEncoder, QrMatrix, QrRenderOptions } from "./oob/qr.js";
export { buildOobDocument, signOobDocument } from "./oob/document.js";
export {
  trustTaskEndpoint,
  signInPortalOrigin,
  TRUST_TASK_HTTPS_SERVICE_TYPE,
  SIGN_IN_PORTAL_SERVICE_TYPE,
} from "./oob/did-document.js";
export type { DidDocument } from "./oob/did-document.js";
export * from "./oob/types.js";
