/**
 * Local wire types for the `auth/oob/*` Trust Task family (base design
 * section 10, plus contract C5).
 *
 * TODO: replace with generated trust-tasks types once `dtgwg-trust-tasks-tf`
 * publishes the `auth/oob/*` bindings.
 */

// TODO: replace with generated trust-tasks types
export const OOB_TYPE_BASE = "https://trusttasks.org/spec/auth/oob";

// TODO: replace with generated trust-tasks types
export const OOB_TYPES = {
  request: `${OOB_TYPE_BASE}/request/0.1`,
  claim: `${OOB_TYPE_BASE}/claim/0.1`,
  prove: `${OOB_TYPE_BASE}/prove/0.1`,
  identify: `${OOB_TYPE_BASE}/identify/0.1`,
  respond: `${OOB_TYPE_BASE}/respond/0.1`,
  grant: `${OOB_TYPE_BASE}/grant/0.1`,
  redeem: `${OOB_TYPE_BASE}/redeem/0.1`,
  cancel: `${OOB_TYPE_BASE}/cancel/0.1`,
} as const;

/** The framework error document type the VTC answers refusals with. */
export const TRUST_TASK_ERROR_TYPE =
  "https://trusttasks.org/spec/trust-task-error/0.5";

export type OobTask = keyof typeof OOB_TYPES;

// TODO: replace with generated trust-tasks types
export type OobPurpose = "login";
// TODO: replace with generated trust-tasks types
export type OobMode = "scan";

/** A signed Trust-Task document as it travels on the wire. */
// TODO: replace with generated trust-tasks types
export interface OobDocument<P = unknown> {
  id: string;
  type: string;
  issuer: string;
  recipient?: string;
  issuedAt?: string;
  expiresAt?: string;
  threadId?: string;
  parentThreadId?: string;
  payload: P;
  proof?: {
    type: string;
    cryptosuite: string;
    verificationMethod: string;
    proofPurpose: string;
    created?: string;
    proofValue: string;
  };
}

// TODO: replace with generated trust-tasks types
export interface RequestPayload {
  purpose: OobPurpose;
  mode: OobMode;
}

/** `claimDeadline` is integer epoch seconds, the unit of `_exp` (C9). */
// TODO: replace with generated trust-tasks types
export interface RequestResponse {
  requestId: string;
  claimDeadline: number;
  ext?: Record<string, unknown>;
}

// TODO: replace with generated trust-tasks types
export interface ClaimPayload {
  requestId: string;
}

// TODO: replace with generated trust-tasks types
export interface Step1Response {
  requestId: string;
  service: { did: string; name: string };
  origin: string;
  purpose: OobPurpose;
  /** Integer epoch seconds. */
  decisionDeadline: number;
}

// TODO: replace with generated trust-tasks types
export interface IdentifyPayload {
  requestId: string;
  approverKey: string;
  enteredNumber: string;
}

// TODO: replace with generated trust-tasks types
export interface ProvePayload {
  identify: OobDocument<IdentifyPayload>;
}

// TODO: replace with generated trust-tasks types
export interface Step2Response extends Step1Response {
  sessionKey: string;
  requester: {
    location: string;
    browser: string;
    os: string;
    createdAt: string;
    sameNetwork: boolean | "unknown";
  };
  identifiedAs: string;
}

// TODO: replace with generated trust-tasks types
export type GrantDecision = "approve" | "decline";

// TODO: replace with generated trust-tasks types
export interface GrantPayload {
  requestId: string;
  decision: GrantDecision;
  sessionKey: string;
  approverKey: string;
  origin: string;
  /** Multibase (`z` or `u`) sha2-256 multihash. */
  contextDigest: string;
  /** Integer epoch seconds. */
  notAfter: number;
}

// TODO: replace with generated trust-tasks types
export interface RespondPayload {
  grant: OobDocument<GrantPayload>;
}

// TODO: replace with generated trust-tasks types
export interface RedeemPayload {
  requestId: string;
}

/**
 * What a successful `redeem` returns in its body. Session material travels as
 * HttpOnly cookies, never here.
 */
// TODO: replace with generated trust-tasks types
export interface RedeemResponse {
  subject: string;
  displayName: string;
  /** Integer epoch seconds. */
  notAfter: number;
  amr: string[];
  /**
   * Service extensions under reverse-DNS namespaces. A bearer-token service
   * (such as DID hosting, `com.affinidi.did-hosting`) returns its tokens to
   * the starter here (C9).
   */
  ext?: Record<string, unknown>;
}

// TODO: replace with generated trust-tasks types
export interface RespondResponse {
  status: "approved" | "declined";
}

// TODO: replace with generated trust-tasks types
export interface CancelResponse {
  status: "cancelled";
}

// TODO: replace with generated trust-tasks types
export interface CancelPayload {
  requestId: string;
}

/** Request states (base design 7.2). */
export type OobRequestState =
  | "pending"
  | "claimed"
  | "identified"
  | "approved"
  | "consumed"
  | "declined"
  | "cancelled"
  | "expired";

/**
 * Machine-readable error codes: `auth/oob:*` for the family, and
 * `auth/oob/<task>:*` for codes one task declares (CONVENTIONS.md section 6).
 * `malformedRequest` is the framework's own code.
 */
// TODO: replace with generated trust-tasks types
export const OOB_ERRORS = {
  keyUnsupported: "auth/oob:keyUnsupported",
  rateLimited: "auth/oob:rateLimited",
  requestNotFound: "auth/oob:requestNotFound",
  requestExpired: "auth/oob:requestExpired",
  notClaimant: "auth/oob:notClaimant",
  notStarter: "auth/oob:notStarter",
  notAuthorized: "auth/oob:notAuthorized",
  alreadyDecided: "auth/oob:alreadyDecided",
  purposeUnsupported: "auth/oob/request:purposeUnsupported",
  modeUnsupported: "auth/oob/request:modeUnsupported",
  alreadyClaimed: "auth/oob/claim:alreadyClaimed",
  numberMismatch: "auth/oob/prove:numberMismatch",
  contextMismatch: "auth/oob/respond:contextMismatch",
  pending: "auth/oob/redeem:pending",
  declined: "auth/oob/redeem:declined",
  malformedRequest: "malformedRequest",
} as const;

export type OobErrorCode = (typeof OOB_ERRORS)[keyof typeof OOB_ERRORS];

/** `^[0-9]{2}$`: `matchNumber` and `enteredNumber` (C9). */
export function isMatchNumber(v: unknown): v is string {
  return typeof v === "string" && /^[0-9]{2}$/.test(v);
}

/** The payload of a `trust-task-error` document. */
export interface TrustTaskErrorPayload {
  code: string;
  message?: string;
  details?: Record<string, unknown>;
}
