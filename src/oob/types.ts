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

/**
 * `claimDeadline` is RFC 3339 here. The base design does not fix its
 * representation; the starter also accepts epoch seconds.
 */
// TODO: replace with generated trust-tasks types
export interface RequestResponse {
  requestId: string;
  claimDeadline: string | number;
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
  decisionDeadline: string;
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
  contextDigest: string;
  notAfter: string;
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
  displayName?: string;
  notAfter: string;
  amr: string[];
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

/** Machine-readable error codes used across the family. */
// TODO: replace with generated trust-tasks types
export type OobErrorCode =
  | "purposeUnsupported"
  | "modeUnsupported"
  | "keyUnsupported"
  | "rateLimited"
  | "requestNotFound"
  | "requestExpired"
  | "alreadyClaimed"
  | "notClaimant"
  | "numberMismatch"
  | "notAuthorized"
  | "alreadyDecided"
  | "contextMismatch"
  | "pending"
  | "declined"
  | "notStarter"
  | "malformedRequest";

/** The payload of a `trust-task-error` document. */
export interface TrustTaskErrorPayload {
  code: string;
  message?: string;
  details?: Record<string, unknown>;
}
