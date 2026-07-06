/**
 * `confirm/{request,response}/0.1` — the RP↔wallet consent protocol.
 *
 * A relying party asks a wallet to obtain the user's confirmation for a
 * specific action; the wallet returns a signed `confirm/response` whose W3C
 * Data Integrity `proof` **is** the cryptographic record of the user's
 * decision. This module is the RP side: it builds `confirm/request` documents
 * and verifies the wallet's `confirm/response`.
 *
 * Spec: https://trusttasks.org/spec/confirm/request/0.1 and /response/0.1.
 * The wallet producer is `@openvtc/pnm-core`'s `buildConfirmResponse`.
 *
 * Both legs travel over the framework DIDComm binding
 * (`https://trusttasks.org/binding/didcomm/0.1/envelope`): the DIDComm message
 * `type` is the binding envelope and its `body` is the Trust-Task document
 * verified here. Transport (DIDComm authcrypt) is the RP's responsibility; this
 * module operates on the already-decrypted document.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58 } from "@scure/base";

import type { DidResolver } from "./did-resolver.js";
import { jcsCanonicalize } from "./jcs.js";

export const CONFIRM_REQUEST_TYPE =
  "https://trusttasks.org/spec/confirm/request/0.1";
export const CONFIRM_RESPONSE_TYPE =
  "https://trusttasks.org/spec/confirm/response/0.1";

/** A framework Trust-Task document (the DIDComm binding `body`). */
export interface TrustTaskDocument<P = Record<string, unknown>> {
  id?: string;
  type: string;
  issuer?: string;
  recipient?: string;
  threadId?: string;
  issuedAt?: string;
  expiresAt?: string;
  payload: P;
  proof?: DataIntegrityProof;
}

/** A W3C Data Integrity proof (`eddsa-jcs-2022`). */
export interface DataIntegrityProof {
  type: string;
  cryptosuite: string;
  verificationMethod: string;
  proofPurpose: string;
  created?: string;
  proofValue: string;
}

export interface ConfirmRequestPayload {
  subject: string;
  challenge: string;
  reason: string;
  actionType?: string;
  actionDetails?: Record<string, unknown>;
  ttl?: number;
  ext?: Record<string, unknown>;
}

export interface ConfirmResponsePayload {
  subject: string;
  challenge: string;
  decision: "approved" | "denied";
  deniedReason?: string;
  ext?: Record<string, unknown>;
}

export type ConfirmVerificationReason =
  | "wrong_type"
  | "malformed_payload"
  | "no_proof"
  | "unsupported_suite"
  | "wrong_proof_purpose"
  | "resolver_failed"
  | "proof_invalid"
  | "subject_mismatch"
  | "challenge_mismatch"
  | "audience_mismatch"
  | "missing_denied_reason";

/** Thrown by {@link verifyConfirmResponse}. Inspect `.reason`. */
export class ConfirmVerificationError extends Error {
  constructor(
    readonly reason: ConfirmVerificationReason,
    message: string,
  ) {
    super(`confirm verification failed (${reason}): ${message}`);
    this.name = "ConfirmVerificationError";
  }
}

export interface VerifyConfirmResponseParams {
  /** The decrypted `confirm/response` Trust-Task document (the DIDComm `body`,
   *  or the message itself if you pass the binding envelope's body). */
  document: unknown;
  /** The subject the RP addressed the `confirm/request` to — the VID whose
   *  consent was sought. Must equal the response subject, issuer, and the
   *  proof's signer. */
  subject: string;
  /** The challenge the RP bound server-side to this pending confirm. Must be
   *  echoed bit-for-bit. */
  challenge: string;
  /** Resolves a DID to its Ed25519 verification-method key. For `did:key`,
   *  {@link KeyResolver} works out of the box. */
  resolver: DidResolver;
  /** Optional expected `recipient` (the RP's own DID) — cross-checked when set. */
  audience?: string;
}

export interface VerifiedConfirmResponse {
  subject: string;
  challenge: string;
  decision: "approved" | "denied";
  deniedReason?: string;
  /** The proven signer DID — equals `subject`. */
  signer: string;
}

/**
 * Verify a wallet's `confirm/response/0.1`. Enforces the spec's consumer
 * requirements: valid Data Integrity proof; `subject === issuer === signer`;
 * `challenge` echoed bit-for-bit; `decision` well-formed (and `deniedReason`
 * present when denied); optional `recipient` audience binding.
 *
 * The caller is still responsible for the stateful checks the SDK can't see:
 * locating the pending request by `challenge` (unknown/expired), consuming it
 * single-use, and persisting the response for audit.
 *
 * @throws {ConfirmVerificationError}
 */
export async function verifyConfirmResponse(
  params: VerifyConfirmResponseParams,
): Promise<VerifiedConfirmResponse> {
  const doc = params.document as TrustTaskDocument<Partial<ConfirmResponsePayload>>;
  if (!doc || typeof doc !== "object" || doc.type !== CONFIRM_RESPONSE_TYPE) {
    throw new ConfirmVerificationError(
      "wrong_type",
      `expected ${CONFIRM_RESPONSE_TYPE}, got ${(doc as { type?: string })?.type}`,
    );
  }

  const payload = doc.payload;
  if (
    !payload ||
    typeof payload.subject !== "string" ||
    typeof payload.challenge !== "string" ||
    (payload.decision !== "approved" && payload.decision !== "denied")
  ) {
    throw new ConfirmVerificationError("malformed_payload", "missing subject/challenge/decision");
  }
  if (payload.decision === "denied" && typeof payload.deniedReason !== "string") {
    throw new ConfirmVerificationError("missing_denied_reason", "denied response must carry deniedReason");
  }

  // The proof IS the consent record — verify it before trusting any field.
  const signer = await verifyDataIntegrityProof(doc, params.resolver, "assertionMethod");

  // subject === issuer === proof signer (SPEC confirm/response §Conformance).
  if (doc.issuer !== undefined && doc.issuer !== payload.subject) {
    throw new ConfirmVerificationError("subject_mismatch", `issuer ${doc.issuer} != subject ${payload.subject}`);
  }
  if (signer !== payload.subject) {
    throw new ConfirmVerificationError("subject_mismatch", `proof signer ${signer} != subject ${payload.subject}`);
  }
  if (payload.subject !== params.subject) {
    throw new ConfirmVerificationError("subject_mismatch", `subject ${payload.subject} != requested ${params.subject}`);
  }

  if (payload.challenge !== params.challenge) {
    throw new ConfirmVerificationError("challenge_mismatch", "response challenge does not match the bound challenge");
  }

  if (params.audience !== undefined && doc.recipient !== undefined && doc.recipient !== params.audience) {
    throw new ConfirmVerificationError("audience_mismatch", `recipient ${doc.recipient} != ${params.audience}`);
  }

  return {
    subject: payload.subject,
    challenge: payload.challenge,
    decision: payload.decision,
    ...(payload.deniedReason ? { deniedReason: payload.deniedReason } : {}),
    signer,
  };
}

/**
 * Verify the `eddsa-jcs-2022` Data Integrity proof on a Trust-Task document.
 * Returns the proven signer DID (the controller of the proof's
 * `verificationMethod`). Does NOT check framework bindings — the caller does.
 *
 * The signing input matches the wallet + VTA: `SHA-256(JCS(proofConfig)) ||
 * SHA-256(JCS(document − proof))`, where `proofConfig` is the proof object
 * without `proofValue`.
 *
 * @throws {ConfirmVerificationError}
 */
export async function verifyDataIntegrityProof(
  document: TrustTaskDocument,
  resolver: DidResolver,
  expectedProofPurpose?: string,
): Promise<string> {
  const proof = document.proof;
  if (!proof || typeof proof !== "object") {
    throw new ConfirmVerificationError("no_proof", "document has no proof");
  }
  if (proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "eddsa-jcs-2022") {
    throw new ConfirmVerificationError("unsupported_suite", `${proof.type}/${proof.cryptosuite}`);
  }
  if (expectedProofPurpose && proof.proofPurpose !== expectedProofPurpose) {
    throw new ConfirmVerificationError("wrong_proof_purpose", `${proof.proofPurpose} != ${expectedProofPurpose}`);
  }
  const vm = proof.verificationMethod;
  if (typeof vm !== "string" || !vm.includes("#")) {
    throw new ConfirmVerificationError("proof_invalid", "missing/invalid verificationMethod");
  }
  if (typeof proof.proofValue !== "string" || !proof.proofValue.startsWith("z")) {
    throw new ConfirmVerificationError("proof_invalid", "proofValue must be multibase base58btc ('z')");
  }
  const controller = vm.slice(0, vm.indexOf("#"));

  let publicKey: Uint8Array;
  try {
    publicKey = await resolver.resolveAuthenticationKey(controller);
  } catch (e) {
    throw new ConfirmVerificationError(
      "resolver_failed",
      `could not resolve ${controller}: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  const proofConfig: Record<string, unknown> = { ...proof };
  delete proofConfig.proofValue;
  const docCopy: Record<string, unknown> = { ...document };
  delete docCopy.proof;

  const toVerify = new Uint8Array(64);
  toVerify.set(sha256(new TextEncoder().encode(jcsCanonicalize(proofConfig))), 0);
  toVerify.set(sha256(new TextEncoder().encode(jcsCanonicalize(docCopy))), 32);

  let sig: Uint8Array;
  try {
    sig = base58.decode(proof.proofValue.slice(1));
  } catch (e) {
    throw new ConfirmVerificationError("proof_invalid", `bad base58btc proofValue: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (sig.length !== 64) {
    throw new ConfirmVerificationError("proof_invalid", `signature must be 64 bytes, got ${sig.length}`);
  }
  if (!ed25519.verify(sig, toVerify, publicKey)) {
    throw new ConfirmVerificationError("proof_invalid", "Ed25519 signature verification failed");
  }
  return controller;
}

export interface BuildConfirmRequestParams {
  /** The RP's own DID — becomes the document `issuer`. */
  issuer: string;
  /** The VID whose consent is sought (usually the wallet's holder DID). */
  subject: string;
  /** base64url nonce, ≥128 bits, bound server-side to (subject, action). */
  challenge: string;
  /** User-meaningful action description, shown verbatim by the wallet. */
  reason: string;
  /** Optional machine-readable action category (e.g. `payment.transfer`). */
  actionType?: string;
  /** Optional structured action detail the wallet MAY surface. */
  actionDetails?: Record<string, unknown>;
  /** Advisory seconds within which the RP expects a response. */
  ttl?: number;
  /** Explicit document id; a UUID is generated when omitted. */
  id?: string;
  /** RFC 3339 timestamp; defaults to now. */
  issuedAt?: string;
}

/**
 * Build a `confirm/request/0.1` Trust-Task document addressed to `subject`.
 * The spec declares the request `proof` REQUIRED (it binds `reason` to the
 * RP's key); attach one with {@link signConfirmRequest} before sending, unless
 * you are relying solely on a mutually-authenticated transport.
 */
export function buildConfirmRequest(params: BuildConfirmRequestParams): TrustTaskDocument<ConfirmRequestPayload> {
  const payload: ConfirmRequestPayload = {
    subject: params.subject,
    challenge: params.challenge,
    reason: params.reason,
    ...(params.actionType ? { actionType: params.actionType } : {}),
    ...(params.actionDetails ? { actionDetails: params.actionDetails } : {}),
    ...(params.ttl !== undefined ? { ttl: params.ttl } : {}),
  };
  return {
    id: params.id ?? crypto.randomUUID(),
    type: CONFIRM_REQUEST_TYPE,
    issuer: params.issuer,
    recipient: params.subject,
    issuedAt: params.issuedAt ?? new Date().toISOString(),
    payload,
  };
}

/** A detached Ed25519 signer the RP plugs in to sign a request (keeps key
 *  management out of the SDK). */
export interface ConfirmSigner {
  /** The proof's `verificationMethod` — a DID URL resolving to `sign`'s key. */
  verificationMethod: string;
  /** Sign 64 bytes of hash input, returning the 64-byte Ed25519 signature. */
  sign(input: Uint8Array): Uint8Array | Promise<Uint8Array>;
  /** RFC 3339 `created`; defaults to now. */
  created?: string;
}

/**
 * Attach an `eddsa-jcs-2022` Data Integrity proof to a document in place and
 * return it. Mirrors the wallet's signer so an RP-signed `confirm/request`
 * verifies with {@link verifyDataIntegrityProof}.
 */
export async function signConfirmRequest(
  document: TrustTaskDocument,
  signer: ConfirmSigner,
  proofPurpose: "assertionMethod" | "authentication" = "assertionMethod",
): Promise<TrustTaskDocument> {
  const proofConfig: Record<string, unknown> = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: signer.verificationMethod,
    created: signer.created ?? new Date().toISOString(),
    proofPurpose,
  };
  const docCopy: Record<string, unknown> = { ...document };
  delete docCopy.proof;

  const toSign = new Uint8Array(64);
  toSign.set(sha256(new TextEncoder().encode(jcsCanonicalize(proofConfig))), 0);
  toSign.set(sha256(new TextEncoder().encode(jcsCanonicalize(docCopy))), 32);

  const sig = await signer.sign(toSign);
  if (sig.length !== 64) throw new Error(`signer returned ${sig.length}-byte signature, expected 64`);
  proofConfig.proofValue = "z" + base58.encode(sig);
  document.proof = proofConfig as unknown as DataIntegrityProof;
  return document;
}
