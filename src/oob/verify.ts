/**
 * Server-side verification of `auth/oob/*` documents, for a site that is
 * itself the sign-in service.
 *
 * Each function checks one document: type, framework bindings (`recipient`,
 * `id`, freshness), the `eddsa-jcs-2022` proof against the right key and
 * verification relationship, and the cross-document bindings of base design
 * section 7 and contract C5. What they cannot see (request state, the ACL,
 * replay of `id`) is the caller's, or {@link OobSignInService}'s.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58, base64urlnopad, hex } from "@scure/base";

import { JcsLimitExceededError, jcsCanonicalize } from "../jcs.js";
import { eddsaJcsHashInput } from "../proof.js";
import { constantTimeEqual } from "../verify-id-token.js";
import { didKeyVerificationMethod, ed25519KeyFromDidKey } from "./did-key.js";
import {
  resolveRelationshipKey,
  type DidDocumentResolver,
  type VerificationRelationship,
} from "./did-document.js";
import {
  OOB_TYPES,
  type ClaimPayload,
  type GrantDecision,
  type GrantPayload,
  type IdentifyPayload,
  type OobDocument,
  isMatchNumber,
} from "./types.js";

export type OobVerificationReason =
  | "wrong_type"
  | "malformed"
  | "document_too_complex"
  | "audience_mismatch"
  | "expired"
  | "not_yet_valid"
  | "no_proof"
  | "unsupported_suite"
  | "wrong_proof_purpose"
  | "key_unsupported"
  | "issuer_mismatch"
  | "resolver_failed"
  | "proof_invalid"
  | "parent_thread_mismatch"
  | "request_mismatch"
  | "approver_mismatch"
  | "session_key_mismatch"
  | "origin_mismatch"
  | "context_mismatch";

/** Thrown by every `verifyOob*` function. Inspect `.reason`. */
export class OobVerificationError extends Error {
  constructor(
    readonly reason: OobVerificationReason,
    message: string,
  ) {
    super(`auth/oob verification failed (${reason}): ${message}`);
    this.name = "OobVerificationError";
  }
}

/** Options every verifier takes. */
export interface OobVerifyCommon {
  /** This service's DID. The document's `recipient` must equal it. */
  serviceDid: string;
  /** Clock reading. Defaults to now. */
  now?: Date;
  /** Oldest acceptable `issuedAt`, seconds. Default 300. */
  maxAgeSecs?: number;
  /** Allowed `issuedAt` in the future, seconds. Default 60. */
  clockSkewSecs?: number;
}

/** What a verifier returns about any document. */
export interface VerifiedOobDocument<P> {
  /** The document `id`. Record it; refuse it if seen before. */
  id: string;
  /** The proven issuer DID. */
  issuer: string;
  payload: P;
}

const fail = (reason: OobVerificationReason, message: string): never => {
  throw new OobVerificationError(reason, message);
};

function checkEnvelope<P>(
  raw: unknown,
  type: string,
  common: OobVerifyCommon,
): OobDocument<P> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    fail("malformed", "document is not an object");
  }
  const doc = raw as OobDocument<P>;
  if (doc.type !== type)
    fail("wrong_type", `expected ${type}, got ${String(doc.type)}`);
  if (typeof doc.id !== "string" || doc.id.length === 0)
    fail("malformed", "missing id");
  if (typeof doc.issuer !== "string") fail("malformed", "missing issuer");
  if (
    !doc.payload ||
    typeof doc.payload !== "object" ||
    Array.isArray(doc.payload)
  ) {
    fail("malformed", "missing payload");
  }
  if (doc.recipient !== common.serviceDid) {
    fail(
      "audience_mismatch",
      `recipient ${doc.recipient ?? "(absent)"} != ${common.serviceDid}`,
    );
  }
  const now = (common.now ?? new Date()).getTime();
  const issuedAt =
    typeof doc.issuedAt === "string" ? Date.parse(doc.issuedAt) : NaN;
  if (!Number.isFinite(issuedAt))
    fail("malformed", "missing or unparseable issuedAt");
  if (issuedAt > now + (common.clockSkewSecs ?? 60) * 1000) {
    fail("not_yet_valid", `issuedAt ${doc.issuedAt} is in the future`);
  }
  if (now - issuedAt > (common.maxAgeSecs ?? 300) * 1000) {
    fail("expired", `issuedAt ${doc.issuedAt} is too old`);
  }
  if (doc.expiresAt !== undefined) {
    const exp = Date.parse(doc.expiresAt);
    if (!Number.isFinite(exp)) fail("malformed", "unparseable expiresAt");
    if (exp <= now) fail("expired", `expired at ${doc.expiresAt}`);
  }
  return doc;
}

/** Check the proof's shape and return its verification method. */
function checkProofShape(
  doc: OobDocument<unknown>,
  purposes: string[],
): string {
  const proof = doc.proof;
  if (!proof || typeof proof !== "object")
    fail("no_proof", "document has no proof");
  const p = proof!;
  if (p.type !== "DataIntegrityProof" || p.cryptosuite !== "eddsa-jcs-2022") {
    fail("unsupported_suite", `${p.type}/${p.cryptosuite}`);
  }
  if (!purposes.includes(p.proofPurpose)) {
    fail(
      "wrong_proof_purpose",
      `${p.proofPurpose} is not ${purposes.join(" or ")}`,
    );
  }
  if (
    typeof p.verificationMethod !== "string" ||
    !p.verificationMethod.includes("#")
  ) {
    fail("proof_invalid", "missing or invalid verificationMethod");
  }
  if (typeof p.proofValue !== "string" || !p.proofValue.startsWith("z")) {
    fail("proof_invalid", "proofValue must be multibase base58btc");
  }
  const controller = p.verificationMethod.slice(
    0,
    p.verificationMethod.indexOf("#"),
  );
  if (controller !== doc.issuer) {
    fail(
      "issuer_mismatch",
      `proof signer ${controller} != issuer ${doc.issuer}`,
    );
  }
  return p.verificationMethod;
}

function checkSignature(
  doc: OobDocument<unknown>,
  publicKey: Uint8Array,
): void {
  let input: Uint8Array;
  try {
    input = eddsaJcsHashInput(
      doc as unknown as Record<string, unknown>,
      doc.proof as unknown as Record<string, unknown>,
    );
  } catch (e) {
    if (e instanceof JcsLimitExceededError)
      fail("document_too_complex", e.message);
    throw e;
  }
  let sig: Uint8Array = new Uint8Array();
  try {
    sig = base58.decode(doc.proof!.proofValue.slice(1));
  } catch {
    fail("proof_invalid", "bad base58btc proofValue");
  }
  if (sig.length !== 64)
    fail("proof_invalid", `signature is ${sig.length} bytes`);
  if (!ed25519.verify(sig, input!, publicKey)) {
    fail("proof_invalid", "Ed25519 signature verification failed");
  }
}

/**
 * Verify a document issued and signed by an Ed25519 `did:key` (`K_a` or
 * `K_b`): `request`, `claim`, `prove`, `respond`, `redeem`, `cancel`.
 * Anything but an Ed25519 `did:key` is `key_unsupported` (threat T21).
 */
export function verifyDidKeyDocument<P>(
  raw: unknown,
  type: string,
  common: OobVerifyCommon,
): VerifiedOobDocument<P> {
  const doc = checkEnvelope<P>(raw, type, common);
  const key = ed25519KeyFromDidKey(doc.issuer);
  if (!key) fail("key_unsupported", "issuer must be an Ed25519 did:key");
  // CONVENTIONS.md section 5 rule 4: starter and lock keys sign with
  // `authentication`.
  const vm = checkProofShape(doc, ["authentication"]);
  if (vm !== didKeyVerificationMethod(doc.issuer)) {
    fail("proof_invalid", `verificationMethod ${vm} is not the did:key's key`);
  }
  checkSignature(doc, key!);
  return { id: doc.id, issuer: doc.issuer, payload: doc.payload };
}

async function verifyDidDocument<P>(
  raw: unknown,
  type: string,
  relationship: VerificationRelationship,
  resolver: DidDocumentResolver,
  common: OobVerifyCommon,
): Promise<VerifiedOobDocument<P>> {
  const doc = checkEnvelope<P>(raw, type, common);
  const vm = checkProofShape(doc, [relationship]);
  let key: Uint8Array = new Uint8Array();
  try {
    key = await resolveRelationshipKey(resolver, doc.issuer, vm, relationship);
  } catch (e) {
    fail("resolver_failed", e instanceof Error ? e.message : String(e));
  }
  checkSignature(doc, key);
  return { id: doc.id, issuer: doc.issuer, payload: doc.payload };
}

function isRequestId(v: unknown): v is string {
  return typeof v === "string" && /^[A-Za-z0-9\-_]{22,43}$/.test(v);
}

/** A verified `auth/oob/claim`. */
export interface VerifiedClaim extends VerifiedOobDocument<ClaimPayload> {
  /** `K_a`: the lock this claim asks for. */
  approverKey: string;
  requestId: string;
}

/**
 * Verify `auth/oob/claim/0.1` (VTI-LNK-054, contract C5): issued and signed by
 * an Ed25519 `did:key`, addressed to this service, with a unique `id` and a
 * `parentThreadId` equal to `payload.requestId`.
 *
 * @throws {OobVerificationError}
 */
export function verifyOobClaim(
  raw: unknown,
  common: OobVerifyCommon,
): VerifiedClaim {
  const v = verifyDidKeyDocument<ClaimPayload>(raw, OOB_TYPES.claim, common);
  if (!isRequestId(v.payload.requestId))
    fail("malformed", "payload.requestId is missing");
  const parent = (raw as OobDocument<unknown>).parentThreadId;
  if (parent !== v.payload.requestId) {
    fail(
      "parent_thread_mismatch",
      `parentThreadId ${parent ?? "(absent)"} != requestId`,
    );
  }
  return { ...v, approverKey: v.issuer, requestId: v.payload.requestId };
}

export interface VerifyIdentifyParams extends OobVerifyCommon {
  resolver: DidDocumentResolver;
  /** The request this identify must name. */
  requestId: string;
  /** The lock (`K_a`) this identify must name. */
  approverKey: string;
}

/**
 * Verify `auth/oob/identify/0.1`, carried in `prove`. The proof must verify
 * against a key the issuer lists under **`authentication`** (contract C5,
 * which replaces base design 7.4's `assertionMethod`), with that proof
 * purpose. Check the issuer against your ACL **before** calling this, so a
 * non-member costs no DID resolution (base design 7.4 step 3).
 *
 * @throws {OobVerificationError}
 */
export async function verifyOobIdentify(
  raw: unknown,
  params: VerifyIdentifyParams,
): Promise<VerifiedOobDocument<IdentifyPayload> & { did: string }> {
  const v = await verifyDidDocument<IdentifyPayload>(
    raw,
    OOB_TYPES.identify,
    "authentication",
    params.resolver,
    params,
  );
  const p = v.payload;
  const keys = Object.keys(p).sort().join(",");
  if (
    keys !== "approverKey,enteredNumber,requestId" ||
    !isMatchNumber(p.enteredNumber)
  ) {
    fail(
      "malformed",
      "identify payload must be exactly {requestId, approverKey, enteredNumber}",
    );
  }
  if (p.requestId !== params.requestId)
    fail("request_mismatch", "identify names another request");
  if (p.approverKey !== params.approverKey)
    fail("approver_mismatch", "identify names another lock");
  return { ...v, did: v.issuer };
}

export interface VerifyGrantParams extends OobVerifyCommon {
  resolver: DidDocumentResolver;
  requestId: string;
  /** The DID that proved membership. The grant must be issued by it. */
  identifiedDid: string;
  /** The lock, `K_a`. */
  approverKey: string;
  /** The starter key, `K_b`. */
  sessionKey: string;
  /** The portal origin stored on the request. */
  origin: string;
  /**
   * The stored context digest ({@link computeContextDigest} of the signed
   * step 2 response). Pass this or `step2Response`.
   */
  contextDigest?: string;
  /** The signed step 2 response, to digest here. */
  step2Response?: unknown;
}

export interface VerifiedGrant extends VerifiedOobDocument<GrantPayload> {
  decision: GrantDecision;
  notAfter: Date;
}

/**
 * Verify `auth/oob/grant/0.1`, carried in `respond` (base design 7.5): issued
 * by `identifiedDid`, proof against **`assertionMethod`**, naming the lock,
 * the starter key, the origin and the digest of the step 2 response.
 *
 * @throws {OobVerificationError}
 */
export async function verifyOobGrant(
  raw: unknown,
  params: VerifyGrantParams,
): Promise<VerifiedGrant> {
  const doc = raw as OobDocument<unknown> | null;
  if (doc && typeof doc === "object" && doc.issuer !== params.identifiedDid) {
    fail(
      "issuer_mismatch",
      "grant is not issued by the DID that proved membership",
    );
  }
  const v = await verifyDidDocument<GrantPayload>(
    raw,
    OOB_TYPES.grant,
    "assertionMethod",
    params.resolver,
    params,
  );
  const p = v.payload;
  if (p.decision !== "approve" && p.decision !== "decline") {
    fail("malformed", "decision must be approve or decline");
  }
  // Integer epoch seconds only (C9); RFC 3339 is refused.
  if (!Number.isSafeInteger(p.notAfter) || p.notAfter < 0)
    fail("malformed", "notAfter must be integer epoch seconds");
  const notAfter = new Date(p.notAfter * 1000);
  if (typeof p.contextDigest !== "string")
    fail("malformed", "missing contextDigest");
  if (p.requestId !== params.requestId)
    fail("request_mismatch", "grant names another request");
  if (p.approverKey !== params.approverKey)
    fail("approver_mismatch", "grant names another lock");
  if (p.sessionKey !== params.sessionKey)
    fail("session_key_mismatch", "grant names another browser key");
  if (p.origin !== params.origin)
    fail("origin_mismatch", `grant origin ${p.origin} != ${params.origin}`);
  const expected =
    params.contextDigest ??
    (params.step2Response !== undefined
      ? computeContextDigest(params.step2Response)
      : undefined);
  if (expected === undefined)
    throw new TypeError("pass contextDigest or step2Response");
  if (!contextDigestsEqual(p.contextDigest, expected)) {
    fail(
      "context_mismatch",
      "contextDigest does not match the step 2 response",
    );
  }
  return { ...v, decision: p.decision, notAfter };
}

/**
 * `contextDigest`: SHA-256 of the JCS-canonical **signed** step 2 response,
 * proof included. Encoded as a multibase (base58btc) sha2-256 multihash,
 * `zQm…`, the encoding the trust-task family uses for digests.
 */
export function computeContextDigest(signedStep2Response: unknown): string {
  const digest = sha256(
    new TextEncoder().encode(jcsCanonicalize(signedStep2Response)),
  );
  const mh = new Uint8Array(34);
  mh[0] = 0x12;
  mh[1] = 0x20;
  mh.set(digest, 2);
  return "z" + base58.encode(mh);
}

/** Decode a context digest to its 32 raw bytes, or null. */
function decodeDigest(s: string): Uint8Array | null {
  try {
    let bytes: Uint8Array;
    if (s.startsWith("z")) bytes = base58.decode(s.slice(1));
    else if (s.startsWith("u")) bytes = base64urlnopad.decode(s.slice(1));
    else return null;
    if (bytes.length === 34 && bytes[0] === 0x12 && bytes[1] === 0x20)
      return bytes.slice(2);
    return null;
  } catch {
    return null;
  }
}

/**
 * Compare two context digests by their bytes. Accepts a multibase
 * (`z` base58btc or `u` base64url) sha2-256 multihash, as the schema's
 * `DigestMultibase` allows. Anything else, hex included, never matches.
 */
export function contextDigestsEqual(a: string, b: string): boolean {
  const x = decodeDigest(a);
  const y = decodeDigest(b);
  if (!x || !y) return false;
  return constantTimeEqual(hex.encode(x), hex.encode(y));
}
