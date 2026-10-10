/**
 * Build and sign `auth/oob/*` documents. Platform-neutral: the signer is a
 * callback, so the browser uses WebCrypto and Node uses whatever key custody
 * the site has.
 */

import {
  attachEddsaJcsProof,
  isoSeconds,
  type EddsaJcsSigner,
} from "../proof.js";
import type { OobDocument } from "./types.js";

/**
 * How far a proof's `created` is back-dated. A Data Integrity verifier
 * rejects a `created` in its own future with no skew allowance; `issuedAt`
 * carries the real freshness bound.
 */
export const CREATED_BACKDATE_MS = 60_000;

export interface BuildOobDocumentParams<P> {
  type: string;
  issuer: string;
  recipient: string;
  payload: P;
  threadId?: string;
  parentThreadId?: string;
  /** Test seam; defaults to now. */
  now?: Date;
  /** Test seam; defaults to a random `urn:uuid:`. */
  id?: string;
}

/** An unsigned document with a fresh `urn:uuid:` id and whole-second `issuedAt`. */
export function buildOobDocument<P>(
  params: BuildOobDocumentParams<P>,
): OobDocument<P> {
  return {
    id: params.id ?? `urn:uuid:${crypto.randomUUID()}`,
    type: params.type,
    issuer: params.issuer,
    recipient: params.recipient,
    issuedAt: isoSeconds(params.now ?? new Date()),
    ...(params.threadId !== undefined ? { threadId: params.threadId } : {}),
    ...(params.parentThreadId !== undefined
      ? { parentThreadId: params.parentThreadId }
      : {}),
    payload: params.payload,
  };
}

/** Sign a document with an `eddsa-jcs-2022` proof. */
export async function signOobDocument<P>(
  doc: OobDocument<P>,
  signer: EddsaJcsSigner,
  options: {
    proofPurpose?: "assertionMethod" | "authentication";
    now?: Date;
  } = {},
): Promise<OobDocument<P>> {
  const created = isoSeconds(
    new Date((options.now?.getTime() ?? Date.now()) - CREATED_BACKDATE_MS),
  );
  return (await attachEddsaJcsProof(doc, signer, {
    proofPurpose: options.proofPurpose ?? "assertionMethod",
    created,
  })) as OobDocument<P>;
}
