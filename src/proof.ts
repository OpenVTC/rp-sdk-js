/**
 * The `eddsa-jcs-2022` Data Integrity hashing and signing shared by every
 * Trust-Task document this SDK builds or verifies.
 *
 * `hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document − proof))`,
 * where `proofConfig` is the proof object without `proofValue`. This must stay
 * byte-identical to the wallet (`@openvtc/pnm-core`), the VTA and the VTC, or
 * proofs stop verifying.
 *
 * Platform-neutral: only `@noble/hashes` and `@scure/base`, so the browser
 * entry point can use it as well as Node.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { base58 } from "@scure/base";

import { jcsCanonicalize } from "./jcs.js";

/**
 * The 64-byte Ed25519 signing input for a document and its proof config.
 * `proof` is removed from the document, and `proofValue` from the config, so a
 * caller may pass either signed or unsigned objects.
 *
 * Throws {@link JcsLimitExceededError} for a document past the JCS bounds.
 */
export function eddsaJcsHashInput(
  document: Record<string, unknown>,
  proof: Record<string, unknown>,
): Uint8Array {
  const proofConfig: Record<string, unknown> = { ...proof };
  delete proofConfig.proofValue;
  const docCopy: Record<string, unknown> = { ...document };
  delete docCopy.proof;

  const out = new Uint8Array(64);
  out.set(sha256(new TextEncoder().encode(jcsCanonicalize(proofConfig))), 0);
  out.set(sha256(new TextEncoder().encode(jcsCanonicalize(docCopy))), 32);
  return out;
}

/** What {@link attachEddsaJcsProof} needs from a key. */
export interface EddsaJcsSigner {
  /** The proof's `verificationMethod`: a DID URL resolving to this key. */
  verificationMethod: string;
  /** Sign the 64-byte hash input; return the 64-byte Ed25519 signature. */
  sign(input: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/**
 * Return a copy of `document` carrying an `eddsa-jcs-2022` proof.
 *
 * `created` should be whole-second RFC 3339 (see {@link isoSeconds}): the VTC
 * re-serialises timestamps through chrono before it hashes them.
 */
export async function attachEddsaJcsProof<T extends object>(
  document: T,
  signer: EddsaJcsSigner,
  options: {
    proofPurpose: "assertionMethod" | "authentication";
    created: string;
  },
): Promise<T & { proof: Record<string, string> }> {
  const proofConfig: Record<string, string> = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: signer.verificationMethod,
    created: options.created,
    proofPurpose: options.proofPurpose,
  };
  const input = eddsaJcsHashInput(
    document as unknown as Record<string, unknown>,
    proofConfig,
  );
  const sig = await signer.sign(input);
  if (sig.length !== 64) {
    throw new Error(
      `signer returned ${sig.length}-byte signature, expected 64`,
    );
  }
  const unsigned = { ...document } as Record<string, unknown>;
  delete unsigned.proof;
  return {
    ...(unsigned as unknown as T),
    proof: { ...proofConfig, proofValue: "z" + base58.encode(sig) },
  };
}

/**
 * RFC 3339 UTC at whole-second precision (`2026-10-10T10:15:00Z`).
 *
 * The VTC parses `issuedAt` into a `chrono::DateTime<Utc>` and re-serialises
 * it before hashing; chrono drops a zero fractional part, while
 * `toISOString` always writes `.000`. Truncating makes the round trip exact.
 */
export function isoSeconds(at: Date): string {
  return `${at.toISOString().slice(0, 19)}Z`;
}
