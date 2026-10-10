/**
 * Ed25519 `did:key` helpers for the throwaway keys of the `auth/oob` family
 * (`K_a`, `K_b`). Platform-neutral.
 */

import { base58 } from "@scure/base";

const ED25519_PREFIX = [0xed, 0x01];

/** `did:key:z6Mk…` for a raw 32-byte Ed25519 public key. */
export function ed25519DidKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(
      `Ed25519 public key must be 32 bytes, got ${publicKey.length}`,
    );
  }
  const bytes = new Uint8Array(34);
  bytes.set(ED25519_PREFIX, 0);
  bytes.set(publicKey, 2);
  return `did:key:z${base58.encode(bytes)}`;
}

/** The verification method id of an Ed25519 `did:key`: `did:key:z…#z…`. */
export function didKeyVerificationMethod(did: string): string {
  return `${did}#${did.slice("did:key:".length)}`;
}

/**
 * The raw public key of an Ed25519 `did:key`, or `null` for anything else.
 * Checks only the multicodec prefix and length, nothing more (threat T21).
 */
export function ed25519KeyFromDidKey(did: unknown): Uint8Array | null {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) return null;
  const id = did.slice("did:key:".length);
  if (id.includes("#") || id.length > 64) return null;
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(id.slice(1));
  } catch {
    return null;
  }
  if (
    decoded.length !== 34 ||
    decoded[0] !== ED25519_PREFIX[0] ||
    decoded[1] !== ED25519_PREFIX[1]
  ) {
    return null;
  }
  return decoded.slice(2);
}
