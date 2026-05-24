/**
 * DID resolution interface for [`verifyIdToken`](./verify-id-token.ts).
 *
 * The SDK ships an in-process [`KeyResolver`] for `did:key` because
 * those DIDs encode their public key in the identifier itself —
 * no network round-trip. did:peer:2 and did:webvh resolution
 * require external infrastructure; callers provide their own
 * implementation, typically a thin wrapper around the
 * `affinidi-did-resolver-cache-sdk` (Rust → wasm) or an HTTP
 * proxy in front of the OpenVTC trust-registry.
 */

import { base58 } from "@scure/base";

/**
 * Minimal DID resolver contract.
 *
 * Implementations return the Ed25519 public-key bytes (32 raw
 * bytes, not multikey-encoded) for the issuer's authentication
 * verification method.
 *
 * Production resolvers should cache resolved keys per DID with
 * the TTL the underlying DID method recommends (10 min for
 * did:webvh; effectively forever for did:key since the key is
 * encoded in the identifier).
 */
export interface DidResolver {
  /**
   * Resolve a DID's authentication verification method to its
   * raw Ed25519 public key bytes.
   *
   * Throws if the DID can't be resolved, doesn't have an
   * Ed25519 authentication method, or has a different
   * verification method type. The caller maps the thrown error
   * to [`IdTokenVerificationError.resolver_failed`].
   */
  resolveAuthenticationKey(did: string): Promise<Uint8Array>;
}

/**
 * In-process resolver for `did:key:z6Mk…` (Ed25519 multikey).
 *
 * The DID identifier itself encodes the public key — no network
 * call, no cache invalidation, no key-rotation concern. Safe
 * default for SIOPv2 flows where the wallet's holder DID is
 * always `did:key`.
 *
 * For `did:peer:2` or `did:webvh` callers, write a custom
 * `DidResolver` and pass it explicitly.
 */
export class KeyResolver implements DidResolver {
  async resolveAuthenticationKey(did: string): Promise<Uint8Array> {
    if (!did.startsWith("did:key:")) {
      throw new Error(
        `KeyResolver only handles did:key, got ${did.split(":", 2).join(":")}`,
      );
    }
    const id = did.slice("did:key:".length).split("#", 1)[0];

    // did:key multibase: base58btc-encoded multikey. Ed25519 has
    // multicodec prefix `0xed01` (varint).
    if (!id.startsWith("z")) {
      throw new Error(`did:key identifier must use base58btc (z-prefix)`);
    }
    const decoded = base58.decode(id.slice(1));

    // Multicodec varint: Ed25519 = 0xed 0x01.
    if (decoded.length < 2 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
      throw new Error(`did:key is not an Ed25519 multikey`);
    }
    const keyBytes = decoded.slice(2);
    if (keyBytes.length !== 32) {
      throw new Error(
        `did:key Ed25519 body must be 32 bytes, got ${keyBytes.length}`,
      );
    }
    return keyBytes;
  }
}
