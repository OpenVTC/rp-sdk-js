import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";

import { KeyResolver } from "../src/index.js";

const resolver = new KeyResolver();

function didKeyFor(pub: Uint8Array, prefix: number[] = [0xed, 0x01]): string {
  const body = new Uint8Array(prefix.length + pub.length);
  body.set(prefix, 0);
  body.set(pub, prefix.length);
  return `did:key:z${base58.encode(body)}`;
}

describe("KeyResolver", () => {
  it("resolves a valid Ed25519 did:key to its raw 32-byte public key", async () => {
    const pub = ed25519.getPublicKey(new Uint8Array(32).fill(3));
    const key = await resolver.resolveAuthenticationKey(didKeyFor(pub));
    expect(key.length).toBe(32);
    expect([...key]).toEqual([...pub]);
  });

  it("ignores a fragment on the DID URL", async () => {
    const pub = ed25519.getPublicKey(new Uint8Array(32).fill(5));
    const key = await resolver.resolveAuthenticationKey(
      `${didKeyFor(pub)}#key-1`,
    );
    expect([...key]).toEqual([...pub]);
  });

  it("rejects a non-did:key method", async () => {
    await expect(
      resolver.resolveAuthenticationKey("did:web:rp.example"),
    ).rejects.toThrow(/only handles did:key/);
  });

  it("rejects a did:key not using base58btc (z-prefix)", async () => {
    await expect(
      resolver.resolveAuthenticationKey("did:key:Qabc"),
    ).rejects.toThrow(/base58btc/);
  });

  it("rejects a did:key whose multicodec is not Ed25519", async () => {
    // 0xec 0x01 is the X25519 multicodec, not Ed25519 (0xed 0x01).
    const pub = ed25519.getPublicKey(new Uint8Array(32).fill(7));
    await expect(
      resolver.resolveAuthenticationKey(didKeyFor(pub, [0xec, 0x01])),
    ).rejects.toThrow(/not an Ed25519 multikey/);
  });

  it("rejects an Ed25519 multikey with the wrong body length", async () => {
    const shortBody = new Uint8Array(31).fill(9); // 31 bytes, not 32
    await expect(
      resolver.resolveAuthenticationKey(didKeyFor(shortBody)),
    ).rejects.toThrow(/must be 32 bytes/);
  });
});
