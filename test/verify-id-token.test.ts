import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { base58 } from "@scure/base";

import {
  IdTokenVerificationError,
  KeyResolver,
  constantTimeEqual,
  verifyIdToken,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

const enc = new TextEncoder();

function base64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlEncodeJson(obj: unknown): string {
  return base64urlEncode(enc.encode(JSON.stringify(obj)));
}

function mintDidKey(seed: number): { did: string; secret: Uint8Array } {
  const seedBytes = new Uint8Array(32).fill(seed);
  const pub = ed25519.getPublicKey(seedBytes);
  // multikey: 0xed 0x01 || pub
  const prefixed = new Uint8Array(2 + pub.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pub, 2);
  return {
    did: `did:key:z${base58.encode(prefixed)}`,
    secret: seedBytes,
  };
}

interface TokenOverrides {
  alg?: string;
  iss?: string;
  sub?: string;
  aud?: string;
  nonce?: string;
  iat?: number;
  exp?: number;
}

function makeToken(
  secret: Uint8Array,
  overrides: TokenOverrides,
  defaults: Required<Omit<TokenOverrides, "alg">>,
): string {
  const header = { alg: overrides.alg ?? "EdDSA", typ: "JWT" };
  const payload = {
    iss: overrides.iss ?? defaults.iss,
    sub: overrides.sub ?? defaults.sub,
    aud: overrides.aud ?? defaults.aud,
    nonce: overrides.nonce ?? defaults.nonce,
    iat: overrides.iat ?? defaults.iat,
    exp: overrides.exp ?? defaults.exp,
  };
  const headerB64 = base64urlEncodeJson(header);
  const payloadB64 = base64urlEncodeJson(payload);
  const sig = ed25519.sign(enc.encode(`${headerB64}.${payloadB64}`), secret);
  return `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("verifyIdToken", () => {
  const resolver = new KeyResolver();
  const { did, secret } = mintDidKey(7);
  const RP = "did:web:rp.example";
  const NONCE = "abc123";
  const now = Math.floor(Date.now() / 1000);
  const defaults = {
    iss: did,
    sub: did,
    aud: RP,
    nonce: NONCE,
    iat: now - 5,
    exp: now + 60,
  };

  it("verifies a well-formed id_token", async () => {
    const tok = makeToken(secret, {}, defaults);
    const v = await verifyIdToken({
      idToken: tok,
      audience: RP,
      nonce: NONCE,
      resolver,
    });
    expect(v.subject).toBe(did);
    expect(v.audience).toBe(RP);
    expect(v.nonce).toBe(NONCE);
  });

  it("rejects alg=none", async () => {
    const tok = makeToken(secret, { alg: "none" }, defaults);
    await expect(
      verifyIdToken({ idToken: tok, audience: RP, nonce: NONCE, resolver }),
    ).rejects.toMatchObject({ reason: "wrong_algorithm" });
  });

  it("rejects alg=HS256 (algorithm substitution)", async () => {
    const tok = makeToken(secret, { alg: "HS256" }, defaults);
    await expect(
      verifyIdToken({ idToken: tok, audience: RP, nonce: NONCE, resolver }),
    ).rejects.toMatchObject({ reason: "wrong_algorithm" });
  });

  it("rejects iss !== sub (not self-issued)", async () => {
    const other = mintDidKey(99);
    const tok = makeToken(secret, { sub: other.did }, defaults);
    await expect(
      verifyIdToken({ idToken: tok, audience: RP, nonce: NONCE, resolver }),
    ).rejects.toMatchObject({ reason: "self_issued_check_failed" });
  });

  it("rejects audience mismatch", async () => {
    const tok = makeToken(secret, {}, defaults);
    await expect(
      verifyIdToken({
        idToken: tok,
        audience: "did:web:attacker.example",
        nonce: NONCE,
        resolver,
      }),
    ).rejects.toMatchObject({ reason: "audience_mismatch" });
  });

  it("rejects nonce mismatch", async () => {
    const tok = makeToken(secret, {}, defaults);
    await expect(
      verifyIdToken({
        idToken: tok,
        audience: RP,
        nonce: "wrong-nonce",
        resolver,
      }),
    ).rejects.toMatchObject({ reason: "nonce_mismatch" });
  });

  it("rejects iat in the future (beyond skew)", async () => {
    const tok = makeToken(secret, { iat: now + 600 }, defaults);
    await expect(
      verifyIdToken({ idToken: tok, audience: RP, nonce: NONCE, resolver }),
    ).rejects.toMatchObject({ reason: "issued_in_future" });
  });

  it("rejects expired tokens", async () => {
    const tok = makeToken(secret, { iat: now - 600, exp: now - 60 }, defaults);
    await expect(
      verifyIdToken({ idToken: tok, audience: RP, nonce: NONCE, resolver }),
    ).rejects.toMatchObject({ reason: "expired" });
  });

  it("rejects forged signatures (different signing key)", async () => {
    const evil = mintDidKey(42);
    // Sign with `evil.secret` but claim `did` as iss/sub. The
    // resolver returns `did`'s key; signature won't verify.
    const tok = makeToken(evil.secret, {}, defaults);
    await expect(
      verifyIdToken({ idToken: tok, audience: RP, nonce: NONCE, resolver }),
    ).rejects.toMatchObject({ reason: "signature_invalid" });
  });

  it("rejects truncated tokens", async () => {
    await expect(
      verifyIdToken({
        idToken: "abc.def",
        audience: RP,
        nonce: NONCE,
        resolver,
      }),
    ).rejects.toMatchObject({ reason: "malformed" });
  });
});

describe("constantTimeEqual", () => {
  it("returns true for equal strings", () => {
    expect(constantTimeEqual("hello", "hello")).toBe(true);
  });
  it("returns false for different strings of equal length", () => {
    expect(constantTimeEqual("hello", "world")).toBe(false);
  });
  it("returns false for different lengths", () => {
    expect(constantTimeEqual("hello", "helloo")).toBe(false);
  });
});

describe("IdTokenVerificationError", () => {
  it("preserves the typed reason", () => {
    const e = new IdTokenVerificationError("x", "audience_mismatch");
    expect(e.reason).toBe("audience_mismatch");
    expect(e.name).toBe("IdTokenVerificationError");
  });
});
