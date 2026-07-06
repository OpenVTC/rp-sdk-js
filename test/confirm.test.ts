import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";

import {
  verifyConfirmResponse,
  buildConfirmRequest,
  signConfirmRequest,
  verifyDataIntegrityProof,
  ConfirmVerificationError,
  KeyResolver,
  CONFIRM_REQUEST_TYPE,
  type ConfirmSigner,
  type TrustTaskDocument,
} from "../src/index.js";

const resolver = new KeyResolver();

// A cross-implementation fixture: these documents were produced by the WALLET's
// actual signer (`@openvtc/pnm-core` buildConfirmResponseDocument). If rp-sdk's
// independent JCS + eddsa-jcs-2022 verifier accepts them, the two
// implementations canonicalize + hash byte-identically. Regenerate with the
// script in the PR description if the wire format changes.
const fixture = JSON.parse(
  readFileSync(fileURLToPath(new URL("./confirm-fixture.json", import.meta.url)), "utf8"),
) as {
  holderDid: string;
  rpDid: string;
  approved: TrustTaskDocument;
  denied: TrustTaskDocument;
};

const CHALLENGE = "VHJhbnNmZXJDb25maXJtTm9uY2VYWQ";

describe("verifyConfirmResponse (cross-impl fixture from the wallet signer)", () => {
  it("verifies a wallet-signed approved response", async () => {
    const result = await verifyConfirmResponse({
      document: fixture.approved,
      subject: fixture.holderDid,
      challenge: CHALLENGE,
      audience: fixture.rpDid,
      resolver,
    });
    expect(result.decision).toBe("approved");
    expect(result.subject).toBe(fixture.holderDid);
    expect(result.signer).toBe(fixture.holderDid);
    expect(result.challenge).toBe(CHALLENGE);
  });

  it("verifies a wallet-signed denied response with its deniedReason", async () => {
    const result = await verifyConfirmResponse({
      document: fixture.denied,
      subject: fixture.holderDid,
      challenge: CHALLENGE,
      resolver,
    });
    expect(result.decision).toBe("denied");
    expect(result.deniedReason).toBe("User does not recognize this transfer.");
  });

  it("rejects a tampered decision (proof no longer matches)", async () => {
    // Flip the signed `denied` decision to `approved` (which needs no
    // deniedReason, so the malformed-payload guards pass) — the proof over the
    // original bytes must catch the change.
    const tampered = structuredClone(fixture.denied);
    (tampered.payload as { decision: string; deniedReason?: string }).decision = "approved";
    delete (tampered.payload as { deniedReason?: string }).deniedReason;
    await expect(
      verifyConfirmResponse({ document: tampered, subject: fixture.holderDid, challenge: CHALLENGE, resolver }),
    ).rejects.toMatchObject({ reason: "proof_invalid" });
  });

  it("rejects a challenge that does not match the bound challenge", async () => {
    await expect(
      verifyConfirmResponse({ document: fixture.approved, subject: fixture.holderDid, challenge: "different", resolver }),
    ).rejects.toBeInstanceOf(ConfirmVerificationError);
  });

  it("rejects a subject other than the addressed one", async () => {
    await expect(
      verifyConfirmResponse({ document: fixture.approved, subject: "did:key:zSomeoneElse", challenge: CHALLENGE, resolver }),
    ).rejects.toMatchObject({ reason: "subject_mismatch" });
  });

  it("rejects a recipient that does not match the expected audience", async () => {
    await expect(
      verifyConfirmResponse({
        document: fixture.approved,
        subject: fixture.holderDid,
        challenge: CHALLENGE,
        audience: "did:key:zWrongRp",
        resolver,
      }),
    ).rejects.toMatchObject({ reason: "audience_mismatch" });
  });

  it("rejects a non-confirm-response document", async () => {
    await expect(
      verifyConfirmResponse({
        document: { type: "https://trusttasks.org/spec/other/1.0", payload: {} },
        subject: fixture.holderDid,
        challenge: CHALLENGE,
        resolver,
      }),
    ).rejects.toMatchObject({ reason: "wrong_type" });
  });
});

describe("buildConfirmRequest + signConfirmRequest round-trip", () => {
  // An RP-side signer over a fresh Ed25519 key, exposed as a did:key.
  function makeSigner(): { signer: ConfirmSigner; did: string } {
    const priv = ed25519.utils.randomSecretKey();
    const pub = ed25519.getPublicKey(priv);
    const body = new Uint8Array(2 + pub.length);
    body.set([0xed, 0x01], 0);
    body.set(pub, 2);
    const did = `did:key:z${base58.encode(body)}`;
    return {
      did,
      signer: {
        verificationMethod: `${did}#${did.slice("did:key:".length)}`,
        sign: (input) => ed25519.sign(input, priv),
      },
    };
  }

  it("builds a spec-shaped request and its DI proof verifies", async () => {
    const { signer, did } = makeSigner();
    const doc = buildConfirmRequest({
      issuer: did,
      subject: fixture.holderDid,
      challenge: CHALLENGE,
      reason: "Confirm transfer of $1,000 to did:web:bob.example",
      actionType: "payment.transfer",
      actionDetails: { amount: "1000", currency: "USD" },
      ttl: 180,
    });
    expect(doc.type).toBe(CONFIRM_REQUEST_TYPE);
    expect(doc.recipient).toBe(fixture.holderDid);

    await signConfirmRequest(doc, signer);
    const signer2 = await verifyDataIntegrityProof(doc, resolver, "assertionMethod");
    expect(signer2).toBe(did);
  });
});
