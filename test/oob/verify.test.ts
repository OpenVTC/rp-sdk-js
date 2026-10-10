import { describe, expect, it } from "vitest";

import {
  computeContextDigest,
  contextDigestsEqual,
  DidKeyDocumentResolver,
  OOB_TYPES,
  OobVerificationError,
  verifyDidKeyDocument,
  verifyOobClaim,
  verifyOobGrant,
  verifyOobIdentify,
  type OobDocument,
} from "../../src/index.js";
import {
  claimDoc,
  didKey,
  grantDoc,
  identifyDoc,
  makeDid,
  MapResolver,
  ORIGIN,
  SERVICE_DID,
  sign,
} from "./helpers.js";

const RID = "Hk2pQ9xV4mT7rW1sZ8yN3A";
const common = { serviceDid: SERVICE_DID };

async function reasonOf(
  p: Promise<unknown> | (() => unknown),
): Promise<string | undefined> {
  try {
    await (typeof p === "function" ? p() : p);
  } catch (e) {
    if (e instanceof OobVerificationError) return e.reason;
    throw e;
  }
  return undefined;
}

const clone = <T>(x: T): T => structuredClone(x);

describe("verifyOobClaim", () => {
  it("accepts a well-formed claim", async () => {
    const ka = didKey();
    const v = verifyOobClaim(await claimDoc(ka, RID), common);
    expect(v.approverKey).toBe(ka.did);
    expect(v.requestId).toBe(RID);
  });

  it("requires parentThreadId == payload.requestId", async () => {
    const ka = didKey();
    const doc = await sign(
      OOB_TYPES.claim,
      ka,
      ka.signer,
      { requestId: RID },
      { parentThreadId: "other" },
    );
    expect(await reasonOf(() => verifyOobClaim(doc, common))).toBe(
      "parent_thread_mismatch",
    );
    const none = await sign(OOB_TYPES.claim, ka, ka.signer, { requestId: RID });
    expect(await reasonOf(() => verifyOobClaim(none, common))).toBe(
      "parent_thread_mismatch",
    );
  });

  it("covers every envelope and proof failure", async () => {
    const ka = didKey();
    const good = await claimDoc(ka, RID);
    const cases: [string, (d: OobDocument<any>) => unknown][] = [
      ["malformed", () => null],
      ["wrong_type", (d) => ({ ...d, type: OOB_TYPES.prove })],
      ["malformed", (d) => ({ ...d, id: "" })],
      ["malformed", (d) => ({ ...d, payload: undefined })],
      ["audience_mismatch", (d) => ({ ...d, recipient: "did:web:other.org" })],
      ["malformed", (d) => ({ ...d, issuedAt: "yesterday" })],
      ["no_proof", (d) => ({ ...d, proof: undefined })],
      [
        "unsupported_suite",
        (d) => ({
          ...d,
          proof: { ...d.proof, cryptosuite: "ecdsa-rdfc-2019" },
        }),
      ],
      [
        "wrong_proof_purpose",
        (d) => ({
          ...d,
          proof: { ...d.proof, proofPurpose: "capabilityInvocation" },
        }),
      ],
      [
        "proof_invalid",
        (d) => ({ ...d, proof: { ...d.proof, proofValue: "abc" } }),
      ],
      [
        "proof_invalid",
        (d) => ({
          ...d,
          proof: { ...d.proof, proofValue: "z" + "1".repeat(10) },
        }),
      ],
      [
        "proof_invalid",
        (d) => ({ ...d, payload: { requestId: RID.replace("H", "J") } }),
      ],
      [
        "issuer_mismatch",
        (d) => ({
          ...d,
          proof: {
            ...d.proof,
            verificationMethod: didKey().signer.verificationMethod,
          },
        }),
      ],
      ["key_unsupported", (d) => ({ ...d, issuer: "did:web:example.org" })],
    ];
    for (const [want, mutate] of cases) {
      expect(
        await reasonOf(() => verifyOobClaim(mutate(clone(good)), common)),
        want,
      ).toBe(want);
    }
  });

  it("checks freshness", async () => {
    const ka = didKey();
    const old = await sign(
      OOB_TYPES.claim,
      ka,
      ka.signer,
      { requestId: RID },
      { parentThreadId: RID, now: new Date(Date.now() - 400_000) },
    );
    expect(await reasonOf(() => verifyOobClaim(old, common))).toBe("expired");
    const future = await sign(
      OOB_TYPES.claim,
      ka,
      ka.signer,
      { requestId: RID },
      { parentThreadId: RID, now: new Date(Date.now() + 120_000) },
    );
    expect(await reasonOf(() => verifyOobClaim(future, common))).toBe(
      "not_yet_valid",
    );
    const d = await claimDoc(ka, RID);
    expect(
      await reasonOf(() =>
        verifyOobClaim({ ...d, expiresAt: "2000-01-01T00:00:00Z" }, common),
      ),
    ).toBe("expired");
    const empty = await sign(
      OOB_TYPES.claim,
      ka,
      ka.signer,
      {},
      { parentThreadId: RID },
    );
    expect(await reasonOf(() => verifyOobClaim(empty, common))).toBe(
      "malformed",
    );
  });

  it("rejects a document nested past the JCS bound", async () => {
    const ka = didKey();
    const d: any = await claimDoc(ka, RID);
    let deep: any = {};
    const root = deep;
    for (let i = 0; i < 200; i++) deep = deep.x = {};
    d.payload.extra = root;
    expect(await reasonOf(() => verifyOobClaim(d, common))).toBe(
      "document_too_complex",
    );
  });
});

describe("verifyDidKeyDocument", () => {
  it("refuses a proof by another key of the right DID shape", async () => {
    const kb = didKey();
    const d = await sign(OOB_TYPES.redeem, kb, kb.signer, { requestId: RID });
    const other = didKey();
    const forged = await sign(
      OOB_TYPES.redeem,
      { did: kb.did },
      { ...other.signer, verificationMethod: kb.signer.verificationMethod },
      { requestId: RID },
    );
    expect(verifyDidKeyDocument(d, OOB_TYPES.redeem, common).issuer).toBe(
      kb.did,
    );
    expect(
      await reasonOf(() =>
        verifyDidKeyDocument(forged, OOB_TYPES.redeem, common),
      ),
    ).toBe("proof_invalid");
  });
  it("refuses a did:key verificationMethod fragment that is not the key", async () => {
    const kb = didKey();
    const d = await sign(
      OOB_TYPES.redeem,
      kb,
      { ...kb.signer, verificationMethod: `${kb.did}#key-1` },
      { requestId: RID },
    );
    expect(
      await reasonOf(() => verifyDidKeyDocument(d, OOB_TYPES.redeem, common)),
    ).toBe("proof_invalid");
  });
});

describe("verifyOobIdentify", () => {
  const alice = makeDid("did:webvh:QmAlice:alice.example.org");
  const resolver = new MapResolver();
  resolver.docs.set(alice.did, alice.document);
  const ka = didKey();
  const params = { ...common, resolver, requestId: RID, approverKey: ka.did };

  it("accepts identify signed for authentication", async () => {
    const v = await verifyOobIdentify(
      await identifyDoc(alice, RID, ka.did, "47"),
      params,
    );
    expect(v.did).toBe(alice.did);
    expect(v.payload.enteredNumber).toBe("47");
  });

  it("refuses identify signed by the assertionMethod key (contract C5)", async () => {
    const asAssertion = await sign(
      OOB_TYPES.identify,
      alice,
      alice.assertion,
      { requestId: RID, approverKey: ka.did, enteredNumber: "47" },
      { proofPurpose: "assertionMethod" },
    );
    expect(await reasonOf(verifyOobIdentify(asAssertion, params))).toBe(
      "wrong_proof_purpose",
    );
    const purposeLie = await sign(
      OOB_TYPES.identify,
      alice,
      alice.assertion,
      { requestId: RID, approverKey: ka.did, enteredNumber: "47" },
      { proofPurpose: "authentication" },
    );
    expect(await reasonOf(verifyOobIdentify(purposeLie, params))).toBe(
      "resolver_failed",
    );
  });

  it("covers binding and shape failures", async () => {
    expect(
      await reasonOf(
        verifyOobIdentify(
          await identifyDoc(alice, "x".repeat(22), ka.did, "47"),
          params,
        ),
      ),
    ).toBe("request_mismatch");
    expect(
      await reasonOf(
        verifyOobIdentify(
          await identifyDoc(alice, RID, didKey().did, "47"),
          params,
        ),
      ),
    ).toBe("approver_mismatch");
    const extra = await sign(
      OOB_TYPES.identify,
      alice,
      alice.auth,
      { requestId: RID, approverKey: ka.did, enteredNumber: "47", ext: {} },
      { proofPurpose: "authentication" },
    );
    expect(await reasonOf(verifyOobIdentify(extra, params))).toBe("malformed");
    const unknown = makeDid("did:webvh:QmBob:bob.example.org");
    expect(
      await reasonOf(
        verifyOobIdentify(
          await identifyDoc(unknown, RID, ka.did, "47"),
          params,
        ),
      ),
    ).toBe("resolver_failed");
  });
});

describe("verifyOobGrant", () => {
  const alice = makeDid("did:webvh:QmAlice:alice.example.org");
  const mallory = makeDid("did:webvh:QmMallory:mallory.example.org");
  const resolver = new DidKeyDocumentResolver(new MapResolver());
  (resolver as any).fallback.docs.set(alice.did, alice.document);
  (resolver as any).fallback.docs.set(mallory.did, mallory.document);
  const ka = didKey();
  const kb = didKey();
  const step2 = {
    id: "urn:uuid:1",
    type: OOB_TYPES.prove + "#response",
    payload: { a: 1 },
    proof: { proofValue: "z1" },
  };
  const params = {
    ...common,
    resolver,
    requestId: RID,
    identifiedDid: alice.did,
    approverKey: ka.did,
    sessionKey: kb.did,
    origin: ORIGIN,
    step2Response: step2,
  };
  const base = {
    requestId: RID,
    sessionKey: kb.did,
    approverKey: ka.did,
    step2,
  };

  it("accepts a grant signed for assertionMethod", async () => {
    const v = await verifyOobGrant(await grantDoc(alice, base), params);
    expect(v.decision).toBe("approve");
    expect(v.notAfter.getTime()).toBeGreaterThan(Date.now());
    const d = await verifyOobGrant(
      await grantDoc(alice, { ...base, decision: "decline" }),
      {
        ...params,
        step2Response: undefined,
        contextDigest: computeContextDigest(step2),
      },
    );
    expect(d.decision).toBe("decline");
  });

  it("covers every binding failure", async () => {
    expect(
      await reasonOf(verifyOobGrant(await grantDoc(mallory, base), params)),
    ).toBe("issuer_mismatch");
    expect(
      await reasonOf(
        verifyOobGrant(
          await grantDoc(alice, { ...base, requestId: "x".repeat(22) }),
          params,
        ),
      ),
    ).toBe("request_mismatch");
    expect(
      await reasonOf(
        verifyOobGrant(
          await grantDoc(alice, { ...base, approverKey: didKey().did }),
          params,
        ),
      ),
    ).toBe("approver_mismatch");
    expect(
      await reasonOf(
        verifyOobGrant(
          await grantDoc(alice, { ...base, sessionKey: didKey().did }),
          params,
        ),
      ),
    ).toBe("session_key_mismatch");
    expect(
      await reasonOf(
        verifyOobGrant(
          await grantDoc(alice, { ...base, origin: "https://evil.example" }),
          params,
        ),
      ),
    ).toBe("origin_mismatch");
    expect(
      await reasonOf(
        verifyOobGrant(
          await grantDoc(alice, {
            ...base,
            step2: { ...step2, payload: { a: 2 } },
          }),
          params,
        ),
      ),
    ).toBe("context_mismatch");
  });

  it("refuses a grant signed for authentication or with a bad decision", async () => {
    const g = await grantDoc(alice, base);
    const asAuth = await sign(OOB_TYPES.grant, alice, alice.auth, g.payload, {
      proofPurpose: "authentication",
    });
    expect(await reasonOf(verifyOobGrant(asAuth, params))).toBe(
      "wrong_proof_purpose",
    );
    const lie = await sign(OOB_TYPES.grant, alice, alice.auth, g.payload, {
      proofPurpose: "assertionMethod",
    });
    expect(await reasonOf(verifyOobGrant(lie, params))).toBe("resolver_failed");
    const bad = await sign(OOB_TYPES.grant, alice, alice.assertion, {
      ...g.payload,
      decision: "maybe",
    });
    expect(await reasonOf(verifyOobGrant(bad, params))).toBe("malformed");
    const noAfter = await sign(OOB_TYPES.grant, alice, alice.assertion, {
      ...g.payload,
      notAfter: "soon",
    });
    expect(await reasonOf(verifyOobGrant(noAfter, params))).toBe("malformed");
  });
});

describe("context digest", () => {
  it("is the SHA-256 of the JCS form, proof included, as a multihash", () => {
    const a = computeContextDigest({ b: 1, a: 2, proof: { proofValue: "z1" } });
    expect(a.startsWith("zQm")).toBe(true);
    expect(
      computeContextDigest({ a: 2, b: 1, proof: { proofValue: "z1" } }),
    ).toBe(a);
    expect(
      computeContextDigest({ a: 2, b: 1, proof: { proofValue: "z2" } }),
    ).not.toBe(a);
  });
  it("compares across encodings and refuses garbage", () => {
    const z = computeContextDigest({ x: 1 });
    expect(contextDigestsEqual(z, z)).toBe(true);
    expect(contextDigestsEqual(z, "nonsense")).toBe(false);
    expect(contextDigestsEqual(z, computeContextDigest({ x: 2 }))).toBe(false);
  });
});
