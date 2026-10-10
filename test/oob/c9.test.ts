// Contract C9 wire details, and schema validation of everything the SDK
// emits against the dtgwg-trust-tasks-tf auth/oob schemas.
import { describe, expect, it } from "vitest";

import { createSignIn, type SignInState } from "../../src/browser.js";
import {
  computeContextDigest,
  OOB_ERRORS as E,
  OOB_TYPES,
  OobError,
  OobVerificationError,
  signInPortalOrigin,
  trustTaskEndpoint,
  verifyDidKeyDocument,
  verifyOobGrant,
  verifyOobIdentify,
  verifyOobClaim,
  type DidDocument,
  type OobDocument,
} from "../../src/index.js";
import { hex } from "@scure/base";
import {
  didKey,
  grantDoc,
  identifyDoc,
  MapResolver,
  makeDid,
  ORIGIN,
  redeemDoc,
  requestDoc,
  SERVICE_DID,
  setup,
  sign,
} from "./helpers.js";
import { validateRequestDocument, validateResponseDocument } from "./schema.js";

const RID = "Hk2pQ9xV4mT7rW1sZ8yN3A";

async function reason(p: Promise<unknown> | (() => unknown)): Promise<string> {
  try {
    await (typeof p === "function" ? p() : p);
  } catch (e) {
    if (e instanceof OobVerificationError) return e.reason;
    if (e instanceof OobError) return e.code;
    throw e;
  }
  return "ok";
}

describe("schema validation of the whole exchange", () => {
  it("every document and response matches its schema", async () => {
    const env = setup({
      redeemExt: async () => ({
        "com.affinidi.did-hosting": { accessToken: "t" },
      }),
    });
    const { svc, alice, store } = env;
    const kb = didKey();
    const ka = didKey();

    const req = await requestDoc(kb);
    expect(validateRequestDocument("request", req)).toEqual([]);
    const opened = await svc.handle(req);
    expect(validateResponseDocument("request", opened.body)).toEqual([]);
    const { requestId, claimDeadline } = opened.body.payload as {
      requestId: string;
      claimDeadline: number;
    };
    expect(Number.isInteger(claimDeadline)).toBe(true);

    const claim = await sign(
      OOB_TYPES.claim,
      ka,
      ka.signer,
      { requestId },
      { parentThreadId: requestId },
    );
    expect(validateRequestDocument("claim", claim)).toEqual([]);
    const step1 = await svc.handle(claim);
    expect(validateResponseDocument("claim", step1.body)).toEqual([]);

    const pending = await svc.handle(await redeemDoc(kb, requestId));
    expect(pending.body.payload).toMatchObject({
      code: E.pending,
      details: { state: "claimed" },
    });
    const matchNumber = (
      pending.body.payload as { details: { matchNumber: string } }
    ).details.matchNumber;
    expect(matchNumber).toMatch(/^[0-9]{2}$/);
    expect(matchNumber).toBe((await store.get(requestId))!.matchNumber);

    const identify = await identifyDoc(alice, requestId, ka.did, matchNumber);
    expect(validateRequestDocument("identify", identify)).toEqual([]);
    const prove = await sign(
      OOB_TYPES.prove,
      ka,
      ka.signer,
      { identify },
      { parentThreadId: requestId },
    );
    expect(validateRequestDocument("prove", prove)).toEqual([]);
    const step2 = await svc.handle(prove, { ip: "203.0.113.9" });
    expect(validateResponseDocument("prove", step2.body)).toEqual([]);
    expect(
      (step2.body.payload as { requester: { sameNetwork: unknown } }).requester
        .sameNetwork,
    ).toBe("unknown");

    const grant = await grantDoc(alice, {
      requestId,
      sessionKey: kb.did,
      approverKey: ka.did,
      step2: step2.body,
    });
    expect(validateRequestDocument("grant", grant)).toEqual([]);
    expect(grant.payload.contextDigest).toMatch(/^zQm/);
    const respond = await sign(
      OOB_TYPES.respond,
      ka,
      ka.signer,
      { grant },
      { parentThreadId: requestId },
    );
    expect(validateRequestDocument("respond", respond)).toEqual([]);
    const responded = await svc.handle(respond);
    expect(responded.body.payload).toEqual({ status: "approved" });
    expect(validateResponseDocument("respond", responded.body)).toEqual([]);

    const redeem = await redeemDoc(kb, requestId);
    expect(validateRequestDocument("redeem", redeem)).toEqual([]);
    const redeemed = await svc.handle(redeem);
    expect(validateResponseDocument("redeem", redeemed.body)).toEqual([]);
    expect(redeemed.body.payload).toMatchObject({
      subject: alice.did,
      displayName: "Alice",
      ext: { "com.affinidi.did-hosting": { accessToken: "t" } },
    });
    expect(
      Number.isInteger(
        (redeemed.body.payload as { notAfter: number }).notAfter,
      ),
    ).toBe(true);
  });

  it("cancel and a declining respond answer with the schema's status values", async () => {
    const env = setup();
    const kb = didKey();
    const { requestId } = await env.svc.request(await requestDoc(kb));
    const cancel = await sign(OOB_TYPES.cancel, kb, kb.signer, { requestId });
    expect(validateRequestDocument("cancel", cancel)).toEqual([]);
    const r = await env.svc.handle(cancel);
    expect(r.body.payload).toEqual({ status: "cancelled" });
    expect(validateResponseDocument("cancel", r.body)).toEqual([]);
    // Cancelling again answers the same way.
    const again = await env.svc.handle(
      await sign(OOB_TYPES.cancel, kb, kb.signer, { requestId }),
    );
    expect(again.body.payload).toEqual({ status: "cancelled" });
  });

  it("displayName falls back to the DID", async () => {
    const env = setup({ displayName: async () => undefined });
    const kb = didKey();
    const ka = didKey();
    const { requestId } = await env.svc.request(await requestDoc(kb));
    await env.svc.claim(
      await sign(
        OOB_TYPES.claim,
        ka,
        ka.signer,
        { requestId },
        { parentThreadId: requestId },
      ),
    );
    const n = (await env.store.get(requestId))!.matchNumber!;
    const step2 = await env.svc.prove(
      await sign(OOB_TYPES.prove, ka, ka.signer, {
        identify: await identifyDoc(env.alice, requestId, ka.did, n),
      }),
    );
    const grant = await grantDoc(env.alice, {
      requestId,
      sessionKey: kb.did,
      approverKey: ka.did,
      step2,
      decision: "decline",
    });
    expect(
      await env.svc.respond(
        await sign(OOB_TYPES.respond, ka, ka.signer, { grant }),
      ),
    ).toEqual({ status: "declined" });
  });

  it("the starter's own documents match their schemas", async () => {
    const env = setup({ redeemHoldMs: 10 });
    const sent: OobDocument<unknown>[] = [];
    const states: SignInState[] = [];
    const signIn = createSignIn({
      endpoint: "https://members.example.org/v1/trust-tasks",
      serviceDid: env.service.did,
      pageHost: "members.example.org",
      onStateChange: (s) => states.push(s),
      fetch: (async (url: string, init: RequestInit) => {
        expect(url).toBe("https://members.example.org/v1/trust-tasks");
        const doc = JSON.parse(init.body as string);
        sent.push(doc);
        const r = await env.svc.handle(doc);
        return new Response(JSON.stringify(r.body), { status: r.status });
      }) as typeof fetch,
    });
    await signIn.start();
    await new Promise((r) => setTimeout(r, 50));
    await signIn.cancel();
    const byType = (t: string) => sent.filter((d) => d.type === t);
    expect(byType(OOB_TYPES.request)).toHaveLength(1);
    expect(byType(OOB_TYPES.redeem).length).toBeGreaterThan(0);
    expect(byType(OOB_TYPES.cancel)).toHaveLength(1);
    for (const d of sent) {
      expect(d.proof?.proofPurpose).toBe("authentication");
      expect(validateRequestDocument(d.type.split("/").at(-2)!, d)).toEqual([]);
    }
    expect(states.map((s) => s.status)).toContain("cancelled");
    signIn.destroy();
  });
});

describe("C9 strictness", () => {
  const common = { serviceDid: SERVICE_DID };

  it("the claim's parentThreadId is required: malformedRequest", async () => {
    const { svc } = setup();
    const kb = didKey();
    const { requestId } = await svc.request(await requestDoc(kb));
    const ka = didKey();
    const none = await sign(OOB_TYPES.claim, ka, ka.signer, { requestId });
    expect(await reason(svc.claim(none))).toBe(E.malformedRequest);
    const other = await sign(
      OOB_TYPES.claim,
      ka,
      ka.signer,
      { requestId },
      { parentThreadId: RID },
    );
    expect(await reason(svc.claim(other))).toBe(E.malformedRequest);
  });

  it("starter and lock documents must be signed for authentication", async () => {
    const kb = didKey();
    const d = await sign(
      OOB_TYPES.redeem,
      kb,
      kb.signer,
      { requestId: RID },
      { proofPurpose: "assertionMethod" },
    );
    expect(
      await reason(() => verifyDidKeyDocument(d, OOB_TYPES.redeem, common)),
    ).toBe("wrong_proof_purpose");
    const ka = didKey();
    const c = await sign(
      OOB_TYPES.claim,
      ka,
      ka.signer,
      { requestId: RID },
      { parentThreadId: RID, proofPurpose: "assertionMethod" },
    );
    expect(await reason(() => verifyOobClaim(c, common))).toBe(
      "wrong_proof_purpose",
    );
  });

  it("enteredNumber must be two digits", async () => {
    const alice = makeDid("did:webvh:QmAlice:alice.example.org");
    const resolver = new MapResolver();
    resolver.docs.set(alice.did, alice.document);
    const ka = didKey();
    for (const n of ["7", "123", "ab"]) {
      const d = await identifyDoc(alice, RID, ka.did, n);
      expect(
        await reason(
          verifyOobIdentify(d, {
            ...common,
            resolver,
            requestId: RID,
            approverKey: ka.did,
          }),
        ),
      ).toBe("malformed");
    }
  });

  it("grant notAfter must be integer seconds; contextDigest must be multibase", async () => {
    const alice = makeDid("did:webvh:QmAlice:alice.example.org");
    const resolver = new MapResolver();
    resolver.docs.set(alice.did, alice.document);
    const ka = didKey();
    const kb = didKey();
    const step2 = { id: "urn:uuid:1", payload: {} };
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
    const g = await grantDoc(alice, {
      requestId: RID,
      sessionKey: kb.did,
      approverKey: ka.did,
      step2,
    });
    const rfc = await sign(OOB_TYPES.grant, alice, alice.assertion, {
      ...g.payload,
      notAfter: "2030-01-01T00:00:00Z",
    });
    expect(await reason(verifyOobGrant(rfc, params))).toBe("malformed");
    const frac = await sign(OOB_TYPES.grant, alice, alice.assertion, {
      ...g.payload,
      notAfter: 1.5,
    });
    expect(await reason(verifyOobGrant(frac, params))).toBe("malformed");
    // The same digest written as hex is refused.
    const z = computeContextDigest(step2);
    const { base58 } = await import("@scure/base");
    const raw = base58.decode(z.slice(1)).slice(2);
    const asHex = await sign(OOB_TYPES.grant, alice, alice.assertion, {
      ...g.payload,
      contextDigest: hex.encode(raw),
    });
    expect(await reason(verifyOobGrant(asHex, params))).toBe(
      "context_mismatch",
    );
    expect(await reason(verifyOobGrant(g, params))).toBe("ok");
  });
});

describe("DID-document service helpers", () => {
  const doc: DidDocument = {
    id: SERVICE_DID,
    service: [
      {
        id: `${SERVICE_DID}#tt`,
        type: "TrustTaskHTTPS",
        serviceEndpoint: "https://members.example.org/v1",
      },
      {
        id: `${SERVICE_DID}#sign-in-portal`,
        type: "SignInPortal",
        serviceEndpoint: "https://members.example.org/members/",
      },
    ],
  };

  it("appends /trust-tasks to the published TrustTaskHTTPS base", () => {
    expect(trustTaskEndpoint(doc)).toBe(
      "https://members.example.org/v1/trust-tasks",
    );
    expect(
      trustTaskEndpoint({
        id: "did:x:y",
        service: [
          {
            id: "#a",
            type: ["TrustTaskHTTPS"],
            serviceEndpoint: "https://h.example/api",
          },
        ],
      }),
    ).toBe("https://h.example/api/trust-tasks");
    // One trailing slash on the base is dropped, not doubled.
    expect(
      trustTaskEndpoint({
        id: "did:x:y",
        service: [
          {
            id: "#a",
            type: "TrustTaskHTTPS",
            serviceEndpoint: "https://h.example/api/",
          },
        ],
      }),
    ).toBe("https://h.example/api/trust-tasks");
  });

  it("matches on type, not id, and refuses non-https", () => {
    expect(
      trustTaskEndpoint({
        id: "d",
        service: [
          {
            id: "#TrustTaskHTTPS",
            type: "Other",
            serviceEndpoint: "https://x.example/",
          },
        ],
      }),
    ).toBeNull();
    expect(
      trustTaskEndpoint({
        id: "d",
        service: [
          {
            id: "#a",
            type: "TrustTaskHTTPS",
            serviceEndpoint: "http://x.example/",
          },
        ],
      }),
    ).toBeNull();
    expect(trustTaskEndpoint({ id: "d" })).toBeNull();
  });

  it("reads the portal origin", () => {
    expect(signInPortalOrigin(doc)).toBe(ORIGIN);
  });
});

describe("the schema check itself", () => {
  it("rejects the shapes C9 forbids", () => {
    const env = { id: "urn:uuid:1", type: OOB_TYPES.request + "#response" };
    expect(
      validateResponseDocument("request", {
        ...env,
        payload: { requestId: RID, claimDeadline: "2030-01-01T00:00:00Z" },
      }),
    ).not.toEqual([]);
    expect(
      validateResponseDocument("request", {
        ...env,
        payload: { requestId: RID, claimDeadline: 1 },
      }),
    ).toEqual([]);
    expect(
      validateResponseDocument("respond", {
        ...env,
        payload: { status: "ok" },
      }),
    ).not.toEqual([]);
    expect(
      validateRequestDocument("identify", {
        ...env,
        payload: {
          requestId: RID,
          approverKey: didKey().did,
          enteredNumber: "7",
        },
      }),
    ).not.toEqual([]);
    const grant = {
      requestId: RID,
      decision: "approve",
      sessionKey: didKey().did,
      approverKey: didKey().did,
      origin: ORIGIN,
      contextDigest: "ab".repeat(32),
      notAfter: 1,
    };
    expect(
      validateRequestDocument("grant", { ...env, payload: grant }),
    ).not.toEqual([]);
    expect(
      validateRequestDocument("grant", {
        ...env,
        payload: { ...grant, contextDigest: computeContextDigest({}) },
      }),
    ).toEqual([]);
    expect(
      validateResponseDocument("prove", {
        ...env,
        payload: { requester: { sameNetwork: "yes" } },
      }).join(),
    ).toMatch(/sameNetwork|missing/);
  });
});
