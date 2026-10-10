import { describe, expect, it } from "vitest";

import {
  OOB_ERRORS as E,
  OOB_TYPES,
  OobError,
  type OobDocument,
  type Step2Response,
} from "../../src/index.js";
import {
  claimDoc,
  didKey,
  grantDoc,
  identifyDoc,
  redeemDoc,
  requestDoc,
  setup,
  sign,
  type TestDid,
  type TestKey,
} from "./helpers.js";

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (e instanceof OobError) return e.code;
    throw e;
  }
  return "ok";
}

async function opened(env = setup()) {
  const kb = didKey();
  const { requestId, claimDeadline } = await env.svc.request(
    await requestDoc(kb),
    { ip: "203.0.113.5", location: "Singapore, SG" },
  );
  return { ...env, kb, requestId, claimDeadline };
}

async function claimed(env = setup()) {
  const o = await opened(env);
  const ka = didKey();
  const step1 = await o.svc.claim(await claimDoc(ka, o.requestId));
  const matchNumber = (await o.store.get(o.requestId))!.matchNumber!;
  return { ...o, ka, step1, matchNumber };
}

async function proved(
  env = setup(),
  who?: (e: ReturnType<typeof setup>) => TestDid,
) {
  const c = await claimed(env);
  const member = who ? who(env) : env.alice;
  const step2 = await c.svc.prove(
    await sign(OOB_TYPES.prove, c.ka, c.ka.signer, {
      identify: await identifyDoc(member, c.requestId, c.ka.did, c.matchNumber),
    }),
    { ip: "203.0.113.5" },
  );
  return { ...c, step2 };
}

const respond = (ka: TestKey, grant: OobDocument<unknown>) =>
  sign(OOB_TYPES.respond, ka, ka.signer, { grant });

describe("OobSignInService", () => {
  it("runs the whole flow: request, claim, prove, respond, redeem", async () => {
    const p = await proved();
    expect(Number.isInteger(p.claimDeadline)).toBe(true);
    expect(p.step1.payload.service).toEqual({
      did: p.service.did,
      name: "Example Community",
    });
    expect(JSON.stringify(p.step1.payload)).not.toContain("Singapore");
    expect(p.step1.proof?.proofPurpose).toBe("assertionMethod");
    const s2 = p.step2.payload as Step2Response;
    expect(s2.sessionKey).toBe(p.kb.did);
    expect(s2.requester.sameNetwork).toBe(true);
    expect(s2.requester.location).toBe("Singapore, SG");
    expect(s2.identifiedAs).toBe(p.alice.did);
    expect(JSON.stringify(s2)).not.toContain("203.0.113.5");

    // Before approval, redeem says pending and gives the number to K_b only.
    const pending = await p.svc.handle(await redeemDoc(p.kb, p.requestId));
    expect(pending.body.payload).toMatchObject({
      code: E.pending,
      details: { state: "identified", matchNumber: p.matchNumber },
    });

    const grant = await grantDoc(p.alice, {
      requestId: p.requestId,
      sessionKey: p.kb.did,
      approverKey: p.ka.did,
      step2: p.step2,
    });
    expect(await p.svc.respond(await respond(p.ka, grant))).toEqual({
      status: "approved",
    });

    const res = await p.svc.handle(await redeemDoc(p.kb, p.requestId));
    expect(res.status).toBe(200);
    expect(res.body.type).toBe(OOB_TYPES.redeem + "#response");
    expect(res.body.payload).toMatchObject({
      subject: p.alice.did,
      displayName: "Alice",
      amr: ["did", "oob", "uv"],
    });
    expect(res.session?.sessionKey).toBe(p.kb.did);
    expect((await p.store.get(p.requestId))!.state).toBe("consumed");

    // Single use.
    expect(await code(p.svc.redeem(await redeemDoc(p.kb, p.requestId)))).toBe(
      E.requestExpired,
    );
  });

  it("refuses unsupported purpose, mode and key", async () => {
    const { svc } = setup();
    const kb = didKey();
    expect(
      await code(
        svc.request(
          await sign(OOB_TYPES.request, kb, kb.signer, {
            purpose: "step-up",
            mode: "scan",
          }),
        ),
      ),
    ).toBe(E.purposeUnsupported);
    expect(
      await code(
        svc.request(
          await sign(OOB_TYPES.request, kb, kb.signer, {
            purpose: "login",
            mode: "push",
          }),
        ),
      ),
    ).toBe(E.modeUnsupported);
    const d = await requestDoc(kb);
    expect(
      await code(svc.request({ ...d, issuer: "did:web:example.org" })),
    ).toBe(E.keyUnsupported);
  });

  it("refuses a replayed document id", async () => {
    const { svc } = setup();
    const d = await requestDoc(didKey());
    await svc.request(d);
    expect(await code(svc.request(d))).toBe(E.notAuthorized);
  });

  it("locks to the first claimant", async () => {
    const c = await claimed();
    expect(await code(c.svc.claim(await claimDoc(didKey(), c.requestId)))).toBe(
      E.alreadyClaimed,
    );
    expect(
      await code(c.svc.claim(await claimDoc(didKey(), "A".repeat(22)))),
    ).toBe(E.requestNotFound);
  });

  it("expires an unclaimed request after the claim window", async () => {
    let now = Date.now();
    const env = setup({ now: () => new Date(now) });
    const o = await opened(env);
    now += 121_000;
    expect(await code(o.svc.claim(await claimDoc(didKey(), o.requestId)))).toBe(
      E.requestExpired,
    );
    expect((await o.store.get(o.requestId))!.state).toBe("expired");
  });

  it("expires after the decision window", async () => {
    let now = Date.now();
    const env = setup({ now: () => new Date(now) });
    const c = await claimed(env);
    now += 121_000;
    expect(await code(c.svc.redeem(await redeemDoc(c.kb, c.requestId)))).toBe(
      E.requestExpired,
    );
  });

  it("prove: a stranger's key is notClaimant and changes nothing", async () => {
    const c = await claimed();
    const other = didKey();
    const doc = await sign(OOB_TYPES.prove, other, other.signer, {
      identify: await identifyDoc(
        c.alice,
        c.requestId,
        other.did,
        c.matchNumber,
      ),
    });
    expect(await code(c.svc.prove(doc))).toBe(E.notClaimant);
    expect((await c.store.get(c.requestId))!.state).toBe("claimed");
  });

  it("prove: a non-member is refused before any resolution, and declines", async () => {
    const c = await claimed();
    c.resolver.calls = [];
    const doc = await sign(OOB_TYPES.prove, c.ka, c.ka.signer, {
      identify: await identifyDoc(
        c.mallory,
        c.requestId,
        c.ka.did,
        c.matchNumber,
      ),
    });
    expect(await code(c.svc.prove(doc))).toBe(E.notAuthorized);
    expect(c.resolver.calls).not.toContain(c.mallory.did);
    expect((await c.store.get(c.requestId))!.state).toBe("declined");
  });

  it("prove: a wrong number declines with numberMismatch", async () => {
    const c = await claimed();
    const wrong = c.matchNumber === "00" ? "01" : "00";
    const doc = await sign(OOB_TYPES.prove, c.ka, c.ka.signer, {
      identify: await identifyDoc(c.alice, c.requestId, c.ka.did, wrong),
    });
    expect(await code(c.svc.prove(doc))).toBe(E.numberMismatch);
    expect(await code(c.svc.redeem(await redeemDoc(c.kb, c.requestId)))).toBe(
      E.declined,
    );
  });

  it("prove: a bad identify signature declines with notAuthorized", async () => {
    const c = await claimed();
    const identify = await identifyDoc(
      c.alice,
      c.requestId,
      c.ka.did,
      c.matchNumber,
    );
    identify.proof!.proofValue = "z" + "2".repeat(87);
    const doc = await sign(OOB_TYPES.prove, c.ka, c.ka.signer, { identify });
    expect(await code(c.svc.prove(doc))).toBe(E.notAuthorized);
    expect((await c.store.get(c.requestId))!.state).toBe("declined");
  });

  it("respond: a context mismatch declines", async () => {
    const p = await proved();
    const grant = await grantDoc(p.alice, {
      requestId: p.requestId,
      sessionKey: didKey().did,
      approverKey: p.ka.did,
      step2: p.step2,
    });
    expect(await code(p.svc.respond(await respond(p.ka, grant)))).toBe(
      E.contextMismatch,
    );
    expect((await p.store.get(p.requestId))!.state).toBe("declined");
  });

  it("respond: a grant over a different step 2 declines", async () => {
    const p = await proved();
    const grant = await grantDoc(p.alice, {
      requestId: p.requestId,
      sessionKey: p.kb.did,
      approverKey: p.ka.did,
      step2: { ...p.step2, id: "x" },
    });
    expect(await code(p.svc.respond(await respond(p.ka, grant)))).toBe(
      E.contextMismatch,
    );
  });

  it("respond: a decline grant ends as declined", async () => {
    const p = await proved();
    const grant = await grantDoc(p.alice, {
      requestId: p.requestId,
      sessionKey: p.kb.did,
      approverKey: p.ka.did,
      step2: p.step2,
      decision: "decline",
    });
    await p.svc.respond(await respond(p.ka, grant));
    const r = await p.svc.handle(await redeemDoc(p.kb, p.requestId));
    expect(r.body.payload).toMatchObject({
      code: E.declined,
      details: { state: "declined" },
    });
  });

  it("respond: a member removed mid-flow is refused", async () => {
    const p = await proved();
    p.members.delete(p.alice.did);
    const grant = await grantDoc(p.alice, {
      requestId: p.requestId,
      sessionKey: p.kb.did,
      approverKey: p.ka.did,
      step2: p.step2,
    });
    expect(await code(p.svc.respond(await respond(p.ka, grant)))).toBe(
      E.notAuthorized,
    );
  });

  it("respond: a second decision is alreadyDecided", async () => {
    const p = await proved();
    const grant = await grantDoc(p.alice, {
      requestId: p.requestId,
      sessionKey: p.kb.did,
      approverKey: p.ka.did,
      step2: p.step2,
    });
    await p.svc.respond(await respond(p.ka, grant));
    const again = await grantDoc(p.alice, {
      requestId: p.requestId,
      sessionKey: p.kb.did,
      approverKey: p.ka.did,
      step2: p.step2,
    });
    expect(await code(p.svc.respond(await respond(p.ka, again)))).toBe(
      E.alreadyDecided,
    );
  });

  it("redeem: only the starter key may redeem", async () => {
    const o = await opened();
    expect(
      await code(o.svc.redeem(await redeemDoc(didKey(), o.requestId))),
    ).toBe(E.notStarter);
  });

  it("redeem: pending before claim carries no number; one poll at a time", async () => {
    const env = setup({ redeemHoldMs: 200, pollIntervalMs: 10 });
    const o = await opened(env);
    const first = o.svc.handle(await redeemDoc(o.kb, o.requestId));
    expect(await code(o.svc.redeem(await redeemDoc(o.kb, o.requestId)))).toBe(
      E.rateLimited,
    );
    const r = await first;
    expect(r.body.payload).toEqual({
      code: E.pending,
      message: "not decided yet",
      details: { state: "pending" },
    });
  });

  it("redeem: a held poll wakes as soon as the request is approved", async () => {
    const env = setup({ redeemHoldMs: 5000, pollIntervalMs: 1000 });
    const p = await proved(env);
    const poll = p.svc.redeem(await redeemDoc(p.kb, p.requestId));
    const grant = await grantDoc(p.alice, {
      requestId: p.requestId,
      sessionKey: p.kb.did,
      approverKey: p.ka.did,
      step2: p.step2,
    });
    const t = Date.now();
    await p.svc.respond(await respond(p.ka, grant));
    expect((await poll).subject).toBe(p.alice.did);
    expect(Date.now() - t).toBeLessThan(500);
  });

  it("cancel: by the starter, then redeem reports cancelled", async () => {
    const c = await claimed();
    await c.svc.cancel(
      await sign(OOB_TYPES.cancel, c.kb, c.kb.signer, {
        requestId: c.requestId,
      }),
    );
    const r = await c.svc.handle(await redeemDoc(c.kb, c.requestId));
    expect(r.body.payload).toMatchObject({
      code: E.declined,
      details: { state: "cancelled" },
    });
    const stranger = didKey();
    expect(
      await code(
        c.svc.cancel(
          await sign(OOB_TYPES.cancel, stranger, stranger.signer, {
            requestId: c.requestId,
          }),
        ),
      ),
    ).toBe(E.notAuthorized);
  });

  it("handle: answers unknown types with a trust-task-error", async () => {
    const { svc } = setup();
    const r = await svc.handle({
      type: "https://example.org/nope",
      id: "urn:uuid:1",
    });
    expect(r.status).toBe(400);
    expect(r.body.type).toBe(
      "https://trusttasks.org/spec/trust-task-error/0.5",
    );
    expect(r.body.threadId).toBe("urn:uuid:1");
  });

  it("refuses windows over 180 s", () => {
    expect(() => setup({ claimWindowSecs: 181 })).toThrow(/180/);
  });
});
