import { describe, expect, it } from "vitest";

import {
  createSignIn,
  Ed25519UnavailableError,
  generateStarterKey,
  type SignInState,
} from "../../src/browser.js";
import { OOB_TYPES, type Step2Response } from "../../src/index.js";
import {
  claimDoc,
  didKey,
  grantDoc,
  identifyDoc,
  ORIGIN,
  setup,
  sign,
} from "./helpers.js";

/** A fetch that hands the body to the reference service. */
function serviceFetch(
  svc: ReturnType<typeof setup>["svc"],
  seen: unknown[] = [],
): typeof fetch {
  return (async (_url: string, init: RequestInit) => {
    const doc = JSON.parse(init.body as string);
    seen.push(doc);
    const r = await svc.handle(doc, {
      ip: "198.51.100.7",
      signal: init.signal ?? undefined,
    });
    return new Response(JSON.stringify(r.body), {
      status: r.status,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
}

class FakeDocument extends EventTarget {
  visibilityState: "visible" | "hidden" = "visible";
  createElement(tag: string) {
    return fakeEl(tag);
  }
  createElementNS(_ns: string, tag: string) {
    return fakeEl(tag);
  }
  hide() {
    this.visibilityState = "hidden";
    this.dispatchEvent(new Event("visibilitychange"));
  }
}
function fakeEl(tag: string) {
  const el = {
    tag,
    attrs: {} as Record<string, string>,
    children: [] as unknown[],
    setAttribute(k: string, v: string) {
      el.attrs[k] = v;
    },
    appendChild(c: unknown) {
      el.children.push(c);
    },
    replaceChildren(...c: unknown[]) {
      el.children = c;
    },
  };
  return el;
}

function waitFor(
  states: SignInState[],
  status: SignInState["status"],
): Promise<SignInState> {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = () => {
      const s = states.find((x) => x.status === status);
      if (s) return resolve(s);
      if (Date.now() - t0 > 4000)
        return reject(
          new Error(`no ${status}; saw ${states.map((x) => x.status)}`),
        );
      setTimeout(tick, 5);
    };
    tick();
  });
}

function harness(overrides = {}, service: Parameters<typeof setup>[0] = {}) {
  const env = setup({ redeemHoldMs: 30, pollIntervalMs: 5, ...service });
  const states: SignInState[] = [];
  const doc = new FakeDocument();
  const container = fakeEl("div");
  const sent: { type: string }[] = [];
  let signedOut = false;
  const signIn = createSignIn({
    endpoint: "/v1/trust-tasks",
    serviceDid: env.service.did,
    container: container as unknown as Element,
    document: doc as unknown as Document,
    pageHost: "members.example.org",
    fetch: serviceFetch(env.svc, sent),
    onStateChange: (s) => states.push(s),
    onSignOut: () => void (signedOut = true),
    ...overrides,
  });
  return {
    env,
    states,
    doc,
    container,
    signIn,
    sent,
    signedOut: () => signedOut,
  };
}

/** The wallet side, driven from the link. */
async function wallet(
  env: ReturnType<typeof setup>,
  link: string,
  number: (n: string) => string = (n) => n,
) {
  const id = new URL(link).hash.match(/_id=([^&]+)/)![1];
  const ka = didKey();
  await env.svc.claim(await claimDoc(ka, id));
  const rec = await env.store.get(id);
  return {
    id,
    ka,
    matchNumber: rec!.matchNumber!,
    enter: number(rec!.matchNumber!),
  };
}

describe("browser starter", () => {
  it("signs in end to end and deletes K_b on sign-out", async () => {
    const h = harness(
      {},
      {
        redeemExt: async () => ({
          "com.affinidi.did-hosting": { token: "bearer" },
        }),
      },
    );
    await h.signIn.start();
    const waiting = (await waitFor(h.states, "waiting")) as Extract<
      SignInState,
      { status: "waiting" }
    >;
    expect(waiting.link).toMatch(
      /^https:\/\/link\.trustoverip\.org\/t#_from=did:webvh:/,
    );
    expect(waiting.codeVisible).toBe(true);
    expect(
      (h.container.children[0] as { tag: string; attrs: { href: string } })
        .attrs.href,
    ).toBe(waiting.link);
    expect(h.sent[0].type).toBe(OOB_TYPES.request);

    const w = await wallet(h.env, waiting.link);
    const claimed = (await waitFor(h.states, "claimed")) as Extract<
      SignInState,
      { status: "claimed" }
    >;
    expect(claimed.matchNumber).toBe(w.matchNumber);
    expect(h.container.children).toHaveLength(0);

    const step2 = await h.env.svc.prove(
      await sign(OOB_TYPES.prove, w.ka, w.ka.signer, {
        identify: await identifyDoc(h.env.alice, w.id, w.ka.did, w.enter),
      }),
    );
    const s2 = step2.payload as Step2Response;
    expect(s2.sessionKey).toMatch(/^did:key:z6Mk/);
    expect(s2.origin).toBe(ORIGIN);
    const grant = await grantDoc(h.env.alice, {
      requestId: w.id,
      sessionKey: s2.sessionKey,
      approverKey: w.ka.did,
      step2,
    });
    await h.env.svc.respond(
      await sign(OOB_TYPES.respond, w.ka, w.ka.signer, { grant }),
    );

    const confirm = (await waitFor(h.states, "confirm")) as Extract<
      SignInState,
      { status: "confirm" }
    >;
    expect(confirm.subject).toBe(h.env.alice.did);
    expect(confirm.displayName).toBe("Alice");
    expect(confirm.notAfter.getTime() % 1000).toBe(0);
    expect(confirm.ext).toEqual({
      "com.affinidi.did-hosting": { token: "bearer" },
    });
    h.signIn.confirm();
    expect(h.signIn.state.status).toBe("signedIn");

    // Every redeem was a fresh document.
    const redeems = (h.sent as { type: string; id: string }[]).filter(
      (d) => d.type === OOB_TYPES.redeem,
    );
    expect(redeems.length).toBeGreaterThan(1);
    expect(new Set(redeems.map((d) => d.id)).size).toBe(redeems.length);

    // K_b signs session documents, then is gone after sign-out.
    const doc = await h.signIn.signDocument("https://example.org/task/0.1", {
      x: 1,
    });
    expect(doc.issuer).toBe(s2.sessionKey);
    expect(h.signIn.sessionKey?.custody).toBe("webcrypto");
    await h.signIn.signOut();
    expect(h.signedOut()).toBe(true);
    expect(h.signIn.state.status).toBe("idle");
    expect(await h.signIn.restoreSessionKey()).toBeNull();
    h.signIn.destroy();
  });

  it("generates a non-extractable K_b", async () => {
    const k = await generateStarterKey();
    expect(k.keyPair!.privateKey.extractable).toBe(false);
    await expect(
      crypto.subtle.exportKey("pkcs8", k.keyPair!.privateKey),
    ).rejects.toThrow();
  });

  it("reports declined on a wrong number", async () => {
    const h = harness();
    await h.signIn.start();
    const waiting = (await waitFor(h.states, "waiting")) as Extract<
      SignInState,
      { status: "waiting" }
    >;
    const w = await wallet(h.env, waiting.link, (n) =>
      n === "00" ? "01" : "00",
    );
    await h.env.svc
      .prove(
        await sign(OOB_TYPES.prove, w.ka, w.ka.signer, {
          identify: await identifyDoc(h.env.alice, w.id, w.ka.did, w.enter),
        }),
      )
      .catch(() => undefined);
    await waitFor(h.states, "declined");
    h.signIn.destroy();
  });

  it("cancel sends auth/oob/cancel and reports cancelled", async () => {
    const h = harness();
    await h.signIn.start();
    await waitFor(h.states, "waiting");
    await h.signIn.cancel();
    expect(h.signIn.state.status).toBe("cancelled");
    expect(h.sent.some((d) => d.type === OOB_TYPES.cancel)).toBe(true);
    expect(h.container.children).toHaveLength(0);
    h.signIn.destroy();
  });

  it("hides the code when the tab is hidden but keeps polling", async () => {
    const h = harness();
    await h.signIn.start();
    const waiting = (await waitFor(h.states, "waiting")) as Extract<
      SignInState,
      { status: "waiting" }
    >;
    h.doc.hide();
    expect(h.container.children).toHaveLength(0);
    expect(h.signIn.state).toMatchObject({
      status: "waiting",
      codeVisible: false,
    });
    await wallet(h.env, waiting.link);
    await waitFor(h.states, "claimed");
    h.signIn.destroy();
  });

  it("reports expired when the service says so", async () => {
    let now = Date.now();
    const h = harness();
    (h.env.svc as unknown as { o: { now: () => Date } }).o.now = () =>
      new Date(now);
    await h.signIn.start();
    await waitFor(h.states, "waiting");
    now += 200_000;
    await waitFor(h.states, "expired");
    h.signIn.destroy();
  });

  it("refuses a link host on the page's own domain", async () => {
    const h = harness({
      linkHost: "link.example.org",
      pageHost: "members.example.org",
    });
    await h.signIn.start();
    expect(h.signIn.state).toMatchObject({
      status: "error",
      code: "TriggerLinkError",
    });
    h.signIn.destroy();
  });

  it("fails clearly without WebCrypto Ed25519 unless the fallback is allowed", async () => {
    const original = crypto.subtle.generateKey.bind(crypto.subtle);
    const mod = await import("../../src/browser/key.js?nocache=" + Date.now());
    (crypto.subtle as { generateKey: unknown }).generateKey = async () => {
      throw new DOMException("no", "NotSupportedError");
    };
    try {
      await expect(mod.generateStarterKey()).rejects.toBeInstanceOf(
        mod.Ed25519UnavailableError,
      );
      const k = await mod.generateStarterKey({ allowInMemoryFallback: true });
      expect(k.custody).toBe("memory");
      expect(k.did).toMatch(/^did:key:z6Mk/);
    } finally {
      (crypto.subtle as { generateKey: unknown }).generateKey = original;
    }
    expect(Ed25519UnavailableError).toBeDefined();
  });
});
