import { describe, expect, it } from "vitest";

import {
  buildTriggerLink,
  encodeFromParam,
  isValidHandle,
  TRIGGER_LINK_MAX_BYTES,
  TriggerLinkError,
} from "../../src/index.js";

const FROM =
  "did:webvh:QmPEQVM1JPTyrvEgBcDXwjK4TeyLGSX1PxjgyeAisPviUx:members.example.org";
const ID = "Hk2pQ9xV4mT7rW1sZ8yN3A";
const EXP = 1791460920;

function reason(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    if (e instanceof TriggerLinkError) return e.reason;
    throw e;
  }
  return undefined;
}

describe("buildTriggerLink", () => {
  it("reproduces the spec's sign-in example byte for byte", () => {
    const link = buildTriggerLink({ from: FROM, requestId: ID, exp: EXP });
    expect(link).toBe(
      "https://link.trustoverip.org/t#_from=did:webvh:QmPEQVM1JPTyrvEgBcDXwjK4TeyLGSX1PxjgyeAisPviUx:members.example.org&_id=Hk2pQ9xV4mT7rW1sZ8yN3A&_exp=1791460920&_type=/vti/flow/sign-in/0.1",
    );
    expect(link.length).toBe(184);
  });

  it("uses the absolute flow URI on another link host (VTI-LNK-042)", () => {
    const link = buildTriggerLink({
      from: FROM,
      requestId: ID,
      exp: EXP,
      linkHost: "links.example.net",
    });
    expect(link).toMatch(/^https:\/\/links\.example\.net\/t#/);
    expect(link).toContain(
      "&_type=https://link.trustoverip.org/vti/flow/sign-in/0.1",
    );
  });

  it("percent-encodes & = # % in _from, and nothing else", () => {
    expect(encodeFromParam("did:web:a&b=c#d%e:f/g?h")).toBe(
      "did:web:a%26b%3Dc%23d%25e:f/g?h",
    );
    const link = buildTriggerLink({
      from: "did:web:example.com%3A8443",
      requestId: ID,
      exp: EXP,
    });
    expect(link).toContain("_from=did:web:example.com%253A8443&");
  });

  it("enforces the 251-byte limit", () => {
    const base = buildTriggerLink({
      from: "did:web:x.org",
      requestId: ID,
      exp: EXP,
    }).length;
    const pad = TRIGGER_LINK_MAX_BYTES - base;
    const exact = "did:web:" + "x".repeat(pad) + "x.org";
    expect(
      buildTriggerLink({ from: exact, requestId: ID, exp: EXP }).length,
    ).toBe(TRIGGER_LINK_MAX_BYTES);
    const over = "did:web:" + "x".repeat(pad + 1) + "x.org";
    expect(
      reason(() => buildTriggerLink({ from: over, requestId: ID, exp: EXP })),
    ).toBe("too-long");
  });

  it("refuses non-ASCII", () => {
    expect(
      reason(() =>
        buildTriggerLink({
          from: "did:web:exämple.org",
          requestId: ID,
          exp: EXP,
        }),
      ),
    ).toBe("bad-from");
  });

  it("refuses a link host on the page's own domain (VTI-LNK-084)", () => {
    const p = { from: FROM, requestId: ID, exp: EXP };
    expect(
      reason(() =>
        buildTriggerLink({
          ...p,
          linkHost: "members.example.org",
          pageHost: "members.example.org",
        }),
      ),
    ).toBe("same-domain-host");
    expect(
      reason(() =>
        buildTriggerLink({
          ...p,
          linkHost: "link.example.org",
          pageHost: "example.org",
        }),
      ),
    ).toBe("same-domain-host");
    expect(
      reason(() =>
        buildTriggerLink({
          ...p,
          linkHost: "example.org",
          pageHost: "members.example.org",
        }),
      ),
    ).toBe("same-domain-host");
    expect(
      reason(() =>
        buildTriggerLink({ ...p, pageHost: "LINK.trustoverip.org" }),
      ),
    ).toBe("same-domain-host");
    expect(
      reason(() =>
        buildTriggerLink({
          ...p,
          linkHost: "link.example.org",
          pageHost: "members.example.org",
        }),
      ),
    ).toBe("same-domain-host");
    expect(
      reason(() =>
        buildTriggerLink({
          ...p,
          linkHost: "link.example.co.uk",
          pageHost: "www.example.co.uk",
        }),
      ),
    ).toBe("same-domain-host");
    expect(
      buildTriggerLink({
        ...p,
        linkHost: "link.other.co.uk",
        pageHost: "www.example.co.uk",
      }),
    ).toMatch(/^https:\/\/link\.other/);
    expect(buildTriggerLink({ ...p, pageHost: "members.example.org" })).toMatch(
      /^https:\/\/link\.trustoverip\.org/,
    );
    // A caller with a real public-suffix list can say what a domain is.
    expect(
      buildTriggerLink({
        ...p,
        linkHost: "a.github.io",
        pageHost: "b.github.io",
        registrableDomain: (h) => h,
      }),
    ).toMatch(/^https:\/\/a\.github/);
  });

  it("refuses link hosts that break the host rules (VTI-LNK-060)", () => {
    const p = { from: FROM, requestId: ID, exp: EXP };
    for (const h of [
      "localhost",
      "127.0.0.1",
      "link.example.org:8443",
      "printer.local",
      "x.home.arpa",
      "Link.Example.org",
      "single",
    ]) {
      expect(reason(() => buildTriggerLink({ ...p, linkHost: h }))).toBe(
        "bad-host",
      );
    }
  });

  it("refuses bad contacts", () => {
    const p = { requestId: ID, exp: EXP };
    expect(
      reason(() => buildTriggerLink({ ...p, from: "members.example.org/@" })),
    ).toBe("bad-from");
    expect(
      reason(() =>
        buildTriggerLink({
          ...p,
          from: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        }),
      ),
    ).toBe("bad-from");
    expect(reason(() => buildTriggerLink({ ...p, from: "" }))).toBe("bad-from");
  });

  it("checks _exp", () => {
    const p = { from: FROM, requestId: ID };
    expect(reason(() => buildTriggerLink({ ...p, exp: -1 }))).toBe("bad-exp");
    expect(reason(() => buildTriggerLink({ ...p, exp: 1.5 }))).toBe("bad-exp");
    expect(
      reason(() => buildTriggerLink({ ...p, exp: 1301, nowSecs: 1000 })),
    ).toBe("bad-exp");
    expect(buildTriggerLink({ ...p, exp: 1300, nowSecs: 1000 })).toContain(
      "_exp=1300&",
    );
  });
});

describe("isValidHandle (VTI-LNK-033)", () => {
  it("accepts 22 and 23 characters, refuses 21, 25 and 44", () => {
    expect(isValidHandle(ID)).toBe(true);
    expect(isValidHandle("Hk2pQ9xV4mT7rW1sZ8yN3AA")).toBe(true);
    expect(isValidHandle("Hk2pQ9xV4mT7rW1sZ8yN3")).toBe(false);
    expect(isValidHandle("Hk2pQ9xV4mT7rW1sZ8yN3AAAA")).toBe(false);
    expect(isValidHandle("A".repeat(44))).toBe(false);
  });
  it("refuses non-zero unused bits and other alphabets", () => {
    expect(isValidHandle("Hk2pQ9xV4mT7rW1sZ8yN3B")).toBe(false);
    expect(isValidHandle("Hk2pQ9xV4mT7rW1sZ8yN+A")).toBe(false);
  });
  it("is enforced by buildTriggerLink", () => {
    expect(
      reason(() =>
        buildTriggerLink({ from: FROM, requestId: "short", exp: EXP }),
      ),
    ).toBe("bad-id");
  });
});
