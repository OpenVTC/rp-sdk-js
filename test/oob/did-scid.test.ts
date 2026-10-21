import { describe, expect, it } from "vitest";

import { sameReference, stripScidSrc } from "../../src/oob/did-scid.js";

describe("did:scid src locator", () => {
  it("strips only a did:scid src", () => {
    expect(stripScidSrc("did:scid:vh:1:Qm?src=example.com/alice")).toBe(
      "did:scid:vh:1:Qm",
    );
    expect(stripScidSrc("did:scid:vh:1:Qm?src=example.com#key-1")).toBe(
      "did:scid:vh:1:Qm#key-1",
    );
    for (const unchanged of [
      "did:scid:vh:1:Qm",
      "did:scid:vh:1:Qm?src=",
      "did:scid:vh:1:Qm?src=a.example&versionId=2",
      "did:scid:vh:1:Qm?versionId=2#key-1",
      "did:webvh:Qm:example.com?versionId=1",
      "did:example:123?src=example.com",
    ]) {
      expect(stripScidSrc(unchanged)).toBe(unchanged);
    }
  });

  it("compares references by DID and fragment", () => {
    expect(
      sameReference("did:scid:vh:1:Qm?src=a.example", "did:scid:vh:1:Qm"),
    ).toBe(true);
    expect(
      sameReference(
        "did:scid:vh:1:Qm?src=a.example#k",
        "did:scid:vh:1:Qm?src=b.example#k",
      ),
    ).toBe(true);
    expect(sameReference("did:scid:vh:1:Qm#k", "did:scid:vh:1:Qm#j")).toBe(
      false,
    );
    expect(sameReference("did:scid:vh:1:Qm", "did:webvh:Qm:a.example")).toBe(
      false,
    );
  });
});
