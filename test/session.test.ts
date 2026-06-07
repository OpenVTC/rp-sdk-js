import { describe, expect, it } from "vitest";

import { buildSessionCookie, establishSession } from "../src/index.js";
import type { VerifiedIdToken } from "../src/index.js";

// ---------------------------------------------------------------------------
// buildSessionCookie — the cookie flags here are load-bearing security
// defaults (HttpOnly + Secure + SameSite=Strict). Pin them explicitly so a
// regression that loosens any of them fails the build.
// ---------------------------------------------------------------------------

describe("buildSessionCookie", () => {
  it("applies the secure defaults", () => {
    const c = buildSessionCookie({ value: "tok" });
    expect(c.name).toBe("openvtc_rp_session");
    expect(c.value).toBe("tok");
    expect(c.options.httpOnly).toBe(true);
    expect(c.options.secure).toBe(true);
    expect(c.options.sameSite).toBe("strict");
    expect(c.options.path).toBe("/");
    expect(c.options.domain).toBeUndefined();
    expect(c.options.maxAge).toBe(900 * 1000); // 15 min, in ms
  });

  it("converts maxAgeSecs to milliseconds for express", () => {
    const c = buildSessionCookie({ value: "tok", maxAgeSecs: 30 });
    expect(c.options.maxAge).toBe(30_000);
  });

  it("honours explicit overrides", () => {
    const c = buildSessionCookie({
      name: "custom",
      value: "tok",
      domain: ".example.com",
      path: "/app",
      secure: false,
      sameSite: "lax",
    });
    expect(c.name).toBe("custom");
    expect(c.options.domain).toBe(".example.com");
    expect(c.options.path).toBe("/app");
    expect(c.options.secure).toBe(false);
    expect(c.options.sameSite).toBe("lax");
    // HttpOnly is never overridable — it stays true.
    expect(c.options.httpOnly).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// establishSession
// ---------------------------------------------------------------------------

describe("establishSession", () => {
  const verified: VerifiedIdToken = {
    subject: "did:key:z6MkExample",
    audience: "did:web:rp.example",
    nonce: "abc123",
    issuedAt: 0,
    expiresAt: 1,
    extra: {},
  };

  it("returns the subject DID and a cookie carrying the access token", () => {
    const { subject, cookie } = establishSession(verified, "access-token");
    expect(subject).toBe("did:key:z6MkExample");
    expect(cookie.value).toBe("access-token");
    expect(cookie.options.httpOnly).toBe(true);
    expect(cookie.options.secure).toBe(true);
    expect(cookie.options.sameSite).toBe("strict");
  });

  it("forwards cookie option overrides", () => {
    const { cookie } = establishSession(verified, "access-token", {
      name: "rp_sess",
      maxAgeSecs: 60,
    });
    expect(cookie.name).toBe("rp_sess");
    expect(cookie.options.maxAge).toBe(60_000);
  });
});
