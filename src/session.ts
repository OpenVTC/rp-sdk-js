/**
 * Helpers for translating a verified SIOPv2 `id_token` into a
 * server-side session cookie.
 *
 * The SDK doesn't take an opinion on which session-store the RP
 * uses (express-session, iron-session, Redis-backed, signed JWT
 * cookies, etc.) — instead it exposes [`buildSessionCookie`]
 * which produces the standard fields any cookie-session strategy
 * needs.
 *
 * Recommended pairing: pass the returned descriptor to
 * `res.cookie(name, value, opts)` (Express) or to the `Set-Cookie`
 * builder for whatever HTTP framework you use.
 */

import type { VerifiedIdToken } from "./verify-id-token.js";

export interface SessionCookieOptions {
  /**
   * Name of the cookie. Default `"openvtc_rp_session"`.
   * Pick something distinct per-RP so cross-origin cookie
   * collisions don't confuse clients.
   */
  name?: string;
  /**
   * Cookie value. The SDK does NOT mint a signed token here —
   * pass the access-token your session-store produces. The SDK
   * is opinionated about cookie *flags* (Secure, HttpOnly,
   * SameSite=Strict) but not about token format.
   */
  value: string;
  /**
   * Cookie max-age in seconds. Default matches a typical
   * access-token TTL (15 min).
   */
  maxAgeSecs?: number;
  /**
   * Cookie domain. Leave undefined to scope to the issuing
   * host. Setting `.example.com` shares the cookie across
   * subdomains — only do this if you understand the
   * security implications.
   */
  domain?: string;
  /**
   * Cookie path. Defaults to `/`.
   */
  path?: string;
  /**
   * Override `Secure`. Default `true` — production should
   * never serve session cookies over HTTP. Set `false` only
   * in local dev (`NODE_ENV !== "production"` is the
   * conventional gate).
   */
  secure?: boolean;
  /**
   * Override `SameSite`. Default `"strict"`. SIOPv2 logins
   * are first-party — there's no legitimate cross-site flow
   * that needs `none`.
   */
  sameSite?: "strict" | "lax" | "none";
}

export interface SessionCookieDescriptor {
  name: string;
  value: string;
  options: {
    maxAge: number;
    domain?: string;
    path: string;
    httpOnly: true;
    secure: boolean;
    sameSite: "strict" | "lax" | "none";
  };
}

/**
 * Construct a session-cookie descriptor with the SDK's
 * load-bearing flags applied: `HttpOnly`, `Secure`,
 * `SameSite=Strict`.
 *
 * `HttpOnly` is non-negotiable — it's the wall between an XSS
 * compromise and a session-hijack escalation.
 *
 * `Secure` is true by default. Override to `false` only for
 * local dev over plain HTTP.
 *
 * `SameSite=Strict` is the default. Lax / None are
 * available but each weakens CSRF protection — make sure
 * you understand the tradeoff before using them.
 */
export function buildSessionCookie(
  opts: SessionCookieOptions,
): SessionCookieDescriptor {
  return {
    name: opts.name ?? "openvtc_rp_session",
    value: opts.value,
    options: {
      maxAge: (opts.maxAgeSecs ?? 900) * 1000, // ms for express
      domain: opts.domain,
      path: opts.path ?? "/",
      httpOnly: true,
      secure: opts.secure ?? true,
      sameSite: opts.sameSite ?? "strict",
    },
  };
}

/**
 * Establish a session from a verified id_token. Returns the
 * canonical subject DID + a cookie descriptor; the RP wires the
 * cookie into its response and persists `verified.subject` as
 * the session's user identifier.
 *
 * Currently a thin wrapper around [`buildSessionCookie`]; future
 * versions may take on more (CSRF token issuance, audit-log
 * emission, etc.) so RPs should call this rather than reaching
 * for `buildSessionCookie` directly.
 */
export function establishSession(
  verified: VerifiedIdToken,
  accessToken: string,
  options?: Omit<SessionCookieOptions, "value">,
): { subject: string; cookie: SessionCookieDescriptor } {
  return {
    subject: verified.subject,
    cookie: buildSessionCookie({ ...options, value: accessToken }),
  };
}
