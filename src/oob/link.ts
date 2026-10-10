/**
 * Trigger links (VTI spec chapter 07a, contract C1): the producer side.
 *
 * ```
 * https://link.trustoverip.org/t#_from=<VTC DID>&_id=<requestId>&_exp=<epoch s>&_type=/vti/flow/sign-in/0.1
 * ```
 *
 * Platform-neutral; used by the browser starter and available to a server
 * that renders the link itself.
 */

/** The shared link host (contract C1). */
export const DEFAULT_LINK_HOST = "link.trustoverip.org";
/** The trigger path on the link host. */
export const DEFAULT_LINK_PATH = "/t";
/** The `sign-in` flow identifier (VTI-LNK-100 to 105). */
export const SIGN_IN_FLOW = "https://link.trustoverip.org/vti/flow/sign-in/0.1";
/** VTI-LNK-081: the longest link a QR code at level M may carry. */
export const TRIGGER_LINK_MAX_BYTES = 251;
/** VTI-LNK-100: a sign-in `_exp` is at most this far after the code is made. */
export const SIGN_IN_MAX_LIFETIME_SECS = 300;

export type TriggerLinkErrorReason =
  | "bad-from"
  | "bad-id"
  | "bad-exp"
  | "bad-host"
  | "bad-path"
  | "same-domain-host"
  | "non-ascii"
  | "too-long";

/** Thrown when a trigger link may not be produced. Inspect `.reason`. */
export class TriggerLinkError extends Error {
  constructor(
    readonly reason: TriggerLinkErrorReason,
    message: string,
  ) {
    super(`trigger link refused (${reason}): ${message}`);
    this.name = "TriggerLinkError";
  }
}

export interface BuildTriggerLinkParams {
  /** The service (VTC) DID: `_from`. */
  from: string;
  /** The `requestId`: `_id`. Unpadded base64url, 16 to 32 bytes. */
  requestId: string;
  /** The claim deadline, epoch seconds: `_exp`. */
  exp: number;
  /** Link host. Defaults to {@link DEFAULT_LINK_HOST}. */
  linkHost?: string;
  /** Trigger path on the link host. Defaults to {@link DEFAULT_LINK_PATH}. */
  linkPath?: string;
  /**
   * Host name of the page that will show the link. When given, a link host on
   * the same domain is refused (VTI-LNK-084). The browser starter always
   * passes `location.hostname`.
   */
  pageHost?: string;
  /**
   * The current time, epoch seconds. When given, `_exp` must be no later than
   * 300 s after it (VTI-LNK-100).
   */
  nowSecs?: number;
  /**
   * Maps a host to its registrable domain for the VTI-LNK-084 check.
   * Defaults to {@link approximateRegistrableDomain}.
   */
  registrableDomain?: (host: string) => string;
  /** The flow URI. Defaults to {@link SIGN_IN_FLOW}. */
  flow?: string;
}

/**
 * Percent-encode a `_from` value: `&`, `=`, `#` and `%`, and nothing else
 * (contract C1).
 */
export function encodeFromParam(from: string): string {
  return from.replace(
    /[&=#%]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"),
  );
}

/**
 * Build a sign-in trigger link, enforcing the producer rules: ASCII only
 * (VTI-LNK-080), at most 251 bytes (VTI-LNK-081), no link host on the page's
 * domain (VTI-LNK-084), and the field grammars of VTI-LNK-030 to 040.
 *
 * @throws {TriggerLinkError}
 */
export function buildTriggerLink(params: BuildTriggerLinkParams): string {
  const linkHost = params.linkHost ?? DEFAULT_LINK_HOST;
  const linkPath = params.linkPath ?? DEFAULT_LINK_PATH;
  const flow = params.flow ?? SIGN_IN_FLOW;

  assertValidHost(linkHost, "link host");
  if (!/^\/[A-Za-z0-9\-._~/]*$/.test(linkPath)) {
    throw new TriggerLinkError("bad-path", `invalid link path ${linkPath}`);
  }
  if (
    params.pageHost !== undefined &&
    sameDomain(
      linkHost,
      params.pageHost,
      params.registrableDomain ?? approximateRegistrableDomain,
    )
  ) {
    throw new TriggerLinkError(
      "same-domain-host",
      `link host ${linkHost} is on the page's own domain ${params.pageHost}`,
    );
  }

  assertValidFrom(params.from);
  assertValidHandle(params.requestId);
  assertValidExp(params.exp, params.nowSecs);

  const flowUrl = new URL(flow);
  // VTI-LNK-042: path form when the flow is on the link's own host.
  const type =
    flowUrl.host === linkHost.toLowerCase() ? flowUrl.pathname : flow;

  const link =
    `https://${linkHost}${linkPath}#_from=${encodeFromParam(params.from)}` +
    `&_id=${params.requestId}&_exp=${params.exp}&_type=${type}`;

  if (!isAscii(link)) {
    throw new TriggerLinkError("non-ascii", "a trigger link must be ASCII");
  }
  if (link.length > TRIGGER_LINK_MAX_BYTES) {
    throw new TriggerLinkError(
      "too-long",
      `link is ${link.length} bytes, the limit at level M is ${TRIGGER_LINK_MAX_BYTES}`,
    );
  }
  return link;
}

function isAscii(s: string): boolean {
  // Printable ASCII only: control characters are no more welcome than
  // non-ASCII in a QR byte-mode payload.
  return /^[\x21-\x7e]*$/.test(s);
}

function assertValidFrom(from: string): void {
  if (typeof from !== "string" || from.length === 0 || !isAscii(from)) {
    throw new TriggerLinkError("bad-from", "_from must be non-empty ASCII");
  }
  if (from.includes("/@")) {
    // VTI-LNK-032: reserved for agent names.
    throw new TriggerLinkError("bad-from", "agent names are not yet allowed");
  }
  if (!/^did:[a-z0-9]+:\S+$/.test(from)) {
    throw new TriggerLinkError("bad-from", "_from must be a DID");
  }
  if (from.startsWith("did:key:")) {
    // VTI-LNK-102: a did:key cannot list the portal service.
    throw new TriggerLinkError(
      "bad-from",
      "a sign-in contact cannot be a did:key",
    );
  }
}

const B64URL =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** VTI-LNK-033: 16 to 32 bytes of unpadded base64url, one spelling only. */
export function isValidHandle(id: string): boolean {
  if (typeof id !== "string" || id.length < 22 || id.length > 43) return false;
  if (id.length % 4 === 1) return false; // 25, 29, 33, 37, 41
  if (!/^[A-Za-z0-9\-_]+$/.test(id)) return false;
  const unusedBits = { 2: 4, 3: 2 }[id.length % 4] ?? 0;
  if (unusedBits > 0) {
    const last = B64URL.indexOf(id[id.length - 1]);
    if ((last & ((1 << unusedBits) - 1)) !== 0) return false;
  }
  return true;
}

function assertValidHandle(id: string): void {
  if (!isValidHandle(id)) {
    throw new TriggerLinkError(
      "bad-id",
      "_id must be 16 to 32 bytes of canonical unpadded base64url",
    );
  }
}

function assertValidExp(exp: number, nowSecs?: number): void {
  if (!Number.isSafeInteger(exp) || exp < 0) {
    throw new TriggerLinkError(
      "bad-exp",
      "_exp must be a non-negative integer",
    );
  }
  if (nowSecs !== undefined && exp > nowSecs + SIGN_IN_MAX_LIFETIME_SECS) {
    throw new TriggerLinkError(
      "bad-exp",
      `_exp is more than ${SIGN_IN_MAX_LIFETIME_SECS} s away`,
    );
  }
}

/** VTI-LNK-060 host rules. */
function assertValidHost(host: string, what: string): void {
  const labels = host.split(".");
  const ok =
    host.length <= 253 &&
    labels.length >= 2 &&
    labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) &&
    !/^[0-9]+$/.test(labels[labels.length - 1]) &&
    !["localhost", "local"].includes(labels[labels.length - 1]) &&
    !host.endsWith(".home.arpa");
  if (!ok) {
    throw new TriggerLinkError("bad-host", `invalid ${what} ${host}`);
  }
}

/**
 * An approximation of the registrable domain ("eTLD+1") without a
 * public-suffix list: the last two labels, or the last three where the
 * top-level label is a two-letter country code and the label before it is
 * three letters or fewer (`example.co.uk`, `example.com.au`). Pass
 * `registrableDomain` to {@link buildTriggerLink} to use a real list.
 */
export function approximateRegistrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  const n =
    labels.length >= 3 &&
    labels[labels.length - 1].length === 2 &&
    labels[labels.length - 2].length <= 3
      ? 3
      : 2;
  return labels.slice(-n).join(".");
}

/** VTI-LNK-084: are the link host and the page host on the same domain? */
function sameDomain(
  linkHost: string,
  pageHost: string,
  registrable: (host: string) => string,
): boolean {
  return registrable(linkHost) === registrable(pageHost);
}
