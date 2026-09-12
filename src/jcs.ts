/**
 * JSON Canonicalization Scheme (RFC 8785) — the canonical byte form the
 * `eddsa-jcs-2022` Data Integrity suite hashes.
 *
 * Minified JSON, object keys sorted lexicographically by UTF-16 code unit,
 * strict JSON-only string escaping per ECMA-404. This MUST produce byte-identical
 * output to the wallet's signer (`@openvtc/pnm-core` `trust-tasks/canonical.ts`)
 * and the VTA's Rust `eddsa-jcs-2022` implementation, or proofs won't verify.
 *
 * Canonicalization descends one JS stack frame per nesting level, and on the
 * verify path the input is an attacker-influenced document. Structural bounds
 * are therefore enforced while encoding: nesting deeper than `maxDepth`, or a
 * canonical form larger than `maxBytes`, is rejected with a typed
 * {@link JcsLimitExceededError}. Without them a ~6 KB JSON body nested a few
 * thousand levels deep raises `RangeError: Maximum call stack size exceeded`
 * from inside verification — an untyped crash of the RP's request handler.
 */

/**
 * Default nesting-depth bound. A real Trust-Task document nests ~4 levels
 * (document → payload → actionDetails → value), so 100 is far above anything
 * the framework produces and far below the engine's stack limit.
 */
export const JCS_MAX_DEPTH = 100;

/**
 * Default size bound for the canonical form, in UTF-8 bytes (1 MiB). Trust-Task
 * documents are a few hundred bytes; this only stops pathological inputs.
 */
export const JCS_MAX_BYTES = 1024 * 1024;

/** Which structural bound a rejected input tripped. */
export type JcsLimit = "depth" | "size";

/**
 * Thrown when JCS input exceeds a structural bound. Distinct from the plain
 * `Error`s thrown for un-encodable values, so a caller can tell "this document
 * is too deep/large to canonicalize" from "this value is not JSON".
 */
export class JcsLimitExceededError extends Error {
  constructor(
    readonly limit: JcsLimit,
    message: string,
  ) {
    super(`JCS input rejected (${limit}): ${message}`);
    this.name = "JcsLimitExceededError";
  }
}

export interface JcsCanonicalizeOptions {
  /** Maximum nesting depth. Default {@link JCS_MAX_DEPTH}. */
  maxDepth?: number;
  /** Maximum canonical size in UTF-8 bytes. Default {@link JCS_MAX_BYTES}. */
  maxBytes?: number;
}

export function jcsCanonicalize(
  value: unknown,
  options: JcsCanonicalizeOptions = {},
): string {
  const maxDepth = options.maxDepth ?? JCS_MAX_DEPTH;
  const maxBytes = options.maxBytes ?? JCS_MAX_BYTES;
  const seen = new WeakSet<object>();
  let bytes = 0;
  return enc(value, 0);

  // Charges the canonical bytes emitted so far against the budget, so an
  // oversized input fails part-way through instead of being fully built.
  function account(n: number): void {
    bytes += n;
    if (bytes > maxBytes) {
      throw new JcsLimitExceededError(
        "size",
        `canonical form exceeds ${maxBytes} bytes`,
      );
    }
  }

  function enc(v: unknown, depth: number): string {
    if (depth > maxDepth) {
      throw new JcsLimitExceededError(
        "depth",
        `input nests deeper than ${maxDepth} levels`,
      );
    }
    if (v === null) {
      account(4);
      return "null";
    }
    if (v === true) {
      account(4);
      return "true";
    }
    if (v === false) {
      account(5);
      return "false";
    }
    if (typeof v === "number") {
      if (!Number.isFinite(v))
        throw new Error("JCS rejects non-finite numbers");
      if (Object.is(v, -0)) {
        account(1);
        return "0";
      }
      const num = String(v);
      account(num.length);
      return num;
    }
    if (typeof v === "string") return encString(v);
    if (Array.isArray(v)) {
      if (seen.has(v)) throw new Error("circular reference in JCS input");
      seen.add(v);
      // brackets + element separators
      account(2 + (v.length > 0 ? v.length - 1 : 0));
      const out = "[" + v.map((el) => enc(el, depth + 1)).join(",") + "]";
      seen.delete(v);
      return out;
    }
    if (typeof v === "object" && v !== null) {
      if (seen.has(v as object))
        throw new Error("circular reference in JCS input");
      seen.add(v as object);
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      // braces + one colon per member + member separators
      account(2 + keys.length + (keys.length > 0 ? keys.length - 1 : 0));
      const parts = keys.map(
        (k) => encString(k) + ":" + enc(obj[k], depth + 1),
      );
      seen.delete(v as object);
      return "{" + parts.join(",") + "}";
    }
    throw new Error(`JCS cannot encode value of type ${typeof v}`);
  }

  function encString(s: string): string {
    let out = '"';
    let size = 2; // the quotes
    for (let i = 0; i < s.length; i++) {
      const ch = s.charCodeAt(i);
      if (ch === 0x22) {
        out += '\\"';
        size += 2;
      } else if (ch === 0x5c) {
        out += "\\\\";
        size += 2;
      } else if (ch === 0x08) {
        out += "\\b";
        size += 2;
      } else if (ch === 0x0c) {
        out += "\\f";
        size += 2;
      } else if (ch === 0x0a) {
        out += "\\n";
        size += 2;
      } else if (ch === 0x0d) {
        out += "\\r";
        size += 2;
      } else if (ch === 0x09) {
        out += "\\t";
        size += 2;
      } else if (ch < 0x20) {
        out += "\\u" + ch.toString(16).padStart(4, "0");
        size += 6;
      } else {
        out += s[i];
        size += utf8Size(ch);
      }
    }
    account(size);
    return out + '"';
  }
}

/**
 * UTF-8 byte size of one UTF-16 code unit. A high surrogate is charged the full
 * 4 bytes of the pair and its trailing low surrogate nothing, so a surrogate
 * pair is counted exactly once.
 */
function utf8Size(codeUnit: number): number {
  if (codeUnit < 0x80) return 1;
  if (codeUnit < 0x800) return 2;
  if (codeUnit >= 0xd800 && codeUnit < 0xdc00) return 4;
  if (codeUnit >= 0xdc00 && codeUnit < 0xe000) return 0;
  return 3;
}
