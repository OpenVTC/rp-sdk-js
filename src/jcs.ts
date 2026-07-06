/**
 * JSON Canonicalization Scheme (RFC 8785) — the canonical byte form the
 * `eddsa-jcs-2022` Data Integrity suite hashes.
 *
 * Minified JSON, object keys sorted lexicographically by UTF-16 code unit,
 * strict JSON-only string escaping per ECMA-404. This MUST produce byte-identical
 * output to the wallet's signer (`@openvtc/pnm-core` `trust-tasks/canonical.ts`)
 * and the VTA's Rust `eddsa-jcs-2022` implementation, or proofs won't verify.
 */
export function jcsCanonicalize(value: unknown): string {
  const seen = new WeakSet<object>();
  return enc(value);

  function enc(v: unknown): string {
    if (v === null) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (typeof v === "number") {
      if (!Number.isFinite(v)) throw new Error("JCS rejects non-finite numbers");
      if (Object.is(v, -0)) return "0";
      return String(v);
    }
    if (typeof v === "string") return encString(v);
    if (Array.isArray(v)) {
      if (seen.has(v)) throw new Error("circular reference in JCS input");
      seen.add(v);
      const out = "[" + v.map(enc).join(",") + "]";
      seen.delete(v);
      return out;
    }
    if (typeof v === "object" && v !== null) {
      if (seen.has(v as object)) throw new Error("circular reference in JCS input");
      seen.add(v as object);
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const parts = keys.map((k) => encString(k) + ":" + enc(obj[k]));
      seen.delete(v as object);
      return "{" + parts.join(",") + "}";
    }
    throw new Error(`JCS cannot encode value of type ${typeof v}`);
  }

  function encString(s: string): string {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
      const ch = s.charCodeAt(i);
      if (ch === 0x22) out += '\\"';
      else if (ch === 0x5c) out += "\\\\";
      else if (ch === 0x08) out += "\\b";
      else if (ch === 0x0c) out += "\\f";
      else if (ch === 0x0a) out += "\\n";
      else if (ch === 0x0d) out += "\\r";
      else if (ch === 0x09) out += "\\t";
      else if (ch < 0x20) out += "\\u" + ch.toString(16).padStart(4, "0");
      else out += s[i];
    }
    return out + '"';
  }
}
