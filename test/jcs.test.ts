import { describe, expect, it } from "vitest";

import {
  jcsCanonicalize,
  JcsLimitExceededError,
  JCS_MAX_DEPTH,
} from "../src/index.js";

/** `depth` nested arrays wrapping a scalar — 2 bytes of JSON per level. */
function nestArrays(depth: number): unknown {
  let v: unknown = 0;
  for (let i = 0; i < depth; i++) v = [v];
  return v;
}

/** `depth` nested single-member objects — 6 bytes of JSON per level. */
function nestObjects(depth: number): unknown {
  let v: unknown = 0;
  for (let i = 0; i < depth; i++) v = { a: v };
  return v;
}

describe("jcsCanonicalize (RFC 8785 output is byte-stable)", () => {
  it("sorts keys, minifies, and escapes per ECMA-404", () => {
    expect(
      jcsCanonicalize({ b: 1, a: "é\n\t\\", c: [true, false, null, -0] }),
    ).toBe('{"a":"é\\n\\t\\\\","b":1,"c":[true,false,null,0]}');
  });

  it("still rejects the values JSON cannot represent", () => {
    expect(() => jcsCanonicalize({ n: Number.NaN })).toThrow(/non-finite/);
    expect(() => jcsCanonicalize({ u: undefined })).toThrow(/cannot encode/);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => jcsCanonicalize(cyclic)).toThrow(/circular/);
  });
});

describe("jcsCanonicalize input bounds", () => {
  it("rejects a ~10 KB deeply nested input with a typed error, not a RangeError", () => {
    // 5000 levels is ~10 KB of JSON. Before the depth bound this threw
    // `RangeError: Maximum call stack size exceeded` from inside the recursive
    // encoder — an untyped crash of the RP's verify call.
    const deep = nestArrays(5000);
    expect(JSON.stringify(deep).length).toBeGreaterThan(10_000);

    let thrown: unknown;
    try {
      jcsCanonicalize(deep);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(JcsLimitExceededError);
    expect(thrown).not.toBeInstanceOf(RangeError);
    expect((thrown as JcsLimitExceededError).limit).toBe("depth");
  });

  it("rejects deeply nested objects the same way", () => {
    let thrown: unknown;
    try {
      jcsCanonicalize(nestObjects(5000));
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(JcsLimitExceededError);
    expect((thrown as JcsLimitExceededError).limit).toBe("depth");
  });

  it("accepts nesting up to the depth bound and rejects one level past it", () => {
    expect(() => jcsCanonicalize(nestArrays(JCS_MAX_DEPTH))).not.toThrow();
    expect(() => jcsCanonicalize(nestArrays(JCS_MAX_DEPTH + 1))).toThrow(
      JcsLimitExceededError,
    );
  });

  it("honours a caller-supplied maxDepth", () => {
    expect(() => jcsCanonicalize(nestArrays(4), { maxDepth: 4 })).not.toThrow();
    expect(() => jcsCanonicalize(nestArrays(5), { maxDepth: 4 })).toThrow(
      /nests deeper than 4/,
    );
  });

  it("rejects an input whose canonical form exceeds the byte bound", () => {
    const wide = { blob: "a".repeat(4096) };
    expect(() => jcsCanonicalize(wide)).not.toThrow();
    let thrown: unknown;
    try {
      jcsCanonicalize(wide, { maxBytes: 1024 });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(JcsLimitExceededError);
    expect((thrown as JcsLimitExceededError).limit).toBe("size");
  });

  it("counts multi-byte characters as UTF-8 bytes, not code units", () => {
    // "€" is 1 UTF-16 code unit but 3 UTF-8 bytes; 4 of them plus the two
    // quotes is 14 bytes, so a 13-byte budget must reject it.
    expect(() => jcsCanonicalize("€€€€", { maxBytes: 14 })).not.toThrow();
    expect(() => jcsCanonicalize("€€€€", { maxBytes: 13 })).toThrow(
      JcsLimitExceededError,
    );
  });
});
