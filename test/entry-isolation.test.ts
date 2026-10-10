import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import * as main from "../src/index.js";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../src");

/** Every module reachable from `entry` through static imports and re-exports. */
function importGraph(entry: string): { local: Set<string>; bare: Set<string> } {
  const local = new Set<string>();
  const bare = new Set<string>();
  const queue = [resolve(SRC, entry)];
  const spec = /(?:import|export)\s[^'"]*?from\s*["']([^"']+)["']/g;
  while (queue.length) {
    const file = queue.pop()!;
    if (local.has(file)) continue;
    local.add(file);
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(spec)) {
      const s = m[1]!;
      if (s.startsWith(".")) {
        queue.push(resolve(dirname(file), s.replace(/\.js$/, ".ts")));
      } else {
        bare.add(s);
      }
    }
  }
  return { local, bare };
}

// DOM-freedom of the main entry is checked by type: `npm run lint` compiles
// src/index.ts with `tsconfig.server-check.json` (lib ES2022, no DOM).

describe("entry point isolation", () => {
  it("the main entry loads no QR library and no browser module", () => {
    const { local, bare } = importGraph("index.ts");
    expect([...bare].filter((s) => s.startsWith("qrcode"))).toEqual([]);
    expect([...local].filter((f) => f.includes("/browser"))).toEqual([]);
  });

  it("the main entry does not export the default QR encoder", () => {
    expect("defaultQrEncoder" in main).toBe(false);
    expect("createTriggerLinkElement" in main).toBe(false);
  });

  it("the browser entry is the one that loads qrcode-generator", () => {
    expect(importGraph("browser.ts").bare.has("qrcode-generator")).toBe(true);
  });

  it("main-entry QR rendering needs an explicit encoder", () => {
    const link = "https://link.trustoverip.org/t#_id=x";
    const encoder = () => ({ size: 1, isDark: () => true });
    expect(() =>
      main.renderQrSvg(link, {} as Parameters<typeof main.renderQrSvg>[1]),
    ).toThrow(/no QR encoder/);
    const svg = main.renderQrSvg(link, { encoder });
    expect(svg).toContain('viewBox="0 0 9 9"');
    expect(main.renderTriggerLinkHtml(link, { encoder })).toContain(
      `<a href="${link}"`,
    );
  });
});
