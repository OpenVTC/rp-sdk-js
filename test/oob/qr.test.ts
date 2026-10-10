import { describe, expect, it } from "vitest";

import {
  createTriggerLinkElement,
  defaultQrEncoder,
  renderQrSvg,
  renderTriggerLinkHtml,
} from "../../src/browser.js";

const LINK =
  "https://link.trustoverip.org/t#_from=did:webvh:QmPEQVM1JPTyrvEgBcDXwjK4TeyLGSX1PxjgyeAisPviUx:members.example.org&_id=Hk2pQ9xV4mT7rW1sZ8yN3A&_exp=1791460920&_type=/vti/flow/sign-in/0.1";

describe("QR rendering", () => {
  it("encodes at level M with a sensible version", () => {
    const m = defaultQrEncoder(LINK);
    // 184 bytes at level M needs version 9 or 10: 53 or 57 modules.
    expect([53, 57]).toContain(m.size);
    // Finder pattern corners are dark.
    expect(
      m.isDark(0, 0) && m.isDark(0, m.size - 1) && m.isDark(m.size - 1, 0),
    ).toBe(true);
  });

  it("draws a 4-module quiet zone and 4 px per module by default, dark on light", () => {
    const size = defaultQrEncoder(LINK).size;
    const svg = renderQrSvg(LINK);
    const units = size + 8;
    expect(svg).toContain(`viewBox="0 0 ${units} ${units}"`);
    expect(svg).toContain(`width="${units * 4}"`);
    expect(svg).toContain('shape-rendering="crispEdges"');
    expect(svg).toContain(
      '<rect width="' + units + '" height="' + units + '" fill="#ffffff"/>',
    );
    expect(svg).toContain('fill="#000000"');
    // The first dark module (finder pattern) sits just inside the quiet zone.
    expect(svg).toContain('d="M4 4h1v1h-1z');
  });

  it("never goes below the minimums", () => {
    const size = defaultQrEncoder(LINK).size;
    const svg = renderQrSvg(LINK, { moduleSize: 1, quietZone: 0 });
    expect(svg).toContain(`width="${(size + 8) * 4}"`);
    const big = renderQrSvg(LINK, { moduleSize: 6, quietZone: 6 });
    expect(big).toContain(`width="${(size + 12) * 6}"`);
  });

  it("refuses non-ASCII, oversize payloads and odd colours", () => {
    expect(() => renderQrSvg("https://x.org/t#_from=é")).toThrow(/ASCII/);
    expect(() => renderQrSvg("https://x.org/" + "a".repeat(260))).toThrow(
      /251/,
    );
    expect(() => renderQrSvg(LINK, { dark: '"/><script>' })).toThrow(/colours/);
  });

  it("wraps the code in a link to the same text (VTI-LNK-086)", () => {
    const html = renderTriggerLinkHtml(LINK);
    expect(
      html.startsWith(
        `<a href="${LINK.replace(/&/g, "&amp;")}" rel="noreferrer"`,
      ),
    ).toBe(true);
    expect(html.endsWith("</svg></a>")).toBe(true);
  });

  it("builds DOM nodes without innerHTML", () => {
    type Node = {
      tag: string;
      ns?: string;
      attrs: Record<string, string>;
      children: Node[];
    };
    const mk = (
      tag: string,
      ns?: string,
    ): Node & {
      setAttribute(k: string, v: string): void;
      appendChild(c: Node): void;
    } => {
      const n: Node = { tag, ns, attrs: {}, children: [] };
      return Object.assign(n, {
        setAttribute: (k: string, v: string) => void (n.attrs[k] = v),
        appendChild: (c: Node) => void n.children.push(c),
      });
    };
    const doc = {
      createElement: (t: string) => mk(t),
      createElementNS: (ns: string, t: string) => mk(t, ns),
    };
    const a = createTriggerLinkElement(
      doc as unknown as Document,
      LINK,
    ) as unknown as Node;
    expect(a.tag).toBe("a");
    expect(a.attrs.href).toBe(LINK);
    expect(a.children[0].tag).toBe("svg");
    expect(a.children[0].ns).toBe("http://www.w3.org/2000/svg");
    expect(a.children[0].children.map((c) => c.tag)).toEqual(["rect", "path"]);
  });
});
