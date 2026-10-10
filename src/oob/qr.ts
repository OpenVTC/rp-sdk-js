/**
 * Render a trigger link as a clickable SVG QR code (VTI-LNK-086 and the
 * chapter 07a rendering guidance): byte mode, level M, no logo, a quiet zone
 * of at least 4 modules, at least 4 CSS px per module, dark on light.
 *
 * The encoder sits behind {@link QrEncoder} so it can be swapped. The default
 * uses `qrcode-generator` (MIT, zero dependencies).
 */

import qrcode from "qrcode-generator";

import { TRIGGER_LINK_MAX_BYTES, TriggerLinkError } from "./link.js";

/** A QR symbol: a square of modules, `true` for dark. */
export interface QrMatrix {
  size: number;
  isDark(row: number, col: number): boolean;
}

/** Encodes ASCII text in byte mode at error-correction level M. */
export type QrEncoder = (text: string) => QrMatrix;

/** The default encoder: `qrcode-generator`, automatic version, level M. */
export const defaultQrEncoder: QrEncoder = (text) => {
  const qr = qrcode(0, "M");
  qr.addData(text, "Byte");
  qr.make();
  const size = qr.getModuleCount();
  return { size, isDark: (r, c) => qr.isDark(r, c) };
};

export interface QrRenderOptions {
  /** CSS px per module. Minimum and default 4. */
  moduleSize?: number;
  /** Quiet zone in modules. Minimum and default 4. */
  quietZone?: number;
  /** Dark module colour. Default `#000000`. */
  dark?: string;
  /** Background colour. Default `#ffffff`. */
  light?: string;
  /** Accessible label. Default "Sign-in code". */
  label?: string;
  /** Replace the encoder (tests, or a different library). */
  encoder?: QrEncoder;
}

interface ResolvedQr {
  matrix: QrMatrix;
  moduleSize: number;
  quietZone: number;
  dark: string;
  light: string;
  label: string;
  pixels: number;
  path: string;
}

const COLOUR = /^(#[0-9a-fA-F]{3,8}|[a-zA-Z]+)$/;

function resolve(text: string, opts: QrRenderOptions): ResolvedQr {
  if (!/^[\x21-\x7e]*$/.test(text)) {
    throw new TriggerLinkError("non-ascii", "a QR payload must be ASCII");
  }
  if (text.length > TRIGGER_LINK_MAX_BYTES) {
    throw new TriggerLinkError(
      "too-long",
      `QR payload over ${TRIGGER_LINK_MAX_BYTES} bytes`,
    );
  }
  const moduleSize = Math.max(4, Math.floor(opts.moduleSize ?? 4));
  const quietZone = Math.max(4, Math.floor(opts.quietZone ?? 4));
  const dark = opts.dark ?? "#000000";
  const light = opts.light ?? "#ffffff";
  if (!COLOUR.test(dark) || !COLOUR.test(light)) {
    throw new Error("QR colours must be hex or named colours");
  }
  const matrix = (opts.encoder ?? defaultQrEncoder)(text);
  // One path of 1x1 squares in module units; the viewBox scales it.
  let path = "";
  for (let r = 0; r < matrix.size; r++) {
    for (let c = 0; c < matrix.size; c++) {
      if (matrix.isDark(r, c))
        path += `M${c + quietZone} ${r + quietZone}h1v1h-1z`;
    }
  }
  return {
    matrix,
    moduleSize,
    quietZone,
    dark,
    light,
    label: opts.label ?? "Sign-in code",
    pixels: (matrix.size + 2 * quietZone) * moduleSize,
    path,
  };
}

function escapeAttr(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/** The QR code as an SVG string, not wrapped in a link. */
export function renderQrSvg(text: string, opts: QrRenderOptions = {}): string {
  const q = resolve(text, opts);
  const units = q.matrix.size + 2 * q.quietZone;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${escapeAttr(q.label)}"` +
    ` width="${q.pixels}" height="${q.pixels}" viewBox="0 0 ${units} ${units}"` +
    ` shape-rendering="crispEdges">` +
    `<rect width="${units}" height="${units}" fill="${q.light}"/>` +
    `<path d="${q.path}" fill="${q.dark}"/></svg>`
  );
}

/**
 * The QR code wrapped in `<a href="link">` (VTI-LNK-086), as an HTML string,
 * for server-side rendering.
 */
export function renderTriggerLinkHtml(
  link: string,
  opts: QrRenderOptions = {},
): string {
  return (
    `<a href="${escapeAttr(link)}" rel="noreferrer" referrerpolicy="no-referrer">` +
    `${renderQrSvg(link, opts)}</a>`
  );
}

const SVG_NS = "http://www.w3.org/2000/svg";

/**
 * The QR code wrapped in `<a href="link">`, as DOM nodes built with
 * `createElementNS` (no `innerHTML`, so it works under Trusted Types).
 */
export function createTriggerLinkElement(
  doc: Document,
  link: string,
  opts: QrRenderOptions = {},
): HTMLAnchorElement {
  const q = resolve(link, opts);
  const units = String(q.matrix.size + 2 * q.quietZone);
  const a = doc.createElement("a");
  a.setAttribute("href", link);
  a.setAttribute("rel", "noreferrer");
  a.setAttribute("referrerpolicy", "no-referrer");
  const svg = doc.createElementNS(SVG_NS, "svg");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", q.label);
  svg.setAttribute("width", String(q.pixels));
  svg.setAttribute("height", String(q.pixels));
  svg.setAttribute("viewBox", `0 0 ${units} ${units}`);
  svg.setAttribute("shape-rendering", "crispEdges");
  const rect = doc.createElementNS(SVG_NS, "rect");
  rect.setAttribute("width", units);
  rect.setAttribute("height", units);
  rect.setAttribute("fill", q.light);
  const path = doc.createElementNS(SVG_NS, "path");
  path.setAttribute("d", q.path);
  path.setAttribute("fill", q.dark);
  svg.appendChild(rect);
  svg.appendChild(path);
  a.appendChild(svg);
  return a;
}
