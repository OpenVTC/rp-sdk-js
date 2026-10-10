/**
 * Render a trigger link as a clickable SVG QR code (VTI-LNK-086 and the
 * chapter 07a rendering guidance): byte mode, level M, no logo, a quiet zone
 * of at least 4 modules, at least 4 CSS px per module, dark on light.
 *
 * This module has no third-party dependency and touches no DOM global: the
 * encoder is passed in through {@link QrEncoder}. The main entry point
 * re-exports these functions with `encoder` required, so importing the
 * server side never loads a QR library. `@openvtc/rp-sdk/browser` wraps them
 * with a default encoder (`qrcode-generator`, see `../browser/qr.ts`).
 */

import { TRIGGER_LINK_MAX_BYTES, TriggerLinkError } from "./link.js";

/** A QR symbol: a square of modules, `true` for dark. */
export interface QrMatrix {
  size: number;
  isDark(row: number, col: number): boolean;
}

/** Encodes ASCII text in byte mode at error-correction level M. */
export type QrEncoder = (text: string) => QrMatrix;

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
  /**
   * The QR encoder. Required when rendering through the main entry point;
   * `@openvtc/rp-sdk/browser` defaults it to `qrcode-generator`.
   */
  encoder?: QrEncoder;
}

/** {@link QrRenderOptions} with the encoder supplied. */
export type QrRenderOptionsWithEncoder = QrRenderOptions & {
  encoder: QrEncoder;
};

/** @internal The rendered geometry, shared with the browser DOM renderer. */
export interface ResolvedQr {
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

/** @internal Validate the input and lay out the modules. */
export function resolveQr(text: string, opts: QrRenderOptions): ResolvedQr {
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
  if (typeof opts.encoder !== "function") {
    throw new TypeError(
      "no QR encoder: pass `encoder`, or render through @openvtc/rp-sdk/browser",
    );
  }
  const matrix = opts.encoder(text);
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
export function renderQrSvg(
  text: string,
  opts: QrRenderOptionsWithEncoder,
): string {
  const q = resolveQr(text, opts);
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
  opts: QrRenderOptionsWithEncoder,
): string {
  return (
    `<a href="${escapeAttr(link)}" rel="noreferrer" referrerpolicy="no-referrer">` +
    `${renderQrSvg(link, opts)}</a>`
  );
}
