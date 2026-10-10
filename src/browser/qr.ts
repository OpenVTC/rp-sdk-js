/**
 * The browser entry point's QR rendering: the dependency-free renderers in
 * `../oob/qr.ts` with a default encoder.
 *
 * The default encoder is `qrcode-generator` (MIT, no dependencies). It is
 * imported only here, so only `@openvtc/rp-sdk/browser` loads it. Pass
 * `encoder` to use a different library.
 */

import qrcode from "qrcode-generator";

import {
  renderQrSvg as renderQrSvgWith,
  renderTriggerLinkHtml as renderTriggerLinkHtmlWith,
  resolveQr,
  type QrEncoder,
  type QrRenderOptions,
  type QrRenderOptionsWithEncoder,
} from "../oob/qr.js";

const SVG_NS = "http://www.w3.org/2000/svg";

/** The default encoder: `qrcode-generator`, automatic version, level M. */
export const defaultQrEncoder: QrEncoder = (text) => {
  const qr = qrcode(0, "M");
  qr.addData(text, "Byte");
  qr.make();
  const size = qr.getModuleCount();
  return { size, isDark: (r, c) => qr.isDark(r, c) };
};

function withDefault(opts: QrRenderOptions): QrRenderOptionsWithEncoder {
  return { ...opts, encoder: opts.encoder ?? defaultQrEncoder };
}

/** The QR code as an SVG string, not wrapped in a link. */
export function renderQrSvg(text: string, opts: QrRenderOptions = {}): string {
  return renderQrSvgWith(text, withDefault(opts));
}

/**
 * The QR code wrapped in `<a href="link">` (VTI-LNK-086), as an HTML string.
 */
export function renderTriggerLinkHtml(
  link: string,
  opts: QrRenderOptions = {},
): string {
  return renderTriggerLinkHtmlWith(link, withDefault(opts));
}

/**
 * The QR code wrapped in `<a href="link">`, as DOM nodes built with
 * `createElementNS` (no `innerHTML`, so it works under Trusted Types).
 */
export function createTriggerLinkElement(
  doc: Document,
  link: string,
  opts: QrRenderOptions = {},
): HTMLAnchorElement {
  const q = resolveQr(link, withDefault(opts));
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
