/**
 * The starter side of wallet sign-in (base design section 13, contract C1
 * and C2), with no UI framework.
 *
 * The page calls {@link SignInController.start} when the member clicks "Show
 * sign-in code". The controller generates `K_b`, signs and sends
 * `auth/oob/request`, builds the trigger link, renders it as a clickable QR
 * code into `container`, and long-polls `auth/oob/redeem` with a freshly
 * signed document each time, one poll at a time. The page draws its own UI
 * from the states it receives.
 *
 * The page carrying the link must be served with `Referrer-Policy:
 * no-referrer`, `Cache-Control: no-store` and CSP `frame-ancestors 'none'`,
 * and load no third-party scripts (VTI-LNK-082). That is the site's job.
 */

import { buildOobDocument, signOobDocument } from "../oob/document.js";
import {
  buildTriggerLink,
  DEFAULT_LINK_HOST,
  DEFAULT_LINK_PATH,
} from "../oob/link.js";
import type { QrRenderOptions } from "../oob/qr.js";
import {
  OOB_ERRORS,
  OOB_TYPES,
  isMatchNumber,
  type OobDocument,
  type RedeemResponse,
  type RequestResponse,
} from "../oob/types.js";
import {
  generateStarterKey,
  MemoryStarterKeyStore,
  starterKeyFromPair,
  type StarterKey,
  type StarterKeyStore,
} from "./key.js";
import { createTriggerLinkElement } from "./qr.js";

/** Everything the page needs to draw. */
export type SignInState =
  | { status: "idle" }
  | { status: "starting" }
  /** Show the code. `codeVisible` turns false when the tab is hidden. */
  | {
      status: "waiting";
      requestId: string;
      link: string;
      expiresAt: Date;
      codeVisible: boolean;
    }
  /** "Approve on your phone. Your number is 47", with Cancel. */
  | { status: "claimed"; requestId: string; matchNumber: string }
  /** "Continue as <displayName>?" with Continue ({@link SignInController.confirm}) and Not me. */
  | {
      status: "confirm";
      subject: string;
      displayName: string;
      notAfter: Date;
      /** The redeem response's `ext`: a bearer-token service's tokens, by namespace. */
      ext?: Record<string, unknown>;
    }
  | {
      status: "signedIn";
      subject: string;
      displayName: string;
      notAfter: Date;
      ext?: Record<string, unknown>;
    }
  | { status: "declined" }
  | { status: "cancelled" }
  | { status: "expired" }
  | { status: "error"; code: string; message: string };

export interface SignInOptions {
  /**
   * The URL Trust-Task documents are POSTed to: the service's
   * `TrustTaskHTTPS` base with `/trust-tasks` appended (e.g.
   * `https://members.example.org/v1/trust-tasks` for the base
   * `https://members.example.org/v1`). Used as is. {@link trustTaskEndpoint}
   * builds it from a DID document.
   */
  endpoint: string;
  /** The service (VTC) DID: `recipient` of every document and `_from`. */
  serviceDid: string;
  /** Link host. Default `link.trustoverip.org`. Never the page's own domain. */
  linkHost?: string;
  linkPath?: string;
  /** Element the clickable QR is rendered into while waiting. Optional. */
  container?: Element;
  qr?: QrRenderOptions;
  /** Where `K_b` is kept after sign-in. Default: memory (page lifetime). */
  keyStore?: StarterKeyStore;
  /** See {@link generateStarterKey}. Default false. */
  allowInMemoryFallback?: boolean;
  /** Called on every state change. */
  onStateChange?: (state: SignInState) => void;
  /** Called after sign-out has deleted `K_b`; end the site session here. */
  onSignOut?: () => void | Promise<void>;
  /** Timeout of an ordinary call, ms. Default 15 000. */
  requestTimeoutMs?: number;
  /** Timeout of one redeem long poll, ms. Default 35 000 (service holds 25 s). */
  pollTimeoutMs?: number;
  /** `fetch` credentials mode. Default `same-origin`. */
  credentials?: RequestCredentials;
  /** Seams for tests and non-window hosts. */
  fetch?: typeof fetch;
  document?: Document;
  /** Host of the page showing the link. Default `location.hostname`. */
  pageHost?: string;
  /** Registrable-domain function for the VTI-LNK-084 check. */
  registrableDomain?: (host: string) => string;
}

/** A refusal from the service, or a transport failure. */
export class SignInError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "SignInError";
  }
}

type PostResult =
  | { ok: true; payload: unknown }
  | {
      ok: false;
      code: string;
      message: string;
      details?: Record<string, unknown>;
    };

/** Create a controller. Nothing happens until {@link SignInController.start}. */
export function createSignIn(options: SignInOptions): SignInController {
  return new SignInController(options);
}

export class SignInController {
  private current: SignInState = { status: "idle" };
  private readonly listeners = new Set<(s: SignInState) => void>();
  private key: StarterKey | null = null;
  private requestId: string | null = null;
  private run = 0;
  private poll: AbortController | null = null;
  private expiryTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly keyStore: StarterKeyStore;
  private readonly doc: Document | undefined;
  private readonly onVisibility = () => this.visibilityChanged();

  constructor(private readonly opts: SignInOptions) {
    this.keyStore = opts.keyStore ?? new MemoryStarterKeyStore();
    this.doc =
      opts.document ?? (typeof document !== "undefined" ? document : undefined);
    if (opts.onStateChange) this.listeners.add(opts.onStateChange);
    this.doc?.addEventListener("visibilitychange", this.onVisibility);
  }

  get state(): SignInState {
    return this.current;
  }

  /** The signing key of the current session, if signed in. */
  get sessionKey(): StarterKey | null {
    return this.current.status === "signedIn" ||
      this.current.status === "confirm"
      ? this.key
      : null;
  }

  /** Listen for state changes. Returns an unsubscribe function. */
  subscribe(listener: (s: SignInState) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * "Show sign-in code": abandon any open request, generate a fresh `K_b`,
   * send `auth/oob/request` and show the code.
   */
  async start(): Promise<void> {
    await this.abandon();
    const run = ++this.run;
    this.set({ status: "starting" });
    try {
      this.key = await generateStarterKey({
        allowInMemoryFallback: this.opts.allowInMemoryFallback,
      });
      const res = await this.post(
        await this.signed(OOB_TYPES.request, {
          purpose: "login",
          mode: "scan",
        }),
        this.opts.requestTimeoutMs ?? 15_000,
      );
      if (run !== this.run) return;
      if (!res.ok) throw new SignInError(res.code, res.message, res.details);
      const { requestId, claimDeadline } = res.payload as RequestResponse;
      // Integer epoch seconds only (C9), written into `_exp` unchanged.
      const expSecs = claimDeadline;
      if (
        typeof requestId !== "string" ||
        !Number.isSafeInteger(expSecs) ||
        expSecs < 0
      ) {
        throw new SignInError(
          "malformedResponse",
          "the service returned an unusable request",
        );
      }
      const link = buildTriggerLink({
        from: this.opts.serviceDid,
        requestId,
        exp: expSecs,
        linkHost: this.opts.linkHost ?? DEFAULT_LINK_HOST,
        linkPath: this.opts.linkPath ?? DEFAULT_LINK_PATH,
        pageHost:
          this.opts.pageHost ??
          (typeof location !== "undefined" ? location.hostname : undefined),
        nowSecs: Math.floor(Date.now() / 1000),
        ...(this.opts.registrableDomain
          ? { registrableDomain: this.opts.registrableDomain }
          : {}),
      });
      this.requestId = requestId;
      const visible = this.doc?.visibilityState !== "hidden";
      if (visible) this.showCode(link);
      this.set({
        status: "waiting",
        requestId,
        link,
        expiresAt: new Date(expSecs * 1000),
        codeVisible: visible,
      });
      this.expiryTimer = setTimeout(
        () => {
          if (run === this.run && this.current.status === "waiting")
            void this.finish("expired");
        },
        Math.max(0, expSecs * 1000 - Date.now()),
      );
      void this.pollLoop(run);
    } catch (e) {
      if (run !== this.run) return;
      await this.dropKey();
      this.fail(e);
    }
  }

  /** Cancel the open request (`auth/oob/cancel`). */
  async cancel(): Promise<void> {
    if (this.current.status !== "waiting" && this.current.status !== "claimed")
      return;
    await this.abandon();
    this.set({ status: "cancelled" });
  }

  /** "Continue as …?": the member confirmed. */
  confirm(): void {
    if (this.current.status !== "confirm") return;
    this.set({ ...this.current, status: "signedIn" });
  }

  /** "Not me": sign out at once. */
  async notMe(): Promise<void> {
    await this.signOut();
  }

  /** Sign out: delete `K_b`, then call `onSignOut`. */
  async signOut(): Promise<void> {
    this.run++;
    this.stopPolling();
    this.hideCode();
    await this.dropKey();
    this.requestId = null;
    this.set({ status: "idle" });
    await this.opts.onSignOut?.();
  }

  /**
   * After a reload, pick the session key back up from the key store. Returns
   * null if there is none. The site still decides whether its session is live.
   */
  async restoreSessionKey(): Promise<StarterKey | null> {
    const pair = await this.keyStore.load();
    this.key = pair ? await starterKeyFromPair(pair) : null;
    return this.key;
  }

  /** Sign a document as `K_b` (base design section 9), addressed to the service. */
  async signDocument<P>(
    type: string,
    payload: P,
    options: { proofPurpose?: "authentication" | "assertionMethod" } = {},
  ): Promise<OobDocument<P>> {
    if (!this.key) throw new SignInError("noKey", "no session key");
    return this.signed(type, payload, options.proofPurpose);
  }

  /** Remove listeners and stop polling. */
  destroy(): void {
    this.run++;
    this.stopPolling();
    this.hideCode();
    this.doc?.removeEventListener("visibilitychange", this.onVisibility);
    this.listeners.clear();
  }

  // ---- internals ---------------------------------------------------------

  private async pollLoop(run: number): Promise<void> {
    let failures = 0;
    while (run === this.run && this.requestId) {
      const requestId = this.requestId;
      this.poll = new AbortController();
      let res: PostResult;
      try {
        res = await this.post(
          await this.signed(OOB_TYPES.redeem, { requestId }),
          this.opts.pollTimeoutMs ?? 35_000,
          this.poll.signal,
        );
      } catch (e) {
        if (run !== this.run) return;
        // Network failure or our own timeout: back off and poll again.
        failures++;
        if (failures > 5) return this.fail(e);
        await sleep(Math.min(1000 * failures, 5000));
        continue;
      }
      if (run !== this.run) return;
      failures = 0;
      if (res.ok) {
        const body = (res.payload ?? {}) as Partial<RedeemResponse>;
        if (
          typeof body.subject !== "string" ||
          !Number.isSafeInteger(body.notAfter)
        ) {
          return this.fail(
            new SignInError(
              "malformedResponse",
              "redeem returned no subject or no integer notAfter",
            ),
          );
        }
        this.clearTimers();
        this.hideCode();
        if (this.key?.keyPair) await this.keyStore.save(this.key.keyPair);
        this.requestId = null;
        const ext =
          body.ext && typeof body.ext === "object" && !Array.isArray(body.ext)
            ? body.ext
            : undefined;
        this.set({
          status: "confirm",
          subject: body.subject,
          displayName:
            typeof body.displayName === "string" && body.displayName
              ? body.displayName
              : body.subject,
          notAfter: new Date(body.notAfter! * 1000),
          ...(ext ? { ext } : {}),
        });
        return;
      }
      switch (res.code) {
        case OOB_ERRORS.pending: {
          const n = res.details?.matchNumber;
          if (isMatchNumber(n) && this.current.status === "waiting") {
            this.clearTimers();
            this.hideCode();
            this.set({ status: "claimed", requestId, matchNumber: n });
          }
          continue;
        }
        case OOB_ERRORS.rateLimited:
          await sleep(1000);
          continue;
        case OOB_ERRORS.declined:
          return this.finish(
            res.details?.state === "cancelled" ? "cancelled" : "declined",
          );
        case OOB_ERRORS.requestExpired:
        case OOB_ERRORS.requestNotFound:
          return this.finish("expired");
        default:
          return this.fail(new SignInError(res.code, res.message, res.details));
      }
    }
  }

  private async finish(
    status: "declined" | "cancelled" | "expired",
  ): Promise<void> {
    this.run++;
    this.stopPolling();
    this.hideCode();
    this.requestId = null;
    await this.dropKey();
    this.set({ status });
  }

  /** Stop the current request: abort the poll and tell the service. */
  private async abandon(): Promise<void> {
    this.run++;
    this.stopPolling();
    this.hideCode();
    const requestId = this.requestId;
    this.requestId = null;
    if (requestId && this.key) {
      try {
        await this.post(
          await this.signed(OOB_TYPES.cancel, { requestId }),
          this.opts.requestTimeoutMs ?? 15_000,
        );
      } catch {
        // Best effort: the request expires on its own.
      }
    }
    await this.dropKey();
  }

  private visibilityChanged(): void {
    if (this.current.status !== "waiting") return;
    if (this.doc?.visibilityState === "hidden" && this.current.codeVisible) {
      // Hide the code, but keep polling: on a phone, tapping the code opens
      // the wallet and hides this tab, and that sign-in must still complete.
      this.hideCode();
      this.set({ ...this.current, codeVisible: false });
    }
  }

  private showCode(link: string): void {
    const c = this.opts.container;
    if (!c || !this.doc) return;
    c.replaceChildren(createTriggerLinkElement(this.doc, link, this.opts.qr));
  }

  private hideCode(): void {
    this.opts.container?.replaceChildren();
  }

  private stopPolling(): void {
    this.poll?.abort();
    this.poll = null;
    this.clearTimers();
  }

  private clearTimers(): void {
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    this.expiryTimer = null;
  }

  private async dropKey(): Promise<void> {
    this.key = null;
    try {
      await this.keyStore.delete();
    } catch {
      // Nothing more to do; the pair is unusable without the page anyway.
    }
  }

  private fail(e: unknown): void {
    this.run++;
    this.stopPolling();
    this.hideCode();
    this.requestId = null;
    const code =
      e instanceof SignInError
        ? e.code
        : ((e as { name?: string })?.name ?? "error");
    const message = e instanceof Error ? e.message : String(e);
    this.set({ status: "error", code, message });
  }

  private set(state: SignInState): void {
    this.current = state;
    for (const l of [...this.listeners]) {
      try {
        l(state);
      } catch {
        // A listener's bug must not stop the flow.
      }
    }
  }

  private async signed<P>(
    type: string,
    payload: P,
    proofPurpose: "authentication" | "assertionMethod" = "authentication",
  ): Promise<OobDocument<P>> {
    const key = this.key!;
    // The starter key signs for `authentication` (CONVENTIONS.md section 5).
    return signOobDocument(
      buildOobDocument({
        type,
        issuer: key.did,
        recipient: this.opts.serviceDid,
        payload,
      }),
      key,
      { proofPurpose },
    );
  }

  private async post(
    doc: unknown,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<PostResult> {
    const f = this.opts.fetch ?? fetch;
    const ctl = new AbortController();
    const timer = setTimeout(
      () => ctl.abort(new SignInError("timeout", "the service did not answer")),
      timeoutMs,
    );
    const onAbort = () => ctl.abort(signal!.reason);
    signal?.addEventListener("abort", onAbort);
    try {
      const res = await f(this.opts.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        credentials: this.opts.credentials ?? "same-origin",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        body: JSON.stringify(doc),
        signal: ctl.signal,
      });
      const body = (await res.json().catch(() => null)) as {
        type?: string;
        payload?: Record<string, unknown>;
      } | null;
      const isError =
        !res.ok ||
        (typeof body?.type === "string" &&
          body.type.includes("/trust-task-error/"));
      if (!isError) return { ok: true, payload: body?.payload };
      const p = body?.payload ?? {};
      const code =
        typeof p.code === "string"
          ? p.code
          : res.status === 429
            ? OOB_ERRORS.rateLimited
            : `http${res.status}`;
      return {
        ok: false,
        code,
        message:
          typeof p.message === "string"
            ? p.message
            : `${res.status} from the sign-in service`,
        ...(p.details && typeof p.details === "object"
          ? { details: p.details as Record<string, unknown> }
          : {}),
      };
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
