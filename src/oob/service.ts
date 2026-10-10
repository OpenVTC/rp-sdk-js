/**
 * A reference `auth/oob` sign-in service: the request state machine of base
 * design section 7, with a pluggable store.
 *
 * `pending → claimed → identified → approved → consumed`; `declined`,
 * `cancelled` and `expired` are final. Every change is a compare-and-set on
 * the record's `version`, so only one caller can make it. A failed prove or
 * respond **from the lock holder** declines the request.
 *
 * Transport-neutral: hand {@link OobSignInService.handle} the parsed body of
 * a `POST` to your trust-task endpoint and write back what it returns. Set
 * the session cookies yourself from `session` on a successful redeem.
 */

import { base64urlnopad } from "@scure/base";

import { isoSeconds, type EddsaJcsSigner } from "../proof.js";
import { buildOobDocument, signOobDocument } from "./document.js";
import type { DidDocumentResolver } from "./did-document.js";
import {
  OobVerificationError,
  computeContextDigest,
  verifyDidKeyDocument,
  verifyOobClaim,
  verifyOobGrant,
  verifyOobIdentify,
} from "./verify.js";
import {
  OOB_ERRORS as E,
  OOB_TYPES,
  TRUST_TASK_ERROR_TYPE,
  isMatchNumber,
  type CancelPayload,
  type GrantPayload,
  type OobDocument,
  type OobErrorCode,
  type OobRequestState,
  type ProvePayload,
  type RedeemPayload,
  type RedeemResponse,
  type RequestPayload,
  type RequestResponse,
  type RespondPayload,
  type RespondResponse,
  type Step1Response,
  type Step2Response,
  type TrustTaskErrorPayload,
} from "./types.js";

/** One sign-in request, as the store holds it (base design 7.2). */
export interface OobRequestRecord {
  requestId: string;
  state: OobRequestState;
  /** Incremented on every change; the compare-and-set key. */
  version: number;
  purpose: "login";
  mode: "scan";
  origin: string;
  /** `K_b`. */
  startKey: string;
  /** Egress IP of the `request`. Drop it once the request ends (T22). */
  startNetwork?: string;
  requester: {
    location: string;
    browser: string;
    os: string;
    createdAt: string;
  };
  /** `K_a`, set at claim. */
  approverKey?: string;
  /** Two digits, set at claim. */
  matchNumber?: string;
  /** Set at prove. */
  identifiedDid?: string;
  /** Digest of the signed step 2 response, set at prove. */
  step2Digest?: string;
  /** Epoch ms. */
  claimDeadline: number;
  /** Epoch ms, set at claim. */
  decisionDeadline?: number;
  /** The signed grant, once decided. */
  grant?: OobDocument<GrantPayload>;
}

/** Storage for requests and seen document ids. Make every method atomic. */
export interface OobRequestStore {
  create(record: OobRequestRecord): Promise<void>;
  get(requestId: string): Promise<OobRequestRecord | undefined>;
  /**
   * Replace the record only if its stored `version` equals `expectedVersion`.
   * Returns false, changing nothing, otherwise.
   */
  compareAndSet(
    requestId: string,
    expectedVersion: number,
    next: OobRequestRecord,
  ): Promise<boolean>;
  /**
   * Record a document `id` until `untilMs`. Returns false if it was already
   * recorded (a replay).
   */
  rememberDocumentId(id: string, untilMs: number): Promise<boolean>;
}

/** An in-memory store, for tests and single-process sites. */
export class MemoryOobRequestStore implements OobRequestStore {
  private readonly records = new Map<string, OobRequestRecord>();
  private readonly ids = new Map<string, number>();

  async create(record: OobRequestRecord): Promise<void> {
    if (this.records.has(record.requestId))
      throw new Error("duplicate requestId");
    this.records.set(record.requestId, structuredClone(record));
  }
  async get(requestId: string): Promise<OobRequestRecord | undefined> {
    const r = this.records.get(requestId);
    return r && structuredClone(r);
  }
  async compareAndSet(
    requestId: string,
    expectedVersion: number,
    next: OobRequestRecord,
  ): Promise<boolean> {
    const cur = this.records.get(requestId);
    if (!cur || cur.version !== expectedVersion) return false;
    this.records.set(requestId, structuredClone(next));
    return true;
  }
  async rememberDocumentId(id: string, untilMs: number): Promise<boolean> {
    const now = Date.now();
    for (const [k, until] of this.ids) if (until < now) this.ids.delete(k);
    if (this.ids.has(id)) return false;
    this.ids.set(id, untilMs);
    return true;
  }
}

/** A refusal, carried to the caller as a `trust-task-error`. */
export class OobError extends Error {
  constructor(
    readonly code: OobErrorCode,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "OobError";
  }

  /** A suggested HTTP status. */
  get httpStatus(): number {
    switch (this.code) {
      case E.rateLimited:
        return 429;
      case E.requestNotFound:
        return 404;
      case E.notAuthorized:
      case E.notClaimant:
      case E.notStarter:
        return 403;
      case E.malformedRequest:
      case E.keyUnsupported:
      case E.purposeUnsupported:
      case E.modeUnsupported:
        return 400;
      default:
        return 409;
    }
  }

  toPayload(): TrustTaskErrorPayload {
    return {
      code: this.code,
      message: this.message,
      ...(this.details ? { details: this.details } : {}),
    };
  }
}

/** Facts about the HTTP connection, which the documents cannot carry. */
export interface OobConnection {
  /** Egress IP. Used only to compute `sameNetwork`; never returned. */
  ip?: string;
  /** City and country from a local GeoIP lookup, or "unknown". */
  location?: string;
  /** Browser family from the User-Agent. */
  browser?: string;
  os?: string;
  /** Aborts a redeem long poll (client went away). */
  signal?: AbortSignal;
}

/** The session a successful redeem creates. Set your cookies from it. */
export interface OobSession {
  subject: string;
  /** `K_b`: the only key that may sign as `subject` in this session. */
  sessionKey: string;
  amr: ["did", "oob", "uv"];
  notAfter: Date;
  /** The display name, or the DID when there is none. */
  displayName: string;
  /** The signed grant, for the audit record. */
  grant: OobDocument<GrantPayload>;
  /**
   * Extensions for the redeem response, from `redeemExt`: a bearer-token
   * service puts its tokens here under its own namespace.
   */
  ext?: Record<string, unknown>;
}

export interface OobSignInServiceOptions {
  serviceDid: string;
  /** The community name shown in step 1. */
  serviceName: string;
  /** The portal origin (`SignInPortal` service). */
  origin: string;
  store: OobRequestStore;
  /** Resolves member DIDs. Cache their documents. */
  resolver: DidDocumentResolver;
  /** The service's `assertionMethod` key, for the step 1 and 2 responses. */
  responseSigner: EddsaJcsSigner;
  /** Is this DID an active member? Called before any DID resolution. */
  isActiveMember(did: string): Promise<boolean>;
  /**
   * For a service without cookie sessions: the `ext` of the redeem response,
   * keyed by reverse-DNS namespace (e.g. `com.affinidi.did-hosting`), which
   * reaches the starter only. Never put tokens anywhere else.
   */
  redeemExt?(
    session: Omit<OobSession, "ext">,
  ): Promise<Record<string, unknown> | undefined>;
  /** Display name for the "Continue as …?" step. */
  displayName?(did: string): Promise<string | undefined>;
  /** Default 120. */
  claimWindowSecs?: number;
  /** Default 120. */
  decisionWindowSecs?: number;
  /** Upper bound on a session, seconds. Default 8 h. */
  sessionLimitSecs?: number;
  /** How long redeem holds an undecided request, ms. Default 25 000. */
  redeemHoldMs?: number;
  /** How often a held redeem re-reads the store, ms. Default 250. */
  pollIntervalMs?: number;
  /** Clock seam. */
  now?: () => Date;
}

/** What {@link OobSignInService.handle} returns. */
export interface OobHandleResult {
  status: number;
  /** A `#response` document or a `trust-task-error` document. */
  body: OobDocument<unknown>;
  /** Set on a successful redeem only. */
  session?: OobSession;
}

const FINAL: OobRequestState[] = [
  "consumed",
  "declined",
  "cancelled",
  "expired",
];

/** The reference state machine. */
export class OobSignInService {
  private readonly o: Required<
    Pick<
      OobSignInServiceOptions,
      | "claimWindowSecs"
      | "decisionWindowSecs"
      | "sessionLimitSecs"
      | "redeemHoldMs"
      | "pollIntervalMs"
      | "now"
    >
  > &
    OobSignInServiceOptions;
  private readonly openPolls = new Set<string>();
  private readonly waiters = new Map<string, Set<() => void>>();

  constructor(options: OobSignInServiceOptions) {
    this.o = {
      claimWindowSecs: 120,
      decisionWindowSecs: 120,
      sessionLimitSecs: 8 * 3600,
      redeemHoldMs: 25_000,
      pollIntervalMs: 250,
      now: () => new Date(),
      ...options,
    };
    if (this.o.claimWindowSecs > 180 || this.o.decisionWindowSecs > 180) {
      throw new Error("claim and decision windows are at most 180 s");
    }
  }

  /** Route a parsed request body by its `type`. Never throws for a refusal. */
  async handle(
    raw: unknown,
    conn: OobConnection = {},
  ): Promise<OobHandleResult> {
    const type = (raw as { type?: unknown } | null)?.type;
    try {
      switch (type) {
        case OOB_TYPES.request:
          return this.ok(raw, await this.request(raw, conn));
        case OOB_TYPES.claim:
          return { status: 200, body: await this.claim(raw) };
        case OOB_TYPES.prove:
          return { status: 200, body: await this.prove(raw, conn) };
        case OOB_TYPES.respond:
          return this.ok(raw, await this.respond(raw));
        case OOB_TYPES.redeem: {
          const session = await this.redeem(raw, conn);
          const body: RedeemResponse = {
            subject: session.subject,
            displayName: session.displayName,
            notAfter: Math.floor(session.notAfter.getTime() / 1000),
            amr: session.amr,
            ...(session.ext ? { ext: session.ext } : {}),
          };
          return { ...this.ok(raw, body), session };
        }
        case OOB_TYPES.cancel:
          return this.ok(raw, await this.cancel(raw));
        default:
          throw new OobError(
            E.malformedRequest,
            `unsupported type ${String(type)}`,
          );
      }
    } catch (e) {
      const err =
        e instanceof OobError
          ? e
          : new OobError(E.malformedRequest, "request refused");
      if (!(e instanceof OobError)) {
        // Unexpected: keep the detail out of the response.
        console.error("auth/oob handler error", e);
      }
      return {
        status: err.httpStatus,
        body: {
          id: `urn:uuid:${crypto.randomUUID()}`,
          type: TRUST_TASK_ERROR_TYPE,
          issuer: this.o.serviceDid,
          issuedAt: isoSeconds(this.o.now()),
          ...threadOf(raw),
          payload: err.toPayload(),
        },
      };
    }
  }

  private ok(raw: unknown, payload: unknown): OobHandleResult {
    const req = raw as OobDocument<unknown>;
    return {
      status: 200,
      body: {
        id: `urn:uuid:${crypto.randomUUID()}`,
        type: `${req.type}#response`,
        issuer: this.o.serviceDid,
        recipient: req.issuer,
        issuedAt: isoSeconds(this.o.now()),
        ...threadOf(raw),
        payload,
      },
    };
  }

  // ---- request -----------------------------------------------------------

  /** `auth/oob/request`: open a pending request for the starter key. */
  async request(
    raw: unknown,
    conn: OobConnection = {},
  ): Promise<RequestResponse> {
    const v = this.verifyKeyDoc<RequestPayload>(raw, OOB_TYPES.request);
    if (v.payload.purpose !== "login")
      throw new OobError(E.purposeUnsupported, "purpose must be login");
    if (v.payload.mode !== "scan")
      throw new OobError(E.modeUnsupported, "mode must be scan");
    await this.fresh(v.id);
    const now = this.o.now();
    // Whole seconds, so `_exp` and `claimDeadline` say the same thing.
    const claimDeadline =
      Math.floor(now.getTime() / 1000) * 1000 + this.o.claimWindowSecs * 1000;
    const requestId = base64urlnopad.encode(
      crypto.getRandomValues(new Uint8Array(16)),
    );
    await this.o.store.create({
      requestId,
      state: "pending",
      version: 0,
      purpose: "login",
      mode: "scan",
      origin: this.o.origin,
      startKey: v.issuer,
      ...(conn.ip ? { startNetwork: conn.ip } : {}),
      requester: {
        location: conn.location ?? "unknown",
        browser: conn.browser ?? "unknown",
        os: conn.os ?? "unknown",
        createdAt: isoSeconds(now),
      },
      claimDeadline,
    });
    return { requestId, claimDeadline: claimDeadline / 1000 };
  }

  // ---- claim (7.3) -------------------------------------------------------

  /** `auth/oob/claim`: lock to `K_a`; returns the signed step 1 response. */
  async claim(raw: unknown): Promise<OobDocument<Step1Response>> {
    let v;
    try {
      v = verifyOobClaim(raw, this.common());
    } catch (e) {
      throw mapVerification(e);
    }
    await this.fresh(v.id);
    const rec = await this.current(v.requestId);
    if (rec.state === "expired")
      throw new OobError(E.requestExpired, "request expired");
    if (rec.state !== "pending")
      throw new OobError(E.alreadyClaimed, "already claimed");
    const now = this.o.now().getTime();
    const next: OobRequestRecord = {
      ...rec,
      state: "claimed",
      version: rec.version + 1,
      approverKey: v.approverKey,
      matchNumber: twoDigits(),
      decisionDeadline: now + this.o.decisionWindowSecs * 1000,
    };
    if (!(await this.cas(rec, next)))
      throw new OobError(E.alreadyClaimed, "already claimed");
    return this.signed(raw, v.approverKey, this.step1(next));
  }

  // ---- prove (7.4) -------------------------------------------------------

  /** `auth/oob/prove`: check membership and number; returns signed step 2. */
  async prove(
    raw: unknown,
    conn: OobConnection = {},
  ): Promise<OobDocument<Step2Response>> {
    const v = this.verifyKeyDoc<ProvePayload>(raw, OOB_TYPES.prove);
    const identify = v.payload.identify as unknown as
      | OobDocument<Record<string, unknown>>
      | undefined;
    const requestId = identify?.payload?.requestId;
    if (typeof requestId !== "string")
      throw new OobError(E.malformedRequest, "identify.requestId missing");
    const rec = await this.lockHolderRecord(requestId, v.issuer, "claimed");
    await this.fresh(v.id);

    // From here every failure declines the request.
    const decline = async (err: OobError): Promise<never> => {
      await this.cas(rec, {
        ...rec,
        state: "declined",
        version: rec.version + 1,
        startNetwork: undefined,
      });
      throw err;
    };
    if (identify!.payload.approverKey !== rec.approverKey) {
      return decline(new OobError(E.notAuthorized, "not authorized"));
    }
    const did = identify!.issuer;
    // ACL check on the issuer string, before any DID resolution (T15).
    if (typeof did !== "string" || !(await this.o.isActiveMember(did))) {
      return decline(new OobError(E.notAuthorized, "not authorized"));
    }
    let verified;
    try {
      verified = await verifyOobIdentify(identify, {
        ...this.common(),
        resolver: this.o.resolver,
        requestId: rec.requestId,
        approverKey: rec.approverKey!,
      });
    } catch {
      return decline(new OobError(E.notAuthorized, "not authorized"));
    }
    if (!(await this.o.store.rememberDocumentId(verified.id, this.idTtl()))) {
      return decline(new OobError(E.notAuthorized, "not authorized"));
    }
    if (
      !isMatchNumber(verified.payload.enteredNumber) ||
      verified.payload.enteredNumber !== rec.matchNumber
    ) {
      return decline(
        new OobError(E.numberMismatch, "the number does not match"),
      );
    }

    const sameNetwork: boolean | "unknown" =
      rec.startNetwork && conn.ip ? rec.startNetwork === conn.ip : "unknown";
    const step2: Step2Response = {
      ...this.step1(rec),
      sessionKey: rec.startKey,
      requester: { ...rec.requester, sameNetwork },
      identifiedAs: verified.did,
    };
    const signed = await this.signed(raw, rec.approverKey!, step2);
    const next: OobRequestRecord = {
      ...rec,
      state: "identified",
      version: rec.version + 1,
      identifiedDid: verified.did,
      step2Digest: computeContextDigest(signed),
    };
    if (!(await this.cas(rec, next)))
      throw new OobError(E.requestExpired, "request changed");
    return signed;
  }

  // ---- respond (7.5) -----------------------------------------------------

  /** `auth/oob/respond`: record the member's signed decision. */
  async respond(raw: unknown): Promise<RespondResponse> {
    const v = this.verifyKeyDoc<RespondPayload>(raw, OOB_TYPES.respond);
    const requestId = (
      v.payload.grant as unknown as
        | OobDocument<Record<string, unknown>>
        | undefined
    )?.payload?.requestId;
    if (typeof requestId !== "string")
      throw new OobError(E.malformedRequest, "grant.requestId missing");
    const rec = await this.lockHolderRecord(requestId, v.issuer, "identified");
    await this.fresh(v.id);

    const decline = async (err: OobError): Promise<never> => {
      await this.cas(rec, {
        ...rec,
        state: "declined",
        version: rec.version + 1,
        startNetwork: undefined,
      });
      throw err;
    };
    let grant;
    try {
      grant = await verifyOobGrant(v.payload.grant, {
        ...this.common(),
        resolver: this.o.resolver,
        requestId: rec.requestId,
        identifiedDid: rec.identifiedDid!,
        approverKey: rec.approverKey!,
        sessionKey: rec.startKey,
        origin: rec.origin,
        contextDigest: rec.step2Digest!,
      });
    } catch (e) {
      const reason = e instanceof OobVerificationError ? e.reason : undefined;
      const mismatch =
        reason === "context_mismatch" ||
        reason === "session_key_mismatch" ||
        reason === "origin_mismatch";
      return decline(
        new OobError(
          mismatch ? E.contextMismatch : E.notAuthorized,
          mismatch ? "context mismatch" : "not authorized",
        ),
      );
    }
    if (!(await this.o.store.rememberDocumentId(grant.id, this.idTtl()))) {
      return decline(new OobError(E.notAuthorized, "not authorized"));
    }
    if (!(await this.o.isActiveMember(rec.identifiedDid!))) {
      return decline(new OobError(E.notAuthorized, "not authorized"));
    }
    const next: OobRequestRecord = {
      ...rec,
      state: grant.decision === "approve" ? "approved" : "declined",
      version: rec.version + 1,
      grant: v.payload.grant,
      startNetwork: undefined,
    };
    if (!(await this.cas(rec, next)))
      throw new OobError(E.alreadyDecided, "already decided");
    return { status: next.state === "approved" ? "approved" : "declined" };
  }

  // ---- redeem (7.6) ------------------------------------------------------

  /**
   * `auth/oob/redeem`: a long poll. Holds an undecided request for up to
   * `redeemHoldMs`, then refuses with retryable `pending`
   * (`details.state`, and `details.matchNumber` once claimed). On approval,
   * consumes the request and returns the session to create.
   */
  async redeem(raw: unknown, conn: OobConnection = {}): Promise<OobSession> {
    const v = this.verifyKeyDoc<RedeemPayload>(raw, OOB_TYPES.redeem);
    if (typeof v.payload.requestId !== "string") {
      throw new OobError(E.malformedRequest, "requestId missing");
    }
    let rec = await this.current(v.payload.requestId);
    if (rec.startKey !== v.issuer)
      throw new OobError(E.notStarter, "not the starter");
    await this.fresh(v.id);

    if (this.openPolls.has(rec.requestId)) {
      throw new OobError(
        E.rateLimited,
        "a poll is already open for this request",
      );
    }
    this.openPolls.add(rec.requestId);
    try {
      const until = Date.now() + this.o.redeemHoldMs;
      for (;;) {
        rec = await this.current(rec.requestId);
        if (rec.state === "approved") return await this.consume(rec);
        if (rec.state === "declined" || rec.state === "cancelled") {
          throw new OobError(E.declined, `request ${rec.state}`, {
            state: rec.state,
          });
        }
        if (rec.state === "expired" || rec.state === "consumed") {
          throw new OobError(E.requestExpired, "request expired", {
            state: rec.state,
          });
        }
        if (Date.now() >= until || conn.signal?.aborted) {
          throw new OobError(E.pending, "not decided yet", {
            state: rec.state,
            ...(rec.matchNumber ? { matchNumber: rec.matchNumber } : {}),
          });
        }
        await this.wait(
          rec.requestId,
          Math.min(this.o.pollIntervalMs, until - Date.now()),
          conn.signal,
        );
      }
    } finally {
      this.openPolls.delete(rec.requestId);
    }
  }

  private async consume(rec: OobRequestRecord): Promise<OobSession> {
    const next = {
      ...rec,
      state: "consumed" as const,
      version: rec.version + 1,
    };
    if (!(await this.cas(rec, next)))
      throw new OobError(E.requestExpired, "already redeemed");
    const did = rec.identifiedDid!;
    if (!(await this.o.isActiveMember(did)))
      throw new OobError(E.notAuthorized, "not authorized");
    const grantNotAfter = rec.grant!.payload.notAfter * 1000;
    const limit = this.o.now().getTime() + this.o.sessionLimitSecs * 1000;
    const displayName = (await this.o.displayName?.(did)) || did;
    const session: OobSession = {
      subject: did,
      sessionKey: rec.startKey,
      amr: ["did", "oob", "uv"],
      // Whole seconds: the wire carries integer epoch seconds.
      notAfter: new Date(
        Math.floor(Math.min(grantNotAfter, limit) / 1000) * 1000,
      ),
      displayName: displayName.slice(0, 128),
      grant: rec.grant!,
    };
    const ext = await this.o.redeemExt?.(session);
    if (ext && Object.keys(ext).length > 0) session.ext = ext;
    return session;
  }

  // ---- cancel ------------------------------------------------------------

  /** `auth/oob/cancel`, from the starter key or the lock. */
  async cancel(raw: unknown): Promise<{ status: "cancelled" }> {
    const v = this.verifyKeyDoc<CancelPayload>(raw, OOB_TYPES.cancel);
    if (typeof v.payload.requestId !== "string")
      throw new OobError(E.malformedRequest, "requestId missing");
    const rec = await this.current(v.payload.requestId);
    if (v.issuer !== rec.startKey && v.issuer !== rec.approverKey) {
      throw new OobError(E.notAuthorized, "not authorized");
    }
    await this.fresh(v.id);
    if (rec.state === "cancelled") return { status: "cancelled" };
    if (rec.state === "expired" || rec.state === "consumed") {
      throw new OobError(E.requestExpired, `request ${rec.state}`);
    }
    if (FINAL.includes(rec.state) || rec.state === "approved") {
      throw new OobError(E.alreadyDecided, `request ${rec.state}`);
    }
    const next = {
      ...rec,
      state: "cancelled" as const,
      version: rec.version + 1,
      startNetwork: undefined,
    };
    if (!(await this.cas(rec, next)))
      throw new OobError(E.alreadyDecided, "request changed");
    return { status: "cancelled" };
  }

  // ---- helpers -----------------------------------------------------------

  private common() {
    return { serviceDid: this.o.serviceDid, now: this.o.now() };
  }

  private verifyKeyDoc<P>(raw: unknown, type: string) {
    try {
      return verifyDidKeyDocument<P>(raw, type, this.common());
    } catch (e) {
      throw mapVerification(e);
    }
  }

  private idTtl(): number {
    // Documents are accepted for maxAgeSecs (300) after issuedAt; keep ids a
    // little longer than that.
    return this.o.now().getTime() + 600_000;
  }

  private async fresh(id: string): Promise<void> {
    if (!(await this.o.store.rememberDocumentId(id, this.idTtl()))) {
      throw new OobError(E.notAuthorized, "document id already used");
    }
  }

  /** The record, with an elapsed deadline applied. */
  private async current(requestId: string): Promise<OobRequestRecord> {
    for (;;) {
      const rec = await this.o.store.get(requestId);
      if (!rec) throw new OobError(E.requestNotFound, "no such request");
      const now = this.o.now().getTime();
      const lapsed =
        (rec.state === "pending" && now > rec.claimDeadline) ||
        ((rec.state === "claimed" ||
          rec.state === "identified" ||
          rec.state === "approved") &&
          now > (rec.decisionDeadline ?? 0));
      if (!lapsed) return rec;
      const next = {
        ...rec,
        state: "expired" as const,
        version: rec.version + 1,
        startNetwork: undefined,
      };
      if (await this.cas(rec, next)) return next;
    }
  }

  private async lockHolderRecord(
    requestId: string,
    issuer: string,
    expected: OobRequestState,
  ): Promise<OobRequestRecord> {
    const rec = await this.current(requestId);
    if (!rec.approverKey || rec.approverKey !== issuer) {
      throw new OobError(E.notClaimant, "not the claimant");
    }
    if (rec.state === "expired")
      throw new OobError(E.requestExpired, "request expired");
    if (rec.state !== expected) {
      throw new OobError(
        expected === "identified" &&
          ["approved", "declined", "cancelled"].includes(rec.state)
          ? E.alreadyDecided
          : E.requestExpired,
        `request is ${rec.state}`,
      );
    }
    return rec;
  }

  private async cas(
    prev: OobRequestRecord,
    next: OobRequestRecord,
  ): Promise<boolean> {
    const ok = await this.o.store.compareAndSet(
      prev.requestId,
      prev.version,
      next,
    );
    if (ok) {
      for (const w of this.waiters.get(prev.requestId) ?? []) w();
    }
    return ok;
  }

  private wait(
    requestId: string,
    ms: number,
    signal?: AbortSignal,
  ): Promise<void> {
    return new Promise((resolve) => {
      const set = this.waiters.get(requestId) ?? new Set();
      this.waiters.set(requestId, set);
      const done = () => {
        clearTimeout(timer);
        set.delete(done);
        if (set.size === 0) this.waiters.delete(requestId);
        signal?.removeEventListener("abort", done);
        resolve();
      };
      const timer = setTimeout(done, Math.max(0, ms));
      set.add(done);
      signal?.addEventListener("abort", done);
    });
  }

  private step1(rec: OobRequestRecord): Step1Response {
    return {
      requestId: rec.requestId,
      service: { did: this.o.serviceDid, name: this.o.serviceName },
      origin: rec.origin,
      purpose: rec.purpose,
      decisionDeadline: Math.floor(rec.decisionDeadline! / 1000),
    };
  }

  private async signed<P>(
    raw: unknown,
    recipient: string,
    payload: P,
  ): Promise<OobDocument<P>> {
    const req = raw as OobDocument<unknown>;
    const doc = buildOobDocument({
      type: `${req.type}#response`,
      issuer: this.o.serviceDid,
      recipient,
      threadId: req.id,
      payload,
      now: this.o.now(),
    });
    return signOobDocument(doc, this.o.responseSigner, {
      proofPurpose: "assertionMethod",
      now: this.o.now(),
    });
  }
}

function threadOf(raw: unknown): { threadId?: string } {
  const id = (raw as { id?: unknown } | null)?.id;
  return typeof id === "string" ? { threadId: id } : {};
}

function mapVerification(e: unknown): OobError {
  if (e instanceof OobError) return e;
  if (e instanceof OobVerificationError) {
    if (e.reason === "key_unsupported")
      return new OobError(E.keyUnsupported, "Ed25519 did:key only");
    if (
      e.reason === "malformed" ||
      e.reason === "wrong_type" ||
      e.reason === "parent_thread_mismatch"
    ) {
      return new OobError(E.malformedRequest, e.message);
    }
    return new OobError(E.notAuthorized, "not authorized");
  }
  throw e;
}

/** Two uniformly random digits, "00" to "99". */
function twoDigits(): string {
  const buf = new Uint8Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < 200) return String(buf[0] % 100).padStart(2, "0");
  }
}
