import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";

import {
  buildOobDocument,
  computeContextDigest,
  didKeyVerificationMethod,
  DidKeyDocumentResolver,
  ed25519DidKey,
  MemoryOobRequestStore,
  OOB_TYPES,
  OobSignInService,
  signOobDocument,
  type DidDocument,
  type DidDocumentResolver,
  type EddsaJcsSigner,
  type OobDocument,
  type OobSignInServiceOptions,
} from "../../src/index.js";

export interface TestKey {
  did: string;
  signer: EddsaJcsSigner;
  publicKey: Uint8Array;
}

/** A fresh Ed25519 did:key (K_a or K_b). */
export function didKey(): TestKey {
  const secret = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(secret);
  const did = ed25519DidKey(publicKey);
  return {
    did,
    publicKey,
    signer: {
      verificationMethod: didKeyVerificationMethod(did),
      sign: (m) => ed25519.sign(m, secret),
    },
  };
}

function multikey(pub: Uint8Array): string {
  const b = new Uint8Array(34);
  b.set([0xed, 0x01]);
  b.set(pub, 2);
  return "z" + base58.encode(b);
}

/** A DID with separate authentication and assertionMethod keys. */
export interface TestDid {
  did: string;
  auth: EddsaJcsSigner;
  assertion: EddsaJcsSigner;
  document: DidDocument;
}

export function makeDid(did: string): TestDid {
  const a = ed25519.utils.randomSecretKey();
  const s = ed25519.utils.randomSecretKey();
  const document: DidDocument = {
    id: did,
    verificationMethod: [
      {
        id: `${did}#auth`,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: multikey(ed25519.getPublicKey(a)),
      },
      {
        id: `${did}#assert`,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: multikey(ed25519.getPublicKey(s)),
      },
    ],
    authentication: ["#auth"],
    assertionMethod: [`${did}#assert`],
  };
  return {
    did,
    document,
    auth: {
      verificationMethod: `${did}#auth`,
      sign: (m) => ed25519.sign(m, a),
    },
    assertion: {
      verificationMethod: `${did}#assert`,
      sign: (m) => ed25519.sign(m, s),
    },
  };
}

export class MapResolver implements DidDocumentResolver {
  readonly docs = new Map<string, DidDocument>();
  calls: string[] = [];
  async resolveDidDocument(did: string): Promise<DidDocument> {
    this.calls.push(did);
    const d = this.docs.get(did);
    if (!d) throw new Error(`unknown DID ${did}`);
    return d;
  }
}

export const SERVICE_DID =
  "did:webvh:QmPEQVM1JPTyrvEgBcDXwjK4TeyLGSX1PxjgyeAisPviUx:members.example.org";
export const ORIGIN = "https://members.example.org";

export function setup(overrides: Partial<OobSignInServiceOptions> = {}) {
  const service = makeDid(SERVICE_DID);
  const alice = makeDid("did:webvh:QmAlice:alice.example.org");
  const mallory = makeDid("did:webvh:QmMallory:mallory.example.org");
  const resolver = new MapResolver();
  resolver.docs.set(service.did, service.document);
  resolver.docs.set(alice.did, alice.document);
  resolver.docs.set(mallory.did, mallory.document);
  const members = new Set([alice.did]);
  const store = new MemoryOobRequestStore();
  const svc = new OobSignInService({
    serviceDid: SERVICE_DID,
    serviceName: "Example Community",
    origin: ORIGIN,
    store,
    resolver: new DidKeyDocumentResolver(resolver),
    responseSigner: service.assertion,
    isActiveMember: async (did) => members.has(did),
    displayName: async (did) => (did === alice.did ? "Alice" : undefined),
    redeemHoldMs: 0,
    ...overrides,
  });
  return { svc, store, resolver, service, alice, mallory, members };
}

export async function sign<P>(
  type: string,
  issuer: { did: string; signer?: EddsaJcsSigner },
  signer: EddsaJcsSigner,
  payload: P,
  extra: {
    parentThreadId?: string;
    recipient?: string;
    now?: Date;
    proofPurpose?: "assertionMethod" | "authentication";
  } = {},
): Promise<OobDocument<P>> {
  const doc = buildOobDocument({
    type,
    issuer: issuer.did,
    recipient: extra.recipient ?? SERVICE_DID,
    payload,
    parentThreadId: extra.parentThreadId,
    now: extra.now,
  });
  // did:key (starter and lock) documents sign for authentication.
  const proofPurpose =
    extra.proofPurpose ??
    (issuer.did.startsWith("did:key:") ? "authentication" : "assertionMethod");
  return signOobDocument(doc, signer, { proofPurpose, now: extra.now });
}

export const requestDoc = (kb: TestKey) =>
  sign(OOB_TYPES.request, kb, kb.signer, { purpose: "login", mode: "scan" });
export const claimDoc = (ka: TestKey, requestId: string) =>
  sign(
    OOB_TYPES.claim,
    ka,
    ka.signer,
    { requestId },
    { parentThreadId: requestId },
  );
export const identifyDoc = (
  who: TestDid,
  requestId: string,
  approverKey: string,
  enteredNumber: string,
) =>
  sign(
    OOB_TYPES.identify,
    who,
    who.auth,
    { requestId, approverKey, enteredNumber },
    { proofPurpose: "authentication" },
  );
export const redeemDoc = (kb: TestKey, requestId: string) =>
  sign(OOB_TYPES.redeem, kb, kb.signer, { requestId });

export async function grantDoc(
  who: TestDid,
  p: {
    requestId: string;
    sessionKey: string;
    approverKey: string;
    step2: unknown;
    decision?: "approve" | "decline";
    origin?: string;
  },
) {
  return sign(
    OOB_TYPES.grant,
    who,
    who.assertion,
    {
      requestId: p.requestId,
      decision: p.decision ?? "approve",
      sessionKey: p.sessionKey,
      approverKey: p.approverKey,
      origin: p.origin ?? ORIGIN,
      contextDigest: computeContextDigest(p.step2),
      notAfter: Math.floor(Date.now() / 1000) + 3600,
    },
    { proofPurpose: "assertionMethod" },
  );
}
