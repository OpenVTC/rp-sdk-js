/**
 * DID-document resolution with verification relationships.
 *
 * The SIOPv2 path only ever needed "the authentication key of this DID"
 * ({@link DidResolver}). The `auth/oob` family needs more: `identify` must be
 * signed by a key listed under `authentication`, and `grant` by one listed
 * under `assertionMethod` (contract C5). So this resolver returns the whole
 * document and {@link resolveRelationshipKey} picks the key.
 */

import { base58, base64urlnopad } from "@scure/base";

import { didKeyVerificationMethod, ed25519KeyFromDidKey } from "./did-key.js";

export type VerificationRelationship = "authentication" | "assertionMethod";

/** The subset of a DID document this SDK reads. */
export interface DidDocument {
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  service?: { id: string; type: string | string[]; serviceEndpoint: unknown }[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: { kty?: string; crv?: string; x?: string };
}

/**
 * Resolves a DID to its DID document. Plug in your resolver (a wrapper over
 * the Affinidi resolver cache, a `did:webvh` resolver, …). Cache member
 * documents: base design 7.4 relies on it so a proof is not a fresh fetch.
 */
export interface DidDocumentResolver {
  resolveDidDocument(did: string): Promise<DidDocument>;
}

/**
 * In-process resolver for Ed25519 `did:key`. Its one key is listed under both
 * `authentication` and `assertionMethod`. Optionally falls through to another
 * resolver for every other method.
 */
export class DidKeyDocumentResolver implements DidDocumentResolver {
  constructor(private readonly fallback?: DidDocumentResolver) {}

  async resolveDidDocument(did: string): Promise<DidDocument> {
    if (!did.startsWith("did:key:")) {
      if (this.fallback) return this.fallback.resolveDidDocument(did);
      throw new Error(`no resolver for ${did.split(":", 2).join(":")}`);
    }
    if (!ed25519KeyFromDidKey(did)) {
      throw new Error("did:key is not an Ed25519 multikey");
    }
    const vm = didKeyVerificationMethod(did);
    return {
      id: did,
      verificationMethod: [
        {
          id: vm,
          type: "Multikey",
          controller: did,
          publicKeyMultibase: did.slice("did:key:".length),
        },
      ],
      authentication: [vm],
      assertionMethod: [vm],
    };
  }
}

/**
 * The raw Ed25519 key of `verificationMethodId`, provided the method belongs
 * to `did` and is listed under `relationship` in its document.
 *
 * @throws Error naming what was missing
 */
export async function resolveRelationshipKey(
  resolver: DidDocumentResolver,
  did: string,
  verificationMethodId: string,
  relationship: VerificationRelationship,
): Promise<Uint8Array> {
  const doc = await resolver.resolveDidDocument(did);
  if (doc.id !== did) {
    throw new Error(`resolved document id ${doc.id} != ${did}`);
  }
  const abs = (ref: string) => (ref.startsWith("#") ? did + ref : ref);
  const target = abs(verificationMethodId);
  if (!target.startsWith(did + "#")) {
    throw new Error(`${verificationMethodId} is not a method of ${did}`);
  }
  const listed = (doc[relationship] ?? []).find((entry) =>
    typeof entry === "string"
      ? abs(entry) === target
      : abs(entry.id) === target,
  );
  if (!listed) {
    throw new Error(`${target} is not listed under ${relationship}`);
  }
  const vm =
    typeof listed === "string"
      ? (doc.verificationMethod ?? []).find((m) => abs(m.id) === target)
      : listed;
  if (!vm) throw new Error(`${target} has no verificationMethod entry`);
  return ed25519KeyOf(vm);
}

function ed25519KeyOf(vm: VerificationMethod): Uint8Array {
  if (vm.publicKeyMultibase) {
    if (!vm.publicKeyMultibase.startsWith("z")) {
      throw new Error("publicKeyMultibase must be base58btc");
    }
    const bytes = base58.decode(vm.publicKeyMultibase.slice(1));
    if (bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) {
      return bytes.slice(2);
    }
    if (bytes.length === 32 && vm.type === "Ed25519VerificationKey2018") {
      return bytes;
    }
    throw new Error(`${vm.id} is not an Ed25519 key`);
  }
  const jwk = vm.publicKeyJwk;
  if (jwk && jwk.kty === "OKP" && jwk.crv === "Ed25519" && jwk.x) {
    const bytes = base64urlnopad.decode(jwk.x);
    if (bytes.length === 32) return bytes;
  }
  throw new Error(`${vm.id} is not an Ed25519 key`);
}

/** The DID-document service type for a Trust-Task HTTPS endpoint (C4, C9). */
export const TRUST_TASK_HTTPS_SERVICE_TYPE = "TrustTaskHTTPS";
/** The DID-document service type of a sign-in portal (C4, VTI-LNK-102). */
export const SIGN_IN_PORTAL_SERVICE_TYPE = "SignInPortal";

function serviceEndpointOf(doc: DidDocument, type: string): string | null {
  // Matched on `type`, never on `id` (VTI-LNK-053).
  for (const svc of doc.service ?? []) {
    const types = Array.isArray(svc.type) ? svc.type : [svc.type];
    if (!types.includes(type)) continue;
    const ep = svc.serviceEndpoint;
    if (typeof ep !== "string") continue;
    let url: URL;
    try {
      url = new URL(ep);
    } catch {
      continue;
    }
    if (url.protocol !== "https:" || url.username || url.password) continue;
    return ep;
  }
  return null;
}

/** The path a client appends to a `TrustTaskHTTPS` base (HTTPS binding 0.2 §6). */
export const TRUST_TASK_HTTPS_PATH = "/trust-tasks";

/**
 * The URL to POST Trust-Task documents to, from the document's
 * `TrustTaskHTTPS` service. The published `serviceEndpoint` is a base URL
 * (VTC `…/v1`, DID hosting `…/api`); this returns it with one trailing
 * slash removed and `/trust-tasks` appended (HTTPS binding 0.2 §6), so
 * `https://members.example.org/v1` gives
 * `https://members.example.org/v1/trust-tasks`. Returns null when there is
 * no usable `https` one.
 */
export function trustTaskEndpoint(doc: DidDocument): string | null {
  const base = serviceEndpointOf(doc, TRUST_TASK_HTTPS_SERVICE_TYPE);
  if (base === null) return null;
  return (
    (base.endsWith("/") ? base.slice(0, -1) : base) + TRUST_TASK_HTTPS_PATH
  );
}

/** The origin of the document's `SignInPortal` service, or null. */
export function signInPortalOrigin(doc: DidDocument): string | null {
  const ep = serviceEndpointOf(doc, SIGN_IN_PORTAL_SERVICE_TYPE);
  return ep ? new URL(ep).origin : null;
}
