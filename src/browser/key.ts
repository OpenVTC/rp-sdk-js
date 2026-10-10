/**
 * The browser's starter key `K_b`: a WebCrypto Ed25519 key generated
 * **non-extractable** (base design section 3), exposed as a `did:key`.
 *
 * `generateKey(…, false, …)` governs the private key only; WebCrypto keeps the
 * public half exportable, which is all the `did:key` needs. The `false` is
 * the point of this module.
 *
 * Where WebCrypto Ed25519 is unavailable (Chrome < 137, Firefox < 130,
 * Safari < 17) generation fails with {@link Ed25519UnavailableError} unless
 * the caller opts into {@link GenerateStarterKeyOptions.allowInMemoryFallback},
 * which keeps a JavaScript key in memory only. That key is extractable by any
 * script in the page and cannot survive a reload; the returned key says so in
 * `custody`.
 */

import { ed25519 } from "@noble/curves/ed25519.js";

import { didKeyVerificationMethod, ed25519DidKey } from "../oob/did-key.js";

/** A key that can sign `auth/oob` documents as `did`. */
export interface StarterKey {
  /** `did:key:z6Mk…`. */
  readonly did: string;
  readonly verificationMethod: string;
  /** `webcrypto`: non-extractable. `memory`: the explicit fallback. */
  readonly custody: "webcrypto" | "memory";
  /** The WebCrypto pair, when `custody` is `webcrypto`. */
  readonly keyPair?: CryptoKeyPair;
  sign(input: Uint8Array): Promise<Uint8Array>;
}

/** Thrown when this browser cannot generate a WebCrypto Ed25519 key. */
export class Ed25519UnavailableError extends Error {
  constructor() {
    super(
      "This browser cannot create an Ed25519 key (needs Chrome 137+, Firefox 130+ or Safari 17+).",
    );
    this.name = "Ed25519UnavailableError";
  }
}

let available: Promise<boolean> | null = null;

/** Can this browser generate a WebCrypto Ed25519 key? Cached. */
export function isEd25519Available(): Promise<boolean> {
  available ??= (async () => {
    if (typeof crypto === "undefined" || !crypto.subtle) return false;
    try {
      await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
        "sign",
        "verify",
      ]);
      return true;
    } catch {
      return false;
    }
  })();
  return available;
}

export interface GenerateStarterKeyOptions {
  /**
   * Use an in-memory JavaScript key when WebCrypto Ed25519 is missing.
   * Default false. Weaker custody: see the module comment.
   */
  allowInMemoryFallback?: boolean;
}

/** Generate a fresh `K_b`. */
export async function generateStarterKey(
  options: GenerateStarterKeyOptions = {},
): Promise<StarterKey> {
  if (await isEd25519Available()) {
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    return starterKeyFromPair(pair);
  }
  if (!options.allowInMemoryFallback) throw new Ed25519UnavailableError();
  const secret = ed25519.utils.randomSecretKey();
  const did = ed25519DidKey(ed25519.getPublicKey(secret));
  return {
    did,
    verificationMethod: didKeyVerificationMethod(did),
    custody: "memory",
    sign: async (input) => ed25519.sign(input, secret),
  };
}

/** Wrap a stored WebCrypto pair as a {@link StarterKey}. */
export async function starterKeyFromPair(
  pair: CryptoKeyPair,
): Promise<StarterKey> {
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  const did = ed25519DidKey(raw);
  return {
    did,
    verificationMethod: didKeyVerificationMethod(did),
    custody: "webcrypto",
    keyPair: pair,
    sign: async (input) =>
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "Ed25519" },
          pair.privateKey,
          input as BufferSource,
        ),
      ),
  };
}

/** Where `K_b` lives for the session. */
export interface StarterKeyStore {
  save(pair: CryptoKeyPair): Promise<void>;
  load(): Promise<CryptoKeyPair | null>;
  delete(): Promise<void>;
}

/** Keeps `K_b` for the life of the page only. The default. */
export class MemoryStarterKeyStore implements StarterKeyStore {
  private pair: CryptoKeyPair | null = null;
  async save(pair: CryptoKeyPair): Promise<void> {
    this.pair = pair;
  }
  async load(): Promise<CryptoKeyPair | null> {
    return this.pair;
  }
  async delete(): Promise<void> {
    this.pair = null;
  }
}

/**
 * Keeps `K_b` in IndexedDB, so the session survives a reload. `CryptoKey` is
 * structured-cloneable and stays non-extractable in storage.
 */
export class IndexedDbStarterKeyStore implements StarterKeyStore {
  constructor(
    private readonly dbName = "openvtc-rp-sdk",
    private readonly keyName = "starter-key",
  ) {}

  private open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, 1);
      req.onupgradeneeded = () => req.result.createObjectStore("keys");
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  private async run<T>(
    mode: IDBTransactionMode,
    op: (s: IDBObjectStore) => IDBRequest,
  ): Promise<T> {
    const db = await this.open();
    try {
      return await new Promise<T>((resolve, reject) => {
        const req = op(db.transaction("keys", mode).objectStore("keys"));
        req.onsuccess = () => resolve(req.result as T);
        req.onerror = () => reject(req.error);
      });
    } finally {
      db.close();
    }
  }

  async save(pair: CryptoKeyPair): Promise<void> {
    await this.run("readwrite", (s) => s.put(pair, this.keyName));
  }
  async load(): Promise<CryptoKeyPair | null> {
    return (
      (await this.run<CryptoKeyPair | undefined>("readonly", (s) =>
        s.get(this.keyName),
      )) ?? null
    );
  }
  async delete(): Promise<void> {
    await this.run("readwrite", (s) => s.delete(this.keyName));
  }
}
