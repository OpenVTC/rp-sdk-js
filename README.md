# @openvtc/rp-sdk

Server-side SDK for Relying Parties (RPs) consuming SIOPv2 `id_token`s
from the OpenVTC browser plugin (`window.vtaWallet.login`).

## What this package does

`window.vtaWallet.login()` POSTs a SIOPv2 self-issued `id_token` to
your `/auth/` endpoint. The token is a compact EdDSA JWS signed by
the wallet's holder `did:key`. **The signature is not optional** —
without verifying it, any page can forge a login as any DID.

This SDK is the audited verification path. `verifyIdToken`:

- pins `alg` to `EdDSA` (no algorithm substitution),
- enforces SIOPv2 `iss === sub`,
- pins `aud` to your RP DID (no leniency),
- pins `nonce` to the challenge you issued (constant-time match),
- checks `iat` / `exp` within a configurable clock-skew window,
- resolves the issuer DID and verifies the JWS signature against
  the resolved Ed25519 verification method.

Failure modes surface as `IdTokenVerificationError` with a typed
`reason` — log it so operators can distinguish misconfigured
audience from a forged token.

## Why this exists

The browser-plugin demo skips verification — it trusts whatever
the wallet POSTs. The demo is widely copy-pasted into production
code, inheriting the gap. The May 2026 OpenVTC security review
flagged this as a high-severity issue (H2). This SDK is the fix.

## Install

```bash
npm install @openvtc/rp-sdk
```

## Usage

### Verify an id_token

```ts
import { verifyIdToken, KeyResolver } from "@openvtc/rp-sdk";

const resolver = new KeyResolver(); // did:key only; see below

const verified = await verifyIdToken({
  idToken: req.body.id_token,
  audience: process.env.RP_DID!,
  nonce: sessionStore.challengeFor(req.body.session_id),
  resolver,
});

// verified.subject is the wallet's holder DID; bind your session to it.
console.log(`logged in: ${verified.subject}`);
```

### Establish a session cookie

```ts
import { establishSession } from "@openvtc/rp-sdk";

const accessToken = await myJwtMinter.mint({ sub: verified.subject });
const { subject, cookie } = establishSession(verified, accessToken);

res.cookie(cookie.name, cookie.value, cookie.options);
// SDK sets HttpOnly + Secure + SameSite=Strict by default.
```

## DID resolvers

The bundled `KeyResolver` handles `did:key:z6Mk…` (Ed25519 multikey)
in-process — no network round-trip, no cache concerns.

For `did:peer:2` (the wallet's default for inbound RP-initiated
flows), `did:webvh`, or `did:web` — implement the `DidResolver`
interface against your preferred resolver. A thin wrapper around
`affinidi-did-resolver-cache-sdk` covers all of them.

```ts
import type { DidResolver } from "@openvtc/rp-sdk";

class MultiMethodResolver implements DidResolver {
  async resolveAuthenticationKey(did: string): Promise<Uint8Array> {
    if (did.startsWith("did:key:")) return keyResolver.resolveAuthenticationKey(did);
    // ... did:peer / did:webvh / did:web cases
  }
}
```

## Confirm (RP → wallet consent)

Beyond login, the SDK verifies the wallet's answer to a
[`confirm/{request,response}/0.1`](https://trusttasks.org/spec/confirm/response/0.1)
consent exchange. You ask the wallet to confirm a specific action; it
returns a `confirm/response` whose W3C Data Integrity `proof` **is** the
cryptographic record of the user's decision.

```ts
import {
  buildConfirmRequest,
  signConfirmRequest,
  verifyConfirmResponse,
  KeyResolver,
} from "@openvtc/rp-sdk";

// 1. Build a request, bind the challenge server-side to (subject, action),
//    and (per spec) sign it so `reason` is bound to your RP key.
const request = buildConfirmRequest({
  issuer: RP_DID,
  subject: walletDid,
  challenge, // ≥128-bit base64url nonce, persisted against this pending confirm
  reason: "Confirm transfer of $1,000 to did:web:bob.example",
  actionType: "payment.transfer",
});
await signConfirmRequest(request, rpSigner); // rpSigner: { verificationMethod, sign() }
// …authcrypt + deliver `request` to the wallet over DIDComm…

// 2. When the wallet's confirm/response arrives (already DIDComm-decrypted),
//    verify the proof + framework bindings:
const decision = await verifyConfirmResponse({
  document: responseDoc,
  subject: walletDid, // must equal issuer + proof signer
  challenge,          // must be echoed bit-for-bit
  audience: RP_DID,   // optional recipient cross-check
  resolver: new KeyResolver(),
});
// decision.decision ∈ {"approved","denied"}; retain the document for audit.
```

`verifyConfirmResponse` verifies the `eddsa-jcs-2022` proof and enforces
`subject === issuer === signer`, the challenge echo, and (optionally) the
recipient audience. It does **not** do the stateful checks the SDK can't
see — locating the pending request by challenge, consuming it single-use,
and persisting the decision — those stay your responsibility. Failures
surface as `ConfirmVerificationError` with a typed `reason`.

The DIDComm transport (authcrypt pack/unpack, mediator forwarding) is not
included; this module operates on the decrypted Trust-Task document.

## Roadmap

Planned for follow-up minor versions:

- `requireStepUp()` middleware — gates routes behind `acr=aal2`.
- `refreshProxy()` middleware — drop-in `/auth/refresh` proxy.
- Express + Fastify + Hono framework adapters.
- DIDComm-transport packing/unpacking helpers, so the confirm verifier
  above can be driven straight from an authcrypted mediator message.

## License

Apache-2.0
