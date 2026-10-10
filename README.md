# @openvtc/rp-sdk

SDK for Relying Parties (RPs) in the OpenVTC stack.

- **Wallet sign-in with a trigger link** (`auth/oob/*`): the default sign-in.
  The page shows a QR code that is also a clickable link; the member
  approves on their wallet, and their VTA signs a grant for a key the
  browser holds. The browser side is in `@openvtc/rp-sdk/browser`; the
  server-side verification helpers and a reference state machine are in
  `@openvtc/rp-sdk`.
- **Confirm** (`confirm/{request,response}/0.1`): ask a wallet to confirm
  an action, and verify its signed answer.
- **Legacy, deprecated:** SIOPv2 `id_token` verification
  (`verifyIdToken`) for the browser plugin's `window.vtaWallet.login`.

## Install

```bash
npm install @openvtc/rp-sdk
```

## Wallet sign-in with a trigger link

The design is `vtc-qr-login-design.md` (sections 7, 10 and 13) plus the
implementation contract `sign-in-trigger-link-contract.md`; the link format
is chapter 07a of the VTI spec (VTI-LNK-*).

```
https://link.trustoverip.org/t#_from=<service DID>&_id=<requestId>&_exp=<epoch s>&_type=/vti/flow/sign-in/0.1
```

### In the browser (`@openvtc/rp-sdk/browser`)

No UI framework. You draw the screens; the controller tells you which one.

```ts
import { createSignIn } from "@openvtc/rp-sdk/browser";

const signIn = createSignIn({
  endpoint: "/v1/trust-tasks",          // the service's trust-task endpoint
  serviceDid: "did:webvh:…:members.example.org",
  container: document.getElementById("sign-in-code")!, // the QR goes here
  // linkHost: "link.trustoverip.org", // default; never your own domain
  onStateChange(state) {
    switch (state.status) {
      case "waiting":   /* code shown; state.codeVisible is false once the tab was hidden */ break;
      case "claimed":   /* "Approve on your phone. Your number is " + state.matchNumber, with Cancel */ break;
      case "confirm":   /* "Continue as " + (state.displayName ?? state.subject) + "?" */ break;
      case "signedIn":  /* show who is signed in, with Sign out */ break;
      case "declined": case "cancelled": case "expired": /* offer a new code */ break;
      case "error":     /* state.code, state.message */ break;
    }
  },
  onSignOut: () => fetch("/logout", { method: "POST" }),
});

showCodeButton.onclick = () => signIn.start();   // "Show sign-in code"
cancelButton.onclick = () => signIn.cancel();
continueButton.onclick = () => signIn.confirm(); // "Continue"
notMeButton.onclick = () => signIn.notMe();      // "Not me": signs out
signOutButton.onclick = () => signIn.signOut();  // deletes K_b
```

What `start()` does:

1. Generates `K_b` with WebCrypto Ed25519, **non-extractable**. Where the
   browser lacks Ed25519 (Chrome < 137, Firefox < 130, Safari < 17) it
   fails with `Ed25519UnavailableError`; `isEd25519Available()` lets you
   hide the option up front. `allowInMemoryFallback: true` opts into a
   JavaScript key held in memory only, with weaker custody
   (`sessionKey.custody === "memory"`).
2. Signs and sends `auth/oob/request`, then builds the trigger link. The
   link is ASCII only and at most 251 bytes (VTI-LNK-080, 081), and a link
   host on the page's own domain is refused (VTI-LNK-084).
3. Renders an SVG QR code at level M, with a quiet zone of at least 4
   modules and at least 4 px per module, dark on light, wrapped in
   `<a href>` with the same link (VTI-LNK-086), so a wallet on the same
   device can be opened by a tap or click.
4. Long-polls `auth/oob/redeem`, one poll at a time, with a freshly signed
   document each time. Every fetch has a timeout.

When the tab becomes hidden, the code is removed but polling continues: on a
phone, tapping the code opens the wallet and hides the tab, and that sign-in
must still finish. A new code needs another `start()`.

After sign-in, `signIn.signDocument(type, payload)` signs member trust tasks
with `K_b`. By default `K_b` lives for the page; pass
`keyStore: new IndexedDbStarterKeyStore()` to keep it across reloads, and
`restoreSessionKey()` to pick it up again.

The page that shows the code must be served with `Referrer-Policy:
no-referrer`, `Cache-Control: no-store` and CSP `frame-ancestors 'none'`, and
load no third-party scripts (VTI-LNK-082).

Lower-level pieces are exported too: `buildTriggerLink`, `renderQrSvg`,
`renderTriggerLinkHtml`, `createTriggerLinkElement` and `generateStarterKey`.

### On the server (`@openvtc/rp-sdk`)

For a site that is itself the sign-in service. `OobSignInService` is a
reference implementation of the request state machine (`pending → claimed →
identified → approved → consumed`, with `declined`, `cancelled` and `expired`
final), with every change a compare-and-set in a store you provide.

```ts
import {
  OobSignInService,
  MemoryOobRequestStore,     // replace with your database for more than one process
  DidKeyDocumentResolver,
  buildSessionCookie,
} from "@openvtc/rp-sdk";

const service = new OobSignInService({
  serviceDid: SERVICE_DID,
  serviceName: "Example Community",
  origin: "https://members.example.org",     // the SignInPortal origin
  store: new MemoryOobRequestStore(),
  resolver: new DidKeyDocumentResolver(myDidResolver), // member DID documents, cached
  responseSigner: serviceAssertionKey,       // { verificationMethod, sign(bytes) }
  isActiveMember: (did) => acl.isActiveMember(did),
  displayName: (did) => directory.nameOf(did),
});

app.post("/v1/trust-tasks", async (req, res) => {
  const out = await service.handle(req.body, {
    ip: req.ip,                       // only for sameNetwork; never returned
    location: geoip.cityCountry(req.ip), // local lookup, or omit
    browser, os,                      // from the User-Agent
    signal: abortOnClientClose(req),
  });
  res.set("Cache-Control", "no-store");
  if (out.session) {
    const cookie = buildSessionCookie({ value: await mintSession(out.session) });
    res.cookie(cookie.name, cookie.value, { ...cookie.options, sameSite: "lax" });
  }
  res.status(out.status).json(out.body);
});
```

Accept `auth/oob/request` only from your portal's origin, with no CORS.

If you run your own state machine, use the verifiers directly. Each throws
`OobVerificationError` with a typed `reason`:

| Function | Checks |
| --- | --- |
| `verifyOobClaim(doc, { serviceDid })` | Ed25519 `did:key` issuer (`K_a`), proof, `recipient`, freshness, and `parentThreadId === payload.requestId` (VTI-LNK-054) |
| `verifyOobIdentify(doc, { serviceDid, resolver, requestId, approverKey })` | proof against a key under **`authentication`** (contract C5), exact payload, request and lock |
| `verifyOobGrant(doc, { serviceDid, resolver, requestId, identifiedDid, approverKey, sessionKey, origin, contextDigest })` | issuer is the identified DID, proof against **`assertionMethod`**, lock, browser key, origin and context digest |
| `verifyDidKeyDocument(doc, type, { serviceDid })` | any document from `K_a` or `K_b` (`request`, `prove`, `respond`, `redeem`, `cancel`) |
| `computeContextDigest(signedStep2)` | SHA-256 of the JCS form of the signed step 2 response, proof included |

The verifiers do not track document ids: record each returned `id` and
refuse it if you have seen it before. Check the `identify` issuer against
your ACL **before** calling `verifyOobIdentify`, so a non-member costs no
DID resolution.

The wire types are local for now (`// TODO: replace with generated
trust-tasks types`) until `dtgwg-trust-tasks-tf` publishes the `auth/oob/*`
bindings.

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
  audience: RP_DID,   // recommended: binds the response to your RP DID
  maxAgeSecs: 300,    // optional: also bound how old issuedAt may be
  resolver: new KeyResolver(),
});
// decision.decision ∈ {"approved","denied"}; retain the document for audit.
```

`verifyConfirmResponse` verifies the `eddsa-jcs-2022` proof and enforces
`subject === issuer === signer` and the challenge echo (compared in
constant time, like the SIOPv2 nonce). Pass `audience`:
when you do, the document's `recipient` must be present and equal to it, so
the response is cryptographically bound to your RP and cannot be re-presented
to another one. A document whose `expiresAt` has passed is rejected with
reason `expired`, and `maxAgeSecs` bounds how far its `issuedAt` may lie
behind now (pass `now` to supply the clock yourself). It does **not** do
the stateful checks the SDK can't
see — locating the pending request by challenge, consuming it single-use,
and persisting the decision — those stay your responsibility. Failures
surface as `ConfirmVerificationError` with a typed `reason`.

The DIDComm transport (authcrypt pack/unpack, mediator forwarding) is not
included; this module operates on the decrypted Trust-Task document.

## Legacy: SIOPv2 `id_token` (deprecated)

> **Deprecated.** `verifyIdToken` and `establishSession` still work and are
> not being removed yet; a removal date will be announced. New sites should
> offer wallet sign-in with a trigger link first, and keep this path behind
> an "Using an older wallet?" link.

### What it does

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

### Why this exists

The browser-plugin demo skips verification — it trusts whatever
the wallet POSTs. The demo is widely copy-pasted into production
code, inheriting the gap. The May 2026 OpenVTC security review
flagged this as a high-severity issue (H2). This SDK is the fix.

### Usage

#### Verify an id_token

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

#### Establish a session cookie

```ts
import { establishSession } from "@openvtc/rp-sdk";

const accessToken = await myJwtMinter.mint({ sub: verified.subject });
const { subject, cookie } = establishSession(verified, accessToken);

res.cookie(cookie.name, cookie.value, cookie.options);
// SDK sets HttpOnly + Secure + SameSite=Strict by default.
```

### DID resolvers

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

## Roadmap

Planned for follow-up minor versions:

- `requireStepUp()` middleware — gates routes behind `acr=aal2`.
- `refreshProxy()` middleware — drop-in `/auth/refresh` proxy.
- Express + Fastify + Hono framework adapters.
- DIDComm-transport packing/unpacking helpers, so the confirm verifier
  above can be driven straight from an authcrypted mediator message.

## License

Apache-2.0
