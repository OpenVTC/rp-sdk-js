// The `src` locator of a `did:scid` DID URL.
//
// A did:scid identity is the DID `did:scid:<format>:<version>:<scid>`. Its
// `src` query parameter (`did:scid:vh:1:<scid>?src=example.com/alice`) says
// where its verification metadata is published; it is not part of the
// identity (VTI-KEY-160), so two DID URLs that differ only in `src` name the
// same party. These mirror `affinidi_did_common::scid`: they touch nothing but
// a did:scid DID URL whose only query parameter is `src`.

/** Remove the `src` locator from a did:scid DID URL, keeping any fragment. */
export function stripScidSrc(didUrl: string): string {
  if (!didUrl.startsWith("did:scid:")) return didUrl;
  const q = didUrl.indexOf("?");
  if (q < 0) return didUrl;
  const hash = didUrl.indexOf("#", q);
  const query = hash < 0 ? didUrl.slice(q + 1) : didUrl.slice(q + 1, hash);
  const src = query.startsWith("src=") ? query.slice(4) : "";
  if (src.length === 0 || src.includes("&")) return didUrl;
  return didUrl.slice(0, q) + (hash < 0 ? "" : didUrl.slice(hash));
}

/** Whether two references name the same thing, ignoring a did:scid `src`. */
export function sameReference(a: string, b: string): boolean {
  return a === b || stripScidSrc(a) === stripScidSrc(b);
}
