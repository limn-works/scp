# Quote an external standard; never attribute a claim to it in a parenthetical

## What happened

`.docs/specs/18-addressability-and-deployment.md` §18.2.2A said: "The canonical serialization is JSON (per did:dht spec)." The did:dht method specification says the opposite. Its BEP44 payload is a bencoded DNS packet compressed per RFC 1035 §4.1.4, and the method states that it "does not make use of JSON-LD."

That clause was the only place in the corpus that authorized a JSON payload on the Mainline layer. `DidDht::publish_document` serialized the document with `serde_json::to_string_pretty` and published those bytes as the BEP44 value. Mainline rejected every publish with BEP44 error 205, the `mainline` crate reported the rejection as a timeout, and the republish loop retried the same bytes every thirty minutes. Eight issues were filed against the symptoms (#310, #489, #627, #284, #1266, #1518, #2151, #482) and each was closed by wiring one more piece.

The issue that finally named the cause, #2297, mis-cited the same method specification twice more: it said did:dht "requires a gzipped DNS packet" (the method names RFC 1035 §4.1.4 compression and never mentions gzip) and that the method "requires 52" characters in the DID suffix (the method states a transformation, `Z-BASE-32(raw-public-key-bytes)`, and no length at all).

Three mis-citations of one external standard, in three artifacts, over months. Nobody read the standard because each artifact carried a citation that looked like somebody already had.

## The rule

When a clause depends on an external standard, quote the standard's own words in the clause, and give the section that carries them. A parenthetical attribution — "per X", "as X requires", "conformant to X" — asserts that somebody checked, and it goes on asserting that after the check turns out never to have happened.

A quote fails loudly. A reader who opens the source and finds different words has caught the error. A reader who opens the source and finds a parenthetical has nothing to compare.

## How to apply it

- Writing a clause that cites an external specification: paste the sentence you are relying on, in quotation marks, with its section heading. Keep it short; one sentence is usually enough.
- Reviewing a clause that carries a bare attribution: treat the attribution as unverified until you read the source, whatever the artifact's status. `Decided` and `Accepted` record that the authors settled a question, not that they checked a citation.
- Writing the rule the standard implies rather than the words the standard uses: say which words you converted, because the conversion is where the error enters. The did:dht suffix length is the worked case — 52 characters is what the method's transformation yields for a 32-byte key, and writing "the method requires 52" turned a derived consequence into a false quotation. That matters here, because `z` is a legitimate z-base-32 data character, so SCP's 53-character suffix passes the method's character class and fails only the transformation.

## Where this rule is now applied

`.docs/specs/18-addressability-and-deployment.md` §18.2.2C carries the did:dht compression, `@context`, TTL, sequence-number and record-layout requirements as quotations with their section names. §18.2.2A's `publicKeyMultibase` row quotes "Data Integrity EdDSA Cryptosuites v1.0" §A.1.1 for the `0xed01` multicodec header. §18.2.2D quotes BEP44's own wording for the 1,000-byte bound, which turns out to bound "the bencoded form of v" rather than the packet — a distinction the attribution form had hidden.
