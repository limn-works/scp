# A Signature Must Cover Whichever Header Selects Its Scope

**Date:** 2026-08-17
**Source:** review of `crates/scp-node/src/bridge_auth.rs` webhook verification, spec
`.docs/specs/12-platform-bridge-connectors.md` §12.10.2

## The bug

A platform sent three headers on every webhook request: `X-SCP-Signature`,
`X-SCP-Platform-Key-Id`, and `X-SCP-Timestamp`. A node looked up whichever key
`X-SCP-Platform-Key-Id` named, verified an Ed25519 signature over
`timestamp || body`, and then applied that event inside whichever bridge and context that key
was registered against.

`X-SCP-Platform-Key-Id` therefore decided scope, and no signature covered it. One platform
bridging into two SCP contexts registers one Ed25519 key twice, once per bridge, under two
identifiers. Whoever captured a request that platform signed for a first bridge changed one
header and replayed it into a second bridge's context, and verification passed, because one key
backed both identifiers and neither identifier entered a signed payload.

## Why a timestamp did not stop it

A timestamp defeats replay against a request's own destination: a node rejects a stale one.
It says nothing about which destination a request was signed for. Freshness and scope are two
different properties, and covering only freshness leaves scope forgeable.

## The criterion

**A signature must cover every input that decides which record, scope, or principal a verified
request acts on.** Apply it by listing what a verifier reads from a request, then, for each
item, asking: if an attacker changes this alone, does a different record get touched? Every
item answering yes belongs inside a signed preimage.

Indicators that suggest a violation, which are evidence rather than a test: a key-id or
tenant-id header outside a preimage; a preimage built from a body alone; a lookup keyed on
something a caller supplies before any signature check; one credential registered under two
identifiers.

## Two ways to satisfy it

1. **Fold that selector into a signed preimage.** SCP took this route:
   `key_id || 0x00 || timestamp || 0x00 || body`. A delimiter is safe here because the two
   segments preceding it are restricted to printable US-ASCII, so neither can carry `0x00` and
   a payload splits exactly one way. State that restriction as a rule the verifier enforces,
   not as an assumption about well-behaved callers.
2. **Derive that selector from something a signature already covers.** Sound only when a
   derivation is injective across every scope. Deriving a key id from a public key alone fails
   here, because two bridges sharing one platform key would collide on one identifier.

## Delimiter framing

Concatenating variable-length segments without a delimiter admits two parses: `key_id="a"`
with `timestamp="12"` and `key_id="a1"` with `timestamp="2"` produce identical bytes. Either
restrict each segment's alphabet and separate segments with a byte outside it, or length-prefix
each segment. Do not rely on a segment's expected shape.

## The same failure in an identifier derivation

Spec §12.2.1 step 3 derived a bridge id as `SHA-256(context_id || operator_did || platform ||
timestamp)`, with no separator between three variable-length strings. Context `ctx-a` with
operator `bc` and context `ctx-ab` with operator `c` produce identical bytes, so two
registrations derive one id — and a bridge id decides which context a request acts inside.
That is the same defect as an unframed signed payload, one layer over: a hash preimage and a
signature preimage both need each variable-length segment to be recoverable.

A test caught it because it asserted the property rather than the value: it derived two ids
from a shifted boundary and required them to differ. An assertion that only compared a derived
id against a fixed vector would have passed. When a function claims injectivity, test
injectivity.

The fix length-prefixes each segment with eight big-endian bytes. Commit `017e6c840` had
already fixed the same class in `derive_shadow_id`, which escapes `%` and `:` in each segment.
Two fixes for one class in one file is a signal to look for a third: check every composite
identifier a system builds.

## Where this generalizes

Any verifier that reads a caller-supplied identifier before checking a signature: webhook
receivers, multi-tenant callbacks, key-id-selected JWS/JWT verification (`kid` outside a
protected header), and any HMAC scheme whose secret is shared across tenants.
