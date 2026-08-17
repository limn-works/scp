# Black Hat Agent Memory

Index only — one line per entry. Detail lives in a linked topic file. Keep this
file under 140 lines; anything past line 200 is silently dropped when it loads.

Operating notes:
- A bash call resets cwd between invocations, so write every path absolute.
- Return absolute paths in a final response, plus a code snippet whenever exact
  text is load-bearing.
- No emojis. No colon before a tool call — write "Let me read the file." with a
  period.
- Memory records go stale. Verify a named file, function, or line before
  recommending action on it.

## Review findings by branch or feature

- [Revocation list across writer and reader](revocation-two-path-key-space.md) — `revocation_list_key` is injective, but the attestation cache is keyed on a bare id, so a free DID overwrites an honest issuer's cache slot; `trust_verify_attestation` reads the list and never writes it; whole-list load per verification
- [PR #2366 attestation fail-closed](pr2366-attestation-fail-closed.md) — six surviving fail-open inputs after issue #2335 findings 2/9/11/13; revocation-list poisoning via an unscoped attestation id; DID document rollback; declared-independence inflation
- [Crypto, economy, persona surfaces](surfaces-crypto-economy-persona.md) — PR #1606 sender-key AAD; consequence `WarningCount` weaponization; ADR-039 persona binding sound but every production resolver returns `None`; TS SDK seam tree-shaken; sdk-coverage gate accepts a type name as runtime proof
- [HTTP and transport surfaces](surfaces-http-and-transport.md) — PR #195 bridge-secret plaintext, blob existence oracle; commit 8873a54 `owner_id` collision, WASM `Send`/`Sync` unsoundness, cover-traffic budget oracle
- [PR #127 UCAN bridge surfaces](surfaces-pr127-ucan-bridges.md) — UCAN validation gaps, `context_close` auth bypass on three bridges, zero-signature token minting, nonce replay TOCTOU
- [PR #76 and spec 22 surfaces](surfaces-pr76-spec22.md) — `claim_shadow()` verifies no signature; `MultiLayerCorroborated` trust level trivially gameable; handle squatting free
- [FFI bridge audit](ffi-bridge-audit.md) — cross-bridge parity and validation gaps
- [PR #1628 BridgeInstance extraction](pr1628-bridge-instance.md) — BLACK-301 post-shutdown ghost ops, BLACK-303 placeholder DID confusion, BLACK-308 rate-limiter ephemeral bypass, BLACK-309 economy unbounded growth
- [PR #2141 R25 batch 3](pr2141-r25-batch3.md)
- [Refactor-plan adversarial analysis](refactor-plan-adversarial-analysis.md) — BLACK-301 through BLACK-311: facade divergence, phase B TOCTOU, asymmetric wiring, BridgeInstance split-brain; mitigations are a generation counter, atomic send-plus-receive wiring, a CI module and re-export check, a feature-flagged BridgeInstance
- Event-log substrate swap phase 2 (no topic file in this worktree) — RFC 6962 swap closed export forgery; equivocation detector false-positives under dormant cross-member replication; in-memory dedup wiped on respawn
- [Historical audits](historical-audits.md)

## Recurring attack patterns worth checking first

- **Caller-supplied key material used as verification material.** A bridge that
  verifies a caller's attestation against a caller's key answers `true` to
  whoever supplies both. Check every `verify_*(&caller_key)` signature.
- **An identifier used as a security key without issuer scoping.** A revocation
  list, a cache, or a dedup map keyed on a free-form id lets one party's record
  govern another party's record. Check what a `check_*` implementation discards.
- **A pure verifier with zero production callers.** A shipped verify function
  nobody calls is a false guarantee to any reader of a type signature. Grep for
  callers outside a test module before crediting a fix.
- **Metadata a subject declares about itself feeding a trust score.** Shared
  memberships, endorsements, freshness stamps, and verifier names inside a
  self-signed record raise a score and carry no independent signature.
- **Self-certifying DIDs make sybil identities free.** A resolver that extracts
  a public key from a DID string admits any freshly generated keypair at zero
  cost, so a count of distinct DIDs is not a count of distinct parties.
- **A boolean bridge return collapsing distinct verdicts.** Degraded, absent,
  forged, and rotated all become one `false`, and a caller cannot tell them
  apart.
- **A gate that iterates only over what already exists.** A call-invariant rule
  keyed on a caller name reports nothing when that caller is deleted, so it
  cannot detect a removal.
- **A test store whose key is finer than the production store's key.** A guard
  test that partitions on `(a, b, c)` while every shipped store partitions on
  `(a, b)` cannot observe the collision it claims to forbid. Compare the test
  double's key tuple against the production store's before crediting a scoping
  guarantee.
- **An alias list widened until a fail-closed stub satisfies a symmetry check.**
  Adding a declining stub's name to a canonical operation's alias list weakens
  that assertion rather than widening its coverage.
