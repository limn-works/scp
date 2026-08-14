---
name: standing-pair-not-a-saga-reframe
description: Crypto review of spec/standing-pair-not-a-saga-v2 (3a161e640) — §5.15.8 reframed from saga to single-context async creation
metadata:
  type: project
---

# §5.15.8 Standing-Pair = Single-Context Async (not a saga) — spec/standing-pair-not-a-saga-v2 @ 3a161e640

Docs-only. Reclassifies standing-pair creation: one MLS group / two members via create + add_member + Welcome, consent-on-Welcome-receipt. SETTLED (classification not relitigated). Crypto verdict: **SOUND** with findings.

## Verified against CODE (worktree was on chore/fuzz-pin-nightly — had to `git show 3a161e640:` the spec; do NOT read working tree)
- `derive_standing_context_digest` (standing_helpers.rs:56) = SHA-256("standing:" ‖ a ‖ ":" ‖ b), a/b lexicographically sorted by `.as_ref()` — BYTE-EXACT to spec preimage. Symmetric.
- `generate_standing_context_id` = "standing-" ‖ hex(digest).
- `context_id_bytes` (scp-protocol context/mod.rs:74) = SHA-256(utf8(string)). So provider DashMap key for a standing ctx = SHA-256("standing-" ‖ hex(derived_context_id)) — spec's load-bearing claim is LITERALLY CORRECT vs code.
- `create_mls_group` (provider.rs:735) DashMap `Entry::Vacant` atomic check-and-occupy on `[u8;32]` key → genuine isolation guard, no overwrite.
- Fused-join two-anchor (ADR-049:153): crypto-layer consumed-init-key set inside `MlsBackend::join_from_welcome`, keyed by HPKE init key (RFC 9420 §10), deny-by-default, fail-closed. This is the REAL single-use enforcement. Old saga "reserve-not-consume" was only a Prepare-time pool-drain courtesy → reframe loses NOTHING on single-use (init-key uniqueness always was the anchor). EQUIVALENT-OR-STRONGER.
- §9.6.1 confirmed: did:dht = z-base-32 of Ed25519 pubkey, no `:` in method-specific id.

## KEY CONTEXT: the length-prefixed backstop is GONE
- PRIOR saga framing (PR #1793) had a SEPARATE injective anchor: group_id = SHA-256("scp-standing-group-v1:" ‖ len32(did_lo)‖did_lo‖len32(did_hi)‖did_hi). My earlier review's soundness argument RESTED on "isolation keys off group_id (length-prefixed), not the context-id string."
- That group_id was removed in spec/standing-group-id-redundant (predates this PR). NOW the ONLY isolation anchor derives from the NON-injective colon-join. The length-prefixed safety net no longer exists. This reframe inherits that posture; it doesn't re-introduce the weakness but the load is now fully on the colon-join.

## The 4 questions
1. **Colon-join injectivity / dropping §9.5.1 len-prefix** — SOUND but defense-in-depth regression, honestly disclosed. CRITICAL SUBTLETY (finding LOW-1): full DID strings CONTAIN colons (did:dht:z6Mk...). Preimage is literally `standing:did:dht:zABC:did:dht:zDEF` — MANY colons. The real injectivity property is NOT "DIDs lack colons" (false) but "the DID grammar is self-delimiting so did_lo‖':'‖did_hi is uniquely re-parseable into the pair" (the method-specific-id portion is `:`-free + fixed-alphabet). Spec's "no attacker-placeable raw `:`" phrasing is correct-in-spirit but imprecise about WHERE. Fix: one len-prefix line (free, retires the human method-admission gate). Not a vuln for did:dht/did:web.
2. **Authenticity-from-MLS (no CreationReceipt sig)** — SOUND, nothing lost. The old CreationReceipt was NEVER signed (prior review confirmed: authenticity always from MLS Welcome + InnerEnvelope Ed25519). Removing it removes a journal/display artifact, not a credential. B's Welcome processing binds B into A's MLS group (RFC 9420 key schedule); first app msg carries InnerEnvelope Ed25519 sender sig. Standalone receipt sig would be redundant divergent surface.
3. **Symmetric-determinism / canonicalization** — SOUND. Canonical DID form BEFORE sort (did:dht z-base-32 lowercase canonical-by-construction; did:web host-lowercase + %-encode). Both feed byte-identical did_lo/did_hi. Matches code (`.as_ref()` bytewise sort). No collision/canonicalization gap for the 2 admitted methods.
4. **Existence-oracle / timing-constant** — SOUND as a spec obligation. Value-indistinguishability + constant-time-wrt-existence both stated normatively. Pure impl obligation; flag for impl-PR enforcement. consent-on-Welcome-receipt is STRICTLY BETTER than old synchronous Prepare-B Rejected (no 1-bit block/existence leak to initiator; blocked peer just never joins = indistinguishable from offline).

## Findings
- LOW-1: colon-join injectivity prose imprecise (DIDs DO contain colons; property is self-delimiting grammar not colon-absence) + dropping len-prefix is a defense-in-depth regression. Fix: add len32 framing OR tighten prose to "self-delimiting DID grammar." Same as prior LOW-1, now more load-bearing since group_id backstop gone.
- LOW-2: spec doesn't invoke MLS's OWN independent group isolation as a backstop. Even if two DID-pairs collided on derived_context_id, the OpenMLS group has its own internal GroupId + distinct key schedule + member credentials; a colliding pair would still need valid Welcome/credentials to actually read. The DashMap guard is the FIRST barrier but not the ONLY one. Spec over-states the colon-join as sole isolation; mentioning MLS-layer defense-in-depth would be more accurate (and reassuring).
- NIT: "Known limitation (Phase 2E)" — Welcome-joined replica can't SEND until spawn-from-Welcome entrypoint. Honestly disclosed; not a crypto defect.

VERDICT: CRYPTO-SOUND. No CRITICAL/HIGH/MED. Reframe loses no crypto guarantee (single-use, authenticity, determinism all preserved/stronger). Residual = colon-join is now sole isolation anchor (len-prefix backstop gone) — disclosed, fail-loud gated, safe for did:dht/did:web.
