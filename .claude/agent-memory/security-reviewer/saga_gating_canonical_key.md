# Saga gating (ADR-049 §3a) — canonical-key bypass

Branch `feat/actor-2c-saga-gating`, supervisor.rs `saga_participant_context_set`.

## The bug (HIGH, design-level, not yet live)
The per-participant-context-set saga reservation keys context-ids INCONSISTENTLY
across saga types:
- `StandingPairCreate` reserves `generate_standing_context_id` =
  `"standing-" + hex(SHA256("standing:"||did_lo||":"||did_hi))` (PREFIXED string).
- `CrossContextToolInvocation` / `BroadcastHostingHandshake` reserve
  `hex::encode([u8;32])` where the `[u8;32]` is the RAW digest (per NORMATIVE
  spec §5.14.13 05-contexts.md:1640 and §6.2.4: these wire fields are ALWAYS the
  raw 32-byte `derived_context_id` digest, NOT the `"standing-"`-prefixed form).

So a standing context is reserved as `"standing-"+hex(D)` by a standing saga but
as `hex(D)` (un-prefixed) by a broadcast/cross-context saga naming that same
standing context. `"standing-"+hex(D) != hex(D)` → NO COLLISION → the two sagas
run concurrently when the spec (§5.15.4:1772, anti-griefing §5.15.8:1824,
aggregate-cap §5.14.13:1693) REQUIRES them to serialize. Breaks the
"same context MUST collide" gating property = DoS-prevention bypass.

`generate_standing_context_id` (standing_helpers.rs:46) and the spec derivation
(05-contexts.md:1804) hash the IDENTICAL preimage, so the raw digest D is the
same — only the prefix differs. Fix: canonicalize the gating key (e.g. reserve
the raw digest hex for ALL saga types, or strip/normalize the standing prefix
in `saga_participant_context_set`). Actor-registry keying by original string is
SEPARATE and fine — the gating key just needs to be self-consistent.

## Why it slipped through
Test `overlap_is_set_membership_across_saga_types`
(tests/actor_saga_concurrent.rs:202) is MISLABELED: doc says
"standing-pair saga and a cross-context saga that touch the SAME context
serialize" but the body holds a standing_pair and starts ANOTHER standing_pair
(swapped DID order). It never feeds a standing ctx id into a cross_context saga.
A faithful test would FAIL and expose the bypass.

## Clean aspects (verified)
- Mutex critical section purely sync, never held across await; clippy allow is
  justified. Drop + try_reserve both `unwrap_or_else(PoisonError::into_inner)` →
  no poison-DoS.
- HashSet self-dedup (`seen.insert` filter) prevents caller==target degenerate
  self-conflict. Correct.
- NeedsRepair releases reservation via RAII Drop on the return path. Correct.
- Within EACH saga family keys are canonical/consistent (all raw-hex, or all
  standing-string) — only the cross-family standing-vs-raw case mismatches.
- CI gate check-saga-gating-granularity.sh enforces GRANULARITY (presence of
  per-set store + extractor + overlap-reject; absence of instance-wide scalar
  guard) but does NOT verify key CANONICALITY — broken-but-present gating passes.
- Production variants all return NotImplemented today (Phase 2C unwired), so the
  bypass is not LIVE yet; it becomes exploitable when dispatch is wired.
