---
name: adr049-classm-floor-registry
description: ADR-049 §9 Class-M MLS epoch/replay floors stay supervisor-owned (Model A) not on-actor (Model B) — verdict SOUND, not sunk-cost
metadata:
  type: project
---

# ADR-049 §9 Class-M floor registry: supervisor-owned (Model A) vs on-actor (Model B)

Interrogated a doc edit (branch `docs/adr049-classm-floor-registry-reconcile`) that reaffirms
keeping per-sender MLS epoch high-water + `recv_sequence_tracker` replay floors in a
supervisor-owned store (reduced from the `MlsCryptoProvider.contexts` DashMap on dissolution),
rejecting moving them onto the per-context actor as Decision-1 ("actor owns state by move")
would suggest.

**Verdict: SOUND.** Not sunk-cost; survives on merit.

**Why Model A is forced (the trilemma):** crash-survival across a *panic* unwind for a
per-message-advancing floor has exactly two exits — (a) live outside the unwinding task =
supervisor-owned store (Model A), or (b) durable write per advance = per-message durability
(naive Model B, hits Decision-14 >15% regression on `deliver_incoming`). Every "third structure"
collapses: batching durability = Class C = the ≤50ms coalesce-window loss (spec §23.17.2 Inv-2
violation, re-admits rejected message); flush-on-unwind is unsound for panic (cleanup runs
mid-mutation); mirror-to-supervisor IS Model A + redundant copy.

**Decisive fact the edit under-sells:** the floor's authoritative live copy ALREADY lives in the
supervisor `Arc` today (`provider.rs` `contexts[ctx].recv_sequence_tracker` + `sender_key_store`
epoch high-water), written in-memory (cheap) by actor `seal`/`open`. Model A = leave it there,
move everything else onto the actor. Burden of proof correctly on Model B; Model B fails it.

**Verified in code:** `provider.rs:2107` inserts recv_sequence_tracker per received message (floor
advances per-message → confirms hot-path). `provider.rs:1771` runs freshness check BEFORE
`nonce_dedup.is_replayed` → confirms nonce_dedup's Class-C reclassification rests on an
independent freshness bound (and it's the low-freq sender-key-request path). Warm-respawn path
`restore_crypto_state_with_floor_guard` (lifecycle_helpers.rs:1728) matches the edit's claim.

**Coherence:** the supervisor-owned exception is NOT a crack. §9 line 221 already documents the
category (per-context state that must survive unwind is homed in a supervisor Arc: journal-backed
Class-S KeyPackage state at line 188, Class-M floors at 221). Refactor never claimed to kill all
supervisor-owned mutable state (Decision 2 keeps registry/ArcSwaps); goal was killing the
per-context dispatch RwLock — floor registry is lock-free DashMap, no dispatch lock reintroduced.

**Two non-blocking QUESTIONs:** (1) Model C (derive floors from durable event log) IS dominated
(per-sender seq floor not in coarse event log → derivation incomplete or as costly as Model B) but
its rejection is NOT recorded in the ADR despite the ADR carrying "Rejected alternatives" elsewhere
(lines 112, 357) — record it. (2) nonce_dedup Class-C safety depends on freshness-window width vs
replay value — defer to cryptographer.
