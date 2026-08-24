---
name: scp241-dual-layer-resolution
description: SCP-241 (DidResolver dual-layer resolution) verdict — 4/15 criteria met; the shipped resolver is the pre-amendment cross-layer highest-seq design, and every type-level criterion rests on a BootstrapCore type that does not exist
metadata:
  type: project
---

SCP-241 in `.docs/prds/reachability.json` reads `pending`, and that is correct: 4 of 15
acceptance criteria are met against `crates/scp-identity/src/resolver.rs`.

**Why:** the two-encoding amendment (§3.10.4 step 5, §3.10.7, §3.10.10 of
`.docs/specs/03-identity.md`; §18.2.2A/C/D of `.docs/specs/18-addressability-and-deployment.md`)
rewrote the story's criteria. The shipped code still implements the design the amendment
deleted — cross-layer highest-seq-wins — so the flip to `pending` records a real regression
against the artifact rather than a bookkeeping change.

**How to apply:** when auditing this file again, five findings are load-bearing and each one
poisons several criteria at once:
- `ResolvedDidDocument` is a `struct` (resolver.rs:69), not the `Full`/`BootstrapCore` enum
  §3.10.10 specifies. `grep -rn "BootstrapCore" crates/` returns nothing. This single gap
  makes criteria 2, 3, 10, 11, 12, 13, 15 unmeetable, so check it first.
- The seq high-water mark is one number per DID, not per (DID, layer):
  `DidCache.entries: Mutex<HashMap<String, CacheEntry>>` (cache.rs:97) and
  `cached_sequence(&self, did)` (cache.rs:254), applied to both layers from one
  `cached_seq` binding (resolver.rs:497).
- `pick_winner_and_detect_divergence` compares the layers directly
  (`relay_rec.resolved.seq.cmp(&dht_rec.resolved.seq)`, resolver.rs:562) and lets Mainline
  win on a higher number (resolver.rs:581), which §3.10.4 step 5c/5d forbid.
- Tests actively assert the forbidden behaviour: `both_respond_dht_has_higher_seq`
  (resolver.rs:1142) asserts `source == MainlineDht`, and `stale_seq_rejected_after_cache_expiry`
  (resolver.rs:1472) asserts BOTH layers are rejected off one cached seq.
- Two §3.10.4 clauses outside the numbered criteria are also unimplemented: the per-layer
  timeout is 10 s (`LAYER_TIMEOUT`, resolver.rs:219) where the spec says 5 s, and the
  2-second settle rule has no code — `tokio::join!` (resolver.rs:482) always awaits both.

What IS met: the `DidResolver` trait (resolver.rs:55), the `ResolutionSource` enum
(resolver.rs:84), `tokio::join!` parallelism (resolver.rs:482), and highest-seq-within-the-
relay-layer selection (`relay_querier.rs:238`, which is correct and stays correct under the
amendment).

Related: [[scp245-per-layer-healing]], [[did-two-encoding-amendment-2297]].
