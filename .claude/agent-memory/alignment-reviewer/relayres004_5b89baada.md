---
name: relayres004-5b89baada
description: SCP-RELAYRES-004 relay WRITE path branch worktree-agent-ac667e2f552c34a31 @5b89baada — confirming pass; prior 4 findings all resolved, 7 new/residual artifact-flow findings (story prose vs code drift)
metadata:
  type: project
---

Branch `worktree-agent-ac667e2f552c34a31` @ `5b89baada`, 9 ahead / 2 behind `origin/main` (d1ebc5ab9), merge-base 51b59d426. Three-dot diff = 25 files, +4091/-349.

**Why:** double-zero confirming pass on SCP-RELAYRES-004 (relay WRITE path, issue #482, `.docs/prds/relay-did-resolution.json`).

**How to apply:** re-use this ledger on the next pass instead of re-deriving.

## Prior 4 findings — ALL RESOLVED (verified, not assumed)
1. §3.10.6 warning carved out → `grep disable_relay crates/scp-node/src/self_host.rs` = 0; `layer_disabled_warning` (self_host.rs:1483) is `tracing::warn!`, wired via `self_host_republish_config()` (1494); test `self_host_republish_config_wires_the_layer_disabled_warning` (4166).
2. Doc block citing §3.10.6 for its inverse → all 27 `§3.10.6` code citations now read correctly.
3. Retraction now in PRD (`details.retracted_claim` + amended description), not only rustdoc — but pattern RECURRED (see F1/F3).
4. One-shot lifecycle → latch deleted; `bound_relay_count` gone from all code; "evaluated ONCE"/"Provenance for the pending bind" blocks gone.
5. Broken intra-doc link → NO NEW ones. `cargo doc -p scp-node -p scp-transport -p scp-identity -p scp-ffi-common` shows only 2 unresolved links in touched files (self_host.rs:2268 `DualLayerResolver`, lib.rs:2713 `JoinHandle`) — both verbatim on origin/main, untouched.

## Residual findings (all prose/artifact-flow, zero code defects)
- **F1 story doesn't own the work**: 004 `files` lists 4 paths; diff touches 25. No AC covers live slots (`PublishedDidRecord`/`NodeDidDocument`/`NodeRelayUrl`), `DidPublisher` seam, tier-change routing, `DidMethod::publish`→`RepublishEntry`, `HealingPublisher::heal(&DidRecordV1)`, `RelayPublisher::publish(ttl,&DidRecordV1)`.
- **F2 phantom API**: `bound_relay_count()` appears 8× in PRD (004 desc/AC3/actionItem[3]; 006 desc/AC3/AC7; 007 AC4/AC6), 0× in code. `BoundRelays::len()` exists but is `pub(crate)`; no public accessor. 004 actionItem[3] was NOT done — latch deleted outright, arm always publishes + fails closed.
- **F3 004 desc says "each 6-day tick logs an honest 'no relay bound'"** — real behavior is 30s→30min backoff (`relay_republish_loop`, republish.rs:949-971) + `RelayPublishDegraded` after 6 failures. Honest text lives in self_host.rs:1441-1446 rustdoc only.
- **F4 008 description already falsified by this branch**: claims `DidDht::publish_document` returns `Result<(),_>` (now `Result<RepublishEntry,_>`, dht.rs:840) and that `self_did_republish_entry` read back off the DHT (function deleted; `dht_client.resolve` in self_host.rs = 0). 008 AC1 + actionItem 1 already met.
- **F5 self_host.rs:1406** (pre-existing, #1860): "loopback relay is a protocol-unaware blob pipe (§10.4), not a DID-document QUERY source" — §10.4 has ZERO "DID record"; its "Protocol-unaware" is about encrypted blobs. Node relay ships `DidRecordValidation::Enabled` by default (native/server.rs:211, propagated http.rs:1853). It IS a QUERY source per §3.10.2/§3.10.4. This false comment justifies `NoOpRelayQuerier` in `build_shared_cache_key_resolver` — which SCP-RELAYRES-006 exists to delete.
- **F6 self_host.rs:1841** inline comment "the relay arm once a relay is bound" contradicts the rustdoc it points at (1441 "Always enabled, including when no relay is bound yet") and test 3549-3554.
- **F7 §3.10.6 MUST is opt-in**: `disable_relay`/`disable_dht` (republish.rs:374-391) warn only if `with_layer_disabled_callback` was wired; `default()` has none (346) and the branch's own test `default_config_has_no_layer_disabled_callback` (1537) pins that. scp-identity already uses `tracing` (929) → unconditional `warn!` would make it mechanical. Note 008 AC6 will only pass with a callback wired.

## Verified-good
- PRD statuses match origin/main: 001/002/003 done (did_record.rs, native/relay_querier.rs, RealMultiRelayQuerier, relay/did_record_validation.rs all on main), 004 in-progress (relay_publisher.rs absent from main), 005-008 pending.
- `python3.12 scripts/validate-prd.py` → 18 files / 446 stories, exit 0.
- 004 AC1/AC2/AC3(behavior)/AC4/AC5 all satisfied by code+tests; 6-day interval = `derive_republish_interval(604800)` = 518400.
- Zero new `#NNNN` issue refs in code (only SCP-RELAYRES-003 ×1, -004 ×10).
- No new dev/test stand-in on a prod path. `TransportRelayPublisher` real + fail-closed. `NoOpRelayQuerier` pre-existing, classified honest-absent under ADR-062 §Decision 5 (resolution.rs:222-226).
- `DidRecordV1` frame + publish contract match §9.10.12 exactly (105-byte prefix, trailing-remainder value, routing_id derived from frame's own key).

Related: [[two-dot-diff-stale-base-trap]]
