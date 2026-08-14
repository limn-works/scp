---
name: pr2226-real-multi-relay-querier
description: PR #2226 ADR-062 slice11a RealMultiRelayQuerier defensive review — fail-closed sound, defense-in-depth real, log-noise finding
metadata:
  type: project
---

# PR #2226 feat/adr062-slice11a-real-multi-relay-querier (white-hat, 3rd pass, 2026-07-15)

RealMultiRelayQuerier<Q: RelayQuerier> in crates/scp-identity/src/relay_querier.rs. Production multi-relay DID composer.

**Why:** ADR-062 slice 11a real relay querier; 11b (InMemoryRelayQuerier demotion) is separate scope. Memory [[adr062-011-relay-blocker]] says 11a mergeable.

**Defenses SOUND:**
- Defense-in-depth REAL: composer selects highest-seq valid via verify_relay_record (BEP44 sig + UTF8/JSON + self-cert, resolution.rs:152 pub(crate)); resolver INDEPENDENTLY re-verifies the single winner via same shared verify_relay_record in validate_relay_result (resolver.rs:700) AND validate_dht_result (resolver.rs:751). Not just a claim — confirmed wired.
- Fail-closed: all relays empty/err/timeout/panic → best=None → Ok(None). Task-level: Ok(Err)→debug+empty Vec, Err(elapsed)→debug+empty Vec, JoinError(panic)→warn+continue (never aborts sweep). Verify fail→warn+skip candidate. Resolver Step5 high-water rollback reject (seq<cached_seq)→None. Stale-only-relay record rejected by resolver even though composer returns it.
- Timeout REAL cancel: tokio::time::timeout drops wrapped inner.query future on elapsed → in-flight op cancelled, not just marker (answers Q4).
- JoinSet cleanup: composer future owns local JoinSet; outer LAYER_TIMEOUT(10s) elapsed drops the query future → drops JoinSet → aborts all spawned tasks. No leak. PER_RELAY(5s)<LAYER(10s) so per-relay fires first, preserves `best`.
- Feature gate WATERTIGHT: config.rs InMemoryPreRotationCustody import + mint arm both #[cfg(feature="testing")]; #[cfg(not(feature="testing"))] arm returns Err(NoPreRotationBackend)=SCP-IDENT-1059. Cargo.toml normal scp-platform edge = software_platform only (NOT testing); testing feature re-adds scp-platform/testing+scp-dht/testing. Shipped build cannot mint the §17.17.2 nullifier. Fail-closed tests gated #[cfg(not(feature="testing"))].
- Shadow-defeat: bad-sig + stale-valid intra-relay AND cross-relay, tested (6 attack tests).

**FINDINGS (all non-blocking):**
- FINDING (log noise / cry-wolf): per-candidate verify failure logged at WARN with did+relay_url (relay_querier.rs ~line "relay candidate failed verification"). Honest relays with co-located junk/stale frames (the design's NORMAL case) emit WARN per candidate per resolve → up to 16*N WARN/resolve. Floods logs + desensitizes ops to WARN. FIX: per-candidate→debug, single aggregated WARN only if ALL candidates at a relay failed (relay served only junk = actually-suspicious). Also a log-amplification vector (attacker-controlled relay/DID).
- INFO: composer take(16) caps Ed25519 CPU but Vec already fully materialized from task before trim → memory bounding delegated to transport RelayQuerier impl (trait doc says impl MUST bound). Layering seam: composer DoS protection complete only if transport honors contract.
- INFO: no cap on NUMBER of relays fanned out. relay_urls from cached_relay_urls (from resolved doc) or bootstrap. Attacker-owned DID doc listing many relay URLs → large JoinSet on resolve of that DID (self-inflicted, self-cert bounds to owner). Consider MAX_RELAYS_PER_RESOLVE hardening.
- PASS: relay-timeout logged debug (acceptable — single relay timeout expected in fan-out, not the security signal); bad-sig is warn (correct security signal).
