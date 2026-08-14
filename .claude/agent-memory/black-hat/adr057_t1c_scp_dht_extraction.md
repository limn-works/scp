---
name: adr057-t1c-scp-dht-extraction
description: ADR-057 T1c DHT extraction to scp-dht crate @6932d2fbf — BEP44 move byte-identical/sound; 2 findings (release.yml missing publish step HIGH, template break MEDIUM)
metadata:
  type: project
---

# ADR-057 T1c: scp-dht crate extraction @6932d2fbf (base c102f8222)

Branch feat/adr057-t1c-scp-dht-extraction. Moved dht_client/ + BEP44 helpers (bep44_signable, verify_bep44_signature) from scp-identity into new native leaf crate scp-dht (no scp-* deps). New DhtError channel mapped to IdentityError via total message-preserving From impl.

## CLEAN (could not break)
- verify_bep44_signature crypto BYTE-IDENTICAL: VerifyingKey::from_bytes → Signature::from_bytes → bep44_signable (format `3:seqi<seq>e1:v<len>:<value>` identical) → verify_strict (preserved — rejects malleability/small-order). pkarr_client.rs diff = pure IdentityError→DhtError rename, nothing else.
- Gateway attacker path (pkarr_client.rs:181): still verifies sig BEFORE trust, `continue` on invalid = fail-closed. Negative-seq i64→0 coercion creates NO forgery (attacker lacks owner sig over seq=0).
- From<DhtError> for IdentityError: total match all 3 variants, message-preserved, no swallow. `?` paths + resolution.rs match-Err-continue both fail-closed.
- Shim gate (check-no-shim-reexports.sh): scp_dht correctly added to closed set + owning_dir. Plant-test: `pub use scp_dht::X` in scp-identity WOULD be caught. Gate runs green.
- Feature surface: production-dht forwards scp-identity→scp-dht/production-dht; mainline+reqwest MOVED not duplicated; no new default-on. napi/runtime/testing/ffi-common get scp-dht WITHOUT production-dht (InMemory+verify only, no mainline). Correct.
- Wasm fence INTACT: scp-dht (pulls tokio) unreachable from scp-protocol/scp-mls/scp-client/scp-client-wasm (cargo tree = 0 occurrences each).
- All in-workspace consumers repointed (straggler grep clean); scp-dht+scp-identity compile with production-dht.

## FINDINGS (@6932d2fbf) — BOTH FIXED @427a6c3f8
- HIGH (release.yml): scp-dht publishable but no Publish step → FIXED. Fix commit added Publish scp-dht step (slot 4, after scp-did before scp-platform/identity/runtime/node), TAGS entry, dry-run summary. All 3 lists now IDENTICAL 17 crates. Re-verified topologically sound against every manifest's scp-* deps (scp-dht is a leaf, no scp-* deps; consumers identity#8/runtime#11/node#16 all later).
- MEDIUM (templates/personal-relay PkarrDhtClient E0432): FIXED. main.rs repointed `scp_dht::PkarrDhtClient` + Cargo.toml adds scp-dht{production-dht}. scaffolds/rust-client also repointed `scp_dht::InMemoryDhtClient` + dep. Straggler grep = 0 across repo. scaffolds/relay + templates/cross-context-bridge use scp-dht transitively only (no source repoint needed; cross-context-bridge cached build confirms it compiles).

## RE-ATTACK @427a6c3f8 (fix commit) — CLEAN, no exploitable findings
- release.yml: 17 = exactly the 17 default-publish crates (client-wasm/ffi/testing are publish=false, correctly excluded). Topo sort valid. No new supply-chain window (--allow-dirty + sleep-60 is pre-existing T1 pattern). Version pins `=0.1.0-beta.2` consistent workspace-wide.
- Gate: scp_dht added to closed set + owning_dir. Plant-tested: foreign `pub use scp_dht::X` in scp-identity CAUGHT; self re-export in crates/scp-dht/src/ ALLOWED. Owning-dir exemption exact. Gate green.
- BEP44 @HEAD: verify_strict + preimage `3:seqi<seq>e1:v<len>:<value>` byte-stable. Fix deleted the pub `DidDht::bep44_signable` passthrough and inlined `scp_dht::bep44_signable` at the signing caller (dht.rs:857) + test (dht.rs:3168) — byte-identical, NO production path altered. verify passthrough (dht.rs:815) KEPT. Attacker gateway path (pkarr_client.rs:182) verify-then-continue fail-closed intact.
- Feature surface: `cargo check -p scp-dht` (default) AND `--features production-dht` both compile offline. pkarr_client fully `#[cfg(feature="production-dht")]`; z_base_32/tracing (now optional) referenced ONLY inside gated file. No build with pkarr-code-without-deps or vice versa. Forward chain intact: node(#23)/uniffi(#51) enable scp-dht/production-dht directly; scp-identity production-dht = scp-dht/production-dht.
- scripts/.github semantic diff: ci.yml + docs.yml path filters ADD crates/scp-dht (widen, not weaken); release.yml adds publish step; gate widened. Nothing weakened.
- INFORMATIONAL only: personal-relay template STILL won't compile due to PRE-EXISTING `scp_node::ApplicationNodeBuilder` E0432 (present at base c102f8222; node moved to NodeConfig construction) — unrelated to DHT extraction, standalone/not-in-CI. Repoint fixed the DHT break it owned; sibling break is separate scope.
