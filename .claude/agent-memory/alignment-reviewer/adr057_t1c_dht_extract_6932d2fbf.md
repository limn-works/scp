---
name: adr057-t1c-dht-extract-6932d2fbf
description: ADR-057 T1c review @6932d2fbf — extract scp-dht transport crate; code matches inventory exactly, but 4 untouched downstream artifacts stale (release.yml HIGH breaks publish)
metadata:
  type: project
---

# ADR-057 T1c — extract scp-dht transport crate @ `6932d2fbf` (base `c102f8222`) — NEEDS DISCUSSION, 1 HIGH + 2 MODERATE + 1 LOW

Branch feat/adr057-t1c-scp-dht, single commit 6932d2fbf, range c102f8222..HEAD (47 files +408/-188). Successor to the T1 dissolve-primitives reviews (47afa5c4f etc.).

**CODE SIDE = ALIGNED, matches T1c inventory EXACTLY (0 code findings).** New native leaf crate `scp-dht` (lib.rs): `DhtError` = exactly 3 variants (DhtPublishFailed/DhtResolveFailed/Bep44SignatureInvalid); `bep44_signable`+`verify_bep44_signature` moved in (params carry only bytes/seq/[u8;32]/[u8;64] — no identity types); `#![forbid(unsafe_code)]`; NO scp-* deps (one-way `scp-identity → scp-dht` edge, acyclic by construction). `dht_client/` (DhtClient trait, DhtRecord, InMemoryDhtClient, PkarrDhtClient behind production-dht) moved in. scp-identity: `From<scp_dht::DhtError> for IdentityError` message-preserving 1:1; lib.rs re-exports removed correctly (verify_bep44_signature dropped from dht:: block; whole `dht_client` module + its DhtClient/InMemoryDhtClient/Pkarr* re-exports deleted — NOT repointed = no shim); dht.rs delegates both bep44 helpers back to scp_dht (one-way). production-dht feature forwarded (`scp-dht/production-dht`). All 6 ADR-named bep44/dht consumers (scp-ffi/src/identity.rs, napi/src/identity.rs, uniffi/bridge.rs, common/resolvers.rs, napi/tools.rs, scp-node/self_host.rs) import `scp_dht::` directly. Gate `check-no-shim-reexports.sh` extended: closed set now `scp_clock scp_crypto scp_did scp_dht scp_mls`, owning_dir arm added — sanctioned expand-coverage edit. Root Cargo.toml adds member. Parser consolidation correctly deferred (extract_public_key stays split; matches "deferred to T1c-b").

**FINDINGS — all in downstream artifacts the diff did NOT touch (ADR/architecture/CLAUDE/release.yml all absent from diff):**

1. **HIGH — release.yml breaks the publish pipeline.** scp-dht has NO `publish=false` and version `0.1.0-beta.2` = publishable; published scp-identity now carries `scp-dht = { version="=0.1.0-beta.2" }` (registry-resolvable). But scp-dht is MISSING from: version-tags TAGS array (~line 167), the ordered publish steps (no `Publish scp-dht` step — must land before `Publish scp-identity` ~line 411, alongside leaf scp-did ~line 379), and the summary crate list (line 863). `cargo publish -p scp-identity` will FAIL (dep not on crates.io). SAME failure class the T1 review caught with scp-client-wasm publish=false — recurring "new publishable crate not added to release pipeline" pattern.

2. **MODERATE — ADR-057 not updated to record T1c landed.** This change set IS T1c but ADR unchanged. (a) slice-list intro line 83 still "T1 executed…T1c and T2 follow"; line 86 "T1c — DHT transport slice." lacks "(landed)" vs T1's line 85 "(landed in this change set)" precedent. (b) crate table line 110 still lists `dht_client/` as scp-identity-owned ("DHT client (dht.rs, dht_client/)") — dht_client/ MOVED to scp-dht = now inaccurate. (c) rejected-alt-5 transport bullet line 138 + line 112 describe extraction in future/"approved" tense — now landed. (d) ASCII dep graph line 119 folds DHT into scp-identity, shows no scp-dht node/edge. NUANCE: ADR frames parser consolidation AS PART OF T1c ("T1c resolves both before consolidating"); impl defers it to "T1c-b" (a sub-slice name NOT in the ADR) — so the correct edit is "transport extraction landed; consolidation (remaining T1c work) pending", not a blanket "T1c landed."

3. **MODERATE — architecture.md stale.** Crate map lines 275-283 + Layer ladder 670-688 enumerate scp-clock/crypto/did/identity but omit scp-dht. Line 706 "Completed extractions" still says scp-identity keeps DHT "as one crate (the DHT is not separable)" — transport WAS separated. Line 720 table cites `scp-core/src/identity/dht_client.rs` — doubly stale (scp-core wrong pre-T1c; file now in scp-dht).

4. **LOW — CLAUDE.md project map omits scp-dht.** Worktree CLAUDE.md lists scp-clock/crypto/did/mls/client/client-wasm but not scp-dht (new crate missing from map).

Verdict NEEDS DISCUSSION: code is mergeable and exactly to-spec, but the ADR (governing artifact) + architecture.md + release.yml must be updated in-changeset before PR — release.yml is a hard blocker (breaks publish), the rest are provenance/system-of-record staleness the "artifacts are system of record" tenet + T1 precedent require.
