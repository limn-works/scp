---
name: scp2185-mlscryptoprovider-rename
description: Completeness review of SCP #2185 mechanical rename MlsCryptoProvider -> NodeMlsFactory (verdict COMPLETE)
metadata:
  type: project
---

SCP #2185 (branch adr049-2185-rename-provider): pure NAME rename `MlsCryptoProvider` -> `NodeMlsFactory`. Follows #2148 (birth-into-actor) which dissolved the struct's per-context state, leaving it a node-level MLS-birth/HPKE helper. Verdict: COMPLETE.

**Why:** After #2148 the type no longer "provides" per-context crypto, so ADR-049 §6/§15 scheduled the rename as #2185.

**How to apply (verifying mechanical renames in this repo):**
- The struct file was NOT renamed (still `crates/scp-runtime/src/crypto/mls/provider.rs`). Enforcement `pipeline_wiring.rs` `PROVIDER_SRC = include_str!(".../provider.rs")` therefore stays valid — the rename only touched assert-MESSAGE strings, ban logic (`!PROVIDER_SRC.contains`) unchanged. Not a weakening.
- `check-deleted-primitives.sh` BAN_ENTRIES: only the description text after the last `|` changed; the actual `pattern|dir|glob` unchanged. Not a weakening.
- Legitimately-left `MlsCryptoProvider` refs are all historical/provenance: struct doc "Renamed from" note (provider.rs:464), ADR-049 §6/§15 (lines 171/389, accurate #2185 mapping), CHANGELOG (append-only), ratchet/block-in-place-count.json `_context`, PRD adr049-crypto-state-move.json (point-in-time PR-7 design narrative), and 7 agent-memory files (frozen records).
- Wiring verified: struct def, 2 impls, `::new`/`::with_backends`, `ActorDeps.crypto: Arc<NodeMlsFactory>`, FFI construction in src(PyO3)/uniffi/napi/common, `[\`NodeMlsFactory\`]` doc-links, bindings (swift 4 + ts test 1). WASM has zero refs (expected — ADR-034 no scp-core dep). No half-renamed hybrids; distinct `ContextCryptoProvider` trait untouched.

**Two non-blocking notes surfaced (neither introduced by this PR / neither blocks close):**
1. `sdk-capability-matrix.json` lines 1774/1788/1802 still say "MlsCryptoProvider impl at provider.rs:739" for rotate_sender_key/remove_member_sender_key/advance_epoch — those methods moved to the actor in #2148 and no longer exist on the struct, so the note was ALREADY stale pre-rename (wrong struct + wrong line + method gone). Pure-rename PR correctly leaves it; worth a future capability-matrix cleanup.
2. 4 doc-comment sites now read "an `NodeMlsFactory`" (article carryover from "an `MlsCryptoProvider`") — should be "a": uniffi/src/runtime.rs:831,879,924 and crypto/mls/provider.rs:538. Cosmetic only.
