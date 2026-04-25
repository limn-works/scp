---
name: Bridge canonical name should already exist in all 4 bridges
description: When registering a new entry in scripts/bridge-aliases.json, prefer canonical names that already appear in every bridge's source. If no shared name exists, file a source-side rename rather than picking arbitrary canonical and growing the alias set.
type: feedback
---

When adding entries to `scripts/bridge-aliases.json`, the canonical name should be one that already exists in all 4 bridges' source code. Aliases reconcile *minor* drift; they should not paper over fundamental naming-shape divergence.

**Why:** PyO3/UniFFI use bare-verb method names on a class (e.g. `governance_propose` on `Scp`/`SCP`). NAPI/WASM use noun-verb free functions (e.g. `context_governance_propose`) because they have no class to qualify. PR #1702 Batch 1 found 14 entries where the canonical name didn't exist in 1+ bridges. Treating the alias list as a workaround instead of a bridge means the matrix grows without resolving the divergence — Batch 2 has to do source-side renames anyway.

**How to apply:** Before adding a `bridge-aliases.json` entry, grep the 4 bridges (`crates/scp-ffi/src/`, `crates/scp-ffi/uniffi/src/`, `crates/scp-ffi/napi/src/`, `crates/scp-ffi/wasm/src/`) for the proposed canonical name. If it appears in fewer than 4, either pick a different canonical that does, or flag as Batch-2 source-rename territory. Sibling ops (block/unblock, mute/unmute) must share canonical stems — `broadcast_block` paired with `broadcast_unblock`, never `broadcast_unblock_subscriber`.
