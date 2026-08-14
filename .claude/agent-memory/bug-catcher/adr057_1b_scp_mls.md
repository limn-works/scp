---
name: adr057-1b-scp-mls
description: ADR-057 Slice 1b scp-mls crate extraction review — CLEAN, behavior-preserving on native; Clock conversion + tie-break verified correct
metadata:
  type: project
---

# ADR-057 Slice 1b — scp-mls crate extraction (branch feat/adr057-1b-scp-mls @ d8fc5d937)

Reviewed delta `git diff feat/adr057-1a...feat/adr057-1b-scp-mls`. VERDICT: CLEAN, behavior-preserving on native. Build/clippy(-D warnings)/wasm32-check/2256 tests all green; scp-mls=103 tests.

**Why:** moved 9 sync MLS files scp-runtime/src/crypto/mls → crates/scp-mls (wasm32-safe), runtime mls/mod.rs became re-export shim.

**How to apply:** reference template for "behavior-preserving crate extraction" reviews.

Key verifications:
- **epoch_grace Clock conversion (Instant→wall-clock u64 millis):** deadlines stored absolute `now_millis()+30000`. Tie-break `min_by_key((deadline, epoch))` — lowest epoch on equal deadline. CORRECT: MLS epochs are monotonically increasing (add_epoch(old_epoch) from g.epoch()), so lowest epoch = added-earliest, preserving "oldest=added-earliest" eviction the prior strictly-increasing-Instant gave for free. Tie-break applied identically in BOTH eviction paths (add_epoch line 276, restore_from_entries line 445). Non-tie case sorts by deadline = identical to original. to_grace_entries now uses absolute deadline/1000 (vs original now_unix+remaining.as_secs) — both correct absolute-expiry reps, round-trips through restore (*1000) to sec granularity. Wall-clock-backwards (NTP) extends grace window slightly — benign, bounded by MAX_GRACE_EPOCHS=100 capacity eviction; documented design intent (wasm32 has no monotonic clock).
- **Public seams from_parts/signer_key_pair/pub EagerDropSigner:** exact 1:1 replacements for prior same-crate pub(crate) field access. from_parts always sets group:Some+destroyed:false (matches only prior restore construction). signer_key_pair returns &SignatureKeyPair = prior .signer.as_ref(). No broader key exposure (in-process snapshot path only, used at provider.rs:2184 restore + ops.rs signing). No invariant break.
- **Re-export shim:** pure `pub use scp_mls::{...}` — identical TypeId, no coherence break. InMemoryMlsProvider single def (scp_mls = OpenMlsRustCrypto). DidDocument/SigningKeyId/decode_multibase_key imported from canonical crates (scp_protocol/scp_primitives) = same types scp_identity re-exports. No type split.
- **wrapping_extension test carve-out:** original 13 = 9 sync (scp-mls) + 4 async/runtime-dep (runtime file). All 13 bodies byte-identical (whitespace-normalized). Zero lost. Attributes preserved (2 #[test]+2 #[tokio::test] in runtime file).
- Production code of all 7 moved files: ONLY super::→crate:: path rewrites + credential.rs import-source change (1a DID move) + visibility widenings. No logic change.
