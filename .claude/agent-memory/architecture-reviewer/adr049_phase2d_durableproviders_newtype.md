---
name: adr049-phase2d-durableproviders-newtype
description: ADR-049 Phase 2D DurableProviders newtype (type-enforced same-backend) + gate repoint @ a1fbe0df4 — APPROVED (1 stale-ADR-text nit)
metadata:
  type: project
---

ADR-049 Phase 2D continuation reviewed @ `a1fbe0df4` (worktree /private/tmp/scp-journal-swap). New structural change since `14f6af943`: `DurableProviders` newtype that TYPE-ENFORCES the saga-journal/mls_storage same-backend invariant. **APPROVED**, one non-blocking provenance nit.

**Why this superseded the combined-handle:** combined-handle (`durable_providers_from_handle`) derived both halves from one Arc but the bridge could still — in principle, via a mutated single constructor — pass divergent backends; a reviewer proved it bypassable at the construction site. The newtype closes it: `with_providers_and_journal` now takes ONLY `DurableProviders` (no separate journal arg), and the sole non-test constructor `DurableProviders::from_handle<S>(Arc<S>)` derives BOTH from one handle. Divergence is now impossible by construction — this IS the convergent end, not more machinery.

**Layering verdict — NO violation:** `OpenMlsStorageAdapter` + `SpawnBlockingStorageAdapter` already lived in scp-runtime (`crypto/mls/storage_adapter.rs`, since ADR-049 commit 4). Bridges already called `mls_storage_from_handle` (a scp-runtime wrapper) before this change. Moving journal derivation into scp-runtime added ZERO new bridge→runtime dependency — both halves were always scp-runtime types the bridge merely instantiated. `from_handle` is the right layer: it lives next to the supervisor it feeds; the same-backend property is a runtime invariant, not an FFI concern.

**4 prod seams (all verified routing through `from_handle` + `with_providers_and_journal`):**
- PyO3: `durable_providers_from_bi(bi)` (takes bi not Arc — StorageProvider Clone-enum; `from_handle(Arc::new(provider.clone()))`); preserves STORAGE_8000 fail-closed (`?`-propagated).
- NAPI + UniFFI: module-level `durable_providers_from_handle<S>(Arc<S>)` → `from_handle`.
- scp-node: `DurableProviders::from_handle(mls_inner)` directly.
- Renamed FROM `build_saga_journal`(PyO3)/`saga_journal_from_handle`(NAPI/UniFFI) — those names now DELETED, 0 source refs.

**Newtype API encapsulation (sound, no divergence reopened):** private fields; `from_handle` (only non-test ctor); `for_test(journal, mls)` `#[cfg(any(test,feature="testing"))]`; `with_noop_journal(mls)` `pub(crate)` (legacy `with_providers` test/example path — examples lack `testing` feature, hence pub(crate) not test-gated; carries NO durable journal so cannot cause silent recovery loss); `mls_storage()` accessor test-gated; `into_parts()` `pub(crate)` — ONE prod consumer (`with_providers_and_journal:1549`). No out-of-crate caller can split+re-pair halves. All `with_providers(` prod-adjacent callers are `#[cfg(test)]` (bridge_instance.rs 2877/4261 inside mod tests@2819) or examples.

**Gate repoint (a1fbe0df4) ACCURATE + STRICTLY STRONGER, not weakened:** every seam still asserts `with_providers_and_journal` routing AND now `DurableProviders::from_handle`; PyO3 additionally keeps `STORAGE_8000`. Positive presence-only defense-in-depth behind the type guarantee — correct posture, not over-engineering, not redundant re-check (it pins the wiring shape, the type pins the property).

**Seq-overflow fix (98cecb6d7):** read-path `is_canonical_seq` now `len==20 && all ascii_digit && parse::<u64>().is_ok()` — closes 20×`9` (>u64::MAX, sorts above zero-pad → shadow-key FSM-flip). Brings read to parity with write (`next_seq_for_saga`). Comment now HONEST: rejects malformed/non-canonical/out-of-range; does NOT defend canonical-in-range CRC-valid forgery (CRC=torn-write detector not MAC; per-entry key→value auth = separate concern). Resolves prior "SAME posture" imprecision nit.

**Spec/ADR:** §17.16.4 added normative (a) bounded-cost compaction (crash-safe: resolution durable BEFORE non-terminal removed) and (b) corrupt-entry + (c) NEW non-canonical-key-suffix skip-and-flag bullets — all match code. Prior metrics rustdoc nit RESOLVED (metrics.rs:4,38 now enumerate corrupt-skip as repair trigger).

**Verified @a1fbe0df4:** builds clean (5 crates); clippy clean (CI features); tests PASS — `durable_providers_from_handle_shares_one_backend`, `load_unresolved_rejects_twenty_digit_overflow_shadow_key`, `prod_supervisor_construction_wires_durable_saga_journal` gate, 5 `saga_bridge_journal_swap`.

**NON-BLOCKING nit (provenance):** ADR-049 line 63 still names `build_saga_journal`(PyO3) and `saga_journal_from_handle`(NAPI/UniFFI) as the journal-building helpers — both DELETED in this same range (0 source refs). Commit 2c2d9a127 ("fix stale bridge notes") updated the 3 per-crate CLAUDE.md but missed ADR line 63. ADR now cites non-existent functions. Fix: rename to `durable_providers_from_bi` / `durable_providers_from_handle`. Producer still dark (reply_saga_deferred NotImplemented, §6.2.4 deferred) — honest, unchanged.
