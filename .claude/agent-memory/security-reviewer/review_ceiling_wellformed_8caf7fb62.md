# PR #1884 ceiling well-formedness construction invariant (8caf7fb62) — APPROVED, ZERO findings

branch fix/ceiling-wellformed-custom-enforcement; fix commit c4660606f..8caf7fb62.
Closes prior MEDIUM (ModifyCeiling bypass) + BLACK cluster (BLACK-002 WASM ModifyCeiling no-validation; BLACK-003 raw-string-vs-parsed-enum divergence).

## What landed
- `ContextRoleState::set_ceiling` made FALLIBLE: `validate_entries()?` BEFORE `self.ceiling = ceiling` → validate-before-store, prior ceiling unchanged on Err (fail-closed, no partial write). Result is std must_use → compiler blocks silent drop (not separately #[must_use]).
- Grammar validator `validate_ceiling_entry`/`validate_as_ceiling_entry` (spec §5.3.1.1): exactly-one-colon custom, kebab `[a-z0-9-]`, explicit `:*` wildcard only, no stray `*`, len cap 256, control/whitespace/HTML-char reject. NO silent widening (old `name→name:*` removed; no-colon Custom defensive fallback = `name:name` concrete, never `name:*`).

## Ceiling-write surface (ALL validate now)
1. ContextRoleState::new (prior fix) 2. set_ceiling (this) 3. import (lifecycle_helpers.rs:1781 validate_entries → ImportRejected, AFTER sig+scope, BEFORE build PerContextState) 4. restore (lifecycle_helpers.rs:2391 → PersistenceFailed) 5. execute_modify_ceiling (governance_helpers.rs:1556 validate per-cap BEFORE staging pending) 6. apply_pending_ceiling_modification (governance_helpers.rs:489 set_ceiling().map_err()?; pending NOT cleared on Err — `=None` after the `?`) 7. all 4 bridges ModifyCeiling via validate_governance_action_strings (common/validate.rs:740, validate_as_ceiling_entry = parsed enum) + create-path per-bridge.

## BLACK-003 (canonical parse) — SOUND
Runtime enforces PARSED form (Capability::new(raw) → ucan_capability_name). Bridges now validate `Capability::new(entry).validate_as_ceiling_entry()` NOT raw string. Capability::new strips `custom:` prefix → `"custom:payments"` (1 colon, passes raw check) parses to Custom("payments") (no-colon, enforced=payments:payments) → REJECTED by parsed-enum. Both `payments` and `custom:payments` spellings caught. 4 bridges: PyO3 src/runtime.rs:1520+, NAPI napi/runtime.rs:1515+, UniFFI uniffi/runtime.rs:1000+ (create-path FILTERS/skips — narrowing-safe, pre-existing), WASM wasm/manager.rs:1448+ (create) & dispatch_modify_ceiling (governance).

## native==WASM — SOUND
WASM ModifyCeiling was the divergence (rebuilt ceiling_strings w/ NO validation). Now dispatch_modify_ceiling validates per-cap BEFORE require_active_context_mut+policy → reject leaves prior unchanged. Stored form capability_to_ucan_format(c.name()) == native ucan_capability_name for tested entries (test asserts set-equality). 

## Verified
cargo test scp-protocol set_ceiling (2 ok), scp-ffi-common modify_ceiling (2 ok), scp-runtime ceiling (26 ok incl import_rejects_malformed), restore_rejects_malformed (--features testing, ok), scp-ffi-wasm modify_ceiling (3 ok incl native-parity). clippy scp-protocol+scp-ffi-common --all-targets clean. Error msgs leak only caller-supplied entry text + grammar reason — no secrets/paths.

## OBS (non-blocking)
- WASM dispatch_modify_ceiling validates grammar BEFORE active/policy check; native execute_modify_ceiling does require_active FIRST then grammar. Ordering differs (WASM=Validation err on inactive ctx, native=InvalidState); both reject malformed, both leave state unchanged. Not security-relevant.
- WASM propose-path maps grammar err to CTX_2040; dispatch_modify_ceiling to VALID_7000 (different layers, both reject). Consistent w/ defense-in-depth.
- supervisor.rs set_ceiling callers (13941/15434/15488) all test-only (.expect on built-in).
