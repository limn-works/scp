---
name: SCP-1717/SCP-1718 Alignment Review (2026-05-03)
description: WASM identity_rotate_key parity + pre-rotation chain validation across 4 bridges + PreRotationCustody trait — ALIGNED verdict
type: project
---

# SCP-1717 (WASM rotate_key) + SCP-1718 (pre-rotation chain validation) — ALIGNED (2026-05-03)

Branch `worktree-scp-1717-wasm-rotate-key`, 27 commits ahead, 9 commits behind origin/main. Reviewed at HEAD `f8a8b0967`.

## What landed
- **`PreRotationCustody` trait** (`crates/scp-platform/src/traits.rs:702-750`) with distinct `PreRotationKeyHandle` newtype (no `From`/`Into` to/from `KeyHandle` — type-level §9.7.4.1 §3 storage isolation).
- **`InMemoryPreRotationCustody`** in `crates/scp-platform/src/testing/pre_rotation_custody.rs` — `Zeroize + ZeroizeOnDrop` on entries, separate `Mutex<HashMap>` from operational `KeyCustody`.
- **WASM `identity_rotate_key`** (`crates/scp-ffi/wasm/src/identity.rs:2104`, inner at `:2113`) — active-only mutation via `with_local_record_mut`; `#0`/pre-rotation/agent state preserved.
- **`migrate_identity`** (`crates/scp-identity/src/dht.rs:1201`) — pre-flight CSPRNG-sourced `import_ed25519_signing_key` capability probe; chain-forward step ordering (publish NEW → destroy old `#active`/`#agent` best-effort → publish OLD with `alsoKnownAs`); old `#0` retained for Step 8 publish.
- **`verify_migration`** (`dht.rs:1794-1951`) — 7 invariants per ADR-003 §4c, returns `Result<bool, IdentityError>` (Ok(false) unreachable by design — see ADR-003 §4c text). Saturating `rotated_at` future-skew (5 min) and past-window (5 years) bounds gated BEFORE crypto.
- **`FileKeyCustody::import_ed25519_signing_key`** content dedup (`scp-platform/src/file.rs:857`) — holds `handle_map.lock()` across scan-and-insert; tests at `:1210`, `:1252`, `:1284`.
- **All 4 bridges** consume `dht::migrate_identity` (PyO3 `:1423`, NAPI `:856`, UniFFI `:12882`/`:12958`, WASM via `migrate_inner`); each bridge's test asserts `SHA-256(revealed_key) == commitment` end-to-end.
- **Reverse-direction parity** (`crates/scp-ffi/wasm/src/identity.rs:5511-5586`) — native serde JSON ↔ WASM `encode_rotation_event_json` bytes; structural-eq + canonical-sort-keys byte-eq + protocol-struct round-trip. `None` arm pinned at `:5594-5637`.
- **`scp-node` KNOWN LIMITATION** documented at `crates/scp-node/src/lib.rs:2859`, `:3030` — builder doesn't carry `P: PreRotationCustody`, drops handle, emits `tracing::warn!`. Out-of-scope per prompt.

## Lessons added
- `.docs/lessons/hash-commitment-preimage-lifetime.md` — generalizes commit-then-reveal lifetime requirement.
- `.docs/lessons/behavioral-invariant-must-be-asserted-on-every-bridge.md` — recommends adding "Item 6" to CLAUDE.md Integration checklist (NOT yet added — follow-up).

## Findings: 0 blocking, 0 material, 7 informational
- **MAX_PAST_WINDOW_SECS leap-day precision** — `5*365*24*3600`, ~1-2 leap days short of literal 5 years. ADR-003 §4c says "5 years" without finer spec, so this is consistent. Sub-user-perceptible.
- **Per-SDK idiom** — Python `rotation_event_json` (snake_case), TS/Swift `rotationEventJson`. Correct per `feedback_per_sdk_idiom.md`.
- **`Ok(false)` unreachable in `verify_migration`** — type signature carries a dead arm; tightening to `Result<(), IdentityError>` would break public API. ADR locks the contract.
- **WASM_MIGRATION_LINKS_CAP=100_000 vs WASM_IDENTITY_REGISTRY_CAP=10_000** — asymmetry justified by per-tab attacker model.
- **`encode_rotation_event_json` always emits `pre_rotation_proof: Some(...)`** — WASM contract documented; native `None` arm validated by deserialize round-trip.
- **CSPRNG probe in `migrate_identity` step 0** — uses OsRng to avoid content-addressed dedup collision; correct.
- **No `Arc<T: PreRotationCustody>` blanket impl** — bridges work around with `.as_ref()`. Storage has it; PreRotationCustody doesn't. Not blocking.

## Patterns reusable for future reviews
- When reviewing branches that span multiple FFI bridges, verify: (a) all bridges call the same Rust core function; (b) each bridge re-asserts cryptographic invariants in its own test (the lesson at `behavioral-invariant-must-be-asserted-on-every-bridge.md`); (c) reverse-direction wire-format parity is asserted (native→WASM round-trip AND byte-canonicalised compare).
- When the prompt enumerates IN-SCOPE and OUT-OF-SCOPE items, FIRST establish the merge base (`git merge-base origin/main HEAD`) — branch diff vs origin/main can show changes already merged on main since the branch diverged. This branch was 9 commits behind main; the apparent "out of scope" diffs (mcp allowlist, ADR-048 §7, etc.) were main-side merges, NOT branch-side scope creep.
- For `verify_migration`-style functions: the typed-all-or-nothing predicate convention (return `Result<bool, _>` where `Ok(false)` is unreachable) is fine if the ADR explicitly mandates it. Otherwise prefer `Result<(), _>` for clarity.
- Type-level isolation via newtypes (`PreRotationKeyHandle` ↔ `KeyHandle` with no conversions) is the project's preferred enforcement — strictly stronger than documentation-based isolation.
