---
name: adr053-pre-rotation-custody-pr1873
description: ADR-053 (PR #1873, docs-only, Proposed) review — separate PreRotationCustodyProvider FFI interface; sound design but FFI method names collide with existing core trait
metadata:
  type: project
---

PR #1873 `docs/adr-053-pre-rotation-custody` (commit 35c9b3d55): docs-only, adds `.docs/adrs/ADR-053-pre-rotation-custody-substrate-isolation.md` (115 lines, Status: Proposed). Closes the §9.7.4.1 §3 substrate-isolation gap on the FFI callback-custody path (today the bridge mints pre-rotation key into `InMemoryPreRotationCustody`, same process memory as operational keys).

**Verdict: NEEDS REVISION (minor, doc-internal — core design sound).**

**Design strengths (accept these):**
- Separate `PreRotationCustodyProvider` interface (NOT new methods on `KeyCustodyProvider`) makes §3 isolation a type-level guarantee, not a doc warning. Correct.
- Single-use handle invariant: adapter invalidates handle in Rust after `consume` regardless of foreign impl. Matches existing trait contract (destroy_after_migration doc already mandates HandleNotFound on reuse).
- `generate()` import-only-backend handling (typed error + from_mnemonic/from_backup alt path) is correct.
- Artifact-flow clean; spec citations verified verbatim (§9.7.4.1 §3/§4/§5 at 09-security-model.md:665/667/678; §9.12 :696). Open Q#3 correctly defers spec-clause-before-code.

**Key API finding — naming collision with existing core trait.** The proposed 4 FFI methods (`generate`/`public_key`/`import_seed_bytes`/`consume`) overlap an ALREADY-EXISTING core trait `PreRotationCustody` at `crates/scp-platform/src/traits.rs:745-793` whose methods are: `store_committed_pre_rotation_key`, `reveal_public_key`, `destroy_after_migration`, `custody_kind`. Only `generate` is genuinely new. `public_key`≈`reveal_public_key`, `consume`≈`destroy_after_migration`, `import_seed_bytes`≈`store_committed_pre_rotation_key` (seed-only vs pub+priv). The ADR's "canonical method names locked" table lists these as the "Rust trait" column as if they're the trait's names — contradicts on-disk trait. Fix: either rename core trait + extend table with final core column, or document adapter mapping as deliberate. Also undefine: does `import_seed_bytes` replace or coexist with `store_committed_pre_rotation_key`?

**Why this matters:** one-concept-two-names across FFI↔core defeats agent-first first-pass authorability (the measure: agent writes correct cross-layer code from the table alone).

Gap verified real: `InMemoryPreRotationCustody` minted at identity.rs:824/922/1052; UniFFI "Substrate isolation is NOT yet satisfied" comment + fail-closed import block at uniffi/bridge.rs:714-737.

Resolves prior memory note ("ADR-053 PreRotationCustodyProvider not in diff, renumber only" from [[sdk_coverage_failclosed_parity_341df72cc]]) — the ADR now exists as its own standalone file.
