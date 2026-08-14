---
name: adr054-prerotation-methodnames-205aedc69
description: PR #1873 docs/adr-053-pre-rotation-custody @205aedc69 — APPROVED; ADR renumbered 053→054, method-names table reconciled with real PreRotationCustody trait
metadata:
  type: project
---

PR #1873 (branch `docs/adr-053-pre-rotation-custody`, worktree `.claude/worktrees/pr-b-adr053`), docs-only ADR, HEAD `205aedc69`, Status: Proposed. APPROVED clean — prior reviewer finding fully resolved.

**Why:** A prior review flagged the ADR's canonical method-names table presenting `public_key`/`consume`/`import_seed_bytes` as the core trait's OWN names, contradicting the actual `PreRotationCustody` trait in `crates/scp-platform/src/traits.rs:745-793`.

**Resolution verified @205aedc69:**
- ADR renumbered 053→054 (ADR-053 = "Node Is Infrastructure" already in phase-2.md). Now standalone file `ADR-054-pre-rotation-custody-substrate-isolation.md`. (This resolves my earlier note that "ADR-053 PreRotationCustodyProvider" was a pending renumber.)
- Table added a "Core trait method (`PreRotationCustody`)" column. All four rows match traits.rs EXACTLY: `public_key`→`reveal_public_key` (771); `import_seed_bytes`→`store_committed_pre_rotation_key` (758); `consume`→`destroy_after_migration` (783); `generate`→*(new, no counterpart)*. Fourth trait fn `custody_kind` (792) noted as having no FFI-callback counterpart.
- Trait is NOT renamed; a `CallbackPreRotationCustody` adapter implements the core trait by dispatching to the foreign FFI provider. FFI consumer sees one consistent 4-method shape (agent-first identical-shape); core trait untouched.
- import-vs-store unambiguous (ADR §53): same core op, two names, "no second 'import' method added to the trait." FFI method takes only seed because adapter derives public_key from Ed25519 seed and forwards both args to `store_committed_pre_rotation_key` — matches real sig `(public_key:&[u8;32], private_key:Zeroizing<[u8;32]>)`.
- No stray reference asserts an old-style name as a trait method; Alternatives §113 discusses `KeyCustodyProvider` (different trait), no contradiction.

**Re-verified 2026-06-23 (2nd independent pass, same HEAD):** All FFI source-line citations in the ADR Context section confirmed LIVE: PyO3 `identity.rs:819-824` InMemoryPreRotationCustody::new() mint; UniFFI `bridge.rs:676` generate_ephemeral_ed25519_seed + ":689" "Substrate isolation is NOT yet satisfied" comment; UniFFI `bridge.rs:736-737` import_ed25519_signing_key Unsupported block with exact quoted error. Confirmed no `import_ed25519_seed_bytes` method exists on any custody trait (the gap is real). The two `generate*` fns in traits.rs (generate_keypair:332, generate_ephemeral_ed25519_seed:540) are on the OPERATIONAL KeyCustody trait, NOT PreRotationCustody — so `generate`-is-new claim holds. Single-use handle invariant (ADR line 51) is STRONGER than trait baseline: adapter invalidates handle in Rust after consume regardless of foreign success/failure, building on trait's post-destroy_after_migration HandleNotFound contract (782) + atomicity contract (700-706). Renumber justified (ADR-053 in phase-2.md), no ADR-054 collision.

**How to apply:** If re-reviewing this PR, the method-names reconciliation is settled — re-verify only if traits.rs changes. The pattern (FFI-canonical-name column + Core-trait-method column + explicit "not renamed / adapter dispatches" prose) is the correct template for any ADR that introduces an FFI callback surface over an existing core trait. Relates to [[cross-sdk-shape-parity]].
