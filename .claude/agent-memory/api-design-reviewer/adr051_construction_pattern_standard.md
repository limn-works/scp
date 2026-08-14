---
name: adr051-construction-pattern-standard
description: Review of construction.md + ADR-051 unified construction pattern (flat config objects, M1-M5, entry-verb rule) on branch docs/adr-051-construction-pattern
metadata:
  type: project
---

# ADR-051 / construction.md standard review (branch docs/adr-051-construction-pattern)

Standard defines ONE flat-config-object construction pattern across 5 entry points (Node/Relay/host_site/Context/Identity) × 5 languages. Entry-verb rule: `start`=spawns runtime (Node/Relay), `create`=value/handle (Identity/Context). host_site keeps verb-named free fn as sugar over Node::start. Rules M1 (enums not bools), M2 (security-critical choice required-or-fail-safe-default), M3 (required caps fail loud not silent no-op), M4 (no whole-struct Default if any field security-relevant/irreducible; use `Thing::defaults(req…)` factory + spread), M5 (one greppable constructor, no Builder/typestate; EncryptedStorage start/start_for_testing split is the ONE exception).

## Round 1 (earlier) — NEEDS REVISION, one High
- High: Relay had no declared M2 choice. **RESOLVED on current branch** — both construction.md §M2 and ADR-051 Decision now name BridgeRole (default Disabled) as Relay's security-critical choice.
- Secondary: IdentityConfig lacked generic bound. **RESOLVED** — target shape now `IdentityConfig<S>` with `persistence: Option<StorageSlot<S>>`, bound attaches on `Identity::create<S: EncryptedStorage>`.

## Round 2 (2026-06-14, current branch) — one Medium finding
**AC-9 honesty mismatch (Medium):** construction.md §M2 "Un-mechanizable carve-out" names exactly TWO human-review properties ("the two properties it cannot": M1-bool judgment + Template-data fail-safety). ADR-051 AC-9 names THREE: those two PLUS (c) M2 default-*direction* per entry point ("the check sees a default exists but cannot judge whether it is the safe one"). The enforced standard undercounts its own check's blind spots relative to the governing ADR. construction.md is the enforced source of truth, so it should carry the fuller list. Fix: extend construction.md's carve-out to include the M2 default-direction clause (two→three).

## Confirmed sound (current branch)
- M2 declared for all 5 entry points (Node/Site DHT, Site TLS, Identity persist, Relay BridgeRole, Context ContextCreation).
- Entry-verb rule, single `TlsMode` (Site reuses NodeConfig.tls), storage vocab triad (`Storage` trait / `StorageSlot` core selector w/ Rust-only `Custom(concrete)` / `StorageConfig` per-FFI mirror omitting Custom) all consistent.
- Identity persistence encrypted-only incl. `StorageSlot::Custom`; bound expressible as `IdentityConfig<S: EncryptedStorage>`. Sound across M2 bullet + EncryptedStorage § + AC-7.
- `BridgeRole::default()==Disabled` justifies RelayConfig keeping whole-struct `Default` under M4; consistent across M1 table / M4 / Relay § / AC-4 with counterfactual stated.
- Providers stay typed enum-selectors/concrete, never `dyn` (RPITIT not object-safe; ADR-049 hot-path). FFI Custom-omission intentional, precedented by StorageConfig + parse_custody asymmetry — not a gap.
