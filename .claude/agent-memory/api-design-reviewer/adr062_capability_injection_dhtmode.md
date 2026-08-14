---
name: adr062-capability-injection-dhtmode
description: ADR-062 draft review — capability-injection DhtMode init selector; NEEDS REVISION, 2 blockers on the "reuse existing DhtMode" claim
metadata:
  type: project
---

# ADR-062 (draft) capability-injection init-config surface review

Reviewed draft ADR-062 (Capability Injection and Application Profiles) proposed public API: required no-`Default` `DhtMode { Memory, Production { gateways } }` selector at the SDK-client bridge-init surface, identical across 4 bindings; `DhtMode::into_client() -> Result<FfiDhtClient, DhtInitError>`.

**Verdict: NEEDS REVISION.** Pattern (required no-Default flat enum selector, typed fail-loud error, identical-shape-across-bindings) is the correct generalization of §17.6 storage rule. Two BLOCKERs:

- **B1: "reuse existing DhtMode" is FALSE + self-contradictory.** Verified `origin/main:crates/scp-node/src/config.rs:210`: existing `DhtMode` is `#[derive(Debug,Clone,Copy,PartialEq,Eq,Default)]`, `Memory` is `#[default]`, `Production` is **fieldless**, lives in **scp-node** (gated behind scp-ffi-common `server` feature, Cargo.toml:30/42). ADR wants it no-`Default` — a type can't derive Default AND be no-Default. ADR conflates "enum has no Default" with "struct FIELD is required"; requiredness is a field-level property, get it by non-defaulted field not by the enum type.
- **B2: proposed shape is a breaking mutation of the shared node type, not reuse.** Adding `Production { gateways: Vec<String> }` breaks `Copy` (39 use-sites in config.rs rely on it: `matches!`, by-value), breaks fieldless-variant constructions (server.rs:314/426/465), and drags scp-node onto the bare client path (client selector needs base `resolvers` feature, node DhtMode only under `server`). Node `Production` = "publish my address" (no gateways); client `Production` = "resolve via these gateways" — genuinely different data. Fix: define client selector as its OWN type in scp-ffi-common; "single vocabulary" = naming consistency not type identity.

**MAJOR findings:**
- Naming: `Memory`/`Production` is node-surface vocab (deployment env), reads wrong at client resolver surface (axis = which transport). Brief's `DhtProfile { Mainline | Ephemeral }` is more discoverable/misuse-resistant (describes backend not environment). Caveat: `Ephemeral` under-signals loss of cross-process resolvability. Recommend transport-descriptive name; ADR recommends the WRONG option on "single-vocabulary" rationale which PRD will cargo-cult.
- `into_client -> Err(ProductionDhtNotCompiled)` for `#[cfg]`-compiled-out arm: variant is unconditional but backing arm is gated → type-checks a choice the binary can't honor. Acceptable ONLY because §3 makes production-dht unconditional on every shipped artifact → error structurally unreachable there (G1 enforces). ADR must STATE that invariant; also correctly can't `#[cfg]` the variant itself (would break identical-shape-across-bindings). Document the why.
- Required-field precedent needs an explicit authorability budget or Slices 2-4 each add "one more required field" → unauthorable wall (simplifier non-convergence). Proposed line: required iff omission nullifies security/correctness AND no fail-safe default exists; else default to fail-safe arm. Keeps DHT/credentials/custody required; NodeConfig.dht correctly stays defaulted (Memory=non-disclosing). Blob durability §3 vs Slice-3 lean opposite — reconcile.

**Sound (don't re-flag):** cross-binding idiomatic-but-identical surfacing is achievable (Py kwarg / TS discriminated union / Swift-Kotlin enum-with-associated-value); enforce identical VARIANT SET via §5 semantic-matrix. In-memory-DHT = legitimate-dev not nullifier (Q3) agreed. `into_client` stays pub(crate)/internal not on binding surface.
