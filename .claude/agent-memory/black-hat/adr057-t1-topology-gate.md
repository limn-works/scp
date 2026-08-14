---
name: adr057-t1-topology-gate
description: Adversarial review of ADR-057 T1 crate-topology refactor (dissolve scp-primitives; extract scp-did) + check-no-shim-reexports.sh gate
metadata:
  type: project
---

# ADR-057 T1 topology refactor + shim gate (branch refactor/dissolve-primitives-split-identity, HEAD 81ef76c56)

Reviewed range 86519aa6f..81ef76c56, 2026-07-02. Verdict: CLEAN mechanical refactor; only LOW/MEDIUM defense-in-depth residuals.

**Why:** scp-primitives dissolved into scp-clock/scp-crypto/scp-did (wasm-safe leaves); scp-mls/scp-client/scp-client-wasm added; new gate `scripts/check-no-shim-reexports.sh`.

**How to apply — residuals to re-probe if this area changes:**
- Shim gate (`check-no-shim-reexports.sh`) matches COMMENTED/doc lines too — `grep -rEn "pub[[:space:]]+use..."` has no comment filter. A `/// pub use scp_clock::X` or `//! pub use scp_mls::*` in any non-owning/non-facade crate = false VIOLATION → CI fail. Verified by simulation. LOW.
- Banned-dep gate `check-protocol-deps.sh` scans ONLY `cargo tree -p scp-protocol`. The 7 OTHER wasm-safe crates (scp-did/crypto/clock/event-log/mls/client/client-wasm) are guarded against native-coupled deps ONLY by the wasm32 compile fence. tokio/scp-runtime/scp-identity/scp-platform all fail wasm32 (scp-platform pulls tokio rt-multi-thread) → caught transitively. Residual: `std::time::SystemTime` compiles-but-misbehaves on wasm32 and NOTHING mechanically bans it in the new wasm-safe crates (Clock privatization only covers scp-protocol). Pre-existing accepted limitation, now wider surface. LOW.
- wasm-protocol CI job compiles `-p scp-clock -p scp-crypto -p scp-did -p scp-protocol -p scp-mls -p scp-client-wasm`. scp-client + scp-event-log covered only TRANSITIVELY (not explicit -p). Feature-unification could theoretically mask; explicit is safer. LOW.
- Templates/scaffolds (cross-context-bridge, rust-client, personal-relay) are standalone `[workspace]` + `publish=false` → INVISIBLE to CI (no workflow builds them). Their scp-did retarget is mechanically UNVERIFIED. Path deps unversioned but unify with scp-core's path dep (same in-repo crate) → no version skew, no supply-chain. LOW.

**What's SOUND (verified):**
- release.yml publish order topologically correct: clock,crypto,did,platform,event-log,protocol,identity,mls,client,client-wasm,runtime,core,... Every consumer after its deps. Tag enum + dry-run summary enum + publish steps ALL consistent.
- Shim gate: closed set {scp_clock,scp_crypto,scp_did,scp_mls}, scp-core facade + owning-crate exempt, cd-to-root, recursive `find crates -type d -name src` (catches nested scp-ffi members), `\b` prevents scp_clockwork/scp_did_thing FP, handles `::` prefix + multi-line `pub use X::{` (first line still matches). Registered in CLAUDE.md enforcement list.
- Shim gate wired as a STEP in already-required unconditional `protocol-deps` job (needs check-draft only, no paths-if) — no new required-check registration needed, cannot be silently skipped. Correct.
- No lingering scp-primitives refs in source/manifests (only docs/ADR/README/agent-memory — historical, correct). No dead workflow path filters.
- scp-did deps = ed25519-dalek + serde only, NO scp-crypto edge (matches ADR claim).
- fuzz retargeted scp-primitives→scp-clock+scp-did+scp-mls correctly.
