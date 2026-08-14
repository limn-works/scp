---
name: adr055-cut-wasm-slice1-ce31836c
description: ADR-055 WASM-bridge removal slice 1 (foundation) review @ ce31836c3 — GO-WITH-CHANGES (none blocking); deferred-cleanup enumeration
metadata:
  type: project
---

# ADR-055 Cut-WASM Slice 1 (foundation) @ `ce31836c3` — 2026-06-29

Branch `chore/cut-wasm-foundation`, worktree `cut-wasm-1`. Deletes `crates/scp-ffi/wasm` entirely; ADR-055 supersedes ADR-034; browser clients become remote thin clients to server-side scp-node. Verdict: **GO on the foundation slice** (sound + correctly scoped + build-coherent). 0 blocking. Deferred downstream doc cleanup is genuinely follow-up-slice work (inert-for-build), but two items are load-bearing-wrong and must be tracked.

**Why:** Alec is cutting the fourth FFI bridge. The convergence-tax (build every protocol feature twice, byte-identical for §9.9.3) + recurring security-divergence + structurally-unreachable parity (timers/sagas/recovery have no wasm analogue) justified removal at pre-release timing.
**How to apply:** When reviewing follow-up slices 2+, the cleanup targets below are the enumerated backlog. Do NOT let a cleanup slice gut the §9.9.3/§9.8.2/§7.3.1 NATIVE↔NATIVE convergence language (it is cross-member/relay equivocation, NOT wasm parity).

## ADR-055 content (phase-4.md:1468) — SOUND + COMPLETE
Captures all five rationale pillars: convergence tax, security divergence, structurally-unreachable convergence, can't-compile-runtime-to-wasm (tokio multi-thread + ADR-049 actor/supervisor), pre-release timing. Correct ADR format (Status/Context/Decision/Rationale/Alternatives/Consequences/Dependencies). 3 alternatives rejected soundly. ADR-034 (phase-4.md:1411) correctly marked "Superseded by ADR-055 (2026-06-29)" with retained-historical note. Consequences explicitly preserve native event-log unification on its own merits ("only its WASM-parity motivation is retired") — exactly right.

## Build coherence — CLEAN
Cargo.toml workspace: no wasm member. `crates/scp-ffi/wasm` tree count=0 at HEAD. bridge-aliases.json/ffi-export-allowlist.json wasm_required keys stripped. pipeline_wiring ratchet 50→41 (9 wasm assertions removed, legitimate deleted-target cleanup). check-sdk-coverage.py never read a "wasm" matrix key.

## TWO load-bearing-wrong residuals (track for cleanup slice, NOT blocking this slice)
1. **§23.16.4 reference-implementation dangling pointer** — `.docs/specs/23-sync-and-offline-strategy.md:481` names the now-DELETED WASM `manager.rs` `wasm_export_snapshot_digest` as "The reference implementation" of the normative export-digest construction. Must re-point to a native artifact (native runtime export path). This is the §23 finding the task flagged — confirmed real.
2. **bridge-aliases.json:2482 stale `_note`** — prose describing WASM #active-signing alignment for "consumers verifying signatures cached from old WASM builds." Inert (JSON `_note`, not a gate key) but describes a deleted bridge. Remove.

## Deferred WASM-as-live-bridge references (inert-for-build, enumerated for follow-up slices)
- specs: 05:192, 09:1260, 10:988/1009, 11:384, 16:1606/1666, 17:417/428/541/546/897, 18:21, 20:69, 21 (multiple: 18/46/47/81/103/139/218/263/431), 23:481(load-bearing)/484/496/498, 25:363
- standards: rust.md, sdk-common.md, typescript.md, sdk-capability-matrix.json (notes at 90/98/254/372/425/439/469 + line 35/61/107 internal/wasm.ts mentions)
- scaffold: rust.md, shared.md, typescript.md
- prds: agent-binding.json, http-features.json, main.json, persistence.json, transport-expansion.json
- CLAUDE.md root: line 5 (bindings list says wasm-bindgen) — slice removed the WASM toolchain table row but left vision-prose. line 258 "compiles for wasm32" is scp-protocol (KEEP).

## §9.9.3 convergence guard — CONFIRMED native↔native, MUST stay intact
09-security-model.md:793 (relay showing different histories to different MEMBERS), :823/:827 (two honest MEMBERS comparing checkpoints), :732/:823 convergent-leaf-timestamp = committer-assigned `created_at` copied by every member (cross-member, §7.3.1/§9.8.2). This is equivocation detection, NOT wasm byte-parity. Follow-up cleanup must NOT touch it.

## #1877 closure carve-outs — CONFIRMED
- **#1877** (OPEN) IS the convergence-tax program (collapse native↔WASM `manager.rs` vs `governance_helpers.rs` behind shared trait). Premise dissolved by ADR-055 (no second impl). ADR-055 Consequences: "convergence program is closed won't-do." → CLOSE won't-do WITH the program.
- **#1925** (native bridges don't wire governance params), **#1845** (event-log cross-member convergence, §9.9.3 latent, native receiver-side), **#1923** (§6.2.0.1 supervisor governance feed) → STAY OPEN, native/remaining-bridge.
- **#1917** (`ucan_evaluate` presenting-agent param divergence) → STAY OPEN but RESCOPE to 3 bridges. Title says "WASM-parity" but body is a 4-bridge shape divergence; the PyO3/NAPI/UniFFI `aud`-tautology default survives wasm deletion (a "no silent security defaults" concern). Drop only the wasm arm.
