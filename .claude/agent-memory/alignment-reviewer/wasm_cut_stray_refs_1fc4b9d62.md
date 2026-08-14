---
name: wasm-cut-stray-refs-1fc4b9d62
description: ALIGNED review of chore/cut-wasm-stray-refs (tip 1fc4b9d62, 6 commits) — tail-end ADR-055 WASM-bridge-removal reference scrub
metadata:
  type: project
---

Branch `chore/cut-wasm-stray-refs` (tip `1fc4b9d62`, 6 commits) reviewed 2026-06-29 — VERDICT ALIGNED, 0 blockers, 0 material findings, 3 observations.

**What it is:** tail-end cleanup of ADR-055 (phase-4.md:1468, supersedes ADR-034/022) — WASM FFI bridge removed; browser = remote thin client; 3 bridges remain (PyO3/UniFFI/napi-rs). ADR-055 itself is on main already; this branch is the downstream scrub of residual refs. 129 files +498/-1239.

**Verified clean:**
1. §9.9.3/§7.3.1/§9.8.2 convergence-invariant reframes all factually correct: "native↔WASM parity" → "every honest member"/"all honest members"/"§9.9.3 convergence". The security boundary (native↔native cross-member equivocation) preserved; only the WASM-second-producer framing removed. Checked consequence.rs, event-log lib.rs/payload.rs/system_actors.rs, governance_integration.rs, sender_keys, envelope/inner.
2. Artifact-flow respected — all spec/doc edits downstream of ADR-055, no phantom provenance. §25 Vector 32 "native↔WASM unification"→"typed-event unification" (taxonomy stands alone; 77 variants/tags 76-77 unchanged). §09 "ephemeral WASM bridge"→"ephemeral storage-less session" (generalizes correctly).
3. Dev-facing docs truthful: README/GETTING-STARTED/TS-README/quickstart/scaffolds all say TS=NAPI-only-server-in-process + browser=remote-thin-client; no "in-browser WASM backend" claim remains. CLAUDE.md worktree copy already updated (3 bridges).
4. Dangling-prose repair complete: custody_parse.rs + sender_keys oxford comma (commit 1fc4b9d62) + governance_integration message (folded into d0612a421). Scanned all reworded lines — no orphan and/but/both/Mirrors/empty-()/double-punct.
5. Dead-code deletions all WASM-only, zero surviving refs: `html_escape_json` (common/lib.rs), `PreRotationCustodyKind::WasmLocalRetention` (platform/traits.rs), CRYPTO_4020-4023. grep clean; scp-platform/scp-protocol/scp-ffi-common compile + clippy clean (all-targets).

**Enforcement-file delta (legit):** check-no-ts-mutable-globals.sh allowlist TRIMMED (removed _wasmModule/_initPromise/_wasmBridge/_bridge/_mcpAddon/_addon — all now-deleted globals). Removing exemptions STRENGTHENS the check; gate runs PASS (allowlisted=2 failed=0). bridge-symmetry fixtures drop wasm/wasm_required keys; run-tests.sh 6/6 pass. Prod bridge-aliases.json + check-bridge-symmetry.sh already 0 wasm refs.

**3 observations (non-blocking):**
- OBS-1 (scope, borderline): protocol-level `enforce_triggered` fn + `ConsequenceDispatcher` trait in scp-protocol/trust/consequence.rs now have ZERO non-test consumers (only impl was WASM bridge; sole remaining impl is `RecordingDispatcher` under #[cfg(test)]; native uses its OWN `enforce_triggered_consequences`/`RuntimeConsequenceDispatcher` in scp-runtime). Branch kept it as live public protocol API (reframed "an implementation that mints leaves...overrides it"). Cutting live pub API is itself a scope decision beyond "scrub refs" — correctly left for a separate change. This is arguably WASM-only-dead-code that survived, but defensible.
- OBS-2 (truthfulness gap, pre-existing): scaffolds/typescript-web/src/index.ts + templates/chat/typescript/src/index.ts now claim "remote thin client...drives server-side scp-node" but the code still calls Identity.create/Context.create IN-PROCESS — the remote-client transport doesn't exist yet (that's the ADR-055 impl work, not this scrub). No WORSE than before (previously claimed deleted WASM backend). Aspirational prose vs unimplemented architecture.
- OBS-3: .docs/specs/05-contexts.md:192 "Statically deployed (WASM, container)" tool implementation_hash row correctly LEFT ALONE — that's a 3rd-party tool-artifact-as-WASM concept, unrelated to the deleted FFI bridge.

**Legit-to-keep residuals confirmed:** scp-transport/scp-protocol wasm32 Cargo deps + README, scp-node application/wasm MIME + CORS, all .docs/audits|planning-sessions|prod-readiness|lessons|prds historical, agent-memory files.
