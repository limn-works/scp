---
name: adr057-browser-client-review
description: ADR-057 (in-browser SCP client over shared scp-mls, keys on-device) alignment review @694fc2ce7 — ALIGNED, 0 blocking, 1 material
metadata:
  type: project
---

# ADR-057 In-Browser Client Review @ `694fc2ce7` (2026-06-30) — ALIGNED

Branch `docs/adr057-browser-client`. Diff = new `.docs/adrs/ADR-057-in-browser-client-over-shared-mls.md` (82 lines) + 1-line "Amended by" marker on ADR-055 in `phase-4.md:1472`.

**Decision:** browser SCP clients run protocol in-tab over a shared `scp-mls` crate (lift the ~9 sync MLS files out of scp-runtime, compile native+wasm32), keys on-device, server never sees plaintext/keys. AMENDS (not supersedes) ADR-055 — bridge-removal stands, only ADR-055's "browser = remote thin client, no in-browser execution" conclusion is revised. Feasibility proven by wasm32 `cargo check` exit-0 on lifted MLS machine + participant-path audit.

**Verdict ALIGNED. 0 blocking.**

**MATERIAL finding (the one real fix):** ADR-057 is structurally a constrained form of ADR-055's REJECTED alternative #3 ("in-browser engine via single-threaded actor runtime", phase-4.md:1512 on main — rejected because relay-retrieval/timer/saga-coordination surfaces "not available in-browser ⟹ partial re-implementation"). ADR-057's scope-fence + cold-presence ARE the answer to that objection (participates, doesn't coordinate; coordinator surfaces fenced out not re-implemented) but it never NAMES alt #3 → reads as a direct contradiction to anyone who internalized ADR-055. Fix = one sentence in §Context/§Alternatives reconciling with alt #3.

**Minor:**
- `phase-4.md:1472` marker garbled/self-referential: reads "**Amended by:** ADR-055 §browser-deployment is revised by ADR-057" → parses as ADR-055 amends itself. Should be "**Amended by:** ADR-057 (revises §browser-deployment)...".
- Driver-orchestration residual parity: shared `scp-mls` kills crypto re-impl, but the browser DRIVER's sequencing (create/join/send/receive, event-log leaf emission) is browser-only code with no native twin that must still agree with scp-runtime on observable §9.9.3 output — a smaller bounded version of the parity surface ADR-055 killed. ADR should name it + say what checks agreement.
- Scope-fence is prose-only; suggest mechanical enforcement (driver crate forbidden from depending on scp-runtime actor/saga/economy modules — dependency-direction invariant, not denylist) so "won't regrow to old bridge size" is enforceable-by-construction.
- 5-vs-9 file count: §Context says ~3,057 lines / 5 files (hot path); §Decision says 9-file liftable unit. Not contradictory but reader trips; clarify 3,057 = hot-path subset.

**What's STRONG (don't re-litigate):** amend-vs-supersede drawn correctly (the two ADR-055 decisions are logically separable); tenet argument sound (custodial thin-client violates encryption-as-access-control/relays-untrusted/human-accountability, on-device preserves them); custodial kept as opt-in secondary = correct; claims well-bounded (cargo check = type-check only, NOT a running client — ADR says exactly that); liveness honestly isolated as the ONE non-passive cost, explicitly NOT custody, always-on-delegate deferred as open crypto question (heartbeat=MLS app msg ⟹ delegate can generally also decrypt). Status "Accepted, impl staged" defensible (feasibility was the only doubt; slices forward-only, no native behavior change) — leans on the participant-path AUDIT more than the compile.

GOTCHA: line numbers shift between worktree (has ADR-057) and main; rejected-alt #3 is phase-4.md:1512 on main. Marker typo is at phase-4.md:1472.
