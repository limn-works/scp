# Completionist Memory

Persistent notes for the completionist review agent. Each entry: what was reviewed, the
completeness/divergence findings, and lessons about where gaps hid (which layer, which
artifact diverged) so future passes trace faster.

## Audits
- [#1933 F3 authoritative event log](issue-1933-f3-authoritative-event-log.md) — @4e52864b2: core fix genuinely done (3 bridges → `Supervisor::authoritative_event_log`, `[0u8;32]` fabrications purged, absence shape restored to ADR-011), but INCOMPLETE: Kotlin SDK untouched (gitignored UniFFI bindings hide it — `eventLogVerify(): Boolean` IS the deleted `verified` flag), no cross-bridge parity test, PyO3 emits VALID_7001 while the branch's own sdk-common row claims 7000, CTX_2139 asserted nowhere, Python `_extract_root_hash` now always returns the 64-zero sentinel.
- [SCP-RELAYRES-004 relay WRITE path](scp-relayres-004-write-path.md) — @5b89baada: code COMPLETE (F1 latch/F2 §3.10.6 warning/F3 DHT read-back all genuinely fixed, all 7 ACs met), INCOMPLETE on artifacts: `bound_relay_count()` is a PHANTOM symbol (8× in PRD, 0× in code — deleted mid-branch after the story rewrite), 008 AC1/AC5 already satisfied by 004, CAPINJECT-011 pending-but-done. Lesson: when a branch rewrites its own PRD mid-flight, re-grep every story-named symbol against FINAL HEAD.
- [SCP-OUT-031 PR-2a runtime OutletErrorSurface](scp-out-031-pr2a-runtime-surface.md) — @dccc50c1b + round-2 @7eaebb81c: zero findings — COMPLETE (PR-2a scope). R1: all 15 InvocationError + 30+ legacy OutletError + SchemaValidationError mapped via wildcard-free to_surface; registry-consistent per-variant; no fabricated detail (BudgetExceeded→None). R2 fixed a REAL security leak R1 rationalized ("internal-only never FFI-facing" was FALSE for unary path) → new typed state-free ContextError::OutletContextNotActive; handled at every ContextError site; ExecutionPanic hashes outlet_id (oracle-resist); drift-guard+reverse-map+3 FFI state-free tests. Lesson: trace propagation to FFI, don't trust "internal-only" comments.
- [SCP-OUT-031 PR-1 fixtures/reconciliation](scp-out-031-pr1-fixtures.md) — @ed4bb5353 (rev of e44055576): zero findings — COMPLETE (PR-1 scope). InvalidGrant reclassified to Input/6120/input.invalid-grant/OutletInputError (all layers consistent); all 8 subclasses Outlet-prefixed; ALL_SLUGS added + registry-driven set-equality closes the earlier slug-drift gap. Env gotcha: stale scp-protocol rlib → false "ALL_SLUGS not found"; cargo clean -p scp-protocol before trusting new-symbol errors.
- [SCP-OUT-007 post-merge audit](scp-out-007-postmerge-audit.md) — scp-mcp lexical outlet↔tool translator @6344c1c67/PR#2249: COMPLETE, zero findings. No ADR-049/SCP-OUT-017 phantom cites; all 14 ACs met; canonical OutletKind=011, runtime gate=013/014.

- [#2069 §9.12 recovery UCAN revocation](issue-2069-recovery-ucan-revocation.md) — branch @46d18af7a INCOMPLETE: nullifier severed, capability absent; both gates still exact-CID; no two-gate regression test; whole orchestrator production-dead.

- [Repo-wide unfinished-work excavation @d1ebc5ab9](repo-wide-excavation-2026-08-08.md) — 2026-08-08 baseline: EncryptedStorage seal bypassed on shipped path (#838/#695 CLOSED but unfixed), revocation no-op returns Ok on 3 bridges, offline queue unwired, 106-op ratchet slack, 3 Proposed ADRs with merged code.

## Operating reminders
- Verdict is binary: COMPLETE or INCOMPLETE. No partial. An empty matrix cell, an unmet
  acceptance criterion, an unwired symbol, or a diverged artifact ⇒ INCOMPLETE.
- Trace top-down from the artifact (spec/ADR/PRD) through every layer: scp-protocol →
  scp-runtime → FFI bridges (PyO3/UniFFI/NAPI/WASM) → SDK wrappers → tests → capability matrix.
- Walk the `CLAUDE.md` Integration checklist for every new operation; build the
  requirement × layer matrix and fill every cell.
- Self-reports prove nothing — grep the real call site, read the real test body, check the
  real checkbox. Green CI only proves the tests that exist pass.
- One-way artifact flow: when code and an upstream artifact disagree, the artifact wins;
  the finding is "code diverged" (or "spec is wrong — fix spec first"), never "update spec
  to match code."
- Never weaken an enforcement file to close a gap (see the enforcement-file list in
  `CLAUDE.md`); the gap is real — fix the gap.
- [Phantom enforcement & stale admissions](phantom-enforcement-and-stale-admissions.md) — verify a gate BINDS (floor vs actual count, file exists, subjects reachable) and that every "not yet"/"test-only until" comment matches real callers.

## Reviews
- [ADR-062 E4 relay-publisher default sever](adr062_e4_relay_publisher_sever.md) — SCP-CAPINJECT-011 COMPLETE. Pattern for E1/E2/E3/E4 `= InMemoryX` default-type-param severs; keep fail-closed READ sibling (NoOpRelayQuerier) SHIPPED/UNGATED; G1 must pass.
- [reply-await-sweep-core @c33e7ee35](bounded-reply-await-sweep-core.md) — INCOMPLETE: shared `bounded_reply_await` helper + sweep; handle.rs/recovery.rs COMPLETE, but supervisor.rs missed 2 genuine reply-awaits (`reserve_outlet_economy_via_actor`:11850, `reserve_outlet_stream_economy_via_actor`:11898 — same dispatch_outlets_command wedge class, pre-existing on main). Lesson: enumerate ALL oneshot::channel sites, not the ones coder remembered.
- [#130 bounded reply-await hardening](bounded-reply-await-130.md) — INCOMPLETE (narrow): named `send`/`send_recover_on_failure` bounded correctly, but self-expanded supervisor/handle.rs sweep missed `dispatch_recovery_send_notification:324` (2 of 3 reply-awaits bounded). Lesson: grep file for ALL X when a sweep claims "all X in file Y".
- [PR #2235 §8.4 AppBound/AppUnbound event log](app_bound_unbound_event_log_pr2235.md) —
  wiring COMPLETE across 3 bridges + 4 SDKs + matrix + enforcement + runtime tests; INCOMPLETE only
  because ZERO behavioral tests at bridge/SDK layers. Prompt traps: Swift wrapper in Scp.swift not
  Context.swift; agent_binding_pipeline_tests.rs is unrelated ADR-039 collateral (bundling WARNING).
- [#2240 recovery invalid-tier 1021 + Option refactor](recovery_invalid_tier_1021_and_option_refactor.md) —
  CONFIRMED COMPLETE at fb76ac5b0. Tier code split 1020(ownership)→1021(tier) consistent across 3 bridges+tests
  +catalog+4 SDK docstrings+matrix note; execute_recovery bool→Option (27 callsites, is_some()-derived flag,
  +AllContextsFailed fail-closed). Deferred WIRE untouched, matrix booleans unchanged.
- [ADR-057 transport wasm-surface parity](adr057_transport_wasm_surface_parity.md) — every
  embedder-facing `pub fn` on `scp-client::ScpClient` must be mirrored on
  `scp-client-wasm::WasmScpClient`; `resubscribe_all` was not (inter-layer gap). Also: type
  renames (Socket→RelaySink) leave stray doc refs; native reciprocal-announce is a legit
  recorded follow-up.
