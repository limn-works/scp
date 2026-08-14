---
name: repo-wide-excavation-2026-08-08
description: Repo-wide unfinished-work excavation at origin/main d1ebc5ab9 — every written admission of incompleteness, which are still true, which are stale, and the highest-severity unowned gaps
metadata:
  type: project
---

Full-repo excavation of every place the code and artifacts admit, in writing, that something
is unfinished. Baseline: `origin/main` @ `d1ebc5ab9` (2026-08-08). Verdict: INCOMPLETE.

**Why:** the orchestrator wanted the true scale of admitted-but-unfinished work, separated
from admissions that are already stale, so the backlog could be scoped against reality
rather than against comment text.

**How to apply:** treat this as a point-in-time snapshot — re-verify before acting on any
single item. The *classes* below recur; the individual line numbers rot fast.

## Highest-severity, UNOWNED (or falsely owned)

- **`EncryptedStorage` seal bypassed on a shipped path.** `crates/scp-ffi/common/src/server.rs:343,459,512`
  call `Node::start_for_testing` with NO cfg guard; `crates/scp-ffi/common/Cargo.toml:67` (in
  `[dependencies]`, not dev) unconditionally sets `features = ["allow_unencrypted_storage"]` on
  scp-node. The fn's own doc (`scp-node/src/config.rs:1209`) claims it "cannot be reached in a
  release build." **#838 and #695 are both CLOSED** — the defect was relocated from the PyO3
  bridge into ffi-common, not fixed. Worst ownership state: recorded as fixed.
- **UCAN revocation never propagates and returns Ok.** `BridgeRevocationDistributor`
  (`crates/scp-ffi/common/src/resolvers.rs:806`) is the ONLY non-test `RevocationDistributor`
  in the repo; wired ungated into `ucan_revoke` on all 3 bridges. #1550 owns the missing
  backend, NOT the always-succeeds return.
- **Offline outbound queue entirely unwired.** `store/queue.rs:160 enqueue_message` has zero
  non-test callers; `ffi-common/src/reconnect.rs:481` admits "the queue drain is presently a
  NO-OP end to end." No issue.
- **Outlet registration signatures never verified.** `verify_outlet_registration_signature`
  (`scp-protocol/src/context/outlets/registry.rs:564`) has zero production callers, while
  `ffi-common/src/context_params.rs:319-338` mints every bridge outlet with
  `operator_did: "did:key:placeholder"`, `implementation_hash: [0u8;32]`, `signature: vec![]`.
- **Supervisor reads the wrong persistence handle** (`supervisor.rs:1355` vs `helper_persistence`
  at `:2271`), and **`self.health_config` has ZERO reads repo-wide** (`supervisor.rs:1392`) —
  every saga/watchdog knob inert.

## Enforcement theater found

- `MIN_PARITY_OPERATIONS = 109` (`ffi_conformance.rs:1434`) vs **215 actual ops** in
  `scripts/bridge-aliases.json` ⇒ **106 slack**. The test is named
  `parity_operation_count_never_decreases` but tolerates deleting 106 operations.
- `bridge_ratchet_baseline.json` is in CLAUDE.md's protected enforcement list (line 125) but
  **does not exist on main** — gates nothing. See [[phantom-enforcement-and-stale-admissions]].
- `scripts/check-handle-affinity.sh` lists 6 PyO3 handle types in `HANDLE_SUFFIXES` but
  **cannot fire for any of them** — no function takes them as parameters.
- Three integration suites dark behind `#![cfg(any())]` (3,370 LOC / 130 fns:
  `network_simulation.rs`, `persistence.rs`, `outlet_economy_wiring.rs`), still registered as
  `[[test]]` targets so CI reports them green. Their stated blocker is CLEARED —
  `NodeMlsFactory::with_backends` exists at `crypto/mls/provider.rs:558`. Owned #1830 (P2).
- Two CLAUDE.md enforcement claims are FALSE: `validate-prd.py` is only in
  `prd-validate.yml.disabled`; ruff `FIX` is selected nowhere (`pyproject.toml:53` =
  `["E","F","W","I","UP","RUF"]`) ⇒ Python TODO/FIXME unenforced.

## Unsettled upstream

ADR-049 (actor-per-context), ADR-062 (capability injection / prove-absent), ADR-054
(pre-rotation custody) are all **`Proposed`** with fully merged code depending on them.
No document defines the status vocabulary: 47 ADRs say `Decided`, 12 `Accepted`, 3 `Proposed`,
2 `Superseded`. **Phantom cite:** `outlets/signer.rs:24,229,240` cite "ADR-034 §1" for the
operator==invoker premise; ADR-034 has no §1, is Superseded by ADR-055, and never uses the
words "operator" or "invoker". ADR-043 is assigned twice (phase-4.md:1642, phase-6.md:3373).

## Scale (production code, excl. tests/ and generated ScpBindings.swift)

`deferred` 161 · `placeholder` 95 · `not yet {implemented,wired,…}` 55 · `follow-up` 42 ·
`out of scope` 19 · `future work` 9 · `KNOWN LIMITATION` 5 · `TODO` 2 · `FIXME`/`HACK`/`todo!`/
`unimplemented!` 1 each. By crate: scp-runtime 194, scp-ffi 70, scp-protocol 26, scp-node 21.
Rust suppressions ~957 production, `#[expect]` = 0 repo-wide; of 135 dead/unused allows:
44 stale, 80 live gap, 11 legitimate. `#[ignore]` = 45 (33 are external-dep gates).
PRDs: **443 stories — 390 done / 6 in-progress / 47 pending** across 18 files.
