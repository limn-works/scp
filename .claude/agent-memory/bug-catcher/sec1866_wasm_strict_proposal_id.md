# SEC-1866 — WASM strict proposal_id hex parse breaks 7 existing tests (CRITICAL)

Branch fix/1866-direct-execute-trust, commit 9b0f52ac5 (FIX C). Reviewed diff c9db30486..b297553c9.

## The break
`parse_proposal_id_bytes` (manager.rs:76) strict-rejects non-64-char hex. Wired into
`execute_governance_action` (manager.rs:3188) AND `propose_governance_action` (manager.rs:4260).
These run for EVERY proposal incl. already-tracked ones. Pre-existing tests seed SHORT
proposal ids ("deadbeef"=4B, "abad1dea"=4B, "feedface"=4B, "feedbeef"=4B) via the test
seam (`test_insert_resolved_proposal`) or via `propose_governance_action`, then execute.
Strict parse now rejects them → 7 failures in `cargo test -p scp-ffi-wasm --lib`:
- manager::tests::direct_execute_of_genuine_proposal_runs_once_then_replay_rejected_wasm (9339)
- consequence::cross_impl_leaf_parity::* (6 tests: 1096,1273,1556,1646,1838,1945)

consequence.rs:1086 comment literally says "deadbeef is valid hex ... used verbatim as the
map key" — assumption invalidated by FIX C.

## Why production is safe but tests aren't
In prod every tracked proposal goes through propose's strict parse → always 64-char id.
Only the test seams inject short ids. Fix = update the test id literals to 64-char hex
(e.g. "ab".repeat(64/2) or pad). NOT a production logic bug; it IS a CI-breaking regression
(CLAUDE.md: cargo test -p scp-ffi-wasm is the WASM test gate).

## LESSON / PATTERN
When tightening an in-crate parse/validator that ALSO runs on internally-tracked/seeded
values (not just fresh caller input), grep ALL test seams that inject the value with the
old lax format. Run the crate's own `--lib` test suite, do not rely on the new targeted
tests passing. The author added 2 new strict tests (which pass) but never ran the existing
suite — classic "new tests green, existing suite red" miss.

## Clean parts of the diff (verified)
- identity_did removed cleanly from all 4 bridges (PyO3/UniFFI/NAPI/WASM) + 4 SDK wrappers;
  ExecuteGovernanceActionPayload has only context_id+proposal_id; all 5 construction sites match.
- WASM consequence subject resolves from tracked proposer on every path (bridge passes
  proposer_did/proposer_did; quorum=voter/voter, auto=proposer/proposer; initiator_did used
  for consequence dispatch == executor on all callers). proposal_proposer_did never None.
- Swift binding regenerated (checksum 14006→15010, FfiConverter drops identityDid).
- New hex-rejection tests are non-tautological.
- LOW: android TestNativeBindings.governanceExecute param named `proposalJson` (stale, was
  arity-mismatched at base when interface was 3-param; B+C accidentally re-aligns arity).
- LOW: test_dispatch_execute_by_id doc (context.rs:5608) still says "authenticated executor DID".
