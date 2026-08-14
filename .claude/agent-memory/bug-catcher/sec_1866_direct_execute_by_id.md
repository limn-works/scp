# SEC-1866 direct-execute governance by-id (fix/1866-direct-execute-trust, HEAD 3834898f0)

CLEAN review — no defects. Reviewed a632c731a..3834898f0.

## What changed
- Direct-execute governance now by tracked `proposal_id` (not caller proposal). `ExecuteGovernanceActionPayload.proposal` (Box<GovernanceProposal>) → `proposal_id: ProposalId`. Closes quorum-bypass: caller can no longer fabricate an Approved proposal / substitute action.
- `execute_governance_action(state, deps, ctx, proposal_id: &ProposalId, executor_did: Option<&DID>)`. Resolves proposal from `state.governance.engine.get_proposal(proposal_id)`; `None` proposal → PermissionDenied "not tracked". `executor_did: None` (direct path) → resolves to `proposal.proposer_did`. `check_commit_fault` moved to top (still fail-closed; only error-message ordering changes).
- Internal callers (propose auto-execute 3139, vote 3455) pass `&proposal.proposal_id, Some(did)`. Engine retains proposal (propose `engine.propose` inserts; vote `engine.approve` mutates to Approved) BEFORE execute re-resolves. `detect_and_handle_conflicts` mutates `approved_proposals` audit map, NOT `engine.proposals` — winner stays Approved on re-resolve; loser skipped via `invalidated_by_conflict`. No TOCTOU (single actor turn, no await yields to other commands).
- Validator: `validate_proposal_id_hex(&str) -> Result<[u8;32], ValidationError>` (single decode). WASM `parse_proposal_id_bytes` thin wrapper → CTX_2040 via `ScpWasmError::proposal_id`. Replaces old `unwrap_or_default + truncate/zero-pad`.
- 4 bridges uniform `(handle, proposal_id_hex)`: PyO3 `parse_proposal_id`, NAPI `parse_napi_proposal_id`, UniFFI `parse_uniffi_proposal_id` (all hex::decode+try_into[u8;32]), WASM `validate_proposal_id_hex`. WASM resolves executor+consequence-subject from `proposal_proposer_did` (errors if untracked, never empty) — passes proposer for BOTH initiator+executor (matches native direct path).
- WASM map keys = hex strings (pending/resolved/executed_proposals); leaf bytes = decoded [u8;32]. Consistent (unchanged from before).
- TestInsertMember command fully `#[cfg(feature="testing")]`-gated (variant + handler + dispatch + supervisor + actor mod fallback). Never in prod.

## Verification performed
- UniFFI checksum 15010: REGENERATED via uniffi-bindgen, ALL checksums match committed ScpBindings.swift (no staleness — the recurring CRITICAL is NOT present). Kotlin internal/scp.kt is git-ignored/generated (no staleness risk).
- `cargo test -p scp-ffi-wasm --lib`: 362 pass. `cargo nextest` scp-runtime+ffi+wasm+common: 3398 pass. scp-testing: 701 pass. governance_integration (testing): 58 pass. wasm_conformance: 55 pass. uniffi e2e governance: 2 pass. PyO3 direct_execute: 2 pass.
- clippy scp-runtime(testing) + scp-ffi-wasm(wasm32): clean. `cargo fmt --check`: clean. `check-bridge-symmetry.sh`: 0 findings.
- All added `.unwrap()`/`panic!` confined to `#[cfg(test)]` mods (napi tests@4709, ffi tests, governance_integration.rs). Production paths use `?`/map_err.
- Tests substantive (not tautological): untracked→reject, forgery→no-state-change, genuine→runs-once-then-replay-rejected; WASM direct-executor leaf parity asserts actor_did=proposer (not caller); AST enforcement assertions pin signature `proposal_id: &ProposalId`, reject `proposal: &GovernanceProposal`.
- Box<ExecuteGovernanceActionPayload> retained but no longer needed for size ([u8;32]+String ~56B); doesn't trip clippy large_enum_variant. Harmless.

## Note (validator)
`validate_proposal_id_hex` does NOT call reject_control_chars/length-cap before hex::decode, but hex::decode rejects any non-hex char and the try_into enforces exactly 32 bytes — so control chars / overlong inputs are rejected anyway. Correct.
