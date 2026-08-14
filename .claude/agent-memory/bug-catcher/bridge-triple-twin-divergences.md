# Bridge-triple twin divergences (sweep @ origin/main d1ebc5ab9, 2026-08-08)

Defect shape hunted: a guard fixed on ONE FFI bridge while its near-identical twin on
another bridge keeps the gap. Reviews pass because the reviewed diff is correct.

## Confirmed (see final report for full proofs)

1. **UniFFI synthesizes a DEFAULT `ContextRoleState` for outlet authorization.**
   `crates/scp-ffi/uniffi/src/bridge.rs:13428` (outlet_register), `:14461`
   (outlet_interface_expose), `:14541` (outlet_interface_accept) each build
   `ContextRoleState::new(ctx, handle.creator_did, default_ceiling(), vec![], clock)` and pass
   it as the authorization state, with `handle.creator_did` as the caller.
   `ContextRoleState::new` **auto-assigns the creator as admin**
   (`crates/scp-protocol/src/context/roles.rs:1729-1745`), so `has_admin_role` /
   `has_outlet_register_capability` are TRUE by construction — tautological gates.
   PyO3 (`src/outlets.rs:308,1706,1765`) and NAPI (`napi/src/outlets.rs:329,1401,1459`) all
   pass the LIVE governance-synced `rt.role_state`. UniFFI knows how to read live role state
   (`bridge.rs:5057` `QueriesCommand::GetRoleState`) — so the synthesis is not justified.

2. **PyO3 has NO context-lifecycle (Active) gate on ANY bridge-local outlet op.**
   NAPI + UniFFI both gate `outlet_invoke`, `outlet_verify`, `outlet_invoke_cross_context`,
   `outlet_session_create`, `outlet_session_invoke`, `outlet_interface_expose/accept`.
   PyO3's `src/outlets.rs` never reads any lifecycle state. Its OWN sibling
   `src/outlet_stream.rs:1228,1239` DOES use `supervisor.read_context_state(...)` — the live
   read is available and already used one file over. Exposure: `Closing`/`Expired`/
   `MigratingOut`/`Tombstoned`/`Poisoned` (FFI state is only removed on full close).

3. **NAPI + UniFFI lack the source-context role-state capability gate** that PyO3 has at
   `src/outlets.rs:986-1000` in `outlet_invoke_cross_context`
   (`has_outlet_invocation_capability` with the SCP-OUT-014 target kind). Zero hits for
   `has_outlet_invocation_capability` anywhere in `crates/scp-ffi/napi/`.

4. **NAPI + UniFFI lack the same dual-check (ADR-010 §7.2) in `outlet_session_invoke`**
   (PyO3 `src/outlets.rs:1554-1573`).

## Verified CLEAN — do not re-derive

outlet_invoke (same-context, all 3 → `invoke_outlet_with_economy`), outlet_invoke_cross_context_saga,
outlet_session_close, outlet_interface_revoke, outlet_stream_open / grant_credit
(durable `next_grant_monotonic_seq` — PyO3 calls the helper directly, NAPI/UniFFI via
`ProtocolRepoVariant::next_stream_credit_seq`; documented, symmetric) /
verify_chunk_signature, outlet_streaming_saga_open (LIVE `read_context_state` on all three),
ucan_validate/evaluate/mint/delegate/revoke, event_log_query/verify (inclusion + absence —
byte-equivalent), event_log_checkpoint, economy_verify_payment_receipts (`MAX_RECEIPT_BATCH`
on all 3), trust_* (all 6), identity_verify_link_attestation,
identity_attest_device / verify_device_attestation (identical cfg(testing) vs
cfg(not(testing)) fail-closed IDENT_1015/1016 on all 3), media_* (all 11),
governance_execute (role-state re-sync on all 3), enforce_caller_principal_binding,
decode_asserted_nonce, MCP stdio allowlist quartet.

## Traps that looked like findings but were NOT (verified)

- **`handle.ceiling` raw-vs-normalized.** NAPI `handle.ceiling` LOOKS raw (parsed from
  `params["ceiling"]` at `napi/src/context.rs:582`) but is normalized via
  `Capability::ucan_capability_name()` at handle construction (`:852-858` create,
  `handle_fields_from_core_params` `:1180` join). Matches UniFFI (`bridge.rs:10195`,
  `:10617`). NOT a divergence — verify the handle CONSTRUCTION site, not the parse site.
- **empty-ceiling → `default_ceiling()` widen** at mint/delegate exists on NAPI
  (`napi/src/ucan.rs:488,614`) + UniFFI (`bridge.rs:5560,5661`) but not PyO3 — PyO3 already
  substitutes the default at `register_ffi_state` (`src/runtime.rs:1559`), so it is
  effectively equivalent.
- **UniFFI `build_ucan_context_state` SKIPS a malformed ceiling entry** (infallible) where
  PyO3/NAPI error. Skipping NARROWS the ceiling → fail-closed. Justified.
- **`#1933` forgeable absence proofs** are SYMMETRIC across all three — not a twin gap.

## Useful sweep technique

Three-way set-diff of guard-shaped call names is a cheap high-signal first pass:

```
git grep -hoE "(verify|validate|check|has|require|ensure|enforce|is)_[a-z_0-9]+\(" \
  origin/main -- "crates/scp-ffi/<dir>" | tr -d '(' | sort -u > set.txt
comm -12 py.txt uni.txt | comm -23 - napi.txt     # missing on NAPI
```
Then per-module py-vs-napi diffs (UniFFI is one 1.1 MB `bridge.rs`, so grep it by fn name).
