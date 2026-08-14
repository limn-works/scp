# c3c-ts-work — ParticipationFacts / participation_record (Phase 2C-1)

Reviewed working-tree diff (13 files + new test participation_record_supervisor.rs). CLEAN except one LOW.

- ParticipationFacts flattening matches produce_participation_profile exactly (same .len()/.values().sum()); profile event_log_root=input.merkle_root vs Facts=record.event_log_root but both equal merkle_root (compute sets record.event_log_root=merkle_root) — no drift.
- Supervisor::participation_record: .unwrap_or([0u8;32]) on event_log_merkle_root only triggers when no log → events empty → core EmptyEventLog. Masking benign.
- NAPI u64 as i64 casts: counts/unix-secs well within i64::MAX; matches NapiTrustScoreResult; clippy::cast_possible_wrap allow justified.
- No attestation double-count: storage key = attestation_key(ctx,subject,id) → overwrite not append. block_on used on FFI threads (handle stored), sequential before supervisor call — no reentrancy.
- credential_attestation_history filters subject==did && Active; test proves it (att-other + Revoked excluded → count 2).
- Test build_supervisor_with_seeded_log: GovernanceActionExecuted matches core; RemoveMember in ADVERSE_ACTION_TYPES so against-Bob counts; gov-by recorded unconditionally for actor; duration 100→400=300; clock None → SystemClock default (clock_ref Some, no NotInitialized). All assertions genuine, attribution to target-not-actor proven.
- pipeline_wiring: 4 real fn_body_contains assertions (not dead refs); ratchet 50→54.
- matrix/aliases/allowlist additive only, exemptions cite #1943 + ADR-034 WASM.

## LOW (UniFFI only)
crates/scp-ffi/uniffi/src/bridge.rs participation_record: reuses VALID_7048 ("Transport checkpoint validation error") for cached_attestations JSON parse failure and VALID_7052 ("Bridge connector payload validation error") for attestation-sourcing failure — semantically mismatched codes from unrelated subsystems. PyO3/NAPI don't have this (PyValueError / validation_error+CTX_2000). Suggest a participation-domain VALID_* code.
