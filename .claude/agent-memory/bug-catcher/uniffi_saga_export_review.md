# UniFFI tool_invoke_cross_context_saga export (commit 6edac5f41, #116 slice C)

Reviewed bridge.rs export of §6.2.4 saga. Implementation correct: async/Send (handler
snapshot `.lock().await.get().cloned()` drops guard same-statement; executor `'static`+Send
captures only owned data; supervisor Arc cloned out of bi-borrow); map_saga_error matches
producer SagaError terminals exactly (Aborted code=SCP-SAGA-{u16}, NeedsRepair=13065,
Busy=13066, retry_after_ms None-not-0); decode_asserted_nonce fail-closed (hex + [u8;16]);
CrossContextToolInvocationRequest field/type match; SagaSigningKeys named (target/caller not
transposed); handle affinity both checked; no unwrap/expect/panic in non-test code; compiles;
3 saga + 5 map + 2 decode tests pass.

## DEFECT (WARNING) — negative binding tests pass for the wrong reason
`xctx_saga_unhosted_caller_did_is_rejected_axis_a` and
`xctx_saga_hosted_non_member_caller_is_rejected_axis_b` assert ONLY `code == SAGA_13050`.
But the supervisor's OWN gate 1 (`!is_member`) ALSO returns code 13050 → map_saga_error →
SagaAborted SAGA_13050, indistinguishable from the bridge's enforce_caller_principal_binding
rejection. Both negative DIDs are non-members, so removing the bridge binding entirely keeps
both tests GREEN (mutation-confirmed by reading producer supervisor.rs:5504-5515). The bridge
axis-(a) custody-registry check (the load-bearing addition over producer membership) is thus
UNTESTED. Fix: also assert on `msg` substring — axis (a) "is not an identity hosted by this
bridge instance", axis (b) "is hosted by this bridge but is not a member" — which the producer
message ("is not a member of caller context ... not authorized to initiate over it") lacks.
PyO3/NAPI siblings don't have these negative tests at all; UniFFI is the only one, so the weak
assertion isn't inherited.
