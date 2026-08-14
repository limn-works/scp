# PR#2235 app-bound/unbound durable event log (§8.4) -- 2026-08-03 -- no BLOCKER

Branch feat/app-bound-unbound-event-log. AppBound/AppUnbound (tags 74/75) across PyO3/UniFFI/NAPI + 4 SDKs. Codes CTX_2056-2059.

## Findings
- WARNING: `timestamp_secs: u64` is fully caller-controlled and written VERBATIM into the durable Merkle leaf on all 3 bridges. `builder.rs::append_context_event_with_payload`->`append_event` does NOT clamp/reject-future/enforce-monotonic. These app_bind/app_unbind are the ONLY PyO3 context FFI methods taking a caller timestamp (others derive from clock). Backdate/postdate audit leaves. Same class as 7f341b8 future-timestamp-window + SCP-ACR-001. Pairs with tracked actor_did-unauth gap (2nd forgeable field on same leaf).
- INFO: SandboxError::EventLogFailed(e.to_string()) surfaces raw provider (ProtocolRepository/storage) error string to caller under CTX_2057. Low blast (caller=host) but internal-state disclosure.
- INFO: validate_declaration CeilingExceeded distinguishes NotInCeiling vs NotInRole in the CTX_2056 message -> capability-enumeration oracle for any actor_did's effective role caps (sig-verify precedes cap-check but caller self-signs own app key). Amplified by unauth actor_did.
- INFO: Python SDK context_app_bind/context_app_unbind SKIP the `_coded_bridge_error` wrapper that every neighbor uses -> raw pyo3 exception, not typed ScpError. TS wrappers correctly use mapBridgeError. Python-only parity gap.
- INFO: bind/unbind registry mutation non-atomic vs durable append (separate lock acquisitions) -> concurrent unbind = duplicate AppUnbound leaves; concurrent bind = last-writer-wins handle + dup leaves. Benign (no cap boundary bypassed). No dedup/idempotency on re-bind.

## Positive
- validate_declaration: requested caps must be in ceiling ∩ role (role = member_has_capability suspension-aware). Non-member(empty role)=>any decl rejected. App never gets a cap the actor lacks. Fail-closed.
- sig-before-cap ordering; did:dht key extraction delegated to single hardened scp_did::extract_public_key_from_did (fixed prior 33-byte multibase bug).
- capabilities.sort_unstable() before encode_payload => deterministic cross-platform Merkle leaf.
- fail-closed on EventLogFailed (no silent attach/detach); was-bound precondition (CTX_2059) parity across 3 bridges; ScopedHandle::new/inner pub(crate).
- VALID_7025-7029 = SDK-wrapper-local WASM guards, documented "never minted by a bridge". Fine.
