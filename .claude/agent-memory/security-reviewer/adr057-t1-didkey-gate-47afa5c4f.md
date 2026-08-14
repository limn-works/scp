# ADR-057 T1 did:key gate restore + Python classifier repair (47afa5c4f) -- 2026-07-03 -- CLEAN

Branch refactor/dissolve-primitives-split-identity. Reviewed newest commit + full range 86519aa6f..47afa5c4f.

## (a) did:key gate in BridgeDidResolver -- prior MEDIUM FULLY CLOSED
- Prior MEDIUM: allow_in_memory_custody transitively enabled scp-did/testing -> did:key:{hex} accepted on UCAN path via extract_public_key_from_did delegation.
- Fix: local gate resolvers.rs:81 `#[cfg(not(any(test, feature="testing")))] if did.starts_with("did:key:") { Err(MalformedToken) }` keyed off scp-ffi-common's OWN testing feature.
- VERIFIED feature graph: allow_in_memory_custody (scp-ffi/uniffi/napi) = [scp-platform/testing, dep:scp-testing|scp-core/testing] -> chain reaches scp-did/testing but NEVER scp-ffi-common/testing. Production [dependencies] pull scp-ffi-common features=["custody"]; testing is [dev-dependencies] ONLY. So gate compiled IN for all shipped/custody artifacts -> did:key rejected.
- Config where did:key accepted = ONLY when scp-ffi-common/testing (feature=["resolvers","scp-did/testing"]) or test cfg on; that FORCES scp-did/testing on too (consistent). Never a shipped artifact.
- ALL resolver entry points covered: BridgeDidResolver::resolve_public_key (gated); resolve_public_key_by_kid routes to resolve_public_key via trait default (validate.rs:93, #active->self.resolve_public_key, else Err); DispatchDidResolver::Bridge delegates to BridgeDidResolver; DispatchDidResolver::new(None)=Bridge is prod-reachable pre-identity-init. IdentityBackedDidResolver = DID-document path, no did:key surface.
- No casing/prefix bypass: both local gate (starts_with) + scp-did (strip_prefix) use lowercase exact; "DID:KEY:"/leading-space -> rejection not acceptance. Fail-closed.

## (b) trust.py classifier -- PURELY DIAGNOSTIC, fail-closed preserved
- Enforcement is Rust ucan_validate (throws). evaluate_trust (trust.py:769) starts all CapabilityValidation True, on ANY exception sets fields = `_PASSED_BEFORE.get(category, set())` membership. Classification only picks which optimistic-True fields survive; failing field + all-after = False; "unknown" -> set() -> all False.
- Misclassifying a DID error into a signatures_valid=True bucket (ceiling/nonce/revoked/expiry) is IMPOSSIBLE: "malformed token: ..." can't startswith those later-stage prefixes, and _SIGNATURE_CHAIN checked first. New prefixes classify "signatures" (signatures_valid=False). Fail-closed regardless.

## (c) conformance guard -- effective vs drift, residual gap fail-closed
- test_ucan_conformance.py brace-matches extract_public_key_from_did body (excludes cfg(test)), extracts format!("...") -> "malformed token: <static>". 3 asserts: exact-set pin (5 strings), each-covered-by-python, not-unknown. Any string change or new format! path fails CI -> forces lockstep Python update.
- Observation (low): pin tracks only format!() literals; a future non-format! error (.ok_or("..")) wouldn't join pinned set, Python not forced -> silent DIAGNOSTIC drift, but unknown->all-False = fail-closed. Not a security hole.

## (d) no regressions across range
- verify_ed25519_signature canonical home = scp-crypto/src/lib.rs (verify_strict + 32/64 length checks; byte-identical dissolve). Other defs (wire.rs private, key_protocol_verify.rs pub(super), scp-testing conformance) are pre-existing DISTINCT local helpers, not dissolve duplicates.
- Canonicality re-encode guard on ALL did:dht decoders: scp-identity/dht.rs:2748, scp-did/lib.rs:144, app_sandbox.rs now DELEGATES did:dht to scp-did (fixes prior 'z'-not-stripped bug + adds canonicality). app_sandbox did:key:z = standard base58btc/multicodec (legit, separate subsystem, not the hex test-convenience).
- serde(transparent) DID + SigningKeyId "#active"/"#agent" unchanged. Cargo.lock: 0 scp-primitives, 1 scp-did, 1 scp-crypto.
- Enforcement scripts: check-protocol-deps.sh + check-no-mutable-globals.sh = cosmetic scp-primitives->scp-clock rename only (no logic weakening). NEW check-no-shim-reexports.sh addressed BOTH prior low-sev observations (find -name src covers nested scp-ffi/*/src 2-deep; `\b` word-boundary catches whole-crate/as-rename/path forms). Closed positive check, honest documented limits, no eval/injection.

## Observation (low): production did:key-reject branch is `cfg(not(test...))` -> compiled OUT under `cargo test`; no Rust unit test can exercise the prod rejection directly. Correctness rests on review + feature-graph analysis (done here), not a test.
