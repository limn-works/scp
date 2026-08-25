# Document a partial validation pipeline by what it checks, never by what it claims

**Status: that divergence cannot recur, because that bridge no longer exists.** `crates/scp-ffi/` holds six directories — `src` (PyO3), `napi`, `napi-test-stubs`, `uniffi`, `common`, and `tests` — and no `wasm` directory. Root `Cargo.toml:25-29` lists the five workspace members rooted there: `crates/scp-ffi`, `crates/scp-ffi/common`, `crates/scp-ffi/uniffi`, `crates/scp-ffi/napi`, and `crates/scp-ffi/napi-test-stubs`. No member and no directory is named `wasm`, so no WASM-local reimplementation of UCAN validation remains to drift. Three native bridges call one shared pipeline instead: `validate_ucan`, declared at `crates/scp-protocol/src/crypto/ucan/validate.rs:729`.

Two details this lesson previously got wrong, corrected here against source. A flat `ceiling_strings: HashSet<String>` is **not** gone: `crates/scp-ffi/common/src/bridge_runtime.rs:376` declares it, `crates/scp-ffi/src/runtime.rs:1482` declares the PyO3 bridge's own copy, and all three native bridges populate it (`crates/scp-ffi/src/runtime.rs:1559` and `:1797`, `napi/src/runtime.rs:1647` and `:1906`, `uniffi/src/runtime.rs:1125`). All three pass it as that pipeline's step-8 ceiling argument (`crates/scp-ffi/src/ucan.rs:328`, `napi/src/outlets.rs:61`, `uniffi/src/bridge.rs:4404`), which `validate.rs:659` types as `ceiling: &'a HashSet<String, S>`. A second representation coexists rather than replacing it: `ContextRoleState::ceiling()` at `crates/scp-protocol/src/context/roles.rs:1901` returns `&CapabilityCeiling`.

Everything under "What went wrong" describes that removed bridge.

## Rule

When a platform constraint forces a partially implemented validation pipeline, its docstring states which checks run and which do not. Documentation that claims a security property code never delivers is worse than absent documentation, because a reader who trusts it stops looking.

## What went wrong (SCP-218)

That bridge's `ucan_validate` docstring claimed "Performs full UCAN validation: signature verification, time bounds checking, delegation chain traversal, attenuation enforcement, nonce replay detection, and capability matching." Its implementation ran five steps: JWT format check, base64/JSON decode, expiry check, capability string match, revocation check. Four of the docstring's six claimed checks never ran — Ed25519 signature verification, delegation chain traversal, attenuation enforcement, and nonce replay detection. The expiry check delivered the claimed time-bounds check, and the capability string match delivered the claimed capability matching. That implementation also skipped three checks the shared pipeline runs and the docstring never claimed: the root issuer check (`validate.rs:768`), audience DID validation (`:771`), and the ceiling check (`:815`).

That bridge could not reach scp-core validation, because scp-core depended on `tokio` with feature `full`, which needs a multi-thread runtime that `wasm32-unknown-unknown` cannot compile. So it re-implemented validation over wasm-compatible crates, and drifted from a pipeline it claimed to run.

Two narrower defects rode along:

- Wildcard matching compared `can_str == "*"` without first pinning resource scope, so a token granting `scp:ctx:A/*` passed validation for `scp:ctx:B/messages:write`. Correct order checks `with_str` first, then allows a wildcard on `can`.
- A missing `exp` raised an error, which that era's reading of UCAN treated as wrong, because UCAN permits a non-expiring token. This codebase settled that question in a different direction, and a reader should not carry that bullet forward as guidance: `UcanPayload::exp` at `crates/scp-protocol/src/crypto/ucan/mod.rs:399` is a required `u64` with no `Option` and no serde default, so a token omitting `exp` now fails to deserialize.

## How to apply

A story acceptance criterion reading "calls scp-core X-step pipeline" cannot be met literally by a bridge that cannot link scp-core. Write that story to name which steps run structurally, which wait on key-custody wiring, and which an architecture forbids outright. Mark each waiting step `// Stub — see SCP-NNN`, pointing at a story that will wire it.
