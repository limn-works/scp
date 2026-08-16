# Document a partial validation pipeline by what it checks, never by what it claims

**Status: resolved since #1877 slice 1.** That bridge's `ucan_validate` now delegates to one shared pipeline, `scp_protocol::crypto::ucan::validate::validate_ucan`, through an extract-validate-writeback pattern, so it runs identical logic to native bridges rather than a local reimplementation. A flat `ceiling_strings: HashSet<String>` representation described below is gone: a ceiling now lives inside shared `scp_protocol::context::roles::ContextRoleState`, and shared `CapabilityCeiling::validate_entries` enforces it. Everything under "What went wrong" describes a pre-convergence implementation.

## Rule

When a platform constraint forces a partially implemented validation pipeline, its docstring states which checks run and which do not. Documentation that claims a security property code never delivers is worse than absent documentation, because a reader who trusts it stops looking.

## What went wrong (SCP-218)

That bridge's `ucan_validate` docstring claimed "Performs full UCAN validation: signature verification, time bounds checking, delegation chain traversal, attenuation enforcement, nonce replay detection, and capability matching." Its implementation ran five steps: JWT format check, base64/JSON decode, expiry check, capability string match, revocation check. Seven claimed checks never ran — Ed25519 signature verification, delegation chain traversal, root issuer check, audience DID validation, attenuation enforcement, ceiling check, and nonce replay detection.

That bridge could not reach scp-core validation, because scp-core depended on `tokio` with feature `full`, which needs a multi-thread runtime that `wasm32-unknown-unknown` cannot compile. So it re-implemented validation over wasm-compatible crates, and drifted from a pipeline it claimed to run.

Two narrower defects rode along:

- Wildcard matching compared `can_str == "*"` without first pinning resource scope, so a token granting `scp:ctx:A/*` passed validation for `scp:ctx:B/messages:write`. Correct order checks `with_str` first, then allows a wildcard on `can`.
- A missing `exp` raised an error, though UCAN and scp-core both treat an absent `exp` as a non-expiring token.

## How to apply

A story acceptance criterion reading "calls scp-core X-step pipeline" cannot be met literally by a bridge that cannot link scp-core. Write that story to name which steps run structurally, which wait on key-custody wiring, and which an architecture forbids outright. Mark each waiting step `// Stub — see SCP-NNN`, pointing at a story that will wire it.
