---
name: attestation-verify-four-sdk-trace
description: Traced Identity/verify_attestation and Trust/trust_verify_attestation through all four SDKs — both wire through; the residual gaps are SDK-layer tests, a Kotlin bindings interface with no production impl, and a caller-asserted class 2 fetch outcome.
metadata:
  type: project
---

At commit 29d9eacc97 both matrix cells hold at the wiring layer. Every SDK wrapper reaches
a per-instance bridge method, and both bridge methods reach one shared Rust flow.

- `Identity/verify_attestation`: `scp_ffi_common::attestation::verify_link_attestation`
  (`crates/scp-ffi/common/src/attestation.rs:445`) resolves the issuer DID document before
  any signature check. Each bridge supplies its own resolver:
  `crates/scp-ffi/src/identity.rs:1691`, `crates/scp-ffi/napi/src/scp.rs:1109`,
  `crates/scp-ffi/uniffi/src/bridge.rs:10057`.
- `Trust/trust_verify_attestation`: `scp_ffi_common::trust_store::verify_attestation_in_context`
  (`crates/scp-ffi/common/src/trust_store.rs:607`) calls `get_revocation_state(context_id)`
  at line 614. Bridge entry points: `crates/scp-ffi/src/trust.rs:1128`,
  `crates/scp-ffi/napi/src/scp.rs:3903`, `crates/scp-ffi/uniffi/src/bridge.rs:17078`.

**Why the trace still found gaps:** wiring completeness and layer completeness are separate
questions. Swift and Kotlin ship a link-attestation verify wrapper with zero SDK-layer
tests, and Python asserts only that the data class lacks a `verify` method. The Rust bridge
tests cover the flow, which is what makes the SDK-layer absence easy to miss.

**How to apply:** when checking a matrix cell, after confirming the wrapper→bridge chain,
grep each SDK's own test tree for the wrapper symbol. Also check whether an SDK exposes a
second public path to the same operation — Kotlin's `IdentityAdvancedBindings`
(`bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Identity.kt:217`) declares
`identityVerifyLinkAttestation` with no bridge instance and has no shipped implementation,
only a test stub, and `scripts/check-sdk-coverage.py` accepts its wrapper name as an alias
for the cell.

**Gate limitation worth remembering:** `scripts/check-sdk-coverage.py` documents itself as a
name-existence check. A cell passes when any aliased symbol name exists, so the gate cannot
distinguish the per-instance wrapper from a wrapper over a declining free function. Read the
call chain yourself; the gate does not.

Related: [[adr057_transport_wasm_surface_parity]].
