# FFI Bridge Cross-Audit Report

**Date:** 2026-03-09
**Scope:** All 4 FFI bridges on `integration/close-remaining-issues` branch
**Methodology:** Adversarial code review comparing validation, authorization, deserialization, identity handling, and error behavior across PyO3, NAPI, UniFFI, and WASM bridges.

---

## Adversary Profiles

### AP-1: Malicious SDK Consumer
A developer who intentionally crafts inputs at the FFI boundary to bypass authorization, forge capabilities, or escalate privileges. Targets the weakest bridge for initial access, then uses cross-bridge interop (e.g., WASM-minted tokens validated by NAPI) to exploit divergences.

### AP-2: Compromised Dependency (Supply Chain)
An attacker who controls a transitive dependency (npm package, PyPI package, or Cargo crate) and can inject code that runs within the same process as the FFI bridge. Exploits the gap between FFI-boundary validation and scp-core enforcement.

### AP-3: Cross-Bridge Exploit Developer
A sophisticated attacker who studies all 4 bridge implementations to find behavioral differences. Crafts payloads that pass validation in one bridge but fail in another, creating inconsistent state. Targets cross-bridge delegation chains and capability transfer.

---

## Attack Narratives

### BLACK-301: WASM Deserialization Payload Injection (MEDIUM)

**Adversary:** AP-1 (Malicious SDK Consumer)
**Objective:** Inject unexpected fields into UCAN tokens that survive parsing and propagate through the system.

**Campaign:**
1. Attacker crafts a UCAN JWT where the header and payload JSON contain additional unknown fields (e.g., `{"alg":"EdDSA","typ":"JWT","ucv":"0.10.0","admin":true}`).
2. WASM bridge parses this with `UcanHeader` struct (`/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-ffi/wasm/src/ucan.rs` lines 38-43) which lacks `#[serde(deny_unknown_fields)]`.
3. Deserialization succeeds silently. The extra `admin` field is discarded by serde's default behavior.
4. Similarly, `UcanPayload` (lines 63-81) and `WasmGovernanceAction` (`/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-ffi/wasm/src/manager.rs` line 76) accept unknown fields.
5. While the extra fields are currently discarded, if any downstream code serializes the parsed struct back to JSON (e.g., for storage, forwarding, or logging), the injected fields are lost -- creating a round-trip inconsistency that could confuse debugging or audit.

**Key Insight:** The real risk is not today's behavior but future code changes. If anyone adds `#[serde(flatten)]` or manual field extraction later, previously-ignored fields become attack surface. Defense in depth says reject what you don't understand.

**Impact:** MEDIUM -- Currently no direct exploit, but violates defense-in-depth principle and creates latent risk.

**Recommended Fix:** Add `#[serde(deny_unknown_fields)]` to `UcanHeader`, `UcanPayload`, `Attenuation`, and `WasmGovernanceAction` in the WASM bridge.

---

### BLACK-302: NAPI context_close Skips DID Validation (MEDIUM)

**Adversary:** AP-1 (Malicious SDK Consumer)
**Objective:** Pass malformed DID strings to context_close to bypass input validation.

**Campaign:**
1. Attacker calls `context_close(handle, "not-a-did\x00\x01\x02")` from Node.js.
2. In NAPI `context_close` (`/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-ffi/napi/src/context.rs` lines 492-523), the `identity_did` parameter is used without calling `validate_did()`.
3. Every sibling function (`context_join`, `context_send`, `context_leave`, etc.) calls `validate_did(&identity_did)?` as the first step after state checks. `context_close` does not.
4. The malformed DID is passed directly to `ContextManager::close_context(core_handle, &DID(identity_did))`.
5. The ContextManager checks the DID against its capability table. A malformed DID will not match any member, so the operation fails -- but with a ContextManager error rather than a clean ValidationError.

**Key Insight:** While the ContextManager provides a second line of defense (the close will fail because no member matches the garbage DID), the inconsistency means: (a) the error message and code differ from what validate_did would produce, enabling fingerprinting, and (b) any control characters in the DID string pass through to the ContextManager's error messages, potentially enabling log injection.

**Impact:** MEDIUM -- No direct authorization bypass due to ContextManager defense-in-depth, but violates the consistent validation pattern and enables error oracle attacks.

**Recommended Fix:** Add `scp_ffi_common::validate::validate_did(&identity_did)?` to `context_close` before the state check, matching all sibling functions.

---

### BLACK-303: NAPI context_subscribe Discards Identity (MEDIUM)

**Adversary:** AP-1 (Malicious SDK Consumer)
**Objective:** Subscribe to context messages without identity validation.

**Campaign:**
1. Attacker calls `context_subscribe(handle, "arbitrary-string", callback)`.
2. In NAPI `context_subscribe` (`/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-ffi/napi/src/context.rs` line 629), `let _ = identity_did;` discards the identity without any validation or authorization check.
3. The function immediately calls the `on_message` callback with `None` (stream completion) and returns success.
4. No membership check occurs -- any caller can "subscribe" regardless of identity.

**Key Insight:** Currently the function is effectively a no-op (signals immediate completion), but when real transport wiring is added, this function will need proper authorization. The `let _ = identity_did;` pattern silently suppresses the unused variable warning, making it easy to miss during review.

**Impact:** MEDIUM -- Currently no data exposure since the function is a stub, but creates a latent authorization gap when transport is wired.

**Recommended Fix:** At minimum, call `validate_did(&identity_did)?` for input validation. When transport is wired, add ContextManager membership verification.

---

### BLACK-304: WASM Capability Format Mismatch (HIGH)

**Adversary:** AP-3 (Cross-Bridge Exploit Developer)
**Objective:** Exploit divergent capability string formats to bypass authorization in cross-bridge scenarios.

**Campaign:**
1. Attacker studies capability formats. In scp-core, capabilities are a typed enum (`Capability::ContextClose` at `/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-core/src/context/roles.rs` line 89). The string representation used in UCAN tokens is `"context:close"` (colon-separated, as seen in test code at `manager.rs` line 7512: `Capability::new("context:close")`).
2. In WASM, capabilities are string-based. The ceiling at `/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-ffi/wasm/src/manager.rs` lines 528-539 uses `"context_close:*"` (underscore, with wildcard).
3. The `close_context` function (line 744) checks `member_has_capability(initiator_did, "context_close:*")`.
4. The `member_has_capability` function (lines 374-391) does `rsplit_once(':')` to split into resource + action, then checks ceiling_strings.
5. Within WASM this is self-consistent: ceiling has `"context_close:*"`, check asks for `"context_close:*"`, match succeeds.
6. However: if a UCAN token is minted by a non-WASM bridge with capability `"scp:ctx:{id}/context:close"` (scp-core format), and that token is validated by the WASM bridge, the capability match will FAIL because WASM expects `"context_close"` not `"context:close"`.
7. Conversely, a WASM-minted token with `"context_close:*"` validated by scp-core will not match `Capability::ContextClose`.

**Key Insight:** The capability string format is a protocol-level identity -- it must be identical across all bridges. The WASM bridge uses underscore-separated names (`context_close`, `tool_register`, `tool_invoke`, `member_invite`, `member_remove`, `governance_propose`, `governance_vote`, `role_assign`) while scp-core uses colon-separated names (`context:close`). This breaks cross-bridge UCAN delegation chains entirely.

**Impact:** HIGH -- Cross-bridge capability tokens are silently incompatible. A UCAN minted on one platform cannot authorize actions on another. Breaks the protocol's interoperability guarantee.

**Recommended Fix:** Align WASM capability strings with scp-core's format. Either import the canonical string representations from scp-core's `Capability` enum documentation, or define a shared constant set in `scp-ffi-common`. All bridges must produce and consume identical capability URIs.

---

### BLACK-305: WASM Nonce Replay After Page Reload (HIGH)

**Adversary:** AP-1 (Malicious SDK Consumer)
**Objective:** Replay UCAN tokens after browser page reload.

**Campaign:**
1. Attacker obtains a valid UCAN token (e.g., by intercepting one in transit or receiving one legitimately).
2. The UCAN is validated by the WASM bridge. Nonce `"1710000000000-abc123"` is recorded in the `WasmContextManager`'s `HashSet<String>` via `ucan_record_nonce`.
3. User navigates away or refreshes the page. WASM module unloads.
4. Page reloads. WASM module re-initializes. The `thread_local! { RefCell<WasmContextManager> }` is empty -- all nonce history is lost.
5. Attacker replays the same UCAN token. Nonce `"1710000000000-abc123"` is not in the empty set. Validation succeeds.
6. The token's time bounds are the only remaining protection. If the token has not yet expired (up to 24 hours), the replay succeeds.

**Key Insight:** The nonce format includes a timestamp prefix (`{unix_millis}-{random_hex}`), but the WASM bridge does not perform freshness validation on the timestamp component. It only checks set membership. Combined with the 24-hour max token lifetime, there is a large window for replay. Non-WASM bridges use `NonceTracker` backed by `DashMap` which persists across requests (but not across process restarts -- similar vulnerability exists but is less exploitable because server processes restart less frequently than browser pages).

**Impact:** HIGH -- Full UCAN replay for up to 24 hours after page reload. Attacker can reuse authorization tokens for any capability the original token granted.

**Recommended Fix:**
1. Persist nonce sets to browser storage (IndexedDB via the `JsStorage` injection point).
2. Add timestamp freshness validation: reject nonces whose timestamp component is older than a configurable threshold (e.g., 5 minutes).
3. Consider reducing MAX_EXPIRY_SECS for browser contexts where persistence is unreliable.

---

### BLACK-306: UniFFI Uses BridgeDidResolver Not DispatchDidResolver (HIGH)

**Adversary:** AP-3 (Cross-Bridge Exploit Developer)
**Objective:** Present a forged DID document on mobile platforms that would be rejected on other platforms.

**Campaign:**
1. Attacker examines DID resolver usage across bridges:
   - PyO3: uses `DispatchDidResolver` which delegates to `IdentityBackedDidResolver` (full BEP44 sig verification, self-certification, sequence tracking, downgrade prevention).
   - NAPI: uses `DispatchDidResolver` (same full verification).
   - WASM: uses local `resolve_public_key` (extracts Ed25519 pubkey from `did:dht:z{zbase32}` -- format check only, no document verification).
   - UniFFI: uses `BridgeDidResolver` directly (`/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-ffi/uniffi/src/bridge.rs` line 3471).
2. `BridgeDidResolver` (in `scp-ffi-common/src/resolvers.rs`) performs string-only DID parsing: it decodes the zbase32 suffix to extract the public key bytes, but does NOT:
   - Verify BEP44 signatures on the DID document
   - Check self-certification (public key matches DID)
   - Track sequence numbers (no downgrade prevention)
   - Validate the DID document structure
3. Attacker crafts a `did:dht:z{zbase32(attacker_pubkey)}` DID. On UniFFI (iOS/Android), the UCAN signed with the attacker's key passes validation because `BridgeDidResolver` trusts the zbase32-encoded key directly.
4. On PyO3/NAPI, the same DID would fail if the IdentityBackedDidResolver queries the DHT and finds no valid BEP44 record.

**Key Insight:** Mobile platforms (iOS, Android) are the highest-value targets for identity spoofing because they have the weakest DID verification. The `BridgeDidResolver` is designed as a fallback for when the full resolver infrastructure is not initialized, but UniFFI uses it as the primary resolver.

**Impact:** HIGH -- Mobile platforms accept DIDs that desktop/server platforms would reject. Self-signed DIDs (where the attacker controls the keypair that the DID encodes) pass UCAN validation on mobile without any DHT or document verification.

**Recommended Fix:** Initialize and use `DispatchDidResolver` in UniFFI, matching PyO3 and NAPI. Call `runtime::init_did_resolver()` during identity creation, and pass the `DispatchDidResolver` to UCAN validation context instead of `BridgeDidResolver`.

---

### BLACK-307: WASM CID Computation Diverges from scp-core (HIGH)

**Adversary:** AP-3 (Cross-Bridge Exploit Developer)
**Objective:** Bypass token revocation by exploiting CID format differences.

**Campaign:**
1. Attacker obtains a UCAN token and it is revoked on a non-WASM platform (e.g., NAPI server-side).
2. scp-core's `compute_revocation_cid` (`/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-core/src/crypto/ucan/revoke.rs` lines 608-615) computes: `hex(SHA-256(encoded_token))` -- a 64-character hex string.
3. WASM's `compute_revocation_cid` (`/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-ffi/wasm/src/ucan.rs` lines 206-213) computes: `hex(SHA-256(encoded_token))` -- same algorithm. These DO match.
4. However, WASM also has `compute_token_cid` (line 595-598) which computes: `"bafyrei" + hex(SHA-256(encoded_token))` -- prefixed with a CIDv1 multicodec stub.
5. If any code path in WASM uses `compute_token_cid` instead of `compute_revocation_cid` for revocation checking, the CID formats will diverge: `"bafyrei{hex}"` vs `"{hex}"`.
6. The WASM `ucan_validate` function (line 422) correctly uses `compute_revocation_cid` for the revocation check. But the existence of a second CID function with a different format is a maintenance hazard.

**Key Insight:** Currently both WASM and scp-core use the same hex-only format for revocation CIDs. The `compute_token_cid` function with the `bafyrei` prefix appears to be used for content addressing (not revocation), but its existence creates confusion. The WASM bridge CLAUDE.md explicitly documents: "compute_token_cid uses bafyrei prefix, scp-core compute_cid differs" suggesting awareness of the divergence. If cross-bridge CID comparison is ever needed for content addressing, this will break.

**Impact:** HIGH for content addressing interop. Currently MEDIUM for revocation (both use the same algorithm). Maintenance hazard.

**Recommended Fix:**
1. Either remove `compute_token_cid` from WASM if it is unused, or align its format with scp-core's content CID computation.
2. Add a cross-bridge conformance test that verifies CID computation produces identical output for the same input across all bridges.
3. Document which CID function is used for which purpose.

---

### BLACK-308: Error Code Divergence Enables Bridge Fingerprinting (MEDIUM)

**Adversary:** AP-1 (Malicious SDK Consumer)
**Objective:** Fingerprint which bridge implementation a target is using, then craft bridge-specific exploits.

**Campaign:**
1. Attacker sends an invalid UCAN token to the target application.
2. Observes the error code in the response:
   - NAPI returns `SCP-PERM-3001` for `UcanError` (`/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-ffi/napi/src/error.rs` line 261).
   - WASM returns `SCP-PERM-3000` for permission errors (`/Users/alec/Developer/limn/scp/.worktrees/integration/crates/scp-ffi/wasm/src/error.rs` line 79).
   - UniFFI returns `SCP-PERM-3002` for UCAN validation failure (`bridge.rs` line 3493).
   - PyO3 returns its own code.
3. Attacker now knows which bridge is in use and tailors subsequent attacks:
   - WASM target: exploit nonce replay after reload (BLACK-305)
   - UniFFI target: exploit weak DID resolver (BLACK-306)
   - NAPI target: exploit context_close DID validation gap (BLACK-302)

**Key Insight:** The error code numbering is not a security mechanism -- it is designed for developer debugging. But divergent codes for semantically identical operations create an unintended oracle. The TypeScript SDK parses error codes to create typed exceptions, so the codes are exposed to application code and potentially to end users.

**Impact:** MEDIUM -- Information disclosure that enables targeted attacks. Not directly exploitable but reduces attacker effort.

**Recommended Fix:** Define canonical error codes in `scp-ffi-common` (or `.docs/standards/sdk-common.md`) and use them consistently across all bridges. Same operation, same error code, regardless of bridge.

---

## Trust Assumption Violations

### TA-1: "All bridges validate inputs at the FFI boundary"

**Assumption:** All public FFI functions call `scp_ffi_common::validate::*` functions before processing.
**Violation:** NAPI `context_close` skips `validate_did()`. NAPI `context_subscribe` discards `identity_did` entirely.
**Impact:** Inconsistent validation surface across bridges.
**Mitigation Feasibility:** Easy -- add the missing validation calls.

### TA-2: "Capability strings are protocol-universal"

**Assumption:** A UCAN token's capability URI has the same meaning on every bridge.
**Violation:** WASM uses `"context_close:*"` format; scp-core uses `"context:close"` format. These are different strings that will never match.
**Impact:** Cross-bridge delegation chains fail silently.
**Mitigation Feasibility:** Moderate -- requires updating WASM's capability string constants and the `member_has_capability` matching logic.

### TA-3: "Nonce replay prevention is durable"

**Assumption:** Once a UCAN nonce is recorded, the same nonce cannot be used again.
**Violation:** WASM nonce set is in-memory (`HashSet<String>` in thread_local). Browser page reload clears all state.
**Impact:** Full UCAN replay for up to 24 hours in browser contexts.
**Mitigation Feasibility:** Moderate -- requires IndexedDB persistence and freshness validation.

### TA-4: "DID resolution provides equivalent verification on all platforms"

**Assumption:** A DID that passes validation on one bridge will pass (or fail) identically on all bridges.
**Violation:** UniFFI uses `BridgeDidResolver` (string-only parsing); PyO3/NAPI use `DispatchDidResolver` (full BEP44 + self-cert + sequence tracking). WASM uses local `resolve_public_key` (format extraction only).
**Impact:** Mobile platforms accept DIDs that server platforms would reject. Identity trust is platform-dependent.
**Mitigation Feasibility:** Moderate -- requires initializing DispatchDidResolver in UniFFI; Hard for WASM (cannot depend on scp-core).

### TA-5: "Error responses do not leak implementation details"

**Assumption:** Error codes and messages are consistent across bridges, revealing nothing about the implementation.
**Violation:** Different bridges return different error codes for the same operation (3000 vs 3001 vs 3002 for UCAN errors), enabling bridge fingerprinting.
**Impact:** Attacker can identify the bridge implementation and target bridge-specific vulnerabilities.
**Mitigation Feasibility:** Easy -- centralize error code definitions.

---

## Creative Abuse Scenarios

### CA-1: Cross-Bridge Token Laundering

An attacker mints a UCAN token on the WASM bridge (which uses `compute_token_cid` with `bafyrei` prefix for content addressing). The token's content CID in WASM-originated audit logs will not match the CID computed by scp-core for the same token. This creates phantom tokens that appear in one system's audit trail but cannot be cross-referenced in another.

### CA-2: Capability Escalation via Format Confusion

An attacker crafts a UCAN with capability string `"context_close:*"` (WASM format). When validated on WASM, this grants context close permission. When the same token is forwarded to a non-WASM bridge for cross-bridge verification, scp-core does not recognize `"context_close:*"` as `Capability::ContextClose` -- it falls through to `Custom("context_close:*")`. If the ceiling contains `Custom` capabilities, the attacker might gain permissions that were not intended.

### CA-3: Nonce Harvesting via Subscribe

Since NAPI `context_subscribe` discards the `identity_did` without validation, an attacker can call subscribe in a loop with different DID strings to probe which context IDs are valid (based on whether the state check passes) without needing a valid identity. This is a context existence oracle with zero authentication cost.

---

## What Resists Attack

### Shared Validation Module (scp-ffi-common)
The `validate.rs` module in `scp-ffi-common` is used by all 4 bridges and provides consistent input validation (max lengths, control character rejection, format checks). When it IS called, it is effective.

### scp-core UCAN Pipeline
When the full 11-step validation pipeline in scp-core is invoked (PyO3 and NAPI), it is thorough: Ed25519 signature verification, delegation chain traversal, root issuer check, audience validation, capability matching with trailing-slash protection, attenuation enforcement, ceiling check, nonce replay, revocation check, and time bounds. This pipeline is well-tested.

### Key Material Redaction
All 4 bridges implement `Debug` redaction on key material types, preventing accidental key exposure in logs.

### ContextManager Authorization
The shared `ContextManager` provides a second line of defense for authorization. Even when a bridge function skips its own validation (e.g., NAPI `context_close`), the ContextManager checks capabilities before executing the operation.

### Constant-Time Token Comparison
Bearer tokens and bridge secrets use `subtle::ConstantTimeEq` across all bridges, preventing timing side channels.

### WASM Ed25519 Verification
The WASM bridge's Ed25519 signature verification implementation is cryptographically sound, using `ed25519-dalek` with proper key extraction from DID strings.

---

## Recommended Threat Model Updates

1. **Add "cross-bridge interoperability" as a threat category.** The current threat model appears to treat each bridge independently. Attacks that exploit divergent behavior between bridges are a distinct class.

2. **Add "browser state lifecycle" as a threat category for WASM.** Page reloads, tab crashes, and service worker termination are adversary-accessible state reset events. Any security property that depends on in-memory state is vulnerable.

3. **Add "DID resolver parity" as a security invariant.** Document that all bridges MUST provide equivalent DID verification strength, or explicitly document and accept the risk of weaker verification on specific platforms.

4. **Add "capability string canonicalization" as a protocol requirement.** The capability URI format must be defined once and used identically everywhere. Currently it is implicit in the `Capability` enum's string representation.

5. **Add cross-bridge conformance tests.** For every security-critical computation (CID, capability matching, nonce format, error codes), add tests that verify identical behavior across all 4 bridges for the same input.
