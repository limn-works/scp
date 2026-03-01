# WASM UCAN Validation Is Structurally Partial — Document It Accurately

**Rule**: When a validation pipeline is partially implemented due to platform constraints, the docstring must accurately describe what IS checked, not claim full validation. False documentation of security properties is worse than no documentation.

**Context (SCP-218)**: The WASM bridge `ucan_validate` docstring claimed "Performs full UCAN validation: signature verification, time bounds checking, delegation chain traversal, attenuation enforcement, nonce replay detection, and capability matching." In reality, the implementation performs: JWT format check, base64/JSON decode, expiry check, capability string match, and revocation check. Missing: Ed25519 signature verification, delegation chain traversal, root issuer check, audience DID validation, attenuation enforcement, ceiling check, nonce replay detection.

**Why scp-core validation cannot be used in WASM**: `scp-core` depends on `tokio = { features = ["full"] }` which requires a multi-thread runtime. `wasm32-unknown-unknown` cannot compile this. The WASM bridge must re-implement validation logic using only WASM-compatible crates.

**What full WASM validation requires**:
- Ed25519 signature verification: requires `JsKeyCustody` wiring (SCP-214 analog for WASM) — WebCrypto API via injected JS callback
- Nonce replay detection: `WasmContextRuntime` already has `revoked_tokens: HashSet<String>`; a nonce set can be added
- Audience validation: check `payload["aud"]` against the presenting identity DID (parameter already available)
- Ceiling check: `WasmContextRuntime` already has `ceiling_strings: HashSet<String>` — use it
- Delegation chain: requires proof token resolution — possible with in-memory HashMap, matching PyO3 bridge pattern

**Wildcard capability matching bug**: `can_str == "*"` must only match within the correct resource scope. Check `with_str` first, then allow wildcard on `can`. A token granting `scp:ctx:A/*` must not pass validation for `scp:ctx:B/messages:write`.

**Missing-exp handling**: `exp` must be treated as optional (non-expiring token) not an error. The UCAN spec and scp-core both allow non-expiring tokens.

**Lesson**: Story acceptance criteria for WASM bridges that say "calls scp-core X-step pipeline" cannot be met literally. The PRD story must be updated to define the WASM-specific validation scope: which steps are implemented structurally, which are deferred to key custody wiring, which are architectural limitations. Mark deferred steps with `// Stub — see SCP-NNN` referencing the story that will wire them.
