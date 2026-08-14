---
name: govexec-identity-did-removal
description: Review of fix/1866 follow-up commits removing identity_did from governance direct-execute across all 4 bridges + 4 SDKs and adding WASM strict proposal_id hex validation
metadata:
  type: project
---

Reviewed `git diff c9db30486..b297553c9` on branch fix/1866-direct-execute-trust (PR #1866 follow-ups). Verdict: APPROVED with one minor finding.

The fix removes the divergent `identity_did` param from governance direct-execute so the signature is uniform `(handle, proposal_id_hex)` everywhere, and adds strict WASM proposal_id hex validation.

**Why:** `identity_did` was a divergent, load-bearing-only-on-WASM param. On native bridges it was accepted then dropped (`let _ = &identity_did`); on WASM it was passed as the consequence subject while the executor was the proposer — a native↔WASM divergence. The fix resolves BOTH executor and consequence subject from the tracked proposal's proposer inside the runtime on all bridges.

**How to apply:** Verified clean — `identity_did` fully gone (no `let _ = &identity_did` in PyO3/NAPI/UniFFI; no dead param). Uniform shape confirmed across PyO3 governance_execute, UniFFI governance_execute, NAPI contextExecuteGovernanceAction, WASM context_execute_governance, and all 4 SDK wrappers + their internal bridge layers. Swift UniFFI binding (ScpBindings.swift) regenerated — checksum 14006→15010 proves regeneration. pipeline_wiring.rs asserts `!entry_sig.contains("identity_did")`. capability-matrix note updated. All native bridges route through `GovernanceCommand::ExecuteGovernanceAction { context_id, proposal_id }` (id-only payload).

**Minor finding (error-code parity):** WASM malformed-proposal-id now emits `SCP-VALID-7000` (via shared `validate_proposal_id_hex` → ScpWasmError From impl), but all three native bridges (PyO3/NAPI/UniFFI `parse_*_proposal_id`) emit `SCP-CTX-2040` for the identical condition. No automated cross-bridge error-code parity gate exists. CTX_2040's own doc-comment is "WASM context operation error" yet WASM no longer uses it for this. Worth unifying but low severity (no gate enforces it; both are Validation-class).

Pattern: UniFFI/NAPI/PyO3 share id-parser helpers with CTX_2040; WASM uses the scp-ffi-common validate.rs ValidationError path which always maps to VALID_7000. When adding shared common validators, the error code diverges from the per-bridge inline parsers.
