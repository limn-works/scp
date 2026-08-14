---
name: sdk-coverage-parity-trust-port
description: Crypto review of fix/sdk-coverage-fail-closed-and-parity (2026-06-19) — TS trust-eval port Layer-1 UCAN classifier, MLS provider doc fixes, ADR-051 pre-rotation custody provider
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity crypto review (2026-06-19, HEAD 8c0713499)

SOUND overall. No CRITICAL/HIGH. Findings are LOW/informational.

## TS trust-eval Layer-1 UCAN classifier (bindings/typescript/src/trust.ts)
- Faithful 1:1 port of bindings/python/scp_sdk/trust.py (`_classify_ucan_error`, `_PASSED_BEFORE`, `_extract_core_error`). Same prefix sets, same match order, same passed-before map.
- Model: UCAN pipeline is SEQUENTIAL + short-circuits at first failure → from WHICH step failed, infer which earlier CapabilityValidation fields passed.
- VERIFIED against crates/scp-protocol/src/crypto/ucan/validate.rs:524-609: order is parse(1)→sig(2)→chain(3-7)→cap/ceiling(6/8)→nonce(9)→revocation(10)→expiry(11), all `?` short-circuit. Revocation IS after nonce + before expiry; expiry IS last. Claim holds.
- Error format: both NAPI (napi/src/error.rs:409) and WASM (wasm/src/error.rs:76) + PyO3 (src/error.rs:157) emit `[{code}] permission error: {message} — <advice>` with advice em-dash = U+2014 (confirmed byte). TS `mapBridgeError` (errors.ts:265) preserves full message + routes SCP-PERM- → UcanPermissionError. `__extractCoreError` strips prefix + U+2014 advice correctly. Chain intact on production NAPI path.
- KEY SOUNDNESS NUANCE (not a bug): Layer-1 booleans are INFERRED from string-parsed error category, NOT independently re-verified. A field=true means "this step did not short-circuit," not "cryptographically re-checked in TS." This is by design — Rust core is the authority; SDK only classifies. Acceptable because TS never re-does crypto.
- LOW: classifier is a denylist of error-string prefixes. If Rust adds a new UcanError variant/message, it falls to "unknown" → _PASSED_BEFORE[unknown]=empty set → ALL Layer-1 fields false = FAIL-CLOSED (conservative, correct). String drift degrades gracefully, never opens. Same property in Python. No cross-impl test pins the prefix strings against the actual Rust Display strings — a KAT would harden this but absence is not a vuln (fail-closed).
- Step-3 chain walk recursively checks parent sig/expiry/revocation, wrapped as `delegation chain broken:` → classified conservatively as "signatures" (only tokensValid passed). Correct — avoids optimistic true on leaf checks that never ran.

## MLS provider doc fixes (crates/scp-runtime/src/crypto/mls/provider.rs)
- Pure doc-comment corrections, zero algorithmic change. MlsCryptoProvider IS a struct w/ inherent impls (no trait) — confirmed (struct@379, impl@476/682, no trait). Removed stale "default implementation / override this / trait indirection" language; updated ContextManager→ADR-049 actor refs. All claims accurate incl. "sig verification deferred to receive handler via key_resolver after open()."

## Identity lifecycle methods (bindings/typescript/src/scp.ts)
- 5 thin forwarders (identityRotateKey/Migrate/AddAgentKey/RotateAgentKey/RemoveAgentKey). Pass opaque `_rawHandle` to bridge, re-wrap result. NO key material crosses JS heap — all crypto in Rust core. Correct design.

## ADR-051 pre-rotation custody substrate isolation (Proposed)
- Cryptographically sound design. Fixes spec §9.7.4.1 §3 violation: callback-custody pre-rotation key currently minted into InMemoryPreRotationCustody co-resident w/ operational key in same process memory.
- SEPARATE PreRotationCustodyProvider interface (not new methods on KeyCustodyProvider) is the RIGHT mechanism — §3 forbids same provider/auth-flow; separate provider enforces structurally not by doc. Rejected-alternatives section correctly rejects the combined-provider option.
- Interface {generate, public_key, import_seed_bytes, consume} is complete for the reveal/commitment/migration flow. generate() keeps keygen INSIDE substrate (correct for HSM/SE — never marshal raw bytes). Zeroizing on import_seed_bytes/consume at FFI boundary.
- GAP TO FLAG IN REVIEW (LOW, design-stage): import_seed_bytes + consume DO marshal raw 32-byte seed across FFI for software/offline backends — unavoidable for those, but ADR should state the seed is Zeroizing end-to-end AND that consume() must be atomic destroy-and-export (it says "atomically" — good). The conformance test "created identity's pre-rotation key NOT recoverable from operational provider" is the right invariant.
- Open Q3 (spec clause) correctly defers to artifact-flow: spec change before code if §9.7.4.1 needs callback sub-clause.
