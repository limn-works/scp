---
name: trust-error-classifier-f6caeb5dd
description: TS trust.ts UCAN error-prefix classifier + check-sdk-coverage fail-closed gate + __setBridgeForTests; CLEAN review @ f6caeb5dd
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ f6caeb5dd (reviewed 2026-06-20) — CLEAN

Branch added: fail-closed SDK coverage gate, TS trust-error classifier, __setBridgeForTests hook,
5 identity lifecycle wrappers, Python parity (discover_contexts, economy_verify_payment_receipts),
ADR-051 (Proposed). No CRITICAL/HIGH. Only standing item = pre-existing MEDIUM (ADR-051).

## trust.ts error-prefix classifier — SAFE pattern (reusable)
`__classifyUcanError`/`__extractCoreError` classify a UcanError Display string into pipeline stage.
Safe BECAUSE: (1) every discriminator is a FIXED prefix at the START of the Display text; all
attacker-controlled interpolation (`{0}`, `{att.with}`, `{kid}`) lands AFTER a fixed colon-literal
(e.g. `nonce reused: <x>`, `unparseable capability URI in attestation: <att.with>`). (2) classifier
uses `String.startsWith(prefix)` — attacker TAIL data can't forge a different stage's prefix.
(3) more-specific `malformed token: DID not found` checked before generic `malformed token:`, but the
only fully-attacker-controlled `malformed token: {0}` is the step-6 `unparseable capability URI in
attestation: <att.with>`; even att.with="DID not found: x" still startsWith the capability prefix →
classified `ceiling` not `signatures`. (4) em-dash (U+2014) truncation in __extractCoreError only
trims the TAIL → never changes a startsWith result.
CRUCIAL: classifier output (CapabilityValidation) is ADVISORY, not an authz gate. Enforcement is
scp.ucanValidate (Rust 11-step pipeline, throws). Misclassification = mislabeled diagnostic field,
not access grant. UcanError Display strings: crates/scp-protocol/src/crypto/ucan/mod.rs.
LESSON: when reviewing error-string classifiers, verify discriminators are START-anchored fixed
prefixes and matching is startsWith (not includes/indexOf). includes() would be exploitable.

## __setBridgeForTests — triple-isolated (NODE_ENV guard is weakest layer)
Target _nativeBridgeForScp is a module-private WeakMap. Reachability from package consumers blocked
INDEPENDENTLY of NODE_ENV by: (a) not re-exported from index.ts; (b) package.json `exports` has only
"." with no subpath/wildcard → Node exports-encapsulation forbids deep import of dist/internal/bridge.
NODE_ENV==="production" guard is defense-in-depth #3. Note: guard reads globalThis.process?.env?.NODE_ENV
→ in browser/WASM process undefined → guard is a no-op (does NOT throw); fine because no prod browser
path reaches the symbol. Pattern to check on any test-only injection hook: index re-export + exports map
+ runtime guard.

## check-sdk-coverage.py fail-closed gate
Removed suffix/substring matching (~23 fabricated names had passed via verb collision). Added
all_exempted_ops check: if every true-SDK for an op uses coverage_exemptions and none statically
verified → hard ERROR. Sound for honest-drift detection; NOT a defense vs malicious matrix committer
(who can also edit the gate/ALIASES/source) — correct trust model; gate is a CLAUDE.md protected file.
Residual: a coverage_exemptions prose reason is faith-based when ANOTHER sdk is verified (partial-row
fabrication undetectable). Low risk given all-exempted backstop.

## ADR-051 (Proposed) — MEDIUM pre-existing, NOT introduced by this branch
Callback-custody (mobile App-Attest/Keychain/Keystore) path mints PRE-ROTATION recovery key into
InMemoryPreRotationCustody → co-resident in process memory with operational handles → violates spec
§9.7.4.1 §3 substrate isolation. Process-memory dump compromises both. Branch only DOCUMENTS + proposes
fix (separate PreRotationCustodyProvider interface). Migration-reveal already fail-closes
(import_ed25519_signing_key → PlatformError::Unsupported). Track until implemented; don't ship-and-forget.

## MLS provider.rs change = DOC-COMMENT-ONLY (no security weight)
crates/scp-runtime/src/crypto/mls/provider.rs diff is entirely ContextManager→actor doc-comment
rewording. No executable change.
