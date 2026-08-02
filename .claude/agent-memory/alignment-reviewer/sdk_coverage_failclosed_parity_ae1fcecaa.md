---
name: sdk-coverage-failclosed-parity-ae1fcecaa
description: Review of fix/sdk-coverage-fail-closed-and-parity (HEAD ae1fcecaa) — coverage gate hardening + cross-SDK parity additions; ALIGNED
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` (HEAD ae1fcecaa, base 0c8f0b065). Reviewed 2026-06-20. Verdict: ALIGNED.

Two coupled efforts:
1. **`scripts/check-sdk-coverage.py` made fail-closed** — a `true` matrix entry with no statically-matchable SDK symbol is now an ERROR (was a silent pass). Escape hatch `coverage_exemptions` is bounded: non-empty reason required + all-exempted guard (at least one SDK must be statically verified, blocking prose-only bypass). Suffix/substring matching removed (had let ~23 fabricated names pass). Added to CLAUDE.md enforcement-file list. Sound + bounded per CLAUDE.md tenet. Gate self-tests in `scripts/test_check_sdk_coverage.py` (4 pass). Gate run: 221 ops, 0 errors, 1 bounded exemption (Kotlin `addRelay`, generated-binding tree-sitter blind spot, verified in other 3 SDKs).
2. **Cross-SDK parity additions** (all wrap pre-existing bridge exports — genuine wiring, not stubs):
   - TS `evaluateTrust` four-layer model ported from Python `scp_sdk.trust.evaluate_trust`. Field-for-field camelCase mirror of the Python dataclasses; identical `__PASSED_BEFORE` UCAN-stage map and `ToolInvoked` Layer-2 logic. Intentional documented divergence: TS takes a `Context` handle, Python takes `context_id` string (NAPI/WASM bridge requires handle) — legitimate per-SDK idiom.
   - Python `discover_contexts` added (TS already had `discoverContexts`); wraps PyO3 `context_discover`.
   - Python SDK wrapper + TS `economyVerifyPaymentReceipts` for the existing PyO3/NAPI `economy_verify_payment_receipts` export.

`crates/scp-runtime/src/crypto/mls/provider.rs` change (67 lines) is **100% doc-comment-only** — stale "default impl / override this / ContextManager handles X" trait-language updated to post-ADR-049 reality (inherent methods, per-context actor ownership). Zero logic change. Slightly bundled vs atomic-commit ideal but harmless.

Minor finding (non-blocking): TS `Identity.rotationEventJson` docstring cites "§3.2.1 (Identity Key migration)" but §3.2.1 is "Key Custody Migration Protocol"; identity-key rotation event is governed by ADR-003 §4b / §9.12 / §9.7.4.1. Citation imprecision only.

ADR-051 (Proposed) added in same branch — pre-rotation custody substrate isolation; it is design provenance for a LARGER future workstream surfaced by the cross-SDK audit, NOT implemented here. Status "Proposed" with open questions; correct per artifact-flow (design before code).
