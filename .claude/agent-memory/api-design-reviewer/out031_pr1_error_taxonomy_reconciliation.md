---
name: out031-pr1-error-taxonomy-reconciliation
description: SCP-OUT-031 PR-1 §5.4.4 OutletError cross-SDK error-taxonomy reconciliation review — DOA-permanent class/name decisions before 4 SDKs implement
metadata:
  type: project
---

SCP-OUT-031 PR-1 (commit e44055576, branch feat/outlet-031-pr1-fixtures-reconciliation) reconciles the §5.4.4 OutletError wire taxonomy BEFORE the 4 SDKs implement it. Files: .docs/specs/05-contexts.md §5.4.4, crates/scp-protocol/src/context/outlets/error_codes.rs + errors.rs, .docs/prds/outlet.json (SCP-OUT-031/042b), tests/conformance/vectors/outlet_error_fixtures.json (69 valid + 8 malformed), crates/scp-testing/tests/integration/outlet_error_conformance.rs.

Verdict: RESOLVED / APPROVED at commit ed4bb5353 (was NEEDS REVISION at e44055576). Both DOA MAJORs actioned + hardened beyond ask.

Resolution (ed4bb5353): (1) InvalidGrant reclassified Protocol/6100→Input/6120, slug protocol.invalid-grant→input.invalid-grant, parent OutletProtocolError→OutletInputError, fixture detail Protocol{rule}→FieldViolation{field_path:"/grant",violation:"range"}, justified by §5.4.5 input.estimate-exceeds-bound precedent; consistent across spec/error_codes.rs(SLUG_INPUT_INVALID_GRANT+slug_to_class Input arm+module-doc row moved to 6120+ALL_SLUGS)/AC[13]/EXPECTED_PAIRS; negative-assertion test slug_to_class("protocol.invalid-grant")==None; zero residual. (2) All 8 subclasses uniformly Outlet-prefixed (OutletProtocolError…OutletGovernanceError incl the 5 formerly bare); AC adds grep-0 for bare names. (3) Both my observations captured as PR-2 reqs in auditNote (round-trip=envelope-reconstruction not wire-blob; RetryPolicy {secs,nanos}). BONUS hardening they added: ALL_SLUGS enumerable array + all_slugs_resolve_through_slug_to_class test (registry slug w/o fixture fails by construction), and `supplementary` corpus with the 32-byte ExecutionPanic hash + >2^53 u64 fixtures — the exact JS-number precision hazard I flagged as "awkward in one language."

--- Original NEEDS-REVISION findings (superseded, kept for provenance) ---

**Why:** decisions become permanent + must read identically across Python/TS/Swift/Kotlin.

Key findings:
- InvalidGrant class = Protocol/6100 is CONTESTED. Input(6120) is textually more defensible: Input class doc literally says "range violations on input" and FieldViolation detail lists "range" as an example violation tag. TELL: the invalid-grant fixture had to stuff `rule:"query-cost-floor"` (nonsensical) into the Protocol `{rule}` detail because Protocol's shape doesn't describe a zero-grant. DEEPER: InvalidGrant is thrown SDK-side by the Credit() factory BEFORE signing — it never travels the wire, so it's arguably a category error to force it into the outlet-WIRE taxonomy at all; the (code,slug) is just a display label. Slug↔class coupling: §5.4.4 leading-segment=class convention means reclassify-to-Input also requires renaming slug protocol.invalid-grant → input.invalid-grant (else it becomes a 2nd cross-class exception, breaking the spec's "single slug" claim re protocol.interface-spam-cost).
- 8-class names mixed prefixed/bare (OutletProtocolError/OutletTransportError/OutletGovernanceError prefixed for collisions; AuthorizationError/InputError/ExecutionError/OutputError/EconomicError bare). RECOMMEND all-8 Outlet-prefixed for agent-first "one canonical rule": mixed scheme risks silent WRONG-CATCH (agent writes bare `ProtocolError` → catches top-level MLS ProtocolError, not outlet). Only bites Python+TS (Swift/Kotlin use nested enum cases, no collision) so "uniform across 4 SDKs" is already loose.
- Fixture `message` is a PLAINTEXT test-only stand-in, NOT the [u8;32] HMAC wire field; pad_nonce/reg_id are hex strings. So the AC's "deserialize→serialize→assert byte-equal" round-trip is NOT literally satisfiable against this JSON as a wire envelope — PR-2/3/4 must define round-trip as envelope-reconstruction and exclude/rederive message. Rust construct() ignores fixture message entirely (recomputes HMAC).
- RetryPolicy Duration serializes {secs,nanos} (Rust serde idiom) — each SDK must special-case, not a native Duration/millis.
- Registry hygiene (slug under 6100, not new code) = clean, consistent w/ compact many-slugs-per-code philosophy; slug_to_class/default-slug/retry all correct + unit-tested.
