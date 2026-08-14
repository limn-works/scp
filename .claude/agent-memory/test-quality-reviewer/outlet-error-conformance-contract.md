---
name: outlet-error-conformance-contract
description: SCP-OUT-031 §5.4.4 OutletError cross-SDK conformance gate — fixtures + Rust test; what it gates well and its coverage holes
metadata:
  type: project
---

# SCP-OUT-031 OutletError conformance (cross-SDK contract)

Files: `crates/scp-testing/tests/integration/outlet_error_conformance.rs` (own `[[test]]` target, Cargo.toml:271) + `tests/conformance/vectors/outlet_error_fixtures.json` (69 valid + 8 malformed). Gates registry `crates/scp-protocol/src/context/outlets/error_codes.rs` + `errors.rs`.

**Why:** PR-1 of a 4-PR chain; the 4 SDKs (PR-2/3/4) validate against these fixtures. Contract rigor is load-bearing.

**Strong core (replicate):**
- Malformed corpus is gold-standard: genuine shape mismatch double-guarded (`assert_ne!(class.expected_detail(), detail.kind())` PRE-check) + asserts the SPECIFIC `DetailShapeMismatch` rejection (not "some error") + reaches the detail gate only after code/slug/class/membership pass. Non-vacuous.
- Registry pinned against `CODE_*`/`SLUG_*` consts via glob-import → a RENAME breaks compilation.
- `ALL_CODES` (enumerable array) → new CODE without fixture is caught by `every_allocated_code_has_a_valid_fixture`.
- Fully deterministic: `include_str!` (compile-time), BTreeSet/BTreeMap iteration, no time/rand/net/fs-at-runtime. Excellent flakiness profile.

**Update (commit ed4bb5353): must-fix items CLOSED, verified green (20 registry unit + 6 conformance tests).**
- Hole #2 (slug drift) FIXED soundly: `pub const ALL_SLUGS: [&str; 69]` added; two unit tests — `all_slugs_resolve_through_slug_to_class` (ALL_SLUGS ⊆ slug_to_class, unique) + `all_slugs_lists_exactly_the_defined_slug_constants` (source-parses `concat!("pub const ","SLUG_")`, set-equates to ALL_SLUGS — genuinely catches a SLUG_* const omitted from ALL_SLUGS; concat! avoids self-match). Conformance now set-equates BOTH fixtures' slug set AND EXPECTED_PAIRS against ALL_SLUGS. Full gate chain: new SLUG_* → source-parse fails → add to ALL_SLUGS → resolve test fails → add to slug_to_class → conformance fails → add fixture+EXPECTED_PAIRS. A registry slug without a fixture now FAILS by construction, against the enumerable registry domain (not the hand-copy).
- Doc overclaims FIXED: "byte-for-byte" → "structural/field-level"; explicit "Not golden wire bytes" para defers golden bytes+HMAC to PR-2.
- Hazards #3/#4 FIXED: separate `supplementary` array (2 fixtures, EXCLUDED from the 69-slug bijection). ExecutionPanic panic_location_hash=[0..31] (serde_hash_32 = serde_bytes; JSON int-array is the correct transport form); elapsed_ms=2^53+1. `supplementary_hazard_fixtures_round_trip_with_exact_field_fidelity` asserts EXACT values — non-vacuous.
- Bundled taxonomy change (spec-backed, provenance intact): `protocol.invalid-grant`/6100 → `input.invalid-grant`/6120 (Input class, per §5.4.5 estimate-exceeds-bound precedent). Flows spec §5.4.4 → error_codes.rs → PRD AC[13] → fixture → test.
- REMAINING (tracked in PRD auditNote as PR-2, NON-blocking): golden serialized-envelope bytes + expected HMAC per fixture; PRD now correctly defines SDK "round-trip" as envelope-reconstruction-from-descriptor, NOT wire-blob deserialization, and notes RetryPolicy Duration serializes as {secs,nanos}.

**Original coverage holes (ranked) — for history:**
1. NO golden wire-bytes / golden HMAC output → now tracked as PR-2 deliverable.
2. Registry slug ADDITIONS not gated (only renames) → CLOSED via ALL_SLUGS (above).
3. `ExecutionPanic { panic_location_hash: [u8;32] }` (serde_hash_32) untested → CLOSED via supplementary.
4. No large-u64 boundary fixture → CLOSED via supplementary (2^53+1).
5. `RetryPolicy::After` never exercised; RelayUrlKind WsLoopback/Unknown unused → still open, lowest value, not raised as must-fix.

Recurring lesson: for a "cross-SDK wire contract," input-vectors + per-SDK re-construction prove self-consistency, NOT cross-SDK wire identity. A real wire contract needs golden serialized OUTPUT bytes and an enumerable registry-domain (not a hand-copied pair list).
