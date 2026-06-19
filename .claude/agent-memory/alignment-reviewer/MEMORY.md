# Alignment Reviewer Memory

## ADR-051 Clockless Reframe Re-Review (2026-06-19) — CHANGES-NEEDED
See [adr051_clockless_reframe_review.md](adr051_clockless_reframe_review.md). Same edit set as 06-18 but velocity CLOCK CUT entirely; ADR retitled clockless. ONE stale ref: phase-2.md:912 "(causal-DAG application-event ordering + median clock)" contradicts ADR title/§6/rejected-alt/specs — self-contradicts within same sentence; FIX=delete "+ median clock". Else CLEAN: all other median/quorum/beacon confined to REJECTED-alt or negating "no convergent clock" framing; frontierRoot retained (DAG-frontier, not clock); CHECKPOINT-V1-interim/V2-end-state coherent; anchored coherent; taxonomy=75; no new #NNNN; cross-refs resolve. POSITIVE: prior 19:593 paymentHistory residual NOW FIXED (19:594). GOTCHA: review target=worktree file, not main repo (main has no "median").

## ADR-051 Causal-DAG App-Event Ordering Review (2026-06-18) — CHANGES-NEEDED
See [adr051_causal_dag_review.md](adr051_causal_dag_review.md). UNCOMMITTED edit set: new ADR-051 + phase-2 (ADR-011 amendment, 2-category exclusion taxonomy) + 07/09/19/25. 1 residual unqualified claim: 19-economic-governance.md:593 `paymentHistory` "retrieves receipts from the context's event log" (pre-existing, untouched; same claim qualified at 211/306/324/333/429 but missed here — PaymentReceipt is local ContextEvent until ADR-051). Else CLEAN: taxonomy=75 (enum+Vector32+PseudonymAnnounced-not-a-variant), §9.8.3 commit-chain-fork vs DAG-concurrent-normal correct, no "all three equally" clock over-claim, all cross-refs resolve, no #NNNN added. Observation: ADR §6 clock unit=u64 ms vs existing §23.16.1 timestamp=u64 sec (impl reconciliation, wire change correctly deferred).

## Event-Log Unification Phase-2 Substrate @ `dc18f5899` (2026-06-18) — APPROVE
See [eventlog_unification_phase2_substrate.md](eventlog_unification_phase2_substrate.md). Branch `feat/eventlog-unification-phase2-substrate` vs base `1c0ccbc7d`. Migrates scp-runtime off free-form-string `SCP-EXPORT-ENTRY:` hash-chain onto canonical RFC 6962 `scp_event_log::tree`. 6/6 ADR-011-Amendment/ADR-050 fidelity items pass. 2 minor: (1) export_import.rs:628-645 STALE comment still says "hash-CHAIN HEAD / pruning-tolerant / front-truncation not neutral" — all false post-substrate (prefix-truncation now rejected); contradicts own rustdoc:453-465 + ADR-050:65. (2) two new `#710` issue-refs in source comments (providers/event_log.rs:124,706) violate no-issue-refs-in-code.

## SCP-1717 + SCP-1718 Round-8 Review at HEAD `6aa83a96d` (2026-05-03) — ALIGNED
See [scp1717_scp1718_round9.md](scp1717_scp1718_round9.md). Round-8 commit `6aa83a96d` (1 commit past round-7 `ad92b17ee`, +115/-14 LOC across 4 files) addressed all 4 round-7 promised follow-ups: (1) Kotlin `IdentityAdvancedBridge.migrate(handle)` bumped from `DeprecationLevel.WARNING` to `DeprecationLevel.ERROR` (Identity.kt:306); (2) docs/examples/kotlin/Identity.kt:70-77 switched from `advanced.migrate(...)` to `advanced.migrateWithRotationEvent(...)` with operability comment about forwarding rotation event JSON; (3) `bind_old_document_to_old_did` (dht.rs:1919-1948) now wraps both `extract_public_key` and `decode_multibase_key` errors in uniform `IdentityError::MigrationVerificationFailed(format!(...))`; (4) Step 0 mismatch error includes 12-byte hex prefixes of `did-derived` vs `document-derived` public keys for triage. NEW regression test `verify_migration_rejects_old_document_with_malformed_vm0_multibase` (dht.rs:4087-4153) locks the `InvalidDidFormat`→`MigrationVerificationFailed` uniformity. Kotlin `IdentityAdvancedBridgeTest` `@Suppress` bumped `DEPRECATION` → `DEPRECATION_ERROR`. All 4 bridges still ship SHA-256 byte-parity. Clippy clean (full CI feature combo). Verdict ALIGNED, 0 blocking, 0 material, 3 informational doc-precision findings CARRIED FORWARD from round-7: (i) `verify_migration` rustdoc `# Verification Steps` (dht.rs:1955-1976) enumerates only steps 1-2; Step 0 / 1b / 1c documented in `# Errors` + `# Caller contract` but not in the steps block; (ii) ADR-003 §4c MODERATE bullet (phase-1.md:418) says "invariants 1-6 enforced" but invariant 7 is always-checked (passes vacuously when no service); (iii) CHANGELOG missing one-line bullet for Kotlin `IdentityAttestation.fromJsonObject` fail-closed behavior. Reusable pattern: Kotlin deprecation level upgrade WARNING → ERROR REQUIRES test `@Suppress` upgrade `DEPRECATION` → `DEPRECATION_ERROR` in the same commit; plain `DEPRECATION` only covers WARNING-level. Round-8 caught this in the same commit.

## SCP-1717 + SCP-1718 Round-7 Review at HEAD `ad92b17ee` (2026-05-10) — ALIGNED, SUPERSEDED
See [scp1717_scp1718_round8.md](scp1717_scp1718_round8.md). Round-7 commit `ad92b17ee` addressed all round-6 findings + minor drifts: (1) `bind_old_document_to_old_did` rustdoc (dht.rs:1907-1918) rewritten to honestly describe self-cert-only scope; (2) `verify_migration` rustdoc (dht.rs:2013-2028) gained `# Caller contract` requiring verified resolution path; (3) MigrationProof/PreRotationProof doc-comments (document.rs:1167-1196) now describe length-prefixed digest `SHA-256(DOMAIN_MIGRATION_V1 || u32_be(len(old_did)) || old_did || u32_be(len(new_did)) || new_did || u64_be(rotated_at))`; (4) ADR-003 §4c renumbered 1-10 (Step 0 self-cert as invariant 1); (5) `build_migration_proof` rustdoc (dht.rs:1441-1460) explicit about digest scope AND defense-in-depth caveat for future PreRotationProof fields; (6) `FileKeyCustody::destroy_key` (file.rs:644-741) standardized lock order (handle_map first, then pseudonym_keys), deferred in-memory map mutation until atomic_write succeeds, typed CustodyError on out-of-bounds desync; (7) regression tests `destroy_key_rejects_out_of_bounds_entry_index` (file.rs:1134) + `verify_migration_rejects_old_document_without_vm0` (dht.rs:4004); (8) Kotlin `IdentityAdvancedBridge.migrate(handle)` `@Deprecated(WARNING)` with `ReplaceWith("migrateWithRotationEvent")` (Identity.kt:299-308); (9) Kotlin `IdentityAttestation.fromJsonObject` fails closed with `IllegalArgumentException` on unrecognized revocation_status JSON shapes (Identity.kt:588-592) + tests; (10) CHANGELOG line 64 now correctly attributes `IdentityMigrateResult` to `migrateWithRotationEvent` (round-6 finding closed). All 4 bridges still ship SHA-256 byte-parity. Clippy clean (full CI feature combo). Verdict ALIGNED, 0 blocking, 0 material, 3 informational doc-precision findings: (i) `verify_migration` rustdoc `# Verification Steps` (dht.rs:1947-1965) enumerates only steps 1-2, not Step 0 — parity-mismatch with ADR §4c 1-10; (ii) ADR-003 §4c MODERATE bullet (phase-1.md:418) says "invariants 1-6 enforced" but invariant 7 is always-checked (just passes vacuously); (iii) CHANGELOG missing one-line bullet for Kotlin `fromJsonObject` fail-closed behavior change. Reusable pattern: when an ADR renumbers N invariants, parity-check every rustdoc step-list, every CHANGELOG bullet, every test name — numbering drift survives if the round's touch-set misses any one of those surfaces. Final-round commit shape (100% doc-precision + regression tests + deprecation hygiene, no new protocol surface) is the canonical "ready to merge after one more clean review" pattern.

## SCP-1717 + SCP-1718 Round-6 Review at HEAD `98d91dcb4` (2026-05-10) — ALIGNED, SUPERSEDED
See [scp1717_scp1718_round7.md](scp1717_scp1718_round7.md). Round-6 commit `98d91dcb4` addressed all round-5 informational drifts: (a) lesson `hash-commitment-preimage-lifetime.md:41` corrected to 3-tuple `(ScpIdentity, DidDocument, PreRotationKeyHandle)` and 3 operational handles; (b) `build_migration_proof` docstring (dht.rs:1442) + `verify_migration` docstring (dht.rs:1936) now correctly describe `u32_be(len(old_did)) || ... || u64_be(rotated_at)`; (c) NEW step-0 defense-in-depth `bind_old_document_to_old_did` helper (dht.rs:1907, called at :2018) before any other invariant; regression test `verify_migration_rejects_forged_old_document` (dht.rs:3913) covers the silent-downgrade attack vector. All 4 bridges still ship SHA-256 byte-parity. Reverse-direction JSON parity tests Some+None arms still pinned. Clippy clean (full CI feature combo). Verdict ALIGNED, 0 blocking, 0 material, 1 informational doc drift: `CHANGELOG.md:64` says Kotlin's `IdentityMigrateResult` is returned by `IdentityAdvancedBridge.migrate` — actual code at Identity.kt:290 has `migrate` returning `Long`; `IdentityMigrateResult` is returned by `migrateWithRotationEvent` (Identity.kt:311). Reusable pattern: defense-in-depth verification helpers should run BEFORE any other invariant when downstream invariants consult caller-supplied auxiliary data (verify_migration consults `old_document.pre_rotation_service()` — step 0 binding ensures the document is bound to old_did first).

## SCP-1717 + SCP-1718 Round-5 Review at HEAD `3408c5820` (2026-05-03) — ALIGNED
One commit past round-4 (`b64c9e350`); round-5 (`3408c5820`) addressed 5 round-4 findings in dht.rs/document.rs/file.rs/wasm identity.rs: (1) `decode_multibase_key` curve-point validation via `VerifyingKey::from_bytes` (mirrors WASM `from_did_inner` gate); (2) `retire_operational_keys_for_migration` tightened to exact-fragment match (`rsplit('#').next()`) across `verification_method`/`authentication`/`assertion_method`; (3) `FileKeyCustody::generate_keypair` lock-ordering parity — `handle_map.lock().await` moved BEFORE `append_entry`, held across append-and-insert; (4) WASM `from_did` doc rewritten to describe both Resolved-insert and Local-preservation branches (impl already preserves `custody_type`/`has_agent_key`/`agent_public_key_multibase` via `or_insert_with`); (5) regression tests for each fix landed (`decode_multibase_key_rejects_non_curve_point`, `retire_operational_keys_for_migration_preserves_unrelated_fragments`, `generate_keypair_concurrent_destroy_does_not_corrupt_handle_map`, `from_did_preserves_existing_local_record`). All 4 bridges still ship SHA-256 byte-parity; reverse-direction JSON parity tests cover Some + None arms. Clippy clean (full CI feature combo). Verdict ALIGNED, 0 blocking, 0 material, 3 informational doc drifts CARRIED FORWARD from round-4 (round-5 only touched dht.rs, did not amend lesson/docstrings): (1) lesson `hash-commitment-preimage-lifetime.md:41` still says `(ScpIdentity, PreRotationKeyHandle)` 2-tuple — impl returns 3-tuple; same line still says "four operational handles" but enumerates THREE (`identity_key`, `active_signing_key`, `agent_signing_key`) — `ScpIdentity` has exactly 3 op handles; (2) `build_migration_proof` docstring at dht.rs:1442 omits length prefixes from digest description (text says `SHA-256("SCP-MIGRATION-V1:" || old_did || new_did || rotated_at)`, code uses `u32(len(old_did)) || old_did || u32(len(new_did)) || new_did`); (3) `verify_migration` docstring at dht.rs:1898 same omission. Reusable pattern: doc-comment drift survives round-after-round if the round's touch-set doesn't include the file containing the prose — explicitly enumerate informational findings' file paths in next-round prompt so they get included.

## SCP-1717 + SCP-1718 Round-4 Review at HEAD `b64c9e350` (2026-05-03) — ALIGNED, SUPERSEDED
One commit past prior round-3 review (`061d9d82e`); round-4 commit `b64c9e350` addressed 8 findings: ADR-003 §4 #1 + CHANGELOG amended to 3-tuple, hard-epoch floor reformulated as standalone invariant 5, STRONG-presence enforcement as invariant 6 (conditional 7-9), Kotlin `IdentityMigrateResult` + `migrateWithRotationEvent` added, WASM `from_did` re-entrancy borrow-split commented, lesson updated to include UniFFI in mirrored list. All 4 bridges still ship SHA-256 byte-parity. Reverse-direction JSON parity tests PLUS `pre_rotation_proof: None` arm pinned. Clippy clean (full CI feature combo). 277 scp-identity / 96 scp-platform / 100 uniffi-lib + 43 uniffi-int / 200 napi-lib / 316 wasm tests pass. Verdict ALIGNED, 0 blocking, 0 material, 4 informational doc drifts: (1) lesson `hash-commitment-preimage-lifetime.md:41` still says `(ScpIdentity, PreRotationKeyHandle)` 2-tuple, (2) same line says "four operational handles" but enumerates three, (3) `build_migration_proof` docstring at dht.rs:1442 omits length prefixes from digest description, (4) `verify_migration` docstring at dht.rs:1875 same omission. Reusable pattern: when an invariant set is renumbered (epoch floor 5→standalone, STRONG-presence as new 6), verify every cite-back chain — CHANGELOG, ADR text, helper docstrings, test names — was updated coherently.

## SCP-1717 + SCP-1718 Round-3 Review at HEAD `061d9d82e` (2026-05-03) — ALIGNED, SUPERSEDED
Three commits past prior review at `f8a8b0967`: `061d9d82e` (round-3 fixes), `f8a8b0967` (round-2 fixes), `c6c33eb5a` (review-roster fixes). 27 commits ahead, 9 behind origin/main; merge base `b64c7fbb1`. All 4 bridges (PyO3, NAPI, UniFFI, WASM) ship `SHA-256(revealed_key)==commitment` byte-parity assertion. `verify_migration` enforces 7 invariants incl. epoch floor `1_700_000_000`. Step 7b retires `#active`/`#agent` operational keys after step 7 publish; step 8 republishes OLD doc with `alsoKnownAs` + `retire_operational_keys_for_migration()`. Layer-1 `rotate_key` test pins `pre_rotation_handle` preservation. Reverse-direction native↔WASM JSON parity test PLUS `pre_rotation_proof: None` arm pinned. Verdict ALIGNED, 0 blocking, 0 material, 4 informational findings (Kotlin SDK shim missing `rotationEventJson` accessor, ADR-003 §4 #1 + CHANGELOG say 2-tuple but impl returns 3-tuple including DidDocument, lesson doc line 27 prose omits UniFFI from "mirrored" list, `create_identity` per ADR §4 #1 returns just `(Identity, PreRotationKeyHandle)` but impl returns `(ScpIdentity, DidDocument, PreRotationKeyHandle)`). Reusable pattern: when CHANGELOG enumerates SDK accessors, verify each named SDK actually exposes it AND check whether sibling SDKs (Kotlin↔Swift via UniFFI, NAPI↔WASM via TypeScript) have parity even when not listed.
## PR #1735 PR-E Enforcement Hardening Review (2026-05-03) — ALIGNED
See [pr_1735_pr_e_review.md](pr_1735_pr_e_review.md). All 4 plan items fulfilled. 2 cleanups: stale `_note` in `bridge-aliases.json:2833` contradicts new §7b registry; `identity_verify_link_attestation_signature` WASM naming divergence not recorded in §7b. 22 incidental §1 cleanups (PyO3 8 + UniFFI 10 free-fn migrations) over allowlisting — strictly stricter than plan asked, consistent with completeness invariant. Pattern: plan-text vs implementation refinement common in enforcement PRs; verify intent preservation, not literal match.

## Phase 4 PR 4 Round-3 Review (2026-04-21) — CLEAN PASS
See [phase4_pr4_round3_review.md](phase4_pr4_round3_review.md). Branch at `d569332d0` (16 commits ahead of c1e037772). All 3 round-2 API-design blockers fixed in `66d0a7ca3`. Round-2 bug-catcher SHIP-BLOCKER (Arc cycle via MCP/suppression) fixed in `d569332d0` via `Arc → Weak` pattern. Verdict: ALIGNMENT PASS, API-DESIGN PASS — shippable. Free-functions-taking-scp count: Python 25, TS 18 (down from ~90). No orthogonal scope in 16 commits.

## Phase 4 PR 4 Façade Deletion Review (2026-04-20) — ALIGNED
See [phase4_pr4_facade_deletion_review.md](phase4_pr4_facade_deletion_review.md) — branch advanced past 2026-04-19 state. Demolition landed: ratchet 0/0/0/0, DEFAULT_BRIDGE_INSTANCE gone, `_deprecation.*` deleted, `SCP-DEFAULT-INSTANCE-OK` count=0, `check-no-default-in-tests.sh` deleted (-410), FOLLOWUP.md deleted. All retro #1692-#1696 have real fix commits. Verdict ALIGNED with two trivial cleanups (stale docstring + stale Swift autogen checksum).

## Phase 4 PR 4 Earlier Review (2026-04-19) — SUPERSEDED
See [phase4_facade_delete_review.md](phase4_facade_delete_review.md). Was MISALIGNED at that commit (only method migration, not demolition). Branch advanced — do NOT cite as current. Pattern reminder: branch names can mislead; verify free-fn counts (`#[pyfunction]`, `#[napi]`, `#[uniffi::export]`), `SCP-DEFAULT-INSTANCE-OK` tag count, ratchet/once-lock-count.json zeros.

## SDK Standards Review Round 2 (2026-02-22)
Second pass after ~38 findings were addressed. 6 of 7 originally tracked issues fixed.
Remaining issue: security scanning CI jobs only in Rust/Go, missing from Python/TS/Swift/Kotlin/C#/Java.
New findings: 13 issues (3 material, 10 minor). Verdict: NEEDS REVISION (3 material findings).

### Material findings:
1. API surface missing `ucan_delegate`, `role_assign`, `tool_update`, cross-context tool ops, MCP ops
2. Python `run_sync[T]` uses PEP 695 syntax (requires 3.12) but minimum version is 3.10
3. Security scanning CI absent from 5 of 7 language pipelines despite sdk-common.md mandate

### Previous findings status:
- Maven coordinate collision: FIXED (kotlin/java now have distinct artifact IDs)
- Python PermissionError shadow: FIXED (now UcanPermissionError)
- Swift force unwraps in examples: FIXED (all examples use proper error handling)
- Missing block/trust operations: FIXED (context_block, context_mute, trust_evaluate, trust_attest added)
- Missing sender key conformance tests: FIXED (dedicated category added)
- TypeScript TS 6.0 reference: FIXED (now 5.7+)
- Security scanning in CI: PARTIALLY FIXED (Rust and Go only)

### Notes:
- `.docs/specs/` is empty (only .gitkeep) -- no product spec files to cross-reference
- Trust operations (evaluate, attest) are forward-looking; not in any current ADR but don't contradict
- Rust streams return OuterEnvelope while other SDKs return Message -- naming table inconsistency

## ADR-022 Review (SCP-060) (2026-02-26)
ADR-022 (TypeScript SDK Dual-Target Architecture) reviewed and PASSED.
- All 8 acceptance criteria satisfied.
- 3 minor issues found: shared.md lists `@limn-works/scp-ts-node` but ADR-022 uses per-platform `@limn-works/scp-ts-napi-{platform}` (shared.md needs update); trust.ts and mcp.ts listed in wrapper layout but no acceptance criteria; Context.join() is static while other methods are instance (inconsistent surface).
- 4 non-blocking suggestions: receive() generator needs cleanup on break; asyncDispose should guard on state; CI commands should match standards file exactly; private field access across classes in sketched code.

### ADR review patterns (reusable):
- Always check the original stub ("What This ADR Will Decide" + "Expected Decisions") against final content
- Cross-reference scaffold/, standards/, and sdk-common.md for naming/convention consistency
- Verify package names in shared.md Distribution Channels match actual ADR decisions
- Check that wrapper file layouts match acceptance criteria coverage (modules listed but not tested = gap)
- Cross-ADR references can drift: verify callback interfaces, trait names, and type names match between dependent ADRs
- Force-try/force-unwrap keeps appearing in Swift examples despite builder tenets -- always flag

## ADR-025 Apple Platform Adapter Review (SCP-082) (2026-02-26)
Initial review: FAIL (2 major, 1 minor). All 3 findings FIXED in PR #86.
- StrongBox rationale moved to ADR-027 where it belongs
- Force-try replaced with proper `throws` in `make()`
- DeviceAttestationProvider now present in ADR-021 UDL (5 callback interfaces total)
Remaining: ADR-025 example code (line 419) still has `.data(using: .utf8)!` force-unwrap, but implementation avoids it.

## PR #86 Full Review (2026-02-26)
Verdict: ALIGNED. ADRs 022, 025, 026, 027, 028, 029, 030, 031 all reviewed.
3 minor doc issues: ADR-025 example force-unwrap, ADR-022 generator cleanup on break, ADR-028 ucanMint accessing private handle.
All previous major findings resolved. Implementation code matches ADR specs.
Phase 6 ADRs (029-031) are "Decided" but not yet implemented; no roadmap conflicts.
Weighted voting deferral in ADR-031 is justified (requires unbuilt token/stake mechanism).

## Gate 1 Verification (Phase 1: Crypto Proof) (2026-02-27)
Deep verification of SCP-001 through SCP-017. All 17 stories VERIFIED.
- All files exist at expected paths
- All acceptance criteria met (spot-checked every story)
- 2,630+ tests across scp-platform (45), scp-core (2,370), scp-transport (215), scp-testing (2 integration)
- All tests pass green
- No unwrap()/expect() in library code (only in #[cfg(test)] blocks)
- #![forbid(unsafe_code)] present in all crate roots
- Proptests for all required crypto operations
- Feature gating correct: testing adapters behind `software_platform` feature
- 0 material findings, 2 minor observations

### Gate 1 verification patterns (reusable):
- Test count from result fields can drift; always run `cargo test` to get actual counts
- Feature flag naming: `software_platform` not `testing` -- the lib.rs aliases `testing` as `software`
- The scp-core crate has 2,370 tests because it includes context, economy, bridge, etc. beyond Phase 1

## SCP-161 Review: Paid Context Templates (2026-02-27)
Verdict: ALIGNED. All 14 acceptance criteria PASS. 71 tests pass.
2 non-blocking actions:
1. serde(rename) inconsistency: PaidService/PaidBroadcast have scp:template/ URIs but older variants (BilateralEphemeral etc.) don't -- mixed serialization conventions.
2. ToolInterface template variant missing from TemplateId enum despite being defined in spec 05-contexts.md:247. PaidService "extends" it conceptually but no structural enforcement.

### Template review patterns (reusable):
- For "extends" relationships: verify the child's properties are a valid specialization of the parent (ceiling can narrow, not just match)
- For caller-supplied fields (like economic_policy): validation should be a separate function, not part of the generic field-comparison loop
- Check serde(rename) consistency across all enum variants -- partial adoption creates wire-format inconsistencies
- Template inheritance is conceptual in this codebase -- no formal extends mechanism, only comments and matching properties

## Gate 3 Verification (Phase 3: Python SDK + MCP) (2026-02-27)
Deep verification of SCP-036 through SCP-058. 23 stories, all marked "done". Verdict: **INCOMPLETE**.
- 23/23 stories have code at correct locations
- 17/23 stories have real, functional implementations
- 6 stories have bridge stubs blocking end-to-end functionality
- Rust MCP crate: 158 tests pass. UCAN crate: 273 tests pass. All green.

### 3 Material findings:
1. **Bridge stubs:** `tools.rs`, `ucan.rs`, `event_log.rs` in `crates/scp-ffi/src/` are stubs returning `Err("not implemented")`. Blocks SCP-040 (tools), SCP-041 (UCAN bridge), SCP-039 (event log).
2. **Missing MCP bridge functions:** `mcp.py` calls 9 bridge functions (`py_mcp_serve`, `py_mcp_client_connect_stdio`, etc.) that do not exist in the `scp-ffi` bridge layer. Blocks SCP-046 (MCP Python wrapper).
3. **Mock-based integration test:** `phase3_integration_test.py` uses `MagicMock` for the bridge -- validates Python SDK logic but not actual Rust integration. Only 3 of 16 test methods attempt real bridge calls. Blocks SCP-058 (integration test story).

### 4 Minor findings:
1. PRD `files` paths systematically wrong (missing `src/` segment) -- `crates/scp-ffi/pyo3/` should be `crates/scp-ffi/src/`
2. Conflicting pyproject.toml: `crates/scp-ffi/pyproject.toml` says Python >=3.9, `bindings/python/pyproject.toml` says >=3.10
3. `ToolError` in `errors.py` is unreachable -- `tools.rs` bridge raises generic `ScpError`, not `ToolError`
4. Async pattern deviation: `context.py` uses `asyncio.to_thread()` instead of `py.allow_threads(|| rt.block_on(...))` pattern from other modules

### What's solid:
- Rust MCP crate (`scp-mcp`): protocol.rs, namespace.rs, server.rs, client.rs, stdio.rs, sse.rs -- all real, tested, comprehensive
- Rust UCAN crate: 11-step validation pipeline, capability matching, nonce tracking, revocation, minting -- all real, 273 tests
- Python SDK wrappers: identity.py, context.py, sync.py, types.py, errors.py, trust.py -- well-structured, correct patterns
- PyO3 bridge: identity.rs, context.rs, error.rs -- real implementations calling scp-core

### Gate 3 verification patterns (reusable):
- PRD file paths can be systematically wrong; always glob to find actual locations
- Bridge layers need function-by-function verification -- stub signatures look correct but return errors
- Python wrappers that call non-existent bridge functions compile fine (dynamic dispatch) -- must cross-reference against bridge lib.rs module registration
- Mock-based integration tests provide false confidence -- verify what the mocks are replacing

## PR #118 Review: Android Platform Adapters + Kotlin Bridge (2026-02-28)
Verdict: NEEDS REVISION (1 blocking finding).
8 stories: SCP-110, SCP-111, SCP-112, SCP-113, SCP-115, SCP-211, SCP-212, SCP-213.

### Blocking:
- **PlatformAdapter.kt missing**: ADR-027 specifies 5 files, only 4 delivered. The factory `AndroidPlatformAdapter.make(context)` that wires adapters into `Scp.create()` does not exist.

### Non-blocking:
- `assertRequest()` vs ADR-027 spec `assert()` -- correct name per UniFFI, ADR needs update
- `verify()` and `custodyType()` listed in ADR-027 scope but absent from Kotlin interface -- Rust trait also omits verify, custodyType redundant with KeyHandle.custodyType field
- `softwareKeys` is `internal` not `private` -- exposes private key material within module
- SQLCipher dependency uses `sqlcipher-android:4.6.1` not `android-database-sqlcipher:4.5.4` (different artifact)
- `py_mcp_load_contexts` ignores `relay_url` param (prefixed with `_`)

### Patterns (reusable):
- ADR code samples diverge from implementation: method names, dependency versions, artifact IDs. Always verify actual code against ADR pseudocode.
- When checking platform adapters against Rust traits, compare method-by-method including return types -- Kotlin interfaces may simplify (e.g. returning DestructionAttestation instead of `()`)
- Android JVM unit tests cannot exercise hardware paths (Keystore, Play Integrity). Tests correctly scope to software/deterministic paths.
- `internal` visibility in Kotlin leaks key material within module -- prefer `private` with API-only test assertions
- PlatformAdapter factory is the critical glue between platform adapters and SDK entry point -- always verify it exists
