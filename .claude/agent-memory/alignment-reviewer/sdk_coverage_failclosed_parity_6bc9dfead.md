---
name: sdk-coverage-failclosed-parity-6bc9dfead
description: fix/sdk-coverage-fail-closed-and-parity @ 6bc9dfead — APPROVED, 0 blocking; PERM-3030 re-raise, §9.12/§3.2.1 citations, TrustLevel/ResolutionLayer Literals, ADR-053, CLAUDE.md enforcement-list
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ 6bc9dfead — APPROVED, 0 blocking

Base CLEAN: merge-base==origin/main==1f1ea7cd2, 0 behind / 60 ahead (no phantom-delete trap). HEAD commits: 6bc9dfead (restore §3.2.1 in TS bridge comment + TypedDicts total=True) / 341df72cc (honest ALIASES docstring) / 660eac83f (ADR-051→ADR-053 rename, 051 taken by causal-dag).

**Why:** 5-point alignment review of the targeted diff (gate + Python/TS SDK parity + ADR-053 + lessons + CLAUDE.md).
**How to apply:** all 5 verification points PASS; this is the same branch family as a2caec4a8/ae8a306aa/b27ef7bff — verdicts converge.

## 5 checks
1. **PERM-3030 re-raise** — CORRECT. PERM_3030 = handle-affinity violation (handle used on wrong SCP instance), a caller-misuse/programmer error, NOT a trust signal (error_codes.rs:510, bridge_instance.rs HandleAffinityError). trust.py:765 `if error_msg.startswith("[SCP-PERM-3030]"): raise` mirrors TS trust.ts:461 `if (/^\[SCP-PERM-3030\]/.test(msg)) throw error`. Message format verified: error.rs:158 renders permission errors `[{code}] permission error: {message}` → reaches Python as `[SCP-PERM-3030] permission error: ...` so startswith matches exactly. Swallowing it would yield false all-False CapabilityValidation for a token never evaluated. Test (test_sdk_parity_additions.py) injects exact format + asserts propagation = sound, not vacuous-echo.
2. **§9.12 vs §3.2.1 citations** — CORRECT. Spec confirms: 03-identity.md:20 §3.2.1 = Key Custody Migration (DID PRESERVED); 09-security-model.md §9.12 = Identity Key Migration (NEW DID via pre-rotation reveal). PR flips identity_migrate/rotation_event_json doc-comments §3.2.1→§9.12,ADR-003§4b across scp.py/identity.py/bridge.ts/test_real_ffi.py; identity_execute_custody_migration correctly RETAINS §3.2.1. Lesson doc identity-migration-cite-9.12-not-3.2.1.md accurate.
3. **TrustLevel/ResolutionLayer Literals** — CORRECT vs IMPL (spec STALE). Python TypedDict `kind`: DirectExchange/LocalPetname/DomainVerified/AttestationVerified/HandleRegistryVerified/MultiLayerCorroborated; `layer`: Petname/HandleRegistry/Attestation/Domain/MultiLayerCorroborated. These match Rust serde enum (scp-protocol/src/discovery/addressing.rs:45 TrustLevel, :102 ResolutionLayer) + TS union (discovery.ts:136) EXACTLY. **Spec §22.7/§22.11.3 is STALE** — still says DiscoveryContextVerified/DiscoveryContext (old names; impl renamed → HandleRegistry*). TypedDicts correctly mirror the authoritative wire format. DOC-PRECISION NIT (pre-existing pattern, also in TS): docstrings cite "§22.7"/"§22.11.3 ResolutionLayer" while using names the spec text lacks. Non-blocking; same as 1ed31cd8c memory note.
4. **ADR-053 substrate isolation** — ACCURATE. Quotes §9.7.4.1 §3 (storage isolation: pre-rotation key MUST be in separate custody provider/auth flow), §4 (approved backends table), §5 (SDK ceremony) verbatim-faithful to 09-security-model.md:655-690. Diagnoses the real gap (callback custody mints pre-rotation into InMemoryPreRotationCustody → same process memory; import_ed25519_signing_key fail-closes blocking migration). Proposes separate PreRotationCustodyProvider FFI interface. Status Proposed, ZERO impl leaked. ADR-051→053 rename grounded (051 = causal-dag).
5. **CLAUDE.md enforcement-list** — ACCURATE. scripts/check-sdk-coverage.py added to NEVER-modify list = legit: CI-wired (ci.yml:146 self-tests BEFORE :147 gate), load-bearing, fail-closed. Ran locally: 11/11 self-tests pass, gate EXIT 0 (223 ops, 0 err, 1 provenance-cited Kotlin addRelay exemption).

## Backing functions verified exist
economy_verify_payment_receipts (economy.rs:469-470, &str→String matching json.dumps/loads); py_context_discover module-level pyfn (discovery.rs:285 — confirms "no per-instance bridge, unlike TS getBridge"); verification_results_to_json (receipt.rs:168, + empty-vacuously-valid test confirms docstring).

## NON-BLOCKING residue
Edited comment lines still carry pre-existing `#632`/`#1549` issue-refs (e.g. `// Recovery and custody migration (#632, spec §9.12)`) — PR trimmed §3.2.1 but left the issue-ref. Same class as ae8a306aa LOW. The substantive change (citation fix) is the point; ideal to also drop the ref but pre-existing.

## LOW finding (api-design-reviewer R23, CONFIRMED) — ResolutionPathDict.source_id over-permissive
`discovery.py` types `source_id: NotRequired[str | None]` but the PyO3 bridge sets it UNCONDITIONALLY (`discovery.rs:239` `resolution_path.set_item("source_id", resolution_source_id)?` — key always present, value nullable). TS counterpart always sets `sourceId: string | null` (discovery.ts:131). So `NotRequired` falsely claims the key may be absent — diverges from BOTH wire shape and TS. Fix = `source_id: str | None`. LOW: type-only, no runtime change; `NotRequired[str|None]` ⊇ `str|None` so consumers still typecheck. This is the ONLY substantive finding across 5 parallel R23 reviews (test-quality/crypto/white-hat/api-design all else APPROVED).

## R23 parallel-review corroboration (all APPROVED)
- test-quality: 18/18 pass; mutation-verified PERM-3030 re-raise (delete branch → all-False return, no exception → pytest.raises fails). Flagged latent (out-of-scope) `_mock_name`/hasattr seam in prod trust.py.
- cryptographer: BridgeTrustLevel discriminants match Rust provenance.rs:43 (ShadowBridged=0..NativeNative=3); MLS provider.rs comments-ONLY, verify-after-decrypt invariant preserved in text; test-guard fail-closed sound vs trust-bridge-swap.
- white-hat: gate fail-closed/all-exempted-guard/closed-allowlist confirmed; PERM-3030 degrades to DENY not permit on format drift (unknown→∅); no trust-escalation path.

## BehavioralRecord honesty
trust.py drops `contexts_participated=1` fabrication → left at default 0 with comment (aggregate not bridge-computable) = honest, removes phantom data. Matches prior-round fix.
