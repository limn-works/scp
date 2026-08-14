---
name: adr058-typed-trust-input-2010
description: ADR-058 #2010 Ops C/D (aggregate_trust_input + trustVerifyAttestation/Response) typed across 4 SDKs — COMPLETE
metadata:
  type: project
---

# ADR-058 #2010 — typed trust-input Ops C/D (COMPLETE)

Branch feat/... worktree fu-2010 @951136123 (4 commits over origin/main). Follow-on to #1991
(A/B typed in #2015 → [[adr058-typed-trust-input-1991]]). Resolves #2010 + completes #1991 AC-3.
READ-ONLY review. **VERDICT: COMPLETE, zero blockers.**

**Scope:** type the remaining 3 trust-input ops' developer-facing surfaces; bridges stay JSON
(ADR-048 §1/§7). ZERO crates/ change. Op C `aggregate_trust_input` (7 typed inputs), Op D
`trust_verify_attestation` (Attestation envelope) + `trust_verify_response` (ChallengeRequest +
ChallengeResponse). All 4 SDKs.

**Op × SDK typed-path matrix — ALL ✓** (py/ts/swift/kt): aggregate_trust_input,
trust_verify_attestation, trust_verify_response.

**Model fidelity (field-for-field vs Rust + proven by real-FFI deserialize):**
- EventLogEntry ↔ `scp_event_log::Event` 7 fields (event_type/actor_did/timestamp/sequence/
  payload{data serde_bytes}/prev_hash[u8;32]/signature serde_bytes 64). merkle_root→[u8;32].
- ThresholdRequirement 6 fields (required_count u32/total_attestors u32/independence_threshold
  f64 + 3 penalties f64 default 0.1/0.5/0.2 — serialized via #[serde(into=Raw)], deser via
  TryFrom<Raw> w/ serde(default) penalties; SDKs emit all 6 explicit ✓).
- AttestorInfo 4 (did/context_memberships/endorsements/attestation:Option<Attestation> explicit-null).
- Attestation (verify_attestation input) 12 fields ← reused CachedAttestationEnvelope; Option
  fields omitted-when-null (serde Option deser accepts missing) ✓.
- ChallengeRequest 8 (challenge_type=bare-URI-string, timeout={secs,nanos}, sig 64) / ChallengeResponse 5.
- AttestationType 8 unit variants bare PascalCase, both as values AND map keys.
- Reused already-typed encoders: consequence_rules, cached_attestations, challenge_results
  (encodeChallengeVerifications from A/B).

**Per-SDK idiom (correct):** Python TypedDict pass-through (snake_case, no camel→snake); TS
encode* fns; Swift Codable structs + CodingKeys, typed free-fn OVERLOADS coexist w/ generated
...Json forwarders (ADR-sanctioned bridge boundary); Kotlin data classes + buildJsonObject
(encodeEnvelopeElement made internal for reuse). Shared serialization point Python
`_encode_aggregate_trust_wire` (module fn + SCP method emit byte-identical).

**Tests:** exact-JSON `toEqual`/`assertEquals`/`json.loads==` per SDK per op + REAL-FFI
call-through TS trust-ffi.test.ts (genesis MemberJoined Event deserializes on real napi) +
Kotlin TrustAggregateFfiTest (uniffi.scp real bridge, all 3 ops) + Python real-bridge
(importorskip _scp_core). Swift encoder-only (29 assertions; can't link w/o XCFramework —
established limitation; wire shape proven by TS/Kt/Py real-FFI on identical bytes).

**Gates:** validate-prd 370 exit0, check-sdk-coverage 227 ops 0 err, check-error-codes 2360
occ PASS. aggregate_trust_input matrix true×4 (unchanged; method names identical so coverage
passes regardless of typing — manual review confirmed typed surface). ADR-058 scope-note
update ACCURATE.

**MINOR (non-blocking):**
- (LOW artifact-divergence) Swift byte-length errors emit SCP-VALID-7064/7065 whose registry
  doc-comments (scp-ffi/common/src/error_codes.rs:823/825) label them "Discovery
  unregister/query validation error." VALID_7064/7065 constants are DEAD (grep: zero Rust
  emitter) so NO runtime collision; Swift is sole emitter. Continuation of A/B pattern
  (7060-7063 same discovery-labeled reuse). Fix = correct registry doc-comments to trust
  byte-length purpose (or assign dedicated codes). check-error-codes only range-validates.
- (OBS, pre-existing) trust_verify_attestation/trust_verify_response/trust_create_challenge
  public in all 4 SDKs but ABSENT from sdk-capability-matrix.json (aggregate_trust_input IS
  present). Pre-existing omission, not this branch, not in ACs.
- (OBS parity) byte-len validation asymmetry: TS/Swift/Kotlin validate event prevHash32/sig64
  + challenge sig64 at encode; Python validates ONLY merkle_root32 (+ attestation-type keys),
  relies on bridge to reject other wrong-length byte arrays (TypedDict pass-through idiom).
  Not an AC.

LESSON: matrix `verify_attestation` entry (line183) is verify_LINK_attestation (identity), NOT
trust_verify_attestation — don't conflate. TS remaining `...Json: string` in scp.ts are
scpidSign/scpidVerify/identityVerifyLinkAttestation (identity ops, not trust-engine, out of
scope). TS `Record<string,unknown>` in AggregatedTrustInput = OUTPUT type (ADR-057 domain).
