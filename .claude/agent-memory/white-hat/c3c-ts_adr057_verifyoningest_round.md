---
name: c3c-ts-adr057-verifyoningest-round
description: White-hat review of c3c-ts ADR-057 CapabilityValidation + verify-on-ingest + participation-once-in-Rust (ADR-055/057 follow-ups)
metadata:
  type: project
---

# c3c-ts ADR-057 / verify-on-ingest follow-up review (2026-06-29, round 2)

Follow-up to ADR-055 round. Prior P1 attestation_count fail-OPEN (ingest) CLOSED. WASM removed — 3 native bridges.

## Round-2 NEW P1 — external/context revocation enforced ONLY at ingest, NOT on cache read-back
- `get_verified_attestations` (scp-protocol/trust/aggregate.rs) is the attestation source for BOTH `attestation_count` (participation) AND `evaluate_trust` (aggregate_trust_input step 1). It NEVER queries `get_revocation_state`. Fresh entries (<TTL 300s) returned unchecked; stale entries re-verified with `verify_attestation` (revocation_checker=None). The new `RevocationStateChecker` is wired ONLY into the ingest path (`verify_and_cache_with_revocation` in populate_and_aggregate / verified_attestations).
- Production store is DURABLE: `ProtocolRepositoryTrustBridge` over storage (InMemoryEncrypted|Sqlite); the `InMemoryFfiTrustStore::new()` calls in trust_store.rs are ALL test-only. `get_cached_attestations` (scp-runtime/store/trust.rs:265) loads raw, no revocation filter.
- Effect: an attestation cached in a prior call, then context-revoked via the revocation list (NOT via the issuer-bound revocation_status FIELD, which IS re-checked), keeps inflating attestation_count/evaluate_trust forever (TTL re-verify with None-checker passes; re-supplying it at ingest gets the re-ingest dropped but does NOT evict the still-fresh cached copy). FAIL-OPEN in the inflation direction. Directly defeats the invariant this change claims ("rejected before it can be cached or counted").
- FIX: thread the context `RevocationStateChecker` into get_verified_attestations and apply to BOTH fresh AND stale entries (O(1) map lookup), or evict on revocation.

## Round-2 P2 — "required in SDKs" only delivered for Python + TS
- presenting_agent_did required (`str`/`string`) in Python scp.py + TS scp.ts. Kotlin (Scp.kt:1710, CoroutineBridge.kt:1007/1947 with `=null` default) + Swift (Scp.swift:1119) still `String?` nullable. Root cause: all 3 FFI bridges take `Option<String>` and fail-closed at runtime; UniFFI generates `String?`. Runtime fail-closed (not exploitable) but violates construction tenet (required choices = required fields) + cross-binding identical-shape + stated scope. FIX: UniFFI bridge fn → `presenting_agent_did: String` (non-Option), keep empty/whitespace guard → Kotlin/Swift surface non-null.

## Round-2 P2/P3 — is_verification_rejection allowlist under-inclusive
- Closed positive allowlist (good per CLAUDE.md) but OMITS canonicalization-failure variants: `TrustError::InvalidEventData` (canonical_attestation_bytes) + `TrustError::ChallengeSigningFailed` (canonical_challenge_verification_bytes). A malformed-but-not-signature caller credential → classified INFRA → aborts the WHOLE batch instead of dropping the one entry. Fail-SAFE direction (no inflation; visible Err) but contradicts the documented rejection-vs-infra contract; latent targeted-abort if reachable. Near-unreachable today (serde_json::Value→msgpack effectively never fails). FIX: add the two variants, or wrap canonicalization-of-caller-data failure in a dedicated malformed-credential rejection variant.

## SOUND this round (verified)
- Q2 gate/diagnostic: validate_did(presenting_agent_did) called in ALL 3 bridges (pyo3 ucan.rs:294, napi ucan.rs:280, uniffi bridge.rs:13322) AFTER trim+filter-empty ok_or_else. Gate sole enforcer (type-system: &mut ctx + mandatory CapabilityUri vs &ctx + Option). Fail-closed None/empty.
- Q3 founder leaf: single `builder::create_context` step-8 appends founder MemberJoined (actor==subject==creator, role "admin") at convergent creation_timestamp_secs; lifecycle_helpers::create_context (supervisor path) DELEGATES to it (line 1411) so NO divergence; rollback on failure. join/leave switched to append_membership_change_leaf (subject-bearing). Membership leaves still committer-only/non-replicated (ADR-051 forward step, documented, pre-existing).
- Q3 empty-log: supervisor.participation_record maps EmptyEventLog→NoParticipationFacts→CTX_2076 uniform across pyo3/napi/uniffi error.rs + per-call trust.rs. Merkle-root fail-closed ([0u8;32] only when events empty, which yields EmptyEventLog anyway). attestation_count_anchored const = false always. Empty-log short-circuits BEFORE attestation processing (subject w/ attestations but no events → CTX_2076, not a zero-participation record).
- challenge_results verify-on-ingest: verify_challenge_verification (challenge.rs) resolves verifier key, checks Ed25519 over canonical bytes binding passed/score/expires_at/subject, before store. Resolver failure → AttestationSignatureInvalid (in rejection list, dropped). No read-path revocation gap (no revocation concept for challenge results).
- Resolver classification: IdentityDidPublicKeyResolver maps ALL resolution failures → AttestationSignatureInvalid (rejection); it's a pure DID-string parse (no network), so resolver failures are genuinely rejections not infra. Sound for the hardcoded production resolver.
