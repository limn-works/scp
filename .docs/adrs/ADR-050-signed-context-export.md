# ADR-050: Signed Context Export Over Full Canonical Snapshot

**Status:** Accepted
**Date:** 2026-06-08
**Phase:** Phase 6 (production readiness, security)
**Related:** ADR-029 (Offline/Sync — defines `ContextSnapshot` and the sync tiers), ADR-031 (Multi-Admin Governance — defines the governance model config, threshold quorum, and consequence rules carried in the snapshot), ADR-038 (Content Access Key Layer — the access-key store carried in the snapshot), ADR-039 (Multi-Key Verification Methods — `#active`/`#agent` key selection), ADR-034 (WASM Constraints — the reference signed-export implementation lives in the WASM bridge)

## Context

A `ContextExport` (spec §17.5) is the portable, self-contained representation of a context's full state, produced for backup, migration, and device transfer. On import, `import_context` (`crates/scp-runtime/src/context/manager/lifecycle.rs:1212-1346`) restores a large set of *trusted* fields verbatim into the importing instance's authoritative state: role ceilings, per-member capabilities, suspended capabilities, role assignments, threshold signer set and threshold value, governance model configuration, economic policy, consequence rules, the read-exclusion list, the access-key store, any pending ceiling modification, and tool registrations.

The export carried two integrity protections: an event-log Merkle chain, and an Ed25519 `snapshot_signature`. The signature, however, was computed over `ContextExport::canonical_snapshot_hash` (`export_import.rs:152-173`) — an **enumerated subset** of only seven inputs: a membership digest, a role-definitions digest, a params digest, a tool-names digest, the Merkle root, the exporter DID, and the version. This subset is the §23.16.4 `ContextSnapshot` (sync-delta) hash recipe, reused for export.

The subset does not cover the trusted fields that `import_context` restores verbatim. The result is forgeable export: an attacker could raise a role's ceiling, inject member capabilities, rewrite the threshold quorum, swap the governance model, alter the economic policy, or tamper the consequence rules / access-key store, and the importer would restore the forged state under a signature that still verifies — because none of those bytes are in the signed preimage. The Merkle chain covers event history, not snapshot configuration, so it does not close the gap.

The root cause is a specification defect: §17.5 claimed the export signature was computed "exactly as specified in §23.16.4," conflating the export integrity proof with the Tier-2 sync-delta hash. Per the artifact-flow invariant, the spec is fixed first.

## Decision

The signed `ContextExport` snapshot signature is **Ed25519 over `SHA-256("SCP-CONTEXT-SNAPSHOT-V1:" || JCS(ContextSnapshot))`**, where `JCS` is the RFC 8785 (JSON Canonicalization Scheme) canonical-JSON serialization of the *entire* embedded `ContextSnapshot` — every field, not a subset. This is specified normatively in spec **§23.16.8 (Signed Context Export)**, and §17.5 now references §23.16.8 instead of §23.16.4.

- **Signer:** the snapshot's `creator_did` (`role_state.creator_did`), via its `#active` (then `#agent`, ADR-039) verification-method key.
- **Importer requirements (verify-before-restore):** resolve the verifying key from `creator_did` (never from an envelope field), assert the envelope's `exporter_did == creator_did`, and verify the Ed25519 signature over the recomputed `SHA-256(domain || JCS(snapshot))` before reading any field into authoritative state.
- **Set/map canonicalization:** snapshot fields backed by non-deterministically-ordered sets/maps MUST be canonicalized to sorted (`BTreeMap`/`BTreeSet`) ordering in the value fed to JCS, so the digest is byte-identical across implementations.
- **Wiped fields:** per-instance anti-abuse and accounting state (`approved_proposals`, `next_proposal_seq`, `budget_tracker`, `participation_cache`, spending-nonce tracker, `proposal_timestamps`, and anti-spam hard-rate-limit / velocity / `cooldown_until` state) is signed but intentionally wiped or sanitized on import (`lifecycle.rs:1233-1308`). The signature proves these were not tampered in transit; the wipe ensures a hostile exporter cannot pre-load enforcement state regardless.
- **Distinct from §23.16.4:** the §23.16.4 enumerated-subset recipe remains unchanged and continues to govern the Tier-2 sync `ContextSnapshot` delta type only. It MUST NOT be used to sign a `ContextExport`.

The reference construction already exists in the WASM bridge (`crates/scp-ffi/wasm/src/manager.rs:5152-5181`): serialize the snapshot to canonical JSON via `serde_json_canonicalizer`, hash `domain-bytes || snapshot-json`, sign the digest.

The native export format `version` increments to **3**. The WASM bridge's JSON envelope `version` is an independent per-serializer integer; the two counters need not match. What converges across implementations is the *construction*, not the envelope integer.

## Alternatives considered

### Sign the §23.16.4 enumerated subset (rejected — the status quo defect)

Reuse the seven-field `canonical_snapshot_hash` recipe for export. **Rejected:** it signs only membership/role-definitions/params/tool-names/Merkle-root/exporter/version and leaves the role ceiling, per-member capabilities, suspended capabilities, threshold signer set and value, governance model configuration, economic policy, consequence rules, read-exclusion list, access-key store, and pending ceiling modification unsigned. `import_context` restores all of those verbatim, so the subset hash makes them forgeable under a valid signature. A subset recipe is correct for a sync *delta* (where the receiver already holds authoritative state and the snapshot is a lightweight reconciliation token) but wrong for an *export* (where the importer trusts the snapshot as the source of authoritative state).

### Extend the enumerated subset to cover every trusted field (rejected)

Add each missing field to the hand-rolled length-prefixed canonical-byte recipe. **Rejected:** the recipe would have to enumerate and version every governance/economy/access field by hand, re-deriving a deterministic encoding for each nested type (threshold sets, policy structs, consequence-rule vectors, access-key maps). This is exactly the encoding work that RFC 8785 JCS already solves once for the whole struct. A hand-rolled enumeration is a perpetual completeness hazard — every new snapshot field is a new opportunity to forget a line and reintroduce a forgeable gap — which violates the completeness baseline. Signing `JCS(full snapshot)` is total by construction: any field present in the struct is in the preimage.

### Verify the signature after restoring state, then roll back on failure (rejected)

Restore optimistically and undo if verification fails. **Rejected:** verify-before-restore is the only safe ordering. Restoring forged governance/economy state before checking the signature exposes a window of partially-applied authoritative state and complicates rollback of side effects.

## Consequences

### Positive

- **Closes the forgery gap.** Every field the importer trusts verbatim is in the signed preimage. Tampering any byte of the snapshot invalidates the signature.
- **Cross-implementation convergence.** All four bridges converge on one construction — domain separator, full-JCS digest, Ed25519, `creator_did` signer, verify-before-restore, `exporter_did == creator_did` — reusing the repo's existing RFC 8785 canonical-JSON convention (`serde_json_canonicalizer` / `scp-protocol::jcs`). The WASM bridge is the reference.
- **Total by construction.** Signing `JCS(full snapshot)` removes the per-field enumeration hazard: new snapshot fields are covered automatically.

### Negative

- **Version bump.** Native export `version` increments to 3; pre-3 exports are rejected on import with a distinct version error (not a signature error), per §17.5 / `SCP-CTX-2093`. SCP is pre-release with no deployed data, so there is no migration path to preserve — the correct end state ships directly.
- **Producer determinism burden.** Producing implementations must canonicalize set/map-backed fields to sorted ordering before JCS so the digest is reproducible. This is a one-time per-field discipline enforced by the spec's normative canonicalization requirement.

## References

- Spec §23.16.8 (Signed Context Export) — normative construction, signer, importer verification/authorization, set/map canonicalization, version note.
- Spec §23.16.4 (ContextSnapshot) — the Tier-2 sync-delta recipe, distinct and unchanged.
- Spec §17.5 (Serialization / Context export integrity) — references §23.16.8.
- Spec §23.17 (Snapshot Sequence-Floor Invariants) — additional import enforcement.
- Spec §9.18.2 — domain separator registry (`SCP-CONTEXT-SNAPSHOT-V1:`).
- ADR-039 — `#active`/`#agent` verification-method selection.
- `crates/scp-ffi/wasm/src/manager.rs:5152-5181` — reference full-JCS signed-export construction.
- `crates/scp-runtime/src/context/manager/lifecycle.rs:1212-1346` — `import_context` verbatim-restore and per-instance-field wipe behavior.
