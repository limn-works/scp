---
name: adr049-pr7-kp-validate-collapse
description: ADR-049 PR-7 double-KP-validation collapse (bf1a787dc) auth-gate re-review — ZERO findings, gate intact
metadata:
  type: project
---

# ADR-049 PR-7 KeyPackage validate-and-bind collapse (bf1a787dc, feat/adr049-pr7-atomic-crypto-move)

Diff de5e9b1a5..bf1a787dc collapses the former double KP validation (validate_key_package + caller-side re-parse via scp_mls::group::key_package_in_did) into ONE validate-and-bind. `ProductionMlsBackend::validate_key_package` (production_backend.rs ~459) now returns `ValidatedKeyPackage { key_package_bytes, credential_did }`.

**VERDICT: ZERO — auth gate intact, no weakening.**

- **Gate ordering correct.** validate_key_package: (1) tls_deserialize, (2) `kp_in.validate(crypto, Mls10)` = OpenMLS sig+protocol verify, (3) `validate_key_package_lifetime(validated.life_time(), clock)` hardened-clock, (4) SCP_CIPHERSUITE reject, THEN (5) extract DID from `validated.leaf_node().credential()`. DID read from the POST-validation object — no gate dropped or reordered after DID trusted. Strictly STRONGER than old key_package_in_did (which skipped the ciphersuite check).
- **DID authenticated, not attacker-supplied.** Extraction `validated.leaf_node().credential() → BasicCredential::try_from → ScpCredential::from_bytes(...).did` is byte-identical to retired key_package_in_did (scp-mls/src/group.rs:708). Leaf credential is covered by the MLS leaf-node signature verified in step 2, so a spoofed credential DID fails `validate`. Cannot forge.
- **Both binding sites still REJECT mismatch.** join_context (lifecycle_helpers.rs ~843) `if member_did != validated.credential_did` → InvalidKeyPackage. execute_add_member (governance_helpers.rs ~1236) `if validated.credential_did.as_str() != owner_did` → MembershipFailed. Same directions as pre-collapse.
- **None-arm prod-reject intact** at both sites: `if !cfg!(any(test, feature="testing")) { return Err(...) }`.

Residual note (mock surface, not a prod finding): a mock `MlsBackend` in test builds could return an arbitrary credential_did since it's now a struct field rather than re-derived caller-side. Production uses ProductionMlsBackend only; test path gated by cfg. Not exploitable.
