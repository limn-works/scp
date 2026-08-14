---
name: spec-918-registry-subsections
description: 09-security-model.md §9.18 registry subsection numbers — which constant lives where (MLS extension types are §9.18.7, not §9.18.6)
metadata:
  type: project
---

In `.docs/specs/09-security-model.md`, the §9.18 Protocol Constants Registry is split into numbered subsections. Cross-references to a constant MUST cite the subsection the *row actually lives in*.

Key subsections (as of 2026-08-01):
- §9.18.2 Domain Separators — e.g. `"SCP-KEYPACKAGE-ATTESTATION-V1:"`, `"SCP-ATTESTATION-V1:"`
- §9.18.6 Context and Governance (Invariants) — role-name limit, close verification window
- **§9.18.7 MLS and UCAN — the MLS extension-type registry: `scp_wrapping_key 0xFF01`, `scp_context_params 0xFF02`, `scp_keypackage_attestation 0xFF03`. NOT §9.18.6.**

**Why:** The `scp_*` MLS extension-type table sits under §9.18.7, but its position right after §9.18.6 makes "§9.18.6" a natural off-by-one misreference. The CRYPTO-22 attestation spec change (branch `crypto-22-attestation-spec`, commit 26b45229c) introduced this exact error in 4 places (09-security-model.md:456 and :603, the ADR-057 amendment, and the commit body) — all cited §9.18.6 for `scp_keypackage_attestation` when the row is in §9.18.7.

**How to apply:** When reviewing/authoring any reference to an MLS extension type (`0xFFxx`), verify it says §9.18.7. When a review flags a §9.18.6 reference to an extension type, it is a genuine stale-xref finding, not a nit.
