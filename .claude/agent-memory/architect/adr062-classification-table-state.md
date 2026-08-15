---
name: adr062-classification-table-state
description: ADR-062's capability classification table now has 24 rows; six classified nullifiers have no gating slice, and the ADR's Status/Decision-5 prose contradicts the tree on Slices 9/10/11.
metadata:
  type: project
---

ADR-062's capability classification table went from 9 rows to 24 on branch
`docs/adr062-classification-completeness` (commit `c90d09af2`, 2026-08-15). Two
things that outlive that commit:

**Six classified nullifiers carry no `cfg` and no slice owns gating them:**
`NoOpStorage`, `NoopContextPersistence`, `InMemorySequenceStore`,
`NoOpRevocationChecker`, the in-memory `ProtocolRepoVariant` arm the ungated
`new_napi`/`new_uniffi` constructors select, and `InMemoryPush`. The G1
shipped-feature-graph gate cannot see any of them, because it tests feature
absence and these carry no feature.

**ADR-062's prose and the tree disagree about Slices 9, 10, and 11.** §Status
and §Decision 5 call three `impl Default` selections live violations. As of
2026-08-15 `impl Default for InMemoryCredentialStore` and
`impl Default for BlobStorageBackend` are gone from their files, and
`RepublishManager` declares no default publisher type parameter. Whether those
slices are complete is unsettled — Alec's call, raised 2026-08-15, not answered.

**Why:** §17.17.2 of the persistence spec makes classification mandatory before
a capability ships, so the table is the gating slice's input; a stale status
claim in the same ADR sends a later reader to work that is already done.

**How to apply:** read the table before touching capability selection or the
prove-absence gate, and do not restate the Slice 9/10/11 status until Alec
settles it. See [[no-nullifiers-in-production]].
