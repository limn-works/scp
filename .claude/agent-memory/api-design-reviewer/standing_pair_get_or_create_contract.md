---
name: standing-pair-get-or-create-contract
description: API contract shape for standing_context get-or-create and how the symmetric model collapses return cases — for reviewing §5.15.8 / ADR-049 standing-pair changes
metadata:
  type: project
---

`standing_context(peer) -> Result<ContextHandle>` is SCP's standing-pair get-or-create entrypoint (spec §5.15.8). Classification SETTLED: standing-pair creation is single-context async MLS creation, NOT a saga — so it has **no `start_*_saga` FFI export** (ADR-049 §3a carve-out).

**Why:** Two design properties make this contract misuse-resistant and worth preserving across future edits:
- **Symmetric initiation collapses the return surface.** Either party may initiate; both get the same `Ok` ("my replica created + Welcome dispatched"). The `did_lo`/`did_hi` tie-break governs ONLY receive-side simultaneous-create collision resolution — it never surfaces on the `standing_context` return path. Offline/slow/blocking/declining peer ALL yield identical `Ok` (block-privacy: a synchronous join confirmation would be an oracle). There is no caller-observable `did_hi`-awaiter case.
- **Two asymmetries must stay separated.** Return contract = symmetric/direction-agnostic. Send capability = temporarily asymmetric (joiner cannot SEND until Phase-2E spawn-from-Welcome entrypoint). Conflating these is the trap — the Phase-2E gap must NOT leak into the return contract.

**How to apply:** When reviewing standing-pair API changes, check: (1) does any new branch make `did_hi`'s return differ from `did_lo`'s? (regression if so); (2) is `AlreadyExists`→`Ok` still gated strictly on verified-self-membership, with non-members getting the generic rejection constant-time wrt existence (existence-oracle prohibition); (3) is `register_standing_context` still internal-only (it's named like a public API but is transitive bookkeeping — flag if exported as a standalone bridge method); (4) does the held-handle auto-revive guarantee (ADR-049 §10, deterministic-id re-drive) stay discoverable. Related: [[pr1744_pseudonym_routing_rehome]].
