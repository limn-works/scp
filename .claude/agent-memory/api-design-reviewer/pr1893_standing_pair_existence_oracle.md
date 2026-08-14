---
name: pr1893-standing-pair-existence-oracle
description: API review of PR #1893 §5.15.8 standing-pair existence-oracle reachability clause; public surface is standing_context(peer) get-or-create
metadata:
  type: project
---

PR #1893 (`spec/standing-pair-slot-replacement-followup`, HEAD 87f2a7420) — spec-only change to `.docs/specs/05-contexts.md` §5.15.8.

**Change:** internal convergence mechanics (atomic replace-not-create, Entry::Vacant scoped to create) + new *Reachability (defense-in-depth scope)* clause on the existence-oracle paragraph.

**Why:** clarifies the non-member existence-oracle defense guards a raw-`derived_context_id` join/resolve entry point, NOT the `standing_context(peer)` surface (which derives id from caller's own DID, so caller is a pair member by construction).

**How to apply (API-design verdict):** the public-surface story is coherent and misuse-resistant. The reachability clause IMPROVES it (narrows blast radius, makes happy path provably oracle-free). `register_standing_context` correctly internal-only (ADR-049 §3a). Get-or-create idempotency contract is clear for binding authors. Strong anti-footgun rules at line 1885: uniform Ok, MUST-NOT-enrich with created/peer_joined discriminant, identical shape across all bindings.

**My findings (all LOW/observation, none blocking):**
- The "raw-`derived_context_id` join/resolve entry point" the clause guards is NOT defined as a named public surface anywhere in 05-contexts.md (grep for join_by_id/resolve_by_id/by-id join = nothing). It's a hypothetical/internal attack surface. The clause is fine but mildly forward-references a surface not yet specced — binding authors can't act on it. Recommend: note it's a Rust-core internal path, not an SDK export, OR cite where it's defined.
- "join/resolve attempt" terminology is two different verbs for one referenced entry point; no definition disambiguates which.

Sibling clause line 1885 (`standing_context` Ok-return contract) is the load-bearing public-API clause and is excellent — diff didn't touch it but it anchors the coherence.
