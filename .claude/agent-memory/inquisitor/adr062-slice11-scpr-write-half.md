---
name: adr062-slice11-scpr-write-half
description: ADR-062 Slice 11 (SCP-CAPINJECT-011) write-half expansion — phantom 11b removed, scope sound; residual "live/silently-swallows" over-reach on a LATENT default
metadata:
  type: project
---

ADR-062 Slice 11 / SCP-CAPINJECT-011 (relay resolution layer). Prior inquisitor finding
(story built only READ half, deferred WRITE to phantom "11b", overclaimed "resilience
restored") was FIXED on branch `docs/adr062-011-scpr-frame-v2` (diff ea4f90bb8..0c5637d8a,
story + ADR only; spec §9.10.12 unchanged/SOUND).

**Why:** the fix folds both halves into 011 (real MultiRelayQuerier READ + real RelayPublisher
WRITE, SCPR kind-1 frame primitive in scp-protocol, severs `RepublishManager<D, R =
InMemoryRelayPublisher>` default at republish.rs:397, fixes the sig/seq drop at
republish.rs:703). Phantom 11a/b/c gone; resilience claim corrected (both halves needed);
blockedBy now [SCP-CAPINJECT-001] (real, forward-only); KeyPackage→kind-2 deferral legit
(KeyPackages functional today via OuterEnvelope.encrypted_blob). PRD validates.

**How to apply — the ONE residual (verified against current code):** `RepublishManager` has
ZERO production construction sites — constructed only under `#[cfg(test)]` (republish.rs:863-917),
and `::new` sets `relay_publisher: None`. So the `InMemoryRelayPublisher` default is a LATENT
by-construction default-selection (structurally identical to E1's `DidDht<D=InMemoryDhtClient>`,
and correctly must be severed by construction) — but it is NOT reached on any shipped path.
The ADR/story call it a "**live** SCP-CAPSEL-8000/8011 violation ... that **silently swallows
relay publishes so the relay layer never receives DID frames**." That causal/liveness claim is a
never-held premise: nothing swallows anything because nothing constructs the manager or starts
relay-publish. The story's own action item (d) — "**wire** a production RepublishManager ... so a
Disabled node actually publishes its own DID" — admits there is no production construction today,
which contradicts "silently swallows" (present tense). Relays receive no DID frames today because
relay-republish is entirely UNWIRED, not because an InMemory default swallows them. This repeats
the exact OVERCLAIM category the original finding flagged. Recommend rewording to
"latent/by-construction default-selection violation (E1-class, must be severed)" and stating the
true cause (unwired relay-republish). Scope/decision to land both halves in 011 is SOUND; this is
an artifact-precision fix, correct the ADR + story per one-way flow before the code slice cites them.

**Heuristic (reusable):** distinguish a LIVE default (reached on a shipped construction/chokepoint —
E1 DidDht::new() x~12, E2 napi/runtime.rs:313) from a LATENT default type param on a type never
constructed in production. Both violate ADR-062's prove-absent thesis and both must be severed, but
only the reached one may be labeled "live" or described as "silently swallowing." Verify the
construction sites before accepting a liveness/causality claim in an ADR.
