---
name: adr062-in-memory-dht-selectability
description: Cryptographic verdict on ADR-062 draft — whether a shipped SDK may runtime-select in-memory (HashMap) DHT as a production resolution backend
metadata:
  type: project
---

# In-memory DHT as production-selectable backend (ADR-062 draft)

VERDICT (cryptographic-soundness angle): in-memory DHT is categorically WORSE than
in-memory STORAGE and must NOT be a free-standing production-selectable resolution
backend. Acceptable ONLY as part of a fully-in-memory *dev profile* (coupled to
in-memory storage + dev/in-memory custody), fail-loud, non-default, and HARD-REJECTED
in combination with any durable storage or real custody. A production-configured node
(durable storage + real custody) selecting in-memory DHT is a DOA/incoherent topology.

**Why:**
- DHT publication/resolution is the trust-root distribution layer (spec §3.10). Self-
  certification (§3.10.8, BEP44 sig vs DID-key) proves a fetched doc is authentic for
  the key — it does NOT prove reachability by counterparties nor freshness. In-memory
  (process-local HashMap) preserves signature-authenticity while destroying BOTH
  network properties: it looks correct and fails silently on the security-critical axis.
- Rotation/revocation IS a DID-document publication (§3.9: "rotation = DID document
  update with authorization chain from old key"). Publish to a process-local map →
  no counterparty ever sees the new #active key → retired/compromised key stays live.
  This is not hypothetical: issue #1880 is the LIVE proof (NAPI/UniFFI rotation built
  over a throwaway InMemoryDhtClient → resolver keeps accepting the retired #active key
  and rejecting the new one; PR #1870 fixed it for PyO3 only).
- Categorically worse than in-memory storage: storage loss = YOUR durability (§17.6,
  fail-closed, mandatory selection, never a degradation path). In-memory DHT failure =
  a SECURITY/verifiability failure across the whole trust graph (can't verify any
  external DID; can't propagate revocation), and it FAILS OPEN on freshness.
- §3.10.6 anti-segmentation invariant: even skipping ONE real layer (relay XOR DHT)
  is a MUST-not requiring fail-loud opt-out. In-memory DHT = namespace of size 1 =
  the extreme violation of that invariant.

**Current main state (origin/main @c791ecc3f):** InMemoryDhtClient is doc'd "test/dev
backend" (scp-dht/README, dht_client/mod.rs:84); PkarrDhtClient gated behind
`production-dht` feature; bridge_instance.rs:357 explicitly ties in-memory DHT to the
in-memory custody path ("production uses real did:dht/did:web resolution"). So today's
wiring already treats it as dev-only-coupled — ADR-062 would loosen that.

**How to apply:** If ADR-062 presents in-memory DHT as a standalone "legitimate-dev
runtime choice" mixable with production components → UNSOUND, push back. Sound end-state:
selectable ONLY as a bundled fully-in-memory dev profile (mirror §17.6 storage discipline
but STRONGER — reject the mixed/half-real topology as a hard error), and provably absent
as an option whenever durable storage or real custody is selected.
