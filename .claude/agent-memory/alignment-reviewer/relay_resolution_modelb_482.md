---
name: relay-resolution-modelb-482
description: Model B relay DID-resolution spec+ADR redesign (feat/relay-resolution-modelb, #482) — docs-only, well-aligned, but lands atop already-merged Model A code (#2226) the reconciliation ignores; PRD stale
metadata:
  type: project
---

# Relay resolution Model B redesign (feat/relay-resolution-modelb) — reviewed @ worktree HEAD 363028aaa (behind origin/main 4e8297b8c)

Docs-only working-tree change (7 files vs HEAD): specs 03-identity §3.10.2/3.10.4/3.10.5/3.10.8 + 09-security-model §9.10.12 rewritten to **Model B** (relays VALIDATE DID-record blobs on write + keep a single highest-seq slot; client ALWAYS re-verifies); tenet "encryption-as-access-control" clarified (untrusted ≠ content-blind) in CLAUDE.md + technical-overview + white-paper; new §10.12.4 BRIDGE_REGISTER precedent note; ADR-062 reconciled to scope relay resolution OUT (Slice 11 = sever InMemoryRelayPublisher default ONLY) and INTO feature #482.

**Why:** This is the spec-first fix to the anti-suppression finding I tracked across ADR-062 Slice 11 reviews (see [[MEMORY]] "ADR-062 Slice 11 FINAL @ 04c666220 NEEDS DISCUSSION"): a cheap unauthenticated 16-blob flood at the DID-derivable routing_id evicts the genuine record from the bounded read window → Model-A relay added ~0 suppression resilience; §3.10.8 "attacker must suppress ALL relays" was FALSE for a Model-A opaque-blob relay. Model B (relay-side single-slot validation, QUERY limit:1) structurally closes it. The redesign is sound and the fix is correct.

**How to apply (findings, verdict NEEDS DISCUSSION):**
1. Spec↔#482: ALIGNED. Model B EXPANDS #482 beyond its issue-body "no relay-side change, just wire identity→transport" assumption (relay-side validation now REQUIRED). Spec is authoritative → #482 issue body is now itself stale; update it. DHT unaffected — confirmed.
2. Artifact-flow: docs-first, code-follows = CORRECT. BUT worktree HEAD is 3 commits behind origin/main; origin/main ALREADY MERGED **#2226 "RealMultiRelayQuerier with shadow-defeat Vec contract (ADR-062 Slice 011a)"** — Model A code (relay_querier.rs: MAX_CANDIDATES_PER_RELAY=16, client-side bad-sig/stale-valid shadow-defeat, §3.10.8 cites). After rebase, Model B spec CONTRADICTS that merged code (spec now mandates limit:1 + relay single-slot; §3.10.8 "intra-relay co-located shadow" bullet DELETED). = phantom provenance on main until #482 reworks it.
3. Tenet edits: CONSISTENT across all 3 files (untrusted; MAY validate public self-certifying records; defense-in-depth/availability not trust dep; never encrypted content; client always re-verifies).
4. ADR reconciliation: PROSE fully reconciled (no lingering "ADR-062 builds querier/restores §3.10.8" — all attribute to #482). BUT INCOMPLETE vs merged reality: does NOT acknowledge Slice 011a (#2226) already shipped a Model A querier under ADR-062, nor state #482 must REPLACE it (delete MAX_CANDIDATES/shadow-defeat Vec, switch limit:1, add relay-side validation). Reads as if querier is unbuilt.
5. PRD SCP-CAPINJECT-011 (.docs/prds/adr062-capability-injection.json): STALE, unchanged by branch. Still Model A full READ+WRITE build ("lands BOTH; no half deferred"), references SCPR kind-1, publish_raw/query_raw, RealMultiRelayQuerier — contradicted by BOTH new ADR scope (sever-default-only) AND new spec (Model B DID-record frame, no kind byte, existing PUBLISH/QUERY). Doubly stale (READ half partly shipped via #2226). Needs rewrite to "sever default only" + a NEW #482 story (Model B relay resolution feature). No #482 story exists yet.

Model B frame delta: SCPR multi-kind magic-tagged frame (magic SCPR + version + kind byte + value_len u32; kind-1 DID / kind-2 KeyPackage reserved) → **minimal DidRecordV1** (version u8=1 + public_key[32] + seq u64 + signature[64] + value trailing-remainder; fixed prefix 105B; NO magic, NO kind byte — routing_id domain is the type discriminant). public_key now carried FOR THE RELAY's verify (client ignores it). KeyPackage kind-2 → its own future frame under #2202.
