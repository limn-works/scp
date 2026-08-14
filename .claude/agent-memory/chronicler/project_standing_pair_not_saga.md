---
name: project-standing-pair-not-saga
description: Standing-pair creation reclassified from saga to single-context async; corpus is 2 sagas; spec/ADR cross-ref state after PR spec/standing-pair-not-a-saga-v2
metadata:
  type: project
---

Standing-pair creation (spec §5.15.8) was reclassified from a cross-context saga to **single-context async creation** (PR branch `spec/standing-pair-not-a-saga-v2`, commit 37cf92e51, dated correction 2026-06-18).

**Why:** A 2-member MLS group is ONE context, not two. Replica sync is MLS (epoch-ordered Commits + bootstrapping Welcome) + the event-log RFC-6962 consistency layer — not a saga journal. A saga only coordinates atomicity across 2+ *distinct* contexts sharing no sync protocol. The prior saga framing (Prepare-A/Prepare-B/CreationReceipt/reserve-not-consume, authored in PR #1793) was a miscategorization.

**The corpus is now exactly TWO live sagas:** §6.2.4 cross-context tool invocation and §5.14.13 broadcast-hosting handshake. Standing-pair creation is reached via the `standing_context` get-or-create entrypoint (single-creator rule: lower DID `did_lo` creates the 1-leaf group + add_members peer; higher DID awaits Welcome). Consent gate applied by joining peer on Welcome receipt (async, no synchronous Rejected → closes a block/existence reply oracle).

**How to apply:** Any future doc/code asserting "three sagas" or "standing-pair saga" or `SagaInput::StandingPairCreate` / `creation_receipt.rs` as live is stale. Those Rust types/scaffolding are slated for deletion in a SEPARATE code-correctness PR (the spec PR was docs-only). DEFERRED-commit-11-saga-use-cases.md preserves the original saga framing under dated `> **Corrected (2026-06-18)**` / `*(Original framing, superseded)*` blockquote markers — that historical text is intentional, not stale.

**Cross-ref anchors confirmed live (06-22 review):** §3.7.1 (Block List Storage, 03-identity.md) + `is_globally_blocked`; §5.12.1 / §5.12.2 / §5.12.6; §9.4.3 / §9.5.1 / §9.6.1; §17.16 / §5.2.1; ADR-049 §3 / §3a / §9. The previously-bogus `§2F` anchor is gone and no new bad anchors introduced. §5.15.1–§5.15.8 numbering contiguous. The `13200-13999` error-band reserved-row example was de-specialized from "standing-pair handshake" to "Future cross-context saga families."

**GOTCHA (review-process):** This was a DOCS-ONLY review of commit 37cf92e51 while the working tree sat on a DIFFERENT branch (`chore/fuzz-pin-nightly`). Plain `grep .docs/` reads the WORKING TREE and returns the OLD pre-correction text — it falsely shows "three sagas" / saga machinery still present. MUST scan with `git show 37cf92e51:<file> | grep` to assess the reviewed tree. The prds/main.json `CreationReceipt` hit is a DIFFERENT unrelated receipt (general create_context two-phase rollback), correctly out of scope.
