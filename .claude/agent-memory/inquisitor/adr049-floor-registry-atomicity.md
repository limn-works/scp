---
name: adr049-floor-registry-atomicity
description: ADR-049 floor-registry (PR-4→PR-6→PR-7) — what the "must be atomic" claim actually covers, and where floors are durable. Speeds future PR-6/PR-7 read-authority reviews.
metadata:
  type: project
---

ADR-049 splits the per-sender MLS epoch/replay floor registry across PRs: PR-4 (#2109,
origin/main 5d8074734) landed a Supervisor-owned `floors: DashMap` as a NON-AUTHORITATIVE
FOLLOWER; PR-6 flips read-authority onto it and deletes the provider mirror; PR-7 moves keys.

**Why:** floor enforcement is the anti-replay / epoch-poisoning defense (§23.17.2 Inv-2/3/4).

**How to apply (reusable premises when reviewing PR-6/PR-7 or any floor work):**
- **D1/D2 are HOME-DIVERGENCE hazards, not "big-PR" hazards.** D1 = Inv-2 bypass (merge writes
  registry, enforcement reads provider mirror). D2 = rollback window (capture reads registry that
  a non-atomic mirror-forward lags). Both require TWO live homes that can diverge, i.e. the
  read-authority FLIP or a partial retarget. Purely-additive scaffolding (new trait impls,
  uncalled registry bodies, a newtype) does NOT open D1/D2. PR-4 itself PROVED this — it landed
  the reserved `validate_and_merge_*` twins as inert `#[allow(dead_code, PR-6)]` in a separate PR.
  So "the read-authority flip is atomic" is TRUE; "every line of PR-6 must be one commit" is
  OVER-BROAD. The security-atomic core = {remove provider enforcement + seam gate + durable
  relocation + restore-guard capture-swap + mirror delete}. Prep is separable.
- **Floors are durable ONLY inside the MLS crypto blob.** `Supervisor.floors` is an in-memory
  `DashMap` with no serde/no persistence — empty on every cold start. The durable source is
  `export_crypto_state` reading the PROVIDER's `SenderKeyStore.epochs` + `recv_sequence_tracker`;
  sink is `restore_crypto_state`. Deleting the provider mirror WITHOUT relocating the
  serialization source/sink to the registry = durable D2 (cold restart loses all floors → replay
  reopens). This is real and mandatory; both master plans omitted it.
- **TOCTOU is genuinely closed** in `supervisor/floors.rs`: `check_and_advance_*` hold ONE DashMap
  entry write-guard across read→compare→write (pinned by `significant_drop_tightening` allow).
  `ContextFloors` bundles `sender_epochs` + `recv_sequence` in one entry (Decision 13).
- **`SenderKeyStore` lives in scp-protocol** (`crypto/sender_keys/mod.rs`, set_checked ~:342), NOT
  scp-runtime. Plans that cite "mod.rs:359" for it are miscrated — re-ground against scp-protocol.
- **F-3 (floors.rs:43-51):** `local_did` never coincides with a remote sender is a LOAD-BEARING
  invariant PR-6/PR-7 must preserve or split the maps. Easy to miss.
- **Single-writer gate→key-insert window is fail-SAFE (liveness), not security.** Gate-first
  ordering + single-entry guard already make "never install/accept below floor" structural in
  PR-6. Co-serialization deferral to PR-7 defers only liveness — robust even if PR-7 rescopes.
