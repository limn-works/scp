---
name: adr049-pr6-prepd-export-floor-passthrough
description: API review of ADR-049 PR-6 Prep D widening export_crypto_state to take floors as params; APPROVED with minor doc fix
metadata:
  type: project
---

ADR-049 PR-6 Prep D (`feat/adr049-pr6-prepD-export-floor-passthrough`, commit 519d8f7d8) widened `MlsCryptoProvider::export_crypto_state` from `(&self, &[u8;32])` to add `sender_key_epochs: Vec<(String,u64)>` + `recv_sequence_floors: Vec<(String, ReceiveFloor)>`. 44 call sites (6 production, ~38 test) updated. Reviewed for API design; verdict APPROVED.

**Why the params-approach is sound (not scope creep):** `export_crypto_state` is `pub` but has ZERO callers outside scp-runtime (only doc-mention in scp-mls) — a genuinely internal API despite `pub`. The two param types match the FINAL atomic-core registry source EXACTLY: `Supervisor::export_recv_sequence_floors` (floors.rs:379) returns `Vec<(String, ReceiveFloor)>` and `Supervisor::export_sender_key_epochs` returns `Vec<(String,u64)>`. So the PR-6 read-authority swap becomes a pure one-token source change (`deps.crypto` → registry handle) with NO wrapper/type change at the 6 prod sites. Typing recv as the `ReceiveFloor` newtype now is the correct forward-looking choice.

**Key findings:**
- Provider twin `export_recv_sequence_floors` returns bare `(u64,u64)` while registry twin returns `ReceiveFloor` — divergent despite being called "twins." This forces the interim wrapper `.map(|(did,(epoch,sequence))| (did, ReceiveFloor{epoch,sequence}))` at every recv-floor call site. Wrapper is TRANSIENT at 6 prod sites (deleted by PR-6 swap) but PERMANENT at ~38 test sites. Unifying the provider twin on `ReceiveFloor` would delete the wrapper everywhere + complete the newtype's anti-transposition mandate — but ripples into the merge path (`validate_and_merge_recv_sequence_floors`, lifecycle_helpers.rs:1762 capture). Flagged as optional follow-up, NOT blocking.
- Two floor params are type-distinct (u64 vs ReceiveFloor) so positional arg-swap is compiler-caught. Good misuse-resistance on the two-arg ordering.
- Residual risk: floors are not bound to the passed `context_id` — caller could pass ctx-B floors with ctx-A id. Only caller discipline (uniform idiom threads same ctx var to all 3 calls) prevents it. Acceptable for internal API but is the inherent leak of the decomposition.
- Idiom is canonical & uniform across all 44 sites, identical at prod and test.
- **Doc quality: only actual fix-worthy item.** The method doc still says "The default implementation returns an empty Vec... Production providers that manage MLS groups MUST override this" — a trait-override contract that no longer exists (ContextCryptoProvider trait deleted, ADR-049 commit 12c.9e; MlsCryptoProvider is concrete/inherent). Stale, and the diff edits this exact block. New param/guard-span docs are otherwise excellent.

**Gotcha for future me:** the agent worktree is `/Users/alec/Developer/limn/scp/.claude/worktrees/agent-*`; the main repo `/Users/alec/Developer/limn/scp` is on a DIFFERENT branch. Always run git/grep from the worktree path or `git -C <worktree>`.
