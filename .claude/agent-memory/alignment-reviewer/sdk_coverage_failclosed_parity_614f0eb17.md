---
name: sdk-coverage-failclosed-parity-614f0eb17
description: Round @ 614f0eb17 ALIGNED — TS uniform typed-error wrapping (all 203 scp.ts methods), PermissionError alias removal, ADR-053 citation verification
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ 614f0eb17 (2026-06-22) — ALIGNED, 0 blocking

Incremental over prior `341df72cc` (ALIGNED). Review ONLY diff `341df72cc..HEAD` (12 commits, +2146/-1006, dominated by scp.ts +2723/-... rewrite). HEAD `614f0eb17` == origin/fix/sdk-coverage-fail-closed-and-parity.

**WORKTREE TRAP (cost time):** prompt's worktree is `/Users/alec/Developer/limn/scp/.claude/worktrees/agent-a0bbc61dae626fa6c` at 614f0eb17. The MAIN repo `/Users/alec/Developer/limn/scp` is on `feat/actor-2c-xctx-tool-saga` @ b321248e1. `cd /Users/alec/Developer/limn/scp` + git grep silently runs against MAIN worktree → ADR-053 appeared "phantom" (false alarm). ALWAYS `cd` into the agent worktree path or use `git -C <worktree>`. Read tool also returned STALE pre-edit file content (errors.ts showed un-removed PermissionError alias) — coder agents modified the worktree outside session, harness file-state desynced. Trust `git show HEAD:<path>` over Read tool here.

**5 focus areas all CLEAN:**
1. Uniform typed-error surface: all 203 scp.ts bridge-calling methods wrapped `try{...}catch(err){throw mapBridgeError(err)}`. Verified by AST script: 0 methods call `this.#native.` without mapBridgeError. mapBridgeError (errors.ts:265) preserves message VERBATIM → bracketed `[SCP-X-NNNN]` prefix survives. Matches sdk-common.md §Error Hierarchy ("same hierarchy all SDKs, message + machine code").
2. PermissionError alias removal: clean — deleted from errors.ts:88-92, index.ts barrel export, errors.test.ts. No orphans. Canonical name always UcanPermissionError (sdk-common.md:13). Consistent w/ no-migration-pre-release.
3. trust.ts classification: STILL message-prefix regex `/^\[SCP-PERM-\d+\]/` + `/^\[SCP-CTX-\d+\]/` (NOT instanceof) — correct because mapBridgeError preserves prefix at message-start. Mirrors Python code-based dispatch (trust.py:769-770 except bridge.UcanError + startswith[SCP-PERM-3030]). Tests tightened: assert typed UcanPermissionError + code + message preserved (was brittle `.toBe(identity)`). Fixed stale code `SCP-CTX-1001`→`SCP-CTX-2001` (CTX band=2000-2999). 103 TS tests pass; tsc+biome clean.
4. ADR-053 (.docs/adrs/ADR-053-pre-rotation-custody-substrate-isolation.md, Proposed, Phase 6): FAITHFUL. §9.7.4.1 §3/§4/§5 quoted verbatim vs 09-security-model.md:655-696 (storage isolation, 6 custody methods incl Argon2id 64MiB/3/4 + 128-bit, ceremony 5a-5f). ADR-003 §4b matches phase-1.md:375-409 (migrate_identity reveal→consume→import-as-#0, separate pre_rotation_custody/key_custody trait objects). In-source cites accurate: UniFFI bridge.rs generate_ephemeral_ed25519_seed ~676, "Substrate isolation NOT yet satisfied" ~689, fail-closed import_ed25519_signing_key error ~736 (quoted VERBATIM); PyO3 identity.rs InMemoryPreRotationCustody 824/922/1052.
5. No phantom provenance. discovery.py §22.7→§22.11.3 citation correction CORRECT (§22.7=Trust Levels prose, §22.11.3=Address Resolution type schema). TypedDict total=False→total=True w/ NotRequired = honesty improvement: source_id is always-present-nullable matching bridge wire (discovery.rs:90-93 always writes "source_id":Option, test:180 asserts null for Domain layer).

**2 OBSERVATIONS (non-blocking, both PRE-EXISTING, orthogonal to branch scope):**
- (OBS-1) ResolutionLayer tag drift: code+both SDKs emit `"HandleRegistry"` (discovery.rs:37, discovery.py Literal, TS "HandleRegistryVerified") but spec §22.11.3 ResolutionLayer variant tag = `"DiscoveryContext"` (09... wait 22-human-readable:1044). Whole-subsystem drift (Rust core ContextDiscoverySource::HandleRegistry, FFI, 2 SDKs all say HandleRegistry; only spec says DiscoveryContext). Pre-existing at 341df72cc. Citing §22.11.3 now makes mismatch MORE visible. Honest fix is UPSTREAM spec (artifact-flow): rename spec tag HandleRegistry OR rename subsystem. Not this branch's job but worth a spec issue.
- (OBS-2) ADR-053 separates `consume`(step5) from §6 post-rotation-cycling cleaner than the spec's Partial-publish paragraph (09-sec:696) which conflates them ("AFTER cold-custody consumption step (§9.7.4.1 item 6...; migrate_identity step 5...)"). ADR more precise than upstream — minor upstream wording could tighten.

Cargo.lock quinn-proto 0.11.14→0.11.15 = RUSTSEC-2026-0185 patch bump. internal/bridge.ts: +§3.2.1 doc citation on custody-migration group (correct: recovery=§9.12, custody-migration=§3.2.1 DID-preserving). check-sdk-coverage.py: docstring-only (documents fail-closed exits added in prior range).
