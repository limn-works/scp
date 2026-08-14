---
name: scp-out-007-postmerge-audit
description: Post-merge completeness verification of SCP-OUT-007 (scp-mcp lexical outlet↔tool translator) at squash commit 6344c1c67 / PR #2249 — COMPLETE, zero findings
metadata:
  type: project
---

SCP-OUT-007 post-merge audit (origin/main squash 6344c1c67, PR #2249, closes #2219): the
scp-mcp lexical outlet↔tool translator re-port. Verdict COMPLETE, zero findings.

**Why:** belt-and-suspenders 2nd completeness pass — pre-merge code reached double-zero but
the final 3-line PRD-text delta got only one deep pass. Focus was phantom-provenance +
14-AC completeness on the MERGED result.

**How to apply / what was checked (all PASS):**
- scp-mcp cites NO ADR-049 (MCP = spec §8.5 + ADR-015; OutletKind classification = §5.4.2 +
  SCP-OUT-011 enum + SCP-OUT-013/014 runtime gate). `grep ADR-049 crates/scp-mcp` clean.
- scp-mcp cites NO SCP-OUT-017. In outlet.json the only 3 SCP-OUT-017 occurrences are
  structural (gate-classification stories array L35, the SCP-OUT-017 story's own id L1113)
  + one honest auditNote changelog (L634). None in a description/AC misattributes the
  canonical enum or runtime gate to 017 (017 = SDK-surface exposure only).
- SCP-OUT-007 + SCP-OUT-002 descriptions present-tense/correct: canonical enum=SCP-OUT-011,
  runtime gate=SCP-OUT-013 + stems SCP-OUT-014. No stale "until SCP-OUT-017 provides
  sentinel/enum" phrasing (the one "sentinel" hit is the auditNote noting its REMOVAL).
- All 14 ACs (AC0-13) met by merged code. Canonical `pub use scp_core::context::outlets::
  OutletKind` (serde rename_all=lowercase at scp-protocol .../outlets/mod.rs:135); no local
  sentinel; no capitalized wire residue (only a test asserting "Query" is REJECTED). Four
  opaque-payload verbatim sites confirmed (arguments ×2, _meta ×2). A3 sibling-clobber guard
  (skips isError/content/_meta) both directions. OutletListing{advisory_kind,definition} in
  client.rs. FFI kind passthrough `kind: t.kind` from real `rt.outlet_registry` in PyO3
  ref bridge (scp-ffi/src/mcp.rs:703) + uniffi (bridge.rs:4910); rename landed in napi too
  (its McpNapiBridgeProvider is a pre-existing placeholder returning empty tools — not a
  007 gap). identity fn `outlet_kind_to_mcp` deleted (0 matches). AC9/AC10 greps pass.
- validate-prd.py: PASS (18 files, 443 stories) via detached worktree at origin/main.
  SCP-OUT-007 status="done", honest.
- AC8 (cargo test -p scp-mcp) verified by test-body inspection (19 integration + ~30
  translator unit tests) + pre-merge double-zero; not re-executed this pass.

**Lesson:** working-tree HEAD can lag origin/main (outlet.json didn't exist at HEAD) — for
post-merge audits extract everything via `git show origin/main:<path>` and run gates in a
`git worktree add --detach <tmp> origin/main` (never checkout on main worktree).
