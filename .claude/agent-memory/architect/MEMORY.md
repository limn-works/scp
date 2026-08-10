# Architect Memory

## Index
- [blockedBy = cannot START](decision_blockedby_cannot_start_not_cannot_finish.md) — express "cannot FINISH without" via description + downstream blockedBy, never by inverting an edge into a cycle.
- [Phantom provenance: the issue number IS the PRD](finding_phantom_provenance_issue_number_is_the_prd.md) — a comment citing "#NNNN owns this" is not provenance until a STORY covers it; grep the artifact, not the number.
- [Readiness gate vs observability accessor](decision_readiness_gate_vs_observability_accessor.md) — delete the GATE, keep the read-only count; schedule unconditionally + fail closed + backoff. Per-tick re-sampling is ALSO rejected.
- [PRD/code desync after a mid-branch story rewrite](finding_prd_code_desync_after_story_rewrite.md) — re-run every AC grep against HEAD; never trust a story's premise or a reviewer's AC index.

## ADR Review Fixes (Feb 2026)
10 HIGH-severity issues identified and fixed across Phase 1-3 ADRs:
- ADR-001: Epoch key grace window (30s max, in-memory only)
- ADR-002: payload_hash now covers plaintext before padding; provenance included in signature scope; pad/sign order canonicalized (hash->sign->pad->encrypt)
- ADR-005: TransportEvent enum replaces raw OuterEnvelope in subscribe streams
- ADR-008: Two-phase commit with CreationReceipt for atomic context creation
- ADR-009/016: Nonce format specified ({unix_millis}-{hex16}), freshness check (+/-5min), replay window tied to token expiry
- ADR-010: Full tool execution lifecycle added (ToolRequest/ToolResponse, timeout, cancellation)
- ADR-011: prove_absence uses sorted-neighbor approach (reveals 2 hashes, not all), rate-limited, admin-only default
- ADR-013/014: run_sync uses dedicated background event loop via run_coroutine_threadsafe (safe in all contexts)

## Key Patterns
- Envelope processing order: hash plaintext -> hash provenance -> sign -> pad -> sender-key encrypt -> MLS encrypt
- Forward secrecy grace windows must be in-memory only, never persisted, hard-capped at 30s
- UCAN nonce lifetime = max(token_expiry + 5min, first_seen + 24h)
