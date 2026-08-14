# Optional SDK tier in check-sdk-coverage.py (additive, non-weakening)

To add an SDK column that is a SUBSET (only some ops) without forcing a mostly-false
column onto every op: add the tier to the ITERATION set `sdks` (so any cell that
claims it is statically verified) but NOT to `expected_sdks` (the required-on-every-op
set). Also register it in SDK_PATHS, SDK_EXTENSIONS, the parser map, and _EXTRACTORS.

Introduced for `typescript-wasm` (ADR-057). This is a LEGITIMATE enforcement-file edit
per CLAUDE.md (expanding coverage) — the four core tiers stay required; nothing weakened.
When reviewing a new optional tier, confirm it is absent from `expected_sdks`, else it
silently becomes mandatory on all 22 domains.
