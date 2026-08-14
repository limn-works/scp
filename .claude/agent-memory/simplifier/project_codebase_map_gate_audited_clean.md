---
name: codebase-map-gate-audited-clean
description: The MAP.md enforcement system (scripts/check-map.py + .docs/standards/map.md) was audited against the over-engineering/non-convergence BLOCKER charter and passed clean — don't re-litigate its soundness.
metadata:
  type: project
---

`scripts/check-map.py` (the federated MAP.md codebase-map gate) + `.docs/standards/map.md` were reviewed for the exact BLOCKER classes the simplifier charter exists to catch (non-convergent denylist, redundant enforcement of a guaranteed property, cost-out-of-proportion). **Verdict: clean bill, no BLOCKER — principled convergent hardening.**

Key facts so future me doesn't re-open this:
- The mapped-area set is a **closed, derived whitelist** (subdirs of crates/+bindings/ + a fixed 10-entry list); frontmatter is a **closed grammar** (unknown keys rejected); sections are exact-title against a closed 7-tuple. This is the *positive-whitelist* shape the charter wants, not a spelling-chasing denylist.
- The ~6 hardening guards added across review rounds each close a **different decidable class** (fence-awareness, --no-renames rename endpoints, symlink confinement, size ceilings, linear ReDoS regex, BOM) — convergent, not "one more spelling."
- The standard **explicitly refuses semantic content-scanning** and cites the CLAUDE.md over-engineering guardrail by name; the gate does only the decidable subset (coverage/anchors/freshness) and delegates semantics to review (chronicler). This is the opposite of redundant enforcement.
- `--stamp-audit` is a proportionate ~65-line advisory (exit 0) surfacing stamp-only `verified:` bumps for reviewer scrutiny — keep it.
- Sizes at audit: gate 675 lines (~553 code), tests 870 lines / 60 cases (~1.3:1).

Only nits found: one redundant test (`test_missing_section_fails` subset of the parametrized `test_each_missing_section_fails`); root-MAP.md-lists-every-area is a decidable property currently left to review (optional to gate, don't add reflexively).

See [[project_commit12_helpers_logic_split]] for the related pure-helpers gate.
