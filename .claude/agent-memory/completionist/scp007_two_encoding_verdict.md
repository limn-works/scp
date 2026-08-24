---
name: scp007-two-encoding-verdict
description: SCP-007 (DID publish/resolve/cache/republish) per-criterion audit after the two-encoding amendment — 15/23 met, keep pending; records which layer each gap lives in.
metadata:
  type: project
---

SCP-007 in `.docs/prds/main.json` was flipped `done` → `pending` by an earlier agent; a
per-criterion re-audit against the Rust source on 2026-08-23 confirmed the flip: 15 of 23
acceptance criteria are met.

**Why:** the two-encoding amendment (§3.10.5, §18.2.2A/C/D, §3.10.10) rewrote several of
SCP-007's criteria. The pre-amendment implementation publishes the full JSON document to
Mainline and parses Mainline records as JSON, which the amendment forbids.

**How to apply:** when re-auditing SCP-007 or SCP-239 (`.docs/prds/reachability.json`, same
`SCP-IDENT-1061` gate), these eight gaps are the checklist. Three greps settle most of it:
- `grep -rn "SCP-IDENT-1061" crates/` → nothing (spec 18 §18.2.2B line 226 already says so).
- `grep -rn "BootstrapCore" crates/` → nothing; `ResolvedDidDocument` is a struct at
  `crates/scp-identity/src/resolver.rs:69`, not §3.10.10's two-variant enum.
- No DNS-packet encoder / `simple-dns`-class dependency anywhere in the workspace, so the
  did:dht Mainline encoding does not exist.

Unmet: 1 (two encodings), 2 (size gate), 8 (re-resolve bootstrap nodes per retry),
10 + 12 (RepublishManager wiring), 13 + 14 + 16 (BootstrapCore resolution), 19 (stale warn).

**Two findings worth carrying forward beyond the verdict:**
- `RepublishManager` (`crates/scp-identity/src/republish.rs:415`) has **zero** non-test
  construction sites repo-wide; `start_republishing`/`stop_republishing` are called only
  from that file's own `#[cfg(test)]` module. Everything in criteria 6/7/9/11 is real code
  that nothing runs. Its only `RelayPublisher` impls are test doubles.
- `crates/scp-identity/src/dht.rs:952` carries the comment "log a warning but still return
  it" directly above a bare `return Ok(cached);` — comment-vs-code drift; `Staleness::Stale`
  is matched nowhere outside a test.

Related: [[did_two_encoding_amendment_2297]] (the amendment itself), [[scp245_per_layer_healing]].
