---
name: project-relayres-004-selfhost-rewiring
description: SCP-RELAYRES-004 self-host rewiring (B1-B7) — signed record is now an OUTPUT of DidMethod::publish; residual tier-change staleness gap left unfixed
metadata:
  type: project
---

SCP-RELAYRES-004's self-host wiring was re-done on `worktree-agent-ac667e2f552c34a31`
(commits b6032764e, dffb133c1, 36358fc17 on base 4f6c247d3) after an 8-reviewer
INCOMPLETE/UNSOUND verdict. The trait/frame work was sound and was preserved.

**The load-bearing architectural change:** `DidMethod::publish` now returns
`RepublishEntry` (the signed BEP44 `(public_key, seq, signature, value)`) instead
of `()`. The signed record is an OUTPUT of signing, threaded
`publish_did_document_for_mode` → `ApplicationNode::published_did_record()` →
`serve_hosted_site` → `start_self_did_republishing(entry: Option<..>)`.

**Why:** the republish entry used to be reconstructed by asking the DHT to read
back the record the node had just signed. That single seam caused three separate
reviewer findings — a CRITICAL (one `Ok(None)` resolve miss ⇒ permanently dormant
republish manager ⇒ DID unresolvable ~2h later), a HIGH (no sequence floor check,
so a lagging/malicious responder's older record got durably republished under the
node's own authority), and a frozen-snapshot bug.

**How to apply:** when a value is computed during signing/minting, return it.
Never re-derive it from a storage or network read-back — the read-back is a new
trust input and a new failure mode for something you already knew.

## Residual gap deliberately NOT fixed (flag it, do not silently inherit)

`apply_tier_change` (crates/scp-node/src/lib.rs) republishes the DID document on a
NAT tier change with a NEW seq+signature, but nothing re-seeds the running
`RepublishManager`. The manager keeps republishing the pre-tier-change entry.
No story owns this: SCP-RELAYRES-006 owns the relay-client binding,
SCP-RELAYRES-008 owns §3.10.5 step 3a create/update. The mechanical blocker is
that `spawn_tier_reevaluation` lives inside `build_no_domain_inner` while the
manager is built later in `serve_hosted_site` — connecting them needs a channel
that does not exist. `DidPublisher::publish` (the object-safe boxed surface the
tier task uses) currently discards the record with an explicit
`.map(|_signed_record| ())`; that is the seam to widen when a story owns it.

Related: [[project-adr057-transport-jssocket]]
