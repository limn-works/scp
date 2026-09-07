---
name: project-frozen-snapshot-live-slot-scp-node
description: scp-node frozen-snapshot defect class + the live-slot remedy (PublishedDidRecord / NodeDidDocument); NodeState.relay_url is the remaining unfixed sibling and needs a public-API call
metadata:
  type: project
---

`crates/scp-node` has a recurring **frozen-snapshot defect class**: a value that a
background task later re-derives is stored *by value* at build time by one or more
readers, so only the task's own copy advances. Three instances found so far, all on
the NAT-tier-change seam (`apply_tier_change`, §10.12.1):

1. `RepublishManager` arms held a `RepublishEntry` by value — fixed `d672278a2` with
   `PublishedDidRecord` (a `watch` slot, private `set`, sole caller = the publish seam).
2. `NodeState.did_document` + `IdentityHandle.document` + the tier task's `current_doc`
   — three copies, one advanced — fixed `f551f63d9` with `NodeDidDocument`, same shape.
3. **STILL UNFIXED: `NodeState.relay_url`** (`crates/scp-node/src/http.rs`). Same writer
   (`apply_tier_change` returns the new URL), same staleness — `.well-known/scp` serves
   `relay:` and the `scp://context/...?relay=` URIs from it, so after a tier change the
   PUBLIC discovery document advertises a dead relay URL. Arguably worse than the
   dev-API case (public + unauthenticated vs token-gated).

**Remedy pattern** (copy it, don't re-invent):
- A `#[derive(Clone)] pub(crate) struct X(Arc<tokio::sync::watch::Sender<T>>)`.
- `fn set(&self, ..)` **private to the module**; its only caller is the site that
  *produces* the new value, writing it in the same expression.
- The producing function must **not return** the value — returning it is the defect
  shape ("trust every holder to refresh").
- Every reader stores a clone of the SLOT, never of its contents.

**Why (3) was not bundled into `f551f63d9`:** it changes a public signature —
`ApplicationNode::relay_url(&self) -> &str` cannot return a borrow out of a `watch`
slot, so it must become `-> String`. That is an orchestrator-level API decision, not a
mechanical fix. Callers are small: `self_host.rs:~1893` + ~6 test assertions.

**How to apply:** when touching any `NodeState` / `ApplicationNode` field that the tier
task or another background loop re-derives, check whether it is a slot. If it is a plain
value, it is stale by construction. Also see [[project-relayres-004-selfhost-rewiring]].

**Gotcha:** `build_domain_inner` sits at EXACTLY the `clippy::too_many_lines` budget
(100). `too_many_lines` ignores comment/blank lines, so trimming comments buys nothing —
you must remove *code* lines (e.g. fold a single-use `let` into its call site).
`build_no_domain_inner` already carries `#[allow(clippy::too_many_lines)]`.
