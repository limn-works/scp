---
name: project-relay-write-path-review-round
description: SCP-RELAYRES-004 relay WRITE path branch — AC-6 publish-seam guarantee is OPEN by design decision; sanitizer belongs in scp-relay-client; spin-yield test helpers are invalid on multi_thread runtimes
metadata:
  type: project
---

Branch `worktree-agent-ac667e2f552c34a31` (relay DID-document WRITE path,
SCP-RELAYRES-004, #482). Local tip `2a1f14838`; `origin/worktree-agent-ac667e2f552c34a31`
is STALE at `9a7193702` (a single pre-rebase push, then the user declined pushing
as a standalone action). Branch is deliberately unpushed and has no PR.

**Why:** the user's standing rule is push+PR on completed reviewed work, but they
explicitly overrode it here — pushing a half-finished branch achieves nothing;
landing it is a separate decision that is theirs. Do not re-push or open a PR for
this branch without being asked.

**How to apply:**

1. **SCP-RELAYRES-004 AC-6 has an OPEN clause, on purpose.** The live-slot
   collapse removed a compile-time guarantee: `NodeDidPublisher` used to own the
   record slot and write it inside `publish`, so publishing without re-seeding was
   not constructible. The unified `NodePublishedState` needs document+relay_url+record
   together, so the slot cannot exist before the startup publish that produces its
   `record` — forcing the write out to three call sites. All three do write it (no
   live defect), but the guarantee is now conventional. The AC states the
   requirement and is marked NOT YET MET; `details.weakened_by_collapse` carries
   the restore plan (move the trait + `NodeDidPublisher` + startup publish-and-seed
   into the private `published_state` module so the trait method is unnameable
   outside it). It is escalated, not deferred — this seam has been restructured
   four times and CLAUDE.md's convergence rule says stop and reframe rather than
   grind a fifth pass without a human scope decision. Do not "fix" it unilaterally.

2. **Relay-supplied text is sanitized in `scp-relay-client::untrusted_text`,
   not in `scp-transport`.** Siting it in `scp-transport::native` made a
   workspace-wide invariant a module convention that 14 sites already violated —
   and a hostile relay picks which adapter is used (`TransportSelector::should_try_quic`
   enables QUIC iff the relay advertises it in its own `.well-known/scp`), so the
   unsanitized QUIC/UDP/WebTransport paths were a one-step bypass. The helper lives
   beside `RelayMessage` in the wasm-safe leaf both `scp-transport` and `scp-client`
   depend on. Any NEW relay-error consumption site must call `relay_error_text`.
   Not re-exported from `scp-transport` — ADR-057 forbids shim re-exports.

3. **`is_control()` is not a sanitizer.** It is Unicode category `Cc` only, and
   misses U+2028/U+2029 (line terminators in most log viewers and all ECMAScript
   pipelines) and U+202E (bidi override). Use the positive whitelist.

Related: [[feedback-spin-yield-invalid-on-multi-thread-tests]]
