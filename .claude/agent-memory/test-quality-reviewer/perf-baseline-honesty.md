---
name: perf-baseline-honesty
description: perf_baseline.rs handshake measurement honesty — the None key-package short-circuit trap and its verified fix
metadata:
  type: project
---

# perf_baseline.rs handshake honesty (ADR-049 Decision 14)

File: `crates/scp-runtime/tests/perf_baseline.rs`.

**The trap (fixed in commit d11800f8c):** `MlsCryptoProvider::add_member`
(`crates/scp-runtime/src/crypto/mls/provider.rs:1162-1181`) short-circuits to
`AddMemberOutput::default()` under `cfg(any(test, feature="testing"))` ONLY when
`key_package_bytes` is `None`. Passing `mls_key_package_bytes: None` therefore
times only the non-crypto join pipeline while a doc may CLAIM MLS crypto ran —
a silent honesty defect that would let a real add-member regression slip the
same-machine pre/post perf gate.

**The fix pattern (verified faithful):** feed `join_context` a REAL
`Some(kp_bytes)` from `scp_mls::group::generate_key_package_with_context_params`
(bob credential + `[0xBB;32]` wrapping pubkey + SystemClock). That routes to
`add_member_from_bytes` → real `group::add_member` (leaf insert + Commit) +
Welcome/Commit TLS serialize + wrapping-key extract/store, then
`distribute_sender_key` HPKE seal + `drain_and_deliver_sender_keys` MLS-encrypt
(join_context at `lifecycle_helpers.rs:920` + `:946`). KP generation is untimed
setup (before `Instant::now()`); one fresh KP per context (random signer, so no
collision). Excluded: cross-node joiner-side Welcome consumption (needs bob's
own MLS provider = scp-testing 2-node harness = dep cycle) — doc is honest.

**Verification signal:** handshake jumps to ~7-12 ms/op (N=1 ~12ms cold, steady
~7.2ms) vs sub-ms non-crypto ops. If handshake shows sub-ms, the `None`
short-circuit crept back.

**Lesson for future perf/crypto tests:** a test that drives a crypto op through
a provider with a `cfg(test)` no-op accommodation MUST supply real inputs, or it
measures/asserts nothing. Cross-check the provider for `cfg(test)`/`feature="testing"`
short-circuits before trusting any "the crypto ran" claim. The smoke `.expect`
alone does not catch this — the no-op path also returns `Ok`.
