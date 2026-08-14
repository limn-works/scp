# ADR-056 context_id_to_bytes chokepoint review (PR #1931, branch chore/fuzz-pin-nightly @859f1af13)

Reviewed the ADR-056 keying-funnel change: `context_id_to_bytes` (state.rs) promoted to `pub`,
decode-64-lowercase-hex-else-SHA256. All real-context keying sites (FFI event-log ×4, FFI
testing.rs ×6, node.rs add_member, runtime: messaging/governance/key_destruction/lifecycle/ttl/
builder/mls-provider seal+open guards) routed through it.

## Verdict: essentially clean. One LOW finding.

### LOW — new broken intra-doc links to `generate_context_id` in scp-runtime
- state.rs:2034 and state.rs:2054 use `[`generate_context_id`]` as intra-doc LINKS, but
  `generate_context_id` lives in `scp-ffi-common`, which scp-runtime does NOT depend on →
  `rustdoc::broken_intra_doc_links` warnings (confirmed via `cargo doc --no-deps -p scp-runtime`).
- builder.rs:696 ALSO writes `[`generate_context_id`]` but rustdoc did NOT warn on it (only first/
  some occurrences reported). Fix: use a plain code span `` `generate_context_id` `` (no brackets),
  as the protocol mod.rs doc rewrite already correctly does for `context_id_to_bytes`.
- NOT a hard CI failure: neither docs.yml nor ci.yml sets RUSTDOCFLAGS=-D warnings. Many pre-existing
  broken-link warnings already exist in scp-runtime. Cosmetic doc defect, newly introduced.

### Verified clean
- Chokepoint guard: strict len==64 && all-lowercase-hex; let-chains (edition 2024, rustc 1.95 OK);
  total/no-panic fallthrough; boundary tests (63/65/uppercase/non-hex) pass.
- All 6 new chokepoint tests + builder digest-keying test + 63 MLS provider tests pass.
- FFI removed-imports correct (no unused_imports; clippy -D warnings clean on scp-ffi/napi/testing).
- `scp_core::context::state::context_id_to_bytes` path resolves (pub mod + pub use re-export + pub fn).
- CI YAML well-formed; deleted gate (check-context-id-keying.sh + ci job) already gone in base; NO
  leftover refs anywhere (yml/sh/md/rs/CLAUDE.md). No dangling `needs:`.
- MLS seal/open guard strengthened from `context_id_bytes==` to `context_id_to_bytes==`: ALL production
  callers (build_encrypted_envelope, deliver_incoming, trust_recovery, supervisor synthetic) derive
  BOTH the 32-byte arg and inner.context_id from the same string via the resolver → consistent, no
  fail-closed regression.

### NOTE (not a defect — fail-closed by construction)
- supervisor.rs:3547 `recovery_send_notification_direct` deliberately calls RAW `context_id_bytes`
  for the synthetic `"identity-private-state"` pseudo-context (byte-identical to resolver for non-64-hex).
  Caller passes `payload.context_id`. IF a real 64-hex id ever reached this "unregistered context"
  branch (e.g. raced close), the raw call keys SHA-256(id) but seal's guard recomputes the DECODED
  digest → mismatch → fail-CLOSED CryptoFailed, NOT a silent wrong-key fail-open. Defensible.
