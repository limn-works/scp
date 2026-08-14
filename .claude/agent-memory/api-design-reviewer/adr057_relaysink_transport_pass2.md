---
name: adr057-relaysink-transport-pass2
description: ADR-057 browser relay transport (RelaySink) pass-2 review @4c8afb284 — 3 majors resolved, 1 minor residue
metadata:
  type: project
---

# ADR-057 browser relay transport — RelaySink pass-2 (feat/adr057-transport-jssocket @4c8afb284)

PASS 2 of double-zero. Verdict: the 3 pass-1 MAJORs are RESOLVED and well-designed. Only residue = 1 minor + nits. Effectively APPROVED.

- **F-API1 (socket-failure vs entry) RESOLVED.** `ScpClient::subscribe` (client.rs:881) is best-effort — swallows ALL send errors via `if let Ok(frame) ... let _ = send`. So `create_context`/`join` never fail on a transient socket error → no ContextAlreadyExists-on-retry. `resubscribe_all` (client.rs:901) is discoverable, idempotent, doc says "embedder MUST call after relay sink reconnects/resumes". `announce_pseudonym` swallows only `Transport` (propagates crypto/codec). create_context # Errors correctly OMITS Transport.
- **F-API2 (PseudonymAnnounced) RESOLVED + symmetric.** Real arm in wasm `drain_events` (lib.rs:586) AND `event_kind` (lib.rs:922). Receive side buffers `ContextEvent::PseudonymAnnounced{member_did,pseudonym}` (client.rs:1910); drain maps member_did→senderDid, pseudonym→payload (raw 32-byte routing id). Round-trips through snapshot. Variant carries required fields (membership.rs:819).
- **F-API3 (Socket→RelaySink rename) RESOLVED except ONE stray.** Rust port `RelaySink` (relay_sink.rs), JS `JsSocket` object + `JsSocketAdapter` (socket.rs) all consistent; excellent module docs explain sink-vs-socket direction split. Residue: **error.rs:53** `ClientError::Transport` docstring still says "The injected [`Socket`](crate::Socket)" — wrong type + broken intra-doc link (`crate::Socket` doesn't exist; only `RelaySink` exported). NOT compile-denied (no broken_intra_doc deny in workspace) so passes CI as a warning. Nit: wasm error.rs:67 comment "outbound Socket".
- Minors settled: `epoch` param dropped from `ScpMlsGroup::derive_pseudonym` (group.rs:272, `None` fixed at core boundary); `from_parts` gated `#[cfg(not(wasm32))]` (lib.rs:293) so no soft clock substitution on shipped wasm.
- Doc-completeness nits: `join_context_encrypted` # Errors omits `Codec` (announce_pseudonym at :776 can emit ClientError::Codec). Post-persist ordering wrinkle: install_local_routing (derive_pseudonym→Mls) + announce (Codec) run AFTER insert+persist in both create/join, so a non-Transport failure there strands a created context behind an Err→retry=ContextAlreadyExists — same wrinkle F-API1 fixed, narrowed to effectively-unreachable crypto/codec failures.
