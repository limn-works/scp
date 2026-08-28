---
name: adr063-user-auth-gate-revision
description: Second-pass review of the ADR-063 context-declared user-authentication gate branch — which blockers closed, and where corpus-wide parameter enumerations keep drifting.
metadata:
  type: project
---

Branch `feat/adr-063-user-authentication-gate` adds a fifth ADR-039 Category C mechanism,
`user_authentication_required`. Revision `b5804574fa` closed three prior blockers (ADR-039
amendment pointer, §9.18.B registry rows, a mis-cited "§27.4.3 contradiction C9") but the
same class of gap reappeared elsewhere.

**Why:** this parameter is named in six artifacts at once — §4.9.3 of `.docs/specs/04-agents.md`,
§5.7 and §5.9 of `05-contexts.md`, §9.18.B of `09-security-model.md`, the Category C entry of
`00-open-questions.md`, ADR-039's Category C bullet list in `.docs/adrs/phase-1.md`, and
`.docs/prds/agent-binding.json`. A rewrite of one sentence leaves its twins standing.

**How to apply:** on any later pass over this branch, re-run these checks rather than trusting
a commit message:
- Enumeration twins: §4.9.3's opening was changed to "members' keys" but §4.7 (`04-agents.md:122`),
  the §4.9.4 bullet (`:252`), and `05-contexts.md:860` still read "what an agent may do".
- Line-number citations into `.docs/adrs/phase-1.md` shift whenever a bullet is added to ADR-039;
  the ADR-039 key-properties table is `:1269`, the Category C heading `:1289`, Enforcement Stack
  layer 1 `:1298` (NOT `:1296`, which is the heading).
- Story attribution: `05-contexts.md:726` says SCP-AB-032 adds all four `ContextParams` fields;
  §9.18.B says SCP-AB-028/030/031/037 do. Those two cannot both be true.
- No story adds a `GovernanceAction` variant (`crates/scp-protocol/src/context/governance/mod.rs:543`),
  though §5.9 says stories deliver the governance path for all five mechanisms.
- Every story adding a `ContextParams` field must regenerate `kat_invitation_bundle_signing_hash`
  (`crates/scp-protocol/src/context/invitation_bundle.rs:617`); only SCP-AB-037 does.

Verified-true absence claims (do not re-litigate): no Rust caller of `assert_request`;
`DidDocument::set_custody_attestation` has only test callers; `ContextParams` declares none of the
four fields; `GovernanceAction` carries none of the five changes; the three bridges return
`SCP-IDENT-1016` at `crates/scp-ffi/src/identity.rs:985`, `crates/scp-ffi/uniffi/src/bridge.rs:4042`,
`crates/scp-ffi/napi/src/scp.rs:4640`.

Related: [[adr057_transport_wasm_surface_parity]].
