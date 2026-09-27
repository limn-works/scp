# A Hash-Then-Reveal Commitment Needs Its Preimage From Commit Time Through Reveal Time

> **Dating note (2026-09-02):** this lesson describes `migrate_identity` and the pre-rotation model as Pre-Rotation Key Custody, §9.7.4.1 of `09-security-model.md`, read before the key-event-log recovery amendment. Root-Authority Recovery and Fork Precedence, §9.7.4.2 of that spec, states the amended model. The lesson's principle stands; its spec citations are historical.

## Rule

When a scheme publishes a commitment (a hash) at time T and requires the preimage at time
T+N, every reachable code path keeps a reference to the preimage from T through T+N, and the
longest possible delay sets the bound. A path that destroys or never stores the preimage
before the reveal site breaks the scheme: verifiers reject the proof and reveal becomes
impossible.

| Commitment | Preimage | Spec | Lifetime |
|---|---|---|---|
| `pre_rotation_commitment` | pre-rotation public key | §9.7.4.1, §9.7.4.2 R1 | inception → the next reveal-authorized event (possibly years) |
| KeyPackage | KeyPackage init key | RFC 9420 | publish → consumption |
| sender key commitment | sender key | §9.16.2 | distribution → destruction |

## Detection

Find each hash over key material (`Sha256::digest`, `*_commitment`), trace where its
preimage is generated, stored, and needed again, and look for a destroy, drop, or scope end
before any reveal site. Then test the whole commit-to-reveal cycle on emitted bytes, as
`.docs/lessons/behavioral-invariant-must-be-asserted-on-every-bridge.md` describes.

## The pre-rotation case

`create` published `SHA-256(pre_rotation_public)` and then destroyed the pre-rotation key
under a literal reading of §9.7.4.1 item 5f; the key handle never reached `ScpIdentity`, and
migration generated a fresh key whose hash could not match. Three fixes were weighed:

1. **Exempt in-memory custody in the spec.** Rejected: it gives up compromise recovery in
   that profile.
2. **Keep the key in operational custody** (`pre_rotation_key: KeyHandle` on `ScpIdentity`).
   Rejected: an attacker who compromises operational custody also gets the recovery
   backstop, which §9.7.4.1 item 3 storage isolation forbids.
3. **A separate `PreRotationCustody` trait with its own `PreRotationKeyHandle`.** Landed.
   `ScpIdentity` carries only `pre_rotation_commitment`; `create` returns
   `(ScpIdentity, KeyEvent, PreRotationKeyHandle)`; `migrate_identity` takes the handle
   and a `&impl PreRotationCustody`. The only implementation, `InMemoryPreRotationCustody`,
   compiles under the `testing` feature alone, so a shipped build has no backend and
   `create_inner` in `crates/scp-identity/src/config.rs` fails closed with
   `IdentityError::NoPreRotationBackend` (`SCP-IDENT-1059`), per ADR-062 §Decision 6.

A distinct trait stops one object from serving both roles and cannot prove two foreign
callbacks use different hardware; see
`.docs/lessons/custody-substrate-isolation-holds-at-rest-not-in-transit.md`.
