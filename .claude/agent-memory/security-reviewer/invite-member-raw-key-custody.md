# invite_member raw-key vs custody (2j-ffi-slice, HEAD 648d4d2fa) — 2026-07-05

Reviewed the closure→`&ed25519_dalek::SigningKey` collapse on `Supervisor::invite_member`
(supervisor.rs:10552). Verdict: raw-key collapse ACCEPTABLE for invite_member itself, but
surfaced a systemic custody finding + a hard build/authz bug.

## Custody model (authoritative)
- `KeyCustody` trait (scp-platform/src/traits.rs:324) has `sign(handle,data)`, `public_key`,
  `dh_agree`, `ed25519_to_x25519_agree`, `derive_pseudonym` — ALL keep key inside. Trait doc
  explicitly: "Ed25519 keys may be hardware-backed (Secure Enclave, Keystore)."
- `export_ed25519_signing_key` is NOT on the trait — inherent method only on software concretes
  `InMemoryKeyCustody` (testing/key_custody.rs:168) + `FileKeyCustody` (file.rs:559). Hardware
  custody physically cannot export. So any raw-`&SigningKey` API = software-custody-only.
- FFI `resolve_signing_key` (scp-ffi/src/context.rs:1227) EXPORTS the raw key via
  `export_ed25519_signing_key`. Used by production governance FFI (propose/vote/export).

## SYSTEMIC (pre-existing, NOT introduced by this diff)
- The whole governance-actor signing protocol is raw-key: `propose/vote` take `&SigningKey` →
  `SigningKeyBytes(Zeroizing<[u8;32]>)` (commands.rs:534) copied over the mailbox → actor
  `to_signing_key()` reconstructs + signs in-process. So propose/vote/invite are ALL
  hardware-custody-incompatible today. True fix = custody-backed signer (KeyHandle+`KeyCustody::sign`)
  threaded through the actor command protocol, used for BOTH proposal and bundle.
- invite_member inherits this by (correctly) routing AddMember through `propose_governance_action`.
  Keeping the removed bundle `sign` closure would be false comfort — the same call already needs
  the raw seed for the proposal. One-key-both-sigs is a genuine improvement (closes
  proposal-signed-as-A / bundle-claiming-B divergence).

## HARD BUGS in this diff (report)
1. invite_member (ungated `pub async fn`) calls the `#[cfg(any(test, feature="testing"))]`
   UNCHECKED `propose_governance_action` (supervisor.rs:11912). VERIFIED `cargo check -p scp-runtime`
   → E0599 (does not compile w/o testing). CI masks it: CI always builds `scp-runtime/testing`.
   Breaks the moment the FFI export slice wires it. Fix = `propose_governance_action_checked`.
2. Unchecked variant skips the `GovernancePropose` UCAN capability check (inner
   check_capability=false); production `_checked` enforces it. Same one-line fix.
- Compiler literally suggests `_checked`.

## Clean
- Key lifetime in invite_member: borrowed `&SigningKey`, transient `.sign()`, not cloned/logged/
  persisted. SigningKeyBytes is Zeroizing. Joiner side still custody-only (ed25519_to_x25519_agree).
- Future FFI invite_member export must zeroize the owned key from resolve_signing_key (cf. context.rs:5187).
