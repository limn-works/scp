# ADR-049 Phase 2J FFI slice (feat/adr049-2j-ffi-slice)

## UPDATE HEAD 0dc94674e — signed InvitationBundle fix (post BLACK-2J-FFI-02)

Fix moved authority to a creator-SIGNED, HPKE-sealed InvitationBundle (full genesis
ContextParams). Joiner opens (split-custody external-DH), verifies creator sig,
verify_structural_consistency, then 0xFF02 cross-check. spawn_actor_from_welcome
supervisor.rs:10728-10990. envelope_seal.rs = HPKE. invitation_helpers.rs = snapshot.

RESIDUAL — BLACK-2J10-001 STILL LIVE for SingleAdmin ONLY:
0xFF02 (group_context_extension.rs:141 verify_against:333) binds governance_HASH
not creator_did. SingleAdmin is a DID-LESS unit variant (params.rs:179); admin =
creator_did (state.rs:1775 SingleAdminEngine::new(creator_did)). bundle.verify only
proves "creator_did's OWN key signed it" — self-asserted. SHA256(JCS("SingleAdmin"))
is constant → 0xFF02 says nothing about WHO. build_welcome_joiner_state:11291
installs bundle.creator_did as admin, NO leaf/credential cross-check.
ATTACK: in-group member Mallory calls invite_member(creator_did=Mallory) — no admin
gate; MLS Add carries Alice's unchanged 0xFF02; params match → victim installs
Mallory as admin of Alice's context. CLOSED for Threshold/Majority/Unanimity (voter
DIDs ARE in the governance hash). FIX: bind creator_did to MLS leaf-0 credential
(creator DID IS committed there). Spec gap §5.12.3.1 steps1-4 / §5.13.3 rules1-7.

SECONDARY: FFI still unwired — uniffi bridge.rs:9535-9543 builds OLD
WelcomeJoinRequest{params,welcome_bytes}+2-arg call; new sig is 4-arg<C:KeyCustody>
with sealed_bundle_enc/ct. Diff touched runtime ONLY. Runtime fix unreachable from
SDKs; "closes FFI-02" premature at binding layer (verify slice boundary/build).

STRONG/RESISTS: HPKE recipient binding (enc||pkRm UKS-closed, cross-recipient replay
fails, distinct domain sep); sig strip→fail, can't forge a SPECIFIC other creator;
welcome/params/context_id inside signature; cross-context replay closed.

---
# (prior pass) ADR-049 Phase 2J FFI slice (HEAD 92bcff46c)

Makes spawn-from-Welcome joiner path production-reachable: `pub Supervisor::{reserve_key_package,
spawn_actor_from_welcome}` (bare DID) + 3 bridge exports (PyO3/NAPI/UniFFI) + SDK wrappers.

## Findings

### BLACK-2J-FFI-01 (HIGH) — UniFFI non-atomic rollback race deletes winner's UCAN state
- crates/scp-ffi/uniffi/src/bridge.rs context_join_from_welcome (~line 255-291)
- PyO3/NAPI use ATOMIC `register_ffi_state` Entry::Occupied (check-and-insert). UniFFI instead:
  separate `context_handle_registry().contains_key` (handle not registered until AFTER spawn) +
  `ucan_preexisted = with_ucan_state().is_some()` flag + idempotent `ensure_ucan_registered` +
  conditional `remove_ucan_state` on failure. Non-atomic check-then-act.
- Concurrent same-context_id joins (the scenario core first-writer-wins/bootstrap_spawn_lock
  defends): both read ucan_preexisted=false → winner spawns+registers handle, loser fails
  first-writer-wins → `if !ucan_preexisted` removes the SHARED ucan state + known-context entry.
- Self-heal makes it worse not better: tool-invoke path (bridge.rs:4478) re-`ensure_ucan_registered`
  from handle → fresh UcanContextState with EMPTY nonce_tracker + EMPTY revocation_list →
  transient nonce-replay window + revocation reset for a LIVE context. Swift/Kotlin only.
- Fix: give UniFFI an atomic occupied-or-insert on the ucan_registry mirroring register_ffi_state.

### BLACK-2J-FFI-02 (MEDIUM/HIGH trust-assumption) — Welcome params/creator not bound to group
- build_welcome_joiner_state (supervisor.rs ~10847): governance engine, CapabilityCeiling,
  creator-as-admin, TTL all built from caller-supplied `params`+`creator_did`. ZERO cross-check
  vs the actual MLS group in welcome_bytes. context_id is an attacker-chosen routing label too.
- Was pub(in crate::context) test-only; slice makes it `pub` + FFI-reachable = first production
  exposure. Malicious inviter → victim installs real group crypto under spoofed governance /
  broadened ceiling / spoofed admin; victim node enforces attacker's metadata. Breaks
  "legibility before opt-in". Recommend binding params into MLS GroupContext extensions or a
  signed context descriptor. (Mirrors create_context trust model but join is a weaker position:
  you trust a remote party's description of someone else's context.)

## Defended well (resists attack)
- Core crash-safety ladder BLACK-2J-01..06: first-writer-wins live (lookup) + durable
  (load_context) both under bootstrap_spawn_lock BEFORE irreversible ConfirmConsume; reversible
  prechecks A-D burn no KP; LIFECYCLE_TIMEOUT bounds the global lock (ConfirmConsume MLS DoS);
  crypto-durability check before persist; fail-closed persist; pseudonym None-reject (no [0u8;32]).
- KP single-use: two independent anchors (reservation journal + crypto init-key set), fused join
  (private signer-state never crosses channel/FFI, only public bytes + opaque reservation id).
- Reservation DoS bounded: MAX_OUTSTANDING_RESERVATIONS=128 + activity-gated TTL sweep.
- Custody gates consistent 3 bridges: reserve=explicit ensure_local_custody; join=implicit via
  derive_member_pseudonym → SCP-IDENT-1054 BEFORE KP burn. KP stores per-identity keyed.
- Enforcement not weakened: MIN_ACTIVE_PIPELINE_ASSERTIONS 48→52 (up).
