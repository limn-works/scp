# ADR-057 Prereq-1: MLS KeyPackage Lifetime routed through injected Clock (2026-07-05)

Branch fix/1965-lifetime-clock, range 3d8bc2cc0..3eee49244 (feat dbbfb0488 + docs 3eee49244).
Purpose: openmls mints/validates KeyPackage Lifetime from its OWN un-injectable clock
(wasm `js` feature = attacker-overridable Date.now). New `scp-mls/src/lifetime.rs`:
`key_package_lifetime(clock)` mints via `Lifetime::init(now-margin, now+life)` (pure ctor,
bypasses openmls internal now); `validate_key_package_lifetime(lt, clock)` re-checks temporal
(strict `<`, mirrors is_valid) + RFC9420 max-range (openmls has has_acceptable_range but never
calls it in validate). Intersection semantics: SCP check ADDS to openmls internal, never replaces.

## Bracketed accept sites (verified)
- group.rs add_member (:476), key_package_in_did (:559)
- encrypt.rs decrypt_with_sender_did + decrypt_with_membership_changes (pre-merge, per add_proposal, fail-closed no half-merge)
- production_backend.rs validate_key_package trait impl (:462 bracketed) + add_member_raw + create/generate
- provider.rs create/generate/add_member(:1155)/decrypt all pass self.clock

## FINDING (MEDIUM, still open at review time)
`MlsCryptoProvider::validate_key_package` (provider.rs ~1013-1074) NOT bracketed — the EAGER
join gate on native path (lifecycle_helpers.rs:727 join_context "validate before mutations").
Sibling ProductionMlsBackend::validate_key_package WAS bracketed same diff → two methods disagree.
NOT a bypass: Phase-3 deps.crypto.add_member (bracketed, fail-closed) is authoritative; expired KP
that slips eager check dies at Phase 3 after rate-limit token consume+refund. Impact = "weaker
advisory window" the change set out to kill + minor wasted work. Fix: add
`validate_key_package_lifetime(verified.life_time(), self.clock.as_ref())?;` before Ok(()).

## Verified clean
- (a) Browser: WasmScpClient::from_js builds WasmClock internally (NOT JS-injectable; from_parts
  is plain impl not #[wasm_bindgen], native-test only). WasmClock=captured_date_now bound at
  module-init. Flows to ScpClient.clock → all mint+accept. No Date.now false-accept except V3.
- (b) V3 residual (Welcome tree-leaf is_valid, pub(crate), unbracketable) risk statement holds:
  Welcome HPKE-sealed + member-signed tree → false-accept admits no new material; false-reject=availability.
- (c) NO untrusted-boundary clock injection: every FFI/node ctor hardcodes Arc::new(SystemClock);
  clock params Rust-internal only. Doc nit: FFI mints fresh SystemClock Arc, not literally the
  "SAME Arc" the ProductionMlsBackend doc claims — harmless (ZST).
- (d) KeyPackageLifetimeInvalid{not_before,not_after,now} local-only (Result to caller, decrypt
  fails = local drop, no NACK). Keep `now` out of synced/exported records if ever added.
- (e) DoS bounded: O(1) per add_proposal, runs AFTER process_message sig-verify, no amplification.
- (f) Enforcement files untouched (ratchet hit = src/ratchet.rs not baseline json). No new external
  dep (scp-mls already had scp-clock; scp-media adds it dev-dep only).
