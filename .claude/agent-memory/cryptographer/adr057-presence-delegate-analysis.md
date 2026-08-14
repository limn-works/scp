# ADR-057 Presence — Attenuated Keep-Alive Delegate Analysis (2026-07-04)

Open crypto question from ADR-057 §"Liveness / presence" (line 49-51): can SCP express a
delegate that may heartbeat / Update / replenish KeyPackages but NOT read/send/admit?

## Verdicts (per decay vector)
- **(a) Heartbeat — NOT attenuable AS-IMPLEMENTED; attenuable only via a re-specced beacon.**
  §9.9.2 heartbeat IS an MLS application message: `MessageType::Heartbeat` (disc 5),
  scp-protocol/src/envelope/inner/mod.rs:79-103. `send_heartbeat` routes EMPTY payload through
  `encrypt_and_send` = inner Ed25519 sign (sender #active/#agent key) + `crypto.seal` (sender-key
  + MLS + outer), messaging_helpers.rs:1778-1863, seal ~203. Emitting needs group epoch secrets
  (→ decrypt-all) AND sender signing key (→ impersonate). Clears SAME write gates as send_message
  (1814-1842) → "can heartbeat ⇒ can send" is literal, not theoretical. Absence-detection only
  needs authenticated+fresh+sender-attributable liveness (receiver classifies before seq tracker,
  1490-1499); confidentiality is incidental. FIX = new signed LivenessBeacon at relay/transport
  layer, UCAN-delegated signing, §9.9.2 amendment. Semantics shift "member here"→"keep-alive here".
- **(b) MLS Update / PCS — IMPOSSIBLE to attenuate.** `propose_update` = `group.self_update(&provider,
  signer, ...)`, ratchet.rs:124-133; signer = leaf Ed25519 SignatureKeyPair inside ScpMlsGroup,
  group.rs:113-123,277. Needs leaf signing key + live epoch secrets = full read + impersonation +
  membership-commit. Pre-signing DEFEATS PCS (pre-generated entropy is inside the compromise
  window it exists to close). RFC 9420 external senders (§12.1.8.2) can't Update (no leaf); external
  commit is join-only; another member committing M's pre-signed Update gives no PCS and M must still
  come online. NO external/by-ref machinery in codebase (grep empty). MLS validates commits by leaf
  key, NOT UCAN → a UCAN can't make it sound. Requires keys online, period.
- **(c) KeyPackage replenish — CLEANLY attenuable, ship it.** `generate_key_package` mints a FRESH
  ephemeral MLS signer per KP + credential(DID+optional UCAN), group.rs:550-615. Publishable artifact
  = PUBLIC bytes; `publish_key_package(owner_did, public_bytes)` transport/provider.rs:231, called at
  key_package_actor.rs:1480. Private signer_state stays with member (zeroized PersistedKeyPackage,
  ~330-342). Member pre-mints N online, retains N private halves, hands delegate ONLY N public blobs +
  publish UCAN. Coverage = N single-use adds (event-based; NO last-resort/reusable KP here). Relay
  needs no trust in uploader (public self-authenticating data). KeyPackageBuffer min10/thresh5,
  key_package.rs:138-171.

## Cold-presence recovery ladder (already implemented, §23 sync)
hours_offline.rs (relay buffer SUBSCRIBE-since + epoch_reconciliation sequential Commit replay +
mls_update on return) → days_offline.rs:779-784 `determine_mls_recovery`: gap<=max_sequential_commits
(default 100) sequential catch-up, else → weeks_offline.rs:902 **re-add with fresh KeyPackage**.
Epoch grace window 30s hard ceiling (epoch_grace.rs:11-12). (c) is load-bearing: keeps member
re-addable while offline. Forward secrecy: lost-state tab can't decrypt missed history + needs re-add.

Heartbeat SEND lives at FFI/SDK layer (actor has no signer), heartbeat_scheduler.rs:1-80,
Supervisor::send_heartbeat, key per-call. Transport HeartbeatMonitor gap detect scp-transport/heartbeat.rs.
