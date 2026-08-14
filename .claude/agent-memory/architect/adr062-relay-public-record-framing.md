---
name: adr062-relay-public-record-framing
description: ADR-062 relay DID-record framing is NET-NEW — no public-record frame exists; OuterEnvelope is the only relay frame and it's the encrypted-message envelope
metadata:
  type: project
---

ADR-062 Slice 11 (relay DID-record framing) must DEFINE a new frame — there is nothing to JOIN. Companion to [[relay-resolution-late-binding]] (the resolution/querier side, which flagged this exact framing as "THE blocking upstream ambiguity" on 2026-07-17); this memory answers it: net-new.

**Why:** Investigated 2026-08-01 to gate a permanent wire-format decision. Findings:
- The relay wire protocol (`crates/scp-transport/src/native/protocol.rs` `ClientMessage::Publish`/`RelayMessage::Blob`) treats `blob: Vec<u8>` as fully OPAQUE — no magic, no version, no kind byte. Relay content-addresses by SHA-256 only. Bounded 1..=512KiB.
- The ONLY structured relay-blob frame is `OuterEnvelope` (`crates/scp-protocol/src/envelope/outer/mod.rs:41`), MessagePack, fields version(u16)+routing_id+recipient_hint+blob_ttl+encrypted_blob+extensions. It is the ENCRYPTED-message envelope (contrast case). NO magic bytes, NO kind discriminator; `version` is informational/unsigned. The SDK transport layer (`native/adapter.rs:654`, `manager.rs:731`) assumes EVERY blob deserializes as an OuterEnvelope.
- KeyPackages (public records) currently MISUSE OuterEnvelope: `provider.rs:231 publish_key_package` wraps raw public `kp_bytes` into `encrypted_blob` via `build_envelope` (`provider.rs:105`). Semantic mismatch — public bytes in an "encrypted_blob" field.
- DID-document relay path is UNWIRED in production: `RelayPublisher` trait (`scp-identity/src/republish.rs:104`) has only test doubles (InMemory/AlwaysFail) + `DualLayerHealingPublisher`. No production impl. The test path passes raw `document_bytes` and DROPS signature+seq (`republish.rs:703`), though spec §3.10.2/§3.10.4/§3.10.5 require the relay blob to be the "BEP44-signed DID document" (value+sig+seq) verifiable on QUERY.
- SCPM magic (§9.16.1, `[0x53,0x43,0x50,0x4D]`) is a 4-byte-magic precedent but lives INSIDE MLS plaintext (mgmt-vs-app discriminator), NOT a relay frame. Magic registered in spec §9.18.8 (NOT §9.18.2, which is Domain Separators — UTF-8 strings only).
- §9.5.1 = canonical hash/length-prefix discipline (4-byte BE len on variable fields) — the encoding rulebook to follow, not a frame.
- §18.1: DID-doc `value` internal encoding = JSON per did:dht/W3C (NOT SCP-owned). Frame must sit OUTSIDE the BEP44 signature.

**How to apply:** DID-record frame is net-new. Realistic future joiners of a unified public-record frame: KeyPackages (migrate off OuterEnvelope misuse), context metadata (§9.10.4.B), attestation revocations (§7.4/§18.1). Broadcast + all sender-key/invitation/epoch traffic ride OuterEnvelope (encrypted) — would NOT join. TTL is a single shared `blob_ttl` u32, MIN=1..=MAX=604800 (7d) for ALL blobs (`native/protocol.rs:40-43`); DID docs already sit at the 7d ceiling (republish every 6d) — identity records cannot get a longer TTL than message blobs without raising the shared max for everyone.
