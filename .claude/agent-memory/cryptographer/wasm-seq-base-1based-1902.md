---
name: wasm-seq-base-1902
description: WASM per-member message sequence base 0->1 reconciliation (#1902 bd98efada) — AAD soundness audit + residual sender-header wire divergence
metadata:
  type: project
---

# WASM per-member sequence base 0->1 (#1902, commit bd98efada) — SOUND

Audit verdict: cryptographically SOUND. Reconciles WASM `send_message`/`publish_broadcast`
to native 1-based (pre-increment). `or_insert(0); *entry += 1; let seq = *entry;` → first
emitted seq = 1, matching native `MembershipState::next_sequence_number`
(membership.rs:153,199-203: `sequence_number:0` then `+= 1; return`).

**Why sound:**
- AAD = `build_sender_aad(ctx,did,epoch,sequence)` length-prefixed, trailing `seq.to_be_bytes()`
  (scp-protocol/.../sender_keys/encrypt.rs:120). WASM RE-EXPORTS the same fn
  (wasm/src/crypto/sender_key.rs:7) — no divergent WASM AAD impl.
- Receiver does NOT recompute seq base: native parses `(epoch,seq)` from sender header
  (provider.rs:1703 parse_sender_header); WASM takes them as explicit caller params
  (manager.rs:2230 decrypt_message). Seq travels with the msg → encrypt/decrypt always
  agree regardless of base. Faithful msg always decrypts.
- Nonce random per call (OsRng, encrypt.rs:60) — independent of seq. No nonce reuse.
  Seq strictly increments (+=1, rollback saturating_sub only on recorded-nothing). No
  (epoch,seq) reuse; base shift just drops value 0 from emitted range (now 1,2,3..).

**This CLOSES a latent cross-family off-by-one:** old WASM first msg=0, native first msg=1
→ AAD trailing 8 bytes differed → native↔WASM tag-verify failure on msg #1. Now both 1-based.
Native reserves seq=0 as sentinel for non-app control (checkpoints/heartbeats,
messaging_helpers.rs:1697,1789 "uses sequence 0, receive returns Ok(None)"); app content
must start at 1. Old WASM app msg collided with reserved-0. Fix is correct base.

**No Merkle/signed-export impact:** MessageSent is category-2 per-author app activity, local
ContextEvent only, NOT a durable RFC6962 EventType leaf (phase-2.md:779,932-951; §25 KAT
carry no MessageSent). Cannot alter tree::root, checkpoint merkle_root, or signed export.
WASM publish_broadcast does NOT encrypt at all (state.rs / manager.rs:5671) — seq is
event-value-only there, zero AEAD impact.

**RESIDUAL (LOW, PRE-EXISTING, NOT this commit):** WASM `encrypt_message`
(wasm/crypto/state.rs:68-88) produces MLS(sender_layer(pt)) and NEVER calls
build_sender_header; native produces MLS(build_sender_header(epoch,seq,sender_layer))
(provider.rs:1703 parses it back). WASM passes (epoch,seq) out-of-band to decrypt_message.
→ header-presence wire asymmetry: native receiver would eat first 16 WASM ct bytes as a
nonexistent header; WASM has no in-band seq for native blobs. Base reconciliation is
NECESSARY but NOT SUFFICIENT for end-to-end WASM↔native ciphertext interop. Orthogonal to
#1902. Should be tracked separately.
