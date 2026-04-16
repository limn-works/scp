---
name: Fuzzing Plan Attack Surface Analysis
description: Red team analysis of SCP fuzzing targets prioritized by exploitability -- trust boundaries, attack chains, missing defenses
type: project
---

## Key Findings (2026-04-12)

### Missing Defenses (confirmed by code reading)
1. **ClientMessage/RelayMessage::from_bytes** has NO pre-deserialization size check. OuterEnvelope and InnerEnvelope both have MAX_ENVELOPE_SIZE pre-check. Protocol messages do not.
2. **SenderKeyDistributionMessage::from_bytes** has NO pre-deserialization size check and NO deny_unknown_fields. These ride inside MLS ciphertext (inner envelope payload with MessageType::KeyDistribution).
3. **`#[serde(flatten)]` on both InnerEnvelope and OuterEnvelope** uses `rmpv::Value` for extensions HashMap. serde buffers all map entries before dispatching when flatten is present -- allocation amplification vector.
4. **strip_padding** trusts the 4-byte length suffix unconditionally after basic bounds check. Does NOT verify the padding region is all zeros. Returns arbitrary prefix of input.
5. **ChunkEnvelope reassemble** allocates `Vec<Option<&[u8]>>` of size `total_chunks` (up to 262,144 entries = ~6 MB) from a single untrusted u32.

### Trust Boundary Map
- **Boundary 1 (network):** ClientMessage, RelayMessage, OuterEnvelope, STUN, .well-known/scp, BEP44
- **Boundary 2 (post-MLS, most dangerous):** InnerEnvelope, SenderKeyDistributionMessage, ChunkEnvelope, BroadcastEnvelope, governance proposals, UCAN tokens
- **Boundary 3 (FFI):** validate_* functions, UCAN parse, CapabilityUri parse, DID parse

### Highest-Value Fuzz Targets (ordered)
1. ClientMessage from_bytes (known missing defense, network-facing)
2. OuterEnvelope from_bytes (flatten amplification)
3. InnerEnvelope from_bytes (flatten amplification, post-decryption)
4. SenderKeyDistributionMessage from_bytes (no size check, no deny_unknown_fields)
5. UCAN parse_ucan + validate_ucan (authorization layer)

### No unsafe in first-party code
All crates (scp-protocol, scp-runtime, scp-transport, scp-identity, scp-event-log) are pure safe Rust. Unsafe is only in dependencies (openmls, ed25519-dalek, aes-gcm, etc.).
