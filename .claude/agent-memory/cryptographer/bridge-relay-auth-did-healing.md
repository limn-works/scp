---
name: bridge-relay-auth-did-healing
description: PR #255 (SCP-247/SCP-245) bridge relay registration auth construction and DualLayerResolver DID healing / anti-rollback
metadata:
  type: project
---

# Bridge relay auth + DID healing (PR #255, SCP-247 / SCP-245)

- Bridge auth signed preimage: `"SCP-BRIDGE-REGISTER-V1:" ‖ routing_id[32] ‖ be_u64(timestamp)`
  = 63 bytes fixed — SOUND (fixed-width, domain-separated, no concat ambiguity).
- `verify_strict()` used. Verification order: timestamp → signature → routing_id
  (fast-reject cheapest-first).
- Routing ID: `SHA-256("scp:did:" ‖ did_string)` — domain-separated, golden vector verified.
  Same derivation as the DID-record relay path, see [[did-record-relay-write-path]].
- DID derivation: `did:dht:z` + `zbase32(pubkey)` — deterministic, invertible.
- 60s replay window, no nonce tracking — acceptable because registration is idempotent.
- `DualLayerResolver`: `tokio::join!`, BEP44 `verify_strict` on both layers,
  anti-rollback via the cached `seq` (`cached_sequence` gate rejects
  `received_seq < cached_seq` on both arms).
- Healing: async best-effort republish to the stale layer, panic-monitored. The heal
  arm now frames into `DidRecordV1` before relay publish (see [[did-record-relay-write-path]]).
- PRE-EXISTING: the migration proof hash (`dht.rs:607`) has variable-length concat
  ambiguity (`old_did ‖ new_did`).
