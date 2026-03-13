# Production Readiness Commits Security Review (2026-03-06)

Branch: feat/achieve-production-readiness
Commits: 7f341b8, 53ed083, 26e2222, d174211, 2444c9a, af4192c, 38fe1cf

## Findings

### 7f341b8 -- sender key JSON->MessagePack + future timestamp fix
- MEDIUM: Future timestamp check uses same 30s window as staleness (60s effective window) -- acceptable but conflates concerns
- MEDIUM: No test for the new future-timestamp rejection path (line 683). Only stale case tested.
- GOOD: All 4 serialization points consistently changed to rmp_serde::to_vec_named
- GOOD: saturating_sub future-timestamp bypass correctly fixed

### 53ed083 -- HPKE domain separator alignment
- CLEAN: One-line constant change, correct domain separation

### 26e2222 -- deny_unknown_fields on InnerEnvelope
- CLEAN: Correct hardening for signed type
- NOTE: SenderKeyEpochAdvance, SenderKeyRequest, BlockNotification (also signed) still lack deny_unknown_fields

### d174211 -- ProtocolRepository named MessagePack
- CLEAN: Both serialize() and store_migratable() changed; backward-compatible read

### 2444c9a -- dedup cache TTL 1h->24h
- CLEAN: LRU capacity (10,000) still bounds memory; TTL change matches spec

### af4192c -- serde rename for wire format
- CLEAN: All 10 ref_id fields + event_type renamed; thorough test coverage

### 38fe1cf -- conflict detection pairs
- CLEAN: RemoveMember same-target + RotateContentKeys pairs added correctly
- NOTE: RestoreReadAccess vs RestoreReadAccess still missing (pre-existing)

## Pre-existing Gaps Highlighted by These Commits
- Sender key wire types lack deny_unknown_fields (confused deputy on signed types)
- handle_sender_key_request does not check request timestamp or use NonceDedup
- RestoreReadAccess/RestoreWriteAccess self-conflict pairs still absent
