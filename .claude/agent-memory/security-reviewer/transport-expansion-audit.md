# Transport Expansion Security Audit (2026-03-04)

## Scope
Commit on `feat/governance-manager-integration` -- ~19k lines adding QUIC, HTTP/3, WebTransport, UDP/DTLS, CoAP to `crates/scp-transport/`.

## Findings

### SEC-001 [HIGH] UDP Listener TOCTOU on Global Session Limit
- File: udp/listener.rs lines 450-535
- read lock check (line 451), drop lock, DTLS handshake (line 517), write lock insert (line 535)
- Per-IP check via register_connection is atomic (line 471) -- only the local max_sessions check is vulnerable
- Fix: single write lock, or AtomicUsize counter incremented before handshake

### SEC-002 [MEDIUM] UDP Plaintext Error Responses Before DTLS
- File: udp/listener.rs lines 464, 489, 1024-1039
- Leaks protocol fingerprint, rate limit state, modest amplification
- Fix: silently drop rejected datagrams

### SEC-003 [MEDIUM] HTTP/3 Connection Limit TOCTOU
- File: http3/adapter.rs lines 208-222
- load() then fetch_add() with gap between; accept loop yields between them
- Fix: fetch_add first, rollback if over limit

### SEC-004 [MEDIUM] HTTP/3 Server Bypasses Shared ConnectionTracker
- File: http3/adapter.rs lines 95-228
- No per-IP limit enforcement; invisible to cross-transport budget
- Fix: accept ConnectionTracker, call register/unregister

### SEC-005 [MEDIUM] QUIC Listener Doesn't Explicitly Disable 0-RTT
- File: quic/listener.rs lines 299-327
- Safe by default (quinn doesn't enable 0-RTT without max_early_data_size), but fragile
- http3/config.rs line 381 doc comment says "0-RTT enabled" but it's disabled -- misleading

### SEC-006 [MEDIUM] SubscriptionRegistry Unbounded HashMap
- File: relay/subscription.rs line 58
- No total subscription limit, no per-routing-id limit, no cleanup task
- Per-connection limits exist but don't cap total registry size

### SEC-007 [MEDIUM] QUIC Adapter query() Unbounded Response Vec
- File: quic/adapter.rs lines 489-513
- Malicious relay can send unlimited Blob messages before query_complete
- Fix: add MAX_QUERY_RESULTS cap

### SEC-008 [MEDIUM] HTTP/3 Doc Comment Contradicts Implementation
- File: http3/config.rs line 381
- Says "0-RTT enabled" but implementation disables it (lines 364-370)
- Risk: future developer may enable 0-RTT thinking it already is

## Good Patterns
- QUIC accept_loop: single write lock for per-IP + total check + increment (exemplary)
- Shared PublishRateLimiter + ConnectionTracker across WS/QUIC/UDP
- Global NEXT_OWNER_ID AtomicU64 prevents cross-transport subscription collisions
- Cover traffic constant-rate invariant; dummies never suppressed by real traffic
- Delivery jitter (BLACK-001 mitigation) with parallel spawned tasks
- HTTP/3 0-RTT disabled with documented rationale
- ConnectionTracker saturating_sub + entry removal at zero
- DTLS cipher suite: ECDHE-ECDSA-AES-GCM only, CIPHER_SERVER_PREFERENCE
- Http3Config Debug redacts certs/key
