---
name: adr062-slice11a-relay-querier
description: ADR-062 Slice 011a RealMultiRelayQuerier red-team chains (downgrade, flood, positioning). Latent — NoOp prod-wired, live w/ 011b.
metadata:
  type: project
---

# ADR-062 Slice 011a — RealMultiRelayQuerier red-team

Files: crates/scp-identity/src/{relay_querier.rs, resolution.rs, resolver.rs}.
`verify_bep44_signature` = scp-dht/src/lib.rs:142 (sync, from_bytes + verify_strict, ~50-100us/candidate, NO async yield).

## Wiring status (calibrates severity)
- `RealMultiRelayQuerier` is EXPORTED (lib.rs:51) but NOT instantiated anywhere in prod or tests except its own module tests. Every prod site (self_host.rs:1410, all 3 FFI bridges, node) wires `NoOpRelayQuerier` (returns Ok(None)). So ALL chains below are LATENT in 011a; they go live when 011b's `TransportRelayQuerier` becomes the `inner`.

## RED-1201 (HIGH latent, SPEC VIOLATION) — cross-relay downgrade / no highest-seq
- composer (relay_querier.rs:106-129) returns FIRST valid candidate in the FIRST relay that has ANY valid record, then `return`s. It never collects across relays/candidates to pick max-seq. verify_relay_record (resolution.rs:141) has NO seq check. Spec §3.10.4 step5 / §3.10.7 require highest-seq wins.
- Attacker controlling a queried relay (esp. position 0) serves a GENUINE-but-OLD self-signed record (records are public+signed, capturable). Composer returns it and stops. Backstops that must ALSO fail for exploit: (a) DHT layer must not supply fresher (censored/timeout/victim relay-only), (b) no fresh cache entry (cold or >7d) so cached_seq rollback check (resolver.rs:494) is None.
- Impact: key-rotation downgrade — serves pre-rotation doc w/ rotated-out (possibly compromised) key as current. Fix: composer must max-by-seq over ALL verified candidates across ALL relays.

## RED-1202 (HIGH latent, upgraded) — unbounded candidate flood + timeout-immune sync loop
- `for record in candidates` (relay_querier.rs:106) verifies EVERY candidate; Vec is unbounded, no self-imposed cap. Trait doc defers bound to "relay implementation MUST bound" — but a MALICIOUS relay is the threat; composer is the trust boundary and must self-cap.
- CRITICAL nuance: the candidate loop is a tight SYNC stretch (verify_bep44_signature is sync, no `.await` between candidates). The resolver's LAYER_TIMEOUT (resolver.rs:459, 10s tokio::time::timeout) only fires at await points — it CANNOT interrupt the sync loop. So 1M bad-sig candidates = ~50-100s of Ed25519 on ONE tokio worker thread, timeout ineffective, worker starved. Concurrent floods across DIDs = full runtime stall (node DoS).
- Interaction: fixing RED-1201 REQUIRES verifying all candidates (to find max-seq), making the cap MANDATORY, not optional. Fix: cap candidates (e.g. 8-16) BEFORE the verify loop; treat overflow as relay-misbehavior.

## RED-1203 (MEDIUM latent) — persistence via cached_relay_urls poisoning
- resolver.rs:450 relay_urls = cache.cached_relay_urls(did).unwrap_or(bootstrap). cached_relay_urls uses EXPIRED entries too (comment 447-449). Relay list is inside the SIGNED doc (can't forge), BUT a stale genuine doc (via RED-1201) lists OLD relays the victim abandoned + attacker may have taken over the URL → cached → future resolves query attacker's relays first → attacker reliably position-0 → PERSISTENT downgrade. Cold-cache path uses static bootstrap_relays: a malicious/MITM'd bootstrap relay downgrades every cold resolve (initial-access variant).

## Non-issues verified
- routing_id = SHA-256("scp:did:"||did), public/precomputable. Enables PRE-positioning writes (flood/squat) but leaks nothing (hash of public data). Relay can't validate BEP44 at store-time (only has the hash, can't recover DID pubkey) — THIS is why the dumb-relay + client-side Vec-verify design is necessary, and why the flood cap must live in the composer.
- relay Ok(None) + DHT None = Ok(None) = fail-closed honest absence, NOT a substitution vector (worst case DoS/unreachable). Expired-cache reuse is confined to relay-URL hints, never served as the answer (answer needs fresh cache hit resolver.rs:435 or fresh layer verify). Bounded.
- verify_strict + self-cert make record SUBSTITUTION (forged content) cryptographically impossible. That control holds.
