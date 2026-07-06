# scp-dht

DHT transport layer for the Shared Context Protocol (SCP).

This is a native leaf crate (no `scp-*` dependencies) that owns the BEP44
signed-mutable-item transport used for DID publishing and resolution:

- the [`DhtClient`] trait and its [`DhtRecord`] value type,
- the [`InMemoryDhtClient`] test/dev backend,
- the production `PkarrDhtClient` (Mainline DHT + optional HTTP gateway
  fallback), behind the `production-dht` feature,
- the pure BEP44 signable/verification helpers `bep44_signable` and
  `verify_bep44_signature`, and
- the crate-local [`DhtError`] error type.

The DID-method layer (`DidDht`, resolution, lifecycle) lives in `scp-identity`,
which depends on this crate one-way and maps [`DhtError`] into its own
`IdentityError` via a `From` impl. See ADR-057 (T1c-a) and ADR-003
(`.docs/adrs/phase-1.md`).
