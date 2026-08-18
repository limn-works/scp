# Closing a Read-Path Finding by Adding a Durable Write Hands the Caller a Write

**Date:** 2026-08-17
**Source:** `verify_attestation_in_context` in `crates/scp-ffi/common/src/trust_store.rs`, the
shared body behind every bridge's `trust_verify_attestation` op. A review recorded that the op
read a context's revocation list and never wrote one, so an application whose only verification
entry point was that op never recorded a revocation it had just seen. Commit `cda7215734` closed
that finding by calling `TrustProtocolRepository::add_revocations` from the op whenever the
attestation it received carried an issuer-signed revocation of itself. An orchestrating agent
ruled that write deleted, and this lesson states why the ruling is right on the merits.

## The rule

A finding that says "this path reads X and never writes X" does not, on its own, authorize a
write on that path. Before adding one, answer two questions about the path:

1. **Who supplies the arguments the write derives from?** When a caller outside your trust
   boundary supplies them, the write is that caller's write, not yours.
2. **What does a later read of X cost, per entry the write adds?** When the read loads all of X,
   the write's cost is not one row — it is one row multiplied by every later read.

When the answer to (1) is "the caller" and the answer to (2) is more than O(1), adding the write
converts a caller's question into a caller's durable write and bills every later reader for it.
Put the write on the path a caller reaches by asking you to *record* something, and leave the
path a caller reaches by asking you a *question* read-only.

## The numbers in this instance

`trust_verify_attestation` takes a context id and attestation JSON, both from its caller. An
attacker derives a DID from a fresh Ed25519 keypair — `IdentityDidPublicKeyResolver` reads a
public key out of a DID string, so no publication gates that derivation — and signs an
attestation that revokes itself. Each such attestation costs one signature and, under the
write-back, added one durable entry to that context's revocation list.
`TrustProtocolRepository::get_revocation_state` loads that whole list, one storage read per
entry, on every later verification in that context. So N signatures bought N entries, and every
later trust decision in that context paid N storage reads. The same pull request's body already
recorded that unbounded growth as an open finding against the read; the write-back fed it.

`verify_and_cache_attestations` keeps the write, because a caller reaches it through
`trust_aggregate` and `participation_record` — operations whose contract is to ingest and count
caller-supplied attestations. The asymmetry is the point: an ingest already accepts caller data
into durable state, and a verification does not.

## How to check for this class

For each finding of the form "path P reads state S and never writes S", before adding a write to P:

- Trace every argument of P to its supplier. A foreign-function-interface entry point takes all
  of them from an application, which takes them from wherever it takes them.
- Read the implementation of every read of S and count its cost in the size of S.
- Find the path whose stated contract is to record into S. When one exists, the finding is about
  an application that called the wrong operation, not about P.

An answer of "the caller supplies them" plus "the read is O(|S|)" plus "another path already
records into S" means the finding closes by documenting which path records, not by adding a write.

## Related

- `.docs/lessons/optional-security-parameter-needs-no-default-wrapper.md` — the sibling rule for
  the read side of this same op: a wrapper that supplies a security parameter hides every omission.
- `.docs/specs/17-persistence-and-storage.md` §17.17 — capability selection, and the
  durability-versus-nullifier classification a persisted structure has to satisfy.
