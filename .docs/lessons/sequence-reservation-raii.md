# Send-sequence reservation: the snapshot is the mechanism, RAII is belt-and-braces

## The rule

Per spec §5.15.7, a send-sequence number is *consumed* (becomes durable) **iff** its
payload was handed to the transport. Any terminal outcome before transmit — a `?`-early
return, a panic, a cancellation — MUST release the number back into the pool, or the next
send skips a sequence and receivers reject the gap. The actor-side implementation is
`SequenceReservation` in `context/actor/sequence.rs`.

## Two mechanisms, layered

Read the module `//!` header — it is explicit that there are two independent protections
and which one is load-bearing:

- **The snapshot is the actual mechanism (across crashes).** The per-context coalesced
  snapshot is the floor: a respawned actor loads a snapshot that predates any in-flight
  reservation, so `SendSequenceTracker` starts from the persisted high-water mark. This is
  what protects monotonicity when the whole actor dies.
- **RAII is belt-and-braces (within a lifetime).** `SequenceReservation` is a Drop guard:
  drop rolls the counter back; an explicit `commit()` makes the reservation durable. It
  closes the within-lifetime paths (panic, `?`, cancellation) that the snapshot floor does
  not need to reason about, replacing the scattered `rollback_sequence_number` calls that
  used to live in the legacy `manager/messaging.rs`.

`SendSequenceTracker::reserve_next` post-increments and returns the reserved number;
`rollback` decrements **iff** the rolled-back number is the head — only the *youngest*
outstanding reservation may be rolled back, so a rollback can never re-use a number an
in-flight younger reservation already holds. This mirrors, deliberately without semantic
change, `MembershipState::rollback_sequence_number` in
`crates/scp-protocol/src/context/membership.rs` (saturating subtract by 1).

## The one pitfall: AAD uses the pre-increment value

`SequenceReservation::reserve` returns the **post-increment** slot (first reservation
returns `1`, not `0`). The legacy MLS sender-key `seal` AAD (spec §9.16.1, ADR-007) is
**0-based** — it binds the *current* counter value, then increments. So a handler
producing byte-identical wire output MUST read `SendSequenceTracker::last_issued()`
**before** reserving to get the pre-increment value for the AAD, and only then call
`SequenceReservation::reserve` to mark the slot consumed. The header spells out the exact
ordering. Feeding `reservation.number()` as the AAD sequence instead of `last_issued()` is
a byte-identity regression: receivers on the legacy decrypt path reject every message with
an AAD mismatch. This is the sole known pitfall when migrating a handler off the legacy
`seal`.

## Cross-refs

- Spec §5.15.7 (send-sequence reservation), §9.16.1 / ADR-007 (sender-key AAD binding).
- `actor-per-context-pattern.md` — the coalesced snapshot that is the crash-recovery floor.
