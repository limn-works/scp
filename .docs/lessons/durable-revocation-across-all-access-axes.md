# A Revocation Must Be Durable, Clearable Only by Authority, and Enforced on Every Access Axis

Source: the broadcast read-ban, §5.14.4 and §5.14.8 of `05-contexts.md`. Green functional
tests passed while the ban was fully launderable; adversarial review found five HIGH evasions
before it held.

## The three properties

1. **Store the revocation where the revoked party cannot clear it.** The first version
   recorded the ban on the membership-scoped `read_exclusion_list`, which the banned member's
   own `leave` clears, so a banned member could self-leave and replay a retained UCAN. The ban now
   lives in `banned_subscribers` on `BroadcastContext`, cleared only by an authority
   `RestoreAccess` and persisted fail-closed in the snapshot. Never co-locate a revocation
   with state the revoked party's own lifecycle mutates.
2. **Enforce it on every path to the resource.** For a read-ban that means admission (the
   subscribe chokepoint), the key-request serve path (a banned non-subscriber can still ask
   for keys), already-cached material (the ban rotates every author's key to a fresh epoch,
   so a key cached before the ban cannot decrypt content after it), and durability across
   self-leave and admin-remove.
3. **Record it for parties who never used the resource.** A read-revoked member who was never
   a subscriber must still be recorded, or the key rotation is skipped and a later subscribe
   leaks.

## How to apply

For any ban, revoke, or deny, write the matrix of access axes (admission × serve ×
cached material × durability × every clearing lifecycle) and fill every cell before calling
it done. Then run an adversarial pass whose only job is to launder the restriction through
leave, rejoin, remove, restore, cache, and every alternate serve path, and treat each bypass
as HIGH until it is closed.
