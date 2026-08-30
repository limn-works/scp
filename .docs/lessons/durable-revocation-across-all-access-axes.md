# Revocation state must be durable, authority-only-clearable, and enforced on EVERY access axis

**Context:** the broadcast read-ban, §5.14.4 and §5.14.8 of the context spec, `05-contexts.md`.

## The invariant

A revocation/ban is a **downward-authorization transition**. For it to actually hold, three properties must ALL be true, and each was initially missing on at least one path:

1. **It must not live on state the revoked party can clear.** The first implementation recorded the ban on the membership-scoped `read_exclusion_list` — which a banned member's own `leave` clears as normal membership hygiene (§5.6.1/§5.9). A banned DID could therefore **launder the ban by self-leaving** and replay a retained UCAN. Fix: a separate durable `banned_subscribers` record on `BroadcastContext`, cleared ONLY by an authority `RestoreAccess`, persisted **fail-closed** in the snapshot (`#[serde(default)]` for back-compat). Rule of thumb: *revocation records must not be co-located with, or clearable by, the same lifecycle the revoked party controls.*

2. **It must be enforced on every path to the protected resource — not just the obvious gate.** A single "can't subscribe" gate is insufficient. A read-ban must be checked on ALL of:
   - **admission** (new subscribe chokepoint),
   - **key-request serve** (before the author/roster grant — a banned non-subscriber can still *ask* for keys),
   - **already-cached material** (a ban must **rotate every author's key** to a fresh epoch so a pre-ban-cached key can't decrypt post-ban content — forward secrecy, §9.5),
   - **durability + reversibility** (recorded for EVERY read-revoked member, subscriber or not; survives self-leave AND admin-remove; cleared only by `RestoreAccess`).
   Enumerate the access axes FIRST (like a coverage matrix); a gate on one axis is a false sense of security while the others leak.

3. **Recorded even for parties who never "used" the resource.** The ban must be recorded for a read-revoked member who was never a subscriber — otherwise the "rotate keys on ban" step is skipped (no subscriber → nothing rotated) and a later subscribe leaks.

## The meta-lesson: adversarial review is load-bearing, not decorative

Green functional tests passed while the ban was fully launderable. The adversarial roster (black-hat + security + cryptographer + bug-catcher) found and closed **five distinct HIGH ban-evasion defects**: three admission-laundering variants (self-leave subscriber, member-not-subscriber, serve-path author), an *inverse* permanent-ban bug (`RestoreAccess` couldn't clear after leave), and the forward-secrecy gap (non-subscriber ban rotated no keys). None were visible to happy-path tests. For any authorization-downgrade feature, budget an explicit adversarial pass whose job is to *launder the restriction* through every lifecycle edge (leave, rejoin, remove, restore, cache, alternate serve path) — and converge to "no residual, no next axis," not "tests pass."

## How to apply

- Adding a ban/revoke/deny? Write the access-axis matrix (admission × serve × cached-material × durability × every clearing lifecycle) and fill every cell before claiming done.
- Store the revocation on authority-scoped, fail-closed-persisted state — never on state the target's own actions mutate.
- Run an adversarial "launder it" pass; treat each bypass as HIGH until proven closed.
- Related: [[fail-closed-gate-escape-hatch-must-be-verified]], the ADR-049 §9 downward-authorization-transition invariant (a downward transition must be durable before it is observable).
