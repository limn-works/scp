# Inquisitor Memory

Verdicts already reached, so later passes do not re-litigate them.

- **Outlet streaming-saga recovery without a key is not a gap.** ADR-049 gives the runtime no custody signing key; the unary and streaming saga FSMs both take `target_signing_key` from the caller per call. Keyless crash recovery therefore re-drives only idempotent steps, and a streaming entry it cannot settle becomes `NeedsRepair` with escrow held (§6.2.4 "NeedsRepair reservation semantics", ADR-049 §3a). Auto-sealing without the key would need autonomous custody, which ADR-049 forbids.
- **A one-shot activation with a "documented sharp edge" is scar tissue.** The fix removes the state (bind the dependency before constructing the consumer); a loop that re-evaluates readiness each tick adds machinery whose only job is tolerating the gap.
