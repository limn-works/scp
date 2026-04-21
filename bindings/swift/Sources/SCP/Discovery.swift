import Foundation

// Phase 4 PR 4 (ADR-048 demolition, #1549): the `DiscoveryBridge` namespace
// — a set of injectable closures whose defaults called `Scp.defaultInstance()`
// — has been deleted. Every discovery operation now dispatches through an
// explicit ``SCP`` instance via the ``SCP`` method extensions in
// ``Scp.swift`` (e.g. ``SCP/petnameSet(ownerDid:targetDid:name:)``,
// ``SCP/handleRegister(...)``, ``SCP/addressResolve(...)``).
//
// Free UniFFI functions that are not per-instance (e.g.
// `discoveryParseAddress`, `discoveryCreateQuery`, `discoveryNormalizeAddress`,
// `contextDiscover`) remain available as top-level functions exported by the
// UniFFI bindings; the `DiscoveryBridge` wrappers around them added no value
// and were removed as part of the demolition.
