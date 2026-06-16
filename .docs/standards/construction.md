# Construction Pattern Standard

This standard **enacts the Agent-first API design builder tenet** (CLAUDE.md) and **ADR-052 (Unified Construction Pattern)**. It is the enforced, mechanical form of the tenet: where the tenet states the goal (every public API optimized for first-pass LLM authorability), this document gives the rules a structural check can verify and an agent can follow without a compile-retry loop.

It governs **every developer-facing construction entry point** in the SDK surface — Node, Relay, `host_site`, Context, Identity — in **all five languages** (Rust core + Python, TypeScript, Swift, Kotlin). It does not govern internal-only constructors that no SDK author calls.

## The pattern

Every construction entry point is **one flat config object** plus **one entry function**:

```rust
let node = Node::start(NodeConfig {
    reach: Reach::Domain { domain: "example.com".into() },
    identity: IdentitySource::Generate { custody, did_method },
    storage: StorageSlot::Sqlite { path, passphrase }, // core slot; the FFI bridges mirror it as their `StorageConfig` enum
    ..NodeConfig::defaults(/* required… */)
}).await?;
```

- **One config object** carries every parameter as a named field. Order is irrelevant; the model reads field names, not positions.
- **One entry function** — `Thing::start(config)` or `Thing::create(config)` per the entry-verb rule below. No fluent chains, no staged transitions, no `.build()` terminator.
- **Required choices are required fields.** What the type system must guarantee is encoded as non-`Option` fields (often enums), not as phantom typestate ordering. The compiler still enforces them; the author can still read them.
- **The shape is identical in all five languages.** The same field names, the same enum variants, the same required/optional split. A model that has written the Python config can write the Swift config.

The measure of success (from the tenet): *an agent writes correct code from the type signature plus one example, with no compile-retry loop.*

## The entry-verb rule

The entry function's verb is **not** left to per-type discretion. There are exactly two verbs, chosen mechanically by what the entry point produces:

- **`Thing::start(config)`** — for anything that **spawns a running server/runtime** (a live process with background tasks, listeners, or a runtime loop): **Node**, **Relay**.
- **`Thing::create(config)`** — for **value/handle construction** (a value or handle with no spawned runtime of its own): **Identity**, **Context**.

This fixes the verb at every entry point: `Node::start`, `Relay::start`, `Identity::create`, `Context::create`. `host_site` keeps its verb-named free-function form as the fail-safe sugar tier over `Node::start`.

> **Context receiver carve-out.** The verb for Context is `create`, but its **receiver** differs from the other value/handle entry. `Identity::create` is a true top-level constructor — an identity is a self-contained value with no dependency on a running manager. A context is not: it is created **within an existing manager runtime** (the Rust-core `Supervisor`, which absorbed the former `ContextManager` per ADR-049 — it owns the MLS group creation, actor spawn, and event-log init that creating a context performs, and is the instance the FFI bridges already drive via `create_context`). There is no manager-free `Context::create(config)` to expose without threading the manager through every caller. The Rust-core context entry is therefore **`<manager>.create(ContextConfig)`** — the verb-`create` method on the `Supervisor`/ContextManager — and the language SDKs surface it as a method on their SDK handle (`sdk.create_context(config)` / `sdk.createContext(opts)`, see sdk-common.md). The verb (`create`) and the flat-config object (`ContextConfig`) are identical to the rest of the pattern; only the receiver is the live manager rather than a bare type.

For Relay, the SDK-facing entry is **`Relay::start(config)`**. The existing low-level `RelayServer::new(config, storage)` is the internal constructor that `Relay::start` wraps; `RelayServer::new` is therefore **not** part of the public construction-pattern surface and is exempt from the verb rule.

## The five mechanical rules

These are enforced by a structural check (`scripts/check-construction-pattern.py`, added per ADR-052 AC-9) over the construction modules, not by documentation alone.

### M1 — Enums, not booleans, for semantic choices

A boolean parameter that selects between two named behaviors is a misuse-magnet: `true`/`false` carry no meaning at the call site, and adding a third behavior breaks the signature. Replace every semantic boolean with an enum whose variants name the choices.

| Replace | With enum |
|---|---|
| `plaintext: bool` (site TLS) | `tls: TlsMode { SelfSigned, Acme { email: Option<String> }, Plaintext, Terminated, Custom(Arc<dyn TlsProvider>) }` (the `Custom` slot is a **Rust-core-only** capability slot — like `NatSlot::Custom` — for injecting a caller-supplied `TlsProvider`; `TlsProvider` is object-safe, unlike the RPITIT provider traits, so it does not violate the no-`dyn` rule below; the per-FFI `TlsMode` mirror **omits** `Custom`) |
| `skip_nat: bool` + addressing flags | `reach: Reach { Domain{…}, NatTraversal, Tunnel{…}, Local }` |
| `supports_bridge: bool` (relay) | `bridge: BridgeRole { Disabled, Enabled }` (`Default = Disabled`) |
| `in_memory: bool` (DHT publish) | `dht: DhtMode { Memory, Production{…} }` |

Booleans that are genuinely binary state with no behavioral fork (e.g. `http3: bool` enabling an additional listener) are permitted, but the bar is high: if the choice has security or addressing consequences, it is an enum.

The ACME contact email is optional: `TlsMode::Acme { email: None }` selects headless ACME (no contact email) — the legacy headless-server default for a domain node that sets no TLS options. `Some(e)` registers the ACME account with contact address `e`. The optionality changes no fail-safe property: ACME on any non-`Domain` reach is still a loud error regardless of the email.

### M2 — The security-critical choice is required or fail-safe-defaulted, never silently unsafe

For each entry point, one choice is designated **security-critical**. It must be either an explicit required field, or defaulted to the **fail-safe** value — never defaulted to the unsafe value, and never inferable into the unsafe value by omission.

- **Node / host_site:** publishing an address to the DHT discloses location/IP. The security-critical direction is **disclosure**, and only `DhtMode::Production` discloses. `dht: DhtMode` defaults to `Memory` (no publish) — the fail-safe, non-disclosing value — and `DhtMode::Production` is the deliberate, explicit opt-in that publishes the address. Because `Memory` never discloses, **`DhtMode::Memory` is always valid for every `Reach`**, including a publishing-capable `Reach` (`Domain`, `NatTraversal`): `NatTraversal` (or `Domain`) + `Memory` is a legitimate, *more-private* config — "publicly reachable, but the address is not published to the DHT; share it out-of-band" — and is never rejected. Erroring on the fail-safe direction would itself violate M2 by nudging callers toward the disclosing one. M2 is satisfied purely by the default direction (`Memory`) and the explicit-opt-in requirement for `Production`; there is **no** "publishing `Reach` + `Memory` ⇒ error" rule, because `Memory` never silently discloses — the one failure M2 guards against. (The genuinely-contradictory TLS checks below — `Domain` + `Plaintext`, `Acme` on a non-`Domain` reach — are unaffected and remain loud errors.)
- **Site TLS:** `TlsMode::Plaintext` is never a default. A config that omits TLS does not silently serve plaintext on a public reach.
- **Identity:** the security-critical choice is whether to **persist key material**. `persistence: None` (an ephemeral identity, no key material at rest) is the fail-safe default; persisting is the explicit `Some(StorageSlot)` choice, never reached by omission. When persistence *is* chosen, the slot is `EncryptedStorage`-bound — persisting is encrypted-only (see the EncryptedStorage compile-time split). This is the same model as a Node's persisted identity, which persists into the Node's own `storage` slot; the only difference is the source of the slot — Node reuses `NodeConfig.storage`, standalone Identity names its own `IdentityConfig.persistence`.
- **Relay:** the security-critical choice is the `BridgeRole` selection. `bridge: BridgeRole` defaults to `Disabled` (the fail-safe — a relay that brokers nothing); `Enabled` is an explicit opt-in never reached by omission. `BridgeRole::Enabled` carries no payload: brokering authenticates each `BRIDGE_REGISTER` by an Ed25519 signature over the DID-to-routing-ID mapping (SCP-247, §10.12.4), so enabling the broker role requires no shared secret. The relay's `bridge_secret` field is a **separate, orthogonal** concern — the internal-relay WebSocket connection-admission secret (`Authorization: Bearer`), set independently of the broker role (e.g. a Node sets `bridge_secret` on a relay that brokers nothing) — and is not part of the construction-pattern surface.
- **Context:** the security-critical choice is the `ContextCreation` Template-vs-Explicit selection itself — a required enum with no default, so M2 applies **per-variant**: within `Explicit`, the permission `ceiling` is a required field (no over-broad default ceiling), and `Template` resolves only to the named template's fail-safe parameters.

> **Un-mechanizable carve-out (human-review).** "A `Template` resolves only to fail-safe parameters" is a property of the template **data**, not of config **shape** — the structural check `scripts/check-construction-pattern.py` (AC-9) inspects type/field structure, so it **cannot** verify what values a named template expands to. This clause is therefore enforced by human review, exactly like the M1 boolean carve-out (whether a surviving `bool` is "genuinely binary state with no behavioral fork" is also a judgment the check cannot make) and the M2 default-*direction* judgment (the check sees that a default exists but cannot judge whether it points at the fail-safe value — Node/Site DHT no-publish, Relay `BridgeRole::Disabled`, Identity ephemeral `persistence: None`). Stating it keeps the mechanical-vs-prose line honest: the check guards config shape; template-data fail-safety, the M1 bool judgment, and the M2 default-direction judgment are the three properties it cannot.

Convenience sugar (presets) may only ever resolve to fail-safe values.

### M3 — Required capabilities fail loud, never silent no-op

A config that names a capability the runtime cannot satisfy must return a typed error at construction, not degrade silently. Model this on `StorageConfig`'s fail-closed behavior (`StorageInitError`): a storage config that cannot initialize returns an error; it never silently falls back to in-memory.

> **M2 vs M3 are distinct axes.** M2 is about the *default direction* of a security-critical choice — when the caller omits it, does it fall to the safe value or the unsafe value? M3 is about a required capability being *satisfiable at runtime* — a config that names something the runtime cannot deliver must fail loud, not silently no-op. They overlap only in "loud error, not silent"; otherwise they are independent (defaults vs. runtime satisfiability).

### M4 — No whole-struct `Default` when any field is security-relevant or irreducible

If any field of a config object is security-relevant or has no safe default (the caller *must* decide), the struct must **not** implement a whole-struct `Default`, because `Default` would manufacture a value for a decision the caller is required to make.

Instead:

- Required fields are **non-`Option`** (so omission is a compile error, not a silent `None`).
- Provide a `Thing::defaults(required…) -> Config` **factory** that takes the irreducible required fields and fills the rest with fail-safe defaults, enabling the spread idiom:

  ```rust
  NodeConfig { reach, identity, storage, ..NodeConfig::defaults(reach2, identity2, storage2) }
  ```

A config whose every field is genuinely fail-safe **may** keep `Default` — `RelayConfig` qualifies, since every field has a safe default. This explicitly depends on `BridgeRole::default() == Disabled`: `bridge` is `RelayConfig`'s only security-consequential field, and because its `Default` is the fail-safe `Disabled` (a relay that brokers nothing until explicitly enabled), the whole struct's `Default` manufactures no unsafe value. If `BridgeRole::default()` were `Enabled`, `RelayConfig` would forfeit this exception and M4 would fire. The rule fires only when a field is security-relevant or irreducible *and lacks a fail-safe default*.

### M5 — One greppable contract

Exactly **one real constructor** per type. No `*Builder` types, no typestate / `PhantomData` state markers, no positional-argument construction of the public config. The construction surface is greppable: searching for `Builder` in a construction module returns nothing.

**The one allowed exception:** the `EncryptedStorage` `start` / `start_for_testing` split (see below). It is the only place a type has two entry functions, and it exists solely to preserve a compile-time security guarantee — not for ergonomic staging.

## The EncryptedStorage compile-time split (the one M5 exception)

`EncryptedStorage` is a sealed trait (`crates/scp-platform/src/encrypted.rs`): production construction requires the storage type to implement it; testing construction is feature-gated to accept any `Storage`. This enforces "production cannot persist plaintext" at compile time. The pattern preserves this guarantee as a **trait-bound split**, not a builder:

```rust
// Production: storage must be encryption-at-rest.
impl Node {
    pub async fn start<S: EncryptedStorage>(config: NodeConfig<S>) -> Result<Node> { … }
}

// Testing: any Storage, feature-gated so it cannot be reached in a release build.
#[cfg(any(test, feature = "allow_unencrypted_storage"))]
impl Node {
    pub async fn start_for_testing<S: Storage>(config: NodeConfig<S>) -> Result<Node> { … }
}
```

This is the **only** sanctioned two-entry-point split. ADR-052 AC-9 additionally requires a structural test proving the unencrypted-storage path is unreachable from the production identity-persisting constructors — `Node::start` and `Identity::create` (the two paths that persist identity key material).

> Rule: the seal stays a compile-time `S: EncryptedStorage` bound, never a runtime check. Rationale: ADR-052 Rejected Alternative #3.

**The seal covers every identity-key persistence path, not just Node.** Identity key material persists only to an encrypted storage slot. Any `StorageSlot` used to persist identity keys is bound by `EncryptedStorage` exactly as `Node::start` is — on **both** production persistence paths:

- **Node** — `NodeConfig.storage` on the production `Node::start` path (`where S: EncryptedStorage`). A Node's persisted identity uses the Node's *own* `storage` slot; there is no separate identity slot to seal.
- **Identity** — `IdentityConfig.persistence` on the production `Identity::create` path. When the slot is `Some(StorageSlot)`, the concrete type it carries must be `EncryptedStorage`-bound, the same compile-time bound as `Node::start`.

Consequently identity key material can **never** persist to plaintext, including via `StorageSlot::Custom`: the `Custom(concrete)` variant on a production persistence path must carry an `EncryptedStorage` type, not merely any `Storage`. This is the storage-layer realization of M2 for Identity — the security-critical Identity choice is persist-or-not, and *persisting is encrypted-only*.

## Providers stay typed enum-selectors — never `dyn`

`KeyCustody`, `Storage`, and `DidMethod` use return-position `impl Trait` in trait (RPITIT) and are **not object-safe**: `Arc<dyn Storage>` does not compile. Config objects therefore carry providers as **typed enum-selectors or concrete types**, never as trait objects.

This is consistent with injection-through-initializers (architecture.md §2.5): the config object **is** the initializer through which custody/storage/DID/transport are injected. The flat shape is the vehicle for dependency injection, not a bypass of it.

> Rule: providers are typed enum-selectors / concrete types, never boxed `dyn`. Rationale: ADR-052 Rejected Alternative #2.

## Storage vocabulary

Three names, three jobs — stated once so they are never conflated:

- **`Storage`** — the raw provider **trait** (the persistence capability itself).
- **`StorageSlot`** — the **Rust-core config selector enum**. Every core config object carries it (`NodeConfig.storage`, `IdentityConfig.persistence`). It includes the **Rust-only `Custom(concrete)`** variant carrying a caller-supplied Rust `Storage` implementation.
- **`StorageConfig`** — the **per-FFI-bridge mirror** of `StorageSlot`, exposing only the named/convenience variants (`InMemory`, `Sqlite`). A Rust trait object cannot cross the FFI boundary, so the bridge mirror omits `Custom(concrete)`.

All core shapes use `StorageSlot`; the bridges mirror it as `StorageConfig`. These are the same selector at two layers, not two different concepts.

## Per-entry-point target shapes

### Node — `NodeConfig`

```
NodeConfig {
    // Required (no whole-struct Default; M4):
    reach: Reach,              // Domain{domain} | NatTraversal | Tunnel{public_url} | Local
    // `Reach` is a NEW enum (P1) that folds the existing addressing machinery —
    // `PublicSurface`, `ReachabilityTier`, and the `skip_nat` / `no_domain` flags
    // (`crates/scp-node/src`) — into one required field.
    identity: IdentitySource,  // Generate{custody, did_method} | Persisted{custody, did_method} | Explicit{identity, document}
    // `IdentitySource::Persisted` means "load-or-create the node's identity, persisting it
    // into the Node's OWN `storage` slot below." It carries no separate storage slot — it
    // reuses `NodeConfig.storage`. (Same persist-to-an-encrypted-slot model as standalone
    // `Identity`, which instead names its own `IdentityConfig.persistence` slot.)
    storage: StorageSlot,      // core storage slot, generic over S; fail-closed (M3); EncryptedStorage-bound on the production `Node::start` path. The FFI bridges mirror this as their per-bridge `StorageConfig` enum.
    // Enums (M1):
    tls: TlsMode,
    dht: DhtMode,              // defaults Memory / no-publish (M2)
    // Defaulted optionals:
    bind_addr, local_api, cors_origins, dht_gateways, http3, dns_provider,
    // Capability slots (typed, never dyn):
    nat: NatSlot, network_detector, blob_storage,
}
```

Entry: `Node::start(NodeConfig)` (production, `where S: EncryptedStorage`) + `Node::start_for_testing(NodeConfig)` (feature-gated). The `Dom`/`Id` typestate markers are deleted; the `<K, D, S>` generics survive, carried by the config and its selectors. (The `IdentitySource` name-reconciliation against the existing private `scp-node` enum is an implementation-sequencing detail — see the ADR-052 Dependencies bullet, not restated here.)

### Relay — `RelayConfig`

Already a flat config object. Bring fully in line: `supports_bridge: bool` → `bridge: BridgeRole { Disabled, Enabled }` (M1). `BridgeRole::Enabled` is payload-free — the broker authenticates each `BRIDGE_REGISTER` by Ed25519 signature (SCP-247, §10.12.4), so it needs no config secret. The relay's `bridge_secret: Option<[u8;32]>` stays a **separate, orthogonal** field — the internal-relay WebSocket connection-admission secret, set independently of the broker role — and is therefore out of the construction-pattern surface (not folded into `BridgeRole`). Entry: `Relay::start(RelayConfig, storage)` — the SDK-facing entry, which wraps the internal `RelayServer::new(config, storage)` (see the entry-verb rule). `RelayConfig` may keep `Default` (every field is fail-safe — M4 does not fire), an exception that holds **precisely because** `BridgeRole::default() == Disabled` (its sole security-consequential field has a fail-safe default).

### host_site — `HostSiteConfig`

Fold `HostSiteOptions` into `HostSiteConfig`:

```
HostSiteConfig {
    reach: Reach,        // required
    tls: TlsMode,        // folds the `plaintext` bool (M1); the same enum as NodeConfig.tls
    dht: DhtMode,        // M2
    site_dir, port, storage_path, …
}
```

> **Why `HostSiteConfig`, not `SiteConfig`.** The bare name `SiteConfig` is already taken by the FFI-exported `crates/scp-node/src/projection.rs` `SiteConfig` (the virtual-host deploy-limits type: hostname / index path / max assets / retention / CSP), which the four bridges export and the SDK capability matrix tracks. Renaming that type is a bridge-parity hazard out of scope here, so the construction host config takes the distinct name `HostSiteConfig` — a compiler-level constraint, the one legitimate reason to deviate from the otherwise-`<Thing>Config` naming.

`HostSiteConfig` carries **both** a `tls: TlsMode` and a `dht: DhtMode`, and inherits the **same M2 DHT-publish rule as `NodeConfig`**: `dht: DhtMode` defaults to the fail-safe `DhtMode::Memory` (no publish), and `DhtMode::Production` is the explicit opt-in that discloses the address. `DhtMode::Memory` is **always valid for every `Reach`** here too — including a publishing-capable `Reach` like `NatTraversal` (the reachable-but-unpublished self-host case) — because `Memory` never discloses. M2's Site-DHT axis is satisfied by the default direction and the explicit-opt-in requirement for `Production`, exactly as for `NodeConfig`; there is no "publishing `Reach` + `Memory` ⇒ error" rule. The Site-TLS axis is the orthogonal, genuinely-contradictory check that *does* fire: omitting TLS never silently serves plaintext on a public reach.

`host_site` (today `host_site(opts: HostSiteConfig)`, `crates/scp-node/src/self_host.rs`) remains the fail-safe **sugar** tier: it constructs a full `HostSiteConfig` and delegates to `Node::start` — never a parallel construction path (matches `start_local` / `start_in_memory`).

### Context — `ContextConfig`

```
ContextConfig {
    creation: ContextCreation,  // Template{template, peer} | Explicit{ceiling, roles, governance, memory_scope}
    // shared optionals: ttl, tools, …
}
```

`ContextCreation` makes the template-vs-explicit XOR a **required enum**. This replaces the Rust `create_context().template().build()` fluent builder and aligns Rust to the options-object that Python/TS/Swift already use — eliminating the `sdk-common.md` Context-creation divergence. Entry: `<manager>.create(ContextConfig)` — the verb-`create` method on the live `Supervisor`/ContextManager (see the Context receiver carve-out under the entry-verb rule for why a context is created within an existing manager runtime rather than via a bare `Context::create`); the language SDKs surface it as a method on their SDK handle.

The `peer` carried by `ContextCreation::Template { template, peer }` is the bilateral counterparty for the invitation step. The invitation/Welcome-delivery that actually adds the peer is a higher SDK layer; until it is wired, the core `create` entry **rejects a supplied peer loudly** (a typed `BilateralPeerNotSupported` error) rather than silently dropping it — a config field is never accepted and then ignored (CLAUDE.md "no silent" tenet). `peer: None` is the supported form at this layer.

### Identity — `IdentityConfig`

```
IdentityConfig<S> {                       // generic over the storage type S, exactly as NodeConfig<S> is
    method: DidMethodSlot,                // required
    custody: KeyCustodySlot,              // required
    persistence: Option<StorageSlot<S>>,  // None = ephemeral identity (fail-safe default; M2). Some(slot) carries S, giving the EncryptedStorage bound somewhere to attach: on the production `Identity::create<S: EncryptedStorage>` path the slot is EncryptedStorage-bound — persisting is encrypted-only, the same seal as `Node::start`.
}
```

Entry: `Identity::create(IdentityConfig)` (production, `where S: EncryptedStorage`), mirroring `Node::start`. The `S` generic is carried by the config and its `StorageSlot<S>` slot, exactly as `NodeConfig<S>` carries it.

## Five-language equivalence

The same config object and its enums map identically across all five language SDKs. **This table is the canonical statement of the cross-language mapping** — ADR-052 and the lesson reference it rather than re-listing it.

| Concept | Rust | Python | TypeScript | Swift | Kotlin |
|---|---|---|---|---|---|
| Config object | `struct` | `@dataclass` | options `interface` | `struct` | `data class` |
| Required choice / XOR | `enum` (data variants) | sum type (`Union` of dataclasses) | discriminated union (`{ kind: "…" }`) | `enum` with associated values | `sealed class` |
| Required field | non-`Option` field | non-defaulted field | required property | non-optional `let`/`var` | non-nullable property |
| Defaults factory | `Thing::defaults(req…)` | classmethod / defaulted kwargs | factory fn / partial spread | static factory | companion factory |

**Worked precedent:** the existing `StorageConfig` FFI mapping already demonstrates this exact equivalence across all four bridges — the pattern is proven, not speculative.

**FFI asymmetry (intentional, precedented).** The core config carries injected providers as typed `StorageSlot` slots (generic over `S`, or a core capability enum). For advanced injection, a core slot may add a `Custom(concrete)` variant carrying a caller-supplied Rust custody or storage implementation — this variant is a **new, Rust-core-only** design element of this pattern, not an existing enum variant. A Rust trait object cannot be injected across an FFI boundary, so each bridge's `StorageConfig` mirror simply omits it and exposes only the named/convenience variants (e.g. `StorageConfig::Sqlite`, `StorageConfig::InMemory`). The established precedent is the existing `StorageConfig` mirror itself — defined identically per bridge — together with the `parse_custody` asymmetry (the FFI surface accepts named custody selectors, never a caller-supplied Rust object). This Rust-core-only/FFI-named split is correct, not a coverage gap.

## Related artifacts

- **CLAUDE.md → Agent-first API design** (builder tenet) — the goal this standard enacts.
- **CLAUDE.md → "enforce mechanically"** — why this lives as a structural check, not prose.
- **ADR-052 (Unified Construction Pattern)** — the worked decision, rationale, and rejected alternatives.
- **ADR-032 §AC-6** — superseded by ADR-052; the original `ApplicationNode` builder mandate.
- **ADR-049 (lock-free-read invariant)** — why providers stay enum-selectors, never boxed `dyn`.
- **architecture.md §2.5** — injection-through-initializers, preserved; the config object is the initializer.
- **sdk-common.md → Context Creation** — rewritten to the `ContextConfig` options-object form to match this standard.
- **`.docs/lessons/llm-first-config-objects-over-typestate.md`** — the evergreen reasoning.
