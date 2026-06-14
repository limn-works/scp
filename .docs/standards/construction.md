# Construction Pattern Standard

This standard **enacts the Agent-first API design builder tenet** (CLAUDE.md) and **ADR-051 (Unified Construction Pattern)**. It is the enforced, mechanical form of the tenet: where the tenet states the goal (every public API optimized for first-pass LLM authorability), this document gives the rules a structural check can verify and an agent can follow without a compile-retry loop.

It governs **every developer-facing construction entry point** in the SDK surface — Node, Relay, `host_site`, Context, Identity — in **all five languages** (Rust core + Python, TypeScript, Swift, Kotlin). It does not govern internal-only constructors that no SDK author calls.

## The pattern

Every construction entry point is **one flat config object** plus **one entry function**:

```rust
let node = Node::start(NodeConfig {
    reach: Reach::Domain { domain: "example.com".into() },
    identity: IdentitySource::Generate { custody, did_method },
    storage: StorageConfig::Sqlite { path, passphrase },
    ..NodeConfig::defaults(/* required… */)
}).await?;
```

- **One config object** carries every parameter as a named field. Order is irrelevant; the model reads field names, not positions.
- **One entry function** — `Thing::start(config)` (or `Thing::create(config)`). No fluent chains, no staged transitions, no `.build()` terminator.
- **Required choices are required fields.** What the type system must guarantee is encoded as non-`Option` fields (often enums), not as phantom typestate ordering. The compiler still enforces them; the author can still read them.
- **The shape is identical in all five languages.** The same field names, the same enum variants, the same required/optional split. A model that has written the Python config can write the Swift config.

The measure of success (from the tenet): *an agent writes correct code from the type signature plus one example, with no compile-retry loop.*

## The five mechanical rules

These are enforced by a structural check (`scripts/check-construction-pattern.py`, added per ADR-051 §AC-9) over the construction modules, not by documentation alone.

### M1 — Enums, not booleans, for semantic choices

A boolean parameter that selects between two named behaviors is a misuse-magnet: `true`/`false` carry no meaning at the call site, and adding a third behavior breaks the signature. Replace every semantic boolean with an enum whose variants name the choices.

| Replace | With enum |
|---|---|
| `plaintext: bool` (site TLS) | `tls: SiteTls { Acme { … }, Plaintext, Terminated }` |
| `skip_nat: bool` + addressing flags | `reach: Reach { Domain{…}, NatTraversal, Tunnel{…}, Local }` |
| `supports_bridge: bool` (relay) | `bridge: BridgeRole { Disabled, Enabled{…} }` |
| `in_memory: bool` (DHT publish) | `dht: DhtMode { Memory, Production{…} }` |

Booleans that are genuinely binary state with no behavioral fork (e.g. `http3: bool` enabling an additional listener) are permitted, but the bar is high: if the choice has security or addressing consequences, it is an enum.

### M2 — The security-critical choice is required or fail-safe-defaulted, never silently unsafe

For each entry point, one choice is designated **security-critical**. It must be either an explicit required field, or defaulted to the **fail-safe** value — never defaulted to the unsafe value, and never inferable into the unsafe value by omission.

- **Node / host_site:** publishing an address to the DHT discloses location/IP. `dht: DhtMode` defaults to `Memory` (no publish). Any `Reach` variant that publishes a routable address requires `DhtMode::Production`, and selecting a publishing `Reach` with `DhtMode::Memory` is a precise, loud error — not a silent publish, not a silent no-op.
- **Site TLS:** `SiteTls::Plaintext` is never a default. A config that omits TLS does not silently serve plaintext on a public reach.

Convenience sugar (presets) may only ever resolve to fail-safe values.

### M3 — Required capabilities fail loud, never silent no-op

A config that names a capability the runtime cannot satisfy must return a typed error at construction, not degrade silently. Model this on `StorageConfig`'s fail-closed behavior (`StorageInitError`): a storage config that cannot initialize returns an error; it never silently falls back to in-memory. Likewise `BridgeRole::Enabled` with no `bridge_secret` is a loud error, not a disabled bridge.

### M4 — No whole-struct `Default` when any field is security-relevant or irreducible

If any field of a config object is security-relevant or has no safe default (the caller *must* decide), the struct must **not** implement a whole-struct `Default`, because `Default` would manufacture a value for a decision the caller is required to make.

Instead:

- Required fields are **non-`Option`** (so omission is a compile error, not a silent `None`).
- Provide a `Thing::defaults(required…) -> Config` **factory** that takes the irreducible required fields and fills the rest with fail-safe defaults, enabling the spread idiom:

  ```rust
  NodeConfig { reach, identity, storage, ..NodeConfig::defaults(reach2, identity2, storage2) }
  ```

A config whose every field is genuinely fail-safe **may** keep `Default` — `RelayConfig` qualifies, since every field has a safe default. The rule fires only when a field is security-relevant or irreducible.

### M5 — One greppable contract

Exactly **one real constructor** per type. No `*Builder` types, no typestate / `PhantomData` state markers, no positional-argument construction of the public config. The construction surface is greppable: searching for `Builder` in a construction module returns nothing.

**The one allowed exception:** the `EncryptedStorage` `start` / `start_for_testing` split (see below). It is the only place a type has two entry functions, and it exists solely to preserve a compile-time security guarantee — not for ergonomic staging.

## The EncryptedStorage compile-time split (the one M5 exception)

`EncryptedStorage` is a **sealed trait** (`crates/scp-platform/src/encrypted.rs`). Production construction requires the storage type to implement it; testing construction is feature-gated to accept any `Storage`. This enforces "production cannot persist plaintext" **at compile time**.

The pattern preserves this guarantee as a **trait-bound split**, not a builder:

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

This is the **only** sanctioned two-entry-point split. ADR-051 §AC-9 additionally requires a structural test proving the unencrypted-storage path is unreachable from the production `Node::start` constructor — a mechanical belt to the compile-time suspenders. Demoting this seal to a runtime check is explicitly rejected (ADR-051 Rejected Alternatives).

## Providers stay typed enum-selectors — never `dyn`

`KeyCustody`, `Storage`, and `DidMethod` use return-position `impl Trait` in trait (RPITIT) and are **not object-safe**: `Arc<dyn Storage>` does not compile. Config objects therefore carry providers as **typed enum-selectors or concrete types**, never as trait objects. This is not a stylistic choice — it is a compiler constraint, and boxing them would also put `async-trait` allocation on storage-read/sign hot paths, regressing the ADR-049 lock-free-read invariant.

This is consistent with injection-through-initializers (architecture.md §2.5): the config object **is** the initializer through which custody/storage/DID/transport are injected. The flat shape is the vehicle for dependency injection, not a bypass of it.

## Per-entry-point target shapes

### Node — `NodeConfig`

```
NodeConfig {
    // Required (no whole-struct Default; M4):
    reach: Reach,              // Domain{domain} | NatTraversal | Tunnel{public_url} | Local
    identity: IdentitySource,  // Generate{custody, did_method} | Persisted{custody, did_method} | Explicit{identity, document}
    storage: StorageConfig,    // existing cross-FFI enum, fail-closed (M3)
    // Enums (M1):
    tls: TlsMode,
    dht: DhtMode,              // defaults Memory / no-publish (M2)
    // Defaulted optionals:
    bind_addr, local_api, cors_origins, dht_gateways, http3, dns_provider,
    // Capability slots (typed, never dyn):
    nat: NatSlot, network_detector, blob_storage,
}
```

Entry: `Node::start(NodeConfig)` (production, `where S: EncryptedStorage`) + `Node::start_for_testing(NodeConfig)` (feature-gated). The `Dom`/`Id` typestate markers are deleted; the `<K, D, S>` generics survive, carried by the config and its selectors.

### Relay — `RelayConfig`

Already a flat config object. Bring fully in line: `supports_bridge: bool` → `bridge: BridgeRole { Disabled, Enabled{ bridge_secret, … } }` (M1); `BridgeRole::Enabled` with no `bridge_secret` is a loud error (M3). `RelayServer::new(config, storage)` is the entry. `RelayConfig` may keep `Default` (every field is fail-safe — M4 does not fire).

### host_site — `SiteConfig`

Fold `HostSiteOptions` into `SiteConfig`:

```
SiteConfig {
    reach: Reach,        // required
    tls: SiteTls,        // folds the `plaintext` bool (M1)
    dht: DhtMode,        // M2
    site_dir, port, storage_path, …
}
```

`host_site(dir)` survives as fail-safe **sugar** that constructs a full `SiteConfig` and delegates — never a parallel construction path (matches `start_local` / `start_in_memory`).

### Context — `ContextConfig`

```
ContextConfig {
    creation: ContextCreation,  // Template{template, peer} | Explicit{ceiling, roles, governance, memory_scope}
    // shared optionals: ttl, tools, …
}
```

`ContextCreation` makes the template-vs-explicit XOR a **required enum**. This replaces the Rust `create_context().template().build()` fluent builder and aligns Rust to the options-object that Python/TS/Swift already use — eliminating the `sdk-common.md` Context-creation divergence.

### Identity — `IdentityConfig`

```
IdentityConfig {
    method: DidMethodSlot,    // required
    custody: KeyCustodySlot,  // required
    persistence: Option<Storage>,
}
```

Entry: `Identity::create(IdentityConfig)`.

## Five-language equivalence

The same config object and its enums map identically across all five language SDKs:

| Concept | Rust | Python | TypeScript | Swift | Kotlin |
|---|---|---|---|---|---|
| Config object | `struct` | `@dataclass` | options `interface` | `struct` | `data class` |
| Required choice / XOR | `enum` (data variants) | sum type (`Union` of dataclasses) | discriminated union (`{ kind: "…" }`) | `enum` with associated values | `sealed class` |
| Required field | non-`Option` field | non-defaulted field | required property | non-optional `let`/`var` | non-nullable property |
| Defaults factory | `Thing::defaults(req…)` | classmethod / defaulted kwargs | factory fn / partial spread | static factory | companion factory |

**Worked precedent:** the existing `StorageConfig` FFI mapping already demonstrates this exact equivalence across all four bridges — the pattern is proven, not speculative.

**FFI asymmetry (intentional, precedented).** Capability enums that carry a `Custom(concrete)` variant — e.g. a caller-supplied Rust custody or storage implementation — are **Rust-core-only**. A Rust trait object cannot be injected across an FFI boundary, so the bridge enums expose only the convenience/named variants (e.g. `StorageConfig::Sqlite`, `StorageConfig::Memory`), never `Custom`. This is the established `StorageConfig` / `parse_custody` asymmetry and is correct, not a coverage gap.

## Related artifacts

- **CLAUDE.md → Agent-first API design** (builder tenet) — the goal this standard enacts.
- **CLAUDE.md → "enforce mechanically"** — why this lives as a structural check, not prose.
- **ADR-051 (Unified Construction Pattern)** — the worked decision, rationale, and rejected alternatives.
- **ADR-032 §AC-6** — superseded by ADR-051; the original `ApplicationNode` builder mandate.
- **ADR-049 (lock-free-read invariant)** — why providers stay enum-selectors, never boxed `dyn`.
- **architecture.md §2.5** — injection-through-initializers, preserved; the config object is the initializer.
- **sdk-common.md → Context Creation** — rewritten to the `ContextConfig` options-object form to match this standard.
- **`.docs/lessons/llm-first-config-objects-over-typestate.md`** — the evergreen reasoning.
