# Construction Pattern Standard

This standard **enacts the Agent-first API design builder tenet** (AGENTS.md) and **ADR-052 (Unified Construction Pattern)**. It is the enforced, mechanical form of the tenet: where the tenet states the goal (every public API optimized for first-pass LLM authorability), this document gives the rules a structural check can verify and an agent can follow without a compile-retry loop.

It governs **every developer-facing construction entry point** in the SDK surface — Node, Relay, `host_site`, Context, Identity — in **all five languages** (Rust core + Python, TypeScript, Swift, Kotlin). It does not govern internal-only constructors that no SDK author calls.

## The pattern

Every construction entry point is **one flat config object** plus **one entry function**:

```rust
let node = Node::start(NodeConfig {
    reach: Reach::Domain { domain: "example.com".into() },
    identity: IdentitySource::Generate { custody, did_method },
    storage: StorageSlot::Sqlite { path, passphrase }, // core slot; the FFI bridges mirror it as their `StorageConfig` enum
    blob_storage: BlobStorageBackend::sqlite(&blob_db)?, // required relay blob backend (M4); durable for a public node
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
| `in_memory: bool` (DHT publish) | `dht: DhtMode` — fail-safe `DhtMode::Disabled` (no publish), `Production{…}` opt-in; `Memory` is test-harness-only |

Booleans that are genuinely binary state with no behavioral fork (e.g. `http3: bool` enabling an additional listener) are permitted, but the bar is high: if the choice has security or addressing consequences, it is an enum.

The ACME contact email is optional: `TlsMode::Acme { email: None }` selects headless ACME (no contact email) — the legacy headless-server default for a domain node that sets no TLS options. `Some(e)` registers the ACME account with contact address `e`. The optionality changes no fail-safe property: ACME on any non-`Domain` reach is still a loud error regardless of the email.

### M2 — The security-critical choice is required or fail-safe-defaulted, never silently unsafe

For each entry point, one choice is designated **security-critical**. It must be either an explicit required field, or defaulted to the **fail-safe** value — never defaulted to the unsafe value, and never inferable into the unsafe value by omission.

- **Node / host_site:** publishing an address to the DHT discloses location/IP. The security-critical direction is **disclosure**, and only `DhtMode::Production` discloses. `dht: DhtMode` defaults to `Disabled` (no publish) — the fail-safe, non-disclosing value — and `DhtMode::Production` is the deliberate, explicit opt-in that publishes the address. `Disabled` is DHT-*layer*-off: it never publishes, and its resolution arm is honestly empty (`Ok(None)`, never a fabricated or in-memory answer) — unlike the former `Memory` default, whose in-memory client is a §17.17.3 *resolve* nullifier and is now **test-harness-only** (compiled only under `feature = "testing"`; ADR-062 §Decision 1). Because `Disabled` never discloses, **`DhtMode::Disabled` is always valid for every `Reach`**, including a publishing-capable `Reach` (`Domain`, `NatTraversal`): `NatTraversal` (or `Domain`) + `Disabled` is a legitimate, *more-private* config — "publicly reachable, but the address is not published to the DHT; share it out-of-band" — and is never rejected. Erroring on the fail-safe direction would itself violate M2 by nudging callers toward the disclosing one. M2 is satisfied purely by the default direction (`Disabled`) and the explicit-opt-in requirement for `Production`; there is **no** "publishing `Reach` + `Disabled` ⇒ error" rule, because `Disabled` never silently discloses — the one failure M2 guards against. (The genuinely-contradictory TLS checks below — `Domain` + `Plaintext`, `Acme` on a non-`Domain` reach — are unaffected and remain loud errors.)
- **Site TLS:** `TlsMode::Plaintext` is never a default. A config that omits TLS does not silently serve plaintext on a public reach.
- **Identity:** the security-critical choice is whether to **persist key material**. `persistence: None` (an ephemeral identity, no key material at rest) is the fail-safe default; persisting is the explicit `Some(StorageSlot)` choice, never reached by omission. When persistence *is* chosen, the slot is `EncryptedStorage`-bound — persisting is encrypted-only (see the EncryptedStorage compile-time split). This is the same model as a Node's persisted identity, which persists into the Node's own `storage` slot; the only difference is the source of the slot — Node reuses `NodeConfig.storage`, standalone Identity names its own `IdentityConfig.persistence`.
- **Relay:** the security-critical choice is the `BridgeRole` selection. `bridge: BridgeRole` defaults to `Disabled` (the fail-safe — a relay that brokers nothing); `Enabled` is an explicit opt-in never reached by omission. `BridgeRole::Enabled` carries no payload: brokering authenticates each `BRIDGE_REGISTER` by a P-256 signature over the identifier-to-routing-id mapping (SCP-247, §10.12.4), so enabling the broker role requires no shared secret. The relay's `bridge_secret` field is a **separate, orthogonal** concern — the internal-relay WebSocket connection-admission secret (`Authorization: Bearer`), set independently of the broker role (e.g. a Node sets `bridge_secret` on a relay that brokers nothing) — and is not part of the construction-pattern surface.
- **Context:** the security-critical choice is the `ContextCreation` Template-vs-Explicit selection itself — a required enum with no default, so M2 applies **per-variant**: within `Explicit`, the permission `ceiling` is a required field (no over-broad default ceiling) and must be non-empty, and `Template` resolves only to the named template's fail-safe parameters. A create whose ceiling is absent, null, or empty fails with the typed `ContextError::CeilingRequired` and creates nothing, because an undeclared ceiling leaves the context's security boundary to a default nobody chose and an empty ceiling describes a context no member can use (Alec's ruling, 2026-09-30). The `ContextError::CeilingRequired` doc in `scp-protocol` states which sites raise it and which error code each declaration maps to.

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
  NodeConfig { reach, identity, storage, blob_storage, ..NodeConfig::defaults(reach2, identity2, storage2, blob_storage2) }
  ```

A config whose every field is genuinely fail-safe **may** keep `Default`. The rule fires only when a field is security-relevant or irreducible *and lacks a fail-safe default*. `RelayConfig` shows both halves: its `bridge` field alone would not fire M4, because `BridgeRole::default() == Disabled` (a relay that brokers nothing until explicitly enabled) is fail-safe; its `relay_url` field does fire M4, because the relay's public URL fixes its reserved push routing ID (spec §10.7.1 step 2) and no value is safe to invent. `RelayConfig` therefore has no `Default` and is built with `RelayConfig::defaults(relay_url)`.

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

`KeyCustody`, `Storage`, and `IdentityBackend` use return-position `impl Trait` in trait (RPITIT) and are **not object-safe**: `Arc<dyn Storage>` does not compile. Config objects therefore carry providers as **typed enum-selectors or concrete types**, never as trait objects.

This is consistent with injection-through-initializers (architecture.md §2.5): the config object **is** the initializer through which custody/storage/identity/transport are injected. The flat shape is the vehicle for dependency injection, not a bypass of it.

> Rule: providers are typed enum-selectors / concrete types, never boxed `dyn`. Rationale: ADR-052 Rejected Alternative #2.

## Storage vocabulary

Three names, three jobs, so a reader never conflates them:

- **`Storage`** — the raw provider **trait** (the persistence capability itself).
- **`StorageSlot`** — the **Rust-core config selector enum**. Every core config object carries it (`NodeConfig.storage`, `IdentityConfig.persistence`). It includes the **Rust-only `Custom(concrete)`** variant carrying a caller-supplied Rust `Storage` implementation.
- **`StorageConfig`** — the **per-FFI-bridge mirror** of `StorageSlot`, exposing only the named/convenience variants (`InMemory`, `Sqlite`). A Rust trait object cannot cross the FFI boundary, so the bridge mirror omits `Custom(concrete)`.

**`IdentityBackendSlot` and `KeyCustodySlot` are the same selector shape for the other two capabilities**, and `IdentityConfig` requires both. `IdentityBackendSlot` carries one named variant, `RelayNetwork`, the `IdentityBackend` of `03-identity.md` §3.10.10 over the SCP relay network, plus the Rust-only `Custom(concrete)`; ADR-063 removed the did:dht backend, so no second named variant exists and a selector with one named variant still states the choice rather than defaulting it. `KeyCustodySlot` carries the two named variants that the custody request vocabulary of `03-identity.md` §3.2.2 defines, plus `Custom(concrete)`: **`EncryptedFile`**, the request value `encrypted_file`, a software key in `FileKeyCustody`'s encrypted file; and **`OsKeystore`**, the request value `os_keystore`, the operating system's own key store reached through a caller-supplied `KeyCustodyProvider`. §3.2.2 names two values, so the slot carries no third named variant (no `Platform`, no `Software`, no `Hardware`), and an in-memory custody is a testing-build affordance outside the slot. `17-persistence-and-storage.md` §17.8's platform table states which store each value reaches on each platform. Each bridge mirrors both as `IdentityBackendConfig` and `KeyCustodyConfig`, omitting `Custom(concrete)` for the reason above.

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
    dht: DhtMode,              // defaults DhtMode::Disabled / no-publish (M2)
    // Defaulted optionals:
    bind_addr, local_api, cors_origins, dht_gateways, http3, dns_provider,
    // Capability slots (typed, never dyn):
    nat: NatSlot, network_detector, blob_storage,
    push: PushSlot,            // Disabled | Enabled(Box<PushProviders{store, senders: PushSenders{apns, fcm}}>); defaults Disabled (M2)
}
```

Entry: `Node::start(NodeConfig)` (production, `where S: EncryptedStorage`) + `Node::start_for_testing(NodeConfig)` (feature-gated). The `Dom`/`Id` typestate markers are deleted; the `<K, D, S>` generics survive, carried by the config and its selectors. (The `IdentitySource` name-reconciliation against the existing private `scp-node` enum is an implementation-sequencing detail — see the ADR-052 Dependencies bullet, not restated here.)

### Node start — `NodeStartConfig`

`node_start` starts a production node from an existing `SCP` instance. The PyO3, napi-rs and UniFFI bridges export it, and the Python, TypeScript and macOS Swift SDKs wrap it. `server::node_start` in `scp-ffi-common` converts a `NodeStartConfig` into the core `NodeConfig` above, and calls `Node::start`. The config takes the name `NodeStartConfig` because the converting function has both `NodeStartConfig` and `NodeConfig` in scope.

`NodeStartConfig` lives in `crates/scp-ffi/common/src/node_start_config.rs`. It is a flat config under this standard. Serde deserializes it with `deny_unknown_fields`, and each of its data enums carries the tag `kind`. A `kind` value is the arm's name in `snake_case`, as the bridges' `StorageConfig` spells `in_memory`: `{"kind": "nat_traversal"}`, `{"kind": "any_origin"}`.

| Field | Type | Status |
|---|---|---|
| `reach` | `FfiReach{Domain{domain}, NatTraversal, Local}` | required; `Tunnel` omitted |
| `identity` | operator handle: each SDK (Python, TypeScript, Swift) takes its own `Identity` handle object, and every bridge receives that handle and checks it under ADR-048. The PyO3 and napi-rs `node_start` take `config_json` plus the handle, and UniFFI takes `Arc<Identity>` in the record. A handle another `SCP` instance minted returns `SCP-PERM-3030` | required |
| `blob_storage` | `FfiBlobBackend{InMemory, Redb{path}, Sqlite{path}}` | required; S3 and Postgres omitted |
| `tls` | `FfiTlsMode{SelfSigned, Acme{email?}, Plaintext, Terminated}` | required |
| `dht` | `FfiDhtMode{Disabled}` | required; `Disabled` only, by keri's scope ruling of 2026-10-13 |
| `cors_origins` | `FfiCorsOrigins{AnyOrigin, Allowlist{origins}}` | required |
| `bind_addr`, `http_bind_addr` | `Option<SocketAddr>` | optional |
| `nat` | `{Auto}` | optional |
| `projection_rate_limit` | `Option<u32>`, greater than 0 | optional |

Field rules:

- **`identity` names the operator.** Alec ruled on 2026-08-17: "nodes don't get identities and don't act. they are not participants". The handle names an operator identity that is already registered on the same `SCP` instance, and the bridge lowers it to `IdentitySource::Explicit`. `NodeStartConfig` has no `Persisted` arm, no passphrase field and no key path.
- **No storage field.** `node_start` takes the `SCP` instance's own storage handle (`17-persistence-and-storage.md` §17.6, first-party storage adapters). A second store on the same directory fails, because `SqliteStorage::new` takes a non-blocking exclusive lock on `scp.db.lock` in that directory. When the instance store is in-memory, `node_start` logs a warning that the node loses all state on drop.
- **`tls` and `dht` are required at the FFI layer, although the core `NodeConfig` defaults both.** The PyO3 and napi-rs bridges read untyped input, so an optional field with a default would let a misspelled key select that default.
- **`cors_origins` is required, because the core `NodeConfig` reads `None` as the permissive `*` origin.** `AnyOrigin` selects `*` only when the caller names it. The listed arm is `Allowlist`, not `List`: UniFFI generates a Kotlin data class per data arm, and a class named `List` shadows `kotlin.collections.List` in its own `origins` field, so the Kotlin bindings do not compile.
- **Validation finishes before any directory or file exists.** `node_start` runs `scp_node::validate_reach_and_tls` and the field checks first, and creates the blob directory and files only after both pass.
- **`internal_relay_url` uses the relay's bound address,** not a hardcoded `ws://127.0.0.1:{port}`.

Arms and fields that `NodeStartConfig` omits:

| Omitted | Reason |
|---|---|
| `Reach::Tunnel` | The core does not thread `public_url` into the published relay URL. |
| `TlsMode::Custom` | It carries an `Arc<dyn TlsProvider>` trait object, which cannot cross the FFI boundary. |
| `DhtMode::Memory` | Its in-memory client is a nullifier compiled only under `feature = "testing"` (ADR-062, capability injection, Decision 1). |
| `NatSlot::Custom`, `NatSlot::Tuned` | Both carry `NatStrategy` trait objects. |
| `push` | Push credentials load only from operator files into zeroizing buffers, so a field that crossed the FFI boundary would carry either key bytes or a second credential loader. An SDK-started node runs with push `Disabled`, and its relay answers a push registration with `4063` `PUSH_NOT_SUPPORTED`. |
| `local_api`, `http3`, `dns_provider`, `network_detector`, `dht_gateways` | `local_api` is a development control plane whose token the node mints. The `http3` field compiles only under `feature = "http3"`, which no bridge enables. `dns_provider` overrides the selected `tls` and `domain` without saying so in the signature. `network_detector` is a core capability slot. `dht_gateways` has no DHT client to reach, because the operator identity owns its DID method and its DHT client. |

keri's scope ruling of 2026-10-13: `dht` exposes `Disabled` only, because ADR-063 removes Mainline publication; under `Disabled` the node runs its relay and publishes nothing. `DnsSubdomain` stays out of the SDK mirror and `dns_provider` stays binary-only, because the DID-derived label collides across one operator's nodes and changes at the `Identifier` cut-over; the keri workstream owns defining that label and a future relay-advertisement variant.

Entry: each bridge's `node_start` resolves the operator identity, takes the instance storage, and calls `server::node_start(cfg, NodeIdentity, InstanceStorage)` in `scp-ffi-common`, which validates and then calls `Node::start`. `sdk-common.md` §"Node start error codes" lists the error code each failure returns.

After `server::node_start` returns the running node, the bridge registers it in the `SCP` instance's node registry and binds the instance's `Supervisor` to it in four steps. First, the start refuses when a running node already holds the instance's binding. Second, the start connects to the node's relay. Third, the start attaches a `Supervisor` when the instance holds none, and reuses the instance's `Supervisor` when it holds one. Fourth, the start rebinds the `Supervisor`'s transport and the instance's transport manager to the relay connection, and registers the operator DID as a local DID. Because the connect runs before the attach, a `RelayConnect` failure attaches no `Supervisor`. Any call that attaches a `Supervisor` lazily leaves one on the instance, and a later start reuses it. The complete list of those calls: `context_create`, `context_join_from_welcome`, `context_import`, `reserve_key_package`, `configure_relay_transport` and `configure_local_transport` on every bridge; `context_join` on PyO3; and `invite_member`, `register_local_did` and `is_local_did` on UniFFI. One node at a time holds an instance's binding: while a running node holds it, a second start returns `ServerError::SupervisorWiring` (`SCP-TRANS-5056`). When a step fails, the bridge shuts the started node down, removes it from the node registry, and returns `ServerError::SupervisorWiring` (`SCP-TRANS-5056`). No bridge falls back to a `Supervisor` without relay transport, and `node_start` returns a node handle only after its own rebind succeeds.

A node handle's `shutdown` and its drop put back the transport provider and the transport manager the start displaced, so a later start binds again. A send already in flight when the transport is rebound finishes on the provider it loaded, and later sends use the new one. A `Supervisor` attached lazily before the start keeps the DID its attaching call gave its MLS factory; the start rebinds only its transport.

### Relay — `RelayConfig`

Already a flat config object. Bring fully in line: `supports_bridge: bool` → `bridge: BridgeRole { Disabled, Enabled }` (M1). `BridgeRole::Enabled` is payload-free and needs no config secret, which the M2 Relay bullet states. The relay's `bridge_secret: Option<[u8;32]>` stays a **separate, orthogonal** field — the internal-relay WebSocket connection-admission secret, set independently of the broker role — and is therefore out of the construction-pattern surface (not folded into `BridgeRole`). Entry: `Relay::start(RelayConfig, storage)` — the SDK-facing entry, which wraps the internal `RelayServer::new(config, storage)` (see the entry-verb rule). `RelayConfig` has no `Default`: `relay_url` (a `LiveRelayUrl` handle every listener of the relay shares, from which the reserved push routing ID derives, §10.7.1 step 2) is irreducible, so M4 fires and the factory is `RelayConfig::defaults(relay_url)`. `bridge` is not the reason, since `BridgeRole::default() == Disabled` is fail-safe.

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

> **Why `HostSiteConfig`, not `SiteConfig`.** The bare name `SiteConfig` is already taken by the FFI-exported `crates/scp-node/src/projection.rs` `SiteConfig` (the virtual-host deploy-limits type: hostname / index path / max assets / retention / CSP), which the three bridges export and the SDK capability matrix tracks. Renaming that type is a bridge-parity hazard out of scope here, so the construction host config takes the distinct name `HostSiteConfig` — a compiler-level constraint, the one legitimate reason to deviate from the otherwise-`<Thing>Config` naming.

`HostSiteConfig` carries **both** a `tls: TlsMode` and a `dht: DhtMode`, and inherits the **same M2 DHT-publish rule as `NodeConfig`**: `dht: DhtMode` defaults to the fail-safe `DhtMode::Disabled` (no publish), and `DhtMode::Production` is the explicit opt-in that discloses the address. `DhtMode::Disabled` is **always valid for every `Reach`** here too — including a publishing-capable `Reach` like `NatTraversal` (the reachable-but-unpublished self-host case) — because `Disabled` never discloses. (The former `DhtMode::Memory` default is now test-harness-only — its in-memory client is a §17.17.3 resolve nullifier; `Disabled` is the shipped no-publish value, ADR-062 §Decision 1.) M2's Site-DHT axis is satisfied by the default direction and the explicit-opt-in requirement for `Production`, exactly as for `NodeConfig`; there is no "publishing `Reach` + `Disabled` ⇒ error" rule. The Site-TLS axis is the orthogonal, genuinely-contradictory check that *does* fire: omitting TLS never silently serves plaintext on a public reach.

`host_site` (today `host_site(opts: HostSiteConfig)`, `crates/scp-node/src/self_host.rs`) remains the fail-safe **sugar** tier: it constructs a full `HostSiteConfig` and delegates to `Node::start` — never a parallel construction path (matches `start_local` / `start_in_memory`).

### Context — `ContextConfig`

```
ContextConfig {
    creation: ContextCreation,  // Template{template, peer} | Explicit{ceiling, roles, governance, memory_scope}
    // shared optionals: ttl, tools, …
}
```

`ContextCreation` makes the template-vs-explicit XOR a **required enum**. This replaces the Rust `create_context().template().build()` fluent builder and aligns Rust to the options-object that Python/TS/Swift already use — eliminating the `sdk-common.md` Context-creation divergence. Entry: `<manager>.create(ContextConfig)` — the verb-`create` method on the live `Supervisor`/ContextManager (see the Context receiver carve-out under the entry-verb rule for why a context is created within an existing manager runtime rather than via a bare `Context::create`); the language SDKs surface it as a method on their SDK handle.

The `peer` carried by `ContextCreation::Template { template, peer }` is the bilateral counterparty for the invitation step. The invitation/Welcome-delivery that actually adds the peer is a higher SDK layer; until it is wired, the core `create` entry **rejects a supplied peer loudly** (a typed `BilateralPeerNotSupported` error) rather than silently dropping it — a config field is never accepted and then ignored (AGENTS.md "no silent" tenet). `peer: None` is the supported form at this layer.

### Identity — `IdentityConfig`

```
IdentityConfig<S> {                       // generic over the storage type S, exactly as NodeConfig<S> is
    backend: IdentityBackendSlot,         // required
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

**Worked precedent:** the existing `StorageConfig` FFI mapping already demonstrates this exact equivalence across all three bridges — the pattern is proven, not speculative.

**FFI asymmetry (intentional, precedented).** The core config carries injected providers as typed `StorageSlot` slots (generic over `S`, or a core capability enum). For advanced injection, a core slot may add a `Custom(concrete)` variant carrying a caller-supplied Rust custody or storage implementation — this variant is a **new, Rust-core-only** design element of this pattern, not an existing enum variant. A Rust trait object cannot be injected across an FFI boundary, so each bridge's `StorageConfig` mirror simply omits it and exposes only the named/convenience variants (e.g. `StorageConfig::Sqlite`, `StorageConfig::InMemory`). The established precedent is the existing `StorageConfig` mirror itself — defined identically per bridge — together with the custody request vocabulary of `03-identity.md` §3.2.2 (the FFI surface accepts the named values `encrypted_file` and `os_keystore`, and an `os_keystore` store arrives as a `KeyCustodyProvider` callback, never as a caller-supplied Rust object). This Rust-core-only/FFI-named split is correct, not a coverage gap.

## Related artifacts

- **AGENTS.md → Agent-first API design** (builder tenet) — the goal this standard enacts.
- **AGENTS.md → "enforce mechanically"** — why this lives as a structural check, not prose.
- **ADR-052 (Unified Construction Pattern)** — the worked decision, rationale, and rejected alternatives.
- **ADR-032 §AC-6** — superseded by ADR-052; the original `ApplicationNode` builder mandate.
- **ADR-049 (lock-free-read invariant)** — why providers stay enum-selectors, never boxed `dyn`.
- **architecture.md §2.5** — injection-through-initializers, preserved; the config object is the initializer.
- **sdk-common.md → Context Creation** — rewritten to the `ContextConfig` options-object form to match this standard.
