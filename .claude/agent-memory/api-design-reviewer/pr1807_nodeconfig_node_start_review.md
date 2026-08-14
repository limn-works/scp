---
name: pr1807-nodeconfig-node-start-review
description: PR #1807 NodeConfig + Node::start flat-config surface (ADR-051 Phase B-P1, scp-node/src/config.rs); both prior Mediums RESOLVED in re-review 2026-06-14 — APPROVED
metadata:
  type: project
---

## Re-review 2026-06-14 (fresh pass): APPROVED — both prior Mediums fixed
- **M-1 RESOLVED**: NodeConfig doc-comment now has TWO examples — "local demo" (Reach::Local, all defaults, valid) + "public node on a domain" which explicitly sets `dht: DhtMode::Production`. Both pass validate_config verbatim. No LLM-copyable example is rejected.
- **M-2 RESOLVED**: validate_config now rejects Acme on every non-Domain reach (TLS rule 2). SelfSigned off-Domain remains a no-op but is correctly documented per-variant + genuinely harmless (no domain to sign; MLS confidentiality). Tests 20/21 cover Acme rejection on Local/Tunnel/NatTraversal.
- TLS×Reach matrix (doc lines 406-411) is COMPLETE + SYMMETRIC with validate_config: rejects exactly Domain+Plaintext and Acme+non-Domain; every other cell validates. Nothing valid rejected, every contradictory combo a loud InvalidConfig.
- M2 DHT axis: Memory + (Domain|NatTraversal) → loud error; Tunnel/Local + Memory valid. Matches doc + Tests 11-13.
- Remaining (Low, unchanged, acceptable for P1): dht/dht_gateways advisory-inert pub fields (dropped in split_config, no builder setter); Tunnel.public_url carried-but-dropped (tracing::warn! makes it observable). Both honestly documented.

---
(original first-pass review below; superseded by re-review above)


# PR #1807 — NodeConfig + Node::start (ADR-051 Phase B-P1)

Branch `feat/p1-nodeconfig-node-start`, file `crates/scp-node/src/config.rs` (~1370 lines incl 16 tests). Additive: lowers flat `NodeConfig` onto existing typestate `ApplicationNodeBuilder`; kernel untouched (deleted later P3). Re-exported at crate root: `config::{ExplicitIdentity, IdentitySource, NatSlot, Node, NodeConfig, Reach, TlsMode}`.

Surface: `Node` (ZST entry namespace) + `Node::start` (prod, `S: EncryptedStorage`) / `start_for_testing` (feature-gated `allow_unencrypted_storage`). Enums: `Reach{Domain,NatTraversal,Tunnel,Local}`, `TlsMode{SelfSigned,Acme,Plaintext,Terminated}`, `IdentitySource{Generate,Persisted,Explicit(Box<ExplicitIdentity>)}`, `NatSlot{Auto,Custom(Arc<dyn>),Tuned{...}}`. `NodeConfig<K,D,S>` defaults to `<NoOpCustody,NoOpDidMethod,NoOpStorage>`. `NodeConfig::defaults(reach,identity,storage)` factory + spread = M4 idiom.

## Verdict: NEEDS REVISION (2 Medium)

**M-1 (Medium): `dht: DhtMode::Memory` default contradicts publishing reaches.** `defaults()` sets Memory, but `validate_config` rejects `Reach::Domain`/`Reach::NatTraversal` (publishing) + Memory with `InvalidConfig`. So `Node::start(NodeConfig::defaults(Reach::Domain{..}, id, st))` — the canonical LLM first attempt — fails at RUNTIME. Worse: the doc-comment example AT TOP of NodeConfig uses `Reach::Domain` and would hit the same M2 error. Fix: doc examples must pair Domain with `dht: DhtMode::Production`; stronger = fold dht intent into Reach so contradiction is unrepresentable. M4 tension: fail-safe field default mutually exclusive with most common required-field value.

**M-2 (Medium): TlsMode `Acme`/`SelfSigned` off-`Domain` are SILENT no-ops.** `apply_tls` returns builder unchanged for non-Domain SelfSigned; `acme_email` set but never provisions. Only `Domain`+`Plaintext` is rejected loudly. `Reach::Local`+`TlsMode::Acme{email}` builds fine, ignores TLS choice — the silent no-op M3 forbids. Fix: reject non-Domain + Acme/SelfSigned in validate_config, or doc the no-op per-variant.

## Observations (Low/Trivial)
- `Reach::Tunnel.public_url` required String but dropped in P1 (only `tracing::warn!` via `warn_tunnel_public_url_deferred`); loopback published instead. Documented deferral, acceptable P1.
- `dht`/`dht_gateways` advisory/inert (dropped in split_config, no builder setter). dht participates in validation; dht_gateways fully inert. Honest but inert pub fields invite misuse.
- start/start_for_testing split = sanctioned M5 EncryptedStorage exception; start_for_testing correctly feature-gated. Good.
- Entry-verb rule OK (start spawns runtime). Generic NoOp defaulting lets Generate drive inference, rarely needs turbofish (Explicit is the exception).
- `NatSlot::Tuned` all-None == `Auto` (trivial redundancy).
