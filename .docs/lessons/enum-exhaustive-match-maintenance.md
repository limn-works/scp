# Exhaustive Match Gaps When Adding Enum Variants

**Problem**: Adding a new enum variant compiles cleanly if any `match` arm uses a wildcard (`_` or `..`). The type system does not protect you from semantic gaps in non-wildcard matches that you forgot to update.

Concrete case (`ResolutionLayer` in SCP-223): a new `MultiLayerCorroborated` variant was added to `ResolutionLayer`, but `shortest_ttl_for_results` already had an exhaustive (no-wildcard) match that needed a new arm. The code would have failed to compile — correctly caught. What is *not* caught: if the original match had a `_ => DISCOVERY_HANDLE_CACHE_TTL` fallback, the new variant would silently inherit the wrong TTL.

**Pattern**:

```rust
// Dangerous: wildcard silently handles future variants
fn ttl_for(layer: &ResolutionLayer) -> Duration {
    match layer {
        ResolutionLayer::Petname => PETNAME_CACHE_TTL,
        _ => DISCOVERY_HANDLE_CACHE_TTL,  // New variants silently fall here
    }
}

// Safe: exhaustive match — adding a variant forces a compiler error here
fn ttl_for(layer: &ResolutionLayer) -> Duration {
    match layer {
        ResolutionLayer::Petname => PETNAME_CACHE_TTL,
        ResolutionLayer::Domain => DOMAIN_HANDLE_CACHE_TTL,
        ResolutionLayer::DiscoveryContext => DISCOVERY_HANDLE_CACHE_TTL,
        ResolutionLayer::Attestation => ATTESTATION_HANDLE_CACHE_TTL,
        ResolutionLayer::MultiLayerCorroborated => DISCOVERY_HANDLE_CACHE_TTL,
    }
}
```

**Rule**: Never use `_` wildcards in `match` arms over enums you own — only over enums from external crates where you want forward-compatibility. When you add a variant, grep for all `match` sites over that enum and verify each one is semantically correct, not just syntactically valid.

**When adding a new enum variant, check**:
1. Every `match` site — exhaustive ones catch themselves; wildcard ones require manual audit.
2. Serialization/deserialization — `serde` derive handles new variants, but existing serialized data won't have them.
3. Display/Debug impls — often have fallthrough logic.

**Files where this pattern matters in SCP**: `ResolutionLayer` in `crates/scp-core/src/discovery/addressing.rs`.
