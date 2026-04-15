#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! StoredValue deserialization fuzz target (Tier 2 — covers #1653).
//!
//! Target: `scp_runtime::store::StoredValue<T>` deserialization path used
//! by `ProtocolRepository::deserialize`. Every value persisted by
//! `ProtocolRepository` is wrapped in a `StoredValue` envelope; corrupt or
//! adversarial bytes at this boundary could cause a panic or unsound upgrade
//! path.
//!
//! # Strategy
//!
//! Raw bytes + dictionary (`msgpack_stored_value.dict`). Uses `rmpv::Value`
//! as the inner `T` because the outer envelope deserialization (version check
//! + data extraction) runs before the inner type is decoded — so exercising
//! the envelope layer does not require a specific inner type.
//!
//! Two code paths are exercised:
//! 1. `rmp_serde::from_slice::<StoredValue<rmpv::Value>>` — mirrors the exact
//!    call in `ProtocolRepository::deserialize`.
//! 2. Version gate: if the deserialized version exceeds `CURRENT_STORE_VERSION`,
//!    `ProtocolRepository::deserialize` returns `IncompatibleVersion`. The fuzz
//!    target replicates this check to exercise the boundary without needing
//!    the async `ProtocolRepository` wrapper.
//!
//! # Security invariants
//! - I1: Must never panic on any byte sequence.
//! - I2: Deserialization is bounded — no unbounded allocation from the version
//!   field (u16) or the `rmpv::Value` inner deserializer.
//!
//! # max_len
//!
//! 1 MiB — matches the outer envelope tier because `StoredValue` wraps
//! arbitrary domain values (which can themselves be large MessagePack blobs).

use libfuzzer_sys::fuzz_target;
use rmpv::Value;
use scp_runtime::store::{CURRENT_STORE_VERSION, StoredValue};

fuzz_target!(|data: &[u8]| {
    // Path 1: deserialize as StoredValue<Value> — exercises the version
    // envelope and the inner data field without requiring a concrete T.
    let result = rmp_serde::from_slice::<StoredValue<Value>>(data);

    if let Ok(ref sv) = result {
        // Path 2: replicate the version gate from ProtocolRepository::deserialize.
        // If the stored version is ahead of current, that is an incompatible
        // version — the runtime would return Err, not panic.
        let _too_new = sv.version > CURRENT_STORE_VERSION;
    }

    // Path 3: also try deserializing as StoredValue<Vec<u8>> — exercises the
    // case where the inner data is raw binary (common for nested msgpack blobs).
    let _ = rmp_serde::from_slice::<StoredValue<Vec<u8>>>(data);

    // Path 4: try deserializing as StoredValue<String> — exercises the error
    // path when the inner type does not match the stored bytes.
    let _ = rmp_serde::from_slice::<StoredValue<String>>(data);

    // I1: none of the above may panic.
    let _ = result;
});
