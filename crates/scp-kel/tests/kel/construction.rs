//! No path builds a `ValidatedChain` or a `ReplayedState` except validation
//! and replay (`09-security-model.md` §9.7.4.2 R3, R8): neither type has a
//! default, a deserializer, or a conversion from bytes or from a bare key
//! state. The doctests on `ReplayedState` pin the struct literal and `new`
//! and carry the positive control; these pin the trait impls, at compile
//! time.

use scp_did::KeyState;
use scp_kel::{ReplayedState, ValidatedChain};
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(
    ValidatedChain: Default,
    serde::Deserialize<'static>,
    From<Vec<Vec<u8>>>,
    From<Vec<u8>>,
);
assert_not_impl_any!(
    ReplayedState: Default,
    serde::Deserialize<'static>,
    From<KeyState>,
    From<ValidatedChain>,
);
