//! The positive control of the `compile_fail` doctest in
//! `scp_ffi_common::custody_namespace`: code outside the crate cannot call
//! `CustodyNamespaces::new`, and reaches a bridge instance's table through
//! `CoreFields::custody_namespaces`, over which a callback custody identity's
//! records open once per instance (spec §17.3). `cargo nextest` runs no doctests,
//! so this test keeps the reachable path checked there too.

#![cfg(all(feature = "custody", feature = "resolvers", feature = "testing"))]

use scp_ffi_common::bridge_instance::CoreFields;
use scp_ffi_common::callback_identity::{CallbackIdentityError, create_records};
use scp_platform::in_memory::InMemoryStorage;

#[test]
fn the_instance_table_opens_callback_custody_records() -> Result<(), CallbackIdentityError> {
    let core = CoreFields::new();
    let first = create_records(core.custody_namespaces(), Some(InMemoryStorage::new()))?;
    let second = create_records(core.custody_namespaces(), Some(InMemoryStorage::new()))?;
    assert_ne!(
        first.namespace(),
        second.namespace(),
        "each create draws its own namespace from the instance table"
    );
    Ok(())
}
