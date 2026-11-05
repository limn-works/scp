//! The must-compile control for the runtime seal's compile-fail cases in this
//! crate's docs (ADR-070 §4). Those cases fail only if the items they name stay
//! private; this test proves the paths they use resolve and that the public
//! items beside them stay reachable from a crate that depends on `scp-core` the
//! way an FFI bridge does. `cargo nextest` runs no doctest, so the control
//! lives here too.

use std::sync::Arc;

use scp_core::context::actor::class_s::ClassSCell;
use scp_core::context::actor::state::PerContextState;
use scp_core::context::outlets::invoke::InvocationError;
use scp_core::context::supervisor::{Supervisor, SupervisorHandle};

/// The signature a bridge would write against the public items.
type Reach = fn(
    &Arc<Supervisor>,
    &PerContextState,
    Option<&ClassSCell>,
    Option<&SupervisorHandle>,
    Option<&InvocationError>,
) -> [u8; 32];

const fn reach(
    _sup: &Arc<Supervisor>,
    state: &PerContextState,
    _cell: Option<&ClassSCell>,
    _handle: Option<&SupervisorHandle>,
    _err: Option<&InvocationError>,
) -> [u8; 32] {
    state.context_id
}

#[test]
fn bridge_reaches_the_public_items_beside_the_sealed_ones() {
    let _: Reach = reach;
    // A bridge builds and reads the public error type the sealed invocation
    // path returns.
    let err = InvocationError::OutletNotFound {
        outlet_id: "weather".to_owned(),
    };
    assert_eq!(err.to_string(), "outlet not found: \"weather\"");
}
