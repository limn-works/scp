//! Storage conformance tests for `InMemoryStorage`.
//!
//! Validates that the in-memory storage adapter passes all 13 conformance
//! tests defined in `storage_conformance!()` (spec sections 17.11, 17.13).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::in_memory::InMemoryStorage;

scp_testing::storage_conformance!(InMemoryStorage::new());
