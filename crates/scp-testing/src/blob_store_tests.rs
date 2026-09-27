//! Conformance tests for `InMemoryBlobStorage`.
//!
//! Applies the [`blob_store_conformance`](crate::blob_store_conformance) macro to the in-memory blob storage
//! implementation to verify it satisfies the spec (section 17.11, 17.13).

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use scp_transport::native::storage::{ClockFn, InMemoryBlobStorage};

    fn make_in_memory_blob_storage() -> (InMemoryBlobStorage, Arc<AtomicU64>) {
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let clock_fn: ClockFn = {
            let c = clock.clone();
            Arc::new(move || c.load(Ordering::Relaxed))
        };
        let store = InMemoryBlobStorage::with_clock(clock_fn);
        (store, clock)
    }

    // Run all 11 blob store conformance tests against InMemoryBlobStorage.
    crate::blob_store_conformance!(make_in_memory_blob_storage());
}
