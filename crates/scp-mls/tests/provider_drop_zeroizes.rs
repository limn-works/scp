//! `InMemoryMlsProvider`'s `Drop` zeroizes every storage value before the map
//! frees it, through a poisoned storage lock too.
//!
//! A test cannot read a value's buffer after `Drop` frees it without a
//! use-after-free, so this binary installs a global allocator that inspects one
//! watched buffer at the moment it is freed. It lives outside `scp-mls`'s
//! library, which forbids unsafe code.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use openmls_traits::OpenMlsProvider as _;
use scp_mls::InMemoryMlsProvider;

/// Address of the buffer whose bytes `dealloc` inspects; 0 watches nothing.
static WATCHED: AtomicUsize = AtomicUsize::new(0);
/// 0: the watched buffer is not freed yet; 1: freed holding only zeroes;
/// 2: freed holding a nonzero byte.
static VERDICT: AtomicU8 = AtomicU8::new(0);

struct WatchingAllocator;

// SAFETY: every method forwards to `System` with the caller's arguments, so
// `System`'s guarantees carry over; `dealloc` only reads the block first.
unsafe impl GlobalAlloc for WatchingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let watched = WATCHED.load(Ordering::SeqCst);
        if watched != 0 && ptr as usize == watched {
            // SAFETY: `ptr` names a live block of `layout.size()` initialized
            // bytes (the watched `Vec<u8>`'s whole capacity, which the test
            // filled) until `System.dealloc` below frees it.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            let verdict = if bytes.iter().all(|b| *b == 0) { 1 } else { 2 };
            VERDICT.store(verdict, Ordering::SeqCst);
            WATCHED.store(0, Ordering::SeqCst);
        }
        // SAFETY: forwarded unchanged; the caller upholds `dealloc`'s contract.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WatchingAllocator = WatchingAllocator;

/// `Drop` recovers a poisoned storage lock and wipes anyway instead of
/// panicking (a panic inside `drop` during unwinding aborts the process), and
/// the stored value's buffer holds only zeroes when the map frees it.
#[test]
#[allow(clippy::panic, clippy::unwrap_used)]
fn drop_wipes_through_a_poisoned_storage_lock() {
    let provider = InMemoryMlsProvider::default();
    let secret = vec![0xAB_u8; 64];
    assert_eq!(secret.capacity(), 64);
    let buffer = secret.as_ptr() as usize;
    provider
        .storage()
        .values()
        .write()
        .unwrap()
        .insert(b"EpochSecrets-a".to_vec(), secret);
    std::thread::scope(|s| {
        let poisoner = s.spawn(|| {
            let _guard = provider.storage().values().write().unwrap();
            panic!("poison the storage lock");
        });
        assert!(poisoner.join().is_err());
    });
    assert!(provider.storage().values().is_poisoned());

    WATCHED.store(buffer, Ordering::SeqCst);
    drop(provider);

    assert_eq!(
        VERDICT.load(Ordering::SeqCst),
        1,
        "the stored value's buffer must be freed holding only zeroes (2 = nonzero bytes, 0 = never freed)"
    );
}
