//! `InMemoryMlsStorage`'s `Drop` zeroizes every stored value before the map
//! frees it, through a poisoned storage lock too, whether the storage is
//! dropped bare or as the field of an `InMemoryMlsProvider`.
//!
//! A test cannot read a value's buffer after `Drop` frees it without a
//! use-after-free, so this binary installs a global allocator that inspects one
//! watched buffer at the moment it is freed. It lives outside `scp-mls`'s
//! library, which forbids unsafe code.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError, RwLock};

use openmls_traits::OpenMlsProvider as _;
use scp_mls::{InMemoryMlsProvider, InMemoryMlsStorage};

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

/// Serializes the tests: `WATCHED` and `VERDICT` hold one watched buffer at a
/// time, and the test harness runs tests on parallel threads.
static WATCH_SLOT: Mutex<()> = Mutex::new(());

type Values = RwLock<HashMap<Vec<u8>, Vec<u8>>>;

/// Inserts a 64-byte `0xAB` value into the storage map that `values` reads
/// out of `owner`, poisons that map's lock, drops `owner`, and returns the
/// verdict `dealloc` recorded for the value's buffer.
#[allow(clippy::panic, clippy::unwrap_used)]
fn verdict_after_drop<T: Sync>(owner: T, values: fn(&T) -> &Values) -> u8 {
    let _slot = WATCH_SLOT.lock().unwrap_or_else(PoisonError::into_inner);
    let secret = vec![0xAB_u8; 64];
    assert_eq!(secret.capacity(), 64);
    let buffer = secret.as_ptr() as usize;
    values(&owner)
        .write()
        .unwrap()
        .insert(b"EpochSecrets-a".to_vec(), secret);
    std::thread::scope(|s| {
        let poisoner = s.spawn(|| {
            let _guard = values(&owner).write().unwrap();
            panic!("poison the storage lock");
        });
        assert!(poisoner.join().is_err());
    });
    assert!(values(&owner).is_poisoned());

    VERDICT.store(0, Ordering::SeqCst);
    WATCHED.store(buffer, Ordering::SeqCst);
    drop(owner);
    WATCHED.store(0, Ordering::SeqCst);
    VERDICT.load(Ordering::SeqCst)
}

/// `Drop` recovers a poisoned storage lock and wipes anyway instead of
/// panicking (a panic inside `drop` during unwinding aborts the process), and
/// the stored value's buffer holds only zeroes when the map frees it. The
/// provider has no `Drop` of its own: dropping its storage field wipes.
#[test]
fn drop_wipes_through_a_poisoned_storage_lock() {
    let verdict = verdict_after_drop(InMemoryMlsProvider::default(), |p| p.storage().values());
    assert_eq!(
        verdict, 1,
        "the stored value's buffer must be freed holding only zeroes (2 = nonzero bytes, 0 = never freed)"
    );
}

/// A bare `InMemoryMlsStorage`, owned by no provider, wipes its stored values
/// when it drops, through a poisoned lock too.
#[test]
fn bare_storage_drop_wipes_through_a_poisoned_lock() {
    let verdict = verdict_after_drop(InMemoryMlsStorage::default(), InMemoryMlsStorage::values);
    assert_eq!(
        verdict, 1,
        "the bare storage's value buffer must be freed holding only zeroes (2 = nonzero bytes, 0 = never freed)"
    );
}
