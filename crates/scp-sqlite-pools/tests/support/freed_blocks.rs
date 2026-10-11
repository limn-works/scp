//! A recording `xFree` installed under `SQLite` before it initializes, shared
//! by the test binaries that check what `SQLite` frees (spec §17.6, `SQLCipher`
//! configuration). `scp-platform` and `scp-transport` include this file by
//! path.
//!
//! The recorder forwards every call to `SQLite`'s default allocator and counts
//! each freed block of at least a minimum size that still holds a needle.
//! `SQLCipher` wraps the installed allocator when it initializes, so the
//! recorder sees each block after `SQLCipher`'s memory security has wiped it,
//! or unwiped when memory security is off. Each including test binary installs
//! the recorder once, before anything initializes `SQLite`, and runs one test.

use std::ffi::{c_int, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::ffi;

type FreeFn = unsafe extern "C" fn(*mut c_void);
type SizeFn = unsafe extern "C" fn(*mut c_void) -> c_int;

struct Recorder {
    free: FreeFn,
    size: SizeFn,
    needle: Vec<u8>,
    min_block: c_int,
}

static RECORDER: OnceLock<Recorder> = OnceLock::new();
static MATCHING_FREES: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn recording_free(p: *mut c_void) {
    let recorder = RECORDER.get().expect("recorder installed");
    if !p.is_null() {
        // SAFETY: `p` is a live block from `SQLite`'s default allocator, which
        // reports its usable size, and the block stays live until `free`.
        let size = unsafe { (recorder.size)(p) };
        if size >= recorder.min_block {
            // SAFETY: `p` points at `size` readable bytes, as above.
            let block = unsafe {
                std::slice::from_raw_parts(p.cast::<u8>(), usize::try_from(size).unwrap())
            };
            if block
                .windows(recorder.needle.len())
                .any(|w| w == recorder.needle.as_slice())
            {
                MATCHING_FREES.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    // SAFETY: forwards the free of a block `SQLite`'s default allocator made.
    unsafe { (recorder.free)(p) }
}

/// Installs the recorder, counting freed blocks of at least `min_block` bytes
/// that contain `needle`. Must run before `SQLite` initializes.
pub fn install(needle: Vec<u8>, min_block: c_int) {
    assert!(!needle.is_empty(), "the needle must not be empty");
    // SAFETY: `sqlite3_mem_methods` is a plain C struct of nullable function
    // pointers and a data pointer, for which all-zero bytes are valid.
    let mut methods: ffi::sqlite3_mem_methods = unsafe { std::mem::zeroed() };
    // SAFETY: `SQLITE_CONFIG_GETMALLOC` takes one `sqlite3_mem_methods*` and
    // writes the current methods into it; nothing else runs `SQLite` yet.
    let code = unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_GETMALLOC, &raw mut methods) };
    assert_eq!(code, ffi::SQLITE_OK, "SQLite must not be initialized yet");
    let recorder = Recorder {
        free: methods.xFree.expect("default xFree"),
        size: methods.xSize.expect("default xSize"),
        needle,
        min_block,
    };
    assert!(RECORDER.set(recorder).is_ok(), "recorder installed once");
    methods.xFree = Some(recording_free);
    // SAFETY: `SQLITE_CONFIG_MALLOC` takes one `sqlite3_mem_methods*` and
    // copies the struct; every method forwards to the default allocator.
    let code = unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_MALLOC, &raw const methods) };
    assert_eq!(code, ffi::SQLITE_OK, "SQLite must not be initialized yet");
}

/// Returns how many matching blocks were freed since the last call, and
/// starts the count again at zero.
pub fn take_matching_frees() -> usize {
    MATCHING_FREES.swap(0, Ordering::SeqCst)
}
