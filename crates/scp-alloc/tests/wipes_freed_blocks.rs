//! `WipingAllocator` overwrites every block with zeros before the inner
//! allocator frees it: a dropped `Vec`, the old block a growing `push` frees,
//! the old block `shrink_to_fit` frees, a block whose start is not
//! word-aligned (head bytes, whole words, and tail bytes), a misaligned block
//! shorter than the distance to its first word boundary, and a block whose
//! size is an exact multiple of the word size.
//!
//! A test cannot read a block after it is freed without a use-after-free, so
//! this binary installs `WipingAllocator<Watching>` as its global allocator.
//! `Watching::dealloc` runs after the wipe and before `System` frees the block,
//! and inspects one watched block at that moment.
//!
//! This binary compiles `src/wiping.rs` itself through `#[path]` and never
//! names the `scp_alloc` library, so rustc does not load that library and its
//! `#[global_allocator]` static does not collide with the one below. The code
//! under test is the same source file every shipped artifact compiles.
//!
//! What this test cannot catch: a compiler deleting the zero stores as dead
//! stores before the free. The inspection reads the block, which makes the
//! stores live in this binary. The stores' volatile semantics, not this test,
//! rule that out in shipped builds.

#[path = "../src/wiping.rs"]
mod wiping;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use wiping::WipingAllocator;

/// Address of the block `Watching::dealloc` inspects; 0 watches nothing.
static WATCHED: AtomicUsize = AtomicUsize::new(0);
/// 0: the watched block is not freed yet; 1: freed holding only zeros;
/// 2: freed holding a nonzero byte.
static VERDICT: AtomicU8 = AtomicU8::new(0);
thread_local! {
    /// When set, this thread's next `Watching::alloc` of an alignment-1 layout
    /// returns a pointer one byte past a word boundary, so the wipe must take
    /// its head path. Thread-local, so no other thread's allocation takes it.
    static MISALIGN_NEXT: Cell<bool> = const { Cell::new(false) };
}
/// Address `Watching::alloc` handed out misaligned; `dealloc` steps back one
/// byte for it before freeing the underlying block.
static MISALIGNED: AtomicUsize = AtomicUsize::new(0);
/// The watch slots are process-wide, so the tests take turns.
static SERIAL: Mutex<()> = Mutex::new(());

struct Watching;

impl Watching {
    /// The layout `System` sees for a block handed out misaligned: one extra
    /// byte in front, aligned for `usize`.
    fn padded(layout: Layout) -> Option<Layout> {
        Layout::from_size_align(layout.size() + 1, align_of::<usize>()).ok()
    }
}

// SAFETY: `alloc` and `dealloc` forward to `System`. A misaligned block is a
// `System` block of `size + 1` bytes with the caller's pointer one byte in, and
// `dealloc` frees it with the same padded layout. `dealloc` only reads the
// block before freeing it.
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() == 1 && MISALIGN_NEXT.with(|flag| flag.replace(false)) {
            let Some(padded) = Self::padded(layout) else {
                return std::ptr::null_mut();
            };
            // SAFETY: `padded` has nonzero size.
            let base = unsafe { System.alloc(padded) };
            if base.is_null() {
                return base;
            }
            // SAFETY: `base` heads a block of `size + 1` bytes.
            let ptr = unsafe { base.add(1) };
            MISALIGNED.store(ptr as usize, Ordering::SeqCst);
            return ptr;
        }
        // SAFETY: forwarded unchanged; the caller upholds `alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let address = ptr as usize;
        if address != 0 && address == WATCHED.load(Ordering::SeqCst) {
            let mut all_zero = true;
            for offset in 0..layout.size() {
                // SAFETY: `ptr` names a live block of `layout.size()` bytes,
                // every one of which the test or the wipe wrote, until the
                // free below.
                if unsafe { ptr.add(offset).read_volatile() } != 0 {
                    all_zero = false;
                }
            }
            VERDICT.store(if all_zero { 1 } else { 2 }, Ordering::SeqCst);
            WATCHED.store(0, Ordering::SeqCst);
        }
        if address != 0 && address == MISALIGNED.load(Ordering::SeqCst) {
            MISALIGNED.store(0, Ordering::SeqCst);
            if let Some(padded) = Self::padded(layout) {
                // SAFETY: `alloc` returned `ptr` one byte into a `System` block
                // of layout `padded`.
                unsafe { System.dealloc(ptr.sub(1), padded) };
            }
            return;
        }
        // SAFETY: forwarded unchanged; the caller upholds `dealloc`'s contract.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WipingAllocator<Watching> = WipingAllocator::new(Watching);

const FILL: u8 = 0xAB;

/// Watches `address`, runs `free`, and asserts the block was freed holding only
/// zeros.
fn assert_freed_wiped(case: &str, address: usize, free: impl FnOnce()) {
    VERDICT.store(0, Ordering::SeqCst);
    WATCHED.store(address, Ordering::SeqCst);
    free();
    let verdict = VERDICT.load(Ordering::SeqCst);
    WATCHED.store(0, Ordering::SeqCst);
    assert_eq!(
        verdict, 1,
        "{case}: the freed block must hold only zeros when the inner allocator frees it \
         (2 = a nonzero byte survived, 0 = the block was never freed)"
    );
}

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn dropped_vec_is_wiped() {
    let _turn = serial();
    let secret = vec![FILL; 64];
    assert_eq!(secret.capacity(), 64);
    let address = secret.as_ptr() as usize;
    assert_freed_wiped("dropped Vec", address, move || drop(secret));
}

#[test]
fn push_growth_wipes_the_old_block() {
    let _turn = serial();
    let mut secret: Vec<u8> = Vec::with_capacity(8);
    secret.extend_from_slice(&[FILL; 8]);
    assert_eq!(secret.capacity(), 8);
    let old = secret.as_ptr() as usize;
    assert_freed_wiped("push growth", old, || secret.push(FILL));
    assert_ne!(secret.as_ptr() as usize, old, "growth must move the block");
    assert_eq!(secret, vec![FILL; 9], "the copy must precede the wipe");
}

#[test]
fn shrink_to_fit_wipes_the_old_block() {
    let _turn = serial();
    let mut secret: Vec<u8> = Vec::with_capacity(64);
    secret.extend_from_slice(&[FILL; 64]);
    secret.truncate(10);
    let old = secret.as_ptr() as usize;
    assert_freed_wiped("shrink_to_fit", old, || secret.shrink_to_fit());
    assert_eq!(secret.capacity(), 10);
    assert_eq!(secret, vec![FILL; 10], "the copy must precede the wipe");
}

#[test]
fn misaligned_odd_size_block_is_wiped_head_words_and_tail() {
    let _turn = serial();
    // 29 bytes starting one byte past a word boundary: on a 64-bit target the
    // wipe writes 7 head bytes, 2 words, and 6 tail bytes; on a 32-bit target
    // 3 head bytes, 6 words, and 2 tail bytes.
    let layout = Layout::from_size_align(29, 1).unwrap_or_else(|_| Layout::new::<u8>());
    assert_eq!(layout.size(), 29);
    MISALIGN_NEXT.with(|flag| flag.set(true));
    // SAFETY: `layout` has nonzero size.
    let ptr = unsafe { std::alloc::alloc(layout) };
    assert!(!ptr.is_null());
    assert_eq!(MISALIGNED.load(Ordering::SeqCst), ptr as usize);
    assert_ne!(
        ptr.align_offset(align_of::<usize>()),
        0,
        "the block must start misaligned"
    );
    // SAFETY: `ptr` heads a live block of `layout.size()` bytes.
    unsafe { ptr.write_bytes(FILL, layout.size()) };
    // SAFETY: `ptr` came from `alloc` with `layout` and is freed once.
    assert_freed_wiped("misaligned odd size", ptr as usize, || unsafe {
        std::alloc::dealloc(ptr, layout);
    });
}

#[test]
fn misaligned_block_shorter_than_its_head_is_wiped() {
    let _turn = serial();
    // 3 bytes starting one byte past a word boundary: on a 64-bit target the
    // distance to the next boundary (7) exceeds the block, so the wipe must
    // clamp its head to the 3 bytes the block holds and write no word.
    let layout = Layout::from_size_align(3, 1).unwrap_or_else(|_| Layout::new::<u8>());
    assert_eq!(layout.size(), 3);
    MISALIGN_NEXT.with(|flag| flag.set(true));
    // SAFETY: `layout` has nonzero size.
    let ptr = unsafe { std::alloc::alloc(layout) };
    assert!(!ptr.is_null());
    assert_eq!(MISALIGNED.load(Ordering::SeqCst), ptr as usize);
    assert_eq!(
        ptr.align_offset(align_of::<usize>()),
        align_of::<usize>() - 1,
        "the block must start one byte past a word boundary"
    );
    // SAFETY: `ptr` heads a live block of `layout.size()` bytes.
    unsafe { ptr.write_bytes(FILL, layout.size()) };
    // SAFETY: `ptr` came from `alloc` with `layout` and is freed once.
    assert_freed_wiped(
        "misaligned, shorter than its head",
        ptr as usize,
        || unsafe {
            std::alloc::dealloc(ptr, layout);
        },
    );
}

#[test]
fn word_multiple_block_is_wiped() {
    let _turn = serial();
    let words = 4;
    let layout = Layout::array::<usize>(words).unwrap_or_else(|_| Layout::new::<usize>());
    assert_eq!(layout.size(), words * size_of::<usize>());
    // SAFETY: `layout` has nonzero size.
    let ptr = unsafe { std::alloc::alloc(layout) };
    assert!(!ptr.is_null());
    assert_eq!(ptr.align_offset(align_of::<usize>()), 0);
    // SAFETY: `ptr` heads a live block of `layout.size()` bytes.
    unsafe { ptr.write_bytes(FILL, layout.size()) };
    // SAFETY: `ptr` came from `alloc` with `layout` and is freed once.
    assert_freed_wiped("word multiple", ptr as usize, || unsafe {
        std::alloc::dealloc(ptr, layout);
    });
}

/// An inner allocator that hands out every block filled with `FILL`, as a
/// reused block that held a secret would arrive, and keeps the trait's default
/// `alloc_zeroed`, which zeroes what its own `alloc` returns.
struct Dirty;

// SAFETY: `alloc` and `dealloc` forward to `System`; `alloc` then writes only
// inside the block `System` returned.
unsafe impl GlobalAlloc for Dirty {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `alloc`'s contract.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            // SAFETY: `ptr` heads a live block of `layout.size()` bytes.
            unsafe { ptr.write_bytes(FILL, layout.size()) };
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged; the caller upholds `dealloc`'s contract.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Copies the `len` bytes at `ptr`.
///
/// # Safety
///
/// `ptr` must head a live block of at least `len` initialized bytes.
unsafe fn bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

#[test]
fn alloc_zeroed_returns_zeros_when_the_inner_alloc_is_dirty() {
    let allocator = WipingAllocator::new(Dirty);
    let layout = Layout::from_size_align(64, 8).unwrap_or_else(|_| Layout::new::<u64>());
    assert_eq!(layout.size(), 64);

    // Control: a plain `alloc` through the wrapper returns the dirty bytes, so
    // the zeros below come from `alloc_zeroed`, not from a clean inner block.
    // SAFETY: `layout` has nonzero size.
    let dirty = unsafe { allocator.alloc(layout) };
    assert!(!dirty.is_null());
    // SAFETY: `Dirty::alloc` initialized all `layout.size()` bytes.
    assert_eq!(unsafe { bytes(dirty, layout.size()) }, vec![FILL; 64]);
    // SAFETY: `dirty` came from `allocator.alloc` with `layout`.
    unsafe { allocator.dealloc(dirty, layout) };

    // SAFETY: `layout` has nonzero size.
    let zeroed = unsafe { allocator.alloc_zeroed(layout) };
    assert!(!zeroed.is_null());
    // SAFETY: `alloc_zeroed` initialized all `layout.size()` bytes.
    let got = unsafe { bytes(zeroed, layout.size()) };
    // SAFETY: `zeroed` came from `allocator.alloc_zeroed` with `layout`.
    unsafe { allocator.dealloc(zeroed, layout) };
    assert_eq!(got, vec![0u8; 64], "alloc_zeroed must return only zeros");
}
