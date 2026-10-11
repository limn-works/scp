//! [`WipingAllocator`] and the wipe routine it runs on every free.
//!
//! This file is the whole implementation. `tests/wipes_freed_blocks.rs`
//! compiles it a second time through `#[path]`, so that test binary can wrap an
//! inspecting allocator without linking this crate's `#[global_allocator]`
//! static, which a binary may have only one of.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{Ordering, compiler_fence};

/// A global allocator that overwrites every block with zeros before freeing it.
///
/// `alloc` and `alloc_zeroed` forward to the inner allocator unchanged.
/// `dealloc` writes zero over each of the block's `layout.size()` bytes with
/// volatile stores, then forwards the free. `realloc` is not overridden: the
/// trait's default allocates the new block, copies `min(old, new)` bytes, and
/// frees the old block through this `dealloc`, so neither a block that moves
/// nor the tail an in-place shrink would leave behind escapes the wipe. The
/// cost is that a growing allocation is never extended in place.
///
/// Volatile stores are never elided, so the compiler cannot treat the wipe as
/// a dead store before the free, on any target. A `compiler_fence` after the
/// stores keeps the compiler from moving them past the inner `dealloc`.
#[derive(Debug, Default, Clone, Copy)]
pub struct WipingAllocator<A = std::alloc::System> {
    inner: A,
}

impl<A> WipingAllocator<A> {
    /// Wraps `inner`, which performs every allocation and free.
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
}

// SAFETY: `alloc`, `alloc_zeroed`, and `dealloc` forward to `inner` with the
// caller's own arguments, so each keeps `inner`'s guarantees. `dealloc` first
// writes zeros into the block the caller is freeing; the caller's contract
// makes that block live, writable, and `layout.size()` bytes long until the
// forwarded `dealloc` returns, so the writes stay inside memory this call owns.
// The trait's default `realloc` is kept, and it calls only these methods.
#[allow(unsafe_code)]
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipingAllocator<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `alloc`'s contract.
        unsafe { self.inner.alloc(layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `alloc_zeroed`'s
        // contract.
        unsafe { self.inner.alloc_zeroed(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees `ptr` was returned by this allocator
        // for `layout`, so `ptr..ptr + layout.size()` is one live block that
        // nothing else accesses during this call.
        unsafe { wipe(ptr, layout.size()) };
        // SAFETY: forwarded unchanged; the caller upholds `dealloc`'s contract.
        unsafe { self.inner.dealloc(ptr, layout) }
    }
}

/// Writes zero over `len` bytes starting at `ptr` with volatile stores: single
/// bytes up to the first word boundary, whole words, then the remaining bytes.
///
/// Every store goes through a raw pointer, and no reference to the block is
/// ever formed, because a freed block's spare capacity may never have been
/// initialized. Volatile stores are never removed as dead stores, so the
/// zeros reach memory although the block is freed right after.
///
/// # Safety
///
/// `ptr..ptr + len` must be one live block the caller may write and that
/// nothing else accesses for the duration of the call.
#[allow(unsafe_code)]
#[inline]
unsafe fn wipe(ptr: *mut u8, len: usize) {
    const WORD: usize = core::mem::size_of::<usize>();
    // Bytes before the first `usize`-aligned address, clamped to the block.
    // `align_offset` may answer `usize::MAX` when it cannot align, which the
    // clamp turns into "wipe every byte singly".
    let head = ptr.align_offset(core::mem::align_of::<usize>()).min(len);
    let words = (len - head) / WORD;
    let tail_start = head + words * WORD;
    for offset in 0..head {
        // SAFETY: `offset < head <= len`, so the byte lies inside the block.
        unsafe { ptr.add(offset).write_volatile(0) };
    }
    // SAFETY: `head <= len`, so `ptr + head` lies inside the block or one past
    // its end.
    if let Some(first_word) = NonNull::new(unsafe { ptr.add(head) }) {
        // `align_offset` made `ptr + head` `usize`-aligned whenever `words > 0`.
        let first_word = first_word.cast::<usize>().as_ptr();
        for index in 0..words {
            // SAFETY: the word at `index < words` spans bytes
            // `head + index * WORD .. head + (index + 1) * WORD <= tail_start
            // <= len` of the block, and its address is `usize`-aligned.
            unsafe { first_word.add(index).write_volatile(0) };
        }
    }
    for offset in tail_start..len {
        // SAFETY: `tail_start <= offset < len`, so the byte lies inside the
        // block.
        unsafe { ptr.add(offset).write_volatile(0) };
    }
    compiler_fence(Ordering::SeqCst);
}
