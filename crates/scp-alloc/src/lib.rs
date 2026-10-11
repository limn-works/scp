#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![deny(unsafe_code)]

mod wiping;

pub use wiping::WipingAllocator;

/// The process's global allocator: every heap block a shipped SCP artifact
/// frees is overwritten with zeros first (§9.15 of the security-model spec,
/// freed heap memory).
///
/// It is process-global because Rust admits exactly one `#[global_allocator]`
/// per linked binary or cdylib, and the guarantee must cover every allocation
/// in the artifact, including those of dependencies SCP does not control. It
/// holds no state: `WipingAllocator<System>` is a zero-sized, immutable
/// wrapper, so the static couples no two SCP instances in one process.
///
/// It lives here rather than in each artifact's root so that one definition
/// serves all six shipped artifacts; each root links it with
/// `use scp_alloc as _;`, which `scripts/check-wiping-allocator.sh` requires.
/// No `cfg` or feature gates it, so no build of a crate that links this one can
/// leave it out.
#[global_allocator]
static WIPING_ALLOCATOR: WipingAllocator = WipingAllocator::new(std::alloc::System);
