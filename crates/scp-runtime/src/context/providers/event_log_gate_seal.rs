// The write-gate seal types, included by the private `gate` module in
// `event_log.rs` (spec 17 §17.3 "Event log write failures"). The file has no
// `use` and no reference to its includer, so the `compile_fail` doctest on
// `FenceChecked` includes the same text and tests the real seal, not a copy.

/// Names a writer that takes a context's write gate through
/// `lock_write_gate_unfenced`. The drain, a restore, and a destroy skip the
/// pending-unit fence; every other writer goes through `lock_write_gate`, the
/// one place that builds [`UnfencedWrite::FencedGate`].
#[derive(Debug, Clone, Copy)]
pub(super) enum UnfencedWrite {
    /// The pending-unit drain, which is the one writer the fence admits.
    Drain,
    /// A restore that replaces the context's log from storage whole.
    Restore,
    /// A destroy that removes the context's log.
    Destroy,
    /// `lock_write_gate`, which runs the fence check once it holds the gate.
    FencedGate(FenceChecked),
}

/// Proof that the writer goes through `lock_write_gate` and its fence check.
/// The field is private to the `gate` module, so no code outside it can build
/// [`UnfencedWrite::FencedGate`] and skip the fence.
///
/// ```compile_fail,E0603
/// mod gate {
///     include!(concat!(
///         env!("CARGO_MANIFEST_DIR"),
///         "/src/context/providers/event_log_gate_seal.rs"
///     ));
/// }
///
/// fn main() {
///     // Claiming the fenced path from outside the gate module.
///     let _forged = gate::UnfencedWrite::FencedGate(gate::FenceChecked(()));
/// }
/// ```
///
/// The control: the same include compiles, outside code builds an unfenced
/// writer, and code inside the module builds the fenced one.
///
/// ```
/// mod gate {
///     include!(concat!(
///         env!("CARGO_MANIFEST_DIR"),
///         "/src/context/providers/event_log_gate_seal.rs"
///     ));
///
///     pub(super) fn fenced() -> UnfencedWrite {
///         UnfencedWrite::FencedGate(FenceChecked(()))
///     }
/// }
///
/// fn main() {
///     let _drain = gate::UnfencedWrite::Drain;
///     let _fenced = gate::fenced();
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub(super) struct FenceChecked(());
