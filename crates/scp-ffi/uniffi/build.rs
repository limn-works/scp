//! Build script for `scp-ffi-uniffi`.
//!
//! Generates UniFFI scaffolding from the supplementary UDL file (`src/scp.udl`).
//! The UDL defines the namespace anchor; all type exports are proc-macro-driven
//! in `bridge.rs` and `lib.rs`.
//!
//! See ADR-021 in `.docs/adrs/phase-4.md`.

fn main() {
    uniffi::generate_scaffolding("src/scp.udl")
        .unwrap_or_else(|e| {
            eprintln!("cargo:error=UDL scaffolding generation failed: {e}");
            std::process::exit(1);
        });
}
