//! scp-kel integration tests: spec 25 known-answer tests and the decoder's
//! rejection rules (`09-security-model.md` §9.7.4.2). One test binary, so the
//! shared fixtures compile once.

mod chain_entry;
mod chain_inception;
mod chain_rows;
mod chain_support;
mod chain_valid;
mod client_data;
mod construction;
mod decode;
mod event_codec;
mod fixtures;
mod key_event_signer;
mod relation;
mod replay;
mod round_trip;
mod signature;
mod vectors;
