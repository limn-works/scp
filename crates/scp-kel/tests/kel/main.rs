//! scp-kel integration tests: spec 25 known-answer tests and the decoder's
//! rejection rules (`09-security-model.md` §9.7.4.2). One test binary, so the
//! shared fixtures compile once.

mod decode;
mod fixtures;
mod round_trip;
mod vectors;
