# An Identifier Interpolated Into a Storage Key Can Escape Its Namespace

`DID` (`crates/scp-did/src/lib.rs`) implements `From<&str>` and `From<String>` with no
character validation. Storage keys use `/` as the hierarchy separator (spec §17.3), and code
builds keys such as `format!("identity/{did}/state")` (`crates/scp-ffi/src/identity.rs`), so an
identifier string containing `/` or `../` addresses keys outside its namespace on any backend that
treats keys hierarchically.

Validate at the type, not at each use site. The identifier's text form is `scp:` followed by
lowercase unpadded base32 (`03-identity.md` §3.1) and never contains `/`, so a checked
constructor that accepts only that form closes the class for every key builder at once. Adapter ids already get this treatment: `validate_adapter()`
restricts them to `[a-zA-Z0-9_-]`.
