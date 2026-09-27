# A DID Interpolated Into a Storage Key Can Escape Its Namespace

`DID` (`crates/scp-did/src/lib.rs`) implements `From<&str>` and `From<String>` with no
character validation. Storage keys use `/` as the hierarchy separator (spec §17.3), and code
builds keys such as `format!("identity/{did}/state")` (`crates/scp-ffi/src/identity.rs`), so a
DID string containing `/` or `../` addresses keys outside its namespace on any backend that
treats keys hierarchically.

Validate at the type, not at each use site. W3C DID Core syntax
(`did:method-name:method-specific-id`) permits `[a-zA-Z0-9._%-]` and `:` in the
method-specific id and never `/`, so a checked constructor that rejects `/` closes the class
for every key builder at once. Adapter ids already get this treatment: `validate_adapter()`
restricts them to `[a-zA-Z0-9_-]`.
