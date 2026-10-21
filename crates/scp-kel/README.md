# scp-kel

The **key-event log codec** for SCP (Shared Context Protocol): the byte
constructions `09-security-model.md` §9.7.4.2 defines over a key event, each
with exactly one implementation (ADR-063, implementation constraints).

This crate owns:

- `EventPreimage` and its parts (`EventKind`, `StandingRootDeclaration`,
  `SignerGroup`, `SignerGroupRole`, `SignatureForm`, `InstalledRootSet`,
  `KeyStateSnapshot`, `Continuation`) — the twelve-field key-event preimage,
  with one typed constructor per kind that places every sentinel the kind
  carries and derives field 9 from the snapshot.
- `encode_preimage` and `decode_preimage` — the only constructors of
  `EncodedPreimage`, which holds a preimage with its signed bytes
  `"SCP-KEL-EVENT-V1:" ‖ fields`. Its `event_digest` and `identifier` read
  those bytes and cannot fail. Both directions read one count-bound table, so
  encode succeeds exactly where decode of its output succeeds (§9.7.4.2, the
  count-bound rule).
- `derive_identifier` — `SHA-256("SCP-KEL-ID-V1:" ‖ inception signed preimage)`,
  refusing any preimage that is not a zero-position inception.
- `prerotation_commitment` and `key_event_seal` — the pre-rotation commitment
  and the key-event seal.
- `routing_id` — the four routing identifiers an identifier's objects are
  stored under (§9.7.4.2 R13, §9.18.2).
- `IndexedSignature` (`Raw` or `WebAuthnAssertion(AssertionSignature)`),
  `IndexedSignature::read` and `to_bytes` (failing with
  `IndexedSignatureReadError`), and `verify_indexed` (failing with
  `IndexedSignatureError`) — one entry of a signature field, read with every
  declared length checked against its §9.18.17 bound, and verified under the
  form field 7 declares with `scp-crypto`'s strict low-`s` P-256 verifier:
  over `D` for the raw form, and for the assertion form over
  `SHA-256(authenticatorData ‖ SHA-256(clientDataJSON))` after the UP and UV
  flags, the `type`, and the challenge are checked (§9.7.4.2, "Signature
  form").
- `key_event_challenge` — the 49 challenge bytes `"SCP-KEY-EVENT-V1:" ‖ D` a
  signer passes to its authenticator.
- `parse_client_data_json` (hidden; public for the fuzz target) and
  `ClientDataError` — the strict `clientDataJSON` acceptance set, a
  hand-written validator with an explicit stack over an
  `AssertionSignature`'s at most 512 bytes.

The key-state value types (`Identifier`, `KeyEntry`, `CommitmentEntry`,
`StandingCommitment` and the four name-bound enumerations) come from `scp-did`;
P-256 point validation and signature verification come from `scp-crypto`.

The crate is a wasm-safe Layer 1 crate (`.docs/architecture.md`, "Layered
Dependency Graph"): no async runtime, no I/O, no clock, and no pointer-width
integer or float on the wire. It compiles to
`wasm32-unknown-unknown`, and `crates/scp-client-wasm/tests/kel_cross_target_kat.rs`
pins byte identity between native and wasm32 against `25-test-vectors.md`
§25.26, §25.28 and §25.29. `scripts/check-protocol-deps.sh` rejects an async-runtime or
platform edge in its dependency tree.

Chain verification (signatures, R3's defect list, R8) is not here yet; it
lands with the verifier story, which wraps `decode_preimage`.
