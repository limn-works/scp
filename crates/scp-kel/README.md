# scp-kel

The **key-event log** for SCP (Shared Context Protocol), as
`09-security-model.md` §9.7.4.2 defines it: the codec for a key event's byte
constructions, the identifier and routing derivations, the validation of an
entry's served events into chains (R3), and the replay of a validated chain
into key state (R8). Each has exactly one implementation (ADR-063,
implementation constraints).

This crate owns:

- `EventPreimage` and its parts (`EventKind`, `StandingRootDeclaration`,
  `SignerGroup`, `SignerGroupRole`, `SignatureForm`, `InstalledRootSet`,
  `KeyStateSnapshot`, `Continuation`) — the twelve-field key-event preimage,
  with one typed constructor per kind that places every sentinel the kind
  carries and derives field 9 from the snapshot.
- `encode_preimage` and `decode_preimage` — the only constructors of
  `EncodedPreimage`, which holds a preimage with its field bytes; the
  signed preimage is `"SCP-KEL-EVENT-V1:" ‖ fields`, with the separator
  implied, so no accessor strips it. Its `event_digest` and
  `inception_identifier` (`None` for every kind but `Inception`) read those
  bytes and cannot fail. Both directions read one count-bound table, pair
  each form list with its index list (`FormListLength` where the lengths
  differ) and read one encoded-length function over the pairs (the signed
  preimage plus each named signer's form ceiling, at most `MAX_EVENT_BYTES`),
  so encode succeeds exactly where decode of its output succeeds (§9.7.4.2,
  the count-bound rule; §9.18.17). Decode errors split by stage:
  `HeaderError` for fields 1 to 7 and step 4's checks, `BodyError` for
  fields 8 to 12.
- `decode_event` — reads one §9.10.12 event unit (`BE32(len)`, the signed
  preimage, the signature field) into an `EventUnit` whose variant is the
  stage of §9.7.4.2's check order that stopped it: `Unframed` (step 1),
  `NoSeparator` (step 2), `HeaderFailed` (step 4, with its `HeaderError`) or
  `Read`. A `ReadUnit` holds the `EventHeader` of fields 1 to 7, whose
  `HeaderGroup`s pair each index with its form (`NamedSigner`), the
  signature-field walk (step 5) as a `SignatureField` of `NamedSignature`s
  with the bytes the unit consumed, or a `SignatureFieldError`, and the
  body decode, kept apart. Fields 1 to 12 are parsed once.
- `RawSignedPreimage` — the received signed preimage of a unit past step 2,
  built only by `decode_event`, which strips the separator once and keeps
  the field bytes: its `identifier` (hashed from the received
  bytes, so it exists even when the body fails to decode), its
  `event_digest`, and `inception_zero_checks`, R3's inception header checks
  read with the header's own reader (`InceptionHeaderDefect`).
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
- `validate_entry` — §9.7.4.2 R3's check order over an entry's served units,
  the one reader of them: it assembles the units by predecessor digest, runs
  every check, and returns an `EntryValidation` whose `EntryVerdict` is
  `Valid` with the `ValidChains`, `InceptionInvalid`, or `NoInception`, and
  every `Discarded` unit with its `EventDefect`, `CheckStep` and
  `FailureClass`. A defect past the inception is a discard, never a verdict
  on the identity. `ValidatedChain` is built only here: `extend` reads one
  more unit, `prefix` cuts it at a position, and `validate_change` checks a
  candidate preimage into a `ValidatedChange`. `HeldHead` and `SigningChange`
  carry the head a signer signs at. `ValidChains::single` returns the chain
  of an unforked entry and `None` for a forked one; choosing among forks is
  R6's fork choice (SCP-310), so no accessor returns one fork of several.
- `replay` and `key_state_at` — the key state the adopted `ValidatedChain`
  derives at its head or at one of its events (R8): that position's latest
  snapshot with the standing commitment there, nothing diffed or merged, as a
  `ReplayedState` carrying the identifier, the position's digest and
  sequence, and the `#active` key and root count R3 resolved for that
  snapshot (`active_key`, `root_members`, `root_count`). `ReplayedState` has no public constructor, so every one comes
  from a validated chain; `key_state_at` fails with `NotOnChain` for a
  digest the chain does not hold.

The key-state value types (`Identifier`, `KeyState`, `KeyEntry`,
`CommitmentEntry`, `StandingCommitment` (`Fixed` or `Abandoned`),
`FixedCommitment` and the four name-bound enumerations) come from `scp-did`;
P-256 point validation and signature verification come from `scp-crypto`.

The crate is a wasm-safe Layer 1 crate (`.docs/architecture.md`, "Layered
Dependency Graph"): no async runtime, no I/O, no clock, and no pointer-width
integer or float on the wire. It compiles to
`wasm32-unknown-unknown`, and `crates/scp-client-wasm/tests/kel_cross_target_kat.rs`
pins byte identity between native and wasm32 against `25-test-vectors.md`
§25.26, §25.28 and §25.29, including the validation of every spec 25 chain
and the bytes of the key state each replays to.
`scripts/check-protocol-deps.sh` rejects an async-runtime or platform edge in
its dependency tree.
