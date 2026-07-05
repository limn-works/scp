# ADR-060: Monetary Value Wire Representation

**Status:** Accepted (2026-07-05).

**Relates to:** ADR-033 (economic governance — defines `Amount`/`Coefficient`/`CostSchedule`/`PricingFormula`), ADR-048 §7 (per-SDK idiom over the JSON FFI), ADR-055/058/059 (typed SDK surfaces — structured value types projected to/from the canonical serde wire shapes), spec §19 (economic governance) and §19.15.1 (wire format tables). Supersedes the "JSON Amount serialization" paragraph in spec §19.8.

## Context

SCP is a crypto-settling, reimplementable interchange protocol: the same economic values (`Amount`, `Coefficient`) cross the wire between independent implementations in Rust, TypeScript, Python, Swift, and Kotlin, and settle against real payment rails (x402/USDC, SPL, Lightning). The canonical serde shapes in `scp-protocol` are the single source of truth (ADR-055/058/059); every SDK and bridge round-trips against them.

The economy types were originally specified to serialize monetary values as **JSON numbers** (`Amount` → unsigned integer, `Coefficient` → signed integer; spec §19.15.1, §19.8). That choice is out of step with how a crypto-settling, multi-language protocol represents money, for reasons that are structural, not a latent bug:

- **Crypto-rail interchange norm.** The rails SCP settles against represent on-wire amounts as **decimal strings over big-integer smallest-units**, precisely to avoid float/precision hazards at language boundaries: USDC and SPL token amounts are base-units-as-strings, and Lightning/BOLT11 carries millisatoshi integers as strings. A protocol that interchanges with these rails should speak the same representation at its own boundary rather than inventing a number-typed dialect that every adapter must reconcile.

- **Reimplementation-safety across language number models.** A JSON *number* is not safely round-trippable as a 64-bit integer in every target. JavaScript `JSON.parse` deserializes numbers into IEEE-754 doubles — integers above 2⁵³ silently lose precision, and there is no hook to intercept the parse. The napi bridge already narrows JS numbers through `i64` at the boundary. A wire form that a first-class SDK target cannot faithfully parse is a defect in the wire form, not in the SDK.

- **Wire/core decoupling (no-DOA).** Encoding money as a number couples the wire representation to the Rust core's integer width. If the core ever widens `u64` → `u128` (or `i64` → `i128`), a number-typed wire has to widen with it — a breaking change on every encoding, including MessagePack. A **string** wire form is width-agnostic: the core can widen later with zero wire impact. Per the no-DOA and no-boundary-hugging tenets, we choose the representation that does not have to be replaced later.

This is a deliberate adoption of the standard enterprise money-representation discipline (integer smallest-units, string on the wire, never floats), aligned to a crypto-settling protocol — **not** a fix for a specific reachable collision. In particular, this decision is **not** justified by any ">2⁵³ JCS hash collision": SCP's currencies and scales keep real amounts far below that bound, so that scenario is unreachable and is not the rationale. The rationale is interchange norms, reimplementation-safety, and wire/core decoupling.

## Decision

**Monetary values serialize on the wire as a canonical base-10 decimal string of their smallest-unit integer.**

- **Wire form.** `Amount(u64)` and `Coefficient(i64)` serialize (in **both** JSON and MessagePack, everywhere they appear in a wire-crossing structure) as a canonical decimal string: plain ASCII digits, no `+`, no leading zeros (except the lone `"0"`), a single optional leading `-` for `Coefficient` only, no separators/underscores, no whitespace, no decimal point, no exponent, no hex. Examples: `Amount(1000000)` → `"1000000"`, `Amount(0)` → `"0"`, `Coefficient(-500000)` → `"-500000"`. The string encodes the **smallest-unit integer**, not a human decimal — `"1.50"` is invalid; the scale stays with `currency` / `COEFFICIENT_SCALE`.

- **Strict, injective decode.** Deserialization accepts ONLY that canonical form and rejects empty, leading zeros, `+`, `-0`, whitespace, separators, non-digit, decimal point, exponent, hex, a bare JSON number, and (for `Amount`) any leading `-`. Encode∘decode is the identity and re-encode is byte-identical, so the representation is reproducible across independent reimplementations.

- **Core width unchanged.** The Rust core keeps `Amount(u64)` / `Coefficient(i64)`. Arithmetic (checked/saturating add/sub/mul, coefficient evaluation) is unchanged. The string form is purely a serde boundary concern; the wire is now decoupled from the core width, so a later `u64` → `u128` widening is a non-breaking wire change.

- **Uniform across encodings.** The decoupling rationale requires the string form in *every* wire encoding, not just JSON — if MessagePack stayed `uint 64`, widening the core would break the binary path. So the single serde impl on the newtype emits/accepts the decimal string for JSON and MessagePack alike.

- **SDK surface: per-language idiom, converting at the FFI boundary (ADR-048 §7).** Each SDK exposes money in its natural integer type — TypeScript `bigint`, Python `int`, Swift `UInt64`, Kotlin `ULong` — and converts to/from the canonical decimal string at the FFI boundary, mirroring the typed-value-type convention of ADR-055/058/059. Each SDK additionally provides a `format(currency)` **display** helper that renders the human decimal (applying the currency's scale) for UIs — display is an SDK concern, never the wire form.

- **Enforcement: closed by construction, no gate.** Enforcement is entirely structural: the custom `Serialize`/`Deserialize` live ON the `Amount` and `Coefficient` newtypes, and every monetary field is typed `Amount`/`Coefficient` — including `ToolCost.amount`, which is retyped from `u64` to `Amount`. There is therefore no way to express a monetary field that serializes as a number. No source-scanning or AST gate is added (that would be a redundant, non-convergent denylist re-checking a property the type system already enforces soundly — see the over-engineering tenet).

The TOOL-REGISTRATION canonical preimage (`compute_tool_registration_canonical_bytes`) continues to hash `ToolCost.amount` as its raw `u64` big-endian bytes (via `amount.0.to_be_bytes()`), NOT the wire string, so that signature preimage — and its KAT — is byte-identical to the pre-ADR-060 preimage.

## Alternatives Considered

- **Status quo: JSON integer (rejected).** The originally-specified number form. Rejected: not round-trippable through JS `JSON.parse` (>2⁵³ precision loss; napi narrows through `i64`), out of step with crypto-rail decimal-string+bignum interchange, and couples the wire to the core width so a later widening breaks every encoding.

- **Widen the core to `u128`/`i128` now (deferred, not rejected).** Widening the core integer would raise the numeric ceiling but does not, by itself, solve JS round-tripping or interchange-representation mismatch, and a number-typed `u128` wire is *worse* for JS. The string wire form makes a future core widening a non-breaking change, so widening is deferred rather than rejected — this decision removes the pressure to decide it now.

- **Arbitrary-precision / bignum type in the core (rejected).** A non-`Copy`, heap-allocating big-integer type is FFI-hostile (no flat value across bindings), complicates the `Copy` arithmetic surface, and is unnecessary — smallest-unit `u64`/`i64` more than covers SCP's currencies. The string wire form already gives width-independence without changing the core type.

- **String only at the wire but string in the SDK surface too (rejected).** Exposing money as strings in the public SDK APIs pushes parsing/formatting onto every caller and contradicts ADR-048 §7's per-language-idiom rule. SDKs use native integers and convert at the boundary.

- **Human-decimal string on the wire, e.g. `"1.50"` (rejected).** A scaled human decimal reintroduces locale/format ambiguity, is not injective (`"1.5"` vs `"1.50"`), forces scale knowledge into the parser, and contradicts ADR-033's smallest-unit-integer model. The wire string encodes the raw smallest-unit integer only.

- **Bespoke source-scanning / AST enforcement gate (rejected).** A check that scans for number-typed money fields would redundantly re-verify, in weaker source-text form, a property the type system already guarantees (serde on the newtype + every field typed `Amount`/`Coefficient`). Per the over-engineering / non-convergent-enforcement tenet, the newtype + `ToolCost` retype IS the enforcement; no gate is added.

## Consequences

- **Wire change, pre-release, no back-compat.** SCP is pre-release with no deployed data. The string form is the ONLY accepted form; there is no dual number-or-string acceptance, no migration, no deprecation window. Any economy KAT / test fixture / JCS preimage vector that serialized a monetary value is regenerated to the string form by running the code.

- **Spec.** Spec §19.1.1 gains an explicit wire-form note; §19.15.1's `Amount`/`Coefficient` rows become canonical decimal string for both JSON and MessagePack; the §19.8 relay-config example uses quoted amounts; and the §19.8 "JSON Amount serialization" paragraph is reversed (it previously declared integers-only and strings-invalid — this ADR supersedes it).

- **Core.** `Amount` and `Coefficient` carry hand-written `Serialize`/`Deserialize` (decimal string out, strict parse in) instead of derived number serde; all other derives, the `.0` field, and all arithmetic are unchanged. `ToolCost.amount` is retyped `u64` → `Amount`.

- **TOOL-REGISTRATION KAT unchanged.** The registration signature preimage still hashes the raw `u64` bytes, so that vector is byte-identical; verified by test.

- **FFI (Phase 2 follow-on).** The bridges consume the canonical serde shapes and compile against the retyped `ToolCost` (their internal construction wraps the native integer in `Amount`); their public **native-integer parameters** for tool cost are unchanged in this phase. Making the FFI/SDK money parameters string-typed end-to-end, adding the per-language `format(currency)` display helpers, and updating the bridge unit-test JSON fixtures that still deserialize bare-number economic policy are Phase 2 work, tracked with the SDK slice — not part of this Rust-core foundation.
