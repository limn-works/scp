# `serde(rename_all = "lowercase")` vs `"snake_case"` — pick what matches the spec

**Source:** `HandleRegisterStatus` wire-format drift

## The bug

`HandleRegisterStatus` was annotated `#[serde(rename_all = "lowercase")]`. For single-word
variants (`Registered`, `Conflict`) this is identical to `snake_case`. The trap surfaces the
moment you add a multi-word variant:

| Variant              | `"lowercase"`           | `"snake_case"` (spec)     |
| -------------------- | ----------------------- | ------------------------- |
| `OwnershipMismatch`  | `"ownershipmismatch"`   | `"ownership_mismatch"`    |
| `CapacityExceeded`   | `"capacityexceeded"`    | `"capacity_exceeded"`     |

Spec §22.3.1 defines the wire-format values as `ownership_mismatch` / `capacity_exceeded`.
The Rust enum silently emitted the no-separator form — tests that round-tripped the value
through serde in a single implementation passed, but any consumer reading the spec literal
would reject it.

## Why it's subtle

1. `"lowercase"` is a common default cargo-culted from examples. It looks harmless.
2. The drift is invisible until someone adds a multi-word variant. The first variant you add
   after that point quietly disagrees with the spec.
3. `#[serde(rename = "ownership_mismatch")]` per-variant is what most devs reach for when they
   notice — but that only fixes the variant they noticed. The container attribute is the real
   bug.

## The rule

**Default to `rename_all = "snake_case"` for any enum whose wire format is defined in a spec**,
unless the spec explicitly calls for a different convention (e.g. `camelCase` for JSON APIs).
Never use `"lowercase"` unless the spec spells every variant as a single concatenated word.

## How to catch this when reviewing

- When adding a multi-word variant to an enum with `#[serde(rename_all = "…")]`, open the spec
  and compare the expected wire value to what serde will produce.
- When reviewing a new enum: grep for `rename_all = "lowercase"` and confirm every variant is
  either single-word or has an explicit per-variant `rename`.
- Prefer round-trip tests that assert the literal JSON string against the spec, not just
  `assert_eq!(x, from_str(to_string(&x)?)?)` — internal round-trips hide spec drift.

## Related

- `crates/scp-protocol/src/discovery/handles.rs::HandleRegisterStatus`
- `.docs/specs/22-human-readable-addressing.md` §22.3.1
- `crates/scp-protocol/src/discovery/scope.rs` — `ScopeRegisterStatus` uses the same pattern
  and needs the same scrutiny whenever a variant is added.
