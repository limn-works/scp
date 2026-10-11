# Platform bridge connectors (archived)

> **ARCHIVED — NOT LIVE PROTOCOL.** Alec cut the platform bridge connector feature on 2026-09-26 ("let's cut."). On 2026-10-09 he ruled that its specs and planning move here instead of being deleted: "delete all the code, keep all the planning and specs -- archive them/backlog them though. don't let any futurecomers get confused by them. note exactly their entire history and state. this way we can revisit specs and work easily if/when we want to and even restore code selectively, without rehashing product and tech design principles." Nothing in this folder binds current code, specs or stories.

## What the feature was

A bridge connector let participants on an external platform, such as X or Discord, take part in an SCP context. An operator with an SCP identity ran the bridge, registered it with a context, and created a shadow identity for each external participant. Bridged content carried provenance naming the bridge, the platform and the operator. An external participant who later created an SCP identity could claim the shadow with an identity attestation, which reattributed the shadow's history. Spec 12, Platform Bridge Connectors, specified the protocol; ADR-023, Bridge Connector Protocol, decided its implementation; PRD stories SCP-084 to SCP-088 and SCP-BCH-001 to SCP-BCH-013 implemented it.

## Contents

| Path | What it holds | Moved by |
|---|---|---|
| `HISTORY.md` | One entry per archived artifact: origin, state when archived with code evidence, the cut, and where the code is | S1, extended by S2 and S9 |
| `adrs/ADR-023-bridge-connector-protocol.md` | ADR-023 cut verbatim out of `.docs/adrs/phase-5.md`, after that file's header lines | S1 |
| `prds/bridge-cooperative.json` | The SCP-BCH PRD, byte-identical. JSON cannot carry a banner, so this README marks the file archived. | S1 |
| `passages/from-adrs-prds-sketch.md` | Every line S1 removed or changed in a live ADR, PRD or `.docs/sketch.md` | S1 |
| `specs/12-platform-bridge-connectors.md` | Spec 12 with a banner | S2 |
| `passages/from-specs-guides-whitepaper.md` | Every line S2 removed or changed in a live spec, guide, architecture document or the white paper | S2 |
| `restore/enforcement-rows.md` | The enforcement-file rows that restored code needs back to pass CI | S2 |

"S1", "S2" and "S9" name the slices of the Track BR plan, which split pull request #2483, "chore: cut platform bridge connectors from every layer (Track BR)", into stacked pull requests. S1 archived the ADRs, PRDs and sketch text, S2 archives the specs and the other prose, and S3a to S9 delete the code.

## What stayed live

These constructs share the word "bridge" and are not part of the cut feature:

- The FFI `BridgeInstance` container in each FFI bridge, which holds a language binding's runtime state.
- The relay bridge in `crates/scp-transport/src/relay/bridge.rs`, its `BridgeRegistry`, and the `BRIDGE_REGISTER` frame that `.docs/adrs/phase-2.md` describes.
- The `SCP-BRIDGE-REGISTER-V1` domain separator of that relay frame.
- The `BridgeRevocation*` resolvers and the Supervisor event channel, `Supervisor::subscribe_events`.
- The `AdapterCredentialStore` of the economy layer, and the test-only `InMemoryCredentialStore` in `crates/scp-runtime/src/economy/credentials.rs`.
- Identity-link attestations (Class 1 OAuth self-attestation), which social graph import still uses.

## Question open when archived

Spec 12 carried two models of a bridge that cannot both hold. ADR-023 and spec 12's February text made a bridge a protocol entity that a context registers through governance and revokes separately from its members. A 2026-03-07 commit to spec 12, "docs(specs): address Phase 11 Lane H-F bridge spec gaps (H-27, H-33)", added that the bridge operator "IS an MLS group member admitted through normal context governance", which makes the bridge software that a member runs. Nobody chose between the two models before the cut. A revival has to choose first, because registration, revocation, shadow claiming and the sender-key path all depend on which model holds.

## How to restore

1. Read `HISTORY.md` for the artifact you want back, including its state when archived.
2. Record the decision to revive in the plan of record. The artifact flow runs plans, then specs, then ADRs, then stories, then code, so restore in that order.
3. Restore text with `git mv` for a whole file (delete the banner lines), or by pasting a fenced passage back at the location its heading names.
4. Restore code from the tag `archive/bridge-connectors-pre-cut` with `git show archive/bridge-connectors-pre-cut:<path> > <path>`, one path at a time. `HISTORY.md` lists the paths.
5. Put back the enforcement rows in `restore/enforcement-rows.md` that the restored code needs, so CI checks it.
