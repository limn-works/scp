# Platform bridge connectors: history and state

> **ARCHIVED — NOT LIVE PROTOCOL.** This file records the history and state of each bridge-connector artifact that the Track BR cut moved into this folder. Read `README.md` first for what the feature was and the question left open.

Each entry has four parts:

- **Origin** names when the artifact entered the repository and the pull requests that changed it.
- **State at archiving** gives the artifact's status on main on 2026-10-09 and the code that implemented it, read from main that day.
- **Cut** names the ruling and the slice that moved the artifact.
- **Code** names where the deleted code lives and how to restore it.

All code paths below existed on main when S1 archived these artifacts. The Track BR code slices, S3a to S9, delete them. The orchestrator tags the merge commit of slice S2, the last main commit before any code deletion, as `archive/bridge-connectors-pre-cut`. Restore one file from that tag with:

```text
git show archive/bridge-connectors-pre-cut:<path> > <path>
```

## The rulings that cut the feature

On 2026-09-26 the orchestrator asked Alec, "Should I cut bridges, including those enforcement-file rows?", after stating that a yes would also approve deleting the bridge rows from `sdk-capability-matrix.json`, `pipeline_wiring.rs` and the FFI conformance checks. Alec answered: "let's cut."

On 2026-10-09 Alec ruled how the cut treats documents: "delete all the code, keep all the planning and specs -- archive them/backlog them though. don't let any futurecomers get confused by them. note exactly their entire history and state. this way we can revisit specs and work easily if/when we want to and even restore code selectively, without rehashing product and tech design principles."

Pull request #2483, "chore: cut platform bridge connectors from every layer (Track BR)", deleted the feature from every layer in one 152-file change. It was too large for one review, so the Track BR plan splits it into stacked slices: S1 archives the ADRs, PRDs and sketch text; S2 archives spec 12 and the other prose; S3a to S9 delete the code. Three pull requests that extended bridges closed unmerged after Alec cut the feature: #2373, "fix(node): bridge handlers restrict every read and write to their authenticated scope"; #2463, "docs(spec): a bridge node admits a bridge only on a governance approval it verifies"; and #2472, "feat(bridge): the four bridge lifecycle EventType variants, the two registration actions, and the eight SCP-BCH stories".

## Design origin

Alec introduced the feature in planning session 02 (`.docs/planning-sessions/planning-session-02.md`, 2026-02-16): "I do think we want a concept of platform bridge connectors, but at the protocol level, not just locally. Facebook doesn't have to conform to SCP, but they could interface with a connector to participate." That session added spec §12 with four operating modes (relay, puppet, API and cooperative) and made a bridge connector a protocol entity run by an accountable identity. Planning session 04 (2026-02-21) sketched the `create_shadow` and `resolve_shadow` Rust signatures. Pull request #383, "spec: bridge uses sender keys, not MLS membership" (2026-03-05), changed spec 12 so that a bridge encrypts each shadow's messages with a per-shadow sender key.

## ADR-023, Bridge Connector Protocol

**Archived at:** `adrs/ADR-023-bridge-connector-protocol.md`, with the four `phase-5.md` header lines that named it in `passages/from-adrs-prds-sketch.md`.

**Origin.** ADR-023 entered `.docs/adrs/phase-5.md` on 2026-02-23 in the commit "integrate broadcast contexts, pull-based key distribution, and spec refinements". Four pull requests changed it: #167, "refactor(identity): simplify claim_shadow return type" (2026-03-02); #274, "ADR-039: Shared-DID human-agent identity model" (2026-03-04); #479, "feat: close remaining issues — 11 PR integration merge" (2026-03-10); and #775, "fix(ffi): add governance_did param to bridge_register" (2026-03-11). Pull request #2484, "docs(identity): replace did:dht with a key-event-log identity (ADR-063)" (2026-09-27), replaced its `did:dht` references.

**State at archiving.** Status Decided, amended 2026-09-10 by the P-256 curve ruling. Its decision text was implemented and wired as follows:

- `crates/scp-protocol/src/bridge/` held `mod.rs` (`BridgeMode` at line 29), `registration.rs`, `shadow.rs`, `provenance.rs`, `claiming.rs` and `envelope.rs`.
- Each FFI `bridge_register` call built a `BridgeRegistry` and discarded it on return, and no governance action drove a registry. Only `registration.rs` wrote `bridge_operator_dids`.
- `verify_claim` had no callers outside `claiming.rs`. Only `py_bridge_claim_shadow` and the test `phase5_integration.rs` called `claim_shadow`. Only tests in `key_protocol_verify.rs` called `handle_bridge_shadow_key_request`.
- Only `crates/scp-ffi/src/bridge_connector.rs` called `seal_shadow_envelope` and `open_shadow_envelope`.
- Spec 12 and ADR-023 disagreed on whether a bridge is a registered protocol entity or software that a context member runs. The section "Question open when archived" in `README.md` records the disagreement.

**Cut.** The 2026-09-26 ruling, carried out by Track BR slice S1 on 2026-10-09. S1 also renamed the phase to "Media, Apple Platform, Swift SDK", removed ADR-023 from the phase diagram, and started the build order at ADR-024.

**Code.** The protocol module `crates/scp-protocol/src/bridge/` (all six files listed above) and its FFI and SDK surface, listed under the SCP-BCH entry below.

## SCP-084 to SCP-088, bridge core stories

**Archived at:** `passages/from-adrs-prds-sketch.md`, section "`.docs/prds/main.json`, the entries `SCP-084` … `SCP-088`", with the gate-5 lines that referenced them.

**Origin.** The commit "create .docs/prds" added the five stories to `.docs/prds/main.json` on 2026-02-25. Gate 5 of `main.json` carried the name "Bridges + Media" until S1 removed "Bridges +".

**State at archiving.** All five had status `done`:

| Story | Title | File named by the story |
|---|---|---|
| SCP-084 | Define bridge core types and module structure | `crates/scp-core/src/bridge/mod.rs` |
| SCP-085 | Implement bridge registration with governance approval | `crates/scp-core/src/bridge/registration.rs` |
| SCP-086 | Implement shadow identity creation and role management | `crates/scp-core/src/bridge/shadow.rs` |
| SCP-087 | Implement BridgeProvenance for bridged content attribution | `crates/scp-core/src/bridge/provenance.rs` |
| SCP-088 | Implement shadow claiming with identity attestation | `crates/scp-core/src/bridge/claiming.rs` |

The bridge files moved from `scp-core` to `crates/scp-protocol/src/bridge/` after the stories closed, and the story text kept the `scp-core` paths. No governance action drove the registration that SCP-085 describes, as the ADR-023 entry states.

**Cut.** The 2026-09-26 ruling, carried out by S1. S1 also removed the Bridge rows from SCP-104, the Phase 5 integration story, which now covers three ADRs and 8 tests where it covered four ADRs and 11 tests. S1 removed the `Bridge.*` cells and `bridgeRegister` items from SCP-302, the ADR-059 structured capability and trust validation story.

**Code.** `crates/scp-protocol/src/bridge/{mod,registration,shadow,provenance,claiming}.rs`.

## SCP-BCH-001 to SCP-BCH-013, `bridge-cooperative.json`

**Archived at:** `prds/bridge-cooperative.json`, moved with `git mv` and byte-identical to the file on main.

**Origin.** Pull request #368, "docs: production readiness audit — open questions, spec audit, execution plan", added the PRD on 2026-03-05. Pull request #382, "feat: add blocked_by and blocked_by_issues to PRD stories", added dependency fields. A commit on 2026-03-06 added SCP-BCH-010 to SCP-BCH-013, the sender-key and operator-metadata stories, and a commit on 2026-03-08 edited the file. Pull request #1066, "fix(core): align bridge credential HKDF with §12.11 key isolation", pull request #1148, "fix(docs): update 50 PRD story statuses for implemented features" (2026-03-14), and pull request #2484, "docs(identity): replace did:dht with a key-event-log identity (ADR-063)" (2026-09-27), made the later edits.

**State at archiving.** All 13 stories had status `done`:

- SCP-BCH-001 to SCP-BCH-007: identity-signed bearer authentication and the `/v1/scp/bridge/{shadow,message,attest,status,webhook}` endpoints, in `crates/scp-node/src/bridge_auth.rs`, `crates/scp-node/src/bridge_handlers.rs` (`bridge_router` at line 968, `bridge_webhook_router` at line 988) and `crates/scp-node/src/webhook.rs`. `crates/scp-node/src/lib.rs` mounted both routers through `http::build_bridge_routers` and `http::build_merged_router` on the full public surface; the self-host surface, `PublicSurface::SelfHost`, did not mount them.
- SCP-BCH-008 and SCP-BCH-009: `BridgeCredentialStore` and its OAuth 2.0 binding, in `crates/scp-runtime/src/bridge/credentials.rs`, `crates/scp-runtime/src/bridge/oauth.rs` and `crates/scp-runtime/src/store/credentials.rs`.
- SCP-BCH-010 to SCP-BCH-012: per-shadow sender keys, their pull-based distribution, and sender-key envelopes, in `crates/scp-protocol/src/bridge/envelope.rs` and the shadow key handler in the key protocol.
- SCP-BCH-013: `bridge_operator_did` in context metadata, written by `registration.rs`.

The FFI and SDK surface: `crates/scp-ffi/src/bridge_connector.rs` (PyO3), `crates/scp-ffi/napi/src/bridge_connector.rs`, `crates/scp-ffi/common/src/{credentials,bridge_id,bridge_state}.rs`, and the wrappers `bindings/python/scp_sdk/bridge.py`, `bindings/typescript/src/bridge.ts` and `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/BridgeConnector.kt`. `bridge-aliases.json` listed 11 operations: `bridge_create_shadow`, eight `bridge_credential_*` operations, `bridge_evaluate_trust` and `bridge_register`. `sdk-capability-matrix.json` carried a "Bridge" domain. The node's context-event webhook ran through `wire_node_webhook_events` in the PyO3, NAPI and UniFFI `server.rs` files and `wire_and_supervise_context_events` in `crates/scp-ffi/common/src/server.rs`.

**Cut.** The 2026-09-26 ruling, carried out by S1.

**Code.** Every path in this entry. Enforcement-file rows that the restored code needs are listed by S2 in `restore/enforcement-rows.md`.

## SCP-CAPINJECT-009 and the ADR-062 credentials capability (E2)

**Archived at:** `passages/from-adrs-prds-sketch.md`, the `.docs/prds/adr062-capability-injection.json` sections (gate-capinject-9 and SCP-CAPINJECT-009) and the ADR-062 sections that named credentials (E2).

**Origin.** Pull request #2120, "docs: capability injection & prove-absent dev backends — spec §17.17 + ADR-062 + 15-story PRD", added ADR-062, capability injection, and its PRD on 2026-07-14. Pull request #2136, "docs: correct ADR-062 over-scope", corrected their scope the same day. Pull request #2188, "feat(credentials): durable bridge-credential backend, delete impl Default, demote in-memory to test-only" (2026-08-01), implemented SCP-CAPINJECT-009. Pull request #2308, "fix(relay): relay WRITE-path + structural AC-6 publish seam" (2026-08-28), updated the story's verification text.

**State at archiving.** SCP-CAPINJECT-009 had status `done`, verified by the test `bridge_credential_survives_store_drop_and_reopen`. The `FfiCredentialStore` enum in `crates/scp-ffi/common/src/credentials.rs` selected the store, and the PyO3, NAPI and UniFFI runtimes held it. ADR-062 classified credentials as capability E2 and gave it rollout slice 9; S1 deleted Slice 9, kept Slices 10 and 11 under their numbers, and retitled §5 to cover blob (E3) and the relay-publisher default (E4).

**Cut.** The 2026-09-26 ruling, carried out by S1. The credentials capability existed only to hold bridge credentials, so it left with them.

**Code.** `crates/scp-ffi/common/src/credentials.rs`, `crates/scp-runtime/src/store/credentials.rs`, and the `FfiCredentialStore` fields in `crates/scp-ffi/src/runtime.rs`, `crates/scp-ffi/napi/src/runtime.rs` and `crates/scp-ffi/uniffi/src/runtime.rs`.

## The `scp:system:bridge-operation` capability

**Archived at:** `passages/from-adrs-prds-sketch.md`, the `.docs/adrs/phase-4.md` and `.docs/prds/capability-registry.json` sections.

**Origin.** Pull request #368, "docs: production readiness audit — open questions, spec audit, execution plan", added `bridge-operation` to the phase-4 system capability list and the capability-registry PRD on 2026-03-05.

**State at archiving.** The registry listed five system capabilities, `bridge-operation` among them. Four code files named it: `crates/scp-protocol/src/trust/capability_registry.rs` (lines 433 and 637), `crates/scp-protocol/src/trust/capability_uri.rs`, `crates/scp-protocol/src/trust/challenge.rs` and `crates/scp-runtime/src/discovery/did_capabilities.rs`. S1 changed the documents to four system capabilities; the code keeps five until the Track BR slice that deletes the registry entry, S9.

**Cut.** The 2026-09-26 ruling, carried out by S1.

**Code.** The `scp:system:bridge-operation` entries in the four files above.

## Shadow claiming in ADR-044, attestation two-class model and provider registry

**Archived at:** `passages/from-adrs-prds-sketch.md`, the two `.docs/adrs/phase-6.md` sections.

**Origin.** Pull request #1401, "docs: spec §3.5 attestation two-class model and provider registry (ADR-044)" (2026-03-18), cited bridge shadow claiming as a use of identity attestations.

**State at archiving.** The rationale and security analysis of ADR-044 named shadow claiming next to social graph import. Social graph import still uses Class 1 attestations and stays live.

**Cut.** The 2026-09-26 ruling, carried out by S1.

**Code.** `crates/scp-protocol/src/bridge/claiming.rs`.

## Bridge text in ADR-048, multi-instance SDK object, and ADR-049, actor-per-context concurrency

**Archived at:** `passages/from-adrs-prds-sketch.md`, the ADR-048 and ADR-049 sections.

**Origin.** Pull request #1683, "refactor(ffi): Phase 4 remainder PR 1 — SCP multi-instance scaffold" (2026-04-18), added the `BridgeConnector` and `CREDENTIAL_STORE` mentions to ADR-048. Pull request #1769, "fix(ffi): wire context events to WebhookDispatcher in production via Supervisor" (2026-06-09), wired the webhook to the Supervisor event channel. Pull request #1787, "feat(actor): Phase 2B — watchdog + respawn + poison, crash-safe state" (2026-06-11), added the webhook references to ADR-049 §12a, the event-channel observer surface.

**State at archiving.** ADR-048 cited spec §12's `BridgeConnector` as an existing application-layer class and listed `CREDENTIAL_STORE` among the process-global registries. ADR-049 §12a said the FFI node-startup path subscribes once to the Supervisor event channel and drives the outbound webhook dispatcher (spec §12.10.5), and disclosed that no operator-facing surface registered webhook targets; §10 compared its recovery-surface disclosures to that webhook deferral. ADR-049 §12 listed the test-only mock OAuth provider in `bridge/oauth.rs` among the allowed `tokio::sync::Mutex` sites. The Supervisor event channel itself, `Supervisor::subscribe_events`, stays live.

**Cut.** The 2026-09-26 ruling, carried out by S1. ADR-049 §12a keeps the sentence that `subscribe()` is called once at node startup until slice S5 deletes the webhook wiring.

**Code.** `crates/scp-node/src/webhook.rs`, the `wire_node_webhook_events` functions and `wire_and_supervise_context_events`, and `crates/scp-runtime/src/bridge/oauth.rs`.

## Bridge routes in the self-host stories and phase 2

**Archived at:** `passages/from-adrs-prds-sketch.md`, the `.docs/prds/self-host-binary.json` (SHB-005, SHB-007) and `.docs/adrs/phase-2.md` sections.

**Origin.** Pull request #1801, "feat(node): one-machine self-host website mode for scp-node (--self-host)" (2026-06-14), added SHB-005, the self-host shutdown and loopback story. Pull request #1860, "feat(node): self-host binary participant shapes — bundled + external" (2026-06-22), added SHB-007's bridge-route text and the phase-2 `dev/bridge` endpoint name.

**State at archiving.** Both stories had status `done`. The test `self_host_public_surface_excludes_relay_and_bridge` in `crates/scp-node/tests/self_host.rs` asserted that `PublicSurface::SelfHost` mounts neither `/scp/v1` nor `/v1/scp/bridge/*`. S1 renamed the test in the stories to `self_host_public_surface_excludes_relay`; slice S5 renames the test in code.

**Cut.** The 2026-09-26 ruling, carried out by S1.

**Code.** The bridge assertions in `crates/scp-node/tests/self_host.rs`, and the bridge routers listed in the SCP-BCH entry.

## Sketch §7, Bridge Connectors, and the other sketch passages

**Archived at:** `passages/from-adrs-prds-sketch.md`, the `.docs/sketch.md` sections.

**Origin.** A commit on 2026-02-17 whose subject begins "stress test spec and sketch" added sketch §7, Bridge Connectors, and the example "Bridging: X Users Participate in a Quest Community". The sketch already held the `bridges: [BridgeInfo]?` field, the `addBridge` and `removeBridge` governance actions, and the metadata `bridges` JSON when the commit "move architecture.md and sketch.md to .docs/" moved it on 2026-02-23.

**State at archiving.** The sketch is a design sketch with no status. Its bridge API (`BridgeConnector`, `createShadow`, `claimShadow`) matched ADR-023 and the code above.

**Cut.** The 2026-09-26 ruling, carried out by S1.

**Code.** None of its own; the sketch described the code in the SCP-BCH and ADR-023 entries.

## Label corrections made alongside the cut

S1 also corrected three wrong ADR labels in one sentence of `.docs/adrs/phase-3.md` (acceptance criteria, lines 334–336) and the same sentence in SCP-216 in `.docs/prds/main.json`. The sentence named ADR-019, ADR-023 and ADR-027 as the TypeScript, Swift and Kotlin SDK ADRs; those numbers belong to Data Provenance, Bridge Connector Protocol and the Android platform adapter. The SDK ADRs are ADR-022 (TypeScript SDK), ADR-026 (Swift SDK) and ADR-028 (Kotlin SDK). The original lines sit in the passages file so the verbatim check covers them; they carried no bridge-connector content.

## Spec 12, Platform Bridge Connectors

**Archived at:** `specs/12-platform-bridge-connectors.md`, moved with `git mv` by the Track BR slice S2 pull request. The banner above the rule is the only text S2 added; everything below it is the file as it stood on main.

**Origin.**

- Planning session 02 (`.docs/planning-sessions/planning-session-02.md`, 2026-02-16) introduced the feature; the section "Design origin" above quotes Alec. The commit "add spec chapters and expand open questions" added the spec chapter on 2026-02-23, the same day ADR-023 entered `phase-5.md`.
- On 2026-03-05 the audit `.docs/audits/spec-audit-12-15-unspecified-details.md` logged 42 findings against spec 12. Pull request #368, "docs: production readiness audit — open questions, spec audit, execution plan", committed that audit the same day. Pull request #383, "spec: bridge uses sender keys, not MLS membership", made shadows sender-key participants the same day.
- On 2026-03-07 five commits pushed to main filled the audit's gaps: "docs(specs): address Phase 11 Lane H-F bridge spec gaps (H-27, H-33)"; "docs(specs): address Phase 11 review findings (H-D-1, H-D-2, H-A-1, H-C-1, H-F-1, H-D-3, H-D-4)"; "docs(specs): Lane E partial — bridge registration/removal protocol, shadow limits, upgrade path (§12.2-12.3)"; "docs(specs): Lane E — bridge connector spec gaps (10 findings)"; and "fix(specs): resolve Phase 11 review HIGH findings — content_hash oracle, registry centralization, signer key rotation". The first of the five added the sentence that the bridge operator "IS an MLS group member admitted through normal context governance", which started the two-model disagreement that `README.md` records.
- Seven later pull requests edited the file: #479, "feat: close remaining issues — 11 PR integration merge" (2026-03-10); #1040, "refactor(core): rename ProtocolStore to ProtocolRepository" (2026-03-13); #1147, "fix(spec): clarify bridge_id encoding as UTF-8 string in HKDF info parameter" (2026-03-14); #1628, "refactor: Part 3 Phase 4 — BridgeInstance extraction" (2026-04-17); #1757 and #1769, the ADR-049 actor-per-context integration and its webhook re-wiring (2026-06-09); and #2098, the outlet re-port (2026-07-11). The last edit before archiving was pull request #2484, "docs(identity): replace did:dht with a key-event-log identity (ADR-063)", on 2026-09-27.

**State at archiving.** Spec 12 carried no status line. The stories that implemented it, SCP-084 to SCP-088 and SCP-BCH-001 to SCP-BCH-013, all had status `done`; the entries above for those stories give their code. Read against main on 2026-10-09:

- **Implemented and reachable:** the §12.10 cooperative HTTP binding (`crates/scp-node/src/bridge_handlers.rs` and `bridge_auth.rs`, routes `/v1/scp/bridge/*`, mounted on the node's full public surface and not on the self-host surface); webhook dispatch (`crates/scp-node/src/webhook.rs`, wired through each FFI bridge's `server.rs`); the §12.11 credential lifecycle (`crates/scp-runtime/src/bridge/credentials.rs`, `bridge/oauth.rs`, `store/credentials.rs` and the FFI `FfiCredentialStore`); the 11 cross-bridge operations in `scripts/bridge-aliases.json`; and §12.5 provenance, which `evaluate_trust` reads.
- **Half-implemented:** §12.2 registration, because each FFI `bridge_register` call builds a `BridgeRegistry` and discards it, and no governance action drives one; §12.3 shadow claiming, because `verify_claim` has no caller outside `crates/scp-protocol/src/bridge/claiming.rs`; and the §12.6.1 sender-key shadow path, because only tests in `key_protocol_verify.rs` call `handle_bridge_shadow_key_request`.
- **Spec-only:** the three non-cooperative modes of §12.4, which exist only as `BridgeMode` variants; §12.7 to §12.9, on self-hosted bridges, platform resistance and incentives; and the §12.12 wire tables, which no code generates.
- **Code that disagreed with spec 12:** spec 12 and §9.18.3 of the security spec named the credential HKDF info string `"scp-bridge-credential-v1"`, and `derive_credential_key` in `crates/scp-runtime/src/bridge/credentials.rs` used `"scp-bridge-credential:" || bridge_id`.

**Cut.** The 2026-09-26 ruling, carried out by S2 on 2026-10-09.

**Code.** The paths in the ADR-023, SCP-084 to SCP-088 and SCP-BCH entries above. The enforcement rows that restored code needs sit in `restore/enforcement-rows.md`.

## Shadow identity claiming, §3.5.5 of the identity spec, and the other identity-spec bridge text

**Archived at:** `passages/from-specs-guides-whitepaper.md`, the `.docs/specs/03-identity.md` sections.

**Origin.** The commit "docs(specs): Lane A — identity spec gaps (7 findings)", pushed to main on 2026-03-07, added §3.5.5, Shadow Identity Claiming Protocol, with `ShadowClaimRequest` and the `SHADOW_ALREADY_CLAIMED` error. The lines S2 changed in §3.5, §3.5.0, §3.5.1 and §3.5.4 named shadow claiming as one use of identity attestations.

**State at archiving.** §3.5.5 specified the claim request, the five validation steps, conflict resolution and participation-record handling. `claim_shadow` and `verify_claim` in `crates/scp-protocol/src/bridge/claiming.rs` implemented the hash and the checks; `verify_claim` had no caller outside that file. The node endpoint in `crates/scp-node/src/bridge_handlers.rs` returned `SHADOW_ALREADY_CLAIMED`. The identity spec keeps Class 1 identity-link attestations, which social graph import uses.

**Cut.** The 2026-09-26 ruling, carried out by S2.

**Code.** `crates/scp-protocol/src/bridge/claiming.rs` and the claim handler in `crates/scp-node/src/bridge_handlers.rs`.

## The `bridging` capability and the `bridges` context metadata, §5.3 and §5.7 of the contexts spec

**Archived at:** `passages/from-specs-guides-whitepaper.md`, the `.docs/specs/05-contexts.md` sections.

**Origin.** The commit "add media transport to capability ceiling, sketch API, and architecture" (2026-02-23) added the `bridging` ceiling category. The 2026-03-07 commit "docs(specs): address Phase 11 Lane H-F bridge spec gaps (H-27, H-33)" added the §5.7 "Active bridges" field with `BridgeMetadata` and `BridgeDirectionality`. Pull request #1894, "fix(ceiling): §5.3.1.1 canonical-resolution collision rule + no-built-in-resource-wildcard-shadow" (2026-06-26), used `bridging` and `bridging:*` as the examples that S2 replaced with `outlet_call:*`.

**State at archiving.** `Capability::Bridging` existed in `crates/scp-protocol/src/context/roles.rs`. `BridgeMetadata` and `BridgeDirectionality` existed in `crates/scp-protocol/src/context/params.rs`, but the `ContextParams` field that held bridges was `bridges: Vec<BridgeInfo>`, a different type, and only `crates/scp-protocol/src/bridge/registration.rs` wrote it.

**Cut.** The 2026-09-26 ruling, carried out by S2 for the text. Track BR slice S8 deletes the `ContextParams` bridge fields, and slice S9 deletes `Capability::Bridging`.

**Code.** `crates/scp-protocol/src/context/params.rs` (`BridgeMetadata`, `BridgeDirectionality`, `BridgeInfo` and the `bridges` fields) and the `Bridging` variant in `crates/scp-protocol/src/context/roles.rs`.

## The bridge constants of the security spec: §9.18.12 and two separator rows

**Archived at:** `passages/from-specs-guides-whitepaper.md`, the `.docs/specs/09-security-model.md` sections.

**Origin.** Pull request #479, "feat: close remaining issues — 11 PR integration merge" (2026-03-10), added the `SCP-CLAIM-V1:` domain separator and the maximum of 10,000 shadows per bridge. Pull request #655, "feat(typescript): add TTL, export/import, delegate bridge methods + WASM fixes" (2026-03-10), added the `scp-bridge-credential-v1` HKDF label. Pull request #1360, "refactor(constants): reclassify protocol constants (ADR-043)" (2026-03-17), gave the shadow limit its own subsection, §9.18.12 Bridge.

**State at archiving.** `claiming.rs` hashed claims under `SCP-CLAIM-V1:`, and `DEFAULT_MAX_SHADOWS_PER_BRIDGE` in `crates/scp-protocol/src/bridge/shadow.rs` was 10,000. No code used the string `scp-bridge-credential-v1`; the code used `scp-bridge-credential:` followed by the bridge ID. `crates/scp-runtime/tests/test_vectors.rs` and `scripts/gen-test-vectors-p256.py` still listed both strings among the domain separators. S2 kept the `SCP-BRIDGE-REGISTER-V1:` row, which belongs to the relay bridge, and changed its section reference from §12 to §10.12.4, Tier 3: Relay Bridging. §9.18.12 was the last subsection of §9.18, so deleting it renumbered no other subsection, and §9.18 now has the 16 subsections that `.docs/specs/21-documentation.md` states.

**Cut.** The 2026-09-26 ruling, carried out by S2 for the text. Slice S9 removes both separators from the test-vector test and the generator.

**Code.** `crates/scp-protocol/src/bridge/claiming.rs`, `crates/scp-protocol/src/bridge/shadow.rs`, `crates/scp-runtime/src/bridge/credentials.rs`, and the separator lists in `crates/scp-runtime/tests/test_vectors.rs` and `scripts/gen-test-vectors-p256.py`.

## Vector 22, §25.10 of the test-vectors spec

**Archived at:** `passages/from-specs-guides-whitepaper.md`, the `.docs/specs/25-test-vectors.md` section.

**Origin.** Pull request #479, "feat: close remaining issues — 11 PR integration merge" (2026-03-10), added §25.10, Claim Validation Vectors, with Vector 22, the shadow claim hash.

**State at archiving.** `crates/scp-runtime/tests/test_vectors.rs` printed and checked "Vector 22: Shadow Claim Hash", and `scripts/gen-test-vectors-p256.py` generated it. No CI step compared spec 25 with the generator, so deleting the spec text breaks no gate.

**Cut.** The 2026-09-26 ruling, carried out by S2 for the text. Slice S9 deletes the vector from the test and the generator.

**Code.** `crates/scp-runtime/tests/test_vectors.rs` and `scripts/gen-test-vectors-p256.py`.

## CONF-036 to CONF-038, §26.11 of the conformance-suite spec

**Archived at:** `passages/from-specs-guides-whitepaper.md`, the `.docs/specs/26-conformance-suite.md` sections.

**Origin.** Pull request #479, "feat: close remaining issues — 11 PR integration merge" (2026-03-10), added §26.11, Bridge Tests, with CONF-036 (bridge registration and approval), CONF-037 (shadow identity creation and claiming) and CONF-038 (bridged message provenance marking), and listed them in the Full conformance tier.

**State at archiving.** `crates/scp-testing/tests/integration/conformance.rs` held `conf_036_bridge_registration`, `conf_037_shadow_identity` and `conf_038_bridged_provenance`. S2 changed the Full tier to "CONF-001 through CONF-035 and CONF-039 through CONF-042" and removed "bridges" and "Bridge" from the tier and layer descriptions. The CONF numbers stay retired; S2 renumbered no test.

**Cut.** The 2026-09-26 ruling, carried out by S2 for the text. A Track BR code slice deletes the three tests.

**Code.** The three test functions in `crates/scp-testing/tests/integration/conformance.rs`.

## Bridge text in spec 27, Attestations

**Archived at:** `passages/from-specs-guides-whitepaper.md`, the `.docs/specs/27-attestations.md` sections.

**Origin.** Pull request #2401, "docs(spec): §27 gathers eight shipped attestation record types into one section — first draft, review findings unapplied" (2026-08-24), counted `StoredAttestation` among the record types outside the eight families and named shadow identity claims among attestation uses.

**State at archiving.** `StoredAttestation`, "A stored platform identity attestation", lived in `crates/scp-node/src/bridge_handlers.rs`, and `BridgeState.attestations` held it. OQ-1 counted ten records, two of them bridge records: `StoredAttestation` and the shadow identity claim. OQ-28 asked whether an identity link takes one wire format, two or three, and counted the platform-vouched shape of spec 12 as the third. S2 removed `StoredAttestation` from the counts (six further record types became five, 39 declarations became 38, thirteen became twelve), removed the shadow-claim clauses, reduced OQ-28 to "one wire format or two?", and recomputed every `file:line` cite whose target line S1 or S2 had moved. Two cites into `.docs/specs/03-identity.md`, in §27.4.2 and OQ-41, already pointed at §3.5.5 lines on main instead of the §3.5.4 cache list they quote, so S2 pointed them at that list.

**Cut.** The 2026-09-26 ruling, carried out by S2 for the text. Slice S5 deletes `bridge_handlers.rs`.

**Code.** `crates/scp-node/src/bridge_handlers.rs`.

## Bridge sentences in the other specs, the architecture document, the self-hosting guide, the white paper and the PRD issue template

**Archived at:** `passages/from-specs-guides-whitepaper.md`, the sections for `.docs/specs/00-open-questions.md`, `07`, `10`, `11`, `15`, `17`, `21`, `22`, `.docs/architecture.md`, `.docs/guides/self-hosting-a-website-on-scp.md`, `.docs/white-paper.md` and `.github/ISSUE_TEMPLATE/prd-story.yml`.

**Origin.**

- The white paper carried bridge connectors from its first version, pull request #456, "docs: add SCP white paper" (2026-03-17).
- Pull request #368 (2026-03-05) added `scp:system:bridge-operation` to §7.3.4 of the trust spec and the five resolved bridge items to the open-questions spec.
- Pull request #479 (2026-03-10) added the architecture document's `scp-protocol/src/bridge/` row and the note that bridge types live in `scp-protocol`.
- Pull request #1801, "feat(node): one-machine self-host website mode for scp-node (--self-host)" (2026-06-14), and pull request #1860, "feat(node): self-host binary participant shapes — bundled + external (SHB-002/007/008)" (2026-06-22), added the `/v1/scp/bridge/*` exclusions to spec 10 and the self-hosting guide.
- Pull request #2120, "docs: capability injection & prove-absent dev backends — spec §17.17 + ADR-062 + 15-story PRD" (2026-07-14), added "credential storage" to §17.17 of the persistence spec.
- The 2026-03-07 commit "docs(specs): Lane F — store/economy/provenance spec gaps (10 findings)" gave handle-outlet writer verification in spec 22 the `BRIDGE_NOT_AUTHORIZED` error code.

**State at archiving.** Each sentence described code listed in the entries above: the node bridge routes, the credential store, the `bridge-operation` system capability (four protocol and SDK files named it), the architecture document's `bridge/` modules, and the Bridge column of the component map. The open-questions spec now counts four system capabilities. The PRD issue template's dropdown lost `bridge-cooperative`, because S1 moved that PRD here. Spec 22 now says only that the writer rejects the request; it names no error code, because `BRIDGE_NOT_AUTHORIZED` belonged to the bridge HTTP binding in `crates/scp-node/src/bridge_auth.rs`.

**Cut.** The 2026-09-26 ruling, carried out by S2 for the text. The code these sentences described leaves in slices S3a to S9.

**Code.** The paths in the entries above.

## Enforcement rows

**Archived at:** `restore/enforcement-rows.md`.

**Origin.** Each row entered its file with the code it checks: the Bridge matrix domain, the coverage aliases and the `ExpectedOp` rows with the SDK wrappers; the 11 `bridge-aliases.json` operations and the eight allowlist entries with the FFI exports; the two mutable-global rows with `CREDENTIAL_HKDF_SALT` and the webhook `EVENT_COUNTER`; `b3_webhook_dispatch_wired` with the webhook dispatcher; and the two `ffi_conformance.rs` includes with the PyO3 and NAPI `bridge_connector.rs` files.

**State at archiving.** Every row was live on main and passing on 2026-10-09; S2 copied them without changing any enforcement file. Alec approved deleting them with the cut ("Yes, all of them").

**Cut.** Slices S3a (matrix, aliases, `ExpectedOp`), S4 (bridge aliases, allowlist), S5 (`b3_webhook_dispatch_wired`), and the slices that delete the code each remaining row checks.

**Code.** Each block's file and line range on main is in its heading in `restore/enforcement-rows.md`.
