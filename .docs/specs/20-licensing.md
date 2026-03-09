# 20. Licensing

## 20.1 Decision

SCP uses a multi-license structure:

| Component | License | SPDX |
|---|---|---|
| Protocol specification (`.docs/specs/`) | CC-BY 4.0 | — |
| Client SDK and bindings | Apache 2.0 | `Apache-2.0` |
| Application node (`scp-node`) | AGPL v3 only | `AGPL-3.0-only` |
| Commercial use | Limn Commercial License | — |

Contributors sign a CLA granting Limn the right to offer contributions under both AGPL and commercial licenses.

## 20.2 Rationale

SCP is an infrastructure protocol with two distinct audiences: **client builders** (agent developers, app developers, enterprises integrating SCP) and **infrastructure operators** (relay hosts, managed service providers). These audiences have different adoption dynamics and different threat models.

**Client SDK: Apache 2.0.** Agent builders need zero-friction integration. The SDK competes for adoption against permissive alternatives in an ecosystem built almost entirely on MIT and Apache 2.0. Any copyleft on the SDK creates legal review friction that kills enterprise adoption. Apache 2.0 provides patent grants (important for a protocol with novel cryptographic constructions), requires attribution, and is universally accepted.

**Application node: AGPL v3 only.** The primary commercial threat is cloud providers running a proprietary fork of the relay as a managed service, extracting value without contributing back. AGPL's Section 13 network-interaction clause requires operators of modified versions to share source with their users. This forces a choice: contribute modifications back to the community, or obtain a commercial license from Limn. AGPL is the standard choice for server-side infrastructure in this position (MongoDB pre-SSPL, Grafana, MinIO, Nextcloud, Supabase).

**Protocol specification: CC-BY 4.0.** The specification must be freely implementable for ecosystem trust. Restricting it would violate the "protocol requires no operator" tenet and undermine SCP's legitimacy as an open standard. CC-BY requires attribution, maintaining provenance. Anyone can write a conforming implementation from scratch under any license.

**CLA: required for dual licensing.** Without a CLA, third-party contributions to `scp-node` would be licensed only under AGPL, making it legally impossible to include them in the commercial license. The CLA grants Limn the right to sublicense contributions, which is the standard mechanism enabling dual-licensed projects.

**AGPL-3.0-only (not "or later").** The "only" qualifier keeps license version decisions with Limn and the community rather than delegating them to the FSF. If a future AGPL version is desirable, the project can explicitly adopt it.

## 20.3 Alternatives Considered

**MIT / Apache 2.0 everywhere.** Maximum adoption, zero commercial protection. Cloud providers can run proprietary relay forks with no obligation to contribute. This is the PostgreSQL/Kubernetes model — works for projects backed by large foundations or companies with alternative revenue streams, but leaves the protocol vulnerable to commoditization in its early years. Rejected.

**AGPL everywhere (SDK + relay).** Strong copyleft protection, but kills SDK adoption. Enterprises with blanket AGPL bans (Google, many Fortune 500) cannot use the SDK. Agent builders choose permissive alternatives. The protocol's "SDK first" tenet is incompatible with AGPL on the SDK. Rejected.

**Business Source License (BSL/BUSL).** Source-available with time-delayed open sourcing. Not OSI-approved. Provoked community backlash and forks when HashiCorp adopted it (OpenTofu). In tension with "protocol requires no operator" tenet. Rejected.

**SSPL (Server Side Public License).** MongoDB's response to AGPL being insufficient against cloud providers. Even more restrictive — requires open-sourcing the entire infrastructure stack. Not OSI-approved, widely rejected by the community and distributions. Rejected.

**MIT + Commercial dual license.** Simpler than AGPL + Commercial, but MIT has no copyleft trigger. Cloud providers can run the relay with no obligations at all. The commercial license only sells support and indemnification, not copyleft exemption. Weaker commercial position. Rejected.

**GPL v3 (not AGPL).** Missing the network-interaction clause of Section 13. A cloud provider running a modified relay as a SaaS offering would have no source-sharing obligation under GPL because they never "distribute" the software. AGPL was specifically designed for this scenario. Rejected.

## 20.4 Precedents

| Project | Client/SDK | Server | Commercial | Outcome |
|---|---|---|---|---|
| MongoDB (pre-SSPL) | Apache 2.0 drivers | AGPL v3 | MongoDB Enterprise | Successful for years; moved to SSPL when AGPL proved insufficient at MongoDB's scale |
| Grafana | Apache 2.0 client libs | AGPL v3 | Grafana Cloud / Enterprise | Thriving; AGPL move increased commercial leverage without hurting adoption |
| MinIO | Apache 2.0 SDKs | AGPL v3 | SUBNET commercial license | Closest analog to SCP's architecture (object storage protocol + SDKs) |
| Nextcloud | Permissive client apps | AGPL v3 | Nextcloud Enterprise | Strong community + enterprise dual track |
| Supabase | Apache 2.0 client libs | AGPL v3 (Realtime, etc.) | Supabase Pro/Enterprise | Fast-growing; permissive clients drive adoption |

Broader context: Linux (GPL v2) and Git (GPL v2) demonstrate that copyleft does not prevent adoption of foundational infrastructure. TCP/IP and HTTP (open standards, no canonical license) demonstrate that freely implementable specifications create the strongest ecosystems.

## 20.5 License Boundary

The license boundary is enforced at the crate level:

```
Apache 2.0                         AGPL v3 only
─────────────────────────────      ────────────────
scp-core                     ──→   scp-node
scp-transport                ──→     (depends on SDK
scp-platform                 ──→      crates; dependency
scp-identity                          flows one way)
scp-event-log
scp-primitives
scp-ffi (PyO3, UniFFI, napi, wasm)
scp-mcp
scp-media
scp-testing
```

Dependencies flow strictly from AGPL into Apache 2.0, never the reverse. Apache 2.0 is compatible with AGPL v3 — Apache-licensed code can be included in an AGPL work. No Apache 2.0 crate depends on `scp-node`.

## 20.6 Copyleft Boundary

- **Configuration, environment variables, runtime flags:** Not modifications. No source obligations.
- **Plugins/extensions linking against `scp-node`:** Combined work under AGPL Section 5(c). Must be AGPL-licensed.
- **Plugins/extensions using only SDK crates (`scp-core`, `scp-transport`, etc.):** Not affected by AGPL. Any license.
- **Independent protocol implementations:** CC-BY 4.0 spec. Any license.
- **Client applications using SDK:** Apache 2.0. Any license.

## 20.7 Tenet Alignment

| Tenet | How licensing aligns |
|---|---|
| Protocol requires no operator | Spec is CC-BY 4.0 — anyone can implement. SDK is Apache 2.0 — anyone can build clients. |
| SDK first | Apache 2.0 on SDK removes all adoption friction. |
| Transport independence | Transport adapters live in Apache 2.0 crates. No transport choice is constrained by AGPL. |
| Provenance everywhere | CC-BY attribution on spec. Apache 2.0 attribution on SDK. AGPL attribution on relay. All require origin tracing. |
| No deferral | Licensing is complete and decided. No "TBD" items. |

## 20.8 Open Items

- **CLA document:** Must be created before accepting external contributions. Use Apache ICLA as template.
- **SPDX file headers:** Consider adding per-file SPDX identifiers to `scp-node` source files. Non-blocking but recommended by AGPL appendix.
- **Future crates:** Any new crates will need explicit license assignments when created. Expected: Apache 2.0 for SDK-layer crates, AGPL v3 for infrastructure-layer crates.
