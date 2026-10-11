# Passages removed from specs, guides, the architecture document and the white paper

> **ARCHIVED — NOT LIVE TEXT.** This file records every line that the Track BR slice S2 pull request removed or changed in a live spec, guide, `.docs/architecture.md`, `.docs/white-paper.md` or `.github/ISSUE_TEMPLATE/prd-story.yml` on 2026-10-09. Nothing below states current protocol or a current decision. Read `../HISTORY.md` for the history and state of each artifact before reviving any passage.

Each section names the source file, the heading that enclosed the passage, and the passage's line range in that file on main when S2 archived it. A four-backtick `text` fence holds the original lines byte for byte, so embedded fences, headings and tables keep their exact text. When S2 changed a line instead of deleting it, a second fence after "Live text after the cut:" holds the replacement. To restore a passage, put the fenced lines back at the named location and delete the replacement lines.

Spec 12, Platform Bridge Connectors, is not repeated here: it sits whole in `../specs/12-platform-bridge-connectors.md`.

## `.github/ISSUE_TEMPLATE/prd-story.yml`, under `label: PRD File`, line 13 on main when archived

````text
        - bridge-cooperative
````

## `.docs/architecture.md`, under `### 1.1 High-Level Component Map`, lines 57–68 on main when archived

````text
│  │  │  ┌──────────┐ ┌─────────┴┐ ┌──────────┐ ┌───────────┐ │ │  │
│  │  │  │Transport │ │ Platform │ │ MCP      │ │ Bridge    │ │ │  │
│  │  │  │          │ │          │ │          │ │           │ │ │  │
│  │  │  │ • SCP    │ │ • Keys   │ │ • Server │ │ • X       │ │ │  │
│  │  │  │   native │ │ • Attest  │ │ • Client │ │ • Bluesky │ │ │  │
│  │  │  │ • Nostr  │ │ • Push   │ │          │ │ • Discord │ │ │  │
│  │  │  │ • Matrix │ │ • Storage│ │          │ │           │ │ │  │
│  │  │  │ • Hyper* │ │          │ │          │ │           │ │ │  │
│  │  │  │ • libp2p │ │          │ │          │ │           │ │ │  │
│  │  │  │ • WS/RTC │ │          │ │          │ │           │ │ │  │
│  │  │  │ • +more  │ │          │ │          │ │           │ │ │  │
│  │  │  └──────────┘ └──────────┘ └──────────┘ └───────────┘ │ │  │
````

Live text after the cut:

````text
│  │  │  ┌──────────┐ ┌─────────┴┐ ┌──────────┐               │ │  │
│  │  │  │Transport │ │ Platform │ │ MCP      │               │ │  │
│  │  │  │          │ │          │ │          │               │ │  │
│  │  │  │ • SCP    │ │ • Keys   │ │ • Server │               │ │  │
│  │  │  │   native │ │ • Attest  │ │ • Client │               │ │  │
│  │  │  │ • Nostr  │ │ • Push   │ │          │               │ │  │
│  │  │  │ • Matrix │ │ • Storage│ │          │               │ │  │
│  │  │  │ • Hyper* │ │          │ │          │               │ │  │
│  │  │  │ • libp2p │ │          │ │          │               │ │  │
│  │  │  │ • WS/RTC │ │          │ │          │               │ │  │
│  │  │  │ • +more  │ │          │ │          │               │ │  │
│  │  │  └──────────┘ └──────────┘ └──────────┘               │ │  │
````

## `.docs/architecture.md`, under `### 2.1 Crate Structure (Rust)`, line 261 on main when archived

````text
│   │   ├── bridge/            # Bridge connector protocol types (§12)
````

## `.docs/architecture.md`, under `### 2.1 Crate Structure (Rust)`, line 271 on main when archived

````text
│   │   └── ...                # envelope, discovery, bridge, economy async modules
````

Live text after the cut:

````text
│   │   └── ...                # envelope, discovery, economy async modules
````

## `.docs/architecture.md`, under `### 2.3 Dependency Graph`, lines 638–640 on main when archived

````text

   Note: Bridge protocol types live in scp-protocol/bridge/,
   not in a separate scp-bridge crate.
````

## `.docs/architecture.md`, under `### Phase 5: Platform Adapters + Swift + Reference App`, line 1167 on main when archived

````text
**Goal:** iOS SDK, reference app integration, bridge adapters, real-time media transport.
````

Live text after the cut:

````text
**Goal:** iOS SDK, reference app integration, real-time media transport.
````

## `.docs/architecture.md`, under `### Phase 5: Platform Adapters + Swift + Reference App`, line 1173 on main when archived

````text
  • scp-core/bridge/ — Bridge protocol types and per-platform adapters
````

## `.docs/architecture.md`, under `### Phase 5: Platform Adapters + Swift + Reference App`, line 1182 on main when archived

````text
  • Bridge: X user participates in quest via bridge
````

## `.docs/architecture.md`, under `### Phase 5: Platform Adapters + Swift + Reference App`, line 1190 on main when archived

````text
  • Bridge adapters
````

## `.docs/guides/self-hosting-a-website-on-scp.md`, under `## 1. What "a website on SCP" actually is`, lines 63–64 on main when archived

````text
   **never** re-exposes the relay upgrade (`/scp/v1`) or bridge routes
   (`/v1/scp/bridge/*`), which are not mounted on the self-host public surface.
````

Live text after the cut:

````text
   **never** re-exposes the relay upgrade (`/scp/v1`), which is not mounted on the
   self-host public surface.
````

## `.docs/guides/self-hosting-a-website-on-scp.md`, under `## 5. Build plan`, line 282 on main when archived

````text
<y>"); **clean teardown** releases the mapping on shutdown; dev/bridge endpoints
````

Live text after the cut:

````text
<y>"); **clean teardown** releases the mapping on shutdown; dev endpoints
````

## `.docs/white-paper.md`, under `## Abstract`, line 16 on main when archived

````text
Key properties: no operator dependency (the protocol functions if its creators disappear), transport independence (17 adapter specifications across 3 tiers), human accountability for all autonomous agents, and context isolation as the security boundary. The protocol is designed to be complementary to existing platforms and tool-level protocols — bridge connectors, transport adapters, and identity attestations enable harmonious interoperation with established distribution networks. The reference implementation is in Rust with bindings for Python, Swift, Kotlin, TypeScript, and WebAssembly. The specification is published under CC-BY 4.0; the SDK is published under Apache 2.0.
````

Live text after the cut:

````text
Key properties: no operator dependency (the protocol functions if its creators disappear), transport independence (17 adapter specifications across 3 tiers), human accountability for all autonomous agents, and context isolation as the security boundary. The protocol is designed to be complementary to existing platforms and tool-level protocols — transport adapters and identity attestations enable harmonious interoperation with established distribution networks. The reference implementation is in Rust with bindings for Python, Swift, Kotlin, TypeScript, and WebAssembly. The specification is published under CC-BY 4.0; the SDK is published under Apache 2.0.
````

## `.docs/white-paper.md`, under `### 1.2 Agents as Primary Actors`, line 44 on main when archived

````text
Beyond new applications, SCP is designed to harmonize with existing platforms rather than replace them. Bridge connectors translate between SCP and external platforms at the protocol level, transport adapters run on any delivery infrastructure, and identity attestations link SCP identities to existing platform accounts. The protocol complements existing distribution networks by providing the open social infrastructure they do not.
````

Live text after the cut:

````text
Beyond new applications, SCP is designed to harmonize with existing platforms rather than replace them. Transport adapters run on any delivery infrastructure, and identity attestations link SCP identities to existing platform accounts. The protocol complements existing distribution networks by providing the open social infrastructure they do not.
````

## `.docs/white-paper.md`, under `### 4.5 Identity Attestations`, line 328 on main when archived

````text
Attestations enable social graph import (resolving existing contacts who have joined SCP), shadow identity claiming (merging bridge-created representations with native identities), and cross-platform reputation continuity.
````

Live text after the cut:

````text
Attestations enable social graph import (resolving existing contacts who have joined SCP) and cross-platform reputation continuity.
````

## `.docs/white-paper.md`, under `### 7.2 Capability Categories`, line 425 on main when archived

````text
Standard capability categories include messaging, outlet invocation, media (voice, video, screen sharing), bridging, outlet interfaces, and child context creation. Every action is checked against the context's capability ceiling, the agent's role permissions, and the token's validity.
````

Live text after the cut:

````text
Standard capability categories include messaging, outlet invocation, media (voice, video, screen sharing), outlet interfaces, and child context creation. Every action is checked against the context's capability ceiling, the agent's role permissions, and the token's validity.
````

## `.docs/white-paper.md`, under `### 9.4 Deployment Spectrum`, line 509 on main when archived

````text
The agent workstation tier is architecturally significant. As autonomous agents become mainstream, users are acquiring dedicated always-on hardware to run them. SCP infrastructure — relays, context hosting, bridge connectors — is marginal additional load on hardware already running continuously, providing a natural deployment point for personal relay processes. The protocol is designed for the online case and tolerates offline periods, rather than the reverse: the protocol assumes agents are running and connected, and optimizes for that case. Offline tolerance exists (Section 9.5) but is the exception, not the design center.
````

Live text after the cut:

````text
The agent workstation tier is architecturally significant. As autonomous agents become mainstream, users are acquiring dedicated always-on hardware to run them. SCP infrastructure — relays, context hosting — is marginal additional load on hardware already running continuously, providing a natural deployment point for personal relay processes. The protocol is designed for the online case and tolerates offline periods, rather than the reverse: the protocol assumes agents are running and connected, and optimizes for that case. Offline tolerance exists (Section 9.5) but is the exception, not the design center.
````

## `.docs/white-paper.md`, under `### 11.1 Threat Model`, line 553 on main when archived

````text
The protocol distinguishes between what it defends against (confidentiality breach, capability escalation, unauthorized access) and what it makes legible (insider misbehavior, governance disputes, bridge operator malfeasance). Some attacks are detectable and attributable but not preventable at the protocol level — the protocol makes the attacker identifiable and the damage measurable, enabling governance response.
````

Live text after the cut:

````text
The protocol distinguishes between what it defends against (confidentiality breach, capability escalation, unauthorized access) and what it makes legible (insider misbehavior, governance disputes). Some attacks are detectable and attributable but not preventable at the protocol level — the protocol makes the attacker identifiable and the damage measurable, enabling governance response.
````

## `.docs/white-paper.md`, under `### 14.2 Limitations`, lines 731–732 on main when archived

````text
**Bridge fidelity.** Platform bridge connectors (Section 12 of the specification) depend on external platforms' willingness or API availability. Relay-mode and puppet-mode bridges are inherently lower fidelity than native SCP communication, and shadow identities carry weaker trust properties than native identities.

````

## `.docs/white-paper.md`, under `## Appendix C: Glossary`, lines 833–836 on main when archived

````text
**Bridge Connector.** A protocol entity that translates between an external platform's protocol and SCP's protocol semantics. Operated by accountable identities.

**Shadow Identity.** A protocol-level representation of an entity from an external platform, created by a bridge connector. Claimable by the real user via identity attestation.

````

## `.docs/specs/00-open-questions.md`, under `## Design Decisions Pending`, line 10 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
- **~~Agent capability metadata standard.~~** ✅ **Resolved.** ADR-041 specifies the full URI namespace and protocol registry. Three authorities: `scp:capability:{kebab-case}/v{N}` (protocol-defined, reserved, SDK-enforced), `did:{method}:{id}:capability:{kebab-case}/v{N}` (DID-scoped custom), `scp:system:{kebab-case}` (protocol feature flags). Initial protocol registry: 28 challenge capabilities across 10 categories + 5 system capabilities. Anti-spoofing: SDKs reject unknown `scp:capability:*` URIs; DID-scoped capabilities derive authority from the definer's identity; `ChallengeVerification` records distinguish self-attested from challenge-verified. §4.4 specifies the two-tier structure (self-attested vs challenge-verified). §7.3.4 specifies the URI format and registry reference. §7.4.1 defines the `agent_capability` attestation type.
````

Live text after the cut:

````text
- **~~Agent capability metadata standard.~~** ✅ **Resolved.** ADR-041 specifies the full URI namespace and protocol registry. Three authorities: `scp:capability:{kebab-case}/v{N}` (protocol-defined, reserved, SDK-enforced), `did:{method}:{id}:capability:{kebab-case}/v{N}` (DID-scoped custom), `scp:system:{kebab-case}` (protocol feature flags). Initial protocol registry: 28 challenge capabilities across 10 categories + 4 system capabilities. Anti-spoofing: SDKs reject unknown `scp:capability:*` URIs; DID-scoped capabilities derive authority from the definer's identity; `ChallengeVerification` records distinguish self-attested from challenge-verified. §4.4 specifies the two-tier structure (self-attested vs challenge-verified). §7.3.4 specifies the URI format and registry reference. §7.4.1 defines the `agent_capability` attestation type.
````

## `.docs/specs/00-open-questions.md`, under `## Design Decisions Pending`, line 13 on main when archived

````text
- **~~Identity attestation discovery.~~** ✅ **Resolved.** Attestations are discoverable through contexts with discovery outlets (§6.2.2B [no such section]) and through the attestation-revocations pointer of the subject's service record (`03-identity.md` §3.10.13, §7.4.1). Platform-specific contexts and bridges surface attestation data alongside their own data, eliminating the need for separate discovery infrastructure.
````

Live text after the cut:

````text
- **~~Identity attestation discovery.~~** ✅ **Resolved.** Attestations are discoverable through contexts with discovery outlets (§6.2.2B [no such section]) and through the attestation-revocations pointer of the subject's service record (`03-identity.md` §3.10.13, §7.4.1). Platform-specific contexts surface attestation data alongside their own data, eliminating the need for separate discovery infrastructure.
````

## `.docs/specs/00-open-questions.md`, under `## Design Decisions Pending`, lines 16–19 on main when archived

````text
- **~~Shadow identity role defaults.~~** ✅ **Resolved.** Observer role by default with restricted capabilities (§12.3). Context governance can override defaults for specific bridges.
- **~~Bridge connector interface specification.~~** ✅ **Resolved.** §12.10 specifies the Cooperative Mode HTTP Binding — a six-endpoint REST API that cooperating platforms implement. Endpoints: shadow creation (`POST /v1/scp/bridge/shadow`), message emission (`POST /v1/scp/bridge/message`), identity attestation (`POST /v1/scp/bridge/attest`), bridge status (`GET /v1/scp/bridge/status`), shadow deletion (`DELETE /v1/scp/bridge/shadow/{shadow_id}`), and platform webhook receiver (`POST /v1/scp/bridge/webhook`). Authentication via DID-signed bearer tokens. JSON over HTTPS with TLS 1.3. Versioned under `/v1/` prefix. Error format, rate limiting, idempotency semantics, and webhook delivery guarantees all specified. Maps directly to existing `scp-core/bridge/` operations. See §12.10.
- **~~Bridge credential custody.~~** ✅ **Resolved (out of protocol scope).** Credential custody is intentionally platform-specific and cannot be specified at the protocol level. The protocol provides the trust framework: operator accountability via DID (§12.2), self-hosting option eliminating third-party credential delegation (§12.7), revocability via context governance (§12.2), and transparency of bridge presence and operator identity to all context members. Credential mechanics (OAuth tokens, API keys, session cookies) vary by platform and authentication model. The cooperative mode HTTP binding (§12.10) eliminates credential delegation entirely — the platform authenticates the bridge operator via DID-signed tokens, and the bridge authenticates to the platform via the platform's own authentication system. No SCP-level credential custody specification is needed or appropriate.
- **~~Shadow identity claiming mechanics.~~** ✅ **Resolved.** §12.3 specifies claiming flow: claimant presents identity attestation matching shadow's platform handle, shadow is retired, historical actions retroactively attributed to claimant DID. API specified in .docs/sketch.md (`Bridge.claimShadow`).
````

## `.docs/specs/00-open-questions.md`, under `## Design Decisions Pending`, line 24 on main when archived

````text
- **~~Cooperative mode trust tiers.~~** ✅ **Resolved.** §12.5 specifies a four-tier trust hierarchy with two independent axes (identity confidence x transport confidence). The tiers explicitly define the trust differential: (1) Native SCP identity + native action = strongest. (2) Native SCP identity + bridged action = strong (identity verified via DID, transport via bridge infrastructure). (3) Claimed shadow + historical bridged = moderate (retroactive DID link, pre-claim content). (4) Shadow identity + bridged action = weakest (no DID claim, trust depends entirely on bridge operator). §12.9 specifies the incentive: "bridged-cooperative is more trusted than bridged-relay because the platform has vouched for the attribution." Cooperative mode gives the platform a "seat" — influence over how its users are perceived in SCP. Non-cooperation means relay/puppet mode scraping with weaker provenance. The trust differential IS the incentive — platforms that implement cooperative mode get their users perceived at tier 2 instead of tier 4.
````

## `.docs/specs/03-identity.md`, under `## 3.5 Identity Attestations`, line 62 on main when archived

````text
A user can publish cryptographic attestations binding their external platform identities to their identifier. These attestations are the mechanism that makes bridging trustworthy and social graph import possible.
````

Live text after the cut:

````text
A user can publish cryptographic attestations binding their external platform identities to their identifier. These attestations are the mechanism that makes social graph import possible.
````

## `.docs/specs/03-identity.md`, under `## 3.5 Identity Attestations`, line 74 on main when archived

````text
Identity attestations enable three critical flows:
````

Live text after the cut:

````text
Identity attestations enable two critical flows:
````

## `.docs/specs/03-identity.md`, under `## 3.5 Identity Attestations`, lines 77–78 on main when archived

````text
2. **Shadow identity claiming.** When a bridge connector creates a shadow identity for an external participant (see §12), a user can claim it by presenting a matching attestation. The shadow identity merges with that user's own identifier (see §3.5.5 for the claiming protocol).
3. **Cross-platform reputation continuity.** Trust judgments about a person can follow them across platforms — not because platforms share data, but because the human has cryptographically proven they're the same person.
````

Live text after the cut:

````text
2. **Cross-platform reputation continuity.** Trust judgments about a person can follow them across platforms — not because platforms share data, but because the human has cryptographically proven they're the same person.
````

## `.docs/specs/03-identity.md`, under `### 3.5.0 Attestation Classes`, line 89 on main when archived

````text
- Self-attestation model: issuer == subject. The identity's controller asserts "I verified this at creation time." Consumers trust the assertion because: (a) the `#active` key signed it, (b) the claim is minimal (no forgery incentive beyond the link itself), and (c) falsifying the link provides no benefit — shadow claiming (§3.5.5) and social graph import (§3.6) only work if the external account is genuinely controlled.
````

Live text after the cut:

````text
- Self-attestation model: issuer == subject. The identity's controller asserts "I verified this at creation time." Consumers trust the assertion because: (a) the `#active` key signed it, (b) the claim is minimal (no forgery incentive beyond the link itself), and (c) falsifying the link provides no benefit — social graph import (§3.6) only works if the external account is genuinely controlled.
````

## `.docs/specs/03-identity.md`, under `### 3.5.1 Provider Registry`, line 133 on main when archived

````text
**`ChallengeResponse` verification method:** the registry above names two platforms that use it, Telegram and Steam, and the mechanism is platform-agnostic beyond them. Any verifier — a context governance engine, a bridge connector, or another participant — challenges an agent to prove a capability or an identity claim over a cryptographic round trip. The verifier chooses the `platform` value, such as the context id or its own domain, and `evidence.verifier_did` names the verifier that issued the challenge.
````

Live text after the cut:

````text
**`ChallengeResponse` verification method:** the registry above names two platforms that use it, Telegram and Steam, and the mechanism is platform-agnostic beyond them. Any verifier — a context governance engine or another participant — challenges an agent to prove a capability or an identity claim over a cryptographic round trip. The verifier chooses the `platform` value, such as the context id or its own domain, and `evidence.verifier_did` names the verifier that issued the challenge.
````

## `.docs/specs/03-identity.md`, under `### 3.5.4 Verification`, line 250 on main when archived

````text
6. **Trust the self-attestation.** Because issuer == subject, the `#active` signature is sufficient. The attestation asserts "I performed OAuth verification at `verified_at` and the OIDC `sub` was `subject_id`." There is no cryptographic proof that the OAuth flow actually occurred — this is a self-attestation. It is acceptable for identity links because: (a) the claim is minimal, (b) the only use case is linking identities the user actually controls, (c) falsifying a link provides no protocol benefit (shadow claiming verifies independently, social graph import only surfaces genuine contacts).
````

Live text after the cut:

````text
6. **Trust the self-attestation.** Because issuer == subject, the `#active` signature is sufficient. The attestation asserts "I performed OAuth verification at `verified_at` and the OIDC `sub` was `subject_id`." There is no cryptographic proof that the OAuth flow actually occurred — this is a self-attestation. It is acceptable for identity links because: (a) the claim is minimal, (b) the only use case is linking identities the user actually controls, (c) falsifying a link provides no protocol benefit (social graph import only surfaces genuine contacts).
````

## `.docs/specs/03-identity.md`, under `### 3.5.4 Verification`, lines 271–308 on main when archived

````text
### 3.5.5 Shadow Identity Claiming Protocol

When a bridge connector creates a shadow identity for an external platform participant (§12.3), the following protocol governs claiming:

**Claiming sequence:**

1. **Eligibility check.** The claimant presents an `IdentityLinkAttestation` (§3.5.2) for the same platform and handle as the shadow identity. The bridge verifies:
   a. The attestation is valid (signature verifies, not expired, not revoked).
   b. The `platform` and `platform_handle` (or `platform_id` if available) match the shadow identity's external identity.
   c. The attestation's `evidence` has been verified within the last renewal interval (§3.5.4).

2. **Claim request.** The claimant sends a `ShadowClaimRequest` to the bridge context:
   ```
   ShadowClaimRequest {
     claimant_did:      Identifier,
     shadow_did:        Identifier,     // the shadow identity's identifier
     attestation_id:    String,         // ID of the IdentityLinkAttestation
     attestation:       IdentityLinkAttestation, // Full attestation for verification
     timestamp:         u64,
     signature:         P256Signature,    // Signs claimant_did || shadow_did || attestation_id || timestamp
   }
   ```

3. **Bridge verification.** The bridge operator verifies:
   a. The attestation links the claimant's identifier to the shadow identity's external identity.
   b. No other identifier has already claimed this shadow identity.
   c. The claimant's identifier is not on any block list relevant to the context.

4. **Merge execution.** On successful verification:
   a. The shadow identity's membership records in all bridge contexts are updated to reference the claimant's identifier.
   b. Historical messages from the shadow identity are re-attributed to the claimant's identifier in the context event log via a `ShadowClaimed { shadow_did, claimant_did, attestation_id, timestamp }` event.
   c. The shadow identity is deactivated — it cannot send new messages or be claimed by another party.
   d. The claimant inherits the shadow identity's role in the context (typically `member`; never higher than the context's default role for new members unless governance explicitly grants an upgrade).

5. **Conflict resolution.** If two claimants present valid attestations for the same shadow identity simultaneously, the first `ShadowClaimRequest` processed by the bridge wins. The second claimant receives a `SHADOW_ALREADY_CLAIMED` error (code 4040). The losing claimant MAY dispute via the bridge context's governance mechanism.

**Participation record handling.** The shadow identity's participation history (message counts, duration, event log entries) is NOT merged into the claimant's participation profile. Shadow participation is recorded under the shadow identity's own identifier: the `ShadowClaimed` event establishes the link for auditing, and participation records stay separate so that no party inflates participation by creating shadow identities.

````

## `.docs/specs/05-contexts.md`, under `## 5.3 Capability Ceiling`, line 59 on main when archived

````text
- **`bridging`** — bridge connector participation (§12)
````

## `.docs/specs/05-contexts.md`, under `### 5.3.1 Exhaustive Capability Categories`, line 97 on main when archived

````text
| `bridging` | Bridge connector participation (§12) | Role permission + governance |
````

## `.docs/specs/05-contexts.md`, under `#### 5.3.1.1 Ceiling-Entry Grammar`, line 119 on main when archived

````text
**No privileged-built-in collision.** A custom entry (shape 2 or shape 3 above) is valid only if it does not name a built-in capability under **any** spelling. A custom entry's string MUST NOT denote a built-in capability — neither a built-in's user-facing colon form (e.g. `outlet:query:*`, `outlet:call:*`, `outlet:call:{outlet_id}`, `bridging`, `messages:read`) nor its canonical UCAN form (e.g. `outlet_query:*`, `outlet_call:*`, `bridging:*`, `context_child:create`), including the parameterized `outlet_query:{outlet_id}` / `outlet_call:{outlet_id}` families for any concrete `outlet_id`. A custom entry that names a built-in under any spelling MUST be rejected at context creation with `InvalidCeilingCategory` (e.g. a custom whose string is `bridging:*` — which denotes the `bridging` built-in — is rejected). This is enforced by **canonical resolution**, not by a denylist of forbidden spellings: an entry is admitted as a custom only if resolving its string through the protocol's single canonical capability parser (`Capability::new`, defined in code at `crates/scp-protocol/src/context/roles.rs`) does **not** yield a built-in capability. Because that parser is the sole authority on which strings denote built-ins — recognizing every built-in in both colon and UCAN spelling, and the parameterized `outlet_query:{outlet_id}` / `outlet_call:{outlet_id}` families for any id — the rule is **closed by construction**: it covers every built-in spelling uniformly and extends automatically to any built-in added later, with no spelling enumeration to maintain. Resolution is applied at the point a custom is admitted, rather than testing only the entry's projected UCAN string, because the masquerade it prevents — a custom that is a distinct ceiling entry yet presents a built-in's privilege when the ceiling is consumed for capability minting — arises specifically from a `Capability` custom value (including one materialized directly from an untrusted, deserialized ceiling that never passed through the colon parser at create time). The clause is stated here as the authoritative, normative invariant so the validator can cite §5.3.1.1 and a custom capability can never masquerade as a privileged built-in.
````

Live text after the cut:

````text
**No privileged-built-in collision.** A custom entry (shape 2 or shape 3 above) is valid only if it does not name a built-in capability under **any** spelling. A custom entry's string MUST NOT denote a built-in capability — neither a built-in's user-facing colon form (e.g. `outlet:query:*`, `outlet:call:*`, `outlet:call:{outlet_id}`, `messages:read`) nor its canonical UCAN form (e.g. `outlet_query:*`, `outlet_call:*`, `context_child:create`), including the parameterized `outlet_query:{outlet_id}` / `outlet_call:{outlet_id}` families for any concrete `outlet_id`. A custom entry that names a built-in under any spelling MUST be rejected at context creation with `InvalidCeilingCategory` (e.g. a custom whose string is `outlet_call:*` — which denotes the `outlet:call:*` built-in — is rejected). This is enforced by **canonical resolution**, not by a denylist of forbidden spellings: an entry is admitted as a custom only if resolving its string through the protocol's single canonical capability parser (`Capability::new`, defined in code at `crates/scp-protocol/src/context/roles.rs`) does **not** yield a built-in capability. Because that parser is the sole authority on which strings denote built-ins — recognizing every built-in in both colon and UCAN spelling, and the parameterized `outlet_query:{outlet_id}` / `outlet_call:{outlet_id}` families for any id — the rule is **closed by construction**: it covers every built-in spelling uniformly and extends automatically to any built-in added later, with no spelling enumeration to maintain. Resolution is applied at the point a custom is admitted, rather than testing only the entry's projected UCAN string, because the masquerade it prevents — a custom that is a distinct ceiling entry yet presents a built-in's privilege when the ceiling is consumed for capability minting — arises specifically from a `Capability` custom value (including one materialized directly from an untrusted, deserialized ceiling that never passed through the colon parser at create time). The clause is stated here as the authoritative, normative invariant so the validator can cite §5.3.1.1 and a custom capability can never masquerade as a privileged built-in.
````

## `.docs/specs/05-contexts.md`, under `## 5.7 Metadata`, line 726 on main when archived

````text
- Active bridges: `Vec<BridgeMetadata>` where each entry describes an active bridge connector registered with the context (§12.2). Bridge metadata is structural because bridge presence materially affects trust evaluation and privacy — a participant cannot give informed consent without knowing that content may flow to an external platform. Bridge metadata is updated whenever a bridge is registered, revoked, or suspended.
````

## `.docs/specs/05-contexts.md`, under `## 5.7 Metadata`, lines 764–791 on main when archived

````text

/// Metadata for an active bridge connector (§12.2).
/// Structural field — always visible before joining.
pub struct BridgeMetadata {
    /// External platform name (e.g., "discord", "slack", "x").
    pub platform: String,
    /// The bridge operator — the human accountable for
    /// bridge behavior (§12.2).
    pub bridge_did: Identifier,
    /// Capabilities the bridge exercises in this context.
    /// Subset of: "relay_messages", "create_shadows",
    /// "attest_identities", "forward_presence".
    pub capabilities: Vec<String>,
    /// Directionality of the bridge.
    pub mode: BridgeDirectionality,
}

/// Whether the bridge relays content in both directions or one.
pub enum BridgeDirectionality {
    /// Platform-to-SCP and SCP-to-platform.
    Full,
    /// Platform-to-SCP only (external content enters SCP,
    /// but SCP messages are not forwarded to the platform).
    ReadOnly,
    /// SCP-to-platform only (SCP messages are forwarded to the
    /// platform, but no external content enters SCP).
    WriteOnly,
}
````

## `.docs/specs/07-trust-validation-and-capabilities.md`, under `#### 7.3.4.1 Capability URI Namespace`, line 542 on main when archived

````text
System capabilities declare what a node does (e.g., relay operation, bridge operation), not what an agent can prove. They are not subject to challenge-response verification.
````

Live text after the cut:

````text
System capabilities declare what a node does (e.g., relay operation), not what an agent can prove. They are not subject to challenge-response verification.
````

## `.docs/specs/07-trust-validation-and-capabilities.md`, under `#### 7.3.4.3 Protocol Capability Registry`, line 610 on main when archived

````text
- `scp:system:bridge-operation` — Platform bridge.
````

## `.docs/specs/07-trust-validation-and-capabilities.md`, under `## 7.6 Attestation as Protocol Primitive`, line 1034 on main when archived

````text
- **Bridges (§12):** Shadow identity claims are bridge operator attestations. Identity claiming is a self-attestation verified against the shadow.
````

## `.docs/specs/09-security-model.md`, under `## 9.2 Identified Threat Vectors and Mitigations`, lines 44–45 on main when archived

````text
**Malicious bridge operator.** A bridge operator (§12) who fabricates shadow messages, drops messages, injects false attestations, or correlates activity across contexts. Note: bridge connectors (translation infrastructure) are not MLS group members, but the bridge operator's identity IS an MLS group member admitted through context governance (§12.6.1) — the operator can read all MLS-encrypted messages. This is an inherent property of bidirectional bridging, which is why bridge admission is a governance decision visible in context metadata (§5.7). Mitigation: bridge provenance (§12.5) makes bridge-originated content distinguishable; bridge registration is per-context (§12.6) limiting correlation; context governance can revoke a bridge at any time (§12.2); attestation freshness checks (§7.4.4) limit false attestation lifetime. See §12.6.2 for the complete bridge threat model.

````

## `.docs/specs/09-security-model.md`, under `#### 9.18.2 Domain Separators`, line 2787 on main when archived

````text
| `"SCP-CLAIM-V1:"` | Shadow identity claim validation | §12.3 |
````

## `.docs/specs/09-security-model.md`, under `#### 9.18.2 Domain Separators`, line 2793 on main when archived

````text
| `"SCP-BRIDGE-REGISTER-V1:"` | Bridge relay registration signing | §12 |
````

Live text after the cut:

````text
| `"SCP-BRIDGE-REGISTER-V1:"` | Bridge relay registration signing | §10.12.4 |
````

## `.docs/specs/09-security-model.md`, under `#### 9.18.3 Key Derivation and HPKE Labels`, line 2836 on main when archived

````text
| `"scp-bridge-credential-v1"` | HKDF info | Bridge credential encryption key derivation | §12 |
````

## `.docs/specs/09-security-model.md`, under `#### 9.18.11 Transport and Relay`, lines 2981–2986 on main when archived

````text
#### 9.18.12 Bridge

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Max shadows per bridge | 10,000 | Maximum shadow identities per bridge connector | §12.3 |

````

## `.docs/specs/10-infrastructure-and-self-hosting.md`, under `## 10.2 Device-as-Node`, lines 31–32 on main when archived

````text
       │                            Natural SCP node: relay, hosting,
       │                            bridge connectors as marginal load.
````

Live text after the cut:

````text
       │                            Natural SCP node: relay, hosting
       │                            as marginal load.
````

## `.docs/specs/10-infrastructure-and-self-hosting.md`, under `## 10.2 Device-as-Node`, line 37 on main when archived

````text
       │                            Hosts bridge connectors.
````

## `.docs/specs/10-infrastructure-and-self-hosting.md`, under `## 10.2 Device-as-Node`, line 48 on main when archived

````text
The **agent workstation** tier is a critical addition to the deployment model. As builder agents (LLMs that generate and manage software) become mainstream, non-technical users are acquiring dedicated always-on hardware to run them. These machines are already always-on, capable, and user-controlled. SCP infrastructure — relays, context hosting, bridge connectors — is marginal additional load on hardware that's already running 24/7. The builder agent that generates an SCP app can also provision the infrastructure: spin up a relay, configure contexts, register outlets — developer and ops in one.
````

Live text after the cut:

````text
The **agent workstation** tier is a critical addition to the deployment model. As builder agents (LLMs that generate and manage software) become mainstream, non-technical users are acquiring dedicated always-on hardware to run them. These machines are already always-on, capable, and user-controlled. SCP infrastructure — relays, context hosting — is marginal additional load on hardware that's already running 24/7. The builder agent that generates an SCP app can also provision the infrastructure: spin up a relay, configure contexts, register outlets — developer and ops in one.
````

## `.docs/specs/10-infrastructure-and-self-hosting.md`, under `## 10.5 SDK Transport Architecture`, line 172 on main when archived

````text
The SCP SDK owns all protocol logic — contexts, agents, trust, capabilities, governance, bridge connectors, provenance. This is the product. Transport is not the product.
````

Live text after the cut:

````text
The SCP SDK owns all protocol logic — contexts, agents, trust, capabilities, governance, provenance. This is the product. Transport is not the product.
````

## `.docs/specs/10-infrastructure-and-self-hosting.md`, under `## 10.10 Business Model Direction`, line 488 on main when archived

````text
**The agent workstation effect.** As builder agents become mainstream and users acquire dedicated always-on hardware to run them (§10.2), the relay economics shift structurally. Relay infrastructure is marginal load on hardware that's already running 24/7. Builder agents can provision SCP infrastructure — relays, context hosting, bridge connectors — as part of generating apps. The "who pays for relays?" question dissolves for users with agent workstations: you already have the hardware, the relay is just another process. Managed infrastructure remains valuable for users without always-on hardware (phone-only users) and for heavy content workloads, but the default self-hosting path becomes significantly more accessible.
````

Live text after the cut:

````text
**The agent workstation effect.** As builder agents become mainstream and users acquire dedicated always-on hardware to run them (§10.2), the relay economics shift structurally. Relay infrastructure is marginal load on hardware that's already running 24/7. Builder agents can provision SCP infrastructure — relays, context hosting — as part of generating apps. The "who pays for relays?" question dissolves for users with agent workstations: you already have the hardware, the relay is just another process. Managed infrastructure remains valuable for users without always-on hardware (phone-only users) and for heavy content workloads, but the default self-hosting path becomes significantly more accessible.
````

## `.docs/specs/10-infrastructure-and-self-hosting.md`, under `### 10.12.11 Self-Hosted Website Surface`, line 852 on main when archived

````text
**Origin-root mount.** In `--self-host` mode the single deployed context is served at the origin root, not only at the canonical `/scp/broadcast/<routing_id>/site/<path>` projection path. `GET /` returns the site's configured `index_path`; `GET /<path>` returns the corresponding site asset. On an exact-path miss the handler applies standard clean-URL resolution against the in-memory path index: an extensionless `<path>` resolves to `<path>.html`, and a directory-style `<path>/` (or `<path>`) resolves to `<path>/index.html`; every candidate is validated through `ContentPath` (so traversal is still rejected) and only a genuine miss returns 404. This is required for browser correctness: an `index.html` referencing root-absolute assets (`/style.css`, `/app.js`) issues those requests at the origin root, which must resolve to the deployed site. The origin-root mount reuses the same content handler as the canonical projection path, so `ContentPath` traversal protection, decryption, `ETag`, `Cache-Control`, and CSP apply identically; it routes only to the single designated default site and never re-exposes the relay upgrade (`/scp/v1`) or bridge routes (`/v1/scp/bridge/*`), which are not mounted on the self-host public surface.
````

Live text after the cut:

````text
**Origin-root mount.** In `--self-host` mode the single deployed context is served at the origin root, not only at the canonical `/scp/broadcast/<routing_id>/site/<path>` projection path. `GET /` returns the site's configured `index_path`; `GET /<path>` returns the corresponding site asset. On an exact-path miss the handler applies standard clean-URL resolution against the in-memory path index: an extensionless `<path>` resolves to `<path>.html`, and a directory-style `<path>/` (or `<path>`) resolves to `<path>/index.html`; every candidate is validated through `ContentPath` (so traversal is still rejected) and only a genuine miss returns 404. This is required for browser correctness: an `index.html` referencing root-absolute assets (`/style.css`, `/app.js`) issues those requests at the origin root, which must resolve to the deployed site. The origin-root mount reuses the same content handler as the canonical projection path, so `ContentPath` traversal protection, decryption, `ETag`, `Cache-Control`, and CSP apply identically; it routes only to the single designated default site and never re-exposes the relay upgrade (`/scp/v1`), which is not mounted on the self-host public surface.
````

## `.docs/specs/10-infrastructure-and-self-hosting.md`, under `## 10.17 Node vs. Participant`, line 1063 on main when archived

````text
- **External (separate process).** The participant client runs in **its own process** and connects to a node's relay over the socket: loopback when on the same box, `wss://` when off-host (the transport-security rules of §10.12.5/§10.12.6 apply to the off-host case). It **brings its own custody**. **Access control for an external participant is cryptographic, not transport-level**: the relay is a protocol-unaware dumb pipe (§10.4), and the participant's authority to read or write context content is enforced by MLS group membership and UCAN capabilities (encryption-as-access-control), exactly as for any participant. External participants reach `/scp/v1` over the node's existing TLS-terminated **Full** public surface — there is no dedicated listener mode, toggle, admission token, or pre-shared secret; relays are anonymous, DHT-auto-discovered dumb pipes that participants do not hand-pick, so reachability is governed entirely by the public-surface selection (§10.12.11), the bind address, and the TLS mode (§10.12.6), exactly as for any client of the relay. Abuse prevention for an open `wss://` relay — a spam, denial-of-service, and storage-abuse vector — is provided by the relay's existing rate limiting and abuse controls (§10.4) together with relay economics (§19.8 Relay Monetization, including `rate_limit_publish`), which satisfy §10.4's "rate limiting and abuse prevention" requirement without an allowlist that is at odds with the anonymous-relay model. Enabling external participants does not expose the dev/control or bridge endpoints, which remain loopback-only: the read-only self-host public surface never mounts `/scp/v1` or `/v1/scp/bridge/*` (§10.12.11 "Origin-root mount").
````

Live text after the cut:

````text
- **External (separate process).** The participant client runs in **its own process** and connects to a node's relay over the socket: loopback when on the same box, `wss://` when off-host (the transport-security rules of §10.12.5/§10.12.6 apply to the off-host case). It **brings its own custody**. **Access control for an external participant is cryptographic, not transport-level**: the relay is a protocol-unaware dumb pipe (§10.4), and the participant's authority to read or write context content is enforced by MLS group membership and UCAN capabilities (encryption-as-access-control), exactly as for any participant. External participants reach `/scp/v1` over the node's existing TLS-terminated **Full** public surface — there is no dedicated listener mode, toggle, admission token, or pre-shared secret; relays are anonymous, DHT-auto-discovered dumb pipes that participants do not hand-pick, so reachability is governed entirely by the public-surface selection (§10.12.11), the bind address, and the TLS mode (§10.12.6), exactly as for any client of the relay. Abuse prevention for an open `wss://` relay — a spam, denial-of-service, and storage-abuse vector — is provided by the relay's existing rate limiting and abuse controls (§10.4) together with relay economics (§19.8 Relay Monetization, including `rate_limit_publish`), which satisfy §10.4's "rate limiting and abuse prevention" requirement without an allowlist that is at odds with the anonymous-relay model. Enabling external participants does not expose the dev/control endpoints, which remain loopback-only: the read-only self-host public surface never mounts `/scp/v1` (§10.12.11 "Origin-root mount").
````

## `.docs/specs/11-prior-art.md`, under `## 11.7 What No Existing Standard Covers`, line 852 on main when archived

````text
- **Provenance:** Protocol-level bridge connectors with provenance-tracked content attribution; non-fungible cross-platform identity attestations with shadow identity claiming
````

Live text after the cut:

````text
- **Provenance:** Non-fungible cross-platform identity attestations
````

## `.docs/specs/15-regulatory-compliance.md`, under `# 15. Regulatory Compliance`, line 5 on main when archived

````text
**Obligations fall on protocol users.** SCP is an open protocol specification, not a service. The protocol does not process data, host content, or operate infrastructure. Entities that build on SCP — app developers, relay operators, managed infrastructure providers, bridge operators — bear the regulatory obligations appropriate to their role. The protocol provides the tools to meet those obligations.
````

Live text after the cut:

````text
**Obligations fall on protocol users.** SCP is an open protocol specification, not a service. The protocol does not process data, host content, or operate infrastructure. Entities that build on SCP — app developers, relay operators, managed infrastructure providers — bear the regulatory obligations appropriate to their role. The protocol provides the tools to meet those obligations.
````

## `.docs/specs/17-persistence-and-storage.md`, under `## 17.17 Capability Selection Is Mandatory, Fails Closed, and Never Defaults`, line 1035 on main when archived

````text
Storage (§17.6) is one instance of a rule that governs **every provider capability** in SCP. A *provider capability* is any pluggable dependency the system resolves to a concrete implementation at construction time and that carries a runtime "which implementation?" choice: client storage (§17.6), relay blob storage (§17.7), identity resolution (`03-identity.md` §3.10), the witness per-subject store (§17.17.4), credential storage, key custody (§17.8), device attestation, and the relay querier are the current set. Each such capability falls under the normative rule stated here.
````

Live text after the cut:

````text
Storage (§17.6) is one instance of a rule that governs **every provider capability** in SCP. A *provider capability* is any pluggable dependency the system resolves to a concrete implementation at construction time and that carries a runtime "which implementation?" choice: client storage (§17.6), relay blob storage (§17.7), identity resolution (`03-identity.md` §3.10), the witness per-subject store (§17.17.4), key custody (§17.8), device attestation, and the relay querier are the current set. Each such capability falls under the normative rule stated here.
````

## `.docs/specs/17-persistence-and-storage.md`, under `### 17.17.2 Security Classification of Development Arms`, line 1053 on main when archived

````text
Many capabilities ship a development/in-memory arm — an implementation intended for testing, CI, or local development. Every such arm MUST be classified, and its classification decides how — and whether — it may exist in a shipped production artifact. The classification is **mandatory before the capability ships**: every provider capability enumerated in §17.17 (client storage, relay blob storage, identity resolution, the witness per-subject store, credential storage, key custody, device attestation, relay querier) MUST have its development arm classified as durability-only or nullifier before that capability is present on any shipped path. A capability shipping with an *unclassified* development arm — one whose classification has never been recorded, so no one has decided whether it is a nullifier — is itself a violation of this section, independent of what the arm later turns out to be: the absence of a classification is a decision not made, which SCP-CAPSEL-8000's "no silent selection" forbids at the classification level.
````

Live text after the cut:

````text
Many capabilities ship a development/in-memory arm — an implementation intended for testing, CI, or local development. Every such arm MUST be classified, and its classification decides how — and whether — it may exist in a shipped production artifact. The classification is **mandatory before the capability ships**: every provider capability enumerated in §17.17 (client storage, relay blob storage, identity resolution, the witness per-subject store, key custody, device attestation, relay querier) MUST have its development arm classified as durability-only or nullifier before that capability is present on any shipped path. A capability shipping with an *unclassified* development arm — one whose classification has never been recorded, so no one has decided whether it is a nullifier — is itself a violation of this section, independent of what the arm later turns out to be: the absence of a classification is a decision not made, which SCP-CAPSEL-8000's "no silent selection" forbids at the classification level.
````

## `.docs/specs/21-documentation.md`, under `### Done`, line 22 on main when archived

````text
| 10 | Wire format tables | §9.5.2, §12.12, §19.15, §22.11, §23.16 | Signed structures, bridge, economy, discovery, sync |
````

Live text after the cut:

````text
| 10 | Wire format tables | §9.5.2, §19.15, §22.11, §23.16 | Signed structures, economy, discovery, sync |
````

## `.docs/specs/21-documentation.md`, under `## 21.14 Compliance Documentation (Agent-Optimized)`, line 505 on main when archived

````text
2. **Wire format reference** — Field-by-field tables for all types that cross the network. Covered in: §12.12 (bridge), §19.15 (economy), §22.11 (discovery). Envelope types in §9.5.2. Sync in §23.16.
````

Live text after the cut:

````text
2. **Wire format reference** — Field-by-field tables for all types that cross the network. Covered in: §19.15 (economy), §22.11 (discovery). Envelope types in §9.5.2. Sync in §23.16.
````

## `.docs/specs/21-documentation.md`, under `## 21.15 Protocol Spec as Standalone Specification`, line 533 on main when archived

````text
| Bridge connectors | §12 | Complete |
````

## `.docs/specs/22-human-readable-addressing.md`, under `### 22.3.1 Handle Outlets`, line 166 on main when archived

````text
5. **Writer verification.** The writer derives the `requester_did`'s key state by replaying its key-event log (`03-identity.md` §3.10.4), takes the key that state names in the `signing_key_id` role, and verifies the P-256 signature over the reconstructed `signed_content`. If verification fails, the request is rejected with a `BRIDGE_NOT_AUTHORIZED` error. The writer MUST hold a key state resolved within the last 300 seconds or cached under a valid bound (§9.10.7).
````

Live text after the cut:

````text
5. **Writer verification.** The writer derives the `requester_did`'s key state by replaying its key-event log (`03-identity.md` §3.10.4), takes the key that state names in the `signing_key_id` role, and verifies the P-256 signature over the reconstructed `signed_content`. If verification fails, the request is rejected. The writer MUST hold a key state resolved within the last 300 seconds or cached under a valid bound (§9.10.7).
````

## `.docs/specs/25-test-vectors.md`, under `### Vector 38: Fingerprint Ordering Is Argument-Order Independent`, lines 616–643 on main when archived

````text
## 25.10 Claim Validation Vectors (§12.3)

Domain: `"SCP-CLAIM-V1:"`

### Vector 22: Shadow Claim Hash

```
Input:
  shadow_id:    "shadow-alice-x-12345"
  claimant_did: "did:dht:z6MkClaim"
  context_id:   "bridge-test-context"
  timestamp:    1700000000

Canonical hash input:
  "SCP-CLAIM-V1:"                              (13 bytes)
  || BE32(20) || "shadow-alice-x-12345"         (4 + 20 = 24 bytes)
  || BE32(17) || "did:dht:z6MkClaim"           (4 + 17 = 21 bytes)
  || BE32(19) || "bridge-test-context"          (4 + 19 = 23 bytes)
  || BE64(1700000000)                           (8 bytes)

Total: 13 + 24 + 21 + 23 + 8 = 89 bytes

Expected SHA-256:
  0xf3469482bb1d91d18e7167d21666fad9476b0559625257589075df6ebca23642
```

The domain separator is 13 ASCII bytes and the preimage is 89. Before 2026-09-10 this vector stated 14 and 90, so an implementer following §25.17 step 3 would have read a correct encoding as wrong. The claim hash is new here: §25.17 step 4 tells an implementer to compare each canonical byte sequence's SHA-256 against an expected hash, and this vector carried none.

````

## `.docs/specs/26-conformance-suite.md`, under `## 26.1 Purpose`, line 10 on main when archived

````text
- **SCP Full Conformance** — all protocol layers including trust, discovery, economy, and bridges.
````

Live text after the cut:

````text
- **SCP Full Conformance** — all protocol layers including trust, discovery, and economy.
````

## `.docs/specs/26-conformance-suite.md`, under `## 26.2 Test Format`, line 21 on main when archived

````text
| **Layer** | Protocol layer (Identity, Context, Messaging, Sync, Trust, Transport, Discovery, Economy, Bridge). |
````

Live text after the cut:

````text
| **Layer** | Protocol layer (Identity, Context, Messaging, Sync, Trust, Transport, Discovery, Economy). |
````

## `.docs/specs/26-conformance-suite.md`, under `### CONF-035: Dynamic Pricing Formula Evaluation (Deterministic)`, lines 429–463 on main when archived

````text
## 26.11 Bridge Tests (§12)

### CONF-036: Bridge Registration and Approval

| Field | Value |
|-------|-------|
| **Layer** | Bridge |
| **Tier** | Full |
| **Spec Sections** | §12.2.1, §12.12 |
| **Preconditions** | Context with governance that can approve bridges. |
| **Steps** | 1. Submit `BridgeRegistrationRequest`. 2. Governance votes to approve. 3. Bridge status changes to `Active`. 4. Bridge appears in context metadata `bridges` field (§5.7). |
| **Expected Outcome** | Registration event in event log. Bridge visible in metadata. Status is `Active`. |

### CONF-037: Shadow Identity Creation and Claiming

| Field | Value |
|-------|-------|
| **Layer** | Bridge |
| **Tier** | Full |
| **Spec Sections** | §12.3, §12.12.3, §12.12.4 |
| **Preconditions** | Active bridge in context. |
| **Steps** | 1. Bridge creates shadow identity for platform user. 2. Shadow has `provenance_status: Shadow`. 3. Platform user creates SCP identity and attestation. 4. User submits `ClaimRequest` with attestation proof. 5. Claim validation hash computed (domain: `"SCP-CLAIM-V1:"`). 6. Shadow status changes to `Claimed`. |
| **Expected Outcome** | Shadow created. Claim succeeds. Provenance status updated. Event log records both events. |

### CONF-038: Bridged Message Provenance Marking

| Field | Value |
|-------|-------|
| **Layer** | Bridge |
| **Tier** | Full |
| **Spec Sections** | §12.5, §12.12.5 |
| **Preconditions** | Active bridge with shadow identity. |
| **Steps** | 1. Bridge relays message from platform user. 2. Message includes `BridgeProvenance` with platform, bridge ID, mode, shadow status. 3. Recipients verify provenance. 4. `BridgeTrustLevel` is `ShadowBridged` (lowest). |
| **Expected Outcome** | Message carries correct provenance. Trust level is distinguishable from native messages. |

````

## `.docs/specs/26-conformance-suite.md`, under `### SCP Full Conformance`, line 526 on main when archived

````text
Tests: All CONF-001 through CONF-042.
````

Live text after the cut:

````text
Tests: CONF-001 through CONF-035 and CONF-039 through CONF-042.
````

## `.docs/specs/26-conformance-suite.md`, under `### SCP Full Conformance`, line 532 on main when archived

````text
- Bridge protocol (registration, shadows, claiming, provenance)
````

## `.docs/specs/27-attestations.md`, under `# 27. Attestations`, line 5 on main when archived

````text
**The author of this section selected the eight; no artifact defines the set.** A name test does not produce it in either direction. `ParticipationProfile` (F8) does not carry the word "attestation," and six further shipped record types do carry it and sit outside the eight: `CounterAttestation`, `KeyDestructionAttestation`, the two distinct `PlatformAttestation` structs, `UcanAttestation`, and `StoredAttestation`, whose doc comment reads "A stored platform identity attestation" and which `BridgeState.attestations` holds in production. §7.6 of the trust spec covers the construct `StoredAttestation` records in its Bridges bullet: "Shadow identity claims are bridge operator attestations. Identity claiming is a self-attestation verified against the shadow." (`.docs/specs/07-trust-validation-and-capabilities.md:1037`). *Derivation:* that list of six comes from one search of the Rust workspace for every public `struct` or `enum` declaration whose name contains `Attestation`, which returns 39 declarations. The list keeps thirteen: the six named above, plus the seven primary types of §27.1.3 the search reaches (F8's `ParticipationProfile` carries no matching name). It drops the other 26, in three groups.
````

Live text after the cut:

````text
**The author of this section selected the eight; no artifact defines the set.** A name test does not produce it in either direction. `ParticipationProfile` (F8) does not carry the word "attestation," and five further shipped record types do carry it and sit outside the eight: `CounterAttestation`, `KeyDestructionAttestation`, the two distinct `PlatformAttestation` structs, and `UcanAttestation`. *Derivation:* that list of five comes from one search of the Rust workspace for every public `struct` or `enum` declaration whose name contains `Attestation`, which returns 38 declarations. The list keeps twelve: the five named above, plus the seven primary types of §27.1.3 the search reaches (F8's `ParticipationProfile` carries no matching name). It drops the other 26, in three groups.
````

## `.docs/specs/27-attestations.md`, under `### 27.1.1 What the word means`, line 40 on main when archived

````text
**Both claims range over a narrower set than the eight families below.** The §7.6 bullets enumerate what "these" covers before the unification sentence: identity links, agent capability metadata, role assignments, outlet integrity attestations, UCAN capability tokens, endorsements, provenance chains, and shadow identity claims. The Trust bullet's participation clause reads, verbatim, "Participation records are computed from verified event attestations" (`.docs/specs/07-trust-validation-and-capabilities.md:1035`), which places the attestations upstream of a participation record rather than calling the record one. §7.4.1 scopes itself the same way, listing eight `type` values — `identity_link | capability_delegation | outlet_integrity | endorsement | role_assignment | agent_capability | context_endorsement | participation_witness`. Its `participation_witness` value names tag 7 of the shipped F2 `AttestationType` enum (§27.3.2), not F8's `ParticipationProfile`. Device attestation (F3), key-custody attestation (F4), KeyPackage attestation (F5), key-destruction attestation (F6), custody-violation attestation (F7), and participation profile (F8) appear in neither list, so neither section claims the envelope covers them.
````

Live text after the cut:

````text
**Both claims range over a narrower set than the eight families below.** The §7.6 bullets enumerate what "these" covers before the unification sentence: identity links, agent capability metadata, role assignments, outlet integrity attestations, UCAN capability tokens, endorsements, and provenance chains. The Trust bullet's participation clause reads, verbatim, "Participation records are computed from verified event attestations" (`.docs/specs/07-trust-validation-and-capabilities.md:1033`), which places the attestations upstream of a participation record rather than calling the record one. §7.4.1 scopes itself the same way, listing eight `type` values — `identity_link | capability_delegation | outlet_integrity | endorsement | role_assignment | agent_capability | context_endorsement | participation_witness`. Its `participation_witness` value names tag 7 of the shipped F2 `AttestationType` enum (§27.3.2), not F8's `ParticipationProfile`. Device attestation (F3), key-custody attestation (F4), KeyPackage attestation (F5), key-destruction attestation (F6), custody-violation attestation (F7), and participation profile (F8) appear in neither list, so neither section claims the envelope covers them.
````

## `.docs/specs/27-attestations.md`, under `### 27.1.2 The membership criterion is undecided`, line 52 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
*Derivation:* §7.6 of the trust spec is that same paragraph carried downstream, so the two artifacts carry one proposition rather than two opposed criteria. Four sentence pairs match: session `:637` "attestation is not a feature of one section — it's a primitive used across the entire protocol" against §7.6 "Attestation is not a feature of any single section of SCP — it is a primitive used by every layer" (`.docs/specs/07-trust-validation-and-capabilities.md:1030`); session `:639` "a single common envelope format" against §7.6 "The common envelope format (§7.4.1) unifies these under a single verifiable structure"; session `:639` "The verification flow is always: check signature → check evidence → check expiry → check revocation" against §7.6 "check signature, check evidence, check expiry, check revocation"; and session `:637` "Different claim content, same envelope structure, same verification mechanics" against §7.6 "What varies is the claim content and how it's evaluated". The artifact flow in `AGENTS.md` runs "plans → specs → ADRs → stories → source code," so the planning session sits above §7.6 and governs it; the two do not conflict, so nothing turns on that ordering here.
````

Live text after the cut:

````text
*Derivation:* §7.6 of the trust spec is that same paragraph carried downstream, so the two artifacts carry one proposition rather than two opposed criteria. Four sentence pairs match: session `:637` "attestation is not a feature of one section — it's a primitive used across the entire protocol" against §7.6 "Attestation is not a feature of any single section of SCP — it is a primitive used by every layer" (`.docs/specs/07-trust-validation-and-capabilities.md:1029`); session `:638` "a single common envelope format" against §7.6 "The common envelope format (§7.4.1) unifies these under a single verifiable structure"; session `:638` "The verification flow is always: check signature → check evidence → check expiry → check revocation" against §7.6 "check signature, check evidence, check expiry, check revocation"; and session `:636` "Different claim content, same envelope structure, same verification mechanics" against §7.6 "What varies is the claim content and how it's evaluated". The artifact flow in `AGENTS.md` runs "plans → specs → ADRs → stories → source code," so the planning session sits above §7.6 and governs it; the two do not conflict, so nothing turns on that ordering here.
````

## `.docs/specs/27-attestations.md`, under `### 27.1.3 The eight families`, line 83 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
| F3 | §9.3.1 of the security spec, Reading a device attestation, which states the service-record entry format, the binding digest, and the reader's procedure and outcomes; §9.3 of the security spec — a trust-signal table row (`.docs/specs/09-security-model.md:175`) and three paragraphs (`:181`, `:187`, `:189`), two of which state what an unsupported device produces; §16.12.4 of the test-infrastructure spec (a conformance macro) | ADR-006 (the in-memory platform adapter), ADR-025 (the Apple adapter) and ADR-027 (the Android adapter), each amended on 2026-09-27 to mint over §9.3.1's binding digest | none |
````

Live text after the cut:

````text
| F3 | §9.3.1 of the security spec, Reading a device attestation, which states the service-record entry format, the binding digest, and the reader's procedure and outcomes; §9.3 of the security spec — a trust-signal table row (`.docs/specs/09-security-model.md:173`) and three paragraphs (`:179`, `:185`, `:187`), two of which state what an unsupported device produces; §16.12.4 of the test-infrastructure spec (a conformance macro) | ADR-006 (the in-memory platform adapter), ADR-025 (the Apple adapter) and ADR-027 (the Android adapter), each amended on 2026-09-27 to mint over §9.3.1's binding digest | none |
````

## `.docs/specs/27-attestations.md`, under `### 27.3.2 F2 — Trust attestation`, line 240 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**Outside the signed scope:** `signature`, `renewal_interval`, and `renewed_at`. **Consolidated** from §25.20 of the test-vector spec, which is the only artifact that states the exclusion (`.docs/specs/25-test-vectors.md:856`):
````

Live text after the cut:

````text
**Outside the signed scope:** `signature`, `renewal_interval`, and `renewed_at`. **Consolidated** from §25.20 of the test-vector spec, which is the only artifact that states the exclusion (`.docs/specs/25-test-vectors.md:828`):
````

## `.docs/specs/27-attestations.md`, under `### 27.3.2 F2 — Trust attestation`, line 246 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**Contradiction C3 — §7.4.1 of the trust spec signs every field; §9.5.2 of the security spec signs nine.** §7.4.1 writes the envelope's signature as "P256Signature (issuer's cryptographic signature over all fields except itself)" (`.docs/specs/07-trust-validation-and-capabilities.md:955`) and lists `renewed_at` among the envelope's fields. §9.5.2 of the security spec tabulates nine fields and omits both renewal fields, and `canonical_attestation_bytes` reproduces the nine. A signer built from §7.4.1 and a verifier built from §9.5.2 never agree on a byte. Under §9.5.2 a holder or relay rewrites `renewed_at` on a signed attestation undetectably, and `check_attestation_freshness` reads that field. `.docs/audits/crypto-constructions-audit.md` carries the standing CRITICAL finding "[CRYPTO-12] Attestation Signature Input Not Canonicalized" against the same §7.4.1 envelope. Open question OQ-30.
````

Live text after the cut:

````text
**Contradiction C3 — §7.4.1 of the trust spec signs every field; §9.5.2 of the security spec signs nine.** §7.4.1 writes the envelope's signature as "P256Signature (issuer's cryptographic signature over all fields except itself)" (`.docs/specs/07-trust-validation-and-capabilities.md:954`) and lists `renewed_at` among the envelope's fields. §9.5.2 of the security spec tabulates nine fields and omits both renewal fields, and `canonical_attestation_bytes` reproduces the nine. A signer built from §7.4.1 and a verifier built from §9.5.2 never agree on a byte. Under §9.5.2 a holder or relay rewrites `renewed_at` on a signed attestation undetectably, and `check_attestation_freshness` reads that field. `.docs/audits/crypto-constructions-audit.md` carries the standing CRITICAL finding "[CRYPTO-12] Attestation Signature Input Not Canonicalized" against the same §7.4.1 envelope. Open question OQ-30.
````

## `.docs/specs/27-attestations.md`, under `### 27.3.2 F2 — Trust attestation`, line 248 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**Contradiction C4 — §7.4.1's envelope names one field differently and omits another the code carries.** §7.4.1 of the trust spec writes the expiry field as `expires: u64?` (`.docs/specs/07-trust-validation-and-capabilities.md:952`); §9.5.2 of the security spec tabulates `expires_at`, and the shipped struct declares `pub expires_at: Option<u64>` with no serde rename. §7.4.1's envelope lists no `renewal_interval`; the shipped struct declares `pub renewal_interval: Option<Duration>`. §7.4.1 fixes the wire encoding — "Serialization: MessagePack, matching the SCP standard serialization format" — so a field-name divergence changes the bytes on the wire. Open question OQ-30.
````

Live text after the cut:

````text
**Contradiction C4 — §7.4.1's envelope names one field differently and omits another the code carries.** §7.4.1 of the trust spec writes the expiry field as `expires: u64?` (`.docs/specs/07-trust-validation-and-capabilities.md:951`); §9.5.2 of the security spec tabulates `expires_at`, and the shipped struct declares `pub expires_at: Option<u64>` with no serde rename. §7.4.1's envelope lists no `renewal_interval`; the shipped struct declares `pub renewal_interval: Option<Duration>`. §7.4.1 fixes the wire encoding — "Serialization: MessagePack, matching the SCP standard serialization format" — so a field-name divergence changes the bytes on the wire. Open question OQ-30.
````

## `.docs/specs/27-attestations.md`, under `### 27.3.3 F3 — Device attestation: §9.3.1 defines the construction, and the shipped code carries none`, line 274 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**What the absent input costs.** *Derivation from a cited artifact:* §7.3.5 of the trust spec states "The primary Sybil resistance mechanism is the DeviceAttestation (§9.3), which binds DIDs to hardware-attested devices" (`.docs/specs/07-trust-validation-and-capabilities.md:737`), and the shipped `attest()` takes no identifier, so a token it mints binds to no identity and an attacker who obtains any valid token files it under any identifier. Whether the protocol requires that binding is open question OQ-2. The next paragraph shows that the Kotlin SDK computes a binding the Rust trait discards, and that the Swift SDK hands Apple the 32-byte `challenge` its caller supplies, unchanged.
````

Live text after the cut:

````text
**What the absent input costs.** *Derivation from a cited artifact:* §7.3.5 of the trust spec states "The primary Sybil resistance mechanism is the DeviceAttestation (§9.3), which binds DIDs to hardware-attested devices" (`.docs/specs/07-trust-validation-and-capabilities.md:736`), and the shipped `attest()` takes no identifier, so a token it mints binds to no identity and an attacker who obtains any valid token files it under any identifier. Whether the protocol requires that binding is open question OQ-2. The next paragraph shows that the Kotlin SDK computes a binding the Rust trait discards, and that the Swift SDK hands Apple the 32-byte `challenge` its caller supplies, unchanged.
````

## `.docs/specs/27-attestations.md`, under `### 27.4.1 F1 — Identity-link attestation`, line 507 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**Step 6 of §3.5.4 of the identity spec depends on one of those six checks.** That step reads: "**Trust the self-attestation.** Because issuer == subject, the DID key signature is sufficient." §3.5.2 of the identity spec states the same invariant only as a struct comment (`.docs/specs/03-identity.md:204`): "subject: DID, // Same as issuer (self-attestation)". `subject` sits inside the signed scope (§27.3.1). *Derivation:* an issuer A can therefore mint an attestation whose `subject` names a victim B, sign it with A's `#active`, and pass `verify_signature`, because the shipped verifier checks the signature alone; step 6's justification does not hold on that record, and a consumer reading `subject` attributes the platform handle to B. Open question OQ-39.
````

Live text after the cut:

````text
**Step 6 of §3.5.4 of the identity spec depends on one of those six checks.** That step reads: "**Trust the self-attestation.** Because issuer == subject, the DID key signature is sufficient." §3.5.2 of the identity spec states the same invariant only as a struct comment (`.docs/specs/03-identity.md:203`): "subject: DID, // Same as issuer (self-attestation)". `subject` sits inside the signed scope (§27.3.1). *Derivation:* an issuer A can therefore mint an attestation whose `subject` names a victim B, sign it with A's `#active`, and pass `verify_signature`, because the shipped verifier checks the signature alone; step 6's justification does not hold on that record, and a consumer reading `subject` attributes the platform handle to B. Open question OQ-39.
````

## `.docs/specs/27-attestations.md`, under `### 27.4.1 F1 — Identity-link attestation`, line 509 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**The revocation endpoint has no implementation.** *Derivation:* the string `AttestationRevocations` appears in two files and four lines — `.docs/specs/03-identity.md:246` (§3.5.2) and `:373` (§3.5.6), and `.docs/specs/18-addressability-and-deployment.md:62` (the §18.2.2 service-endpoint table) and `:132` (that section's example document) — and in no Rust, Python, TypeScript, Swift, or Kotlin file. It appears in no line of `.docs/specs/07-trust-validation-and-capabilities.md`; the §18.2.2 table row points its Spec Reference column at §7.4.4 of the trust spec, which states the revocation duty without naming the endpoint. Open question OQ-16.
````

Live text after the cut:

````text
**The revocation endpoint has no implementation.** *Derivation:* the string `AttestationRevocations` appears in two files and four lines — `.docs/specs/03-identity.md:245` (§3.5.2) and `:334` (§3.5.6), and `.docs/specs/18-addressability-and-deployment.md:62` (the §18.2.2 service-endpoint table) and `:132` (that section's example document) — and in no Rust, Python, TypeScript, Swift, or Kotlin file. It appears in no line of `.docs/specs/07-trust-validation-and-capabilities.md`; the §18.2.2 table row points its Spec Reference column at §7.4.4 of the trust spec, which states the revocation duty without naming the endpoint. Open question OQ-16.
````

## `.docs/specs/27-attestations.md`, under `### 27.4.2 F2 — Trust attestation`, line 523 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**Step 2 tests presence and a type string; it does not verify evidence.** *Derivation from shipped code:* `validate_evidence` rejects two conditions and no others — `attestation.evidence.is_none()` on the two types that require evidence, and `evidence.evidence_type.is_empty()` — and never reads `evidence.data`, which is declared `pub data: serde_json::Value`. So an `OutletIntegrity` attestation carrying `evidence_type: "x"` and `data: null` passes all five steps. §7.4.2 of the trust spec carries seven type bullets, and three of them state a `Verification:` procedure: capability delegation, "Verification: cryptographic chain validation" (`.docs/specs/07-trust-validation-and-capabilities.md:986`); outlet integrity, "Verification: deterministic testing (Layer 2)"; and role assignment, "Verification: validate against governance model and UCAN chain". A fourth, identity link, states a verification sentence without a procedure — "Verification of the evidence is automated where possible". The remaining three — agent capability, endorsement, and context endorsement — state none; the endorsement bullet says why: "No objective evidence — the value comes from the issuer's own participation record and the attestation's accuracy history." No shipped component runs any of the three stated procedures. Open question OQ-40.
````

Live text after the cut:

````text
**Step 2 tests presence and a type string; it does not verify evidence.** *Derivation from shipped code:* `validate_evidence` rejects two conditions and no others — `attestation.evidence.is_none()` on the two types that require evidence, and `evidence.evidence_type.is_empty()` — and never reads `evidence.data`, which is declared `pub data: serde_json::Value`. So an `OutletIntegrity` attestation carrying `evidence_type: "x"` and `data: null` passes all five steps. §7.4.2 of the trust spec carries seven type bullets, and three of them state a `Verification:` procedure: capability delegation, "Verification: cryptographic chain validation" (`.docs/specs/07-trust-validation-and-capabilities.md:985`); outlet integrity, "Verification: deterministic testing (Layer 2)"; and role assignment, "Verification: validate against governance model and UCAN chain". A fourth, identity link, states a verification sentence without a procedure — "Verification of the evidence is automated where possible". The remaining three — agent capability, endorsement, and context endorsement — state none; the endorsement bullet says why: "No objective evidence — the value comes from the issuer's own participation record and the attestation's accuracy history." No shipped component runs any of the three stated procedures. Open question OQ-40.
````

## `.docs/specs/27-attestations.md`, under `### 27.4.2 F2 — Trust attestation`, line 539 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**Threshold checking is a fourth entry point, and two spec sections disagree about whether the protocol enforces its result.** `check_threshold_attestation` counts attestations of one type across an attestor set and scores independence by penalizing shared context memberships and mutual endorsements. §7.3.5 of the trust spec states that the protocol does not enforce the result (`.docs/specs/07-trust-validation-and-capabilities.md:735`): "Independence is verified by the consumer, not enforced by the protocol." §22.13.3 of the human-readable-addressing spec states the opposite for one named context (`.docs/specs/22-human-readable-addressing.md:1247`): "The Verified bootstrap context requires endorsement independence checking as part of its `ContextSybilPolicy::high_trust()` admission policy. This is a normative requirement. … Implementations MUST add this wiring." It goes on: "the admission flow MUST additionally invoke `check_threshold_attestation` on the Endorsements signal category when the policy requires endorsements." *Derivation from shipped code:* the code follows §22.13.3 — `RequiredSignal` carries the `threshold_requirement: Option<ThresholdRequirement>` field §22.13.3 mandates, and `evaluate_sybil_resistance` calls `check_endorsement_independence`, which calls `check_threshold_attestation`. So the protocol does enforce the independence result on that path, and §7.3.5's sentence does not hold over it. Open question OQ-43.
````

Live text after the cut:

````text
**Threshold checking is a fourth entry point, and two spec sections disagree about whether the protocol enforces its result.** `check_threshold_attestation` counts attestations of one type across an attestor set and scores independence by penalizing shared context memberships and mutual endorsements. §7.3.5 of the trust spec states that the protocol does not enforce the result (`.docs/specs/07-trust-validation-and-capabilities.md:734`): "Independence is verified by the consumer, not enforced by the protocol." §22.13.3 of the human-readable-addressing spec states the opposite for one named context (`.docs/specs/22-human-readable-addressing.md:1247`): "The Verified bootstrap context requires endorsement independence checking as part of its `ContextSybilPolicy::high_trust()` admission policy. This is a normative requirement. … Implementations MUST add this wiring." It goes on: "the admission flow MUST additionally invoke `check_threshold_attestation` on the Endorsements signal category when the policy requires endorsements." *Derivation from shipped code:* the code follows §22.13.3 — `RequiredSignal` carries the `threshold_requirement: Option<ThresholdRequirement>` field §22.13.3 mandates, and `evaluate_sybil_resistance` calls `check_endorsement_independence`, which calls `check_threshold_attestation`. So the protocol does enforce the independence result on that path, and §7.3.5's sentence does not hold over it. Open question OQ-43.
````

## `.docs/specs/27-attestations.md`, under `### 27.4.2 F2 — Trust attestation`, line 543 on main when archived

S2 changed only the line number here. On main the cite pointed at a §3.5.5 shadow-claim line, which S2 deleted, instead of the §3.5.4 cache list the sentence quotes; the new number points at that list.

````text
**Verification is cacheable by class, and one of the two TTLs matches no artifact.** `AttestationVerificationCache` keys on attestation id and expires entries by the class constants `REFERENCE_TTL_SECS` (3600) and `CRYPTOGRAPHIC_TTL_SECS` (86400). §3.5.4 of the identity spec defines one cache and scopes it to Reference attestations (`.docs/specs/03-identity.md:296`): "Consumer-side. Each consumer maintains its own cache of Reference attestation verification results. - TTL: 1 hour. … - Cache key: attestation ID." The same list closes "Class 1 attestations do not require caching — DID signature verification is deterministic and fast." *Derivation:* the 3600-second Reference constant matches that TTL and the 86400-second Cryptographic constant matches no artifact.
````

Live text after the cut:

````text
**Verification is cacheable by class, and one of the two TTLs matches no artifact.** `AttestationVerificationCache` keys on attestation id and expires entries by the class constants `REFERENCE_TTL_SECS` (3600) and `CRYPTOGRAPHIC_TTL_SECS` (86400). §3.5.4 of the identity spec defines one cache and scopes it to Reference attestations (`.docs/specs/03-identity.md:262`): "Consumer-side. Each consumer maintains its own cache of Reference attestation verification results. - TTL: 1 hour. … - Cache key: attestation ID." The same list closes "Class 1 attestations do not require caching — DID signature verification is deterministic and fast." *Derivation:* the 3600-second Reference constant matches that TTL and the 86400-second Cryptographic constant matches no artifact.
````

## `.docs/specs/27-attestations.md`, under `### 27.4.2 F2 — Trust attestation`, line 545 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**The cache stores a verification result under a key revocation does not change.** The entry type is `Option<&Result<(), TrustError>>`, returned by `get(&self, attestation_id: &str, now: u64)`, so a cached positive outcome survives for its TTL. For F1 the id stays stable across revocation: `compute_id` takes `issuer`, `claim.platform`, `claim.platform_handle`, and `issued_at`, none of which the issuer changes when republishing with `revocation_status: Revoked`. §7.4.4 of the trust spec states the duty that bears on this (`.docs/specs/07-trust-validation-and-capabilities.md:1010`): "Agents that cached a previous verification SHOULD re-check on a defined interval (RECOMMENDED: at least once per hour for security-critical attestations, once per day for others). A revoked attestation MUST NOT be accepted by validators for any purpose." No component invalidates a cache entry on revocation, and a workspace search for `AttestationVerificationCache` finds the type only in its own declaration and its own unit tests, so no shipped path caches a verification result today. Open question OQ-41.
````

Live text after the cut:

````text
**The cache stores a verification result under a key revocation does not change.** The entry type is `Option<&Result<(), TrustError>>`, returned by `get(&self, attestation_id: &str, now: u64)`, so a cached positive outcome survives for its TTL. For F1 the id stays stable across revocation: `compute_id` takes `issuer`, `claim.platform`, `claim.platform_handle`, and `issued_at`, none of which the issuer changes when republishing with `revocation_status: Revoked`. §7.4.4 of the trust spec states the duty that bears on this (`.docs/specs/07-trust-validation-and-capabilities.md:1009`): "Agents that cached a previous verification SHOULD re-check on a defined interval (RECOMMENDED: at least once per hour for security-critical attestations, once per day for others). A revoked attestation MUST NOT be accepted by validators for any purpose." No component invalidates a cache entry on revocation, and a workspace search for `AttestationVerificationCache` finds the type only in its own declaration and its own unit tests, so no shipped path caches a verification result today. Open question OQ-41.
````

## `.docs/specs/27-attestations.md`, under `### 27.4.3 F3 — Device attestation`, line 576 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**§9.3.1 of the security spec states what a production verifier checks, and the shipped code runs none of it.** §9.3.1 gives the reader's procedure and its return type, `DeviceAttestationVerdict`, with the four variants `Verified`, `Absent`, `Rejected{cause}` and `Unverifiable{cause}`. For App Attest the reader verifies the certificate chain to Apple's App Attestation Root CA at the credential certificate's minting time and compares the credential certificate's nonce against `SHA-256(authData ‖ D)`. For Play Integrity the reader verifies a verdict signed by the verifier the context's `accepted_android_packages` names for the app's package, the party whose Google Cloud project Google links to that package, because no peer can decode the token without Google's servers, so a Play Integrity pass is trust in that verifier. §9.3.1 also states that a pass proves no distinct device. §9.3.1 admits an identifier under `require_device_attestation` only on `Verified`, so the map-key gate above diverges from it; SCP-316, the device-attestation reader story of `.docs/prds/main.json`, carries the fix. Before §9.3.1, §9.3 of the security spec repositioned the family rather than specifying it (`.docs/specs/09-security-model.md:187`): "Device attestation (Apple App Attest, Google Play Integrity) is an optional SDK-level trust signal, not a protocol-level uniqueness gate." The same paragraph states what an unsupported device produces: "Its absence is expected — desktop users, non-native clients, protocol-only implementations — and is not penalizing." The next paragraph stated the platform scope: "**Desktop gap acknowledged.** macOS, Linux, and Windows have no App Attest or Play Integrity equivalent." That sentence was out of date, because App Attest reaches macOS 27 and later, and §9.3 now says so. ADR-025 and ADR-027 describe the platform-side mint, and their 2026-09-27 amendments carry `D` into it. Open question OQ-2 records the answer.
````

Live text after the cut:

````text
**§9.3.1 of the security spec states what a production verifier checks, and the shipped code runs none of it.** §9.3.1 gives the reader's procedure and its return type, `DeviceAttestationVerdict`, with the four variants `Verified`, `Absent`, `Rejected{cause}` and `Unverifiable{cause}`. For App Attest the reader verifies the certificate chain to Apple's App Attestation Root CA at the credential certificate's minting time and compares the credential certificate's nonce against `SHA-256(authData ‖ D)`. For Play Integrity the reader verifies a verdict signed by the verifier the context's `accepted_android_packages` names for the app's package, the party whose Google Cloud project Google links to that package, because no peer can decode the token without Google's servers, so a Play Integrity pass is trust in that verifier. §9.3.1 also states that a pass proves no distinct device. §9.3.1 admits an identifier under `require_device_attestation` only on `Verified`, so the map-key gate above diverges from it; SCP-316, the device-attestation reader story of `.docs/prds/main.json`, carries the fix. Before §9.3.1, §9.3 of the security spec repositioned the family rather than specifying it (`.docs/specs/09-security-model.md:185`): "Device attestation (Apple App Attest, Google Play Integrity) is an optional SDK-level trust signal, not a protocol-level uniqueness gate." The same paragraph states what an unsupported device produces: "Its absence is expected — desktop users, non-native clients, protocol-only implementations — and is not penalizing." The next paragraph stated the platform scope: "**Desktop gap acknowledged.** macOS, Linux, and Windows have no App Attest or Play Integrity equivalent." That sentence was out of date, because App Attest reaches macOS 27 and later, and §9.3 now says so. ADR-025 and ADR-027 describe the platform-side mint, and their 2026-09-27 amendments carry `D` into it. Open question OQ-2 records the answer.
````

## `.docs/specs/27-attestations.md`, under `### 27.4.6 F6 — Key-destruction attestation`, line 718 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**Contradiction C19 — §9.15 gives its signed record the name the code gives an unsigned one.** §9.15 of the security spec specifies the record as `KeyDestructionAttestation { contextID, memberDID, destroyedAt, platformAttestation, method, signature }` (`.docs/specs/09-security-model.md:1380`). The shipped `KeyDestructionAttestation` carries `context_id`, `level`, `attested_at`, `mls_group_destroyed`, and `sender_keys_destroyed`, and no signature; the struct matching §9.15's six fields ships under a different name, `PublishableKeyDestructionAttestation`. An implementer who reads §9.15 and greps for its struct name binds the unsigned type. Open question OQ-25.
````

Live text after the cut:

````text
**Contradiction C19 — §9.15 gives its signed record the name the code gives an unsigned one.** §9.15 of the security spec specifies the record as `KeyDestructionAttestation { contextID, memberDID, destroyedAt, platformAttestation, method, signature }` (`.docs/specs/09-security-model.md:1378`). The shipped `KeyDestructionAttestation` carries `context_id`, `level`, `attested_at`, `mls_group_destroyed`, and `sender_keys_destroyed`, and no signature; the struct matching §9.15's six fields ships under a different name, `PublishableKeyDestructionAttestation`. An implementer who reads §9.15 and greps for its struct name binds the unsigned type. Open question OQ-25.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 809 on main when archived

````text
**OQ-1 — What criterion decides membership in the attestation category, and which records does it admit?** *Undefined:* §7.4 of the trust spec's "signed claims by identities about something" admits ten of the eleven structures §9.5.2 of the security spec tabulates and states no test that separates the ten from each other (§27.1.2), and no artifact defines the set of eight this section gathers. The rule must also decide ten records the section leaves out. Six carry the word: `CounterAttestation`, `KeyDestructionAttestation`, the two `PlatformAttestation` structs, `UcanAttestation`, and `StoredAttestation`, the bridge-operator record §7.6 of the trust spec covers in its Bridges bullet and §12 of the platform-bridge-connectors spec specifies (see OQ-28). Three do not: the UCAN capability delegation that §7.4.2 of the trust spec names as an attestation type with its own format; `ChallengeVerification`, which §7.3.4 of the trust spec specifies with a record format (`.docs/specs/07-trust-validation-and-capabilities.md:437`), §9.18.2 of the security spec gives its own domain separator, §7.4.1 of the trust spec calls F8's sibling, and the `scp-protocol` crate ships with a verifier; and the shadow identity claim, which §7.6's Bridges bullet names — "Shadow identity claims are bridge operator attestations" — and which carries the registered separator `"SCP-CLAIM-V1:"` (§9.18.2 of the security spec), a byte-exact vector (§25.10 of the test-vector spec), and an implementation in the `scp-protocol` crate. The tenth is `DataProvenance`, specified by §7.7.1 of the trust spec: §7.6's Security bullet calls provenance chains attestations — "Provenance chains are sequences of attestations about where data came from" (`.docs/specs/07-trust-validation-and-capabilities.md:1036`) — while the shipped struct declares twelve fields and no signature, so §7.4's "signed claims" wording excludes it and §7.6's bullet admits it. *Derivation:* `ChallengeVerification` exhibits all three of §27.1.2's indicators, which F3, F4, F6, and F7 do not, so a criterion that admits the eight and excludes it is not a criterion the indicators produce. *Should define it:* §7.4 of the trust spec, which carries the corpus's only membership sentence, amended to state a test. §27.1.2 shows that the corpus states one criterion and no second one: the paragraph at `.docs/planning-sessions/planning-session-02.md:637` enumerates seven constructs and reports two properties they share, and §7.6 of the trust spec carries that same paragraph downstream, so the amendment states a test the corpus does not yet carry rather than reconciling two artifacts. §27.1 then enumerates against the test. *Breaks meanwhile:* a reviewer cannot tell whether a ninth construct belongs to this surface, so the ninth family drifts the way the first eight did.
````

Live text after the cut:

````text
**OQ-1 — What criterion decides membership in the attestation category, and which records does it admit?** *Undefined:* §7.4 of the trust spec's "signed claims by identities about something" admits ten of the eleven structures §9.5.2 of the security spec tabulates and states no test that separates the ten from each other (§27.1.2), and no artifact defines the set of eight this section gathers. The rule must also decide eight records the section leaves out. Five carry the word: `CounterAttestation`, `KeyDestructionAttestation`, the two `PlatformAttestation` structs, and `UcanAttestation`. Two do not: the UCAN capability delegation that §7.4.2 of the trust spec names as an attestation type with its own format; and `ChallengeVerification`, which §7.3.4 of the trust spec specifies with a record format (`.docs/specs/07-trust-validation-and-capabilities.md:437`), §9.18.2 of the security spec gives its own domain separator, §7.4.1 of the trust spec calls F8's sibling, and the `scp-protocol` crate ships with a verifier. The eighth is `DataProvenance`, specified by §7.7.1 of the trust spec: §7.6's Security bullet calls provenance chains attestations — "Provenance chains are sequences of attestations about where data came from" (`.docs/specs/07-trust-validation-and-capabilities.md:1034`) — while the shipped struct declares twelve fields and no signature, so §7.4's "signed claims" wording excludes it and §7.6's bullet admits it. *Derivation:* `ChallengeVerification` exhibits all three of §27.1.2's indicators, which F3, F4, F6, and F7 do not, so a criterion that admits the eight and excludes it is not a criterion the indicators produce. *Should define it:* §7.4 of the trust spec, which carries the corpus's only membership sentence, amended to state a test. §27.1.2 shows that the corpus states one criterion and no second one: the paragraph at `.docs/planning-sessions/planning-session-02.md:637` enumerates seven constructs and reports two properties they share, and §7.6 of the trust spec carries that same paragraph downstream, so the amendment states a test the corpus does not yet carry rather than reconciling two artifacts. §27.1 then enumerates against the test. *Breaks meanwhile:* a reviewer cannot tell whether a ninth construct belongs to this surface, so the ninth family drifts the way the first eight did.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 839 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**OQ-16 — Which component implements the `AttestationRevocations` service endpoint?** *Undefined:* two spec sections require verifiers to query it — §3.5.2 of the identity spec (`.docs/specs/03-identity.md:246`) and §3.5.6 of the same spec, which calls the check "ALWAYS required regardless of `revocation_status` value" — and §18.2.2 of the addressability spec lists it as a service type (`.docs/specs/18-addressability-and-deployment.md:62`), pointing its Spec Reference column at §7.4.4 of the trust spec. No source file in any language references it (§27.4.1). *Should define it:* §7.4.4 of the trust spec and §18.2.2 of the addressability spec. *Breaks meanwhile:* §3.5.2 of the identity spec's mandatory revocation check cannot be performed, so a revoked F1 attestation stays verifiable.
````

Live text after the cut:

````text
**OQ-16 — Which component implements the `AttestationRevocations` service endpoint?** *Undefined:* two spec sections require verifiers to query it — §3.5.2 of the identity spec (`.docs/specs/03-identity.md:245`) and §3.5.6 of the same spec, which calls the check "ALWAYS required regardless of `revocation_status` value" — and §18.2.2 of the addressability spec lists it as a service type (`.docs/specs/18-addressability-and-deployment.md:62`), pointing its Spec Reference column at §7.4.4 of the trust spec. No source file in any language references it (§27.4.1). *Should define it:* §7.4.4 of the trust spec and §18.2.2 of the addressability spec. *Breaks meanwhile:* §3.5.2 of the identity spec's mandatory revocation check cannot be performed, so a revoked F1 attestation stays verifiable.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 863 on main when archived

````text
**OQ-28 — Should the identity-link claim have one wire format, two, or three?** *Undefined:* F1 is a standalone struct with a MessagePack claim and its own domain separator; F2 carries the same logical claim as `AttestationType::IdentityLink` with a JSON claim and a different field set (§27.6). §3.5.2 of the identity spec says F1 uses the §7.4.1 envelope; §9.5.2 of the security spec says the two canonicalization schemes are independent. §12 of the platform-bridge-connectors spec specifies a third shape, issued by a party that is neither the subject nor the issuer of the other two (`.docs/specs/12-platform-bridge-connectors.md:499`): "Platform vouches for a user's identity. This produces an `IdentityLink` attestation (§3.5) signed by the bridge operator, asserting the platform's confidence in the mapping between the platform handle and the user." The same section gives it its own evidence schema — `evidence_type`, `verification_method`, `verified_at`, `platform_confidence`, `additional_signals` (`:525`–`:530`) — and its own expiry rule: "The bridge node stores the attestation and signs it with the operator's DID. Attestation expiry defaults to 24 hours; the platform MAY request a different TTL." Its shipped record is `StoredAttestation`. *Derivation:* a bridge-operator issuer contradicts F1's structural check that `issuer` equals `subject`, so the third shape cannot be an F1 record. *Should define it:* §7.4.1 of the trust spec, §3.5.2 of the identity spec, and §12 of the platform-bridge-connectors spec, together. *Breaks meanwhile:* a consumer that receives an identity-link claim must guess which of three verifiers to run, `attestation_count` counts one shape while §3.5 of the identity spec governs another, and the bridge shape has no canonicalization, no domain separator, and no verifier at all.
````

Live text after the cut:

````text
**OQ-28 — Should the identity-link claim have one wire format or two?** *Undefined:* F1 is a standalone struct with a MessagePack claim and its own domain separator; F2 carries the same logical claim as `AttestationType::IdentityLink` with a JSON claim and a different field set (§27.6). §3.5.2 of the identity spec says F1 uses the §7.4.1 envelope; §9.5.2 of the security spec says the two canonicalization schemes are independent. *Should define it:* §7.4.1 of the trust spec and §3.5.2 of the identity spec, together. *Breaks meanwhile:* a consumer that receives an identity-link claim must guess which of two verifiers to run, and `attestation_count` counts one shape while §3.5 of the identity spec governs another.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 873 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**OQ-33 — What does §9.3 of the security spec state that an unsupported device produces?** *Settled upstream; ADR-025 and the Swift adapter now follow it:* the no-dev-stand-in tenet of `AGENTS.md` already decides that the adapter fails closed. It forbids "a hardcoded/placeholder/reconstructed-from-args value" that "may be reachable on a shipped production path," and `.docs/standards/sdk-common.md` §Stub and Placeholder Policy admits no exception: the prove-absence gate "admits **zero nullifier features — no exceptions**. There is no "documented," "tracked," or "legible" allowlisted nullifier edge." `AppleDeviceAttestation.attest` and `assertRequest` throw a typed error, and return no bytes, whenever `DCAppAttestService.shared.isSupported` is false (§27.3.3, contradiction C8, resolved). *§9.3.1 of the security spec now answers the question the tenet left open:* "An unsupported device, a simulator, and a desktop client without App Attest publish no `ScpDeviceAttestation` entry, and a reader returns `Absent` for them," and a placeholder token returns `Rejected{MalformedToken}` at every reader. ADR-025's 2026-09-27 amendments remove the synthetic token from the decision, and the Swift adapter returns none. Before §9.3.1 a human had to decide whether §9.3 needed a sentence naming what an unsupported device produces, or whether its two existing sentences already cover a simulator and an unsupported iOS device (`.docs/specs/09-security-model.md:187`): "Its absence is expected — desktop users, non-native clients, protocol-only implementations — and is not penalizing," and "macOS, Linux, and Windows have no App Attest or Play Integrity equivalent" (the second sentence, since corrected, now excludes macOS 27 and later). §9.3 governs ADR-025 under the artifact flow, so the amendment runs from §9.3 to ADR-025 to the adapter. *Breaks meanwhile:* nothing on the Apple adapter's path, which returns no token on an unsupported device. The same tenet reaches the Android adapter, and §27.3.3 records what its two entry points do.
````

Live text after the cut:

````text
**OQ-33 — What does §9.3 of the security spec state that an unsupported device produces?** *Settled upstream; ADR-025 and the Swift adapter now follow it:* the no-dev-stand-in tenet of `AGENTS.md` already decides that the adapter fails closed. It forbids "a hardcoded/placeholder/reconstructed-from-args value" that "may be reachable on a shipped production path," and `.docs/standards/sdk-common.md` §Stub and Placeholder Policy admits no exception: the prove-absence gate "admits **zero nullifier features — no exceptions**. There is no "documented," "tracked," or "legible" allowlisted nullifier edge." `AppleDeviceAttestation.attest` and `assertRequest` throw a typed error, and return no bytes, whenever `DCAppAttestService.shared.isSupported` is false (§27.3.3, contradiction C8, resolved). *§9.3.1 of the security spec now answers the question the tenet left open:* "An unsupported device, a simulator, and a desktop client without App Attest publish no `ScpDeviceAttestation` entry, and a reader returns `Absent` for them," and a placeholder token returns `Rejected{MalformedToken}` at every reader. ADR-025's 2026-09-27 amendments remove the synthetic token from the decision, and the Swift adapter returns none. Before §9.3.1 a human had to decide whether §9.3 needed a sentence naming what an unsupported device produces, or whether its two existing sentences already cover a simulator and an unsupported iOS device (`.docs/specs/09-security-model.md:185`): "Its absence is expected — desktop users, non-native clients, protocol-only implementations — and is not penalizing," and "macOS, Linux, and Windows have no App Attest or Play Integrity equivalent" (the second sentence, since corrected, now excludes macOS 27 and later). §9.3 governs ADR-025 under the artifact flow, so the amendment runs from §9.3 to ADR-025 to the adapter. *Breaks meanwhile:* nothing on the Apple adapter's path, which returns no token on an unsupported device. The same tenet reaches the Android adapter, and §27.3.3 records what its two entry points do.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 885 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**OQ-39 — Which component runs F1's `validate_structure` at verification time?** *Undefined:* the six structural checks — including `issuer` equals `subject` and `id` equals `compute_id` — run only on the mint path shared by the three bridges, and no verifier calls them (§27.4.1). §3.5.4 of the identity spec lists six Class 1 verification steps and none of them is a structural check, yet its step 6 rests on one of them: "**Trust the self-attestation.** Because issuer == subject, the DID key signature is sufficient." §3.5.2 of the identity spec carries the invariant only as a struct comment, "subject: DID, // Same as issuer (self-attestation)" (`.docs/specs/03-identity.md:204`). *Should define it:* §3.5.4 of the identity spec, adding the structural checks to its numbered steps and naming the component that runs them. *Breaks meanwhile:* an issuer A mints an attestation whose signed `subject` names a victim B, signs it with A's `#active`, and passes the shipped `verify_signature`, so a consumer reading `subject` attributes the platform handle to B — and step 6's justification, which assumes issuer equals subject, does not hold on that record.
````

Live text after the cut:

````text
**OQ-39 — Which component runs F1's `validate_structure` at verification time?** *Undefined:* the six structural checks — including `issuer` equals `subject` and `id` equals `compute_id` — run only on the mint path shared by the three bridges, and no verifier calls them (§27.4.1). §3.5.4 of the identity spec lists six Class 1 verification steps and none of them is a structural check, yet its step 6 rests on one of them: "**Trust the self-attestation.** Because issuer == subject, the DID key signature is sufficient." §3.5.2 of the identity spec carries the invariant only as a struct comment, "subject: DID, // Same as issuer (self-attestation)" (`.docs/specs/03-identity.md:203`). *Should define it:* §3.5.4 of the identity spec, adding the structural checks to its numbered steps and naming the component that runs them. *Breaks meanwhile:* an issuer A mints an attestation whose signed `subject` names a victim B, signs it with A's `#active`, and passes the shipped `verify_signature`, so a consumer reading `subject` attributes the platform handle to B — and step 6's justification, which assumes issuer equals subject, does not hold on that record.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 887 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**OQ-40 — Is "check evidence" an envelope duty or a per-type duty, and which component owns each type's procedure?** *Undefined:* §7.6 of the trust spec states one uniform mechanic — "check signature, check evidence, check expiry, check revocation" — while §7.4.2 of the trust spec states a distinct `Verification:` procedure for only three of its seven attestation types — "Verification: cryptographic chain validation" for capability delegation (`.docs/specs/07-trust-validation-and-capabilities.md:986`), "Verification: deterministic testing (Layer 2)" for outlet integrity, and "Verification: validate against governance model and UCAN chain" for role assignment. Identity link states a verification sentence without a procedure, and agent capability, endorsement, and context endorsement state none. The shipped step 2 tests only presence and a non-empty `evidence_type` string and never reads `evidence.data` (§27.4.2). *Should define it:* §7.4.2 and §7.6 of the trust spec, together, stating which duty the envelope verifier discharges, naming the component that runs each of the three stated procedures, and stating whether the four types with no stated procedure need one. *Breaks meanwhile:* an `OutletIntegrity` attestation carrying `evidence_type: "x"` and `data: null` passes all five steps of the F2 verifier, so §7.4.2's deterministic-testing requirement has no owner.
````

Live text after the cut:

````text
**OQ-40 — Is "check evidence" an envelope duty or a per-type duty, and which component owns each type's procedure?** *Undefined:* §7.6 of the trust spec states one uniform mechanic — "check signature, check evidence, check expiry, check revocation" — while §7.4.2 of the trust spec states a distinct `Verification:` procedure for only three of its seven attestation types — "Verification: cryptographic chain validation" for capability delegation (`.docs/specs/07-trust-validation-and-capabilities.md:985`), "Verification: deterministic testing (Layer 2)" for outlet integrity, and "Verification: validate against governance model and UCAN chain" for role assignment. Identity link states a verification sentence without a procedure, and agent capability, endorsement, and context endorsement state none. The shipped step 2 tests only presence and a non-empty `evidence_type` string and never reads `evidence.data` (§27.4.2). *Should define it:* §7.4.2 and §7.6 of the trust spec, together, stating which duty the envelope verifier discharges, naming the component that runs each of the three stated procedures, and stating whether the four types with no stated procedure need one. *Breaks meanwhile:* an `OutletIntegrity` attestation carrying `evidence_type: "x"` and `data: null` passes all five steps of the F2 verifier, so §7.4.2's deterministic-testing requirement has no owner.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 889 on main when archived

S2 changed only line numbers here. On main the first cite pointed at a §3.5.5 shadow-claim line, which S2 deleted, instead of the §3.5.4 cache list the sentence quotes; the new number points at that list. The other cite changed because S2 moved its target line.

````text
**OQ-41 — What TTL does a Cryptographic verification-result cache carry, and what invalidates an entry on revocation?** *Undefined:* §3.5.4 of the identity spec defines one cache, scopes it to Reference attestations at a one-hour TTL, and states "Class 1 attestations do not require caching" (`.docs/specs/03-identity.md:302`); the shipped `CRYPTOGRAPHIC_TTL_SECS` of 86400 matches no artifact (§27.4.2). §7.4.4 of the trust spec states a re-check duty on cached verifications — "at least once per hour for security-critical attestations, once per day for others" — and "A revoked attestation MUST NOT be accepted by validators for any purpose" (`.docs/specs/07-trust-validation-and-capabilities.md:1010`), and no component invalidates an entry. *Should define it:* §3.5.4 of the identity spec for the class TTLs and §7.4.4 of the trust spec for the invalidation duty, together. *Breaks meanwhile:* the cache stores a verification outcome under an id that revocation does not change — `compute_id` reads `issuer`, `claim.platform`, `claim.platform_handle`, and `issued_at`, none of which an issuer changes when republishing as `Revoked` — so a positive result would survive a revocation for its whole TTL on any path that adopts the cache.
````

Live text after the cut:

````text
**OQ-41 — What TTL does a Cryptographic verification-result cache carry, and what invalidates an entry on revocation?** *Undefined:* §3.5.4 of the identity spec defines one cache, scopes it to Reference attestations at a one-hour TTL, and states "Class 1 attestations do not require caching" (`.docs/specs/03-identity.md:266`); the shipped `CRYPTOGRAPHIC_TTL_SECS` of 86400 matches no artifact (§27.4.2). §7.4.4 of the trust spec states a re-check duty on cached verifications — "at least once per hour for security-critical attestations, once per day for others" — and "A revoked attestation MUST NOT be accepted by validators for any purpose" (`.docs/specs/07-trust-validation-and-capabilities.md:1009`), and no component invalidates an entry. *Should define it:* §3.5.4 of the identity spec for the class TTLs and §7.4.4 of the trust spec for the invalidation duty, together. *Breaks meanwhile:* the cache stores a verification outcome under an id that revocation does not change — `compute_id` reads `issuer`, `claim.platform`, `claim.platform_handle`, and `issued_at`, none of which an issuer changes when republishing as `Revoked` — so a positive result would survive a revocation for its whole TTL on any path that adopts the cache.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 891 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**OQ-42 — Which parties may issue an F7 custody-violation record, and what does a reader check before acting on one?** *Undefined:* ADR-039's Enforcement Stack layer 4 names no issuer, and no artifact states whether the issuer must be a member of a context the subject participates in, whether the record binds a context id at all, or how a reader distinguishes a genuine violation record from an attacker minting records against a victim. The shipped constructor takes `verifier_did` and `verifier_signature` from its caller and checks neither. §7.4.1 of the trust spec states the rule F7 needs a counterpart to, for the two sibling constructs (`.docs/specs/07-trust-validation-and-capabilities.md:980`): "Because a `verifier_did` is self-certifying, a subject can self-issue a genuinely-signed challenge result from a DID it controls — so a valid signature is a necessary, not sufficient, condition… a consumer MUST establish it SEPARATELY — e.g. a context-membership proof, a trusted-signer set, or the threshold/independence path (§7.3.5) — and MUST NOT treat a passing signature check as an authorization decision." *Should define it:* §9.5.2 of the security spec, which now owns F7's construction and states no issuer rule. *Breaks meanwhile:* §9.9.3 of the security spec's durable cross-context trust penalty — "This violation is durable and affects the operator's trust score across all contexts where other members observe the violation record" — lands on a subject on the say-so of any identity, and §9.5.2's construction does not change that, because a correct signature over a defined construction still proves only that some identity signed.
````

Live text after the cut:

````text
**OQ-42 — Which parties may issue an F7 custody-violation record, and what does a reader check before acting on one?** *Undefined:* ADR-039's Enforcement Stack layer 4 names no issuer, and no artifact states whether the issuer must be a member of a context the subject participates in, whether the record binds a context id at all, or how a reader distinguishes a genuine violation record from an attacker minting records against a victim. The shipped constructor takes `verifier_did` and `verifier_signature` from its caller and checks neither. §7.4.1 of the trust spec states the rule F7 needs a counterpart to, for the two sibling constructs (`.docs/specs/07-trust-validation-and-capabilities.md:979`): "Because a `verifier_did` is self-certifying, a subject can self-issue a genuinely-signed challenge result from a DID it controls — so a valid signature is a necessary, not sufficient, condition… a consumer MUST establish it SEPARATELY — e.g. a context-membership proof, a trusted-signer set, or the threshold/independence path (§7.3.5) — and MUST NOT treat a passing signature check as an authorization decision." *Should define it:* §9.5.2 of the security spec, which now owns F7's construction and states no issuer rule. *Breaks meanwhile:* §9.9.3 of the security spec's durable cross-context trust penalty — "This violation is durable and affects the operator's trust score across all contexts where other members observe the violation record" — lands on a subject on the say-so of any identity, and §9.5.2's construction does not change that, because a correct signature over a defined construction still proves only that some identity signed.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 893 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**OQ-43 — Does the protocol enforce endorsement independence, or does the consumer?** *Undefined:* §7.3.5 of the trust spec states "Independence is verified by the consumer, not enforced by the protocol" (`.docs/specs/07-trust-validation-and-capabilities.md:735`); §22.13.3 of the human-readable-addressing spec states, for the Verified bootstrap context, "This is a normative requirement… Implementations MUST add this wiring" and "the admission flow MUST additionally invoke `check_threshold_attestation` on the Endorsements signal category when the policy requires endorsements" (`.docs/specs/22-human-readable-addressing.md:1247`, `:1251`). The shipped `evaluate_sybil_resistance` follows §22.13.3 (§27.4.2, §27.4.3). *Should define it:* §7.3.5 of the trust spec and §22.13.3 of the human-readable-addressing spec, together, stating whether §7.3.5's sentence carries a per-context exception or whether §22.13.3 states a policy option rather than a protocol duty. *Breaks meanwhile:* one shipped function enforces independence under one spec section and states, under another, that enforcement is the consumer's, so a reader cannot tell which sentence a second implementation must honour.
````

Live text after the cut:

````text
**OQ-43 — Does the protocol enforce endorsement independence, or does the consumer?** *Undefined:* §7.3.5 of the trust spec states "Independence is verified by the consumer, not enforced by the protocol" (`.docs/specs/07-trust-validation-and-capabilities.md:734`); §22.13.3 of the human-readable-addressing spec states, for the Verified bootstrap context, "This is a normative requirement… Implementations MUST add this wiring" and "the admission flow MUST additionally invoke `check_threshold_attestation` on the Endorsements signal category when the policy requires endorsements" (`.docs/specs/22-human-readable-addressing.md:1247`, `:1251`). The shipped `evaluate_sybil_resistance` follows §22.13.3 (§27.4.2, §27.4.3). *Should define it:* §7.3.5 of the trust spec and §22.13.3 of the human-readable-addressing spec, together, stating whether §7.3.5's sentence carries a per-context exception or whether §22.13.3 states a policy option rather than a protocol duty. *Breaks meanwhile:* one shipped function enforces independence under one spec section and states, under another, that enforcement is the consumer's, so a reader cannot tell which sentence a second implementation must honour.
````

## `.docs/specs/27-attestations.md`, under `## 27.7 Open questions`, line 897 on main when archived

S2 changed only line numbers here: S1 and S2 moved the cited lines.

````text
**OQ-45 — Which MessagePack key order do F1's `claim`, `evidence`, and `revocation_status` enter the preimage under?** *Settled upstream; the shipped code diverges:* §3.5.2 of the identity spec answers it already — the three sub-structures "are individually serialized as MessagePack (sorted-key encoding) and included as variable-length byte fields" (`.docs/specs/03-identity.md:230`). `canonical_signing_bytes` serializes all three through `rmp_serde::to_vec_named`, which emits declaration order, and `AttestationClaim`'s declaration order is not sorted order (§27.3.1, contradiction C29). Under the artifact flow in `AGENTS.md` the spec governs and the code changes. The same answer settles contradiction C28, the two doc comments on `IdentityLinkAttestation` that name a MessagePack preimage the function does not produce, and the doc comment on `canonical_signing_bytes` itself that asserts the output is independent of field ordering. *Decides it:* a human, choosing whether to amend §3.5.2 of the identity spec to state declaration order instead — in which case §25.13 of the test-vector spec is amended downstream, because its Vector 26 equates the two encodings in the phrase "MessagePack (`rmp_serde::to_vec_named`, sorted-key encoding)". *Breaks meanwhile:* a binding author who implements §3.5.2 as written signs a different preimage from the Rust core, every cross-implementation F1 signature fails, and no vector catches it because §25.13 Vector 26 publishes no expected hash (OQ-21).
````

Live text after the cut:

````text
**OQ-45 — Which MessagePack key order do F1's `claim`, `evidence`, and `revocation_status` enter the preimage under?** *Settled upstream; the shipped code diverges:* §3.5.2 of the identity spec answers it already — the three sub-structures "are individually serialized as MessagePack (sorted-key encoding) and included as variable-length byte fields" (`.docs/specs/03-identity.md:229`). `canonical_signing_bytes` serializes all three through `rmp_serde::to_vec_named`, which emits declaration order, and `AttestationClaim`'s declaration order is not sorted order (§27.3.1, contradiction C29). Under the artifact flow in `AGENTS.md` the spec governs and the code changes. The same answer settles contradiction C28, the two doc comments on `IdentityLinkAttestation` that name a MessagePack preimage the function does not produce, and the doc comment on `canonical_signing_bytes` itself that asserts the output is independent of field ordering. *Decides it:* a human, choosing whether to amend §3.5.2 of the identity spec to state declaration order instead — in which case §25.13 of the test-vector spec is amended downstream, because its Vector 26 equates the two encodings in the phrase "MessagePack (`rmp_serde::to_vec_named`, sorted-key encoding)". *Breaks meanwhile:* a binding author who implements §3.5.2 as written signs a different preimage from the Rust core, every cross-implementation F1 signature fails, and no vector catches it because §25.13 Vector 26 publishes no expected hash (OQ-21).
````
