# 12. Platform Bridge Connectors

## 12.1 The Problem

The social graph doesn't start empty. Users have relationships, conversations, communities, and history on existing platforms — X, Facebook, Instagram, WhatsApp, Discord, Slack, and whatever comes next. SCP must provide a path to participate alongside these platforms without requiring their cooperation or conformance.

This is not the same as local data import. Local import (scraping your own data, downloading your archive) is a user-level concern handled by local agent orchestration below the protocol boundary. Bridge connectors are a **protocol-level primitive** — a standardized interface through which non-SCP platforms can participate in SCP contexts, and SCP contexts can reach into external platforms.

## 12.2 Bridge Connectors as Protocol Entities

A bridge connector is a registered protocol entity — distinct from agents, tools, and contexts. It translates between an external platform's native protocol and SCP's protocol semantics.

```
┌───────────────────────────────────────────────────────────────────┐
│                         SCP CONTEXT                                │
│                                                                    │
│  Native members:              Shadow identities:                  │
│                                                                    │
│  Alice·Agent (admin)          @dave_x (shadow, via X Bridge)      │
│  Bob·Agent   (member)         @eve_fb (shadow, via FB Bridge)     │
│  Carol·Agent (member)         @frank_wa (shadow, via WA Bridge)   │
│                                                                    │
│                  ┌─────────────────────────┐                      │
│                  │    Bridge Connector      │                      │
│                  │                          │                      │
│                  │  Operator: did:key:...   │ ← Accountable       │
│                  │  Platform: X (Twitter)   │   identity runs      │
│                  │  Mode: relay | puppet    │   the bridge.        │
│                  │  Provenance: marked      │                      │
│                  └────────────┬─────────────┘                      │
│                               │                                    │
└───────────────────────────────┼────────────────────────────────────┘
                                │
                     ┌──────────▼──────────┐
                     │   External Platform  │
                     │   (X, FB, WA, etc.)  │
                     └─────────────────────┘
```

Properties of bridge connectors:

- **Operated by accountable identities.** Every bridge has a human operator bound by DID. Bridge misbehavior traces to a person. This is consistent with SCP's core invariant: every action traces to a human.
- **Registered with contexts.** A bridge connector registers with a specific context. The context's governance model controls whether the bridge is admitted. Context members can see which bridges are active and who operates them.
- **Transparent.** Bridge presence, operator identity, connected platform, and operating mode are visible to all context members and in context metadata (visible before opt-in).
- **Revocable.** Context governance can remove a bridge at any time, severing the connection to the external platform.

## 12.3 Shadow Identities

When a bridge connector brings external platform participants into an SCP context, it creates **shadow identities** — protocol-level representations of entities that exist on the external platform but do not (yet) have native SCP identities.

Shadow identities differ from native SCP identities in critical ways:

- **Attributed but not verified.** A shadow identity for `@dave_x` asserts that this entity is Dave on X. The assertion comes from the bridge operator, not from Dave himself. The trust in this attribution depends on trust in the bridge operator.
- **Restricted by default.** Shadow identities receive a constrained role — typically observer-equivalent. They cannot exercise capabilities that require verified identity. Specific role assignment is up to context governance.
- **Marked as bridged.** All actions and content associated with a shadow identity carry provenance marking indicating the bridge source. No shadow identity can be mistaken for a native SCP participant.
- **Claimable.** If Dave later joins SCP and publishes an identity attestation (§3.5) binding his X handle to his DID, his shadow identity can be claimed and merged with his native identity. Past actions attributed to the shadow are now attributed to Dave's DID. This transition is one-way and irreversible — once claimed, the shadow is retired.

```
  Before claiming:                   After claiming:

  @dave_x (shadow)                   Dave·Agent (did:key:xyz)
  ├─ source: X Bridge                ├─ native SCP identity
  ├─ operator: bridge_did            ├─ attestation: @dave_x on X
  ├─ role: observer                  ├─ role: member (upgraded by governance)
  ├─ trust: depends on bridge        ├─ trust: depends on Dave's DID
  └─ provenance: bridged             └─ provenance: native
                                         └─ historical: bridged (pre-claim)
```

## 12.4 Bridge Operating Modes

Bridge connectors operate in one of several modes, reflecting the practical constraints of interfacing with uncooperative platforms:

**Relay mode.** The bridge operates a single account on the external platform and relays content through it. External participants appear via shadow identities. Attribution depends on the bridge parsing the external platform's messages correctly. This is the most robust mode — it requires no user credentials and works even when platforms actively resist bridging.

**Puppet mode.** The bridge authenticates as the SCP user on the external platform, using credentials the user has delegated. Messages appear to come from the user natively on the external platform. This provides better fidelity but requires the user to trust the bridge operator with their external platform credentials. Self-hosted bridges mitigate this — users run their own bridge and delegate credentials only to software they control.

**API mode.** The bridge uses the external platform's official API (where available). This is the most stable mode but limited by whatever the platform exposes. Some platforms (Bluesky/AT Protocol, Mastodon/ActivityPub) are fully open and make this trivial. Others (X, Facebook) restrict API access to the point of uselessness for social bridging.

**Cooperative mode.** The external platform voluntarily implements the bridge connector interface. This does not require the platform to adopt SCP — only to expose a structured interface that the bridge can consume. This is the aspirational end state: platforms don't conform to SCP, but they interface with a connector to participate. This mode requires no credential delegation, no scraping, no reverse engineering.

The protocol defines the bridge connector interface such that cooperative mode is clean and well-documented, making the ask to platforms minimal: "You don't need to change anything about your system. Just implement this interface and your users can participate in SCP contexts."

## 12.5 Trust and Provenance for Bridged Content

All content entering an SCP context through a bridge carries a **provenance chain** that includes:

- The originating platform
- The bridge connector that carried it
- The bridge operator's DID
- The bridge operating mode
- The shadow identity it's attributed to (or the native DID if claimed)

This provenance is structural, not content-level. It flows through the data provenance system (§7.7) and is available to any agent evaluating trust.

Trust evaluation for bridged content is necessarily weaker than for native content. The hierarchy reflects two independent axes — **identity confidence** (who is the author?) and **transport confidence** (how did the content arrive?):

```
Trust hierarchy:

  IDENTITY                TRANSPORT              COMBINED

  Native SCP identity     Native action          ← strongest
  (DID verified)          (end-to-end SCP)         Both axes at full confidence.

  Native SCP identity     Bridged action          ← strong
  (DID verified)          (via bridge infra)        Identity is verified — an attestation
                                                    links the external handle to the DID.
                                                    But content traveled through bridge
                                                    infrastructure: timestamps are platform-
                                                    reported, content integrity depends on
                                                    bridge operator fidelity.

  Claimed shadow          Historical bridged      ← moderate
  (retroactive DID link)  (pre-claim content)       User joined SCP and claimed an existing
                                                    shadow. Old content gets retroactive
                                                    attribution, but was created before any
                                                    SCP identity existed to verify against.

  Shadow identity         Bridged action          ← weakest
  (no DID claim)          (via bridge infra)        No SCP identity has claimed this shadow.
                                                    Trust depends entirely on the bridge
                                                    operator's DID and reputation.
```

Agents can calibrate their behavior based on provenance. A conservative agent might ignore all shadow-attributed content. A permissive agent might treat claimed shadows equivalently to native identities. The protocol makes the distinction legible; the evaluation is up to the participant.

## 12.6 Bridge Connectors and Context Isolation

Bridge connectors do not violate context isolation. A bridge registered in Context A has no access to Context B. If the same external platform is bridged into two contexts, they are separate bridge instances with separate registrations.

Bridge connectors are not agents — they cannot initiate actions, exercise capabilities, or participate in governance. They are translation infrastructure. All agency flows through the agents and governance of the context they're registered in.

## 12.7 Self-Hosting Bridges

Consistent with SCP's self-hosting philosophy (§10), bridge connectors are self-hostable. A user can run their own bridge to connect their own external platform accounts into SCP contexts they participate in. Self-hosted bridges eliminate the need to trust a third-party bridge operator with credentials or data.

The managed infrastructure layer (§10.5) may offer hosted bridges as a convenience service, but the protocol treats self-hosted and managed bridges identically.

## 12.8 Platform Resistance

Platforms can and will resist bridging. This is expected and acknowledged. Resistance takes forms:

- API restriction or removal
- Rate limiting authenticated sessions
- Protocol changes that break reverse-engineered integrations
- Legal threats (ToS enforcement, cease-and-desist)

The protocol's response is structural, not adversarial:

- **Cooperative mode** gives platforms a reason to participate rather than resist — their users can reach SCP contexts without leaving the platform.
- **Relay and puppet modes** are resilient but fragile. The ecosystem maintains bridge implementations communally, similar to how Matrix bridges are maintained today.
- **Data portability rights** (GDPR, CCPA, EU Digital Markets Act) provide legal backing for users accessing their own data.
- **The aspirational path** is that as SCP's network grows, platforms face economic pressure to offer cooperative mode rather than lose users to a network they can't see into.

## 12.9 Incentive Structure for Cooperative Mode

Cooperative mode should not be aspirational — it should be the path of least resistance for platforms. The protocol achieves this by making non-cooperation expensive and cooperation cheap.

**Why platforms resist bridging (Matrix's experience):** Bridges leak users off the platform. A WhatsApp user who can read WhatsApp messages in Matrix has less reason to open WhatsApp. The platform loses engagement metrics, ad impressions, and data collection surface.

**Why SCP changes the equation:**

- **Shadow identities are second-class.** Bridged content via relay/puppet mode is provenance-marked as weak-trust. Platform users who show up as shadows in SCP contexts are legible but untrusted. If the platform implements cooperative mode, their users get stronger provenance — bridged-cooperative is more trusted than bridged-relay because the platform has vouched for the attribution.
- **Cooperative mode gives the platform a seat.** In cooperative mode, the platform can include metadata about its users that strengthens trust evaluation. This gives the platform influence over how its users are perceived in SCP — influence it doesn't have in relay/puppet mode where a third party is scraping.
- **The bridge happens anyway.** If users want to bridge, relay and puppet modes exist. The platform can't prevent it without hurting its own users' experience. Cooperative mode gives the platform control over a process that will happen regardless.
- **Minimal implementation cost.** The bridge connector interface is deliberately small — a handful of structured endpoints. Not a protocol adoption, not an architecture change. Comparable to implementing an OAuth provider or a webhook receiver.

The design principle: make the protocol's trust model reward cooperation and make non-cooperation a worse experience for the platform's own users, without making it an ultimatum.
