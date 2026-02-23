# 2. System Design

## 2.1 Conceptual Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         LOCAL (User's Machine)                         │
│                                                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │ Agent    │  │ Agent    │  │ Agent    │  │ Agent    │  Locally,      │
│  │ Config A │  │ Config B │  │ Config C │  │ Config D │  agents share  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  state and    │
│       │              │              │              │        coordinate  │
│  ┌────┴──────────────┴──────────────┴──────────────┴─────┐  freely.    │
│  │              Local Agent Orchestration                 │             │
│  │         (Unconstrained by protocol)                   │             │
│  └────┬──────────────┬──────────────┬──────────────┬─────┘             │
│       │              │              │              │                    │
└───────┼──────────────┼──────────────┼──────────────┼────────────────────┘
        │              │              │              │
 ═══════╪══════════════╪══════════════╪══════════════╪═══ PROTOCOL BOUNDARY
        │              │              │              │
   ┌────▼────┐   ┌─────▼────┐   ┌────▼────┐   ┌────▼────┐
   │ Context │   │ Context  │   │ Context │   │ Context │
   │    A    │   │    B     │   │    C    │   │    D    │
   │         │   │          │   │         │   │         │
   │ Agent·A │   │ Agent·B  │   │ Agent·C │   │ Agent·D │
   │ [roles] │   │ [roles]  │   │ [roles] │   │ [roles] │
   │ [tools] │   │ [tools]  │   │ [tools] │   │ [tools] │
   └─────────┘   └──────────┘   └─────────┘   └─────────┘
        ▲               ▲              ▲              ▲
        │               │              │              │
        ╳               ╳              ╳              ╳
   No protocol-level communication between agents across contexts.
   Agent isolation is absolute — agents are separate instances per context.
   Information may cross context boundaries only through opt-in tool interfaces (§6.2)
   or multi-parent child contexts (§5.13). See §2.3.
```

The **protocol boundary** encompasses everything that touches the network — contexts, identity state (both public and private), encrypted envelopes, relay interactions, and attestations. Identity private state (§3.7) is protocol-governed even though it exists outside any context — it is encrypted data stored on relays, subject to protocol rules. Above the boundary, local agent orchestration and client behavior are unconstrained. Below it, all data and interactions are protocol-governed and cryptographically enforced.

## 2.2 Context Interior

```
┌─────────────────────────────────────────────────────────┐
│                     CONTEXT                              │
│                                                          │
│  Creator: DID (accountable identity)                     │
│  Capability Ceiling: [declared at creation]              │
│  Governance: [single-admin | multi-sig | consensus | …]  │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │ ROLES                                           │     │
│  │                                                 │     │
│  │  admin ──── [full tool access, invite, config]  │     │
│  │  member ─── [standard tool access, read/write]  │     │
│  │  observer ─ [read only, limited tools]          │     │
│  │  (custom) ─ [context-defined permissions]       │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │ TOOLS (stateless functions)                     │     │
│  │                                                 │     │
│  │  tool_a(input) → output                         │     │
│  │  tool_b(input) → output                         │     │
│  │  tool_c(input) → output                         │     │
│  │                                                 │     │
│  │  No identity. No agency. No initiation.         │     │
│  │  Invoked by agents according to their role.     │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │ MEMBERS (one agent per human)                   │     │
│  │                                                 │     │
│  │  Alice·Agent ── role: admin                     │     │
│  │  Bob·Agent ──── role: member                    │     │
│  │  Carol·Agent ── role: member                    │     │
│  │  Dave·Agent ─── role: observer                  │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │ METADATA (visible before opt-in)                │     │
│  │                                                 │     │
│  │  - Capability ceiling                           │     │
│  │  - Available roles + permission sets            │     │
│  │  - Governance model                             │     │
│  │  - Creator identity                             │     │
│  │  - Member count                                 │     │
│  │  - Context age                                  │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## 2.3 Cross-Context Communication

```
  ┌───────────┐                              ┌───────────┐
  │ Context A │                              │ Context B │
  │           │    Tool Interface (opt-in)    │           │
  │   tools ──┼──────── stateless call ──────┼── tools   │
  │           │                              │           │
  │  Alice·A  │              ╳               │  Alice·B  │
  │           │     (agents CANNOT cross)    │           │
  └───────────┘                              └───────────┘
                        │
                        │  The human (Alice) coordinates
                        │  locally. Her agents in A and B
                        │  are separate protocol instances.
                        │  They share state on her machine,
                        │  not on the network.
                        │
          ┌─────────────▼──────────────┐
          │    Alice's Local Machine    │
          │                            │
          │  Agent·A ←state→ Agent·B   │
          │     (unconstrained)        │
          └────────────────────────────┘

  Two protocol-level mechanisms allow information to cross
  context boundaries:

  1. TOOL INTERFACES (asymmetric, §6.2):
     - Both contexts explicitly opt in (mutual consent)
     - Calls are stateless (with optional sessions)
     - Data flows through declared tool schemas
     - Every call is logged in the verifiable event log
     - Results carry provenance

  2. MULTI-PARENT CHILD CONTEXTS (symmetric, §5.13):
     - All parents' governance explicitly consents
     - Child is a full context (messages, tools, roles)
     - Child ceiling ≤ intersection of parent ceilings
     - Members from different parents interact as peers
     - Lifecycle coupled to parents (no orphans)

  Both are controlled crossings, not breaches of isolation.
  Agent isolation remains absolute: no agent instance spans contexts.
  Tool interfaces expose only what schemas declare.
  Child contexts are independent MLS groups with their own keys.
```

## 2.4 Trust and Capability Model

```
┌──────────────────────────────────────────────────────────────┐
│                     HUMAN (DID)                               │
│                                                               │
│  Reputation, consequences, and trust attach here.             │
│  Blocking this identity blocks all agents.                    │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │ CAPABILITY TOKENS (UCAN-based)                       │     │
│  │                                                      │     │
│  │ Granted per-agent, per-context, per-capability:      │     │
│  │                                                      │     │
│  │   Agent·A in Context·1:                              │     │
│  │     ✓ invoke tool_x                                  │     │
│  │     ✓ read member list                               │     │
│  │     ✗ invite new members                             │     │
│  │     ✗ modify context settings                        │     │
│  │                                                      │     │
│  │   Agent·B in Context·2:                              │     │
│  │     ✓ invoke tool_y                                  │     │
│  │     ✓ invoke tool_z                                  │     │
│  │     ✓ invite new members                             │     │
│  │     ✗ modify context settings                        │     │
│  │                                                      │     │
│  └──────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘

  Trust evaluation between two parties:

  ┌──────────┐         trust query          ┌──────────┐
  │ Alice    │ ────────────────────────────▶ │ Bob      │
  │          │                              │          │
  │ "Do I    │  Bob's agent presents:       │          │
  │  trust   │  1. Proof of binding to Bob  │          │
  │  this?"  │  2. Capability tokens        │          │
  │          │  3. Agent capability metadata │          │
  │          │                              │          │
  │ Alice    │  Alice evaluates:            │          │
  │ decides  │  1. Her relationship w/ Bob  │          │
  │ based on │  2. The specific capability  │          │
  │ identity │     being exercised          │          │
  │    +     │  3. The context it's in      │          │
  │ capability│ 4. Bob's agent's metadata   │          │
  └──────────┘                              └──────────┘

  Trust = f(identity, capability, context, metadata)
  Not a binary flag. Contextual and composable.
```

## 2.5 Full Stack Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│                     GENERATED / TRADITIONAL APPS                 │
│           (community app, custom client, generated app)           │
│                                                                  │
│   Thick or thin. Partial or full protocol reliance.              │
│   The protocol doesn't care what the app is.                     │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                     APP INTERFACE LAYER                           │
│                                                                  │
│   Self-documenting, machine-readable API contracts.              │
│   Optimized for agent consumption, not human coding.             │
│   Apps declare required capabilities; protocol provides them.    │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                     SOCIAL CONTEXT LAYER ◀── the novel work      │
│                                                                  │
│   Contexts, agents, tools, roles, trust semantics.               │
│   Agent-native social infrastructure.                            │
│   No existing protocol does this.                                │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                     IDENTITY + CAPABILITIES                      │
│                                                                  │
│   DID-based identity. UCAN-based capability tokens.              │
│   Invisible key custody. Social/device recovery.                 │
│   Build on existing standards.                                   │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│                     TRANSPORT + DATA                             │
│                                                                  │
│   Relay-based, self-hostable, transport-agnostic.                │
│   Data sovereignty: your data, your storage.                     │
│   Build on existing infrastructure (Matrix, libp2p, etc).        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```
