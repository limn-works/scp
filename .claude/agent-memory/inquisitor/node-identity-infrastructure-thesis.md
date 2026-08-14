---
name: node-identity-infrastructure-thesis
description: Interrogation of "a hosting node is infrastructure, holds no DID, self-minted DID is an accidental default" — HOLDS WITH QUALIFICATIONS; surfaced a real spec §18.6.4 vs §10.17 contradiction
metadata:
  type: project
---

# Thesis: hosting node = infrastructure, needs no DID of its own

Interrogated 2026-07-14. Maintainer's thesis: a hosting `scp-node` is INFRASTRUCTURE not a
participant; holds NO sovereign DID; serving is keyless; anything that ACTS uses a delegated key
on a HUMAN's DID; the node self-minting a DID on startup is an accidental builder default; the
pre-rotation-custody-on-the-node problem is downstream of that needless identity.

**Verdict: HOLDS WITH QUALIFICATIONS.** No case found where a node needs a sovereign,
human-rootless, non-re-homable DID. Relay + storage + forwarding sign NOTHING (verified across
scp-transport/scp-relay/scp-node — only signature in the path is the node VERIFYING clients).

**Why:** Core is correct AND is the spec's own considered position — §10.17 "Node vs. Participant"
(10-infrastructure-and-self-hosting.md:1053-1066): "A scp-node is pure infrastructure... never
participates in a context as itself... does not join contexts, create MLS groups, or sign protocol
messages in its own right." Self-host is framed as a co-located SDK participant "sharing the node's
custody," "never a single 'participating node.'"

**How to apply / qualifications the thesis must absorb:**
- "Holds NO DID / serving is keyless" is too strong. Relay/storage/forwarding ARE keyless. But (i)
  SCP-native reachability requires a self-controlled DID: the relay URL is an `SCPRelay` entry in a
  BEP44-signed DID doc, and BEP44 makes location=pubkey=signer INSEPARABLE (dht.rs:857-877) — you
  cannot publish "under someone else's DID"; re-homing = the relay becomes an entry in the
  OPERATOR's own DID doc signed by the operator's key (spec's "device is the node", §10.15:15). (ii)
  self-host AUTHORS broadcast content under a signing DID. So: no SEPARATE MACHINE DID needed, but a
  held DID key (the operator's) is load-bearing. HTTP projection also holds broadcast DECRYPTION keys.
- Self-mint IS an accidental default — confirmed. `IdentitySource::{Generate,Persisted}` mint via
  `did_method.create(custody, pre_rotation_custody)` (config.rs:78-108, lib.rs:2561/2756);
  `Explicit` (lib.rs:2572) already re-homes to any supplied identity. §18.8 deploy flow defaults to
  `.generate_identity()`. Pre-rotation custody is required BECAUSE create mints a did:dht identity —
  so the thesis's causal claim is right for the self-mint, but re-homing to an operator identity
  co-located on the box still needs custody (problem relocated/reduced, not eliminated).
- Delegated-key-on-human-DID is a REAL primitive: `#agent` key is a verification method on the same
  DID (controller==did; document.rs vm_agent), UCAN scoped delegation real (03-identity.md:78,
  04-agents.md:9/96). BUT self_host.rs hardwires author to `node.identity()` (self_host.rs:115/126/
  1417) — no delegation seam today. Re-homable in principle, not in code.
- Accountability tenet is CONTEXTUAL not universal: 01-thesis.md:19 "Unattested DIDs are valid
  protocol participants." So a rootless node DID authoring a public site is a *valid* participant;
  human-rooting is a per-context requirement, not a hard invariant. Thesis's "every action traces to
  a human" is aspirational, not enforced.

**Distinctive inquisitor finding — SPEC INCOHERENCE (drift):** §18.6.4:473 (added 2026-02-23,
eabf8aad2) says "The node's identity is a full SCP identity. It can create contexts, join contexts,
send messages — it is a protocol participant, not just infrastructure." This DIRECTLY contradicts
the later, considered §10.17 ("never a single 'participating node'"). §18.473 is the exact conflation
§10.17 exists to refute. Fix per one-way flow: correct §18.6.4:473 (and §18.8's generate-default
framing) to align with §10.17. The thesis is arguing FOR §10.17 against §18.473.
