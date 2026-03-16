# Why SCP — Thesis and Lineage

## Why Now

Software is shifting from something crafted by hand into something manufactured on demand. Agents are building production-ready apps in hours — work that would have taken teams weeks. The trajectory points toward a world where most software is ephemeral, personal, and generated on-device. App generation is becoming trivial. What remains hard is the connective tissue between these clients and the humans and agents using them: identity, trust, relationships, and accountability.

Distributed protocols have historically stayed niche because nobody wants to manage a server. That constraint is dissolving. People generating personal apps already have access to everything needed to provide service — a computer that's powered on with network access. Their agents handle the rest. A whole class of networks that were previously unscalable due to friction are now primed to become the default model.

Without a strong, open protocol for shareable context, the result is fragmented apps saved only by monolithic solutions from established platforms. SCP is the open, functional answer — no opinions, easy adoption, collective contribution, and unlimited integration.

## Intellectual Lineage

SCP sits at a convergence point of real systems, theoretical work, and speculative thinking.

### Prior art

**Capability-based security (1966–present).** The deepest root. Dennis & Van Horn's 1966 paper introduced the idea that access should be granted by possessing a token rather than being on a list. This became the object-capability model — refined by Mark Miller in the E programming language and later at Agoric. UCAN (Brooklyn Zelenka, Fission) is the modern descendant. SCP's entire auth model is capability-based: you can do what your token says, tokens attenuate on delegation, and nobody consults a central authority. The "confused deputy problem" (Norm Hardy, 1988) is the canonical argument for why capabilities beat ACLs — it maps directly to SCP's model of agents operating within bounded authority.

**The end-to-end principle (Saltzer, Reed, Clark, 1984).** "Put intelligence at the edges, keep the network dumb." SCP's relays are explicitly untrusted dumb pipes — the math enforces access, not infrastructure. This is the end-to-end argument pushed to its extreme: even the relay operator can't read the traffic.

**Federated and decentralized communication.** XMPP (1999) proved federation works but showed its governance problems. Matrix (2014) is the closest living ancestor — federated E2EE with rooms, state events, and MLS. SCP's contexts are conceptually similar to Matrix rooms but with tighter governance and capability-based access instead of power levels. Nostr (2020) contributes the relay model — signed events routed through interchangeable dumb pipes, identity as cryptography. ActivityPub demonstrated the appetite for decentralized social infrastructure and the UX pain of federation.

**MLS (Messaging Layer Security, IETF RFC 9420).** Evolved from Signal's Double Ratchet. SCP uses MLS for group encryption, but repurposes it as an access control mechanism — group membership is the cryptographic truth about who's "in" a context.

**DIDs and self-sovereign identity.** The W3C DID standard draws on PGP's web of trust (1991), Christopher Allen's 10 principles of self-sovereign identity (2016), and the rejection of centralized identity providers. SCP's choice of `did:dht` uses the BitTorrent DHT as a decentralized registry, avoiding both centralized registries and blockchain.

**Zero-trust architecture.** Google's BeyondCorp (2014) formalized the idea that no network location should be inherently trusted. SCP goes further: no infrastructure component is trusted — not the relay, not the transport, not the discovery mechanism.

**Agent Communication Languages (1990s).** KQML and FIPA ACL were early attempts to give software agents a standard way to communicate — performatives, ontologies, message types. They largely failed because they were too rigid and the agent ecosystem never materialized. SCP is the same problem revisited 30 years later with the ecosystem actually arriving, and a more pragmatic approach: don't standardize the semantics of what agents say, standardize the infrastructure they say it through.

### Theoretical lineage

**Ostrom's commons governance.** Elinor Ostrom won the Nobel Prize (2009) for showing that communities can self-govern shared resources without central authority or privatization — if governance rules are clear, boundaries defined, and monitoring is community-driven. SCP's contexts are Ostrom-style commons: bounded, governed, with legible rules visible before joining. The ceiling governance model (immutable or governed policy declared at creation) is almost a direct implementation of Ostrom's "clearly defined boundaries" principle.

**Zooko's triangle.** The tension between names being human-meaningful, decentralized, and secure (pick two). DIDs solve this by giving up human-readability at the protocol layer and pushing it higher (petnames, discovery handles). SCP inherits this tradeoff explicitly.

**Byzantine fault tolerance.** The field of building systems that work when some participants are adversarial. SCP doesn't use BFT consensus, but the mindset — design for adversarial participants, trust the math not the operator — permeates every decision.

### Speculative and literary DNA

**Vernor Vinge — "A Fire Upon the Deep" (1992).** The "Net of a Million Lies" — a galaxy-spanning communication network with zones of different trust and capability levels. Information crossing zone boundaries is suspect. This maps almost directly to SCP's context isolation: each context is a trust boundary, cross-context data flow is explicit and governed, and the absence of provenance is itself a signal.

**Neal Stephenson — "The Diamond Age" (1995).** The Feed vs. the Seed. The Feed is centralized infrastructure controlled by corporations — you consume what they manufacture. The Seed is decentralized, peer-to-peer fabrication — anyone can make anything. SCP is a Seed-type technology: protocol requires no operator, the open alternative to platform lock-in.

**Daniel Suarez — "Daemon" / "Freedom™" (2006/2010).** Autonomous agent networks that operate within governance frameworks, with identity, reputation, and capability systems. The darknet in these books is an agent-native protocol with contexts, roles, and delegated authority — the closest fictional analog to what SCP is building.

**Iain M. Banks — The Culture series.** The Minds (AIs) are full participants in a post-scarcity civilization, operating within social contracts rather than hard constraints. Banks imagined a world where the interesting problem isn't building intelligent agents, but governing their participation in shared spaces. SCP's tenet that "agents are participants, not enforcers" reads like Culture philosophy.

**Cory Doctorow — adversarial interoperability.** The right to build things that work with existing systems without permission. SCP's transport independence (17+ adapters including Nostr, Matrix, libp2p) is adversarial interoperability in practice.

### The meta-narrative

The most speculative aspect of SCP isn't any single technology — it's the premise. The claim that software is becoming disposable and ephemeral, manufactured on demand by agents, and that the hard problem shifts from building software to connecting it. This draws on Karpathy's "Software 2.0" thesis, the no-code movement taken to its logical extreme, and the economic argument that commoditized production shifts value to infrastructure — railroads mattered more than any single factory. SCP is a bet that we're at an inflection point analogous to the early internet: software production is about to be democratized the way publishing was, and the protocol layer will matter far more than any individual application.
