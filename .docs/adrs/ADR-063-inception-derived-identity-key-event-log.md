# ADR-063: Inception-Derived Self-Certifying Identity over a Key-Event Log

**Status:** Accepted 2026-08-30, the day Alec settled the identity form and delegated the choice of a freshness anchor. He confirmed the witness and watcher layer in scope on 2026-08-31. Five later rulings by Alec changed decisions this record already carried, and one executor call rewrote a sixth. Each amendment sits beside the decision it changed, with its date. Accepted records that the identity model is settled and not that the code exists.

**Supersedes:** ADR-003, DID creation over did:dht. ADR-003 flips to `Superseded by ADR-063` and keeps its body as the historical record.

This record states the decisions and the reasons for them. The rules live in the specifications, and each decision below names the section that carries its rule. A reader who wants a rule opens that section. A reader who wants the reason finds it here.

## Context

SCP's identity method was did:dht until 2026-08-30. An identifier was a z-base-32 encoding of an Ed25519 public key. A DID document held the keys, the rotation state, the transport endpoints, and the service metadata. A resolver read that document from a BEP44 signed mutable item on the Mainline distributed hash table and took the copy carrying the highest sequence number, so the newest record a resolver could reach defined the current key state.

The authority behind that method was false. The nullifier-and-crate-split plan carried, as its twentieth settled decision, the sentence `Conform to did:dht — SETTLED. Alec: "we're doing did:dht as it should be."` Alec never said that. He typed, on 2026-08-11, one bullet among others about the Mainline BEP44 bootstrap record: "-ok we should be just doing did:dht as it should be. no need to do anything custom." He named the defect on 2026-08-30: "that was in the context of mainline bootstrapping. ultimately it is a falsification of intent." The recorded decision turned a preference into a settled fact, dropped the controlling clause, and widened a statement about a bootstrap encoding into a mandate over the whole identity method. That widened decision was the only authority the did:dht direction rested on, so the direction fell with it.

Alec asked the same day what to build instead: "am i wrong in saying that it sounds like we should just use keri?" and "i'm soured on did:dht shaped approach here."

The Key Event Receipt Infrastructure specification answers the question did:dht answered badly. An identifier there is derived from its own inception event, so the identifier authenticates the log rather than a mutable record authenticating the identifier (`spec-body` §Autonomic identifier (AID)). A controller commits to the digests of its next keys before it uses them, so a thief who holds the current keys cannot rotate the identity away (§Pre-rotation). The log is append-only and each event binds its predecessor's digest, so a reader replays it rather than trusting a single record (§Tetrad bindings). A validator depends on no infrastructure for correctness, because it verifies every event itself (§End-verifiable). Witnesses and watchers give a reader evidence that a controller published two versions of one event (§Indirect exchange via witnesses and watchers, §Duplicity). A delegator anchors a delegate's establishment events in its own log (§Cooperative Delegation).

Alec fixed on 2026-09-02 how far to take it: "keri is the model. dont force it. leverage it… just be", with a procedure he typed the same day, "problem>does keri have an analog>does keri's analog solve it>use keri". He added: "its ok to be different if it suits us just dont churn on issues keri solved".

## Decision

### The identity form

SCP's identity is an inception-derived self-certifying identifier over an append-only key-event log, encoded in SCP's own format. SCP takes KERI's shape and adopts none of KERI's code or wire formats: no CESR encoding, no out-of-band-introduction discovery, and no dedicated witness or watcher pools. Alec settled the form on 2026-08-30 with the two sentences the Context quotes, and bounded the adoption on 2026-09-02 with the procedure quoted there. The identifier's construction and the log's validity rules live in `09-security-model.md` §9.7.4.2. The canonical hash construction every preimage uses lives in §9.5.1.

### What the identifier replaces

**did:dht is not SCP's method.** Resolution by highest-sequence mutable record is replaced by replay of the log, and `09-security-model.md` §9.7.4.2 R8 states how a verifier derives a key state from the chain it adopted. Alec's 2026-08-30 repudiation, quoted in the Context, is the reason.

**The Mainline distributed hash table is removed.** SCP runs no did:dht-conformant Mainline bootstrap layer, and the SCP relay network carries identity. Alec answered on 2026-08-28, when asked whether riding Mainline was worth its cost: "axe it." He reconfirmed on 2026-09-05: "we are not using did:dht what r u talking about." The relay artifact that replaces the bootstrap layer is the community relay list, which `18-addressability-and-deployment.md` §18.5.1 defines.

**did:web is cut outright and no did:web code is authorized.** ADR-003's contingency method died with the method it backed. This is the executor's call, from Track U1 of the identity-substrate plan of record.

**The DID string is a deferred facade.** A `did:scp` string stays optional and unbuilt, interface-ready through the identity seam and foreclosed by nothing. Alec on 2026-08-30: "did:scp: ok. punt, be ready, don't foreclose."

**The seam is named `IdentityBackend`.** Alec proposed the rename on 2026-08-30, "should we rename \"DidMethod\" then?", and confirmed the name on 2026-09-10: "yes i remember and we settled on backend."

### Which authority signs

**SCP keeps a distinct root authority, separate from the rotating operational key.** Alec ruled it on 2026-08-30, relayed through a peer session and confirmed by him on 2026-09-10: "yes keep #0 as root we like this design so far". The reason this record keeps is the decoupling it buys: a status assertion signed by the root survives compromise of the operational key without that key's cooperation. The root set, its threshold, and the operational role live in `09-security-model.md` §9.7.4.2's definitions.

**The root signs establishment events and nothing else.** That separation is the executor's, decided under Alec's ruling above, and it keeps the root cold: an operational key is retired by an event the root signs, and no content signature ever needs the root. `09-security-model.md` §9.7.4.2 R3 states which signatures each kind of event carries.

**An identity's root may hold several members.** Alec set the shape on 2026-09-03: "if we can support orgs we should." An identity that several officers jointly control, none of them able to act alone, is therefore in scope from the first event, because the identifier is the inception event's digest and the inception event fixes the root set's shape. The member cap is SCP's own, and `09-security-model.md` §9.18.17 carries it.

**A key's standing is a root-asserted condition, not an absence.** The vocabulary is `current`, `Superseded`, `Retired`, and `Compromised{from: N}`, and `09-security-model.md` §9.7.1 states what each one licenses. Alec settled the four values, and the audit that restored them on 2026-09-05 found a same-day collapse to one condition that had let the security specification overrule this Accepted record and the plan of record's settled row, which the artifact-flow invariant forbids.

**A content signature and an attestation read a key's standing differently.** A content signature verifies against a retired key, and an attestation verifies against the current key alone. Alec's ruling predates this redesign as ADR-003's asymmetry and is unchanged, and `09-security-model.md` §9.7.1 states the boundary that separates the two. **Amended 2026-09-10.** This record previously carried a compromise carve-out and a causally-concurrent fail-closed arm, both written before the security specification adopted an epoch boundary. The orchestrator rewrote the text to that model, which closes the open question this record carried about how a compromise position maps onto a per-context anchor.

### The curve and the root's custody

**Every SCP key is an ECDSA key on NIST P-256 with SHA-256.** Alec ruled on 2026-09-10: "ok p256 then". **Amended 2026-09-10**, superseding Ed25519. The reason the orchestrator recommended and Alec accepted: P-256 is the curve every secure enclave, every passkey provider, every FIDO2 token, every trusted platform module, and every browser's WebCrypto speaks, so hardware custody becomes real on Apple platforms and in the browser. The protocol mandates one ciphersuite for version 1, with no negotiation and no fallback, and `09-security-model.md` §9.5 states the suite, the signature encoding, and the point-validation obligation a verifier carries.

**Root custody defaults to a passkey.** Alec named the substrate on 2026-09-10, "a passkey in your apple passwords or similar", and typed the domain rule the same day: "roots would get created under a universal identifier by default like ctx.network". **Amended 2026-09-10.** A passkey's private key is non-exportable, which is what moves the default off a key the controller can copy. The consequence for the log is that a root signature may be a WebAuthn assertion rather than a raw signature, and `09-security-model.md` §9.7.4.2's definitions state both slot layouts and the checks a verifier runs on an assertion.

**Self custody of a key the controller can copy leaves the consumer profile.** Alec ruled on 2026-09-10 that self custody "is writing down a key, yes" and is "not a concern". The three copyable methods therefore sit on the headless profile alone, and `09-security-model.md` §9.7.4.1 item 4 states which method conforms on which profile.

**The root credential and the pre-rotation credential share one platform account by default.** Alec chose that default on 2026-09-10 from two options the orchestrator put to him: keep the two together and tell the user. **Amended 2026-09-10.** The identity-substrate decision log records the ruling as prose and records no reason from Alec. The default places the identity's root authority and its recovery authority behind one authentication factor, so the same section requires the SDK to state the co-residence at custody selection and to offer a separated pre-rotation credential.

**Device custody and recovery stay in the platform layer, outside the identity method.** The executor decided it on 2026-08-30 from the KERI grounding: KERI puts device-loss custody recovery in the wallet layer and not in the method, which is what confirmed that the earlier churn over a device-custody DID method was self-inflicted by pulling custody into the method. Alec's contribution is the question that opened it, "wallet???". The custody obligations the protocol does state live in `09-security-model.md` §9.7.4.1, and ADR-054, pre-rotation key custody substrate isolation, is their Proposed realization.

### Fork precedence

**The root decides a fork.** Where a verifier holds two valid chains for one identity, the root authority behind each chain decides between them, and the order in which the verifier saw the two decides nothing. Alec ruled it on 2026-09-07: "Root wins sounds like a good solution." **Amended 2026-09-07**, replacing an ordering by first observation. `09-security-model.md` §9.7.4.2 R6 states the ranking a verifier applies, and R7 states what an equal rank means.

**A root signature counts at the standing the shared prefix fixed, and not at the standing the claimant's own event installs.** Alec gave the reason on 2026-09-07: "If an attacker has the root, it's GG. What would you gain by trying to optimize against that case?" Reading the later standing would let every claimant satisfy the test against a root its own event installed, which would make the test decide nothing. The pin exists so that two honest verifiers holding the same two chains reach the same verdict, and §9.7.4.2 R6 fixes what rank reads.

### Freshness and the witness layer

**Layer A is freshness and anti-rollback at parity with what did:dht actually delivered.** The anchor is the log's own highest-sequence key event, so freshness costs no new signature and no relay signs anything. Alec delegated the choice of an SCP-native anchor on 2026-08-30 with one word, "ya", which authorized the executor to pick the anchor and write it. An earlier draft invented a periodic root-signed receipt. That draft was wrong, because it forced the root hot, and the 2026-08-30 correction records it. `09-security-model.md` §9.7.4.2 R12 states the rollback rule.

**Layer B, the witness and watcher layer, is in scope.** Alec confirmed the scope on 2026-08-31 with one word, "agree". That confirmation covered the layer's scope alone.

**Witnesses are relays.** Alec asked on 2026-08-31, "witness policy essentialy has the same machinery as identity relays then?" The layer reuses the relay infrastructure, the identity-to-relay association, the application management, and the shipped-default machinery SCP already runs for transport, and adds a cosigned head, two key-state fields, and the comparison a watcher runs.

**A witness watches and reports, and decides nothing.** Alec ruled it on 2026-09-10: "watch and report as well". **Amended 2026-09-10.** His reason, as the decision log records it: the residual the earlier required-witnessing model rested on, a lost root together with a leaked copy of a spent pre-rotation key, does not arise for a user who keeps the default passkey custody. The asymmetry was stated to him before he ruled: moving from required to watch-and-report later is a relaxation, and moving the other way is a flag day. No rule of `09-security-model.md` §9.7.4.2 reads a cosignature, and §9.7.4.3 states the one check a witness runs and the two objects it produces.

**The superseded required model was the orchestrator's design call and not Alec's.** He asked on 2026-09-08, "So root, witness required, witness decides?", and the orchestrator answered "root decides, witnesses required, witnesses never decide". He never confirmed the required half in his own words. He had already stated the general correction on 2026-09-06: "I said B because you presented as an option that solves the problem not because it was something specific that I wanted. You gave me some options. I chose one."

**Operator independence is not enforceable, and the specification says so in those terms.** Alec asked on 2026-09-07: "those ownership requirements are unenforceable arent they?" They are not. What is mechanical is a local set-membership test against the shipped list together with proof of control of the declared operator identity, which `09-security-model.md` §9.7.4.2's definitions state. Keeping one operator off the list for an identity it also witnesses is a curation obligation the list's curator carries, and a badly curated list is a supply-chain risk of the class a compromised browser root store belongs to. The obligation to state that unenforceability in the specification is this record's own drafting requirement and not Alec's words.

### Where the retired DID document's contents went

The DID document's contents split three ways. Keys, rotation, status, and the pre-rotation commitment go into the key-event log. Transport and service metadata go into a separate resolvable service record, which `03-identity.md` §3.10.13 defines and `18-addressability-and-deployment.md` §18.2.2A accounts for. Attestations become their own signed objects under `27-attestations.md`. The `@context` framing and the informational device roster are dropped. Alec ruled the drops on 2026-08-30, "drop @context/id, devices roster", and accepted the split on 2026-08-31: "custody split: proposal accepted / endorsement: accepted but triple check against history and code first."

The split is what keeps the root cold across a transport change. A relay-endpoint change, a private-state relocation, and a capability-URI edit are each one service-record write signed by the operational key, appending no key event. It is also what keeps the identifier independent of the initial relay list, because an identifier that committed to that list would need a root threshold to change a relay.

**The retired-key retention bound of two is retired.** The append-only log retains the whole key history by construction, so no retention bound applies to it. The size constraint that motivated the old pruning bound went with the mutable record it bounded.

**The `alsoKnownAs` field is re-accounted rather than re-homed.** Its migration-rename use is eliminated, because the identifier is stable and a root recovery renames nothing. Its external-identity-linking use is served by a control-binding attestation to the foreign identity.

**The identifier does not change when the root changes.** No rename therefore tells a relying party that the person behind an identifier may have changed, and fork precedence adopts a chain rather than authenticating a person. Alec approved continuity re-verification on 2026-09-03 as the gate the rename used to supply, and `09-security-model.md` §9.11 states the standing a party keeps per identifier and the acts each standing withholds.

### Implementation constraints

**The pure key-event-log logic lives in a wasm-safe leaf crate**, with no tokio, no input or output, and no thread edge. Asynchronous fetch and cosigning stay in the native identity crate. Alec set both halves on 2026-08-31: "we don't compile to wasm as a backend/server env", and "though, relegating to wasm safe/non-tokio bound leaf crates is good."

**The resolver's mutable cross-identity state is lock-free on the read path**, published through an immutable descriptor, and durable in the persist-before-acted-on class. It is not a monotone maximum, because adopting a lower-sequence rank winner decreases the recorded sequence, and a monotone maximum cannot record that.

**No key-event preimage contains a pointer-width integer, a float, or a value that depends on map-iteration order.** Integers are big-endian and fixed width, and a native-versus-wasm32 known-answer test pins byte identity. `25-test-vectors.md` §25.26 carries the vectors.

**Every time-dependent decision takes an injected clock** and never reads system time directly.

**The key-event-log leaf hash, the event-type tag, and the inception derivation each have exactly one implementation in one module.** A second copy that drifts breaks verification silently.

**No substrate implementation lands before the specifications are amended.** This is a hard gate at this record's level and not a reconciliation that may run in parallel, because code that implemented the log while the specifications still described did:dht would create phantom provenance.

### Executor calls on record

Ten calls the orchestrator made and surfaced to Alec rather than asked about. He may reverse any of them.

1. Superseding a decided ADR takes a new ADR, a status flip on the old one, and the old body retained as the historical record.
2. One ADR covers the whole substrate, with rotation and recovery as log events, and the custody realization stays in the pre-rotation custody discussion and in ADR-054, pre-rotation key custody substrate isolation.
3. ADR-064, cooperative delegation, extends this record rather than replacing it.
4. The persona seam reshapes into a selector between a human identity and a delegated agent identity rather than retiring.
5. ADR-054 keeps its Proposed status, and its did:dht-coupled body re-homes with the specification corpus rather than as a separate edit.
6. The pre-rotation custody discussion keeps its Proposed label, and only its body re-scopes.
7. **The key state carries the current keys only.** A verifier derives every historical key's condition by replaying the log, and a root recovery asserts only the condition changes it makes and the keys it installs. This deletes the every-key-ever enumeration, the four-thousand-key ceiling, the byte arithmetic that measured the repetition, and the controller's duty to enumerate every installed key before it composes a snapshot. Alec's status vocabulary survives, and so does his rule about a retired key and a content signature.
8. **A relay operator's identifier is non-transferable.** An operator's community-relay-list entry carries its P-256 public key, that key does not rotate, and a new key takes a new entry at the next release. This deletes the operator-chain resolution floor, its disclosed truncation residual, the witness-key-state field of both witness objects, and the rule that split which position each object reads. The cost SCP takes on is that an operator whose key leaks is replaced at a release boundary rather than by its own rotation.
9. **Reserve rotation is allowed.** An unexposed member of the next set may be re-committed, and the destruction duty binds revealed keys only. The recommendation of a next threshold of two or more now has a mechanism behind it.
10. **The conflict register is resolved.** Twenty-six of its twenty-seven entries carry a resolution and its author. The twenty-seventh, a proposal that Limn ship an out-of-cycle release to remove an operator, is the agent's proposal and stays open for Alec. Three curator obligations leave the specification corpus for the relay plan as open proposals, because Alec's 2026-09-07 question about who curates the shipped list is unanswered.

## Relationship to KERI

In every citation below, `spec-body` names a section of the KERI specification body, and a name of the form KID000N names a KERI Implementation Document: KID0001 on prefixes and derivation codes, KID0003 on event serialization and element labels, and KID0010 on the witness-agreement algorithm.

### What SCP adopts as KERI states it

Each rule below is KERI's, and the SCP section that carries it cites KERI and restates none of it.

- **Pre-rotation with two thresholds.** The current key list and its threshold, the next digest list and its threshold, and the rule that a rotation satisfies the prior event's next threshold as well as its own (`spec-body` §Key list field, §Key and key digest threshold fields, §Next key digest list field, §Pre-rotation, §General Pre-rotation).
- **Indexed signatures**, which let a threshold set sign without a fixed layout (§Indexed Signatures).
- **The self-addressing identifier.** An event is named by its preimage digest and never by its bytes (§SAID fields).
- **The message-type field**, and the split it draws between establishment and non-establishment events (§Message type field).
- **The sequence number as a location** and never an arbiter between two chains (§Sequence number field, §First Seen Policy).
- **Abandonment by an empty next list**, and its terminality (§Next key digest list field).
- **An identifier that survives the evolution of its key state** (§Autonomic identifier (AID)).
- **Keys in the log and endpoints in signed reply records outside it** (§Reply Message Body).
- **End-verifiability**, under which a validator depends on no other infrastructure (§End-verifiable).
- **A recognized witness set the reading party controls**, which the subject's controller does not (§Indirect exchange via witnesses and watchers).
- **Equivocation evidence that requires holding both versions** of the event in dispute (§Duplicity).
- **A controller that watches its own witnesses** (§Indirect exchange via witnesses and watchers).
- **A key state that carries the current keys** and names no historical key (KID0003 §Key State Notice Messages).
- **Non-transferable witness identifiers**, so a witness needs no log of its own (§Backer list).
- **Reserve rotation**, which holds a next-set member unexposed across several establishment events (§Reserve Rotation).
- **Cooperative delegation**, where a delegator anchors a delegate's establishment events (§Cooperative Delegation, §Delegated Event Live-attacks).
- **A witness that cosigns only what the subject's controller offers it** (KID0010 §Witnessing Policy).
- **A derivation code carried beside every key primitive** (KID0001).
- **The key-event seal's field set** (§Key Event seal).
- **The backward hash chain** that makes one cosignature cover every event below the head it names (§Tetrad bindings).

### What SCP adapts, and why

**Fork precedence.** KERI resolves two versions of one event by first observation and pays for it with a watcher network that makes the first observation ambient (`spec-body` §First Seen Policy, §Superseding Recovery). SCP replaced that with the root rule, on Alec's 2026-09-07 ruling. The reason a first-observation rule cannot stand here: it divides relying parties by what each saw first, and it forecloses recovery from an unforeseen compromise in exactly the case the owner needs it, because the owner's own recovery is the second reveal of the commitment. The substitution is not free, and the Alternatives section below states what it costs.

**The witness layer.** KERI's witnesses gate an event's acceptance through a threshold of receipts and an agreement algorithm (`spec-body` §KERI's Algorithm for Witness Agreement). Under Alec's watch-and-report ruling an SCP witness gates nothing: it runs one check, signs or refuses, and no validity rule reads its signature. KERI's kind-based carve-out, which lets a recovery past a witness's held head, is dropped with the gate, because under watch-and-report a recovery reaches witnesses by naming a fresh set and needs no carve-out.

**The key-event seal.** SCP keeps KERI's seal for anchoring another identity's key event and drops KERI's anchoring of arbitrary data, because SCP content commits through MLS and never touches the log.

**The key state.** SCP's key state carries KERI's field set plus two fields KERI has no analog for: a custody type per key, which declares the substrate holding that key's private half, and the designation of the key that signs the identity's service record.

**Bounds and encoding.** KERI bounds no key list. SCP caps the root set, the next set, and the witness set, and `09-security-model.md` §9.18.17 carries every bound with its reason. SCP writes its own byte layouts under the canonical hash construction of §9.5.1 rather than adopting CESR, and registers every domain separator in one table.

**Discovery.** SCP runs no out-of-band-introduction mechanism and no dedicated witness or watcher pools. A witness is a relay the SDK already ships in the community relay list.

### What SCP owns because KERI does not reach it

**MLS coupling.** SCP encrypts group traffic with MLS, and the key-event log meets that layer at four places: the attestation that binds an MLS leaf to an identity, the leaf replacement an identity's key-state change forces, the sender-key gate a pending continuity standing closes, and the content boundary a key's retirement fixes. KERI specifies no group-encryption layer, so none of the four has a KERI analog. `09-security-model.md` §9.7.1 and §9.11 carry the rules.

**Contexts.** Every SCP interaction happens inside a bounded, governed context, so a verdict about an identity has to be expressible per context. The content boundary and the abandonment boundary are both per-context notions for that reason, and neither is a property of the log. KERI validates an event against a log and knows no such boundary.

**Per-context pseudonyms.** SCP addresses a member by a per-context pseudonym rather than by an identifier, which `09-security-model.md` §9.10.4 states. KERI has no analog, because KERI has no group layer to hide membership inside. The identity substrate reaches pseudonyms at one point: the curve ruling makes pseudonym derivation feed a seed-to-scalar step into a P-256 key generation.

**Relays as transport and as the shipped list.** SCP ships a fixed list of relays with each SDK release, each entry declaring its operator and that operator's key, and `18-addressability-and-deployment.md` §18.5.1 defines the artifact. Two rules read the artifact, the first-contact floor of `09-security-model.md` §9.7.4.2 R11 and the SDK's default recognized set. KERI has no shipped operator list, because a KERI validator picks its own watchers. Relay-side validation stays optional and a verifier depends on no relay for correctness, which `03-identity.md` §3.10.2 states.

**The service record.** SCP publishes every transport and service field an identity advertises in one signed record outside the log, at its own routing derivation, settled by last writer wins on its own sequence. KERI's reply records carry endpoints and carry no equivalent of SCP's broadcast-context advertisements, participation-statements pointer, or attestation-revocations pointer. `03-identity.md` §3.10.13 defines the record.

**Consumer custody.** KERI puts custody in the wallet layer by its own scoping. SCP states it, because the default custody decides whether the protocol's recovery path is real for a person who owns a phone: which substrates may hold a pre-rotation key, which of them is independent of operational custody, what the SDK discloses when a method is copyable, and what the ceremony does before it signs. `09-security-model.md` §9.7.4.1 carries all of it.

## Consequences

**The specification corpus moves before the code.** The rewrite runs in dependency order: the security model's identity core, then this record, then the identity, addressability, sync, persistence, and test-vector specifications, then the sections that only restate them, then the technical overview and the white paper. One writer at a time, each fact in one place, every other site citing it.

**The code follows in one order: the curve, then the key-event log and resolution, then the relays, then the SDK surfaces.** The curve slice carries a build constraint found on 2026-09-10: every core function that takes a raw signing key has to take a signer instead, and every key-export accessor has to leave the custody adapters and all three bridges, because hardware custody on the governance path is impossible until then.

**The work lands on a stack and not on main.** The branch `docs/adr-063-kel-identity-substrate` is the integration base, code slices stack on it, main is merged in regularly, and the stack merges to main when the specifications and the code agree. Alec ruled it on 2026-09-10, "yes, we need a stack", because the specifications cannot land on main ahead of the code: "other agents will organically encounter the discrepancy while working on unrelated things".

**Six items are tracked outside the specification corpus**, each in the plan of record's tracked-items table.

1. **The delegation model** waits on ADR-064, cooperative delegation, and until it lands a verifier rejects every chain naming a delegator.
2. **The identifier's textual form** waits on a later revision of `09-security-model.md` §9.7.4.2 R13, and no derivation the protocol performs waits with it.
3. **The key-event seal's fate, and the two non-compromise retired conditions.** Whether the seal survives, and whether those two conditions collapse into one, are upstream questions for the next draft of this record. No specification pass decides either, and this draft decides neither.
4. **The ripple sweep** covers the stale sites outside the four core homes, in three classes: the agent verification method, the DID document, and did:dht with the Mainline distributed hash table.
5. **What leaves the specification corpus for the relay plan**: the curator's removal obligation, the curation criterion, the pricing prohibition on an entry's cosigning, the out-of-cycle-release proposal, portability across several vendors' applications, and the record that Limn operates public relays.
6. **The stack and the shape of the fresh write** are settled and wait on nothing.

**First-contact discovery stays open.** Mapping a human-readable handle or a referral to an inception-derived identifier is an open item of this record. Those paths supply the identifier, and resolving its key state from there is the Layer A path.

**Two things are deferred by Alec, and no text decides anything about either.** The questions about the relying-party identifier under which the default root custody registers its credential are deferred. Alec on 2026-09-10: "i thought we said we were not going to talk about this right now and didnt have to. if we have to do it now then this question is too detailed too early." `00-open-questions.md` carries them as a dated entry that recommends nothing. Portability of an identity across several vendors' applications is deferred. Alec on 2026-09-10: "do we have to decide on portability right now? want to avoid sidequests." Nothing in the key-event log forecloses any escape the decision log records.

## Alternatives considered

**A KERI-pure key status, where rotation is the only way to retire a key.** KERI's key state names no condition for any key: a rotated-away key is absent from the current key list and appears nowhere else, and KERI's nearest construct marks a whole branch disputed and says nothing about an individual key (KID0003 §Key State Notice Messages, `spec-body` §Superseding Recovery). Rejected, because Alec's 2026-08-30 ruling keeps a distinct root authority, and because the decoupling that ruling buys needs a condition the root asserts about a key rather than the key's mere absence from a list.

**Shipping the `did:scp` facade now.** Rejected by Alec on 2026-08-30: "did:scp: ok. punt, be ready, don't foreclose." The facade costs a method specification, a resolver, and a document format, none of which any SCP path reads, and the identity seam keeps the option open.

**Required witnessing, where a threshold of witness cosignatures conditions an event's acceptability.** This record carried it until 2026-09-10, when Alec superseded it: "watch and report as well". The residual it existed for, a lost root together with a leaked copy of a spent pre-rotation key, does not arise for a user on the default passkey custody, and requiring witnessing makes an identity's usability depend on infrastructure the protocol does not control. The direction of the asymmetry decided the order of the two: relaxing a requirement later costs nothing, and adding one later is a flag day.

**Ranking a fork by witness cosignature.** Rejected on 2026-09-05, before the watch-and-report ruling and independently of it. Ranking by cosignature hands a thief who holds the root and a copied pre-rotation key the win over a controller who holds the genuine pre-rotation key and has lost the root, which inverts the outcome the root rule exists to deliver. A cosignature is evidence a party reads and never a term any rank reads.

**Ordering two valid reveals of one commitment by first observation.** Proposed on 2026-09-06 and withdrawn the same day after four reviewers rejected it, before anything reached a specification. Ordering by first observation divides relying parties by what each saw first. Ordering by any field in the events lets the second author read the first and match it. Every such rule removes recovery from an unforeseen compromise, because the owner's own recovery is the second reveal in exactly the case the owner needs it.

**Ed25519, the curve SCP carried until 2026-09-10.** Nobody chose it: it arrived as the joint default of did:dht, whose identifier is an Ed25519 key, of the MLS baseline ciphersuite, and of the one-algorithm rule this project set. No ADR, planning session, or issue argued it against an alternative, and the one issue that raised the Secure Enclave mismatch was closed by an agent, reopened by Alec for research, and closed again without the research. Superseded by Alec's P-256 ruling on 2026-09-10. Of the three reasons that had been offered for it, did:dht is dead, the MLS baseline governs an ephemeral leaf key rather than an identity key, and the one-algorithm rule is a rule this project set and can set differently.

**Holding foreign identities natively.** Rejected by Alec on 2026-08-30 with one word: "link". SCP attests internally and links to natively-held foreign identities, and native holding stays reserved for the deferred facade. SCP core is not a general-purpose credential wallet.

## Relates to

ADR-003, DID creation over did:dht, is the durable in-repository basis this record supersedes, and its body stays in `.docs/adrs/phase-1.md` as the historical record. ADR-055, remove the WASM bridge, in `.docs/adrs/phase-4.md`, is the supersession precedent.

ADR-039, the shared-DID human-agent identity model, flips to `Superseded by ADR-063` on 2026-08-30 and keeps its body as the historical record, because the shared identity it decided is the structure this record replaces. ADR-064, cooperative delegation, extends this record with the human-to-agent trace and is the artifact that writes the replacing model. Alec confirmed delegation on 2026-08-30, overturning the shared-DID agent verification method: separate delegated identities anchored by a seal in the human's key-event log, with sub-delegation leaf-only for identity and unlimited for authority through UCAN attenuation. KERI states the mechanism under `spec-body` §Cooperative Delegation and §Delegated Event Live-attacks.

ADR-057, in-browser SCP clients over a shared MLS crate, rested on did:dht resolution in its body and now rests on the key-state model this record settles: its attestation-freshness bound reads the log's own rollback rule, and its production-method whitelist reads one identity backend.

ADR-054, pre-rotation key custody substrate isolation, and RFC #2130, pre-rotation recovery custody, are the Proposed realization of the independent pre-rotation custody this record depends on. The dependency is the specification rule in `09-security-model.md` §9.7.4.1, not that Proposed realization.

The security model specification carries the rules this record decides: the ciphersuite and the canonical construction in `09-security-model.md` §9.5 and §9.5.1, pre-rotation custody in §9.7.4.1, the log's validity and precedence rules in §9.7.4.2, the witness and watcher layer in §9.7.4.3, key continuity in §9.11, and the log's constants in §9.18.17. The identity specification carries resolution and the service record in `03-identity.md` §3.10, and the addressability specification carries the community relay list in `18-addressability-and-deployment.md` §18.5.1.

The working plan of record is the identity-substrate plan at `/Users/alec/.claude/plans/identity-substrate-plan.md`, whose §1 states every rule this record decides and whose §2 states the sequence. The dated reasoning and the verbatim quote record sit in the identity-substrate decision log beside it.
