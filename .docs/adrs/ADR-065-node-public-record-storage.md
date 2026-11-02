# ADR-065: Node Public-Record Storage

**Status:** Accepted 2026-11-02. ADR-063, the inception-derived identity key-event log, reserved this number on 2026-09-21 for "the relay ADR, pending", when Alec split that record's branch and moved seven relay-storage sections out of it. Round 3 of the key-event-log node backend design replaced relays with nodes, and its per-kind storage table and quota classes closed the review that the relay ADR waited on. This record takes the seven moved sections, rewritten for nodes, and adds that table and those classes.

**Spec:** `09-security-model.md` §9.7.4.2 R9 (*What a node may do, and what no node decides*; *What a validating node keeps, per retained kind*), §9.10.12 (Node Record Frames), §9.6.3 (Node List Authentication) and §9.18.B (Configurable Parameters); `10-infrastructure-and-self-hosting.md` §10.4 (Node Architecture: **Storage and quotas**, **Every conforming node validates public records**, **Identity private state**); `03-identity.md` §3.7 (identity private state).

## Context

A node serves two roles (`10-infrastructure-and-self-hosting.md` §10.4). As the node of a context it orders that context's submissions, which ADR-069, Node-Ordered Commits, decides. As a public-record store it stores and serves key-event logs, service records, witness cosignatures, conflict statements, node-list records, identity private state and KeyPackages. This record decides the second role: what a node admits, what it keeps, how it bounds what it keeps, and what it may charge for.

A node authenticates no publisher (ADR-004, the SCP native relay protocol), so a node cannot tell an identity's controller from a third party that copied the controller's records. Every rule below therefore reads the record's own signatures, and no rule reads who sent it. The failure every rule guards against is a third party that freezes an identity or the node list, or locks its owner out, by writing records an honest node then prefers over the owner's.

ADR-063 states the identity model and owns no storage rule. Its heading *The relay's storage policy moved to the relay ADR on 2026-09-21* lists the duties that bind a validating node, each with the specification section that states it. The tag `archive/kel-combined-pre-split` preserves ADR-063's combined text, which carries the seven sections below in their relay-era wording and the twenty-one executor-call entries that moved with them.

## Decision

### 1. Every conforming node validates, and validation is defense in depth

**Every conforming SCP node runs the full R3 check order on every event of a key-event frame before it stores the frame, and runs each other retained kind's admission rule before it stores a record of that kind** (`10-infrastructure-and-self-hosting.md` §10.4; `09-security-model.md` §9.10.12). Alec answered "1. ok" on 2026-09-27 to the proposal that a listed relay validate the key-event records it stores, which ADR-063's register entry of that date records. Round 3 extended the duty from listed nodes to every conforming node and from key-event records to every retained kind.

The check keeps records no reader would apply out of the storage R9 bounds. It is never a trust dependency: every reader runs the same check order on every event it reads, so a node that skips the check degrades availability and changes no verdict. The tenet "Encryption as access control" permits exactly this: a node validates a public, self-certifying record it stores, and never validates encrypted content.

### 2. Admission and selection per kind

**A node's selection mirrors the verifier's own retention rules.** A node keeps what `09-security-model.md` §9.7.4.2 R9 says a verifier keeps, keyed as R9 keys it. It holds every chain it retains under R9, the accepted chain and every retained suffix alike, and it selects per chain. It never selects by the one chain it currently accepts, because a fork author who could make a node accept its chain would then strip the honest chain's service records and witness heads from that node.

The per-kind table below is the one `09-security-model.md` §9.10.12 states. This record carries the reason behind each row's freeze-and-lockout column.

| Kind | Admission | Selection | Why no third party freezes or locks out |
|---|---|---|---|
| `scp:did:` | R2 and R3, refusing with `4040` or `4044` | R9's accepted-chain rule and suffix retention, bounded by `MAX_RETAINED_SUFFIXES` and `MAX_RETAINED_BYTES` | R9 bounds the suffixes and ranks them by R6, so a forger's suffix displaces no chain that outranks it. |
| `scp:svc:` | The frame verifies under the service key that some chain the node retains designates at the record's position; with no log of the identity held, the node refuses with `4040` | Per (subject, designated service key), the `03-identity.md` §3.10.13 settlement winner, so at most `MAX_RETAINED_SUFFIXES + 1` records per subject | A record under one chain's designation never displaces another chain's. A reader's R6 picks the chain, then reads the record that chain's designation signed. |
| `scp:wit:` | Signed by the node key of a `NodeBinding` the node holds; the subject's key state on the chain carrying the head's `event_digest` names that binding's `NodeId`; standing in the held node list gates only the opening of a new (subject, witness) slot | Keyed (subject, witness, `event_digest`) across every retained chain, never on the suffix, at most `MAX_WITNESS_SET_SIZE` × `MAX_RETAINED_SUFFIXES` = 256 heads per identity; the binding bytes stored with each head | Both heads of a fault-proof pair survive at one key, so a fork author cannot strip the honest branch's heads, and a third party holds no bound node key. A head from an attributed key that conflicts with a held head, and a conflict statement naming one, are always admitted, so removing a witness from the list never shields a fault it already committed. |
| `scp:wcf:` | Signed by a bound node key that the subject's key state names on either conflicting chain, with both conflicting heads verifying | One per (witness, retained suffix), the highest `observed_at` | As `scp:wit:`. |
| `scp:nls:` | Verifies under the governor's `#active` at the record's `signing_key_state_head`, in the governor key state the node holds; the node drops each record whose signing key a later governor event marks `Compromised` | The highest sequence per governor signing key; records under the current key served first | A thief's record at sequence 2^64−1 under an old governor key displaces nothing under the current key. |
| Identity private state | The write proof (decision 4); the content is encrypted and never validated | Append-only per routing id, bounded by the private-state quota class | Routing ids and write keys differ per node, so no node or third party addresses another node's copy. |
| KeyPackage set | The set verifies under the subject's `#active` that is `Current` in the key state the node holds, and every package passes the node's KeyPackage admission (`10-infrastructure-and-self-hosting.md` §10.7.1) | Per (subject, device), the highest per-device sequence under the current `#active`, with slots bounded by the key state's device count; a set at or below the held sequence is refused | A replayed older set has a lower sequence and displaces nothing. A thief of the current `#active` can pin a device's set at sequence 2^64−1 until the subject's §9.12 rotation, and the rotation drops every set under the old key. |

The KeyPackage row records round 3's design and its amendment items X3, L3 and L4. `09-security-model.md` §9.7.4 and `10-infrastructure-and-self-hosting.md` §10.7.1 still describe KeyPackages at relays, and the spec change that states the set and its separator `SCP-KEY-PACKAGE-SET-V1:` has not merged. The set keeps the KeyPackage routing ID `09-security-model.md` §9.7.4 already defines, so one object keeps one address.

**Rejected: selecting by the chain the node accepts.** Round 2 of the design had a node keep each kind's records for its own accepted chain. It costs nothing to compute, and it fails: a fork author whose chain a node accepts first strips the honest chain's service records and witness heads from that node. Selection per chain costs a node one bounded record set per retained chain.

**Rejected: refusing a witness head once the witness loses standing.** It keeps a node's store to listed witnesses only. It also lets an operator that the governor delisted shield the conflicting head that proves its fault. Standing therefore gates only the opening of a new (subject, witness) slot.

### 3. Four quota classes, keyed on routing id, with no value

**The protocol defines four quota classes, each keyed on routing id: retained public records (`scp:did:`, `scp:svc:`, `scp:wit:`, `scp:wcf:` and `scp:nls:`), KeyPackages, identity private state, and TTL-bearing blobs** (`09-security-model.md` §9.10.12; `10-infrastructure-and-self-hosting.md` §10.4). Only the TTL-bearing class carries a TTL. A node applies its quota to the validated selection and never to raw writes, so a write the selection would keep and the quota cannot hold is refused under the node's declared terms, and a third party's junk writes, which validation refuses, spend no owner's quota.

The protocol sets no quota value. Asked on 2026-10-24 whether the operator setting `SCP_RELAY_MAX_BLOB_TTL` should go away, Alec ruled: "Remove we will add and design quotas later". The classes exist so that each kind's bound is separable: a node that fills its TTL-bearing class with Commits and Welcomes cannot thereby refuse an identity's key-event log, and the message-lifetime bound reads only TTL-bearing blobs, so no lifetime setting expires a retained record.

**Rejected: one quota over everything a node stores.** It is one figure to declare. A burst of TTL-bearing traffic would then refuse key-event writes, which turns a traffic spike into an identity freeze.

### 4. Identity private state carries a per-node write proof

**The first write to a private-state routing id stores `SHA-256(write_key)` at the node, and every later write and every delete there presents `write_key`** (`03-identity.md` §3.7; `10-infrastructure-and-self-hosting.md` §10.4 **Identity private state**; ADR-004 operations 1 and 5). The owner derives the routing id and `write_key` per node from its PSK through HKDF, with one derivation id per target node that the identity's `IdentityPrivateState` service entry records (`03-identity.md` §3.7, amendment item X5 of round 3). AES-256-GCM encrypts the blobs under a separate derived `enc_key`, so no key serves both as an HKDF input and as an AEAD key.

The proof exists because a node authenticates no publisher and private state carries no TTL. Without it, the blobs at an old routing id would stay on the node forever after a PSK rotation, and any party that learned a routing id could append to it. After a rotation each device keeps the derived old pair (routing id, `write_key`) for each node, never the old PSK, until the delete at that node succeeds.

**Rejected: a single-owner context on a node, as round 3's option B.** It applies `03-identity.md` §3.7's sentence that private state is the single-owner case of context state. A phone-only identity runs no node, so its context would need another party as operator and member, which breaks the single-owner premise, and the state would be unreachable whenever that one node is off.

### 5. A node may stop holding a record, and no retained record expires

**A node may refuse a write, and may stop holding what it once held, on terms its operator declares; a refusal is never a verdict about the identity** (`09-security-model.md` §9.7.4.2 R9). Retained kinds carry no TTL. R10's self-observation cadence re-publishes what a node stopped holding, so the controller needs no reason from the node. A verifier reaches its verdict from the events it read and the node list it accepted, and from nothing a node asserts.

### 6. The seven sections moved from ADR-063, rewritten for nodes

Each section below keeps Alec's words as his. `09-security-model.md` §9.7.4.2 R9 states only that a node declares its terms. The rent and ring-buffer rulings fix what those declared terms are, and the quota design that Alec's 2026-10-24 ruling postponed will state their figures and their fields.

**A node's storage policy.** Alec settled what bounds a node's key-event storage on 2026-09-13, and the decision is his. A per-identifier byte ceiling misses the actor: "the risk is bad actors not theives", and `09-security-model.md` §9.7.4.2 R9 states why. He asked for both halves of the answer, "we need both eviction and denial", named rent as a bound a node already has, "relays can already charge rent.", and closed the exchange with "ok." Four parts of that decision are his: denial, eviction, rent, and the frame that holds the three together. `MAX_ACCEPTED_CHAIN_BYTES` is withdrawn; `MAX_RETAINED_BYTES` stays, as a per-source, per-resolution fetch bound at the verifier and as the byte bound on what a node retains for one identity.

**Proof of work is cut.** Alec, 2026-09-14: "cut it", answering the orchestrator's statement that filling a 512 MiB store at 24 bits of difficulty costs about two minutes of one GPU. No node declares a difficulty, no PUBLISH carries a puzzle nonce, and no refusal scope names one.

**A node's retained storage is a ring buffer.** Alec, 2026-09-14: "ok ring buffer". Where a node declares a retained-storage bound, the newest write displaces the oldest, with no idle clock, no refresh write and no pressure ordering, so `EVICTION_IDLE_SECONDS` is deleted. The ring's unit and order are the executor's derivations, which the next section states.

**The units are the identity and the chain.** Alec, 2026-09-14: "slot is a bad name for the chain unit. why do we need special names? identity, and chain, no?" The per-fork unit a node stores is a chain, and the unit the ring displaces is everything the node holds for one identity. The ring never reaches the divergent suffixes a verifier retains under R9's count and byte bounds. A node never displaces the identity whose write it is admitting.

**What a payment buys is the operator's to declare.** Asked what a payment buys, Alec answered on 2026-09-14: "suppose its up to the operator?", and confirmed the stated resolution with "ok". A node that charges declares which refusal scopes it exempts a paying identity from, in the `node_config` object it publishes at `.well-known/scp`, which `IdentityBackend::read_policy` reads (`03-identity.md` §3.10.10), so a publisher reads what its money buys before it spends. He confirmed two further sentences in the same answer: a node never evicts the identity it is currently writing for, and a payment covers the identity it names up to the bytes it paid for, with the excess being ordinary evictable data.

**Coverage is rent.** Alec, 2026-09-14: "it's rent. as long as you keep paying. operator says, \"pay x at y frequency, get quota a of b thing\"." A node that sells coverage declares a rent price, a rent period and a quota of stored bytes. Coverage lasts while the rent is current and lapses when it is not.

**What a rent exempts applies to storage, in amount and duration, and not to traffic.** Alec, 2026-09-14: "it should really only apply to storage (amount, duration). not to traffic." A rent therefore exempts no rate limit, which is traffic, and names no receipt as storage. The executor added a third exclusion on its own ground: a node cannot store past the capacity its own host holds, so no rent exempts a node-wide total.

### 7. The twenty-one moved executor-call entries

Twenty-one of ADR-063's executor-call entries moved with the seven sections, and the tag `archive/kel-combined-pre-split` keeps their full text under ADR-063's archived numbering. **None is a live rule unless `09-security-model.md` §9.7.4.2 R9, §9.10.12 or this record's decisions 1 to 6 state it.** The entries that name the rent receipt, its wire fields and the exemption set wait on the quota design Alec postponed on 2026-10-24, which decides whether each returns. By archived number:

- 20, proof of work reintroduced on 2026-09-13 and cut on 2026-09-14;
- 21, the unit the ring displaces is one identity;
- 22, `Identifier` and `Total` name two different bounds;
- 23, PUBLISH carries a `payment_receipt`;
- 25, `receipt_exempts` names the field carrying what a current rent exempts;
- 26, the two-member exemption set is superseded;
- 27, coverage is a cap, never a sum credited per write;
- 28, the receipt comparisons sit behind the call that returns their operands;
- 29, `write_binding` and `frame_value_digest` are deleted;
- 30, `RENT` is a client operation of its own;
- 32, the payee comparison is deleted;
- 33, `RENT` names its beneficiary under a signature;
- 34, one verified rent payment has one stated effect;
- 35, no node charges a `scp:wit:` or `scp:wcf:` write;
- 36, the exemption's currency is the identity's current rent;
- 37, a node serves a routing id's frames interleaved across every chain it holds there;
- 38, a validating node's accepted chain wins every pairwise R6 comparison;
- 39, a node never serves a head it has verified superseded;
- 40, every destructive act on a PUBLISH runs behind chain verification;
- 41, a payment sets the quota to what it bought;
- 44, the spent set gains a retention rule.

### 8. The relay-layer scope Alec ruled on 2026-09-21

Alec chose on 2026-09-21 not to defend relays against a party holding a threshold of a victim's pre-rotation keys and no root member: the orchestrator offered "defend it" and "do not defend", and he chose "Do not defend". ADR-063 records the choice and named this record as the one that carries the node-layer scope. **No node rule exists whose only reason is that party**, as no node rule exists against a root holder (ADR-063, *Root theft is not solvable*).

## Consequences

- The node's public-record store is built in `scp-node`, which already depends on `scp-identity`, so the store adds no crate edge.
- A node declares its terms and a publisher reads them; neither the SDK nor a verifier treats a node's refusal or a node's silence as a verdict.
- Quota values, the rent fields and the payment receipt wait on the quota design Alec postponed on 2026-10-24. Until it lands, a node declares no quota value, and the four classes bound nothing.
- The KeyPackage set row waits on the spec change that states the set; until it merges, `09-security-model.md` §9.7.4 governs KeyPackages as it stands.

## Alternatives considered

**A per-identifier byte ceiling on the accepted chain.** Rejected by Alec on 2026-09-13: "the risk is bad actors not theives". A ceiling sized against a thief prices out an honest controller whose chain is long, and the party it was proposed against writes many chains instead of stealing one. ADR-063's Alternatives section records the ceiling and the checkpoint that fell with it.

**Proof of work as the write price.** Reintroduced on 2026-09-13 and cut by Alec on 2026-09-14 ("cut it"), because a GPU fills a node's store in minutes at any difficulty an honest phone can pay.

**Designation as a write permit**, where a node stores an identity's records only when the identity's service record designates it. Withdrawn: it would make the node list an admission service, which the tenet "The protocol requires no operator" forbids, and it constrains no node that charges nothing.

**Each rejected option in decisions 2 to 4** is stated beside the decision it lost to.

## Relates to

ADR-063, the inception-derived identity key-event log, is upstream: this record cites it for R6's rank, the R9 retention rules, the key-event record frame, the node list and the witness objects. ADR-004, the SCP native relay protocol, is the wire every rule here travels on, including the `retain` flag, the `write_key` guard and the `4041` and `4043` refusals. ADR-069, Node-Ordered Commits, decides the node's other role, ordering a context's submissions, and nothing in this record governs that role.
