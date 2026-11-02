# ADR-069: Node-Ordered Commits

**Status:** Accepted 2026-11-02. Alec settled the design on 2026-10-25 (decisions D1 to D3 and question Q4 of the context-operation plan), and ruled "Rewrite now" on 2026-11-02 for the artifacts that ADR-067 had shaped.

**Supersedes:** ADR-067, Concurrent Commits and fork merge, in `phase-6.md`. ADR-067's status flips to `Superseded by ADR-069`, and its body stays as the historical record.

**Amends:** ADR-066 decisions 5, 10, 32 and 40 and its acceptance-criteria paragraph; ADR-031 §7 and its 2026-10-17 amendment; ADR-029 §5b, §5c and §6 step 4, and its rationale paragraph on conflict resolution; ADR-001 criterion 6; ADR-051 §3, "No trusted sequencer". Each amended record carries a dated amendment that names this record.

**Spec:** `07-trust-validation-and-capabilities.md` §7.3.1 and §7.3.1.1 ("Competing Commits", "Commit order"), `05-contexts.md` §5.13.3 rules 11 and 16, `09-security-model.md` §9.5.2, §9.7.1, §9.7.2, §9.9.3, §9.14 and §9.18, `10-infrastructure-and-self-hosting.md` §10.2, §10.3 and §10.8.1, `23-sync-and-offline-strategy.md` §23.4, §23.5 and §23.7, and `25-test-vectors.md` §25.33.

## Context

`admit_and_merge_own_commit` (`crates/scp-mls/src/group.rs`) merges the committer's own Commit before anyone orders it. When two members commit at one epoch N, each merges its own Commit, and each member's openmls then rejects the other Commit as `WrongEpoch`, so the group splits.

ADR-066 decision 5 had answered the race with "Epoch order decides conflicts": a Commit that loses the race for an epoch never merges, and its executor re-checks it and sends it again. That rule needs one order of Commits that every member reads. On 2026-10-24 no party could give that order, because Alec had ruled "We can’t rely on daily presence" and the relays were untrusted store-and-forward services. ADR-067 therefore let every member keep both children of an epoch, choose one by the least (rank, cth), and re-apply the losing child's changes through fork records, imports and a merge function G. It needed sixteen mechanisms (M1 to M16), a fifth body item `merge` in the governance block, a journal, a key ledger, an epoch table, branch retention for up to seven days, a PPRF over child init secrets, two signed notice records, and ten accepted residuals.

On 2026-10-25 Alec settled how a context runs (`~/.claude/plans/context-operation-plan.md`, rulings 1 to 10):

- "Contexts most certainly have operators, and in fact, require them." "Nodes are pieces of infrastructure that operate many things. One of those things could absolutely be a specific context."
- "if a context runs on a single node and that node is off then the context is unreachable. Se la vie."
- "The context is the engine for finalization." "Why would governance be involved? It's an immutable part of the protocol".
- D1: "One node runs a context and is its MLS Delivery Service: it totally orders submitted Commits, one per epoch. Members verify every Commit."
- D2: members submit Commits directly to the context's node, with the priority class (Remove, re-join, other) as a field of the submission outside the MLS message, ordered "Remove first, then re-join, then arrival."
- D3: "The node holds no MLS group secrets."
- Q4: the node signs each chain entry (position, item hash, previous hash) and returns a signed receipt that assigns a position to each accepted submission, under a key the operator binds to its identifier when the context is instantiated.

A node that runs the context is online whenever the context is reachable, so the ordering party that ADR-067 lacked exists. The question this record answers is how members turn the node's order into one Commit per epoch when the node cannot read a Commit.

## Options considered

1. **Keep ADR-067 and add the node as a relay.** Every mechanism of ADR-067 stays, and the node only delivers. This lost because the node already gives a total order, so every mechanism that exists to merge two orders protects against a case the node removes. ADR-067's own necessity table justifies each mechanism by a fork, and a fork needs two Commits that two members both merge.
2. **The node accepts one Commit per epoch and refuses the rest.** The node reads the epoch from the `PrivateMessage` framing (RFC 9420 §6.3, which leaves `epoch` in the clear), appends the first Commit it receives for the current epoch, refuses the rest, and then expects the next epoch. This lost because of D3: the node holds no group secret, so it cannot verify a Commit. A member that sends a malformed Commit for epoch N would take epoch N's place, every member would reject it, and the node would refuse every honest Commit for epoch N as stale, so the context would stop. The node also cannot prove a refusal (Q4: "Refusal to accept is provable to no one").
3. **The node orders every submission, and members take the first valid Commit for each epoch.** The node appends every submission it accepts to one signed chain. Every member processes the chain in position order, and the canonical Commit for epoch N is the first Commit in the chain that names epoch N and passes the member's verification at epoch N. This option is chosen. It meets D1 ("one per epoch", "Members verify every Commit") and D3, because the choice reads only the chain order and each member's own verdict, and ADR-066 decision 10 makes that verdict a function of the Commit's bytes and the state every member holds identically.
4. **A member quorum or a witness set signs the order.** Members or witness nodes would sign which Commit comes first. This lost because Alec ruled on 2026-10-25 that "The context is the engine for finalization" and asked of governance "Why would governance be involved? It's an immutable part of the protocol", so no member, witness or governance action takes part in ordering.

## Decision

1. **The node orders.** The node that runs a context is its MLS Delivery Service, the role RFC 9750 (the MLS architecture) gives the service that orders and delivers a group's messages. A member sends each Commit it makes to that node, at the address the context's `ContextNodeAddress` names. The node appends every submission it accepts to the context's chain at the next position, signs the chain entry, and returns a signed receipt naming the position (Q4). The node holds no MLS group secret (D3), so it never decides whether a Commit is valid.
2. **Priority.** Each submission carries its class outside the MLS message: Remove, re-join, or other (D2). Among the submissions it holds and has not yet appended, the node appends Remove-class submissions first, then re-join-class submissions, then the rest in arrival order. A Commit is Remove-class when its derived leaves include a `MemberLeft` leaf, re-join-class when it is an external re-seat or its derived leaves include a `MemberReset` leaf and no `MemberLeft` leaf, and other-class otherwise. The chain item is the submission as received (`item_hash` and the receipt's `submission_hash` hash the same bytes), so every member reads the class, and every member treats a Commit whose class differs from the class its content gives as invalid at its position. D2 does not say how long the node holds a submission before it appends it, and the priority order changes nothing while the node holds one submission at a time. `00-open-questions.md` records that question ("Node append timing and the D2 priority order").
3. **One Commit per epoch.** Every member processes the chain in position order. At epoch N, the canonical Commit is the first chain item that is a Commit naming epoch N and that passes steps 1 and 2 of `07-trust-validation-and-capabilities.md` §7.3.1.1 "Receiver processing" in the member's state at epoch N. A member skips every other Commit: a Commit naming an epoch below its current one, and a Commit naming its current epoch that fails verification. A skipped Commit changes no member's state. Because every member's verdict reads only the Commit and state that every member holds identically (ADR-066 decision 10), every honest member merges the same Commit at every epoch.
4. **The committer merges its own Commit at its position.** A committer keeps its own Commit staged and unmerged after it submits it. It merges the staged Commit when, processing the chain in order, it reaches the position its receipt names and its group is still at the epoch the Commit names. When an earlier chain item moved its group past that epoch, it discards the staged Commit, re-checks its action against the new state, and submits it again or reports the proposal `Invalidated`, as ADR-066 decision 5 states. The committer never merges a Commit that the chain does not hold.
5. **Conflicts are serial.** "Committed first" in ADR-031 §7 means earlier in the chain. The conflict rule of §7.3.1.1 "Conflicts" and the executed-proposal set settle every pair of actions in chain order, and no merge function runs. The `member:X` conflict key stays: the governance state keeps `change_seq["member:X"]` after X leaves, so an Add of X anchored before a Remove of X loses to that Remove, and an invitation anchored after the Remove passes.
6. **The governance block has four body items.** The body loses item 5, `merge`, and with it the fork record, the import leaves, the re-applications and the carried re-seats. The body bound returns to 1 + 168 + 3 + 16,224 + 15,616 + 1 = 32,013 bytes, 751 bytes below the 32,764-byte body (`07-trust-validation-and-capabilities.md` §7.3.1.1, "Why 32,768 bytes and 96 approvals").
7. **No merge state.** The journal, the key ledger, the epoch table, the fork records, the imports, the pending joiners and the re-seat windows leave the governance state, and `merge_state_hash` leaves the `0xFF02` extension (`05-contexts.md` §5.13.3 rule 16 is withdrawn). A Commit with an empty block again carries the GroupContextExtensions proposal with its extensions unchanged (ADR-066 decision 32).
8. **The re-join.** An external re-seat (`09-security-model.md` §9.7.1) is a Commit like any other in the chain: the identity submits it with the re-join class, and the first valid Commit for the epoch wins. When another Commit for that epoch is earlier in the chain, the identity sends a new re-seat request and re-seats at the epoch it is answered from, which keeps Alec's ruling of 2026-10-21 that the re-joiner "rebuilds its Commit against the new epoch and sends it again". Rank −1, the re-seat window, the `D_MAX` send rule, the carried re-seat and the unused carried seat are removed.
9. **Verdicts read no clock.** The choice of decision 3 requires every member to reach one verdict on each Commit, and openmls reads the system clock when it validates a LeafNode or KeyPackage lifetime on receipt. Two artifacts disagree on how SCP meets this, and this record does not settle it: `09-security-model.md` §9.7.1 records Alec's answer of 2026-10-04, "no patch, bound, leave us a note for the happy future path", under which SCP bounds openmls's check, while ADR-067 added an openmls patch that sets `LeafNodeLifetimePolicy::Skip`. `00-open-questions.md` lists the question ("openmls lifetime check under node order").

## Invariants ADR-067 protected

Each row names an invariant ADR-067 protected and where it now lives, or why it no longer arises.

| # | Invariant | ADR-067 mechanism | Under node order |
|---|---|---|---|
| I1 | Two Commits at one epoch never split the group | M1, M2, M9 | Protected by decisions 1 and 3: every member reads one chain and merges the same first valid Commit per epoch. |
| I2 | Every device of every member chooses the same Commit | M2, M2r | Protected by decision 3; the choice reads the chain position and a verdict that ADR-066 decision 10 makes identical at every member. |
| I3 | A committer never merges a Commit that loses | M14 | Protected by decision 4: the committer merges only at its own chain position. |
| I4 | No change is lost silently, and its author learns the outcome | M3 obligations 1 and 3, `ConcurrentChangeExpired` | Protected by decision 4 and ADR-066 decision 5: a Commit that is not first executed nothing, and its executor re-checks it and submits it again or reports the proposal `Invalidated`. |
| I5 | A re-joiner and a Remove are not starved by a member that commits nonstop | M2r, M4 rank-0 window, rank −1 | Protected by decision 2 when the node holds more than one submission at once. How long the node holds a submission is open (`00-open-questions.md`), so this row depends on that answer. |
| I6 | A removed member is not re-added by an Add anchored before the Remove | M3 obligation 1(d), `member:X` | Protected by decision 5: the `member:X` key is a serial conflict rule. |
| I7 | A change executes at most once | M6 collision rule, change identities | Protected by the executed-proposal set, the reset counter floor and the revocation set, because only one Commit per epoch executes anything. |
| I8 | Retained key material is bounded and consumed keys stay unrecoverable | M1, M12 | Does not arise: no member keeps a state that is not on its one path, so RFC 9420's deletion schedule applies as written, and a committer's discarded staged Commit holds no secret of a merged epoch. |
| I9 | A joiner can check the governance state it rebuilds | M13 `merge_state_hash` | Protected by `log_head_hash`, `governance_state_hash` and `key_positions_hash`; no merge state exists to check. |
| I10 | An honest fork raises no equivocation alert | M16 | Does not arise: honest members never hold two logs. A log disagreement is the node equivocating, which two chain entries for one position prove (Q4). |
| I11 | Verdicts read no clock | SCP-357, the openmls patch | Required by decision 9; the mechanism, a patch or the 2026-10-04 bound, is open (`00-open-questions.md`). |
| I12 | A late release does not undo a merged re-join | Carried re-seat, M5a depth bound | Does not arise: the chain is append-only, so no Commit is released after members merged a later one. |
| I13 | A departure can be re-executed after the member uninstalls | M10 `DepartureRequest` | Does not arise: no losing branch exists to re-execute from. |
| I14 | A member a losing branch removed reads no message on the canonical path | M11 send barrier | Does not arise: a Remove is final when its Commit is canonical, at every member. |
| I15 | Members on two sides of a divergence see it | M15 `ForkNotice`, `GroupSplit` | Does not arise among honest members. A node that shows two chains signs two entries for one position, which any member can prove and act on by re-founding (plan D9). |
| I16 | Two devices of one person converge | M9 | Protected by decision 1: both devices read one chain from one node. |
| I17 | A restrictive-only change (a Remove, a revocation) is never dropped | G, restrictive-only class | Protected by decisions 2 and 4: a Remove has first priority, and an executor whose Remove was not first submits it again. |
| I18 | A re-added member's KeyPackage is used once | M8 fresh KeyPackage | Does not arise: no Add is re-applied. |
| I19 | The tree's leaves match the governance membership | M8 tree reconciliation | Does not arise: one Commit per epoch changes both together, as before ADR-067. |

## Consequences

- Two members that commit at one epoch no longer split the group, and no member keeps parent states, branch stores, a PPRF over child init secrets, a journal, a key ledger or an epoch table.
- The governance block body has four items, and the body bound is 32,013 bytes. Spec 25's fork-merge vectors (§25.33, Vectors 71 to 79) are removed, and the `ForkNotice` and `DepartureRequest` preimages and the fork record leave `09-security-model.md` §9.5.2.
- A context with its node off makes no progress: no member can commit until the node returns (ruling 4).
- A malformed or stale Commit costs a chain position and changes no member's state.
- A member trusts the node for liveness and order, never for validity, because every member verifies every Commit. A node that equivocates or drops a receipted submission is proven by its own signatures (Q4) and answered by re-founding (plan D9).
- The starvation guarantee of decision 2 depends on the node's hold time, which `00-open-questions.md` lists as open.
- Withdrawal and re-signing by key rotation (`05-contexts.md` §5.9.1, ADR-066 decision 10) still rest on an Update that rotates `signature_key`, and `propose_update` (`crates/scp-mls/src/ratchet.rs`) passes `LeafNodeParameters::default()`, so no Update rotates it yet.
- This record changes the order of Commits only. Plan decision D6 also has the node order application messages in place of ADR-051's causal DAG, and the artifacts that describe the DAG are not changed by this record.

## Acceptance Criteria

The stories that implement this record list their criteria in `.docs/prds/main.json` under the gate `gate-node-order`: SCP-357 (a Commit kept staged and unmerged until its chain position), SCP-351 (the first valid Commit per epoch, and the committer's merge at its own position) and SCP-361 (the `member:X` conflict key). The node side of decision 1, the chain, its receipts and the submission transport, belongs to the execution of plan decision D1, which `~/.claude/plans/identity-artifacts/node-backend-execution-plan.md` records as having no story yet.
