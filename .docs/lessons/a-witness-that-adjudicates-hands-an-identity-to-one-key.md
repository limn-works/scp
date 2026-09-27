# A witness that adjudicates hands an identity to one key

## The criterion

`09-security-model.md` §9.7.4.3, the witness and watcher layer, states the one check a witness runs and states the fresh-set path a recovery takes. A witness never adjudicates between two chains.

The test to apply to any proposed witness rule: does it ask the witness to decide something. A rule that lets a witness accept an event outside its one check has made the witness an adjudicator, whatever the rule is called.

## The instance

Two rewrites of the witness layer failed, and both failed at the same sentence — the one that let a witness say yes to an event that did not extend its last cosigned head.

**The supersession carve-out.** The first design let a witness accept an event that superseded the chain it had been cosigning, on the reasoning that a recovery is a legitimate non-extension and the witness must not block it. That rule hands the identity to whoever presents such an event. The witness cannot tell a controller's recovery from a thief's fork, because both arrive as a signed event that does not extend the last cosigned head and both claim to be the recovery. The carve-out converts the one check into a check the attacker chooses the input to.

**The head-establishment repair.** The second design tried to close that hole by having the witness re-derive which head was the legitimate one before deciding whether to cosign. That is adjudication written as a repair. It gave the witness a fork-choice rule, which put the fork verdict in the witness layer, where a threshold of witnesses then decided the identity — and a corrupted threshold takes the identity outright.

Alec settled the layer on 2026-09-10 with "watch and report as well", superseding the required-witnessing model of 2026-09-07 under which a threshold of witness cosignatures was a condition of an event's acceptability. The decision log records that he did not confirm the "required" half of that earlier model in his own words. `09-security-model.md` §9.7.4.3 states the settled model.

## The fix

**Name a fresh set; never write a smarter witness.** `09-security-model.md` §9.7.4.3, the witness and watcher layer, states the path a recovery takes to a fresh witness set. The outgoing witnesses go on refusing the recovered suffix, and they report truthfully that the chain they were watching did not continue.

**Keep the fork verdict out of the layer.** §9.7.4.3 enumerates what the layer produces, and the root rule of `09-security-model.md` §9.7.4.2, root-authority recovery and fork precedence, settles every fork.

**Read a proposed `MAY` as an adjudication in disguise.** Both failed designs were expressible as a permissive clause: a witness *may* accept a superseding event, a witness *may* re-derive the head. A permission to accept something the one check rejects is the whole defect, whatever its modal verb.
