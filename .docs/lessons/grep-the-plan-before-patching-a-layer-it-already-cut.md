# Grep the Plan Before You Write a Decision About a Layer the Plan Already Cut

**Source:** the identity-substrate spec passes 7 and 8 on `.docs/specs/03-identity.md` and
`.docs/specs/09-security-model.md`, corrected by Alec on 2026-09-05.

## What happened

The identity-substrate plan settled two rows before pass 7 began: it axed the Mainline DHT
resolution layer, and it cut did:web. Passes 7 and 8 kept both alive in the two specs and
patched them. Pass 7 scoped the DHT layer's store as an availability path, pass 8 gave the
DHT layer a signed head-pointer record with a 1000-byte bound, both passes carried a
`DhtMode::Disabled` branch through the first-contact rule, and pass 8 wrote a did:web exit
for the key-continuity standing. Across review rounds 5 and 6, twelve reviewer findings
argued about a layer the plan had already removed. Pass 9 deleted every one of those
sentences.

## The cause

The orchestrator wrote the pass-7 and pass-8 decisions from the reviewers' findings without
reading the plan's settled-decision table. Each finding described a real defect inside the
DHT layer, so each decision that repaired the layer read as correct work. Nothing in a
finding says that the layer it names does not exist; only the plan says that.

## The rule

Before writing any decision about a layer, a method, a backend, or a dependency, grep the
plan's settled-decision table and its track list for that layer's name, and read the row.
A layer the plan axed is deleted, never patched: the decision to write is which sentences
lose their subject, not how the layer should behave. A reviewer finding inside a cut layer
is evidence that the layer is still in the text, and the fix is the deletion the plan
already ordered.
