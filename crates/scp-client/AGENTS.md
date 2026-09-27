# scp-client

Test transport behavior against the relay model in `tests/common/mod.rs`, which reproduces what the real relay does: a subscription table, delivery of every publish back to its publisher, subscribe-before-publish timing, backfill only on `since: Some`, and a pump that runs until quiescent so the reciprocal-announcement cascade completes. A simpler loopback harness without those behaviors once validated a design that then failed on the real relay. Keep the model faithful when the relay changes, and never test the client against a loopback that drops one of them.
