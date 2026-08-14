# ADR-049 N1 PR-2: false regression test (final-drain masked by Shutdown ok_mutated)

Branch fix marks Class-C class_c_view mutations durable via Outcome.mutated in 3 handlers
(handle_seed_peer_pseudonym, handle_test_insert_member, commit_a replay). Handler fixes all correct.

BUG (confirmed empirically): the new test
`coalesced_seed_peer_pseudonym_is_durable_across_final_drain`
(crates/scp-runtime/src/context/actor/mod.rs) is a FALSE regression guard. It passes even with
the old buggy `Outcome::ok(())` seed handler.

Root cause: `send_shutdown()` -> `LifecycleControlCommand::Shutdown` handler
(handlers/lifecycle_control.rs:61-65) sets lifecycle_state=Closed and returns
`Outcome::ok_mutated(())`, unconditionally setting self.dirty=true. The post-loop final drain
(`if self.dirty { persist_snapshot() }`) then persists the whole live state, which already
contains the in-memory pseudonym (the class_c_view insert runs regardless of the returned
mutated flag — the flag only gates persistence). So the assertion passes either way.

VALID pattern already exists: `coalesced_class_c_mutation_is_durable_across_coalesce_tick` uses
tokio::time::pause() + advance past COALESCE_INTERVAL to fire the Arm-4 coalesce tick WHILE THE
ACTOR IS STILL RUNNING (pre-shutdown). Arm-4 only fires when self.dirty is true, which only the
mutation handler can set pre-shutdown → genuinely distinguishes the fix.

LESSON: Any actor-durability test that triggers persist via send_shutdown() cannot validate a
handler's mutated flag, because the Shutdown handler itself returns ok_mutated. Test the
mutated flag via the coalesce-tick (still-running) path, NOT the final-drain (shutdown) path.
