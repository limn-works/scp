# A local `cargo deny` run sees fewer advisories than CI does

**The rule:** a local `cargo deny check advisories` that reports an ignore entry as
`advisory-not-detected` is no evidence that the entry is unused. Before you delete an entry
from `deny.toml`'s `[advisories] ignore` list, open the advisory record under
`~/.cargo/advisory-db/` and read its `patched` range, then decide by one of two tests:

1. `cargo update --dry-run -p <crate>@<locked version>` moves the crate into the `patched`
   range. Run the update, delete the entry, and repeat for every lockfile in the repository
   (`Cargo.lock` and `fuzz/Cargo.lock`). The entry was masking an advisory a lock-only
   update fixes, and `.docs/lessons/an-advisory-ignore-is-a-claim-to-recheck.md` states
   the rule that applies.
2. `cargo tree -i <crate>` prints nothing, so no crate reaches the advisory any more.
   Delete the entry.

When neither test passes, the entry stays, and its comment names the release that will
clear it.

## What happened

Pull request #2460, the cold-compile dependency cut, removed three dependency edges and
with them 46 crates, including every crate under `openmls_libcrux_crypto`. Six advisory
ignores in `deny.toml` named those crates. A local `cargo deny check advisories` under
cargo-deny 0.19.0 reported those six as `advisory-not-detected`, and reported a seventh
entry the same way:

```
warning[advisory-not-detected]: advisory was not encountered
   ┌─ deny.toml:66:6
   │
66 │     "RUSTSEC-2026-0097",
   │      ━━━━━━━━━━━━━━━━━ no crate matched advisory criteria
```

That seventh entry covers RUSTSEC-2026-0097, the rand advisory for an aliased mutable
reference when a custom `log` logger calls `rand::rng()` during a `ThreadRng` reseed. The
same local run against the unmodified tree reported the same warning. All seven entries
came out.

`Rust / deny`, which runs `EmbarkStudios/cargo-deny-action@v2`, then failed on the pull
request:

```
error[unsound]: Rand is unsound with a custom logger using `rand::rng()`
    ├ Advisory: https://rustsec.org/advisories/RUSTSEC-2026-0097
advisories FAILED, bans ok, licenses ok, sources ok
```

The first fix reinstated the ignore entry with a comment that told the next reader not to
delete it. Review of that fix read the advisory record, which names three patched lines —
`>= 0.8.6` below 0.9, `>= 0.9.3` below 0.10, and `>= 0.10.1` — and read `Cargo.lock`,
which resolved rand 0.8.5, rand 0.9.2 and rand 0.10.0. An ignore is keyed by advisory ID,
so the reinstated entry masked all three lines, and its comment named only the first.
Every requirement on rand in the lock is a caret range that admits the patched release:
the workspace's own `rand = "0.8"`, `hpke-rs-rust-crypto` and `openmls_rust_crypto` on
0.8, `crc-fast`, `libcrux-traits`, `metrics-util`, `quinn-proto` and `tungstenite` on
0.9, and `hpke-rs-libcrux` on 0.10. So
`cargo update -p rand@0.8.5 -p rand@0.9.2 -p rand@0.10.0` moved three lock entries to
rand 0.8.8, 0.9.5 and 0.10.2 and changed nothing else, the same command inside `fuzz/`
moved the three entries `fuzz/Cargo.lock` carried, and the entry came out of `deny.toml`
for the reason the rule above names: a lock-only update fixed the advisory.

The same review then applied test 1 to every other entry in the list. RUSTSEC-2026-0074,
the libcrux-sha3 advisory for incorrect incremental SHAKE XOF output, names
libcrux-sha3 >= 0.0.8 as patched, and its comment read "Awaiting an hpke-rs release that
raises its libcrux-sha3 floor". `Cargo.lock` resolved hpke-rs 0.6.0 with libcrux-sha3
0.0.6 and 0.0.7, and `cargo update --dry-run -p hpke-rs@0.6.0` moved hpke-rs to 0.6.1,
which requires libcrux-sha3 `^0.0.8`, so that release had shipped and nobody had
re-checked the comment against it. The update moved ten lock entries to newer releases, removed the eleven
entries that only the older libcrux releases pulled in, and the entry came out. `fuzz/Cargo.lock`
already resolved hpke-rs 0.6.1 and libcrux-sha3 0.0.8, because the Fuzz CI jobs run
`cargo check` without `--locked` and had re-resolved it. The three libcrux entries that
stay — RUSTSEC-2026-0207 and RUSTSEC-2026-0208 on libcrux-sha3, patched at >= 0.0.10, and
RUSTSEC-2026-0212 on libcrux-secrets, patched at >= 0.0.6 — fail both tests today:
hpke-rs 0.6.1 requires libcrux-sha3 `^0.0.8`, hpke-rs 0.7.0 requires libcrux-sha3
`=0.0.10` but openmls_rust_crypto 0.5.1 does not admit hpke-rs 0.7, and libcrux-traits
0.0.6 requires libcrux-secrets `=0.0.5`. Each of those three comments now names the
release that clears it.

## What the two runs showed

The local run used cargo-deny 0.19.0 from the mise shim, against an advisory database it
had fetched from `https://github.com/rustsec/advisory-db` that same day into
`~/.cargo/advisory-db/`. That database contained
`crates/rand/RUSTSEC-2026-0097.md` with the `patched` ranges quoted above, and the local
run still reported the advisory as not detected while `Cargo.lock` resolved rand 0.8.5.
The CI job reported the same advisory against the same lockfile as `error[unsound]`. I do
not know which difference between the two runs causes the local one to pass over the
advisory.

The failure mode is asymmetric. A local run that reports an advisory the CI run does not
costs a developer one unnecessary ignore. A local run that passes over an advisory the CI
run reports costs a red merge gate, and it reads as a clean local result right up to the
push.

## What to do instead

- Treat `cargo deny check advisories` on a developer machine as a lower bound on what CI
  reports, and apply the two tests at the top of this file to every entry you consider
  deleting.
- Never write "do not delete this entry" into `deny.toml`. That sentence instructs the
  next reader to keep a mask in place, and the reader who obeys it never runs the
  `cargo update --dry-run` that shows the mask is unnecessary. Write the release that
  clears the entry instead, so a reader can check whether it has shipped.
- `fuzz/Cargo.lock` is a second lockfile that resolves the workspace crates through path
  dependencies, and no CI job runs `cargo deny` against it. When a lock-only update fixes
  an advisory in `Cargo.lock`, run the same update inside `fuzz/`, where rustup applies
  `fuzz/rust-toolchain.toml`.
