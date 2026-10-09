# Archived features

Nothing under this folder is current protocol, policy or a story. Each subfolder holds the specs, ADRs, PRD stories and planning text of one feature that Alec cut, kept so that a later decision can revive the feature without rediscovering its design.

The archive follows five rules:

1. A cut feature gets one folder, named after the feature, holding a `README.md` and a `HISTORY.md`. The README states what the feature was, what stayed live, which questions were open, and how to restore it. HISTORY.md records each archived artifact's origin, its state when archived with code evidence, the ruling that cut it, and where the deleted code lives.
2. Moved text stays verbatim. A moved file carries a banner above a rule line and the original bytes below it. A JSON file cannot carry a banner, so it moves byte-identical and the folder README marks it. A passage cut out of a live file sits in a `passages/` file inside a four-backtick `text` fence under a heading that names its source file, its enclosing heading and its line range on main.
3. Archived files carry no commit hashes, because the repository squash-merges and branch hashes stop resolving. A file names a git tag or a pull-request number instead.
4. Live documents do not cite into the archive, except where deleting a passage would make live text false.
5. Revival starts from the feature's HISTORY.md. An archived spec re-enters `.docs/specs/` only by a new decision, recorded in the plan of record and then in a spec, ADR and story in that order.

`scripts/check-doc-citations.py` does not scan this folder, and `scripts/validate-prd.py` reads only `.docs/prds/*.json`, so archived text cannot fail either gate. `scripts/check-doc-includes.py` reads every `.md` and `.json` file under `.docs/`, so archived text must not contain `scp:include`, `scp:fragment` or `scp:end` markers.

| Folder | Feature | Cut |
|---|---|---|
| `bridge-connectors/` | Platform bridge connectors: spec 12, ADR-023 and their PRD stories | 2026-09-26 |
