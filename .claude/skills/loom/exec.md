# /loom (exec)

Launch the Loom autonomous development loop. You must `unset CLAUDECODE` before running the script so nested `claude` invocations work.

Use this table to map skill `$ARGUMENTS` to script flags where applicable.

| Argument | Flag | Value | Default Value (flag passed, value omitted) |
| --- | --- | --- | --- |
| `<prompt>` | `--prompt` | `<prompt>` | None (required) |
| `dry-run` | `--dry-run` | `true` | None (required) |
| `github` | `--github` | `true` | None (required) |
| `linear` | `--linear` | `true` | None (required) |
| `slack` | `--slack` | `true` | None (required) |
| `notion` | `--notion` | `true` | None (required) |
| `sentry` | `--sentry` | `true` | None (required) |
| `resume <directory>` | `--resume` | `<directory>` | none (handled by the script) |
| `wt <bool>` | `--worktree` | `<bool>` | `true` |
| `worktree <bool>` | `--worktree <bool>` | `true` | `true` |
| `pr <bool>` | `--pr <bool>` | `true` | `true` |

## Routing

Look at `$ARGUMENTS` and determine which case applies:

### Case 1: No arguments (`$ARGUMENTS` is empty)

Check if you're in a loom worktree or branch already, or if there are logs from recent iterations that are still fresh (happened in last several hours and relate to the most recent commits or uncommitted working changes). If so, resume in the current branch:

```bash
unset CLAUDECODE && .loom/start.sh --resume
```

Otherwise start the loop:

```bash
unset CLAUDECODE && .loom/start.sh
```

### Case 2: `status`

Show run summary:

```bash
.loom/loom-status.sh
```

### Case 3: `stop`

Graceful stop (finishes current iteration, then halts):

```bash
.loom/stop.sh && echo "Loom will stop after the current iteration." || echo "Failed to signal stop."
```

### Case 4: `kill`

Immediate kill (terminates the tmux session without waiting):

```bash
tmux kill-session -t "loom-$(basename "$PWD")" 2>/dev/null && echo "Loom killed." || echo "Loom is not running."
```

### Case 5: `dry-run`

Dry run — analyze one iteration without executing changes:

```bash
unset CLAUDECODE && .loom/start.sh --dry-run
```

### Case 6: `linear <query_or_url>`

Linear mode — fetch from Linear, implement, update ticket:

```bash
unset CLAUDECODE && .loom/start.sh --linear "$REST"
```

Where `$REST` is everything after the word `linear`.

### Case 7: `github <query_or_url>`

GitHub mode — fetch from GitHub, implement, close issues:

```bash
unset CLAUDECODE && .loom/start.sh --github "$REST"
```

Where `$REST` is everything after the word `github`.

### Case 8: `issue <number>`

Shorthand for GitHub issue mode:

```bash
unset CLAUDECODE && .loom/start.sh --github "$NUMBER"
```

### Case 9: `slack <url>`

Slack mode — fetch Slack message, implement:

```bash
unset CLAUDECODE && .loom/start.sh --slack "$URL"
```

### Case 10: `notion <query_or_url>`

Notion mode — fetch Notion page, implement:

```bash
unset CLAUDECODE && .loom/start.sh --notion "$REST"
```

Where `$REST` is everything after the word `notion`.

### Case 11: `sentry <query_or_url>`

Sentry mode — fetch Sentry issue, fix the bug:

```bash
unset CLAUDECODE && .loom/start.sh --sentry "$REST"
```

Where `$REST` is everything after the word `sentry`.

### Case 12: Arguments start with `-` (raw flags passthrough)

Pass flags through directly to `start.sh`:

```bash
unset CLAUDECODE && .loom/start.sh $ARGUMENTS
```

This is a fallback for advanced usage. Most users should use the subcommand forms above.

### Case 13: Arguments are plain text (a prompt)

Write the text to a file and pass it via `--prompt`:

```bash
printf '%s' '$ARGUMENTS' > .loom/.directive && unset CLAUDECODE && .loom/start.sh --prompt .loom/.directive
```

Examples:
- `/loom Fix all lint errors` → writes "Fix all lint errors" to `.loom/.directive`, then runs with `--prompt .loom/.directive`
- `/loom Refactor all callbacks to async/await` → same pattern

### How to tell the difference

1. If `$ARGUMENTS` is empty → Case 1
2. If `$ARGUMENTS` equals `status` → Case 2
3. If `$ARGUMENTS` equals `stop` → Case 3
4. If `$ARGUMENTS` equals `kill` → Case 4
5. If `$ARGUMENTS` equals `dry-run` → Case 5
6. If `$ARGUMENTS` starts with `linear ` → Case 6
7. If `$ARGUMENTS` starts with `github ` → Case 7
8. If `$ARGUMENTS` starts with `issue ` → Case 8
9. If `$ARGUMENTS` starts with `slack ` → Case 9
10. If `$ARGUMENTS` starts with `notion ` → Case 10
11. If `$ARGUMENTS` starts with `sentry ` → Case 11
12. If `$ARGUMENTS` starts with `--` or `-` → Case 12
13. Otherwise → Case 13

## After launching

Report back to the user (substitute the actual project directory name):
- Attach to monitor: `tmux attach -t loom-<project>`
- Kill the loop: `tmux kill-session -t loom-<project>`
