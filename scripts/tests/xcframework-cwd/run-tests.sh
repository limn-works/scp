#!/usr/bin/env bash
# Cases for the working directory of every cargo command in bindings/swift/build-xcframework.sh.
#
# THE CRITERION: every cargo command the script runs has the repository root as its working
# directory, whatever directory the script was started from. Cargo reads `.cargo/config.toml`
# by searching upward from its working directory, and that file's `[env]` table supplies
# `LIBSQLITE3_FLAGS=-DSQLITE_ENABLE_MEMORY_MANAGEMENT` (spec 17 §17.6), so a cargo command
# run from outside the checkout builds the bundled SQLCipher without the option.
#
# Each case copies the real script into `<tmp>/repo/bindings/swift/` and runs it from
# `<tmp>/elsewhere`, a directory outside that tree. `cargo`, `rustup`, `xcodebuild`, `lipo`
# and `uname` are stubs on PATH. The cargo stub records its subcommand and `pwd -P`, and
# writes the files the script expects each subcommand to produce. Each case then compares
# every recorded working directory with `<tmp>/repo`.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
SCRIPT="$REPO_ROOT/bindings/swift/build-xcframework.sh"
PASSED=0
FAILED=0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
WORK="$(cd "$WORK" && pwd -P)"

STUBS="$WORK/bin"
LOG="$WORK/cargo.log"
TARGET="$WORK/target"
mkdir -p "$STUBS"

cat > "$STUBS/cargo" <<STUB
#!/usr/bin/env bash
echo "\$1 \$(pwd -P)" >> "$LOG"
case "\$1" in
  metadata)
    printf '{"packages":[],"target_directory":"%s","version":1}\n' "$TARGET"
    ;;
  build)
    target=""; profile=release
    while [ "\$#" -gt 0 ]; do
      case "\$1" in
        --target) target="\$2"; shift ;;
        --profile) profile="\$2"; shift ;;
      esac
      shift
    done
    mkdir -p "$TARGET/\$target/\$profile"
    touch "$TARGET/\$target/\$profile/libscp_ffi_uniffi.a" "$TARGET/\$target/\$profile/libscp_ffi_uniffi.dylib"
    ;;
  run)
    out=""
    while [ "\$#" -gt 0 ]; do
      if [ "\$1" = --out-dir ]; then out="\$2"; fi
      shift
    done
    mkdir -p "\$out"
    touch "\$out/scp_ffi_uniffi.swift" "\$out/scp_ffi_uniffiFFI.h" "\$out/scp_ffi_uniffiFFI.modulemap"
    ;;
esac
exit 0
STUB

cat > "$STUBS/rustup" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
STUB

cat > "$STUBS/xcodebuild" <<'STUB'
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = -output ]; then mkdir -p "$2"; fi
  shift
done
STUB

cat > "$STUBS/lipo" <<'STUB'
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = -output ]; then touch "$2"; fi
  shift
done
STUB

cat > "$STUBS/uname" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  -m) echo arm64 ;;
  *) echo Darwin ;;
esac
STUB

chmod +x "$STUBS"/*
export PATH="$STUBS:$PATH"

run_case() {
    local name="$1"
    shift
    local repo="$WORK/repo"
    rm -rf "$repo" "$WORK/elsewhere" "$TARGET"
    mkdir -p "$repo/bindings/swift" "$repo/crates/scp-ffi/uniffi" "$WORK/elsewhere"
    cp "$SCRIPT" "$repo/bindings/swift/build-xcframework.sh"
    : > "$LOG"

    local out
    if ! out="$(cd "$WORK/elsewhere" && bash "$repo/bindings/swift/build-xcframework.sh" "$@" 2>&1)"; then
        echo "FAIL $name: the script exited non-zero"
        awk '{ print "    " $0 }' <<< "$out"
        FAILED=$((FAILED + 1))
        return
    fi

    local calls wrong
    calls="$(wc -l < "$LOG" | tr -d ' ')"
    wrong="$(awk -v root="$repo" '$2 != root' "$LOG")"
    if [ "$calls" -eq 0 ]; then
        echo "FAIL $name: the script ran no cargo command"
        FAILED=$((FAILED + 1))
    elif [ -n "$wrong" ]; then
        echo "FAIL $name: cargo ran outside the repository root $repo:"
        awk '{ print "    " $0 }' <<< "$wrong"
        FAILED=$((FAILED + 1))
    else
        echo "ok   $name ($calls cargo commands, all from the repository root)"
        PASSED=$((PASSED + 1))
    fi
}

run_case "dev build started outside the checkout" --dev
run_case "full build started outside the checkout"

echo "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
