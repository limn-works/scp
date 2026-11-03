#!/usr/bin/env bash
#
# Fail unless no named library takes OpenSSL from the machine that loads it.
#
# CRITERION: a library passes when the loader resolves none of its OpenSSL symbols
# outside the library itself. Concretely:
#   - an ELF shared object names no `libcrypto` or `libssl` in a DT_NEEDED entry and
#     leaves no OpenSSL symbol undefined in its dynamic symbol table;
#   - a Mach-O image names no `libcrypto` or `libssl` load command and leaves no
#     OpenSSL symbol undefined;
#   - a PE image imports from no DLL whose name starts with `libcrypto` or `libssl`;
#   - a static archive defines every OpenSSL symbol one of its members leaves
#     undefined, so the program linking it needs no OpenSSL of its own.
# An OpenSSL symbol is one whose name starts with `EVP_`, `OPENSSL_`, `CRYPTO_`,
# `ERR_`, `RAND_`, `HMAC_` or `PKCS5_`, after the leading underscore Mach-O adds;
# those prefixes are indicators of the OpenSSL API SQLCipher calls, not the whole of
# it, and the DT_NEEDED, load-command and import checks stand on their own.
#
# WHY THIS EXISTS. The npm addon, the Android AAR's `.so` files, the XCFramework and
# the C ABI library each compile SQLCipher, and each installs onto a machine whose
# OpenSSL the build never saw, so each must carry its own OpenSSL (built from source
# through the bridge crate's `vendored-openssl` feature) or, on an Apple target, use
# CommonCrypto. A build that drops the feature still links on a host that supplies a
# libcrypto, and nothing but the artifact's dependency list shows the difference.
# `.github/workflows/build-matrix.yml` runs this on every such artifact before it
# uploads it, and prints each artifact's dependency list.
#
# A file whose format this script cannot read, a listing tool that is missing or exits
# non-zero, and an empty argument list each fail the run.
#
# Tools, each replaceable through the variable named, which the self-test uses:
#   ELF      $READELF (readelf) -d, and $NM (nm) -D --undefined-only
#   Mach-O   $OTOOL (otool) -L, and $NM (nm) -u
#   PE       $READOBJ (llvm-readobj) --coff-imports, else $OBJDUMP (objdump) -p
#   archive  $NM (nm) -g -P
#
# Usage:
#   assert-no-dynamic-libcrypto.sh <library>...
#   assert-no-dynamic-libcrypto.sh --self-test
set -euo pipefail

SYMBOLS='^_?(EVP|OPENSSL|CRYPTO|ERR|RAND|HMAC|PKCS5)_'
LIBRARIES='^(lib)?(crypto|ssl)([-.0-9_]|x64|$)'

# format_of <file>: elf, macho, pe, archive, or nothing.
format_of() {
  local magic
  magic="$(od -An -tx1 -N8 "$1" | tr -d ' \n')"
  case "$magic" in
    7f454c46*) echo elf ;;
    cffaedfe*|cefaedfe*|feedfacf*|feedface*|cafebabe*|bebafeca*) echo macho ;;
    4d5a*) echo pe ;;
    213c617263683e0a) echo archive ;;
  esac
}

# Each lister prints one dependency name per line, and fails when its tool fails.
elf_needed() {
  local out
  out="$("${READELF:-readelf}" -d "$1")" || return 1
  printf '%s\n' "$out" | sed -nE 's/.*\(NEEDED\).*\[([^]]+)\].*/\1/p'
}
macho_needed() {
  local out
  out="$("${OTOOL:-otool}" -L "$1")" || return 1
  printf '%s\n' "$out" | tail -n +2 | sed -E 's/^[[:space:]]+//; s/ \(compatibility.*$//' | sed -E 's#.*/##'
}
pe_needed() {
  local out
  if command -v "${READOBJ:-llvm-readobj}" >/dev/null 2>&1; then
    out="$("${READOBJ:-llvm-readobj}" --coff-imports "$1")" || return 1
    printf '%s\n' "$out" | sed -nE 's/^[[:space:]]*Name: (.*\.[dD][lL][lL])[[:space:]]*$/\1/p'
  elif command -v "${OBJDUMP:-objdump}" >/dev/null 2>&1; then
    out="$("${OBJDUMP:-objdump}" -p "$1")" || return 1
    printf '%s\n' "$out" | sed -nE 's/^[[:space:]]*DLL Name: (.*)$/\1/p'
  else
    echo "neither ${READOBJ:-llvm-readobj} nor ${OBJDUMP:-objdump} is on PATH to list $1's imports" >&2
    return 1
  fi
}

# Undefined OpenSSL symbols the loader would resolve elsewhere.
elf_undefined() {
  local out
  out="$("${NM:-nm}" -D --undefined-only "$1")" || return 1
  printf '%s\n' "$out" | awk '{print $NF}' | grep -E "$SYMBOLS" || true
}
macho_undefined() {
  local out
  out="$("${NM:-nm}" -u "$1")" || return 1
  printf '%s\n' "$out" | awk '{print $NF}' | grep -E "$SYMBOLS" || true
}
# An archive's members reference each other, so only an OpenSSL symbol some member
# leaves undefined and no member defines reaches the final link. Apple's nm exits 1 when
# any member has no symbols (a Rust staticlib holds several), so a non-zero exit fails
# only when nm wrote some other diagnostic. Rust also embeds LLVM bitcode in each member,
# which an nm built on an older LLVM (Xcode's) rejects; --no-llvm-bc, where nm offers it,
# reads the object's own symbol table instead.
archive_unresolved() {
  local out errors rc=0 flags=(-g -P)
  "${NM:-nm}" --help 2>&1 | grep -q -- '--no-llvm-bc' && flags+=(--no-llvm-bc)
  errors="$(mktemp)" || return 1
  out="$("${NM:-nm}" "${flags[@]}" "$1" 2>"$errors")" || rc=$?
  if [[ "$rc" -ne 0 ]] && grep -vE '(^[[:space:]]*$|: no symbols$)' "$errors" >&2; then
    rm -f "$errors"; return 1
  fi
  if [[ "$rc" -ne 0 && ! -s "$errors" ]]; then rm -f "$errors"; return 1; fi
  rm -f "$errors"
  printf '%s\n' "$out" | awk -v re="$SYMBOLS" '
    NF >= 2 && $1 ~ re { if ($2 == "U") u[$1] = 1; else d[$1] = 1 }
    END { for (s in u) if (!(s in d)) print s }' | sort
}

# check_one <file>: print the file's dependency list, then return 1 on a violation.
check_one() {
  local file="$1" format needed bad="" undefined=""
  [[ -f "$file" ]] || { echo "FAIL — $file does not exist"; return 1; }
  format="$(format_of "$file")"
  case "$format" in
    elf)     needed="$(elf_needed "$file")" || { echo "FAIL — could not list $file's DT_NEEDED entries"; return 1; }
             undefined="$(elf_undefined "$file")" || { echo "FAIL — could not list $file's undefined symbols"; return 1; } ;;
    macho)   needed="$(macho_needed "$file")" || { echo "FAIL — could not list $file's load commands"; return 1; }
             undefined="$(macho_undefined "$file")" || { echo "FAIL — could not list $file's undefined symbols"; return 1; } ;;
    pe)      needed="$(pe_needed "$file")" || { echo "FAIL — could not list $file's imports"; return 1; } ;;
    archive) needed=""
             undefined="$(archive_unresolved "$file")" || { echo "FAIL — could not list $file's symbols"; return 1; } ;;
    *)       echo "FAIL — $file is not an ELF, Mach-O, PE or ar file"; return 1 ;;
  esac
  echo "--- $file ($format)"
  if [[ "$format" == archive ]]; then
    echo "    a static archive; the program that links it resolves its undefined symbols"
  else
    printf '%s\n' "$needed" | sed -E '/^$/d; s/^/    needs /'
  fi
  bad="$(printf '%s\n' "$needed" | grep -iE "$LIBRARIES" || true)"
  if [[ -n "$bad" || -n "$undefined" ]]; then
    [[ -z "$bad" ]] || printf '%s\n' "$bad" | sed 's/^/    FAIL — loads OpenSSL library /'
    [[ -z "$undefined" ]] || printf '%s\n' "$undefined" | head -5 | sed 's/^/    FAIL — leaves OpenSSL symbol undefined: /'
    return 1
  fi
  echo "    ok   — takes no OpenSSL from the loading machine"
}

run() {
  [[ $# -gt 0 ]] || { echo "assert-no-dynamic-libcrypto.sh: name at least one library" >&2; return 2; }
  local file failures=0
  for file in "$@"; do check_one "$file" || failures=$((failures + 1)); done
  [[ "$failures" -eq 0 ]] || { echo "FAIL — $failures of $# libraries take OpenSSL from the loading machine or could not be read"; return 1; }
  echo "PASS — none of $# libraries takes OpenSSL from the loading machine"
}

# The self-test plants files with each format's magic bytes and stub listing tools that
# print canned output, so it runs on any host and proves each rejection fires.
self_test() {
  local dir failures=0
  dir="$(mktemp -d)"
  # shellcheck disable=SC2064 # $dir is fixed now, and this trap must remove this one.
  trap "rm -rf '$dir'" RETURN
  printf '\x7fELF\x02\x01\x01\x00' > "$dir/a.so"
  printf '\xcf\xfa\xed\xfe\x07\x00\x00\x01' > "$dir/a.dylib"
  printf 'MZ\x90\x00\x03\x00\x00\x00' > "$dir/a.dll"
  printf '!<arch>\n' > "$dir/a.a"
  printf 'not a library' > "$dir/a.txt"
  # Each stub prints the variable it is named after, so a case sets the output it needs.
  local tool
  for tool in readelf nm otool readobj; do
    printf '#!/bin/sh\n[ -n "$STUB_FAIL" ] && exit 1\nprintf "%%s\\n" "$STUB_%s"\n[ -z "$STUB_STDERR" ] || { printf "%%s\\n" "$STUB_STDERR" >&2; exit 1; }\n' "$(echo "$tool" | tr a-z A-Z)" > "$dir/$tool"
    chmod +x "$dir/$tool"
  done
  expect() { # <label> <PASS|FAIL> <command>...
    local label="$1" want="$2" got=PASS; shift 2
    "$@" >/dev/null 2>&1 || got=FAIL
    if [[ "$got" == "$want" ]]; then echo "   ok   — $label"; else echo "   FAIL — $label (wanted $want)"; failures=$((failures + 1)); fi
  }
  local clean_elf=' 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x0000000000000001 (NEEDED)             Shared library: [libdl.so]'
  local crypto_elf="$clean_elf"'
 0x0000000000000001 (NEEDED)             Shared library: [libcrypto.so.3]'
  local clean_macho="$dir/a.dylib:
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)
	/System/Library/Frameworks/Security.framework/Versions/A/Security (compatibility version 1.0.0, current version 61439.0.0)"
  local crypto_macho="$clean_macho
	/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib (compatibility version 3.0.0, current version 3.0.0)"
  local clean_pe='  Name: KERNEL32.dll
  Name: ntdll.dll'
  export READELF="$dir/readelf" NM="$dir/nm" OTOOL="$dir/otool" READOBJ="$dir/readobj" OBJDUMP="$dir/absent-objdump"
  export STUB_FAIL="" STUB_STDERR="" STUB_READELF="" STUB_NM="" STUB_OTOOL="" STUB_READOBJ=""

  STUB_READELF="$clean_elf" STUB_NM='                 U memcpy' expect "an ELF object needing only libc PASSES" PASS run "$dir/a.so"
  STUB_READELF="$crypto_elf" STUB_NM='' expect "an ELF object needing libcrypto.so.3 FAILS" FAIL run "$dir/a.so"
  STUB_READELF="${clean_elf/libdl.so/libssl.so.3}" STUB_NM='' expect "an ELF object needing libssl.so.3 FAILS" FAIL run "$dir/a.so"
  STUB_READELF="$clean_elf" STUB_NM='                 U EVP_EncryptInit_ex' expect "an ELF object leaving EVP_EncryptInit_ex undefined FAILS" FAIL run "$dir/a.so"
  STUB_READELF="$clean_macho" STUB_NM='_CCCrypt' expect "a Mach-O image on CommonCrypto PASSES" PASS run "$dir/a.dylib"
  STUB_READELF="" STUB_OTOOL="$crypto_macho" STUB_NM='' expect "a Mach-O image loading libcrypto.3.dylib FAILS" FAIL run "$dir/a.dylib"
  STUB_OTOOL="$clean_macho" STUB_NM='_OPENSSL_init_crypto' expect "a Mach-O image leaving _OPENSSL_init_crypto undefined FAILS" FAIL run "$dir/a.dylib"
  STUB_READOBJ="$clean_pe" expect "a PE image importing only system DLLs PASSES" PASS run "$dir/a.dll"
  STUB_READOBJ="$clean_pe"$'\n  Name: libcrypto-3-x64.dll' expect "a PE image importing libcrypto-3-x64.dll FAILS" FAIL run "$dir/a.dll"
  STUB_READOBJ="$clean_pe" READOBJ="$dir/absent-readobj" expect "a PE image with no import lister on PATH FAILS" FAIL run "$dir/a.dll"
  STUB_NM=$'EVP_EncryptInit_ex U\nEVP_EncryptInit_ex T 0 0' expect "an archive defining the OpenSSL symbol a member needs PASSES" PASS run "$dir/a.a"
  STUB_NM=$'_EVP_EncryptInit_ex U\n_CCCrypt U' expect "an archive leaving _EVP_EncryptInit_ex unresolved FAILS" FAIL run "$dir/a.a"
  STUB_NM='_ring_core_0_17_14__CRYPTO_memcmp U' expect "an archive leaving only a prefixed ring symbol undefined PASSES" PASS run "$dir/a.a"
  STUB_NM='_CCCrypt U' STUB_STDERR="$dir/a.a[empty.o]: no symbols" expect "an archive whose nm exits 1 over a member with no symbols PASSES" PASS run "$dir/a.a"
  STUB_NM='_CCCrypt U' STUB_STDERR="$dir/a.a: truncated or malformed archive" expect "an archive whose nm exits 1 with another diagnostic FAILS" FAIL run "$dir/a.a"
  STUB_READELF="$clean_elf" STUB_NM='' STUB_FAIL=1 expect "a listing tool that exits non-zero FAILS" FAIL run "$dir/a.so"
  expect "a file of no known format FAILS" FAIL run "$dir/a.txt"
  expect "a missing file FAILS" FAIL run "$dir/absent.so"
  expect "an empty argument list FAILS" FAIL run
  STUB_READELF="$clean_elf" STUB_NM='' expect "one bad library among good ones FAILS" FAIL run "$dir/a.so" "$dir/a.txt"

  [[ "$failures" -eq 0 ]] && echo "   SELF-TEST: all passed." && return 0
  echo "   SELF-TEST: $failures failed."; return 1
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  run "$@"
fi
