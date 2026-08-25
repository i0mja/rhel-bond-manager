#!/usr/bin/env bash
# Compile lib/*.sh into the single-file distribution artifact.
# The build is deterministic (no timestamps) so `make dist` output can be
# committed and CI can verify the committed artifact matches the sources.
#
# Gates (build fails on any):
#   - bash -n parse check of the generated file
#   - shellcheck of the generated file (when shellcheck is installed)
#   - duplicate function definitions
#   - bm::* functions that are called but never defined (the class of bug
#     that shipped in v2.1.0 as the undefined bond_context_text)
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
OUT="${1:-$ROOT/bond_manager.sh}"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

VERSION="$(sed -n 's/^BM_VERSION="\(.*\)"$/\1/p' "$ROOT/lib/00-core.sh")"

{
  printf '#!/usr/bin/env bash\n'
  printf '# bond-manager v%s — safe NetworkManager bond management for RHEL-like systems.\n' "$VERSION"
  printf '# SPDX-License-Identifier: MIT\n'
  printf '#\n'
  printf '# GENERATED FILE — built from lib/*.sh by build/build.sh (`make dist`).\n'
  printf '# Edit the modules in lib/, not this file. Section markers below map\n'
  printf '# stack traces on a production box back to the source module.\n'
  printf 'set -Eeuo pipefail\n'

  for mod in "$ROOT"/lib/*.sh; do
    printf '\n# ==== %s ====\n' "$(basename "$mod")"
    # strip: shebangs, shellcheck file directives, and source guards
    # (the concatenated file is a single compilation unit)
    grep -v -E '^#!/|^# shellcheck shell=|^\[\[ -n "\$\{BM_LIB_[A-Z]+:-\}" \]\] && return 0$|^BM_LIB_[A-Z]+=1$' "$mod"
  done

  printf '\n# ==== entrypoint ====\n'
  printf 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then\n'
  printf '  bm::main "$@"\n'
  printf 'fi\n'
} >"$TMP"

fail() {
  echo "build: $*" >&2
  exit 1
}

# Gate 1: parse
bash -n "$TMP" || fail "generated file does not parse"

# Gate 2: duplicate function definitions
dups="$(grep -oE '^[a-z_:0-9]+\(\)' "$TMP" | sort | uniq -d)"
[[ -z "$dups" ]] || fail "duplicate function definitions: $dups"

# Gate 3: called-but-undefined bm:: functions (comment lines excluded)
defined="$(grep -oE '^\s*bm::[a-z_:0-9]+\(\)' "$TMP" | sed 's/^\s*//; s/()$//' | sort -u)"
called="$(grep -vE '^\s*#' "$TMP" \
  | grep -oE '(^|[^a-zA-Z0-9_:."'"'"'])bm::[a-z_:0-9]+' \
  | grep -oE 'bm::[a-z_:0-9]+' | sort -u)"
missing="$(comm -13 <(printf '%s\n' "$defined") <(printf '%s\n' "$called"))"
[[ -z "$missing" ]] || fail "functions called but never defined: $missing"

# Gate 4: shellcheck (best effort locally, mandatory in CI where it exists)
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "$TMP" || fail "shellcheck failed on generated file"
fi

install -m 0755 "$TMP" "$OUT"
echo "built $OUT (v$VERSION, $(wc -l <"$OUT") lines)"
