# lib/00-core.sh — constants, exit codes, error handling, shared helpers.
# Modules define functions and defaults only; no I/O happens at source time.
# shellcheck shell=bash
[[ -n "${BM_LIB_CORE:-}" ]] && return 0
BM_LIB_CORE=1

BM_VERSION="3.1.0"
BM_PROG="bond-manager"

# Typed exit codes (stable contract, see docs/bond-manager.8).
BM_EX_OK=0
BM_EX_ERR=1
BM_EX_USAGE=2
BM_EX_PRECONDITION=3
BM_EX_LOCKED=4
BM_EX_VERIFY=5
BM_EX_PARTIAL=6
BM_EX_DEGRADED=10
BM_EX_DOWN=11

# Every filesystem root the tool reads or writes is overridable so the test
# suite (and doctor --root inspection) can point it at a fixture tree.
: "${BM_PROC_ROOT:=/proc}"
: "${BM_SYS_ROOT:=/sys}"
: "${BM_CONN_DIR:=/etc/NetworkManager/system-connections}"
# RHEL 8's NetworkManager defaults to the ifcfg-rh plugin, which stores
# profiles here instead; snapshots must cover both stores.
: "${BM_IFCFG_DIR:=/etc/sysconfig/network-scripts}"
: "${BM_CONF:=/etc/bond_manager.conf}"
: "${BM_LOG_FILE:=/var/log/bond_manager.log}"
: "${BM_BACKUP_DIR:=/var/backups/bond_manager}"
: "${BM_SUPPORT_DIR:=/var/log/bond_manager/support}"
: "${BM_RUN_DIR:=/run/bond-manager}"
: "${BM_LOGROTATE_CONF:=/etc/logrotate.d/bond_manager}"

# Runtime flags, set by the CLI layer.
BM_DRY_RUN=0
BM_ASSUME_YES=0
BM_JSON=0
BM_DEBUG=0
BM_QUIET=0
BM_NO_CHECKPOINT=0
BM_FORCE_UNSAFE=0
BM_ROLLBACK_WINDOW=""   # empty = use config default
BM_SELF=""              # absolute path of the running script, set in main
BM_CMDLINE=""           # shell-quoted argv of this invocation (for hints)
BM_CUR_CMD=""           # subcommand being run (for "see: help CMD" hints)

# Terminal state saved by the interactive widgets; restored on exit so a
# crash or Ctrl-C never leaves the operator's terminal without echo.
BM_TTY_SAVED=""
BM_TTY_CURSOR_HIDDEN=0

bm::core::timestamp() { date +'%Y-%m-%dT%H:%M:%S%z'; }
bm::core::epoch() { date +%s; }

bm::core::have_cmd() { command -v "$1" >/dev/null 2>&1; }
bm::core::is_root() { [[ ${EUID} -eq 0 ]]; }
bm::core::is_tty() { [[ -t 0 && -t 1 ]]; }

# ---- color ----------------------------------------------------------------
BM_COLOR=0
bm::core::init_color() {
  if [[ -n "${NO_COLOR:-}" || "${BM_NO_COLOR:-0}" == 1 || ! -t 1 || "${TERM:-}" == dumb ]]; then
    BM_COLOR=0
  else
    BM_COLOR=1
  fi
}
bm::core::c() { # c <sgr> <text>  -> colored text when enabled
  if (( BM_COLOR )); then printf '\033[%sm%s\033[0m' "$1" "$2"; else printf '%s' "$2"; fi
}
bm::core::c_ok()   { bm::core::c '32' "$1"; }
bm::core::c_warn() { bm::core::c '33' "$1"; }
bm::core::c_err()  { bm::core::c '31' "$1"; }
bm::core::c_bold() { bm::core::c '1'  "$1"; }
bm::core::c_dim()  { bm::core::c '2'  "$1"; }

# ---- error handling -------------------------------------------------------
# The ERROR line is a stable, test-asserted contract. A hint — what to do
# next, in plain words — goes on its own line underneath so it never changes
# the message scripts may match on.
bm::core::die() { # die <message> [exit-code] [next-step hint]
  local msg="$1" code="${2:-$BM_EX_ERR}" hint="${3:-}"
  bm::log::error "$msg"
  printf '%s: %s %s\n' "$BM_PROG" "$(bm::core::c_err ERROR:)" "$msg" >&2
  if [[ -z "$hint" && "$code" == "$BM_EX_USAGE" && -n "$BM_CUR_CMD" ]]; then
    hint="see examples: $BM_PROG help $BM_CUR_CMD"
  fi
  if [[ -n "$hint" ]]; then
    printf '  %s %s\n' "$(bm::core::c_bold 'Next step:')" "$hint" >&2
  fi
  exit "$code"
}

bm::core::require_root() {
  bm::core::is_root && return 0
  local hint="start it with sudo: sudo $BM_PROG"
  if [[ -n "$BM_CMDLINE" ]]; then
    hint="run it again with sudo: sudo $BM_PROG ${BM_CMDLINE% }"
  fi
  bm::core::die "this operation must be run as root" "$BM_EX_PRECONDITION" "$hint"
}

bm::core::on_error() { # ERR trap: log a compact function-stack trace
  local rc=$1 line=$2 cmd=$3
  local stack="" i
  for ((i = 1; i < ${#FUNCNAME[@]}; i++)); do
    stack+="${FUNCNAME[$i]}:${BASH_LINENO[$((i - 1))]} "
  done
  bm::log::error "rc=$rc line=$line cmd='$cmd' stack=[${stack% }]"
}

bm::core::init_traps() {
  # shellcheck disable=SC2154
  trap 'bm::core::on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
  trap 'bm::core::cleanup' EXIT
}

# Private scratch directory, created on first use and removed by the EXIT
# trap (bm::core::cleanup). It sets BM_TMPDIR in the CALLING shell and prints
# nothing — never call it inside $(...): the directory would then be made in
# a subshell whose BM_TMPDIR the cleanup never sees, which is how every
# `init` and `bundle` used to leak a /tmp/bond-manager.XXXXXX directory.
# Callers use "${BM_TMPDIR:?}/name" so a misuse can never write to "/name".
BM_TMPDIR=""
bm::core::ensure_tmpdir() {
  if [[ -n "$BM_TMPDIR" && -d "$BM_TMPDIR" ]]; then
    return 0
  fi
  BM_TMPDIR=""
  local d
  d="$(mktemp -d "${TMPDIR:-/tmp}/bond-manager.XXXXXX")" || return 1
  BM_TMPDIR="$d"
  return 0
}

bm::core::cleanup() {
  bm::core::term_restore
  # only ever delete a directory ensure_tmpdir made
  if [[ -n "$BM_TMPDIR" && "${BM_TMPDIR##*/}" == bond-manager.* && -d "$BM_TMPDIR" ]]; then
    rm -rf "$BM_TMPDIR"
  fi
  BM_TMPDIR=""
  return 0
}

# Undo whatever the interactive widgets did to the terminal: line mode and
# echo back on, cursor visible, colors reset. Safe to call at any time.
bm::core::term_restore() {
  if [[ -n "$BM_TTY_SAVED" && -t 0 ]]; then
    stty "$BM_TTY_SAVED" 2>/dev/null || true
  fi
  BM_TTY_SAVED=""
  if (( BM_TTY_CURSOR_HIDDEN )); then
    printf '\033[?25h\033[0m' >&2 2>/dev/null || true
    BM_TTY_CURSOR_HIDDEN=0
  fi
  return 0
}

# ---- misc helpers ---------------------------------------------------------
bm::core::join() { # join <sep> [items...]
  local sep="$1" out="" item
  shift || true
  for item in "$@"; do
    [[ -n "$out" ]] && out+="$sep"
    out+="$item"
  done
  printf '%s' "$out"
}

bm::core::in_list() { # in_list <needle> [haystack...]
  local needle="$1" x
  shift || true
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

# Split a comma- and/or space-separated list into the global BM_LIST array.
bm::core::split_list() {
  local raw="${1//,/ }"
  read -r -a BM_LIST <<<"$raw"
}

# ---- "did you mean" -------------------------------------------------------

# Levenshtein distance between two short words; result in BM_EDIT_DIST.
BM_EDIT_DIST=0
bm::core::edit_distance() { # edit_distance <a> <b>
  local a="$1" b="$2"
  local la=${#a} lb=${#b} i j cost del ins sub best
  local -a prev=() cur=()
  for ((j = 0; j <= lb; j++)); do prev[j]=$j; done
  for ((i = 1; i <= la; i++)); do
    cur=()
    cur[0]=$i
    for ((j = 1; j <= lb; j++)); do
      cost=1
      if [[ "${a:i-1:1}" == "${b:j-1:1}" ]]; then cost=0; fi
      del=$(( prev[j] + 1 ))
      ins=$(( cur[j - 1] + 1 ))
      sub=$(( prev[j - 1] + cost ))
      best=$del
      if (( ins < best )); then best=$ins; fi
      if (( sub < best )); then best=$sub; fi
      cur[j]=$best
    done
    prev=("${cur[@]}")
  done
  BM_EDIT_DIST=${prev[lb]}
}

# Print the candidate closest to <word> (typo or unambiguous-ish prefix), or
# nothing when no candidate is plausibly what the operator meant.
bm::core::closest() { # closest <word> <candidate>...
  local word="${1,,}" c lc best="" bestd=999 max
  shift || true
  [[ -n "$word" ]] || return 0
  max=$(( ${#word} / 3 ))
  if (( max < 1 )); then max=1; fi
  for c in "$@"; do
    [[ -n "$c" ]] || continue
    lc="${c,,}"
    bm::core::edit_distance "$word" "$lc"
    if (( ${#word} >= 3 )) && [[ "$lc" == "$word"* ]] && (( BM_EDIT_DIST > 1 )); then
      BM_EDIT_DIST=1
    fi
    if (( BM_EDIT_DIST < bestd )); then
      bestd=$BM_EDIT_DIST
      best="$c"
    fi
  done
  if [[ -n "$best" ]] && (( bestd <= max )); then
    printf '%s\n' "$best"
  fi
  return 0
}
