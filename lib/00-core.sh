# lib/00-core.sh — constants, exit codes, error handling, shared helpers.
# Modules define functions and defaults only; no I/O happens at source time.
# shellcheck shell=bash
[[ -n "${BM_LIB_CORE:-}" ]] && return 0
BM_LIB_CORE=1

BM_VERSION="3.0.0"
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

bm::core::timestamp() { date +'%Y-%m-%dT%H:%M:%S%z'; }
bm::core::epoch() { date +%s; }

bm::core::have_cmd() { command -v "$1" >/dev/null 2>&1; }
bm::core::is_root() { [[ ${EUID} -eq 0 ]]; }
bm::core::is_tty() { [[ -t 0 && -t 1 ]]; }

# ---- color ----------------------------------------------------------------
BM_COLOR=0
bm::core::init_color() {
  if [[ -n "${NO_COLOR:-}" || "${BM_NO_COLOR:-0}" == 1 || ! -t 1 ]]; then
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

# ---- error handling -------------------------------------------------------
bm::core::die() { # die <message> [exit-code]
  local msg="$1" code="${2:-$BM_EX_ERR}"
  bm::log::error "$msg"
  printf '%s: %s %s\n' "$BM_PROG" "$(bm::core::c_err ERROR:)" "$msg" >&2
  exit "$code"
}

bm::core::require_root() {
  bm::core::is_root || bm::core::die "this operation must be run as root" "$BM_EX_PRECONDITION"
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

BM_TMPDIR=""
bm::core::tmpdir() { # lazily create a private temp dir, echo its path
  if [[ -z "$BM_TMPDIR" ]]; then
    BM_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/bond-manager.XXXXXX")"
  fi
  printf '%s' "$BM_TMPDIR"
}
bm::core::cleanup() {
  [[ -n "$BM_TMPDIR" && -d "$BM_TMPDIR" ]] && rm -rf "$BM_TMPDIR"
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
