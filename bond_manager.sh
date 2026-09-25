#!/usr/bin/env bash
# bond-manager v3.1.0 — safe NetworkManager bond management for RHEL-like systems.
# SPDX-License-Identifier: MIT
#
# GENERATED FILE — built from lib/*.sh by build/build.sh (`make dist`).
# Edit the modules in lib/, not this file. Section markers below map
# stack traces on a production box back to the source module.
set -Eeuo pipefail

# ==== 00-core.sh ====
# lib/00-core.sh — constants, exit codes, error handling, shared helpers.
# Modules define functions and defaults only; no I/O happens at source time.

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

# ==== 10-log.sh ====
# lib/10-log.sh — structured logging to file, journal (via logger), and stderr.
# File logging is off by default so read-only commands never write anywhere;
# the plan engine and mutating commands call bm::log::enable_file first.

BM_LOG_TO_FILE=0
BM_LOG_OP=""   # operation tag included in every record, e.g. op=create

bm::log::enable_file() {
  BM_LOG_TO_FILE=1
  mkdir -p "$(dirname "$BM_LOG_FILE")" 2>/dev/null || true
}

bm::log::set_op() { BM_LOG_OP="$1"; }

bm::log::_emit() { # _emit <LEVEL> <message...>
  local level="$1"
  shift || true
  local tag=""
  [[ -n "$BM_LOG_OP" ]] && tag=" op=$BM_LOG_OP"
  local line
  line="[$(bm::core::timestamp)] [$level]$tag $*"
  if (( BM_LOG_TO_FILE )); then
    printf '%s\n' "$line" >>"$BM_LOG_FILE" 2>/dev/null || true
    if bm::core::have_cmd logger; then
      logger -t "$BM_PROG" -- "[$level]$tag $*" 2>/dev/null || true
    fi
  fi
  if (( BM_DEBUG )); then
    printf '%s\n' "$line" >&2
  fi
}

bm::log::info()  { bm::log::_emit INFO "$@"; }
bm::log::warn()  { bm::log::_emit WARN "$@"; }
bm::log::error() { bm::log::_emit ERROR "$@"; }
bm::log::debug() { (( BM_DEBUG )) && bm::log::_emit DEBUG "$@"; return 0; }

# User-facing progress line (suppressed by --quiet, never by --json parsing
# concerns: goes to stderr so stdout stays machine-readable).
bm::log::say() {
  (( BM_QUIET )) && return 0
  printf '%s\n' "$*" >&2
}

bm::log::render_logrotate() {
  cat <<EOF
# Managed by ${BM_PROG} v${BM_VERSION}
${BM_LOG_FILE} {
    $(bm::config::get LOGROTATE_FREQUENCY)
    rotate $(bm::config::get LOGROTATE_ROTATE)
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF
}

# ==== 15-config.sh ====
# lib/15-config.sh — /etc/bond_manager.conf handling.
# The file is parsed line-by-line against a key allowlist and NEVER sourced,
# so a writable config can no longer inject shell that runs as root.
# v2.x key names are kept verbatim for compatibility.

declare -A BM_CFG=(
  [DEFAULT_MIIMON]="100"
  [DEFAULT_8023AD_LACP_RATE]="fast"
  [DEFAULT_8023AD_XHP]="layer3+4"
  [MAX_BACKUPS]="10"
  [LOGROTATE_FREQUENCY]="weekly"
  [LOGROTATE_ROTATE]="12"
  [NIC_ALLOWLIST_PATTERNS]="^(ens|enp|eno|eth|em|p[0-9]+p)[0-9].*"
  [NIC_BLOCKLIST_PATTERNS]="^lo\$ ^veth.* ^docker.* ^br-.* ^virbr.* ^vnet.* ^tun.* ^tap.* ^nm-.* ^wl.* ^bond.* ^team.* ^ovs.* ^cali.* ^flannel.* ^cni.*"
  [ROLLBACK_WINDOW]="120"
  [ACTIVATE_TIMEOUT]="45"
  [LINK_SETTLE_TIMEOUT]="15"
  [MIN_SPEED_MBPS]="0"
)

bm::config::get() { printf '%s' "${BM_CFG[$1]:-}"; }
bm::config::set() { BM_CFG["$1"]="$2"; }

bm::config::_valid_value() { # _valid_value <key> <value>
  local key="$1" val="$2"
  case "$key" in
    DEFAULT_MIIMON | MAX_BACKUPS | LOGROTATE_ROTATE | ROLLBACK_WINDOW | \
      ACTIVATE_TIMEOUT | LINK_SETTLE_TIMEOUT | MIN_SPEED_MBPS)
      [[ "$val" =~ ^[0-9]+$ ]] ;;
    DEFAULT_8023AD_LACP_RATE) [[ "$val" == fast || "$val" == slow ]] ;;
    DEFAULT_8023AD_XHP)
      bm::core::in_list "$val" layer2 layer2+3 layer3+4 encap2+3 encap3+4 vlan+srcmac ;;
    LOGROTATE_FREQUENCY) bm::core::in_list "$val" daily weekly monthly ;;
    NIC_ALLOWLIST_PATTERNS | NIC_BLOCKLIST_PATTERNS)
      # Regex lists: reject anything that could smuggle shell metacharacters
      # into contexts beyond [[ =~ ]].
      [[ "$val" != *'`'* && "$val" != *'$('* ]] ;;
    *) return 1 ;;
  esac
}

# Parse the config file. Unknown keys and malformed lines are reported to
# stderr (once) and ignored; valid keys override the built-in defaults.
bm::config::load() {
  [[ -r "$BM_CONF" ]] || return 0
  local line key val n=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    # strip comments and surrounding whitespace
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    if [[ ! "$line" =~ ^([A-Z0-9_]+)=(.*)$ ]]; then
      bm::log::say "$(bm::core::c_warn "config: ignoring malformed line $n in $BM_CONF")"
      continue
    fi
    key="${BASH_REMATCH[1]}"
    val="${BASH_REMATCH[2]}"
    # strip one layer of matching quotes
    if [[ "$val" == \"*\" || "$val" == \'*\' ]]; then
      val="${val:1:${#val}-2}"
    fi
    if [[ -z "${BM_CFG[$key]+x}" ]]; then
      bm::log::say "$(bm::core::c_warn "config: ignoring unknown key '$key' (line $n)")"
      continue
    fi
    if ! bm::config::_valid_value "$key" "$val"; then
      bm::log::say "$(bm::core::c_warn "config: rejecting invalid value for '$key' (line $n)")"
      continue
    fi
    BM_CFG["$key"]="$val"
  done <"$BM_CONF"
}

bm::config::default_text() {
  cat <<'EOF'
# /etc/bond_manager.conf — bond-manager configuration.
#
# This file is parsed (KEY="value" per line), not executed. Unknown keys and
# invalid values are ignored with a warning.

# Bond tuning defaults
DEFAULT_MIIMON="100"
DEFAULT_8023AD_LACP_RATE="fast"       # fast|slow
DEFAULT_8023AD_XHP="layer3+4"         # layer2|layer2+3|layer3+4|encap2+3|encap3+4

# Snapshots / log rotation
MAX_BACKUPS="10"
LOGROTATE_FREQUENCY="weekly"          # daily|weekly|monthly
LOGROTATE_ROTATE="12"

# NIC selection policy (space-separated ERE patterns)
NIC_ALLOWLIST_PATTERNS="^(ens|enp|eno|eth|em|p[0-9]+p)[0-9].*"
NIC_BLOCKLIST_PATTERNS="^lo$ ^veth.* ^docker.* ^br-.* ^virbr.* ^vnet.* ^tun.* ^tap.* ^nm-.* ^wl.* ^bond.* ^team.* ^ovs.* ^cali.* ^flannel.* ^cni.*"

# Safety engine
ROLLBACK_WINDOW="120"                 # seconds before auto-rollback of an unconfirmed change
ACTIVATE_TIMEOUT="45"                 # seconds to wait for nmcli activation
LINK_SETTLE_TIMEOUT="15"              # seconds to wait for links to settle before verify

# Warn when a selected member NIC reports less than this speed in Mb/s (0 = off)
MIN_SPEED_MBPS="0"
EOF
}

# Install the default config and logrotate policy (only `init` calls this).
bm::config::install() {
  bm::core::require_root
  bm::core::ensure_tmpdir || bm::core::die "could not create a temporary directory in ${TMPDIR:-/tmp}" "$BM_EX_ERR"
  if [[ ! -f "$BM_CONF" ]]; then
    local tmp
    tmp="${BM_TMPDIR:?}/conf"
    bm::config::default_text >"$tmp"
    install -m 0640 -o root -g root "$tmp" "$BM_CONF"
    bm::log::say "installed default config at $BM_CONF"
  else
    bm::log::say "config already present at $BM_CONF (left unchanged)"
  fi
  local tmp2
  tmp2="${BM_TMPDIR:?}/logrotate"
  bm::log::render_logrotate >"$tmp2"
  if [[ ! -f "$BM_LOGROTATE_CONF" ]] || ! cmp -s "$tmp2" "$BM_LOGROTATE_CONF"; then
    install -m 0644 -o root -g root "$tmp2" "$BM_LOGROTATE_CONF"
    bm::log::say "installed logrotate policy at $BM_LOGROTATE_CONF"
  fi
  mkdir -p "$BM_BACKUP_DIR" "$BM_SUPPORT_DIR"
  chmod 0750 "$BM_BACKUP_DIR" "$BM_SUPPORT_DIR" 2>/dev/null || true
}

# ==== 18-val.sh ====
# lib/18-val.sh — input validators and the bond-mode option matrix.
# The matrix is the single source of truth for which bond.options are valid
# per mode; both the CLI and the TUI validate through it.

BM_MODES=(balance-rr active-backup balance-xor broadcast 802.3ad balance-tlb balance-alb)

# Options accepted for every mode.
BM_OPTS_COMMON="miimon updelay downdelay use_carrier num_grat_arp num_unsol_na resend_igmp all_slaves_active lp_interval"

# Mode-specific additions. arp monitoring is only valid for modes the kernel
# supports it on (not 802.3ad/tlb/alb).
declare -A BM_MODE_OPTS=(
  [balance-rr]="arp_interval arp_ip_target arp_validate packets_per_slave"
  [active-backup]="arp_interval arp_ip_target arp_validate arp_all_targets primary primary_reselect fail_over_mac"
  [balance-xor]="arp_interval arp_ip_target arp_validate xmit_hash_policy"
  [broadcast]="arp_interval arp_ip_target arp_validate"
  [802.3ad]="xmit_hash_policy lacp_rate ad_select ad_actor_sys_prio ad_actor_system ad_user_port_key min_links"
  [balance-tlb]="primary primary_reselect tlb_dynamic_lb xmit_hash_policy"
  [balance-alb]="primary primary_reselect"
)

# One plain sentence per mode, used by help and the TUI.
declare -A BM_MODE_HELP=(
  [balance-rr]="Sends packets in turn on each port. Switch needs a static port-channel."
  [active-backup]="Simple failover: one port works, the other waits. Works with any switch."
  [balance-xor]="Shares traffic by address. Switch needs a static port-channel."
  [broadcast]="Sends everything on every port. Special cases only."
  [802.3ad]="LACP: all ports carry traffic. The switch MUST be set up for LACP."
  [balance-tlb]="Shares outgoing traffic only. No switch setup needed."
  [balance-alb]="Shares traffic in both directions. No switch setup needed."
)

bm::val::mode() {
  bm::core::in_list "$1" "${BM_MODES[@]}"
}

bm::val::ifname() { # kernel IFNAMSIZ is 16 incl NUL; no '/', no spaces
  local n="$1"
  [[ -n "$n" && ${#n} -le 15 && "$n" =~ ^[A-Za-z0-9._-]+$ && "$n" != "." && "$n" != ".." ]]
}

bm::val::vlan_id() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 4094 ))
}

bm::val::uint() { # uint <value> [min] [max]
  local v="$1" min="${2:-0}" max="${3:-4294967295}"
  [[ "$v" =~ ^[0-9]+$ ]] && (( v >= min && v <= max ))
}

bm::val::mtu() { bm::val::uint "$1" 68 65535; }

bm::val::ipv4_addr() {
  local ip="$1" o
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1:4}"; do
    (( o <= 255 )) || return 1
  done
  return 0
}

bm::val::ipv4_cidr() {
  local a="${1%/*}" p="${1#*/}"
  [[ "$1" == */* ]] || return 1
  bm::val::ipv4_addr "$a" && bm::val::uint "$p" 0 32
}

bm::val::ipv6_addr() {
  local ip="$1"
  # Pragmatic check: hex groups and colons, at most one '::'. nmcli performs
  # the authoritative validation; this catches operator typos early.
  [[ "$ip" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
  [[ "$ip" == *:* ]] || return 1
  [[ "$ip" != *:::* ]] || return 1
  local no_dc="${ip//::/}"
  local colons="${ip//[^:]/}" dc=0
  [[ "$ip" == *"::"* ]] && dc=1
  if (( dc == 0 )); then
    [[ "${#colons}" -eq 7 ]] || return 1
  else
    # only one '::'
    [[ "${ip/::/}" != *"::"* ]] || return 1
    (( ${#no_dc} >= 0 )) || return 1
  fi
  return 0
}

bm::val::ipv6_cidr() {
  local a="${1%/*}" p="${1#*/}"
  [[ "$1" == */* ]] || return 1
  bm::val::ipv6_addr "$a" && bm::val::uint "$p" 0 128
}

bm::val::ip_list() { # ip_list <v4|v6> <comma-list>
  local fam="$1" list="$2" ip
  bm::core::split_list "$list"
  (( ${#BM_LIST[@]} > 0 )) || return 1
  for ip in "${BM_LIST[@]}"; do
    if [[ "$fam" == v4 ]]; then
      bm::val::ipv4_addr "$ip" || return 1
    else
      bm::val::ipv6_addr "$ip" || return 1
    fi
  done
  return 0
}

# ---- option matrix --------------------------------------------------------

bm::val::opts_for_mode() { # echo the full space-separated allowlist for a mode
  printf '%s %s' "$BM_OPTS_COMMON" "${BM_MODE_OPTS[$1]:-}"
}

bm::val::option_allowed() { # option_allowed <mode> <key>
  local mode="$1" key="$2"
  # shellcheck disable=SC2046
  bm::core::in_list "$key" $(bm::val::opts_for_mode "$mode") mode
}

bm::val::option_value() { # option_value <key> <value> — format check for known keys
  local key="$1" val="$2"
  case "$key" in
    mode) bm::val::mode "$val" ;;
    miimon | updelay | downdelay | arp_interval | resend_igmp | num_grat_arp | \
      num_unsol_na | lp_interval | packets_per_slave | min_links | ad_actor_sys_prio | \
      ad_user_port_key)
      bm::val::uint "$val" ;;
    use_carrier | all_slaves_active | tlb_dynamic_lb) bm::core::in_list "$val" 0 1 ;;
    lacp_rate) bm::core::in_list "$val" slow fast 0 1 ;;
    xmit_hash_policy)
      bm::core::in_list "$val" layer2 layer2+3 layer3+4 encap2+3 encap3+4 vlan+srcmac ;;
    ad_select) bm::core::in_list "$val" stable bandwidth count 0 1 2 ;;
    primary) bm::val::ifname "$val" ;;
    primary_reselect) bm::core::in_list "$val" always better failure 0 1 2 ;;
    fail_over_mac) bm::core::in_list "$val" none active follow 0 1 2 ;;
    arp_validate)
      bm::core::in_list "$val" none active backup all filter filter_active filter_backup 0 1 2 3 4 5 6 ;;
    arp_all_targets) bm::core::in_list "$val" any all 0 1 ;;
    arp_ip_target) bm::val::ip_list v4 "$val" ;;
    ad_actor_system) [[ "$val" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] ;;
    *) return 0 ;; # unknown keys pass through to nmcli's own validation
  esac
}

# Validate a full option set for a mode. Options arrive as an assoc array
# name passed by reference. Returns non-zero and prints reasons on failure.
bm::val::option_set() { # option_set <mode> <assoc-name>
  local mode="$1"
  local -n _opts="$2"
  local key ok=0
  bm::val::mode "$mode" || { echo "unknown bond mode '$mode'"; return 1; }
  for key in "${!_opts[@]}"; do
    if ! bm::val::option_allowed "$mode" "$key"; then
      echo "option '$key' is not valid for mode $mode"
      ok=1
      continue
    fi
    if ! bm::val::option_value "$key" "${_opts[$key]}"; then
      echo "invalid value '${_opts[$key]}' for option '$key'"
      ok=1
    fi
  done
  # cross-option constraints
  if [[ -n "${_opts[arp_interval]:-}" && "${_opts[arp_interval]}" != 0 ]]; then
    case "$mode" in
      802.3ad | balance-tlb | balance-alb)
        echo "arp monitoring is not supported in mode $mode"
        ok=1 ;;
    esac
    if [[ -z "${_opts[arp_ip_target]:-}" ]]; then
      echo "arp_interval requires arp_ip_target"
      ok=1
    fi
    if [[ -n "${_opts[miimon]:-}" && "${_opts[miimon]}" != 0 ]]; then
      echo "miimon and arp_interval are mutually exclusive; set one of them to 0"
      ok=1
    fi
  fi
  if [[ -n "${_opts[arp_ip_target]:-}" && -z "${_opts[arp_interval]:-}" ]]; then
    echo "arp_ip_target requires arp_interval"
    ok=1
  fi
  if [[ -n "${_opts[primary]:-}" ]]; then
    case "$mode" in
      active-backup | balance-tlb | balance-alb) : ;;
      *)
        echo "option 'primary' is only valid for active-backup/balance-tlb/balance-alb"
        ok=1 ;;
    esac
  fi
  return "$ok"
}

# ==== 20-facts.sh ====
# lib/20-facts.sh — read-only inventory of NICs and bonds from /proc, /sys
# and the routing table. All paths go through BM_PROC_ROOT/BM_SYS_ROOT so the
# test suite can point them at fixture trees.

bm::facts::nic_exists() { [[ -e "$BM_SYS_ROOT/class/net/$1" ]]; }

bm::facts::nic_state() {
  cat "$BM_SYS_ROOT/class/net/$1/operstate" 2>/dev/null || echo unknown
}

bm::facts::nic_speed() { # Mb/s, or "unknown" (link down reads fail with EINVAL)
  local spd
  spd="$(cat "$BM_SYS_ROOT/class/net/$1/speed" 2>/dev/null || true)"
  if [[ -z "$spd" || "$spd" == "-1" ]]; then
    echo unknown
  else
    echo "$spd"
  fi
}

bm::facts::nic_mac() {
  cat "$BM_SYS_ROOT/class/net/$1/address" 2>/dev/null || echo unknown
}

bm::facts::nic_mtu() {
  cat "$BM_SYS_ROOT/class/net/$1/mtu" 2>/dev/null || echo unknown
}

bm::facts::nic_driver() {
  local link
  link="$(readlink "$BM_SYS_ROOT/class/net/$1/device/driver" 2>/dev/null || true)"
  [[ -n "$link" ]] && basename "$link" || echo unknown
}

bm::facts::nic_is_physical() { # has a backing device (PCI/USB/...) in sysfs
  [[ -e "$BM_SYS_ROOT/class/net/$1/device" ]]
}

bm::facts::nic_bond_master() { # bond the NIC is currently enslaved to, if any
  local link
  link="$(readlink "$BM_SYS_ROOT/class/net/$1/master" 2>/dev/null || true)"
  [[ -n "$link" ]] && basename "$link" || true
}

# First line of a (sysfs) file into BM_READ1; rc 1 when unreadable/empty.
# Reading some attributes of a down link fails with EINVAL — that is "no
# value", never an error worth surfacing.
BM_READ1=""
bm::facts::_read1() {
  BM_READ1=""
  [[ -r "$1" ]] || return 1
  { IFS= read -r BM_READ1 <"$1"; } 2>/dev/null || true
  [[ -n "$BM_READ1" ]]
}

# Physical link in plain terms: up | no-link (cable/switch) | off (admin
# down) | unknown. carrier is authoritative when readable; fixture trees and
# odd drivers only have operstate, so fall back to it.
BM_LINK=unknown
bm::facts::_link_of() { # _link_of <sysfs-dir> -> BM_LINK
  local d="$1" flags
  BM_LINK=unknown
  [[ -e "$d" ]] || return 0
  if bm::facts::_read1 "$d/flags" && [[ "$BM_READ1" =~ ^0x[0-9a-fA-F]+$ ]]; then
    flags=$(( BM_READ1 ))
    if (( (flags & 1) == 0 )); then
      BM_LINK=off
      return 0
    fi
  fi
  if bm::facts::_read1 "$d/carrier"; then
    case "$BM_READ1" in
      1) BM_LINK=up; return 0 ;;
      0) BM_LINK=no-link; return 0 ;;
    esac
  fi
  if bm::facts::_read1 "$d/operstate"; then
    case "$BM_READ1" in
      up) BM_LINK=up ;;
      down | lowerlayerdown | dormant | notpresent) BM_LINK=no-link ;;
    esac
  fi
  return 0
}

bm::facts::nic_link() { # nic_link <nic> -> up | no-link | off | unknown
  bm::facts::_link_of "$BM_SYS_ROOT/class/net/$1"
  printf '%s\n' "$BM_LINK"
}

# Everything the pickers and `nics` show about one NIC, without a subshell
# per field. Sets BM_NIC_{LINK,SPEED,MASTER,MTU}.
bm::facts::nic_info() { # nic_info <nic>
  local d="$BM_SYS_ROOT/class/net/$1" t
  BM_NIC_LINK=unknown BM_NIC_SPEED=unknown BM_NIC_MASTER="" BM_NIC_MTU=unknown
  [[ -e "$d" ]] || return 1
  bm::facts::_link_of "$d"
  BM_NIC_LINK="$BM_LINK"
  if bm::facts::_read1 "$d/speed" && [[ "$BM_READ1" =~ ^[0-9]+$ ]] \
    && (( BM_READ1 > 0 && BM_READ1 < 4000000 )); then
    BM_NIC_SPEED="$BM_READ1"
  fi
  if [[ -L "$d/master" ]]; then
    t="$(readlink "$d/master" 2>/dev/null || true)"
    BM_NIC_MASTER="${t##*/}"
  fi
  if bm::facts::_read1 "$d/mtu"; then BM_NIC_MTU="$BM_READ1"; fi
  return 0
}

bm::facts::nic_link_failures() { # from the member's proc slave section
  local bond="$1" nic="$2"
  [[ -r "$BM_PROC_ROOT/net/bonding/$bond" ]] || { echo unknown; return; }
  awk -v nic="$nic" '
    /^Slave Interface:/ { cur = $3 }
    /^Link Failure Count:/ && cur == nic { print $4; found = 1; exit }
    END { if (!found) print "unknown" }' "$BM_PROC_ROOT/net/bonding/$bond"
}

# ---- policy ---------------------------------------------------------------

bm::facts::_match_any() {
  local text="$1" p
  shift || true
  for p in "$@"; do
    [[ -z "$p" ]] && continue
    [[ "$text" =~ $p ]] && return 0
  done
  return 1
}

bm::facts::nic_allowed() {
  local ifname="$1"
  local -a allow=() block=()
  read -r -a allow <<<"$(bm::config::get NIC_ALLOWLIST_PATTERNS)"
  read -r -a block <<<"$(bm::config::get NIC_BLOCKLIST_PATTERNS)"
  bm::facts::_match_any "$ifname" "${block[@]}" && return 1
  (( ${#allow[@]} == 0 )) && return 0
  bm::facts::_match_any "$ifname" "${allow[@]}"
}

bm::facts::eligible_nics() { # NICs the policy allows, one per line
  local n
  for n in "$BM_SYS_ROOT"/class/net/*; do
    [[ -e "$n" ]] || continue
    n="$(basename "$n")"
    bm::facts::nic_allowed "$n" || continue
    printf '%s\n' "$n"
  done
}

# ---- bonds ----------------------------------------------------------------

bm::facts::kernel_bonds() { # bonds the kernel knows about, one per line
  local f
  for f in "$BM_PROC_ROOT"/net/bonding/*; do
    [[ -e "$f" ]] || continue
    basename "$f"
  done
}

bm::facts::bond_exists_kernel() { [[ -e "$BM_PROC_ROOT/net/bonding/$1" ]]; }

bm::facts::bond_proc_value() { # bond_proc_value <bond> <label>
  local bond="$1" label="$2"
  [[ -r "$BM_PROC_ROOT/net/bonding/$bond" ]] || return 0
  awk -F': ' -v l="$label" '
    $1 == l { print $2; exit }' "$BM_PROC_ROOT/net/bonding/$bond"
}

bm::facts::bond_mode() { # normalized kernel mode name (first word)
  local raw
  raw="$(bm::facts::bond_proc_value "$1" "Bonding Mode")"
  case "$raw" in
    "load balancing (round-robin)") echo balance-rr ;;
    "fault-tolerance (active-backup)"*) echo active-backup ;;
    "load balancing (xor)") echo balance-xor ;;
    "fault-tolerance (broadcast)") echo broadcast ;;
    "IEEE 802.3ad Dynamic link aggregation") echo 802.3ad ;;
    "transmit load balancing") echo balance-tlb ;;
    "adaptive load balancing") echo balance-alb ;;
    "") echo unknown ;;
    *) echo "$raw" ;;
  esac
}

bm::facts::bond_members() { # member NICs from proc, one per line
  local bond="$1"
  [[ -r "$BM_PROC_ROOT/net/bonding/$bond" ]] || return 0
  awk -F': ' '/^Slave Interface:/ { gsub(/[[:space:]]/, "", $2); print $2 }' \
    "$BM_PROC_ROOT/net/bonding/$bond"
}

bm::facts::bond_member_mii() { # per-member MII status
  local bond="$1" nic="$2"
  [[ -r "$BM_PROC_ROOT/net/bonding/$bond" ]] || { echo unknown; return; }
  awk -v nic="$nic" '
    /^Slave Interface:/ { cur = $3 }
    /^MII Status:/ && cur == nic { print $3; found = 1; exit }
    END { if (!found) print "unknown" }' "$BM_PROC_ROOT/net/bonding/$bond"
}

bm::facts::bond_member_speed_duplex() { # "<speed> <duplex>" from proc slave section
  local bond="$1" nic="$2"
  [[ -r "$BM_PROC_ROOT/net/bonding/$bond" ]] || { echo "unknown unknown"; return; }
  awk -v nic="$nic" '
    /^Slave Interface:/ { cur = $3 }
    /^Speed:/ && cur == nic { spd = $2 }
    /^Duplex:/ && cur == nic { print (spd ? spd : "unknown"), $2; found = 1; exit }
    END { if (!found) print "unknown unknown" }' "$BM_PROC_ROOT/net/bonding/$bond"
}

# 802.3ad detail: aggregator id + partner mac of the bond, plus churn state.
bm::facts::bond_lacp_info() { # prints "key value" lines
  local bond="$1"
  [[ -r "$BM_PROC_ROOT/net/bonding/$bond" ]] || return 0
  # The bond-level "802.3ad info" block (tab-indented "Active Aggregator
  # Info:") carries the aggregator and partner MAC; the churn states are
  # emitted per port, further down, so they need their own pass.
  awk '
    /^802.3ad info/, /^Slave Interface:/ {
      if ($0 ~ /^[[:space:]]*Aggregator ID:/)       { print "aggregator_id " $3 }
      if ($0 ~ /^[[:space:]]*Partner Mac Address:/) { print "partner_mac " $4 }
      if ($0 ~ /^[[:space:]]*Number of ports:/)     { print "ports " $4 }
    }
    /^[[:space:]]*Actor Churn State:/   { if (!a++) print "actor_churn " $NF }
    /^[[:space:]]*Partner Churn State:/ { if (!p++) print "partner_churn " $NF }
    /^[[:space:]]*Actor Churned:/       { if (!ac++) print "actor_churned " $NF }
    /^[[:space:]]*Partner Churned:/     { if (!pc++) print "partner_churned " $NF }
  ' "$BM_PROC_ROOT/net/bonding/$bond"
}

bm::facts::bond_member_agg_id() { # member aggregator id (802.3ad)
  local bond="$1" nic="$2"
  [[ -r "$BM_PROC_ROOT/net/bonding/$bond" ]] || { echo unknown; return; }
  awk -v nic="$nic" '
    /^Slave Interface:/ { cur = $3 }
    /^Aggregator ID:/ && cur == nic { print $3; found = 1; exit }
    END { if (!found) print "unknown" }' "$BM_PROC_ROOT/net/bonding/$bond"
}

# Health verdict for one bond: healthy | degraded | down, with reasons.
# Output: first line = verdict, following lines = reasons.
bm::facts::bond_health() {
  local bond="$1"
  local verdict=healthy
  local -a reasons=()

  if ! bm::facts::bond_exists_kernel "$bond"; then
    printf 'down\nbond device not present in kernel\n'
    return
  fi

  local state
  state="$(bm::facts::nic_state "$bond")"
  if [[ "$state" != up ]]; then
    verdict=down
    reasons+=("bond operstate is '$state'")
  fi

  local -a members=()
  mapfile -t members < <(bm::facts::bond_members "$bond")
  if (( ${#members[@]} == 0 )); then
    printf 'down\nbond has no members\n'
    return
  fi

  local m up_count=0 mii
  local speeds="" spd dup
  for m in "${members[@]}"; do
    mii="$(bm::facts::bond_member_mii "$bond" "$m")"
    if [[ "$mii" == up ]]; then
      up_count=$((up_count + 1))
    else
      [[ "$verdict" == healthy ]] && verdict=degraded
      reasons+=("member $m MII status is '$mii'")
    fi
    read -r spd dup <<<"$(bm::facts::bond_member_speed_duplex "$bond" "$m")"
    # the kernel reports "Unknown" (capitalized) for a link-down member;
    # that is not a real speed/duplex reading, so never compare against it
    if [[ "$spd" != unknown && "$spd" != Unknown ]]; then
      if [[ -n "$speeds" && "$speeds" != "$spd" ]]; then
        [[ "$verdict" == healthy ]] && verdict=degraded
        reasons+=("member speed mismatch ($speeds vs $spd)")
      fi
      speeds="$spd"
    fi
    if [[ "$dup" != full && "$dup" != unknown && "$dup" != Unknown ]]; then
      [[ "$verdict" == healthy ]] && verdict=degraded
      reasons+=("member $m duplex is '$dup'")
    fi
  done
  if (( up_count == 0 )); then
    verdict=down
    reasons+=("no member has link")
  fi

  local mode
  mode="$(bm::facts::bond_mode "$bond")"
  if [[ "$mode" == "802.3ad" ]]; then
    local partner
    partner="$(bm::facts::bond_lacp_info "$bond" | awk '$1=="partner_mac"{print $2}')"
    if [[ -z "$partner" || "$partner" == "00:00:00:00:00:00" ]]; then
      [[ "$verdict" == healthy ]] && verdict=degraded
      reasons+=("no LACP partner (switch side not aggregating?)")
    fi
    local churn
    churn="$(bm::facts::bond_lacp_info "$bond" | awk '$1=="partner_churn"{print $2}')"
    if [[ "$churn" == churned ]]; then
      [[ "$verdict" == healthy ]] && verdict=degraded
      reasons+=("LACP partner churn state is 'churned'")
    fi
  fi

  printf '%s\n' "$verdict"
  printf '%s\n' "${reasons[@]:-}"
}

# Kernel VLAN interfaces from /proc/net/vlan/config: "dev vid parent" lines.
bm::facts::kernel_vlans() {
  local f="$BM_PROC_ROOT/net/vlan/config"
  [[ -r "$f" ]] || return 0
  awk -F'|' 'NR > 2 && NF >= 3 {
      d = $1; v = $2; p = $3
      gsub(/[[:space:]]/, "", d); gsub(/[[:space:]]/, "", v); gsub(/[[:space:]]/, "", p)
      if (d != "") print d, v, p
    }' "$f"
}

bm::facts::vlan_parent() { # vlan_parent <dev> -> parent device, or nothing
  local dev="$1" p
  p="$(bm::facts::kernel_vlans | awk -v d="$dev" '$1 == d { print $3; exit }')"
  if [[ -z "$p" && "$dev" == *.* ]] && bm::facts::bond_exists_kernel "${dev%.*}"; then
    p="${dev%.*}"
  fi
  printf '%s' "$p"
}

# ---- routing / ssh context ------------------------------------------------

bm::facts::route_dev_for() { # egress device for an IP, per the routing table
  local ip="$1"
  ip route get "$ip" 2>/dev/null | awk '
    { for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
}

bm::facts::default_gw4() { # "gateway dev" of the (first) IPv4 default route
  ip -4 route show default 2>/dev/null | awk '
    NR == 1 { gw = ""; dev = ""
      for (i = 1; i < NF; i++) {
        if ($i == "via") gw = $(i + 1)
        if ($i == "dev") dev = $(i + 1)
      }
      print gw, dev }'
}

bm::facts::ssh_egress_dev() { # device carrying this SSH session, if any
  local peer=""
  # sudo's default env_reset strips SSH_CONNECTION, and this tool is normally
  # run under sudo — so fall back to the sshd connection recorded for this
  # session's controlling terminal before concluding "not over SSH".
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    peer="$(awk '{print $1}' <<<"$SSH_CONNECTION")"
  elif [[ -n "${SSH_CLIENT:-}" ]]; then
    peer="$(awk '{print $1}' <<<"$SSH_CLIENT")"
  else
    peer="$(bm::facts::_ssh_peer_from_session)"
  fi
  [[ -n "$peer" ]] || return 0
  bm::facts::route_dev_for "$peer"
}

# Recover the SSH peer address from the login record for our terminal.
bm::facts::_ssh_peer_from_session() {
  local tty peer=""
  tty="$(ps -o tty= -p $$ 2>/dev/null | tr -d ' ')"
  [[ -n "$tty" && "$tty" != "?" ]] || return 0
  if bm::core::have_cmd who; then
    # "user pts/0 2026-08-25 10:00 (10.1.2.3)"
    peer="$(who 2>/dev/null | awk -v t="$tty" '$2 == t {
      if (match($0, /\(([^)]+)\)/)) { print substr($0, RSTART + 1, RLENGTH - 2); exit }
    }')"
  fi
  # a hostname is useless to `ip route get`; only pass through literal IPs
  [[ "$peer" =~ ^[0-9a-fA-F.:]+$ ]] || peer=""
  printf '%s' "$peer"
}

bm::facts::dev_addrs() { # addresses on a device, one CIDR per line
  local dev="$1"
  ip -br addr show dev "$dev" 2>/dev/null | awk '
    { for (i = 3; i <= NF; i++) print $i }'
}

# ==== 25-nm.sh ====
# lib/25-nm.sh — the only module that talks to nmcli.
# Rules: every invocation is an argv array through bm::nm::run (logged,
# dry-run aware); terse output is split with an escape-aware state machine
# (nmcli escapes ':' as '\:' and '\' as '\\'); connections are addressed by
# UUID so operations never depend on profile naming conventions.

bm::nm::run() { # run nmcli with logging + dry-run guard (plans normally
  # render instead of executing, this guard is defense in depth)
  if (( BM_DRY_RUN )); then
    bm::log::info "dry-run: nmcli $*"
    printf '[dry-run] nmcli %s\n' "$*" >&2
    return 0
  fi
  bm::log::info "nmcli $*"
  nmcli "$@"
}

# Split one line of `nmcli -t` output into the global BM_FIELDS array,
# honoring nmcli's '\:' and '\\' escapes.
bm::nm::terse_split() {
  local line="$1" field="" c i esc=0
  BM_FIELDS=()
  for ((i = 0; i < ${#line}; i++)); do
    c="${line:i:1}"
    if (( esc )); then
      field+="$c"
      esc=0
    elif [[ "$c" == "\\" ]]; then
      esc=1
    elif [[ "$c" == ":" ]]; then
      BM_FIELDS+=("$field")
      field=""
    else
      field+="$c"
    fi
  done
  BM_FIELDS+=("$field")
}

# List all connection profiles: one record per line, fields joined with the
# ASCII unit separator (0x1f), safe against any legal profile name.
# Fields: uuid<US>name<US>type<US>active-device
# NOTE: the connection LIST only accepts column fields (UUID/NAME/TYPE/DEVICE);
# setting.property fields like connection.master exist only on a single
# profile's `connection show <id>` output and are fetched via con_get/con_props.
bm::nm::con_list() {
  local line
  nmcli -t -f UUID,NAME,TYPE,DEVICE connection show 2>/dev/null | while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    bm::nm::terse_split "$line"
    local IFS=$'\x1f'
    printf '%s\n' "${BM_FIELDS[*]}"
  done
}

bm::nm::con_get() { # con_get <uuid-or-name> <property> — single property value
  nmcli -g "$2" connection show "$1" 2>/dev/null || true
}

# UUID of the bond connection profile for a bond interface name.
# Prefers an exact connection.interface-name match, falls back to con-name.
bm::nm::bond_con_uuid() {
  local bond="$1" rec uuid name type dev
  local by_name=""
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r uuid name type dev <<<"$rec"
    [[ "$type" == bond ]] || continue
    if [[ "$(bm::nm::con_get "$uuid" connection.interface-name)" == "$bond" ]]; then
      printf '%s\n' "$uuid"
      return 0
    fi
    [[ "$name" == "$bond" && -z "$by_name" ]] && by_name="$uuid"
  done < <(bm::nm::con_list)
  if [[ -n "$by_name" ]]; then
    printf '%s\n' "$by_name"
    return 0
  fi
  return 1
}

# All bond connection profiles: lines of "uuid<US>name<US>ifname".
bm::nm::bond_cons() {
  local rec uuid name type dev ifname
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r uuid name type dev <<<"$rec"
    [[ "$type" == bond ]] || continue
    ifname="$(bm::nm::con_get "$uuid" connection.interface-name)"
    printf '%s\x1f%s\x1f%s\n' "$uuid" "$name" "${ifname:-$dev}"
  done < <(bm::nm::con_list)
}

# Port (slave) profiles of a bond: match connection.master against the bond's
# uuid, con-name, or interface name — never against a naming convention.
# Output lines: "uuid<US>name<US>ifname".
bm::nm::port_cons() {
  local bond="$1"
  local bond_uuid bond_name
  bond_uuid="$(bm::nm::bond_con_uuid "$bond" || true)"
  bond_name=""
  [[ -n "$bond_uuid" ]] && bond_name="$(bm::nm::con_get "$bond_uuid" connection.id)"
  local rec uuid name type dev master stype ifname
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r uuid name type dev <<<"$rec"
    # bond ports are ethernet-like profiles; bond/vlan profiles never are
    [[ "$type" == bond || "$type" == vlan ]] && continue
    master="$(bm::nm::con_get "$uuid" connection.master)"
    [[ -n "$master" ]] || continue
    stype="$(bm::nm::con_get "$uuid" connection.slave-type)"
    [[ "$stype" == bond || -z "$stype" ]] || continue
    ifname="$(bm::nm::con_get "$uuid" connection.interface-name)"
    if [[ "$master" == "$bond" || ( -n "$bond_uuid" && "$master" == "$bond_uuid" ) || \
          ( -n "$bond_name" && "$master" == "$bond_name" ) ]]; then
      printf '%s\x1f%s\x1f%s\n' "$uuid" "$name" "${ifname:-$dev}"
    fi
  done < <(bm::nm::con_list)
}

# VLAN profiles on top of a bond, discovered via vlan.parent (also finds
# inactive profiles, unlike matching on the DEVICE column).
# Output lines: "uuid<US>name<US>ifname<US>vlan-id".
bm::nm::vlan_cons() {
  local bond="$1"
  local bond_uuid
  bond_uuid="$(bm::nm::bond_con_uuid "$bond" || true)"
  local rec uuid name type dev parent vid ifname
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r uuid name type dev <<<"$rec"
    [[ "$type" == vlan ]] || continue
    parent="$(bm::nm::con_get "$uuid" vlan.parent)"
    [[ "$parent" == "$bond" || ( -n "$bond_uuid" && "$parent" == "$bond_uuid" ) ]] || continue
    vid="$(bm::nm::con_get "$uuid" vlan.id)"
    ifname="$(bm::nm::con_get "$uuid" connection.interface-name)"
    printf '%s\x1f%s\x1f%s\x1f%s\n' "$uuid" "$name" "${ifname:-$dev}" "$vid"
  done < <(bm::nm::con_list)
}

bm::nm::con_exists() { # any profile with this name or uuid?
  nmcli -g connection.uuid connection show "$1" >/dev/null 2>&1
}

# ---- bond.options handling ------------------------------------------------

# Parse a bond.options string into an assoc array (by reference).
# Tokens without '=' are treated as continuations of the previous value
# (arp_ip_target=a,b legitimately embeds commas).
bm::nm::opts_parse() { # opts_parse <string> <assoc-name>
  local raw="$1"
  local -n _out="$2"
  local tok last=""
  local IFS=','
  for tok in $raw; do
    if [[ "$tok" == *=* ]]; then
      last="${tok%%=*}"
      _out["$last"]="${tok#*=}"
    elif [[ -n "$last" && -n "$tok" ]]; then
      _out["$last"]+=",$tok"
    fi
  done
}

# Render an assoc array back to a deterministic bond.options string:
# mode first, remaining keys sorted.
bm::nm::opts_render() { # opts_render <assoc-name>
  local -n _in="$1"
  local out="" key
  [[ -n "${_in[mode]:-}" ]] && out="mode=${_in[mode]}"
  while IFS= read -r key; do
    [[ -z "$key" || "$key" == mode ]] && continue
    [[ -n "$out" ]] && out+=","
    out+="$key=${_in[$key]}"
  done < <(printf '%s\n' "${!_in[@]}" | LC_ALL=C sort)
  printf '%s' "$out"
}

# Merge changes into an options string. Changes are key=value tokens;
# "key=" (empty value) deletes the key. Echoes the merged string.
bm::nm::opts_merge() { # opts_merge <current-string> [key=value ...]
  local current="$1"
  shift || true
  local -A merged=()
  bm::nm::opts_parse "$current" merged
  local chg key val
  for chg in "$@"; do
    key="${chg%%=*}"
    val="${chg#*=}"
    if [[ -z "$val" ]]; then
      unset 'merged[$key]'
    else
      merged["$key"]="$val"
    fi
  done
  bm::nm::opts_render merged
}

# ---- profile operations (used as plan steps) ------------------------------

# NB: ipv6.method 'disabled' only exists from NetworkManager 1.20; 'ignore'
# means the same thing here and works on every release this tool supports.
bm::nm::add_bond() { # add_bond <bond> <options-string>
  bm::nm::run connection add type bond con-name "$1" ifname "$1" \
    bond.options "$2" ipv4.method disabled ipv6.method ignore
}

bm::nm::add_port() { # add_port <bond-ref> <nic>  (bond-ref: uuid preferred)
  bm::nm::run connection add type ethernet con-name "bond-port-$2" ifname "$2" \
    master "$1" slave-type bond
}

bm::nm::add_vlan() { # add_vlan <bond> <vid>  -> profile/ifname "<bond>.<vid>"
  bm::nm::run connection add type vlan con-name "$1.$2" ifname "$1.$2" \
    vlan.parent "$1" vlan.id "$2" ipv4.method disabled ipv6.method ignore
}

bm::nm::modify() { bm::nm::run connection modify "$@"; }

bm::nm::up() { # up <uuid-or-name> [timeout]
  local timeout="${2:-$(bm::config::get ACTIVATE_TIMEOUT)}"
  bm::nm::run -w "$timeout" connection up "$1"
}

bm::nm::down() { bm::nm::run connection down "$1"; }

bm::nm::delete() { bm::nm::run connection delete "$1"; }

bm::nm::reload() { bm::nm::run connection reload; }

# Build the nmcli property arguments for an IP spec and store them in the
# global array BM_NM_IP_ARGS. family: 4|6; method: dhcp|auto|none|static.
bm::nm::ip_args() { # ip_args <4|6> <method> <addrs> <gw> <dns>
  local fam="$1" method="$2" addrs="$3" gw="$4" dns="$5"
  BM_NM_IP_ARGS=()
  local p="ipv$fam"
  case "$method" in
    dhcp | auto)
      BM_NM_IP_ARGS+=("$p.method" auto)
      ;;
    none | disabled)
      # ipv4 has had 'disabled' forever; ipv6 uses 'ignore' for NM < 1.20
      if [[ "$fam" == 6 ]]; then
        BM_NM_IP_ARGS+=("$p.method" ignore)
      else
        BM_NM_IP_ARGS+=("$p.method" disabled)
      fi
      ;;
    static)
      BM_NM_IP_ARGS+=("$p.method" manual "$p.addresses" "$addrs")
      [[ -n "$gw" ]] && BM_NM_IP_ARGS+=("$p.gateway" "$gw")
      ;;
    *)
      return 1
      ;;
  esac
  if [[ -n "$dns" ]]; then
    BM_NM_IP_ARGS+=("$p.dns" "${dns// /,}")
  fi
  return 0
}

# ==== 30-snap.sh ====
# lib/30-snap.sh — connection-profile snapshots with manifests, and a
# reconciling restore: profiles created after the snapshot are deleted (with
# confirmation) so restoring actually undoes creates, not just edits.
#
# Two profile stores are covered, because NetworkManager's default storage
# differs across the supported releases:
#   - keyfile: $BM_CONN_DIR (/etc/NetworkManager/system-connections) — RHEL 9+
#   - ifcfg:   $BM_IFCFG_DIR (/etc/sysconfig/network-scripts) — RHEL 8's
#     ifcfg-rh plugin, where nmcli writes ifcfg-*/keys-*/route-*/rule-* files
# A snapshot without the ifcfg store would silently fail to protect a RHEL 8
# host. Only NetworkManager's own file patterns are touched there — never the
# legacy scripts that share the directory.

# Snapshot ids that prune must never delete (the pending change's snapshot,
# and the snapshot a restore is currently reading).
BM_SNAP_PROTECT_ID=""

bm::snap::_dir() { printf '%s' "$BM_BACKUP_DIR"; }

bm::snap::path() { # path <id> -> keyfile archive path
  printf '%s/conn-%s.tar.gz' "$(bm::snap::_dir)" "$1"
}
bm::snap::ifcfg_path() { # path <id> -> ifcfg archive path
  printf '%s/conn-%s.ifcfg.tar.gz' "$(bm::snap::_dir)" "$1"
}
bm::snap::manifest_path() {
  printf '%s/conn-%s.manifest' "$(bm::snap::_dir)" "$1"
}

bm::snap::exists() { [[ -f "$(bm::snap::path "$1")" ]]; }

# ifcfg files NetworkManager owns. Everything else in that directory (the
# legacy ifup/ifdown helpers on RHEL 8) is deliberately left alone.
bm::snap::_ifcfg_files() {
  [[ -d "$BM_IFCFG_DIR" ]] || return 0
  (cd "$BM_IFCFG_DIR" 2>/dev/null &&
    find . -maxdepth 1 -type f \
      \( -name 'ifcfg-*' -o -name 'keys-*' -o -name 'route-*' -o -name 'route6-*' -o -name 'rule-*' -o -name 'rule6-*' \) \
      -printf '%P\n' | LC_ALL=C sort)
}

bm::snap::_keyfile_files() {
  [[ -d "$BM_CONN_DIR" ]] || return 0
  (cd "$BM_CONN_DIR" 2>/dev/null && find . -type f -printf '%P\n' | LC_ALL=C sort)
}

# Create a snapshot; echoes the snapshot id.
bm::snap::create() { # create [reason]
  local reason="${1:-manual}"
  bm::core::require_root
  mkdir -p "$(bm::snap::_dir)"
  chmod 0750 "$(bm::snap::_dir)" 2>/dev/null || true
  local id
  id="$(date +'%Y%m%d-%H%M%S')"
  # avoid collisions within the same second
  while bm::snap::exists "$id"; do id="${id}x"; done
  local archive ifcfg_archive manifest
  archive="$(bm::snap::path "$id")"
  ifcfg_archive="$(bm::snap::ifcfg_path "$id")"
  manifest="$(bm::snap::manifest_path "$id")"

  local -a ifcfg_files=()
  mapfile -t ifcfg_files < <(bm::snap::_ifcfg_files)

  {
    printf '# bond-manager snapshot manifest\n'
    printf 'id=%s\n' "$id"
    printf 'version=%s\n' "$BM_VERSION"
    printf 'created=%s\n' "$(bm::core::timestamp)"
    printf 'host=%s\n' "$(hostname 2>/dev/null || echo unknown)"
    printf 'reason=%s\n' "$reason"
    printf 'keyfile_dir=%s\n' "$BM_CONN_DIR"
    printf 'ifcfg_dir=%s\n' "$BM_IFCFG_DIR"
    local f
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      printf 'file=%s\t%s\n' "$(sha256sum "$BM_CONN_DIR/$f" 2>/dev/null | awk '{print $1}')" "$f"
    done < <(bm::snap::_keyfile_files)
    for f in "${ifcfg_files[@]}"; do
      [[ -n "$f" ]] || continue
      printf 'ifcfg_file=%s\t%s\n' "$(sha256sum "$BM_IFCFG_DIR/$f" 2>/dev/null | awk '{print $1}')" "$f"
    done
  } >"$manifest"
  chmod 0640 "$manifest"

  if ! tar -C "$BM_CONN_DIR" -czf "$archive" . 2>/dev/null; then
    rm -f "$archive" "$ifcfg_archive" "$manifest"
    bm::log::error "snapshot archive creation failed for $BM_CONN_DIR"
    return 1
  fi
  chmod 0640 "$archive"

  if (( ${#ifcfg_files[@]} > 0 )); then
    if ! tar -C "$BM_IFCFG_DIR" -czf "$ifcfg_archive" "${ifcfg_files[@]}" 2>/dev/null; then
      rm -f "$archive" "$ifcfg_archive" "$manifest"
      bm::log::error "snapshot archive creation failed for $BM_IFCFG_DIR"
      return 1
    fi
    chmod 0640 "$ifcfg_archive"
    bm::log::info "snapshot $id includes ${#ifcfg_files[@]} ifcfg profile file(s)"
  fi

  bm::log::info "snapshot $id created ($archive) reason=$reason"
  bm::snap::prune "$id"
  printf '%s\n' "$id"
}

bm::snap::list() { # newest first: "id  created  reason"
  local m id created reason line
  for m in $(ls -1t "$(bm::snap::_dir)"/conn-*.manifest 2>/dev/null || true); do
    id="" created="" reason=""
    while IFS= read -r line; do
      case "$line" in
        id=*) id="${line#id=}" ;;
        created=*) created="${line#created=}" ;;
        reason=*) reason="${line#reason=}" ;;
      esac
    done <"$m"
    [[ -n "$id" ]] && printf '%s\t%s\t%s\n' "$id" "$created" "$reason"
  done
  # archives from v2.x have no manifest; list them too
  local a
  for a in "$(bm::snap::_dir)"/conn-*.tar.gz; do
    [[ -e "$a" ]] || continue
    id="$(basename "$a")"
    id="${id#conn-}"
    id="${id%.tar.gz}"
    [[ "$id" == *.ifcfg ]] && continue
    [[ -f "$(bm::snap::manifest_path "$id")" ]] && continue
    printf '%s\t%s\t%s\n' "$id" "(no manifest)" "legacy"
  done
}

bm::snap::latest() {
  bm::snap::list | head -n1 | awk -F'\t' '{print $1}'
}

bm::snap::_manifest_files() { # keyfile paths recorded in a manifest
  local id="$1"
  awk -F'\t' '/^file=/ { print $2 }' "$(bm::snap::manifest_path "$id")" 2>/dev/null
}

bm::snap::_manifest_ifcfg_files() { # ifcfg paths recorded in a manifest
  local id="$1"
  awk -F'\t' '/^ifcfg_file=/ { print $2 }' "$(bm::snap::manifest_path "$id")" 2>/dev/null
}

bm::snap::_current_files() { bm::snap::_keyfile_files; }

# Files present now but absent from the snapshot (i.e. created after it).
bm::snap::stray_files() { # stray_files <id>
  local id="$1"
  [[ -f "$(bm::snap::manifest_path "$id")" ]] || return 0
  comm -23 <(bm::snap::_current_files) <(bm::snap::_manifest_files "$id" | LC_ALL=C sort)
}

bm::snap::stray_ifcfg_files() { # stray_ifcfg_files <id>
  local id="$1"
  [[ -f "$(bm::snap::manifest_path "$id")" ]] || return 0
  comm -23 <(bm::snap::_ifcfg_files) <(bm::snap::_manifest_ifcfg_files "$id" | LC_ALL=C sort)
}

bm::snap::diff() { # human summary of snapshot vs current state
  local id="$1"
  bm::snap::exists "$id" || bm::core::die "snapshot '$id' not found" "$BM_EX_PRECONDITION"
  if [[ ! -f "$(bm::snap::manifest_path "$id")" ]]; then
    echo "(legacy snapshot without manifest: file-level diff unavailable)"
    return 0
  fi
  local added removed
  added="$(bm::snap::stray_files "$id")"
  removed="$(comm -13 <(bm::snap::_current_files) <(bm::snap::_manifest_files "$id" | LC_ALL=C sort))"
  local changed="" f sum cur
  while IFS=$'\t' read -r sum f; do
    [[ -n "$f" && -f "$BM_CONN_DIR/$f" ]] || continue
    cur="$(sha256sum "$BM_CONN_DIR/$f" 2>/dev/null | awk '{print $1}')"
    [[ -n "$sum" && "$cur" != "$sum" ]] && changed+="$f"$'\n'
  done < <(awk -F'\t' '/^file=/ { sub(/^file=/, "", $1); print $1 "\t" $2 }' "$(bm::snap::manifest_path "$id")")

  local ifcfg_added
  ifcfg_added="$(bm::snap::stray_ifcfg_files "$id")"

  local any=0
  if [[ -n "$added" ]]; then
    any=1
    echo "Profiles created since snapshot (would be DELETED on restore):"
    sed 's/^/  + /' <<<"$added"
  fi
  if [[ -n "$ifcfg_added" ]]; then
    any=1
    echo "ifcfg profiles created since snapshot (would be DELETED on restore):"
    sed 's/^/  + /' <<<"$ifcfg_added"
  fi
  if [[ -n "$removed" ]]; then
    any=1
    echo "Profiles removed since snapshot (would be recreated on restore):"
    sed 's/^/  - /' <<<"$removed"
  fi
  if [[ -n "$changed" ]]; then
    any=1
    echo "Profiles modified since snapshot (would be reverted on restore):"
    sed 's/^/  ~ /' <<<"${changed%$'\n'}"
  fi
  (( any )) || echo "No differences between snapshot $id and current profiles."
}

# Reconciling restore. Deletes stray profile files, takes a pre-restore
# snapshot, untars, restores SELinux contexts and reloads NetworkManager.
# Callers are responsible for showing bm::snap::stray_files and confirming
# with the operator BEFORE calling this (the UI layer sits above this module).
bm::snap::restore() { # restore <id>
  local id="$1"
  bm::core::require_root
  bm::snap::exists "$id" || bm::core::die "snapshot '$id' not found" "$BM_EX_PRECONDITION"

  # A dry-run must not write anything at all — check before the pre-restore
  # snapshot, which is itself a real write.
  if (( BM_DRY_RUN )); then
    bm::log::say "[dry-run] would restore snapshot $id into $BM_CONN_DIR (and $BM_IFCFG_DIR)"
    bm::snap::diff "$id" || true
    return 0
  fi

  local stray stray_ifcfg
  stray="$(bm::snap::stray_files "$id")"
  stray_ifcfg="$(bm::snap::stray_ifcfg_files "$id")"

  # the restore itself is undoable: snapshot current state first. Protect the
  # snapshot we are about to read so pruning cannot delete it underneath us.
  local prev_protect="$BM_SNAP_PROTECT_ID"
  BM_SNAP_PROTECT_ID="$id"
  local pre
  pre="$(bm::snap::create "pre-restore-of-$id")" || {
    BM_SNAP_PROTECT_ID="$prev_protect"
    bm::core::die "could not snapshot current state — refusing to restore" "$BM_EX_ERR"
  }
  BM_SNAP_PROTECT_ID="$prev_protect"
  bm::log::say "current state saved as snapshot $pre"

  local f
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    rm -f "$BM_CONN_DIR/$f"
    bm::log::info "restore: removed stray profile $f"
  done <<<"$stray"
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    rm -f "$BM_IFCFG_DIR/$f"
    bm::log::info "restore: removed stray ifcfg profile $f"
  done <<<"$stray_ifcfg"

  # An unchecked extraction here would report success after the strays are
  # already gone, leaving the host with fewer profiles than either state.
  if ! tar -C "$BM_CONN_DIR" -xzf "$(bm::snap::path "$id")"; then
    bm::log::error "restore: extracting $(bm::snap::path "$id") failed"
    bm::core::die "restore FAILED while extracting snapshot $id — profiles may be incomplete. The state from before this attempt is snapshot $pre." "$BM_EX_ERR"
  fi
  if [[ -f "$(bm::snap::ifcfg_path "$id")" ]]; then
    if ! tar -C "$BM_IFCFG_DIR" -xzf "$(bm::snap::ifcfg_path "$id")"; then
      bm::log::error "restore: extracting $(bm::snap::ifcfg_path "$id") failed"
      bm::core::die "restore FAILED while extracting ifcfg profiles of snapshot $id — profiles may be incomplete. The state from before this attempt is snapshot $pre." "$BM_EX_ERR"
    fi
  fi

  if bm::core::have_cmd restorecon; then
    restorecon -RF "$BM_CONN_DIR" 2>/dev/null || true
    [[ -d "$BM_IFCFG_DIR" ]] && restorecon -RF "$BM_IFCFG_DIR" 2>/dev/null || true
  fi
  bm::nm::reload
  bm::log::info "restored snapshot $id"
  bm::log::say "restored snapshot $id (previous state: snapshot $pre)"
}

# Delete snapshots beyond MAX_BACKUPS, oldest first. Snapshots referenced by
# a pending change (or named via BM_SNAP_PROTECT_ID / the extra arguments) are
# never deleted: pruning the snapshot a rollback depends on would destroy the
# only way back.
bm::snap::prune() { # prune [protected-id...]
  local keep
  keep="$(bm::config::get MAX_BACKUPS)"
  [[ "$keep" =~ ^[0-9]+$ ]] || keep=10
  local -a protected=("$@")
  [[ -n "$BM_SNAP_PROTECT_ID" ]] && protected+=("$BM_SNAP_PROTECT_ID")
  local pending
  pending="$(bm::snap::_pending_snapshot_id)"
  [[ -n "$pending" ]] && protected+=("$pending")

  # newest first, excluding the companion ifcfg archives
  local -a archives=()
  mapfile -t archives < <(
    local a
    for a in "$(bm::snap::_dir)"/conn-*.tar.gz; do
      [[ -e "$a" ]] || continue
      [[ "$a" == *.ifcfg.tar.gz ]] && continue
      printf '%s\n' "$a"
    done | while IFS= read -r a; do
      printf '%s\t%s\n' "$(stat -c '%Y' "$a" 2>/dev/null || echo 0)" "$a"
    done | LC_ALL=C sort -rn -k1,1 | cut -f2-
  )
  local i id kept=0
  for ((i = 0; i < ${#archives[@]}; i++)); do
    id="$(basename "${archives[$i]}")"
    id="${id#conn-}"
    id="${id%.tar.gz}"
    if bm::core::in_list "$id" "${protected[@]:-}"; then
      continue    # protected snapshots are kept and do not consume the budget
    fi
    kept=$((kept + 1))
    (( kept > keep )) || continue
    rm -f "${archives[$i]}" "$(bm::snap::ifcfg_path "$id")" "$(bm::snap::manifest_path "$id")"
    bm::log::info "pruned old snapshot $id"
  done
}

# The snapshot id recorded in the pending-change state file, if any. Read as
# plain data rather than through the checkpoint module, which layers above.
bm::snap::_pending_snapshot_id() {
  local f="$BM_RUN_DIR/pending.state" line
  [[ -f "$f" ]] || return 0
  while IFS= read -r line; do
    case "$line" in
      snapshot=*) printf '%s' "${line#snapshot=}"; return 0 ;;
    esac
  done <"$f"
  return 0
}

# ==== 33-ckpt.sh ====
# lib/33-ckpt.sh — change protection tiers.
#   T1 "checkpoint": NetworkManager D-Bus checkpoint via busctl. NM itself
#      rolls back device + profile state server-side if we never confirm —
#      safe even when the change severs the SSH session driving it.
#   T2 "deadman":    transient systemd timer that runs `bond-manager rollback`
#      against the snapshot if not cancelled in time.
#   T3 "snapshot":   tar snapshot only (always taken in every tier).
# Pending-change state lives in $BM_RUN_DIR/pending.state so a NEW session
# can `bond-manager commit` / `bond-manager rollback` after a disconnect.

BM_NM_DBUS_DEST="org.freedesktop.NetworkManager"
BM_NM_DBUS_PATH="/org/freedesktop/NetworkManager"
BM_NM_DBUS_IFACE="org.freedesktop.NetworkManager"
# NMCheckpointCreateFlags: DELETE_NEW_CONNECTIONS(2) | DISCONNECT_NEW_DEVICES(4)
# — this is what lets a rollback undo a *create*, not just an edit.
BM_CKPT_FLAGS=6

bm::ckpt::state_file() { printf '%s/pending.state' "$BM_RUN_DIR"; }

# Which tier can this host support right now?
bm::ckpt::probe_tier() {
  if (( BM_NO_CHECKPOINT )); then
    if bm::core::have_cmd systemd-run; then echo deadman; else echo snapshot; fi
    return
  fi
  if bm::core::have_cmd busctl && \
     busctl --timeout=3 call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" \
       org.freedesktop.DBus.Peer Ping >/dev/null 2>&1; then
    echo checkpoint
    return
  fi
  if bm::core::have_cmd systemd-run; then
    echo deadman
    return
  fi
  echo snapshot
}

# ---- T1: NM checkpoints ---------------------------------------------------

bm::ckpt::dbus_create() { # dbus_create <timeout-secs> -> checkpoint object path
  local timeout="$1" out
  out="$(busctl call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" "$BM_NM_DBUS_IFACE" \
    CheckpointCreate aouu 0 "$timeout" "$BM_CKPT_FLAGS" 2>&1)" || {
    bm::log::warn "CheckpointCreate failed: $out"
    return 1
  }
  # reply: o "/org/freedesktop/NetworkManager/Checkpoint/N"
  local path
  path="$(sed -n 's/^o "\(.*\)"$/\1/p' <<<"$out")"
  [[ -n "$path" ]] || {
    bm::log::warn "could not parse checkpoint path from: $out"
    return 1
  }
  printf '%s\n' "$path"
}

bm::ckpt::dbus_destroy() { # commit: drop the checkpoint, keep the changes
  busctl call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" "$BM_NM_DBUS_IFACE" \
    CheckpointDestroy o "$1" >/dev/null 2>&1
}

bm::ckpt::dbus_rollback() {
  busctl call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" "$BM_NM_DBUS_IFACE" \
    CheckpointRollback o "$1" >/dev/null 2>&1
}

bm::ckpt::dbus_extend() { # add seconds to the rollback timeout
  busctl call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" "$BM_NM_DBUS_IFACE" \
    CheckpointAdjustRollbackTimeout ou "$1" "$2" >/dev/null 2>&1
}

# ---- T2: deadman timer ----------------------------------------------------

bm::ckpt::deadman_arm() { # deadman_arm <timeout-secs> <snapshot-id> -> unit name
  local timeout="$1" snap="$2"
  # The timer runs this program from systemd, with no shell and no cwd: an
  # unrunnable path would arm protection that silently never fires, which is
  # worse than honestly falling back a tier.
  if [[ -z "$BM_SELF" || ! -x "$BM_SELF" ]]; then
    bm::log::warn "deadman: '$BM_SELF' is not an executable path; cannot arm a timer"
    return 1
  fi
  local unit
  unit="bond-manager-deadman-$$-$(date +%s)"
  systemd-run --collect --unit "$unit" --on-active="${timeout}s" \
    --timer-property=AccuracySec=1s \
    "$BM_SELF" rollback --snapshot "$snap" --deadman --yes >/dev/null 2>&1 || return 1
  printf '%s\n' "$unit"
}

bm::ckpt::deadman_cancel() {
  local unit="$1"
  systemctl stop "${unit}.timer" >/dev/null 2>&1 || true
  systemctl stop "${unit}.service" >/dev/null 2>&1 || true
  systemctl reset-failed "${unit}.service" >/dev/null 2>&1 || true
}

# ---- pending-change state -------------------------------------------------

# arm: create protection before the first mutating step.
# Writes the state file and sets:
#   BM_CKPT_TIER, BM_CKPT_PATH (T1), BM_CKPT_UNIT (T2), BM_CKPT_DEADLINE
bm::ckpt::arm() { # arm <timeout-secs> <snapshot-id> <summary>
  local timeout="$1" snap="$2" summary="$3"
  BM_CKPT_TIER="$(bm::ckpt::probe_tier)"
  BM_CKPT_PATH=""
  BM_CKPT_UNIT=""
  BM_CKPT_DEADLINE=$(( $(bm::core::epoch) + timeout ))

  case "$BM_CKPT_TIER" in
    checkpoint)
      if ! BM_CKPT_PATH="$(bm::ckpt::dbus_create "$timeout")"; then
        bm::log::warn "checkpoint creation failed; falling back"
        if bm::core::have_cmd systemd-run; then
          BM_CKPT_TIER=deadman
        else
          BM_CKPT_TIER=snapshot
        fi
      fi
      ;;
  esac
  if [[ "$BM_CKPT_TIER" == deadman ]]; then
    if ! BM_CKPT_UNIT="$(bm::ckpt::deadman_arm "$timeout" "$snap")"; then
      bm::log::warn "deadman timer creation failed; snapshot-only protection"
      BM_CKPT_TIER=snapshot
    fi
  fi

  BM_CKPT_SNAPSHOT="$snap"
  BM_CKPT_SUMMARY="$summary"
  bm::ckpt::_write_state
  bm::log::info "armed tier=$BM_CKPT_TIER checkpoint=$BM_CKPT_PATH unit=$BM_CKPT_UNIT snapshot=$snap timeout=${timeout}s"
}

# Persist the pending-change state so a NEW session can commit or roll back.
bm::ckpt::_write_state() {
  mkdir -p "$BM_RUN_DIR"
  chmod 0750 "$BM_RUN_DIR" 2>/dev/null || true
  {
    printf 'tier=%s\n' "${BM_CKPT_TIER:-}"
    printf 'checkpoint_path=%s\n' "${BM_CKPT_PATH:-}"
    printf 'deadman_unit=%s\n' "${BM_CKPT_UNIT:-}"
    printf 'snapshot=%s\n' "${BM_CKPT_SNAPSHOT:-}"
    printf 'deadline=%s\n' "${BM_CKPT_DEADLINE:-0}"
    printf 'created=%s\n' "$(bm::core::timestamp)"
    printf 'pid=%s\n' "$$"
    printf 'summary=%s\n' "${BM_CKPT_SUMMARY:-}"
  } >"$(bm::ckpt::state_file)"
  chmod 0640 "$(bm::ckpt::state_file)" 2>/dev/null || true
}

# Load pending state into BM_PENDING_* variables. Returns 1 if none.
bm::ckpt::load_pending() {
  local f
  f="$(bm::ckpt::state_file)"
  [[ -f "$f" ]] || return 1
  BM_PENDING_TIER="" BM_PENDING_PATH="" BM_PENDING_UNIT=""
  BM_PENDING_SNAPSHOT="" BM_PENDING_DEADLINE="" BM_PENDING_SUMMARY=""
  local line
  while IFS= read -r line; do
    case "$line" in
      tier=*) BM_PENDING_TIER="${line#tier=}" ;;
      checkpoint_path=*) BM_PENDING_PATH="${line#checkpoint_path=}" ;;
      deadman_unit=*) BM_PENDING_UNIT="${line#deadman_unit=}" ;;
      snapshot=*) BM_PENDING_SNAPSHOT="${line#snapshot=}" ;;
      deadline=*) BM_PENDING_DEADLINE="${line#deadline=}" ;;
      summary=*) BM_PENDING_SUMMARY="${line#summary=}" ;;
    esac
  done <"$f"
  return 0
}

bm::ckpt::clear_pending() { rm -f "$(bm::ckpt::state_file)"; }

# Reset the auto-rollback deadline to a full window. Applying a plan consumes
# real time (each activation can take up to ACTIVATE_TIMEOUT), so without this
# the operator would get whatever is left of the window to decide — sometimes
# nothing at all on a slow bond. Called once verification has passed.
bm::ckpt::rebudget() { # rebudget <seconds>
  local secs="$1"
  case "${BM_CKPT_TIER:-}" in
    checkpoint)
      [[ -n "${BM_CKPT_PATH:-}" ]] || return 0
      bm::ckpt::dbus_extend "$BM_CKPT_PATH" "$secs" || {
        bm::log::warn "could not extend the checkpoint rollback timeout"
        return 1
      }
      ;;
    deadman)
      [[ -n "${BM_CKPT_UNIT:-}" ]] || return 0
      local snap="${BM_CKPT_SNAPSHOT:-}"
      [[ -n "$snap" ]] || return 0
      bm::ckpt::deadman_cancel "$BM_CKPT_UNIT"
      local unit
      if unit="$(bm::ckpt::deadman_arm "$secs" "$snap")"; then
        BM_CKPT_UNIT="$unit"
      else
        bm::log::warn "could not re-arm the deadman timer after applying"
        return 1
      fi
      ;;
    *) return 0 ;;
  esac
  BM_CKPT_DEADLINE=$(( $(bm::core::epoch) + secs ))
  bm::ckpt::_write_state
  bm::log::info "rollback deadline re-budgeted to ${secs}s after apply"
  return 0
}

# commit: keep the applied changes, disarm all protection.
# Returns 0 when protection was genuinely disarmed, 1 when there was nothing
# pending, and BM_EX_CKPT_LOST (2) when the checkpoint had already gone —
# which on NetworkManager means the rollback timeout expired and the change
# was reverted server-side. Reporting that as "committed" would tell the
# operator their change is live when it is not.
BM_EX_CKPT_LOST=2

bm::ckpt::commit() {
  bm::ckpt::load_pending || {
    bm::log::say "no pending change to commit"
    return 1
  }
  local rc=0
  case "$BM_PENDING_TIER" in
    checkpoint)
      if [[ -n "$BM_PENDING_PATH" ]]; then
        if ! bm::ckpt::dbus_destroy "$BM_PENDING_PATH"; then
          bm::log::warn "CheckpointDestroy failed for $BM_PENDING_PATH — the checkpoint no longer exists, so NetworkManager has most likely already rolled the change back"
          rc="$BM_EX_CKPT_LOST"
        fi
      fi
      ;;
    deadman)
      [[ -n "$BM_PENDING_UNIT" ]] && bm::ckpt::deadman_cancel "$BM_PENDING_UNIT"
      ;;
  esac
  bm::ckpt::clear_pending
  if (( rc == 0 )); then
    bm::log::info "committed pending change (tier=$BM_PENDING_TIER)"
  else
    bm::log::error "commit could not disarm the checkpoint (tier=$BM_PENDING_TIER); change may have been auto-rolled-back"
  fi
  return "$rc"
}

# rollback: revert the pending change through whichever tier is armed.
bm::ckpt::rollback_pending() {
  bm::ckpt::load_pending || return 1
  local ok=0
  case "$BM_PENDING_TIER" in
    checkpoint)
      if [[ -n "$BM_PENDING_PATH" ]] && bm::ckpt::dbus_rollback "$BM_PENDING_PATH"; then
        ok=1
      else
        bm::log::warn "checkpoint rollback failed (expired?); falling back to snapshot restore"
      fi
      ;;
    deadman)
      [[ -n "$BM_PENDING_UNIT" ]] && bm::ckpt::deadman_cancel "$BM_PENDING_UNIT"
      ;;
  esac
  if (( ! ok )) && [[ -n "$BM_PENDING_SNAPSHOT" ]]; then
    bm::snap::restore "$BM_PENDING_SNAPSHOT"
    ok=1
  fi
  bm::ckpt::clear_pending
  (( ok ))
}

# ==== 35-verify.sh ====
# lib/35-verify.sh — post-apply verification gate.
# Produces a structured pass/warn/fail report; the plan engine commits only
# when nothing failed. Checks run against kernel state (/proc, /sys) and the
# routing table — the ground truth, not what nmcli believes.

# Results accumulate in these arrays: level (pass|warn|fail) + message.
BM_VERIFY_LEVELS=()
BM_VERIFY_MSGS=()

bm::verify::_add() {
  BM_VERIFY_LEVELS+=("$1")
  BM_VERIFY_MSGS+=("$2")
}

bm::verify::reset() {
  BM_VERIFY_LEVELS=()
  BM_VERIFY_MSGS=()
}

bm::verify::failed() { # any fail recorded?
  local l
  for l in "${BM_VERIFY_LEVELS[@]}"; do
    [[ "$l" == fail ]] && return 0
  done
  return 1
}

bm::verify::render() {
  local i mark
  for i in "${!BM_VERIFY_LEVELS[@]}"; do
    case "${BM_VERIFY_LEVELS[$i]}" in
      pass) mark="$(bm::core::c_ok '  ok  ')" ;;
      warn) mark="$(bm::core::c_warn ' warn ')" ;;
      fail) mark="$(bm::core::c_err ' FAIL ')" ;;
    esac
    printf '[%s] %s\n' "$mark" "${BM_VERIFY_MSGS[$i]}"
  done
}

# Wait for a condition function to return true, up to LINK_SETTLE_TIMEOUT.
bm::verify::_settle() { # _settle <fn> [args...]
  local deadline
  deadline=$(( $(bm::core::epoch) + $(bm::config::get LINK_SETTLE_TIMEOUT) ))
  while ! "$@"; do
    (( $(bm::core::epoch) >= deadline )) && return 1
    sleep 1
  done
  return 0
}

bm::verify::_bond_up() { [[ "$(bm::facts::nic_state "$1")" == up ]]; }

bm::verify::_member_enslaved() { # _member_enslaved <bond> <nic>
  bm::facts::bond_members "$1" | grep -qx "$2"
}

# Verify a bond against expectations.
#   bm::verify::bond <bond> [mode] [members-csv] [ip-dev] [gw4] [expect-state] [absent-members-csv]
# Empty expectation fields are skipped. ip-dev is the device that should
# carry the IP (the bond itself or a VLAN interface on it).
# expect-state is 'up' (default) or 'any' — 'any' is for operations that
# legitimately leave the bond down, such as --no-activate or removing the
# last member; demanding 'up' there would fail a correct change and roll it
# back. absent-members names NICs that must NO LONGER be enslaved.
bm::verify::bond() {
  local bond="$1" want_mode="${2:-}" want_members="${3:-}" ip_dev="${4:-}" gw4="${5:-}"
  local expect_state="${6:-up}" absent_members="${7:-}"

  if ! bm::facts::bond_exists_kernel "$bond"; then
    if [[ "$expect_state" == any ]]; then
      bm::verify::_add warn "bond '$bond' is not present in the kernel"
      return 0
    fi
    bm::verify::_add fail "bond '$bond' not present in kernel (/proc/net/bonding)"
    return 0
  fi
  bm::verify::_add pass "bond '$bond' exists in kernel"

  if bm::verify::_settle bm::verify::_bond_up "$bond"; then
    bm::verify::_add pass "bond '$bond' operstate is up"
  elif [[ "$expect_state" == any ]]; then
    bm::verify::_add warn "bond '$bond' operstate is '$(bm::facts::nic_state "$bond")' (not expected to be up after this change)"
  else
    bm::verify::_add fail "bond '$bond' operstate is '$(bm::facts::nic_state "$bond")'"
  fi

  if [[ -n "$absent_members" ]]; then
    bm::core::split_list "$absent_members"
    local gone
    for gone in "${BM_LIST[@]}"; do
      if bm::facts::bond_members "$bond" | grep -qx "$gone"; then
        bm::verify::_add fail "member $gone is still enslaved to $bond"
      else
        bm::verify::_add pass "member $gone is no longer enslaved to $bond"
      fi
    done
  fi

  if [[ -n "$want_mode" ]]; then
    local mode
    mode="$(bm::facts::bond_mode "$bond")"
    if [[ "$mode" == "$want_mode" ]]; then
      bm::verify::_add pass "mode is $mode"
    else
      bm::verify::_add fail "mode is '$mode', expected '$want_mode'"
    fi
  fi

  if [[ -n "$want_members" ]]; then
    bm::core::split_list "$want_members"
    local m mii
    for m in "${BM_LIST[@]}"; do
      if bm::verify::_settle bm::verify::_member_enslaved "$bond" "$m"; then
        mii="$(bm::facts::bond_member_mii "$bond" "$m")"
        if [[ "$mii" == up ]]; then
          bm::verify::_add pass "member $m enslaved, MII up"
        else
          bm::verify::_add warn "member $m enslaved but MII status is '$mii'"
        fi
      else
        bm::verify::_add fail "member $m is not enslaved to $bond"
      fi
    done
  fi

  local mode_now
  mode_now="$(bm::facts::bond_mode "$bond")"
  if [[ "$mode_now" == "802.3ad" ]]; then
    local partner
    partner="$(bm::facts::bond_lacp_info "$bond" | awk '$1=="partner_mac"{print $2}')"
    if [[ -n "$partner" && "$partner" != "00:00:00:00:00:00" ]]; then
      bm::verify::_add pass "LACP partner present ($partner)"
    else
      bm::verify::_add warn "no LACP partner detected — check switch-side LACP configuration"
    fi
  fi
  if [[ "$mode_now" == active-backup ]]; then
    local active
    active="$(bm::facts::bond_proc_value "$bond" "Currently Active Slave")"
    if [[ -n "$active" ]]; then
      bm::verify::_add pass "active member is $active"
    else
      bm::verify::_add warn "no currently active member reported"
    fi
  fi

  if [[ -n "$ip_dev" ]]; then
    local addrs
    addrs="$(bm::facts::dev_addrs "$ip_dev")"
    if [[ -n "$addrs" ]]; then
      bm::verify::_add pass "$ip_dev has address(es): $(tr '\n' ' ' <<<"$addrs")"
    else
      bm::verify::_add warn "$ip_dev has no addresses yet (DHCP still negotiating?)"
    fi
  fi

  if [[ -n "$gw4" && -n "$ip_dev" ]]; then
    # Reachability through the changed interface — not per-member ping -I,
    # which is meaningless on enslaved NICs that carry no IP.
    if ping -c 2 -W 2 -I "$ip_dev" "$gw4" >/dev/null 2>&1; then
      bm::verify::_add pass "gateway $gw4 reachable via $ip_dev"
    else
      bm::verify::_add warn "gateway $gw4 not answering ping via $ip_dev"
    fi
  fi
  return 0
}

# ==== 40-json.sh ====
# lib/40-json.sh — correct JSON emission in pure bash.
# Strings are escaped per RFC 8259 including control characters (\u00XX).
# Documents carry schema_version so consumers can detect format changes.

BM_JSON_SCHEMA_VERSION=1

bm::json::escape() {
  local s="$1" out="" c i o
  for ((i = 0; i < ${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      '"') out+='\"' ;;
      '\') out+='\\' ;;
      $'\n') out+='\n' ;;
      $'\r') out+='\r' ;;
      $'\t') out+='\t' ;;
      *)
        printf -v o '%d' "'$c"
        if (( o > 0 && o < 32 )); then
          printf -v c '\\u%04x' "$o"
        fi
        out+="$c"
        ;;
    esac
  done
  printf '%s' "$out"
}

bm::json::str() { printf '"%s"' "$(bm::json::escape "$1")"; }

bm::json::num_or_str() { # numbers stay numbers, everything else is a string
  if [[ "$1" =~ ^-?[0-9]+$ ]]; then
    printf '%s' "$1"
  else
    bm::json::str "$1"
  fi
}

bm::json::bool() { # bool <0|1|true|false>
  case "$1" in
    1 | true) printf 'true' ;;
    *) printf 'false' ;;
  esac
}

# Join pre-rendered JSON values into an array.
bm::json::arr() {
  local out="" v
  for v in "$@"; do
    [[ -n "$out" ]] && out+=","
    out+="$v"
  done
  printf '[%s]' "$out"
}

# Array of strings from lines on stdin.
bm::json::arr_of_lines() {
  local out="" line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ -n "$out" ]] && out+=","
    out+="$(bm::json::str "$line")"
  done
  printf '[%s]' "$out"
}

# ==== 45-help.sh ====
# lib/45-help.sh — every piece of plain-English guidance in one place, so the
# CLI (`help`, error hints) and the TUI (menus, help screens, result panels)
# say exactly the same thing. Pure text: nothing here reads or changes state
# except config defaults quoted in examples.
#
# Help text is deliberately 7-bit ASCII: it must read cleanly on a serial
# console with no UTF-8 locale, which is where people need it most.

BM_HELP_COMMANDS=(list show status diagnose verify doctor nics config completion help
  create modify add-member remove-member swap-member remove vlan clone repair
  commit rollback snapshot bundle init tui version)
BM_HELP_TOPICS=(basics modes lacp safety practice moving glossary keys exit-codes)

# Words people type when they mean a command. Suggested, never executed.
declare -A BM_HELP_SYNONYMS=(
  [move]=swap-member [migrate]=swap-member [swap]=swap-member [replace]=swap-member
  [undo]=rollback [revert]=rollback [keep]=commit [confirm]=commit [accept]=commit
  [fix]=repair [new]=create [make]=create [build]=create [add]=add-member
  [ls]=list [info]=show [check]=status [health]=status [ports]=nics
  [interfaces]=nics [nic]=nics [cards]=nics [delete]=remove [destroy]=remove
  [del]=remove [rm]=remove [edit]=modify [change]=modify [set]=modify
  [backup]=snapshot [menu]=tui [menus]=tui [preflight]=doctor [support]=bundle
)

bm::help::canonical() { # canonical <word> -> command name (aliases resolved), rc 1 if none
  local w="$1"
  case "$w" in
    delete) w=remove ;;
    support-bundle) w=bundle ;;
  esac
  bm::core::in_list "$w" "${BM_HELP_COMMANDS[@]}" || return 1
  printf '%s\n' "$w"
}

bm::help::is_command() { bm::help::canonical "$1" >/dev/null; }
bm::help::is_topic() { bm::core::in_list "$1" "${BM_HELP_TOPICS[@]}"; }

bm::help::synonym() { # synonym <word> -> suggested command, or nothing
  local w="${1,,}"
  if [[ -n "${BM_HELP_SYNONYMS[$w]:-}" ]]; then
    printf '%s\n' "${BM_HELP_SYNONYMS[$w]}"
  fi
  return 0
}

# Best "did you mean" for a word that is not a command: synonym first, then
# the closest spelling.
bm::help::suggest_command() { # suggest_command <word>
  local s
  s="$(bm::help::synonym "$1")"
  if [[ -z "$s" ]]; then
    s="$(bm::core::closest "$1" "${BM_HELP_COMMANDS[@]}" delete)"
  fi
  printf '%s' "$s"
}

# ---- short lists shared by usage and the TUI ------------------------------

bm::help::common_tasks() {
  cat <<EOF
  Are my bonds OK?            $BM_PROG list
  Which ports can I use?      $BM_PROG nics
  Preview, change nothing     $BM_PROG -n <command> ...
  Move to a new switch        $BM_PROG swap-member BOND --old IF --new IF
  Build a bond                $BM_PROG create BOND --mode M --members A,B
  Fix settings that drifted   $BM_PROG repair BOND
  Keep / undo last change     $BM_PROG commit  |  $BM_PROG rollback
EOF
}

# ---- modes ------------------------------------------------------------------

bm::help::mode_short() { # a two-word nickname shown next to the kernel name
  case "$1" in
    active-backup) echo "failover" ;;
    802.3ad) echo "LACP" ;;
    balance-alb) echo "adaptive balancing" ;;
    balance-tlb) echo "transmit balancing" ;;
    balance-xor) echo "hash balancing" ;;
    balance-rr) echo "round-robin" ;;
    broadcast) echo "broadcast" ;;
    *) echo "$1" ;;
  esac
}

bm::help::mode_label() { # one plain sentence per mode (BM_MODE_HELP, 18-val)
  printf '%s\n' "${BM_MODE_HELP[$1]:-$1}"
}

bm::help::mode_switch_needs() { # none | lacp | static
  case "$1" in
    802.3ad) echo lacp ;;
    balance-rr | balance-xor | broadcast) echo static ;;
    *) echo none ;;
  esac
}

bm::help::mode_alias() { # mode_alias <word> -> kernel mode name, or nothing
  local w="${1,,}"
  case "$w" in
    lacp | 8023ad | 802.3 | 802-3ad | ieee802.3ad | 4) echo 802.3ad ;;
    failover | ab | active-passive | activebackup | active_backup | 1) echo active-backup ;;
    round-robin | roundrobin | rr | 0) echo balance-rr ;;
    xor | 2) echo balance-xor ;;
    tlb | 5) echo balance-tlb ;;
    alb | 6) echo balance-alb ;;
    3) echo broadcast ;;
    *)
      if bm::val::mode "$w"; then echo "$w"; fi
      ;;
  esac
  return 0
}

# ---- health reasons, results, safety -------------------------------------

# Turn one bond_health reason into plain words plus what to do about it.
# Prints two lines: the explanation, then "What to do: ...".
bm::help::explain_reason() { # explain_reason <reason>
  local r="$1" what="" todo=""
  case "$r" in
    "bond device not present in kernel")
      what="The bond is not running right now - only its saved settings exist."
      todo="Bring it up (nmcli connection up NAME) or check that its ports exist." ;;
    "bond operstate is "*)
      what="The bond itself is not up (the kernel says ${r#bond operstate is })."
      todo="Usually every cable is unplugged or the switch ports are disabled." ;;
    "bond has no members")
      what="The bond has no network ports in it, so it cannot carry traffic."
      todo="Add a port: menu 'Change a bond' > 'Add a port' (or: $BM_PROG add-member)." ;;
    "member "*" MII status is "*)
      local m="${r#member }"
      m="${m%% *}"
      what="Port $m has no link: the cable is unplugged or broken, or the switch port is off."
      todo="Check the cable and the switch port. The other ports keep the bond working." ;;
    "member speed mismatch"*)
      what="The ports run at different speeds ${r#member speed mismatch }. Traffic gets uneven."
      todo="Use ports of the same speed, or check speed/auto-negotiation on the switch." ;;
    "member "*" duplex is "*)
      local d="${r#member }"
      d="${d%% *}"
      what="Port $d runs at half duplex, which is slow and error-prone."
      todo="Check the cable and the switch port settings (it should say full duplex)." ;;
    "no member has link")
      what="None of the bond's ports has a link, so this bond carries no traffic."
      todo="Check the cables and switch ports of every port in the bond." ;;
    "no LACP partner"*)
      what="The switch is not answering LACP: its ports are probably not set up as an LACP bundle."
      todo="Ask the network team for an LACP port-channel on these switch ports, or use active-backup." ;;
    "LACP partner churn"*)
      what="LACP talks to the switch but cannot agree - often ports split across two separate switches."
      todo="Check the switch port-channel. During a switch migration, use active-backup." ;;
    *)
      what="$r"
      todo="Run a closer look: $BM_PROG diagnose BOND" ;;
  esac
  printf '%s\nWhat to do: %s\n' "$what" "$todo"
}

bm::help::health_word() { # healthy | needs attention | DOWN
  case "$1" in
    healthy) echo "healthy" ;;
    degraded) echo "needs attention" ;;
    down) echo "DOWN" ;;
    *) echo "$1" ;;
  esac
}

bm::help::tier_sentence() { # tier_sentence <checkpoint|deadman|snapshot>
  case "$1" in
    checkpoint) echo "Safety net: if you do not confirm, NetworkManager undoes the change by itself - even if the change cuts your connection." ;;
    deadman) echo "Safety net: if you do not confirm, a system timer undoes the change by itself." ;;
    snapshot) echo "Safety net: a backup copy only - nothing undoes the change automatically. Have console access ready." ;;
    *) echo "Safety net: $1" ;;
  esac
}

bm::help::tier_short() { # for the dashboard
  case "$1" in
    checkpoint) echo "automatic undo (NetworkManager)" ;;
    deadman) echo "automatic undo (backup timer)" ;;
    snapshot) echo "backup copy only - nothing undoes changes automatically" ;;
    *) echo "$1" ;;
  esac
}

# Plain-words summary of how an action ended. Fills BM_HELP_TITLE,
# BM_HELP_STYLE (ok|warn|err|info) and BM_HELP_LINES.
BM_HELP_TITLE=""
BM_HELP_STYLE=info
BM_HELP_LINES=()
bm::help::explain_rc() { # explain_rc <rc> [outcome] [practice 0|1]
  local rc="$1" outcome="${2:-}" practice="${3:-0}"
  BM_HELP_LINES=()
  case "$rc:$outcome" in
    0:committed)
      BM_HELP_TITLE="Done - the change is live and kept."
      BM_HELP_STYLE=ok
      BM_HELP_LINES=("All checks passed and you confirmed it.") ;;
    0:dry-run)
      BM_HELP_TITLE="Practice run finished - nothing was changed."
      BM_HELP_STYLE=info
      BM_HELP_LINES=("The plan above is exactly what would run for real."
        "To do it for real: switch practice mode off (key p) and repeat.") ;;
    0:cancelled)
      BM_HELP_TITLE="Cancelled - nothing was changed."
      BM_HELP_STYLE=info ;;
    0:noop)
      BM_HELP_TITLE="Nothing to do - it is already set up that way."
      BM_HELP_STYLE=ok ;;
    0:*)
      BM_HELP_TITLE="Finished."
      BM_HELP_STYLE=ok
      if (( practice )); then
        BM_HELP_LINES=("Practice mode: nothing was changed.")
      else
        BM_HELP_LINES=("See the messages above for details.")
      fi ;;
    "$BM_EX_USAGE":*)
      BM_HELP_TITLE="Something you entered was not accepted - nothing was changed."
      BM_HELP_STYLE=err
      BM_HELP_LINES=("The red ERROR line above says what, and 'Next step' how to fix it.") ;;
    "$BM_EX_PRECONDITION":*)
      BM_HELP_TITLE="Could not start - nothing was changed."
      BM_HELP_STYLE=err
      BM_HELP_LINES=("The ERROR line above says why (and what to do next).") ;;
    "$BM_EX_LOCKED":*)
      BM_HELP_TITLE="Another bond-manager is busy on this server - nothing was changed."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("Wait for it to finish, then try again.") ;;
    "$BM_EX_VERIFY":expired)
      BM_HELP_TITLE="Time ran out, so the change was undone."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("Your network is back the way it was before.") ;;
    "$BM_EX_VERIFY":lost)
      BM_HELP_TITLE="Too late to keep it - the safety net had already undone the change."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("Check the result with 'Check my bonds'.") ;;
    "$BM_EX_VERIFY":*)
      BM_HELP_TITLE="The change was undone - everything is back as it was."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("Either a check failed (see the FAIL lines above) or you chose Undo."
        "Nothing is left half-done.") ;;
    "$BM_EX_PARTIAL":*)
      BM_HELP_TITLE="The change is live but NOT kept yet."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("It will undo itself automatically unless you keep it."
        "Keep it: menu 'Undo & safety' (or: $BM_PROG commit).") ;;
    130:*)
      BM_HELP_TITLE="You stopped it."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("If a change had already started, its safety net is still armed.") ;;
    "$BM_EX_DEGRADED":* | "$BM_EX_DOWN":*)
      BM_HELP_TITLE="Some bonds need attention."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("The reasons and what to do are listed above.") ;;
    *)
      BM_HELP_TITLE="Something went wrong (code $rc)."
      BM_HELP_STYLE=err
      BM_HELP_LINES=("Read the messages above; the full record is in $BM_LOG_FILE.") ;;
  esac
}

bm::help::speed_label() { # speed_label <Mb/s|unknown> -> 10G, 1G, 100M, -
  local s="$1"
  if [[ ! "$s" =~ ^[0-9]+$ ]]; then
    echo "-"
  elif (( s >= 1000 && s % 1000 == 0 )); then
    echo "$(( s / 1000 ))G"
  elif (( s >= 1000 )); then
    echo "$(( s / 100 ))" | sed 's/\(.\)$/.\1G/'
  else
    echo "${s}M"
  fi
}

bm::help::option_help() { # one line per bond option key
  case "$1" in
    miimon) echo "How often (ms) to check each port's link. 100 is a good default." ;;
    updelay) echo "Wait this long (ms) after a link comes back before using it again." ;;
    downdelay) echo "Wait this long (ms) after a link drops before giving up on it." ;;
    use_carrier) echo "1 = trust the driver's link signal (normal); 0 = older method." ;;
    primary) echo "The port to prefer whenever it has a link (failover-style modes)." ;;
    primary_reselect) echo "When the preferred port returns: always | better | failure." ;;
    fail_over_mac) echo "How the MAC address moves on failover: none | active | follow." ;;
    lacp_rate) echo "How often LACP talks to the switch: fast (1s) or slow (30s)." ;;
    xmit_hash_policy) echo "How traffic is split across ports: layer2 | layer2+3 | layer3+4 ..." ;;
    ad_select) echo "Which LACP group wins: stable | bandwidth | count." ;;
    min_links) echo "Minimum working ports before the bond reports itself up." ;;
    arp_interval) echo "Check links by ARP-pinging a target every N ms (instead of miimon)." ;;
    arp_ip_target) echo "The IPv4 address(es) to ARP-ping when arp_interval is used." ;;
    arp_validate) echo "Which ARP replies count as proof of life: none | active | backup | all." ;;
    arp_all_targets) echo "A port is up if any / all ARP targets answer." ;;
    num_grat_arp | num_unsol_na) echo "How many announcements to send after a failover." ;;
    resend_igmp) echo "How many IGMP reports to resend after a failover." ;;
    all_slaves_active) echo "1 = accept traffic on standby ports too (rarely needed)." ;;
    lp_interval) echo "Seconds between learning packets (tlb/alb modes)." ;;
    packets_per_slave) echo "Packets per port before moving to the next (round-robin)." ;;
    tlb_dynamic_lb) echo "1 = rebalance by load; 0 = by hash only (tlb mode)." ;;
    ad_actor_sys_prio | ad_actor_system | ad_user_port_key) echo "Advanced LACP identity setting. Leave alone unless the network team asks." ;;
    *) echo "Advanced bonding option (see the kernel bonding documentation)." ;;
  esac
}

# ---- topics -----------------------------------------------------------------

bm::help::topic_title() {
  case "$1" in
    basics) echo "What is a bond? (start here)" ;;
    modes) echo "Which bond mode should I pick?" ;;
    lacp) echo "LACP and the switch" ;;
    safety) echo "The safety net: how changes undo themselves" ;;
    practice) echo "Practice mode" ;;
    moving) echo "Moving a server to a new switch" ;;
    glossary) echo "Words you will see" ;;
    keys) echo "Keys in the menus" ;;
    exit-codes) echo "Exit codes (for scripts)" ;;
    *) echo "$1" ;;
  esac
}

bm::help::topic() { # topic <name> — rc 1 if unknown
  local t="$1"
  case "$t" in
    basics) cat <<EOF
WHAT IS A BOND?

A bond joins two (or more) network ports into one. The server sees a single
connection - say bond0 with one IP address - that runs over several cables.
If a cable, a network card or a switch dies, traffic keeps flowing over the
others. Depending on the mode, the ports can also share the load.

    cable 1 --\\
               >== bond0 (one IP) ==> the server
    cable 2 --/

The ports inside a bond are called its "members" (or "ports"). Each one is
a network card such as ens1f0 or eth1. A VLAN is a tagged network riding on
top of the bond, e.g. bond0.120.

WHAT THIS TOOL DOES FOR YOU

Changing a bond on a live server is risky: one wrong step and you cut off the
SSH session you are typing in. bond-manager makes every change safe:

  1. It shows you the exact plan first (and can stop there: practice mode).
  2. It saves a backup copy of the network settings.
  3. It arms a safety net that undoes the change if you do not confirm it.
  4. It makes the change, then checks the real kernel state.
  5. If a check fails it undoes everything by itself. If all is well, it asks
     you to keep the change - and undoes it if you never answer.

Start with:  sudo $BM_PROG        (menus; press p for practice mode)
       or:   $BM_PROG list        (are my bonds OK?)
EOF
      ;;
    modes) cat <<EOF
WHICH BOND MODE SHOULD I PICK?

Not sure? Pick active-backup. It works with any switch and never needs the
network team.

  Mode           What it does                     Switch setup needed?
  -------------  -------------------------------  -------------------------
  active-backup  One port works, the others wait. No
  802.3ad        LACP: all ports carry traffic.   YES - an LACP bundle
  balance-alb    Shares traffic in and out.       No
  balance-tlb    Shares outgoing traffic.         No
  balance-xor    Shares traffic by address.       Yes - static port-channel
  balance-rr     Packets take turns per port.     Yes - static port-channel
  broadcast      Everything on every port.        Yes - special cases only

If the switch is not set up for the mode you pick, the bond may come up but
pass no traffic - bond-manager's checks will notice and undo the change.
EOF
      ;;
    lacp) cat <<EOF
LACP AND THE SWITCH

802.3ad (LACP) lets all ports carry traffic at once, but it is a deal between
the server AND the switch: the switch ports must be configured as one LACP
bundle (Cisco: "port-channel ... mode active"; others: "LAG", "trunk group").

- If the switch side is not set up, the bond has "no LACP partner" and may
  carry no traffic. '$BM_PROG diagnose BOND' shows this.
- All ports of an LACP bond must end on ONE switch, or on a pair of switches
  that act as one (MLAG, vPC, a stack).
- Moving to a new switch one cable at a time means one leg on each switch for
  a while. Unless the two switches share an LACP group, switch the bond to
  active-backup first, move both cables, then switch back to 802.3ad.
EOF
      ;;
    safety) cat <<EOF
THE SAFETY NET: HOW CHANGES UNDO THEMSELVES

Every change follows the same steps:

  plan -> backup copy -> arm the safety net -> change -> check -> keep?

- Plan: the exact nmcli commands are shown before anything happens.
- Backup copy: the saved network settings are archived (a "snapshot").
- Safety net: the strongest one this server supports.
    automatic undo (NetworkManager)  NetworkManager itself undoes the change
                                     if it is not confirmed in time - even if
                                     the change cut your SSH session.
    automatic undo (backup timer)    a system timer restores the backup copy.
    backup copy only                 nothing automatic; undo by hand.
  '$BM_PROG doctor' tells you which one you get.
- Check: the real kernel state is read back. A failed check undoes the
  change immediately.
- Keep?: you get a countdown (default $(bm::config::get ROLLBACK_WINDOW) seconds). Press K to keep the
  change, U to undo it. Do nothing and it is undone.

IF YOUR SSH SESSION DROPS

Do not panic. Wait for the countdown to run out and reconnect - the change
will have been undone. If you can reconnect before that, run
  sudo $BM_PROG commit      to keep the change, or
  sudo $BM_PROG rollback    to undo it now.
EOF
      ;;
    practice) cat <<EOF
PRACTICE MODE

In practice mode bond-manager does everything except change the server: you
go through the same questions and see the exact plan, and it stops there.
Nothing is written, no backup is taken, no network is touched.

- In the menus: press p (or pick "Practice mode") to switch it on or off.
  If you are not root it is always on.
- On the command line: add -n (or --dry-run), e.g.
    $BM_PROG -n swap-member bond0 --old ens1f0 --new ens2f0
EOF
      ;;
    moving) cat <<EOF
MOVING A SERVER TO A NEW SWITCH (NO OUTAGE)

A bond survives losing one cable, so you move one cable at a time:

  1. Plug a free port into the new switch.
  2. Swap it into the bond in place of one old port:
       $BM_PROG swap-member bond0 --old ens1f0 --new ens2f0
     bond-manager adds the new port, WAITS until it really works, and only
     then removes the old one. The bond is never short a leg.
  3. Keep the change, then repeat for the other cable.

LACP bonds (802.3ad): unless the old and new switches are one LACP group,
switch to active-backup for the move, then back:
       $BM_PROG modify bond0 --mode active-backup
       ...swap both cables...
       $BM_PROG modify bond0 --mode 802.3ad

In the menus: "Move a bond to a new switch" walks you through all of this.
EOF
      ;;
    glossary) cat <<EOF
WORDS YOU WILL SEE

bond           Several network ports acting as one connection (e.g. bond0).
port / member  One network card inside a bond (e.g. ens1f0). "Enslaved" is
               the kernel's word for "is a member".
NIC            Network interface card - a network port.
link           A working cable connection. "No link" = unplugged cable,
               broken cable, or a switch port that is off.
mode           How the bond uses its ports (see: $BM_PROG help modes).
LACP / 802.3ad A mode where server and switch agree to use all ports.
VLAN           A tagged network on top of the bond, e.g. bond0.120 = VLAN 120.
MTU            The largest packet size. 1500 is normal; 9000 = "jumbo frames"
               (only if every switch in the path allows it).
profile        A saved NetworkManager setting (what 'nmcli connection' lists).
snapshot       A backup copy of all saved network settings.
checkpoint     NetworkManager's own undo point; the strongest safety net.
commit / keep  Confirm a change so it is not undone.
rollback/undo  Put the network back the way it was.
drift          When the saved settings no longer match what the kernel runs.
EOF
      ;;
    keys) cat <<EOF
KEYS IN THE MENUS

  Up / Down (or k / j)   move
  Enter (or Right)       choose
  1-9                    choose item by number
  Esc, q (or Left)       go back
  Space                  tick / untick (lists with checkboxes)
  a / n                  tick all / none
  p                      practice mode on/off (main menu)
  r                      refresh (main menu)
  ?                      help (main menu)

While a change waits for you:  K = keep it,  U = undo it,  E = 5 more minutes

Plain mode (--plain, serial consoles): type the number and press Enter;
q goes back.
EOF
      ;;
    exit-codes) cat <<EOF
EXIT CODES (FOR SCRIPTS AND MONITORING)

  0   success, or nothing to do
  1   error
  2   usage error (something typed wrong)
  3   could not start (not root, NetworkManager down, bond missing, ...)
  4   another bond-manager is running
  5   the change failed its checks and was undone
      (also: 'commit' found the change already undone)
  6   applied but not confirmed yet (no terminal to ask on)
  10  status: at least one bond needs attention
  11  status: at least one bond is down
EOF
      ;;
    *) return 1 ;;
  esac
}

# ---- per-command help --------------------------------------------------------

bm::help::command() { # command <name> — rc 1 if unknown
  local c
  c="$(bm::help::canonical "$1")" || return 1
  local p="$BM_PROG"
  case "$c" in
    list) cat <<EOF
$p list - one line per bond: name, mode, health

Shows every bond on this server and whether it is healthy. Needs no root and
changes nothing.

Usage:
  $p list
  $p --json list          (machine-readable)

Examples:
  $p list

See also: $p status, $p show BOND
EOF
      ;;
    show) cat <<EOF
$p show - everything about one bond

Mode, health (with reasons), link monitoring, the active port, every member
with its link state and speed, addresses and VLANs. Read-only.

Usage:
  $p show BOND
  $p --json show BOND

Examples:
  $p show bond0

See also: $p diagnose BOND (deeper), $p list
EOF
      ;;
    status) cat <<EOF
$p status - health check, made for monitoring

Like 'show' for every bond (or one), and the exit code says how it went:
0 = all healthy, 10 = something needs attention, 11 = something is down.
Read-only; safe to run from cron or a monitoring agent.

Usage:
  $p status [BOND]
  $p --json status [BOND]

Examples:
  $p status
  $p status bond0 || echo "bond0 needs attention"

See also: $p help exit-codes
EOF
      ;;
    diagnose) cat <<EOF
$p diagnose - a closer look at one bond, for troubleshooting

Shows the kernel's own view of the bond, a plain health verdict, the link of
every port, LACP partner details (802.3ad), addresses, and a ping test
through the bond. --extended adds the saved profiles, driver details and the
recent NetworkManager log. Read-only.

Usage:
  $p diagnose BOND [--extended] [--target IP]

Examples:
  $p diagnose bond0
  $p diagnose bond0 --extended --target 10.0.0.1

See also: $p verify BOND, $p help lacp
EOF
      ;;
    verify) cat <<EOF
$p verify - re-run the safety checks against the bond as it is now

The same checks that run after every change: bond exists, is up, has the
right mode, members really are members, the gateway answers. Read-only.
Exit code 1 if a check fails.

Usage:
  $p verify BOND

Examples:
  $p verify bond0
EOF
      ;;
    doctor) cat <<EOF
$p doctor - is this server ready, and how well am I protected?

Checks that the tools bond-manager needs are present, that NetworkManager is
running, and which safety net changes will get (see: $p help safety).
Run it once on every new server. Read-only.

Usage:
  $p doctor
EOF
      ;;
    nics) cat <<EOF
$p nics - which network ports are there, and can I use them?

Lists every network port with its link state, speed, which bond it is in,
its addresses, and a plain note: "free - good to use", "no link - cable or
switch port?", "has an IP - probably in use", "carries your SSH connection".
Read-only; needs no root.

Usage:
  $p nics [--all]

  --all   also list ports the NIC policy hides (virtual devices etc.)

Examples:
  $p nics

See also: $p create, $p swap-member
EOF
      ;;
    config) cat <<EOF
$p config - show the settings in effect

Usage:
  $p config show     every setting and its current value
  $p config path     where the config file lives

The file ($BM_CONF) is read, never executed.
Create a commented default with 'sudo $p init'.
EOF
      ;;
    completion) cat <<EOF
$p completion - tab completion for bash

Usage:
  $p completion bash > /etc/bash_completion.d/bond-manager
EOF
      ;;
    help) cat <<EOF
$p help - explanations and examples

Usage:
  $p help            the overview
  $p help COMMAND    one command, with examples (= COMMAND --help)
  $p help TOPIC      a topic explained in plain words

Topics: ${BM_HELP_TOPICS[*]}

Examples:
  $p help swap-member
  $p help modes
EOF
      ;;
    create) cat <<EOF
$p create - build a new bond from free network ports

Joins two or more free ports into one bond, optionally with an IP address
and VLANs, then checks it really works.

Usage:
  $p create BOND --mode MODE --members IF1,IF2 [options]

  --mode MODE        active-backup (safe choice), 802.3ad (LACP), ...
                     see: $p help modes
  --members A,B      the ports to use (see: $p nics)
  --ip4 dhcp|none|ADDRESS/PREFIX   --gw4 GATEWAY   --dns4 A,B
  --ip6 auto|dhcp|none|ADDRESS/PREFIX  --gw6 GATEWAY  --dns6 A,B
  --vlan VID[:ip4=..;gw4=..]   add a VLAN (repeatable)
  --mtu N   --no-activate   --opt key=value (advanced)

Examples:
  $p -n create bond0 --mode active-backup \\
      --members ens1f0,ens1f1 --ip4 dhcp
  sudo $p create bond0 --mode 802.3ad --members ens1f0,ens1f1 \\
      --ip4 10.0.0.10/24 --gw4 10.0.0.1 --dns4 10.0.0.53

Good to know:
  - Pick free ports: '$p nics' marks them "free - good to use".
  - 802.3ad needs the switch ports set up as an LACP bundle first.
  - The whole change is undone automatically if you do not confirm it.
EOF
      ;;
    modify) cat <<EOF
$p modify - change an existing bond's mode, options, IP or MTU

Only what you name is changed; everything else stays as it is.

Usage:
  $p modify BOND [--mode MODE] [--opt K=V]... [--del-opt KEY]...
      [--ip4 ...] [--gw4 ...] [--dns4 ...] [--ip6 ...] [--mtu N]
  shortcuts: --miimon MS  --primary IF  --lacp-rate fast|slow
      --xmit-hash POLICY  --min-links N  --arp-interval MS --arp-targets IP

Examples:
  $p -n modify bond0 --mode active-backup
  sudo $p modify bond0 --primary ens1f0
  sudo $p modify bond0 --ip4 10.0.0.10/24 --gw4 10.0.0.1

Good to know:
  - Changing the mode drops options that only made sense in the old mode,
    and tells you which.
  - Changing the IP of the address you are logged in on will cut your
    session: open a new session to the new address and run
    'sudo $p commit' before the countdown ends.
EOF
      ;;
    add-member) cat <<EOF
$p add-member - add one or more ports to a bond

Usage:
  $p add-member BOND IF[,IF...]

Examples:
  $p -n add-member bond0 ens1f2
  sudo $p add-member bond0 ens1f2,ens1f3

Good to know:
  - The new port should be plugged in and have a link ('$p nics').
  - For 802.3ad, the switch port must join the same LACP bundle.
EOF
      ;;
    remove-member) cat <<EOF
$p remove-member - take one or more ports out of a bond

Usage:
  $p remove-member BOND IF[,IF...]

Examples:
  $p -n remove-member bond0 ens1f1
  sudo $p remove-member bond0 ens1f1

Good to know:
  - A bond with one port left still works, but has no spare.
  - Removing the LAST port takes the bond down; you are asked first.
  - To replace a port, use swap-member instead - it never leaves a gap.
EOF
      ;;
    swap-member) cat <<EOF
$p swap-member - replace a bond port with another, with no outage

The tool for moving a live server to a new switch, one cable at a time. It
adds the new port, WAITS until the kernel really uses it, and only then
removes the old one - so the bond is never short a leg.

Usage:
  $p swap-member BOND --old IF --new IF

Examples:
  $p -n swap-member bond0 --old ens1f0 --new ens2f0      (preview)
  sudo $p swap-member bond0 --old ens1f0 --new ens2f0
  sudo $p swap-member bond0 --old ens1f1 --new ens2f1

Good to know:
  - The new port must have a link before you start ('$p nics').
  - 802.3ad (LACP) across two separate switches will not aggregate; switch
    to active-backup for the move (see: $p help moving).
EOF
      ;;
    remove) cat <<EOF
$p remove - delete a bond and its saved settings

Deletes the bond's profile, its member profiles and (unless --keep-vlans)
its VLAN profiles. You are asked to type the bond name to confirm.

Usage:
  $p remove BOND [--keep-vlans]

Examples:
  $p -n remove bond1
  sudo $p remove bond1

Good to know:
  - Removing the bond your SSH session uses will disconnect you (the safety
    net then undoes it, if the server supports automatic undo).
EOF
      ;;
    vlan) cat <<EOF
$p vlan - add, change, remove or list VLANs on a bond

Usage:
  $p vlan add BOND VID[:ip4=ADDR/PREFIX;gw4=GW;dns4=DNS]
  $p vlan modify BOND VID [--ip4 ...] [--gw4 ...] [--ip6 ...]
  $p vlan remove BOND VID
  $p vlan list BOND

Examples:
  $p -n vlan add bond0 120
  sudo $p vlan add bond0 '120:ip4=10.20.30.40/24;gw4=10.20.30.1'
  sudo $p vlan remove bond0 120

Good to know:
  - The switch ports must carry the VLAN (tagged/trunk) for it to work.
  - Quote the VID:settings part - the ';' would otherwise end the command.
EOF
      ;;
    clone) cat <<EOF
$p clone - copy a bond's settings onto a new bond with other ports

Usage:
  $p clone SRC DST --members IF[,IF...] [--copy-ip] [--copy-vlans]

Examples:
  $p -n clone bond0 bond1 --members ens2f0,ens2f1
  sudo $p clone bond0 bond1 --members ens2f0,ens2f1 --copy-vlans

Good to know:
  - --copy-ip copies the IP too: two bonds with the same IP conflict, so
    only use it when the old bond is going away.
EOF
      ;;
    repair) cat <<EOF
$p repair - make the saved settings match what the bond really runs

Bonds drift: a port gets added by hand and never saved, or a saved port no
longer exists. The next reboot then brings the bond back wrong. repair
saves a profile for every real member that lacks one and deletes profiles
for ports that are no longer members.

Usage:
  $p repair BOND

Examples:
  $p -n repair bond0      (which way did it drift? changes nothing)
  sudo $p repair bond0
EOF
      ;;
    commit) cat <<EOF
$p commit - keep the last change (stop the automatic undo)

Normally you press K when asked. Use this from a NEW session when the
change cut your old one - for example after changing the IP you were
logged in on.

Usage:
  sudo $p commit

Exit code 5 means you were too late: the change had already been undone.
EOF
      ;;
    rollback) cat <<EOF
$p rollback - undo the last change now, or restore a backup copy

Usage:
  sudo $p rollback                    undo the change that is waiting
  sudo $p rollback --snapshot ID      restore a specific backup copy

Examples:
  $p snapshot list
  $p -n rollback --snapshot 20260101-120000   (what would change)
EOF
      ;;
    snapshot) cat <<EOF
$p snapshot - backup copies of all saved network settings

A snapshot is taken automatically before every change.

Usage:
  $p snapshot list              the copies there are
  $p snapshot diff ID           what restoring ID would change
  sudo $p snapshot create       take one now
  sudo $p snapshot restore [ID] restore one (default: the newest)
  sudo $p snapshot prune        keep only the newest $(bm::config::get MAX_BACKUPS)
EOF
      ;;
    bundle) cat <<EOF
$p bundle - collect everything support needs in one file

Usage:
  sudo $p bundle [--output PATH] [--redact]

  --redact   hide IP and MAC addresses (for tickets that leave the site)
EOF
      ;;
    init) cat <<EOF
$p init - install a commented default config and log rotation

Usage:
  sudo $p init

Writes $BM_CONF (if missing) and a logrotate policy.
Optional: without a config file the defaults are used.
EOF
      ;;
    tui) cat <<EOF
$p tui - the guided menus

The same as running $p with no arguments on a terminal. Every menu
explains itself, practice mode (key p) lets you try things safely, and each
change shows the command line that does the same thing.

Usage:
  sudo $p            (or: $p tui)
  $p --plain         numbered menus for serial consoles

See also: $p help keys
EOF
      ;;
    version) cat <<EOF
$p version - print the version (same as --version)
EOF
      ;;
  esac
  return 0
}

# ==== 50-ui.sh ====
# lib/50-ui.sh — the terminal toolkit: menus, checklists, text input, boxes
# and prompts, in pure bash (no whiptail, no dialog, nothing to install).
#
# Two modes, picked once by bm::ui::init:
#   fancy  a real terminal: arrow-key menus, colors, boxes, in-place redraw
#   plain  numbered prompts, 7-bit ASCII — serial consoles, --plain, pipes
#
# Contract for every widget: the answer goes into BM_UI_REPLY (and
# BM_UI_REPLY_LIST for multi-select), never through $(...) — widgets run in
# the caller's shell so terminal state and colors stay consistent. Return
# code 0 = answered, 1 = cancelled (Esc / q / back / Ctrl-C / end of input).
# On end of input BM_UI_EOF=1 is also set and every loop must stop.
#
# Everything is drawn on stderr and read from stdin, so stdout (plans,
# verification reports) stays in order and is never hidden behind a dialog.

BM_UI_MODE=""          # fancy | plain ("" = not yet initialised)
BM_UI_UTF8=0
BM_UI_ROWS=24
BM_UI_COLS=80
BM_UI_REPLY=""
BM_UI_REPLY_LIST=()
BM_UI_KEY=""
BM_UI_EOF=0
BM_UI_INTERRUPTED=0
BM_UI_RESIZED=0
BM_UI_DRAWN=0          # height of the block currently drawn in place
BM_UI_VERR=""          # a validator's own error message
BM_UI_SEL=0            # menu cursor (position among selectable items)
BM_UI_TOP=0            # menu viewport start (item index)
BM_UI_HDR=()           # lines a --header function fills in
BM_UI_HDR_MAX=0        # how many header lines fit (set before calling it)
BM_UI_LINES=()         # scratch: lines of a frame
BM_UI_WRAPPED=()
BM_UI_VLEN=0
BM_UI_FIT=""
BM_UI_FMT=""
BM_UI_ROW=""
BM_UI_W=80
BM_UI_CHECKED=0
BM_UI_RULE=""

# ---- setup ------------------------------------------------------------------

bm::ui::_fancy_capable() {
  [[ "${BM_PLAIN:-0}" != 1 ]] || return 1
  [[ -t 0 && -t 1 && -t 2 ]] || return 1
  case "${TERM:-}" in
    "" | dumb | unknown | vt52) return 1 ;;
  esac
  local tty
  tty="$(readlink "/proc/$$/fd/0" 2>/dev/null || true)"
  case "$tty" in
    /dev/ttyS* | /dev/ttyAMA* | /dev/ttyUSB* | /dev/hvc* | /dev/ttysclp*) return 1 ;;
  esac
  stty -g >/dev/null 2>&1 || return 1
  return 0
}

bm::ui::init() { # init [--force]
  if [[ -n "$BM_UI_MODE" && "${1:-}" != --force ]]; then
    return 0
  fi
  BM_UI_MODE=plain
  if bm::ui::_fancy_capable; then
    BM_UI_MODE=fancy
  fi
  BM_UI_UTF8=0
  if [[ "$BM_UI_MODE" == fancy && "${BM_ASCII:-0}" != 1 && "${TERM:-}" != linux ]]; then
    # A UTF-8 locale that is not actually installed leaves bash in "C",
    # where this is three bytes long — the glyphs would come out as junk.
    local t='●'
    if (( ${#t} == 1 )); then
      BM_UI_UTF8=1
    fi
  fi
  bm::ui::_glyphs
  bm::ui::_styles
  bm::ui::_size
  return 0
}

bm::ui::_ensure_init() {
  if [[ -z "$BM_UI_MODE" ]]; then
    bm::ui::init
  fi
  return 0
}

bm::ui::fancy() { [[ "$BM_UI_MODE" == fancy ]]; }

bm::ui::_glyphs() {
  if (( BM_UI_UTF8 )); then
    BM_G_H='─' BM_G_V='│' BM_G_TL='┌' BM_G_TR='┐' BM_G_BL='└' BM_G_BR='┘'
    BM_G_TEE='├─' BM_G_END='└─' BM_G_DOT='●' BM_G_ODOT='○' BM_G_OK='✔' BM_G_BAD='✖'
    BM_G_PTR='❯' BM_G_LARR='←' BM_G_UP='▲' BM_G_DN='▼' BM_G_SEP='·' BM_G_ELL='…'
    BM_G_WARN='!' BM_G_ON='[x]' BM_G_OFF='[ ]' BM_G_ARROW='›' BM_G_BAR='━'
  else
    BM_G_H='-' BM_G_V='|' BM_G_TL='+' BM_G_TR='+' BM_G_BL='+' BM_G_BR='+'
    BM_G_TEE='|-' BM_G_END='`-' BM_G_DOT='*' BM_G_ODOT='o' BM_G_OK='[ok]' BM_G_BAD='x'
    BM_G_PTR='>' BM_G_LARR='<-' BM_G_UP='^' BM_G_DN='v' BM_G_SEP='-' BM_G_ELL='~'
    BM_G_WARN='!' BM_G_ON='[x]' BM_G_OFF='[ ]' BM_G_ARROW='>' BM_G_BAR='='
  fi
}

# SGR sequences as plain variables, so building a frame never forks. Colors
# follow BM_COLOR (NO_COLOR, --no-color, TERM=dumb); in fancy mode bold,
# dim and reverse stay on without color — they are emphasis, not hue.
bm::ui::_styles() {
  local e=$'\033['
  BM_S_RST="" BM_S_BOLD="" BM_S_DIM="" BM_S_REV=""
  BM_S_RED="" BM_S_GREEN="" BM_S_YELLOW="" BM_S_CYAN=""
  BM_S_BADGE_LIVE="" BM_S_BADGE_PRACTICE=""
  if (( BM_COLOR )) || [[ "$BM_UI_MODE" == fancy ]]; then
    BM_S_RST="${e}0m" BM_S_BOLD="${e}1m" BM_S_DIM="${e}2m" BM_S_REV="${e}7m"
    BM_S_BADGE_LIVE="${e}1;7m" BM_S_BADGE_PRACTICE="${e}1;7m"
  fi
  if (( BM_COLOR )); then
    BM_S_RED="${e}31m" BM_S_GREEN="${e}32m" BM_S_YELLOW="${e}33m"
    BM_S_CYAN="${e}36m"
    BM_S_BADGE_LIVE="${e}1;97;41m" BM_S_BADGE_PRACTICE="${e}1;30;43m"
  fi
}

bm::ui::_size() {
  local r="" c="" sz=""
  if [[ -t 0 ]] && sz="$(stty size 2>/dev/null)"; then
    read -r r c <<<"$sz" || true
  fi
  if ! [[ "$r" =~ ^[0-9]+$ ]] || (( r < 8 )); then r="${LINES:-}"; fi
  if ! [[ "$c" =~ ^[0-9]+$ ]] || (( c < 20 )); then c="${COLUMNS:-}"; fi
  if ! [[ "$r" =~ ^[0-9]+$ ]] || (( r < 8 )); then r=24; fi
  if ! [[ "$c" =~ ^[0-9]+$ ]] || (( c < 20 )); then c=80; fi
  BM_UI_ROWS="$r"
  BM_UI_COLS="$c"
  return 0
}

bm::ui::width() { # usable width for boxes and wrapped text -> BM_UI_W
  local w=$(( BM_UI_COLS - 1 ))
  if (( w > 100 )); then w=100; fi
  if (( w < 30 )); then w=30; fi
  BM_UI_W="$w"
}

# ---- text helpers (pure; unit-testable) ------------------------------------

bm::ui::vlen() { # vlen <text> -> BM_UI_VLEN, visible characters (SGR ignored)
  local s="$1" re=$'\033\\[[0-9;]*m'
  while [[ "$s" =~ $re ]]; do
    s="${s/"${BASH_REMATCH[0]}"/}"
  done
  BM_UI_VLEN=${#s}
}

# Cut <text> to at most <width> visible characters, ending in an ellipsis when
# something was cut. Escape sequences are copied through untouched.
bm::ui::fit() { # fit <text> <width> -> BM_UI_FIT
  local s="$1" w="$2"
  bm::ui::vlen "$s"
  if (( BM_UI_VLEN <= w )); then
    BM_UI_FIT="$s"
    return 0
  fi
  local out="" i=0 n=${#s} ch count=0 seq
  while (( i < n && count < w - 1 )); do
    ch="${s:i:1}"
    if [[ "$ch" == $'\033' && "${s:i+1:1}" == "[" ]]; then
      seq="${s:i}"
      seq="${seq%%m*}m"
      out+="$seq"
      i=$(( i + ${#seq} ))
      continue
    fi
    out+="$ch"
    count=$(( count + 1 ))
    i=$(( i + 1 ))
  done
  BM_UI_FIT="$out$BM_G_ELL$BM_S_RST"
}

bm::ui::pad() { # pad <text> <width> -> BM_UI_FIT, fitted and right-padded
  bm::ui::fit "$1" "$2"
  bm::ui::vlen "$BM_UI_FIT"
  local gap=$(( $2 - BM_UI_VLEN ))
  if (( gap > 0 )); then
    printf -v BM_UI_FIT '%s%*s' "$BM_UI_FIT" "$gap" ""
  fi
}

bm::ui::fmt_secs() { # fmt_secs <seconds> -> BM_UI_FMT "m:ss"
  local s="$1"
  if (( s < 0 )); then s=0; fi
  printf -v BM_UI_FMT '%d:%02d' $(( s / 60 )) $(( s % 60 ))
}

# Word-wrap plain text into BM_UI_WRAPPED (one element per line).
bm::ui::wrap() { # wrap <width> <text>
  local w="$1" text="$2" line="" word
  BM_UI_WRAPPED=()
  local -a words=()
  read -r -a words <<<"$text" || true
  for word in "${words[@]}"; do
    while (( ${#word} > w )); do
      if [[ -n "$line" ]]; then
        BM_UI_WRAPPED+=("$line")
        line=""
      fi
      BM_UI_WRAPPED+=("${word:0:w}")
      word="${word:w}"
    done
    if [[ -z "$line" ]]; then
      line="$word"
    elif (( ${#line} + 1 + ${#word} <= w )); then
      line+=" $word"
    else
      BM_UI_WRAPPED+=("$line")
      line="$word"
    fi
  done
  if [[ -n "$line" || ${#BM_UI_WRAPPED[@]} -eq 0 ]]; then
    BM_UI_WRAPPED+=("$line")
  fi
}

# ---- output primitives --------------------------------------------------------

bm::ui::_out() { printf '%s\n' "$@" >&2; }

# Answers read from a pipe are not echoed by a terminal; echo them so a
# scripted session (or a test transcript) reads like a real one.
bm::ui::_echo_piped() {
  if [[ ! -t 0 ]]; then
    printf '%s\n' "$1" >&2
  fi
  return 0
}

bm::ui::clear() { # fresh screen (fancy) or a visual break (plain)
  bm::ui::_ensure_init
  BM_UI_DRAWN=0
  if bm::ui::fancy; then
    printf '\033[H\033[2J' >&2
  else
    printf '\n' >&2
  fi
}

bm::ui::_para() { # _para <indent> <style> <text> — wrapped paragraph
  local indent="$1" style="$2" text="$3" l
  bm::ui::width
  bm::ui::wrap $(( BM_UI_W - ${#indent} )) "$text"
  for l in "${BM_UI_WRAPPED[@]}"; do
    printf '%s%s%s%s\n' "$indent" "$style" "$l" "${style:+$BM_S_RST}" >&2
  done
}

bm::ui::heading() { # heading <title> [step info, e.g. "Step 2 of 5"]
  bm::ui::_ensure_init
  local t="$1" step="${2:-}"
  printf '\n' >&2
  if bm::ui::fancy; then
    printf '%s%s%s %s%s%s%s\n' "$BM_S_CYAN" "$BM_G_BAR$BM_G_BAR" "$BM_S_RST" \
      "$BM_S_BOLD" "$t" "$BM_S_RST" "${step:+  $BM_S_DIM$step$BM_S_RST}" >&2
  else
    printf '== %s%s ==\n' "$t" "${step:+ ($step)}" >&2
  fi
}

bm::ui::note() { bm::ui::_ensure_init; bm::ui::_para "  " "" "$*"; }
bm::ui::dim() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_DIM" "$*"; }
bm::ui::ok() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_GREEN" "$BM_G_OK $*"; }
bm::ui::warn() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_YELLOW" "$BM_G_WARN $*"; }
bm::ui::err() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_RED" "$BM_G_BAD $*"; }
bm::ui::info() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_CYAN" "$*"; }

# Print literal lines (command output, help text) indented, untouched.
bm::ui::block() { # block <text>
  local l
  while IFS= read -r l; do
    printf '  %s\n' "$l" >&2
  done <<<"$1"
}

# A bordered box. Lines are fitted to the width (never wrap).
bm::ui::box() { # box [--title T] [--badge B] [--style ok|warn|err|info] -- line...
  bm::ui::_ensure_init
  local title="" badge="" style=""
  while (( $# )); do
    case "$1" in
      --title) title="$2"; shift 2 ;;
      --badge) badge="$2"; shift 2 ;;
      --style) style="$2"; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  bm::ui::box_lines "$title" "$badge" "$style" "$@"
  printf '%s\n' "${BM_UI_LINES[@]}" >&2
}

# Build a box into BM_UI_LINES (so menus can embed it in their frame).
bm::ui::box_lines() { # box_lines <title> <badge> <style> line...
  local title="$1" badge="$2" style="$3"
  shift 3
  bm::ui::width
  local w="$BM_UI_W" bc="" inner l
  case "$style" in
    ok) bc="$BM_S_GREEN" ;;
    warn) bc="$BM_S_YELLOW" ;;
    err) bc="$BM_S_RED" ;;
    info) bc="$BM_S_CYAN" ;;
  esac
  inner=$(( w - 4 ))
  BM_UI_LINES=()
  # top border: ┌─ title ──── badge ─┐
  local top="$BM_G_TL$BM_G_H" used=2 rest
  if [[ -n "$title" ]]; then
    bm::ui::fit "$title" $(( inner - 12 ))
    top+=" $BM_S_RST$BM_S_BOLD$BM_UI_FIT$BM_S_RST$bc "
    bm::ui::vlen "$BM_UI_FIT"
    used=$(( used + BM_UI_VLEN + 2 ))
  fi
  local blen=0
  if [[ -n "$badge" ]]; then
    bm::ui::vlen "$badge"
    blen=$(( BM_UI_VLEN + 2 ))
  fi
  rest=$(( w - used - blen - 2 ))
  if (( rest < 1 )); then rest=1; fi
  local fill
  printf -v fill '%*s' "$rest" ""
  fill="${fill// /$BM_G_H}"
  top+="$fill"
  if [[ -n "$badge" ]]; then
    top+=" $BM_S_RST$badge$bc "
  fi
  top+="$BM_G_H$BM_G_TR"
  BM_UI_LINES+=("$bc$top$BM_S_RST")
  for l in "$@"; do
    bm::ui::pad "$l" "$inner"
    BM_UI_LINES+=("$bc$BM_G_V$BM_S_RST $BM_UI_FIT$BM_S_RST $bc$BM_G_V$BM_S_RST")
  done
  printf -v fill '%*s' $(( w - 2 )) ""
  fill="${fill// /$BM_G_H}"
  BM_UI_LINES+=("$bc$BM_G_BL$fill$BM_G_BR$BM_S_RST")
}

# Draw a block in place of the previous one (fancy): one printf per frame,
# relative cursor movement, every line fitted so nothing ever wraps.
bm::ui::_frame() { # _frame line...
  local out="" l
  local -i n=0
  bm::ui::width
  if (( BM_UI_DRAWN > 0 )); then
    out+=$'\r'$'\033['"${BM_UI_DRAWN}A"
  fi
  for l in "$@"; do
    bm::ui::fit "$l" $(( BM_UI_COLS - 1 ))
    out+=$'\r'"$BM_UI_FIT$BM_S_RST"$'\033[K\n'
    n=$(( n + 1 ))
  done
  out+=$'\033[J'
  printf '%s' "$out" >&2
  BM_UI_DRAWN=$n
}

bm::ui::_commit_block() { BM_UI_DRAWN=0; }

# ---- keyboard ---------------------------------------------------------------

bm::ui::_raw_on() {
  bm::ui::fancy || return 0
  if [[ -z "$BM_TTY_SAVED" ]]; then
    BM_TTY_SAVED="$(stty -g 2>/dev/null || true)"
  fi
  stty -echo -icanon min 1 time 0 2>/dev/null || true
  printf '\033[?25l' >&2
  BM_TTY_CURSOR_HIDDEN=1
}

bm::ui::_raw_off() { bm::core::term_restore; }

bm::ui::_drain() { # discard type-ahead so a stray key never answers a prompt
  bm::ui::fancy || return 0
  local _k
  while IFS= read -rsn1 -t 0.01 _k; do :; done
  return 0
}

# Read one key into BM_UI_KEY. Named keys: UP DOWN LEFT RIGHT HOME END PGUP
# PGDN DELETE ENTER SPACE TAB BACKSPACE ESC CTRL_U CTRL_D INTERRUPT RESIZE
# UNKNOWN; anything else is the character itself.
# rc: 0 key, 1 timeout, 2 end of input (BM_UI_EOF=1).
bm::ui::read_key() { # read_key [timeout-seconds]
  local t="${1:-}" k="" k2="" k3="" c="" seq="" rc=0
  BM_UI_KEY=""
  if [[ -n "$t" ]]; then
    IFS= read -rsn1 -t "$t" k || rc=$?
  else
    IFS= read -rsn1 k || rc=$?
  fi
  if (( rc > 128 )); then
    if (( BM_UI_INTERRUPTED )); then
      BM_UI_KEY=INTERRUPT
      return 0
    fi
    if (( BM_UI_RESIZED )); then
      BM_UI_KEY=RESIZE
      return 0
    fi
    return 1
  fi
  if (( rc != 0 )); then
    BM_UI_EOF=1
    BM_UI_KEY=EOF
    return 2
  fi
  case "$k" in
    "" | $'\r' | $'\n') BM_UI_KEY=ENTER ;;
    " ") BM_UI_KEY=SPACE ;;
    $'\t') BM_UI_KEY=TAB ;;
    $'\x7f' | $'\b') BM_UI_KEY=BACKSPACE ;;
    $'\x15') BM_UI_KEY=CTRL_U ;;
    $'\x04') BM_UI_KEY=CTRL_D ;;
    $'\033')
      if ! IFS= read -rsn1 -t 0.1 k2; then
        BM_UI_KEY=ESC
        return 0
      fi
      case "$k2" in
        "[" | O)
          if ! IFS= read -rsn1 -t 0.1 k3; then
            BM_UI_KEY=ESC
            return 0
          fi
          case "$k3" in
            A) BM_UI_KEY=UP ;;
            B) BM_UI_KEY=DOWN ;;
            C) BM_UI_KEY=RIGHT ;;
            D) BM_UI_KEY=LEFT ;;
            H) BM_UI_KEY=HOME ;;
            F) BM_UI_KEY=END ;;
            [0-9])
              seq="$k3"
              while IFS= read -rsn1 -t 0.1 c; do
                if [[ "$c" == "~" || "$c" == [A-Za-z] ]]; then
                  break
                fi
                seq+="$c"
                if (( ${#seq} > 6 )); then
                  break
                fi
              done
              case "$seq" in
                1 | 7) BM_UI_KEY=HOME ;;
                4 | 8) BM_UI_KEY=END ;;
                5) BM_UI_KEY=PGUP ;;
                6) BM_UI_KEY=PGDN ;;
                3) BM_UI_KEY=DELETE ;;
                *) BM_UI_KEY=UNKNOWN ;;
              esac
              ;;
            *) BM_UI_KEY=UNKNOWN ;;
          esac
          ;;
        *) BM_UI_KEY=ESC ;;
      esac
      ;;
    *) BM_UI_KEY="$k" ;;
  esac
  return 0
}

# ---- menu -------------------------------------------------------------------

# Pure cursor maths: move BM_UI_SEL among <count> selectable items.
bm::ui::_nav() { # _nav <key> <count> <page>
  local key="$1" count="$2" page="$3"
  if (( count <= 0 )); then
    BM_UI_SEL=0
    return 0
  fi
  case "$key" in
    UP | k) BM_UI_SEL=$(( (BM_UI_SEL - 1 + count) % count )) ;;
    DOWN | j | TAB) BM_UI_SEL=$(( (BM_UI_SEL + 1) % count )) ;;
    HOME | g) BM_UI_SEL=0 ;;
    END | G) BM_UI_SEL=$(( count - 1 )) ;;
    PGUP) BM_UI_SEL=$(( BM_UI_SEL - page )); if (( BM_UI_SEL < 0 )); then BM_UI_SEL=0; fi ;;
    PGDN) BM_UI_SEL=$(( BM_UI_SEL + page )); if (( BM_UI_SEL > count - 1 )); then BM_UI_SEL=$(( count - 1 )); fi ;;
  esac
  return 0
}

# Keep item <idx> inside a viewport of <vis> rows over <total> items.
bm::ui::_view() { # _view <idx> <total> <vis> [heading-above 0|1]
  local idx="$1" total="$2" vis="$3" head="${4:-0}"
  if (( idx < BM_UI_TOP )); then
    BM_UI_TOP=$idx
    if (( head && idx > 0 )); then BM_UI_TOP=$(( idx - 1 )); fi
  fi
  if (( idx >= BM_UI_TOP + vis )); then
    BM_UI_TOP=$(( idx - vis + 1 ))
  fi
  if (( BM_UI_TOP > total - vis )); then BM_UI_TOP=$(( total - vis )); fi
  if (( BM_UI_TOP < 0 )); then BM_UI_TOP=0; fi
  return 0
}

# Shared by menu and checklist: parse "TAG LABEL..." pairs.
bm::ui::_items() {
  _tags=()
  _labels=()
  _sel_idx=()
  local i=0
  while (( $# >= 2 )); do
    _tags+=("$1")
    _labels+=("$2")
    if [[ "$1" != "-" ]]; then
      _sel_idx+=("$i")
    fi
    i=$(( i + 1 ))
    shift 2
  done
}

# One item row for fancy frames: "  ❯ 1  Label   note" -> BM_UI_ROW
bm::ui::_item_row() { # _item_row <selected 0|1> <number-or-empty> <label> [mark]
  local selected="$1" num="$2" label="$3" mark="${4:-}" main note=""
  main="${label%%$'\t'*}"
  if [[ "$label" == *$'\t'* ]]; then
    note="${label#*$'\t'}"
  fi
  local ptr="  " numtxt="   "
  if [[ -n "$num" ]]; then
    printf -v numtxt '%-2s ' "$num"
  fi
  if (( selected )); then
    ptr="$BM_S_CYAN$BM_G_PTR$BM_S_RST "
    BM_UI_ROW=" $ptr$BM_S_DIM$numtxt$BM_S_RST$mark$BM_S_REV$BM_S_BOLD $main $BM_S_RST${note:+  $BM_S_DIM$note$BM_S_RST}"
  else
    BM_UI_ROW=" $ptr$BM_S_DIM$numtxt$BM_S_RST$mark $main ${note:+  $BM_S_DIM$note$BM_S_RST}"
  fi
}

# menu [--default TAG] [--header FN] [--refresh S] [--keys "p r ?"]
#      [--footer TEXT] -- TITLE TAG LABEL [TAG LABEL ...]
# A TAG of "-" is a non-selectable heading. LABEL may be "main<TAB>note".
# Keys listed in --keys return rc 0 with BM_UI_REPLY="key:<k>".
bm::ui::menu() {
  bm::ui::_ensure_init
  local def="" header="" refresh="" keys="" footer=""
  while (( $# )); do
    case "$1" in
      --default) def="$2"; shift 2 ;;
      --header) header="$2"; shift 2 ;;
      --refresh) refresh="$2"; shift 2 ;;
      --keys) keys="$2"; shift 2 ;;
      --footer) footer="$2"; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  local title="$1"
  shift
  local -a _tags=() _labels=() _sel_idx=()
  bm::ui::_items "$@"
  BM_UI_REPLY=""
  local count=${#_sel_idx[@]}
  if (( count == 0 )); then
    return 1
  fi
  BM_UI_SEL=0
  local p
  if [[ -n "$def" ]]; then
    for p in "${!_sel_idx[@]}"; do
      if [[ "${_tags[${_sel_idx[$p]}]}" == "$def" ]]; then
        BM_UI_SEL=$p
      fi
    done
  fi
  if bm::ui::fancy; then
    bm::ui::_menu_fancy
  else
    bm::ui::_menu_plain
  fi
}

bm::ui::_menu_plain() {
  local i n=0
  if [[ -n "$header" ]]; then
    BM_UI_HDR_MAX=40
    BM_UI_HDR=()
    "$header"
    if (( ${#BM_UI_HDR[@]} > 0 )); then
      printf '%s\n' "${BM_UI_HDR[@]}" >&2
    fi
  fi
  printf '\n%s%s%s\n' "$BM_S_BOLD" "$title" "$BM_S_RST" >&2
  for i in "${!_tags[@]}"; do
    if [[ "${_tags[$i]}" == "-" ]]; then
      printf '   %s\n' "${_labels[$i]}" >&2
      continue
    fi
    n=$(( n + 1 ))
    local main="${_labels[$i]%%$'\t'*}" note=""
    if [[ "${_labels[$i]}" == *$'\t'* ]]; then note="${_labels[$i]#*$'\t'}"; fi
    printf '  %2d) %s%s\n' "$n" "$main" "${note:+  ($note)}" >&2
  done
  local extra="" qword=back
  if [[ " $keys " == *" q "* ]]; then
    qword=quit
  fi
  printf '   q) %s\n' "${qword^}" >&2
  local k
  for k in $keys; do
    case "$k" in
      p) extra+="   p) practice on/off" ;;
      r) extra+="   r) refresh" ;;
      "?") extra+="   ?) help" ;;
    esac
  done
  if [[ -n "$extra" ]]; then
    printf '%s\n' "$extra" >&2
  fi
  local defnum=$(( BM_UI_SEL + 1 )) ans
  while :; do
    if [[ -n "$def" ]]; then
      printf 'Choose 1-%d [%d] (q = %s): ' "$count" "$defnum" "$qword" >&2
    else
      printf 'Choose 1-%d (q = %s): ' "$count" "$qword" >&2
    fi
    if ! IFS= read -r ans; then
      printf '\n' >&2
      BM_UI_EOF=1
      return 1
    fi
    bm::ui::_echo_piped "$ans"
    ans="${ans#"${ans%%[![:space:]]*}"}"
    ans="${ans%"${ans##*[![:space:]]}"}"
    if [[ -z "$ans" && -n "$def" ]]; then
      ans="$defnum"
    fi
    if [[ -n "$ans" && " $keys " == *" $ans "* ]]; then
      BM_UI_REPLY="key:$ans"
      return 0
    fi
    case "${ans,,}" in
      q | back | 0 | quit | exit) return 1 ;;
    esac
    if [[ "$ans" =~ ^[0-9]+$ ]] && (( ans >= 1 && ans <= count )); then
      BM_UI_SEL=$(( ans - 1 ))
      BM_UI_REPLY="${_tags[${_sel_idx[$BM_UI_SEL]}]}"
      return 0
    fi
    for i in "${_sel_idx[@]}"; do
      if [[ "${_tags[$i]}" == "$ans" ]]; then
        BM_UI_REPLY="$ans"
        return 0
      fi
    done
    printf '  Please type a number from 1 to %d (or q).\n' "$count" >&2
  done
}

# Build the frame for the current menu state into BM_UI_LINES.
bm::ui::_menu_lines() {
  local total=${#_tags[@]} i vis avail hdr_n
  BM_UI_LINES=()
  local -a hdr=()
  if [[ -n "$header" ]]; then
    # the choices come first: the header gets what the items leave over
    local want=$total half=$(( BM_UI_ROWS / 2 ))
    if (( half < 6 )); then half=6; fi
    if (( want > half )); then want=$half; fi
    BM_UI_HDR_MAX=$(( BM_UI_ROWS - 3 - want ))
    BM_UI_HDR=()
    "$header"
    hdr=("${BM_UI_HDR[@]}")
    BM_UI_LINES=() # the header may have used it as scratch space
  fi
  hdr_n=${#hdr[@]}
  avail=$(( BM_UI_ROWS - 1 - hdr_n - 3 ))
  vis=$total
  if (( vis > avail )); then
    vis=$(( avail - 2 ))
    if (( vis < 3 )); then vis=3; fi
  fi
  local cur=${_sel_idx[$BM_UI_SEL]} head=0
  if (( cur > 0 )) && [[ "${_tags[$((cur - 1))]}" == "-" ]]; then head=1; fi
  bm::ui::_view "$cur" "$total" "$vis" "$head"
  if (( hdr_n > 0 )); then
    BM_UI_LINES+=("${hdr[@]}")
  fi
  BM_UI_LINES+=("$BM_S_BOLD$title$BM_S_RST")
  if (( vis < total )); then
    if (( BM_UI_TOP > 0 )); then
      BM_UI_LINES+=("    $BM_S_DIM$BM_G_UP $BM_UI_TOP more$BM_S_RST")
    else
      BM_UI_LINES+=("")
    fi
  fi
  local end=$(( BM_UI_TOP + vis )) num p
  for ((i = BM_UI_TOP; i < end && i < total; i++)); do
    if [[ "${_tags[$i]}" == "-" ]]; then
      BM_UI_LINES+=("   $BM_S_DIM${_labels[$i]}$BM_S_RST")
      continue
    fi
    num=""
    for p in "${!_sel_idx[@]}"; do
      if (( _sel_idx[p] == i )); then
        if (( p < 9 )); then num=$(( p + 1 )); fi
        break
      fi
    done
    bm::ui::_item_row $(( i == cur )) "$num" "${_labels[$i]}"
    BM_UI_LINES+=("$BM_UI_ROW")
  done
  if (( vis < total )); then
    if (( end < total )); then
      BM_UI_LINES+=("    $BM_S_DIM$BM_G_DN $(( total - end )) more$BM_S_RST")
    else
      BM_UI_LINES+=("")
    fi
  fi
  local hint="$BM_G_UP$BM_G_DN move $BM_G_SEP Enter choose $BM_G_SEP 1-9 jump $BM_G_SEP Esc back"
  if [[ -n "$footer" ]]; then
    hint="$footer"
  fi
  BM_UI_LINES+=(" $BM_S_DIM$hint$BM_S_RST")
}

bm::ui::_menu_fancy() {
  local cur rc redraw=1
  BM_UI_TOP=0
  BM_UI_DRAWN=0
  bm::ui::_raw_on
  while :; do
    if (( redraw )); then
      bm::ui::_menu_lines
      bm::ui::_frame "${BM_UI_LINES[@]}"
    fi
    redraw=1
    rc=0
    bm::ui::read_key "${refresh:-1}" || rc=$?
    if (( rc == 2 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      BM_UI_EOF=1
      return 1
    fi
    if (( rc == 1 )); then
      # timeout: only a live header (countdown, --refresh) needs a redraw
      if [[ -z "$refresh" ]]; then redraw=0; fi
      continue
    fi
    case "$BM_UI_KEY" in
      RESIZE)
        BM_UI_RESIZED=0
        bm::ui::_size
        printf '\033[H\033[2J' >&2
        BM_UI_DRAWN=0
        continue
        ;;
      INTERRUPT)
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 1
        ;;
    esac
    if [[ ${#BM_UI_KEY} == 1 && " $keys " == *" $BM_UI_KEY "* ]]; then
      bm::ui::_raw_off
      bm::ui::_commit_block
      BM_UI_REPLY="key:$BM_UI_KEY"
      return 0
    fi
    case "$BM_UI_KEY" in
      ENTER | RIGHT | l | SPACE)
        cur=${_sel_idx[$BM_UI_SEL]}
        BM_UI_REPLY="${_tags[$cur]}"
        bm::ui::_frame "$BM_S_DIM$title$BM_S_RST $BM_G_ARROW ${_labels[$cur]%%$'\t'*}"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 0
        ;;
      [1-9])
        if (( BM_UI_KEY <= count )); then
          BM_UI_SEL=$(( BM_UI_KEY - 1 ))
          cur=${_sel_idx[$BM_UI_SEL]}
          BM_UI_REPLY="${_tags[$cur]}"
          bm::ui::_frame "$BM_S_DIM$title$BM_S_RST $BM_G_ARROW ${_labels[$cur]%%$'\t'*}"
          bm::ui::_raw_off
          bm::ui::_commit_block
          return 0
        fi
        ;;
      ESC | q | Q | LEFT | h | BACKSPACE | CTRL_D)
        bm::ui::_frame "$BM_S_DIM$title $BM_G_ARROW (back)$BM_S_RST"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 1
        ;;
      *)
        bm::ui::_nav "$BM_UI_KEY" "$count" 8
        ;;
    esac
  done
}

# ---- checklist ----------------------------------------------------------------

# checklist [--min N] [--max N] [--on TAG,TAG] [--header FN] -- TITLE TAG LABEL...
# Result: BM_UI_REPLY_LIST (tags, in list order), BM_UI_REPLY (comma-joined).
bm::ui::checklist() {
  bm::ui::_ensure_init
  local min=1 max=0 on="" header="" footer=""
  while (( $# )); do
    case "$1" in
      --min) min="$2"; shift 2 ;;
      --max) max="$2"; shift 2 ;;
      --on) on="$2"; shift 2 ;;
      --header) header="$2"; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  local title="$1"
  shift
  local -a _tags=() _labels=() _sel_idx=() _chk=()
  bm::ui::_items "$@"
  local count=${#_sel_idx[@]} i p
  (( count > 0 )) || return 1
  if (( max <= 0 || max > count )); then max=$count; fi
  for i in "${!_tags[@]}"; do
    _chk[i]=0
    if [[ ",$on," == *",${_tags[$i]},"* ]]; then _chk[i]=1; fi
  done
  BM_UI_REPLY=""
  BM_UI_REPLY_LIST=()
  BM_UI_SEL=0
  local rc=0
  if bm::ui::fancy; then
    bm::ui::_check_fancy || rc=$?
  else
    bm::ui::_check_plain || rc=$?
  fi
  (( rc == 0 )) || return "$rc"
  for p in "${_sel_idx[@]}"; do
    if (( _chk[p] )); then
      BM_UI_REPLY_LIST+=("${_tags[$p]}")
    fi
  done
  BM_UI_REPLY="$(bm::core::join , "${BM_UI_REPLY_LIST[@]}")"
  return 0
}

bm::ui::_check_count() {
  local p n=0
  for p in "${_sel_idx[@]}"; do
    if (( _chk[p] )); then n=$(( n + 1 )); fi
  done
  BM_UI_CHECKED=$n
}

bm::ui::_check_rule() { # the min/max rule in words
  if (( min == max )); then
    BM_UI_RULE="pick exactly $min"
  elif (( max >= count )); then
    BM_UI_RULE="pick at least $min"
  else
    BM_UI_RULE="pick $min to $max"
  fi
}

bm::ui::_check_plain() {
  local ans tok n i p ok
  bm::ui::_check_rule
  while :; do
    printf '\n%s%s%s  (%s)\n' "$BM_S_BOLD" "$title" "$BM_S_RST" "$BM_UI_RULE" >&2
    n=0
    for i in "${!_tags[@]}"; do
      if [[ "${_tags[$i]}" == "-" ]]; then
        printf '   %s\n' "${_labels[$i]}" >&2
        continue
      fi
      n=$(( n + 1 ))
      local mark="$BM_G_OFF" main="${_labels[$i]%%$'\t'*}" note=""
      if (( _chk[i] )); then mark="$BM_G_ON"; fi
      if [[ "${_labels[$i]}" == *$'\t'* ]]; then note="${_labels[$i]#*$'\t'}"; fi
      printf '  %2d) %s %s%s\n' "$n" "$mark" "$main" "${note:+  ($note)}" >&2
    done
    bm::ui::_check_count
    if (( BM_UI_CHECKED > 0 )); then
      printf 'Type the numbers to pick, e.g. 1 2 (Enter = keep ticked, q = back): ' >&2
    else
      printf 'Type the numbers to pick, e.g. 1 2 (q = back): ' >&2
    fi
    if ! IFS= read -r ans; then
      printf '\n' >&2
      BM_UI_EOF=1
      return 1
    fi
    bm::ui::_echo_piped "$ans"
    case "${ans,,}" in
      q | back) return 1 ;;
    esac
    if [[ -n "${ans//[[:space:],]/}" ]]; then
      local -a newchk=()
      for i in "${!_tags[@]}"; do newchk[i]=0; done
      ok=1
      local -a toks=()
      read -r -a toks <<<"${ans//,/ }" || true
      for tok in "${toks[@]}"; do
        local found=0
        if [[ "$tok" =~ ^[0-9]+$ ]] && (( tok >= 1 && tok <= count )); then
          newchk[${_sel_idx[$((tok - 1))]}]=1
          found=1
        else
          for p in "${_sel_idx[@]}"; do
            if [[ "${_tags[$p]}" == "$tok" ]]; then
              newchk[p]=1
              found=1
            fi
          done
        fi
        if (( ! found )); then
          printf '  "%s" is not on the list - use the numbers shown.\n' "$tok" >&2
          ok=0
        fi
      done
      (( ok )) || continue
      _chk=("${newchk[@]}")
    fi
    bm::ui::_check_count
    if (( BM_UI_CHECKED < min || BM_UI_CHECKED > max )); then
      printf '  Please %s.\n' "$BM_UI_RULE" >&2
      continue
    fi
    return 0
  done
}

bm::ui::_check_fancy() {
  local total=${#_tags[@]} vis i num p cur rc msg=""
  bm::ui::_check_rule
  BM_UI_TOP=0
  BM_UI_DRAWN=0
  bm::ui::_raw_on
  while :; do
    BM_UI_LINES=()
    local -a hdr=()
    if [[ -n "$header" ]]; then
      BM_UI_HDR_MAX=6
      BM_UI_HDR=()
      "$header"
      hdr=("${BM_UI_HDR[@]}")
    fi
    vis=$(( BM_UI_ROWS - 6 - ${#hdr[@]} ))
    if (( vis > total )); then vis=$total; fi
    if (( vis < 3 )); then vis=3; fi
    cur=${_sel_idx[$BM_UI_SEL]}
    bm::ui::_view "$cur" "$total" "$vis"
    local -a frame=()
    if (( ${#hdr[@]} > 0 )); then frame+=("${hdr[@]}"); fi
    bm::ui::_check_count
    frame+=("$BM_S_BOLD$title$BM_S_RST  $BM_S_DIM($BM_UI_RULE; $BM_UI_CHECKED picked)$BM_S_RST")
    if (( vis < total )); then
      if (( BM_UI_TOP > 0 )); then frame+=("    $BM_S_DIM$BM_G_UP $BM_UI_TOP more$BM_S_RST"); else frame+=(""); fi
    fi
    for ((i = BM_UI_TOP; i < BM_UI_TOP + vis && i < total; i++)); do
      if [[ "${_tags[$i]}" == "-" ]]; then
        frame+=("   $BM_S_DIM${_labels[$i]}$BM_S_RST")
        continue
      fi
      num=""
      for p in "${!_sel_idx[@]}"; do
        if (( _sel_idx[p] == i )); then
          if (( p < 9 )); then num=$(( p + 1 )); fi
          break
        fi
      done
      local mark="$BM_G_OFF"
      if (( _chk[i] )); then mark="$BM_S_GREEN$BM_G_ON$BM_S_RST"; fi
      bm::ui::_item_row $(( i == cur )) "$num" "${_labels[$i]}" "$mark"
      frame+=("$BM_UI_ROW")
    done
    if (( vis < total )); then
      if (( BM_UI_TOP + vis < total )); then
        frame+=("    $BM_S_DIM$BM_G_DN $(( total - BM_UI_TOP - vis )) more$BM_S_RST")
      else
        frame+=("")
      fi
    fi
    if [[ -n "$msg" ]]; then
      frame+=(" $BM_S_YELLOW$BM_G_WARN $msg$BM_S_RST")
    else
      frame+=(" $BM_S_DIM""Space tick $BM_G_SEP 1-9 tick $BM_G_SEP a all $BM_G_SEP n none $BM_G_SEP Enter done $BM_G_SEP Esc back$BM_S_RST")
    fi
    bm::ui::_frame "${frame[@]}"
    msg=""
    rc=0
    bm::ui::read_key 1 || rc=$?
    if (( rc == 2 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      return 1
    fi
    (( rc == 0 )) || continue
    case "$BM_UI_KEY" in
      RESIZE)
        BM_UI_RESIZED=0
        bm::ui::_size
        printf '\n' >&2
        BM_UI_DRAWN=0
        ;;
      SPACE | x)
        _chk[cur]=$(( 1 - _chk[cur] ))
        ;;
      [1-9])
        if (( BM_UI_KEY <= count )); then
          BM_UI_SEL=$(( BM_UI_KEY - 1 ))
          p=${_sel_idx[$BM_UI_SEL]}
          _chk[p]=$(( 1 - _chk[p] ))
        fi
        ;;
      a | A)
        for p in "${_sel_idx[@]}"; do _chk[p]=1; done
        ;;
      n | N)
        for p in "${_sel_idx[@]}"; do _chk[p]=0; done
        ;;
      ENTER | RIGHT)
        bm::ui::_check_count
        if (( BM_UI_CHECKED < min || BM_UI_CHECKED > max )); then
          msg="Please $BM_UI_RULE (Space ticks the highlighted line)."
          continue
        fi
        local picked=""
        for p in "${_sel_idx[@]}"; do
          if (( _chk[p] )); then picked+="${picked:+, }${_tags[$p]}"; fi
        done
        bm::ui::_frame "$BM_S_DIM$title$BM_S_RST $BM_G_ARROW $picked"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 0
        ;;
      ESC | q | Q | LEFT | CTRL_D | INTERRUPT)
        bm::ui::_frame "$BM_S_DIM$title $BM_G_ARROW (back)$BM_S_RST"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 1
        ;;
      *)
        bm::ui::_nav "$BM_UI_KEY" "$count" 8
        ;;
    esac
  done
}

# ---- text input ---------------------------------------------------------------

# input [--default V] [--validate FN] [--error MSG] [--example EX] [--optional]
#       -- PROMPT
# FN "<value>" returns 0 when acceptable; it may set BM_UI_VERR to explain.
bm::ui::input() {
  bm::ui::_ensure_init
  local def="" validate="" errmsg="" example="" optional=0
  while (( $# )); do
    case "$1" in
      --default) def="$2"; shift 2 ;;
      --validate) validate="$2"; shift 2 ;;
      --error) errmsg="$2"; shift 2 ;;
      --example) example="$2"; shift 2 ;;
      --optional) optional=1; shift ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  local prompt="$1"
  BM_UI_REPLY=""
  if bm::ui::fancy; then
    bm::ui::_input_fancy
  else
    bm::ui::_input_plain
  fi
}

# Shared acceptance check: sets _why when the value is refused.
bm::ui::_input_ok() { # _input_ok <value>
  local v="$1"
  _why=""
  if [[ -z "$v" ]]; then
    if (( optional )); then return 0; fi
    _why="Please type something (or go back)."
    return 1
  fi
  if [[ -n "$validate" ]]; then
    BM_UI_VERR=""
    if ! "$validate" "$v"; then
      _why="${BM_UI_VERR:-${errmsg:-That does not look right.}}"
      if [[ -n "$example" ]]; then
        _why+=" Example: $example"
      fi
      return 1
    fi
  fi
  return 0
}

bm::ui::_input_plain() {
  local v _why
  if [[ -n "$example" ]]; then
    printf '  (example: %s)\n' "$example" >&2
  fi
  while :; do
    if [[ -n "$def" ]]; then
      printf '%s [%s]: ' "$prompt" "$def" >&2
    elif (( optional )); then
      printf '%s (Enter = none): ' "$prompt" >&2
    else
      printf '%s: ' "$prompt" >&2
    fi
    if ! IFS= read -r v; then
      printf '\n' >&2
      BM_UI_EOF=1
      return 1
    fi
    bm::ui::_echo_piped "$v"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    case "$v" in
      q | back) return 1 ;;
    esac
    if [[ -z "$v" ]]; then v="$def"; fi
    if bm::ui::_input_ok "$v"; then
      BM_UI_REPLY="$v"
      return 0
    fi
    printf '  %s\n' "$_why" >&2
  done
}

bm::ui::_input_fancy() {
  local buf="$def" rc _why="" shown
  BM_UI_DRAWN=0
  bm::ui::_raw_on
  while :; do
    local -a frame=("$BM_S_BOLD$prompt$BM_S_RST")
    shown="$buf"
    if (( ${#buf} > BM_UI_COLS - 8 )); then
      shown="$BM_G_ELL${buf: -$(( BM_UI_COLS - 10 ))}"
    fi
    frame+=("  $BM_S_CYAN$BM_G_ARROW$BM_S_RST $shown$BM_S_REV $BM_S_RST")
    if [[ -n "$_why" ]]; then
      frame+=("  $BM_S_RED$BM_G_BAD $_why$BM_S_RST")
    elif [[ -n "$example" ]]; then
      frame+=("  $BM_S_DIM""example: $example $BM_G_SEP Enter OK $BM_G_SEP Esc back$BM_S_RST")
    else
      frame+=("  $BM_S_DIM""Enter OK $BM_G_SEP Esc back$BM_S_RST")
    fi
    bm::ui::_frame "${frame[@]}"
    rc=0
    bm::ui::read_key 1 || rc=$?
    if (( rc == 2 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      return 1
    fi
    (( rc == 0 )) || continue
    case "$BM_UI_KEY" in
      ENTER)
        buf="${buf#"${buf%%[![:space:]]*}"}"
        buf="${buf%"${buf##*[![:space:]]}"}"
        if bm::ui::_input_ok "$buf"; then
          BM_UI_REPLY="$buf"
          bm::ui::_frame "$BM_S_DIM$prompt$BM_S_RST $BM_G_ARROW ${buf:-(none)}"
          bm::ui::_raw_off
          bm::ui::_commit_block
          return 0
        fi
        ;;
      ESC | CTRL_D | INTERRUPT)
        bm::ui::_frame "$BM_S_DIM$prompt $BM_G_ARROW (back)$BM_S_RST"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 1
        ;;
      BACKSPACE)
        buf="${buf%?}"
        _why=""
        ;;
      CTRL_U)
        buf=""
        _why=""
        ;;
      SPACE)
        buf+=" "
        _why=""
        ;;
      RESIZE)
        BM_UI_RESIZED=0
        bm::ui::_size
        ;;
      *)
        if (( ${#BM_UI_KEY} == 1 )) && [[ "$BM_UI_KEY" == [[:print:]] ]]; then
          buf+="$BM_UI_KEY"
          _why=""
        fi
        ;;
    esac
  done
}

# ---- prompts ------------------------------------------------------------------

# yesno [--default y|n] <question> -> 0 yes / 1 no. Always a typed line
# (y + Enter): one stray keypress must never apply a plan. The plain path is
# byte-for-byte the historical behavior scripts and tests rely on.
bm::ui::yesno() {
  local def=n
  if [[ "${1:-}" == --default ]]; then
    def="${2:-n}"
    shift 2
  fi
  local msg="$1"
  if (( BM_ASSUME_YES )); then
    return 0
  fi
  bm::ui::_ensure_init
  local ans="" hint="[y/N]"
  if [[ "$def" == y ]]; then hint="[Y/n]"; fi
  if bm::ui::fancy; then
    bm::ui::_drain
    if ! read -r -p "$BM_S_BOLD$msg$BM_S_RST $hint: " ans; then
      return 1
    fi
  elif [[ "$def" == y ]]; then
    if ! read -r -p "$msg $hint: " ans; then
      return 1
    fi
  else
    read -r -p "$msg [y/N]: " ans || true
  fi
  if [[ -z "$ans" && "$def" == y ]]; then
    return 0
  fi
  [[ "${ans,,}" == y || "${ans,,}" == yes ]]
}

bm::ui::confirm_exact() { # require typing an exact string (destructive ops)
  local what="$1" expected="$2"
  if (( BM_ASSUME_YES )); then
    return 0
  fi
  bm::ui::_ensure_init
  bm::ui::note "This cannot be undone with a key press. To be sure it is not a slip of the finger, type the name exactly as shown."
  if ! bm::ui::input -- "Type '$expected' to confirm $what"; then
    return 1
  fi
  [[ "$BM_UI_REPLY" == "$expected" ]]
}

bm::ui::pause() { # pause [prompt]
  bm::ui::_ensure_init
  local prompt="${1:-Press Enter to go back}" _l rc
  if bm::ui::fancy; then
    printf '%s%s%s' "$BM_S_DIM" "$prompt" "$BM_S_RST" >&2
    bm::ui::_raw_on
    while :; do
      rc=0
      bm::ui::read_key 1 || rc=$?
      if (( rc == 2 )); then break; fi
      (( rc == 0 )) || continue
      case "$BM_UI_KEY" in
        ENTER | ESC | SPACE | q | Q | INTERRUPT | CTRL_D | LEFT) break ;;
      esac
    done
    bm::ui::_raw_off
    printf '\r\033[K' >&2
  else
    printf '%s... ' "$prompt" >&2
    if ! IFS= read -r _l; then
      BM_UI_EOF=1
    fi
    printf '\n' >&2

  fi
  return 0
}

bm::ui::msg() { # msg <text> — show text, then wait for Enter
  bm::ui::_ensure_init
  printf '\n%b\n\n' "$1" >&2
  bm::ui::pause
}

# ---- commit gate ------------------------------------------------------------

bm::ui::gate_intro() { # gate_intro <tier>
  bm::ui::_ensure_init
  local tier="$1"
  local -a lines=("$BM_S_GREEN$BM_G_OK All checks passed - your change is live.$BM_S_RST" "")
  if [[ "$tier" == snapshot ]]; then
    lines+=("Nothing will undo it automatically on this server."
      "  K  keep it       U  undo it now (restore the backup copy)")
  else
    lines+=("If you do nothing, it is UNDONE automatically when the time runs out."
      "That is the safety net: if this change cut your connection, just wait.")
    lines+=("")
    if [[ "$tier" == checkpoint ]]; then
      lines+=("  K  keep it       U  undo it now       E  5 more minutes")
    else
      lines+=("  K  keep it       U  undo it now")
    fi
  fi
  printf '\n' >&2
  bm::ui::box --title "Keep this change?" --style ok -- "${lines[@]}"
  BM_UI_DRAWN=0
}

bm::ui::gate_status() { # gate_status <seconds-left> <tier> [message]
  local left="$1" tier="$2" m="${3:-}" col="$BM_S_GREEN" ext="" note=""
  if [[ "$tier" == checkpoint ]]; then ext="  [E]+5 min"; fi
  if [[ -n "$m" ]]; then note="  $BM_S_YELLOW$m$BM_S_RST"; fi
  if [[ "$tier" == snapshot ]]; then
    bm::ui::_frame "$BM_S_BOLD""Keep this change?$BM_S_RST  [K]eep  [U]ndo" "$note"
    return 0
  fi
  bm::ui::fmt_secs "$left"
  if (( left <= 20 )); then
    col="$BM_S_RED"
  elif (( left <= 60 )); then
    col="$BM_S_YELLOW"
  fi
  bm::ui::_frame "$BM_S_BOLD""Keep this change?$BM_S_RST  [K]eep  [U]ndo$ext   Auto-undo in $col$BM_S_BOLD$BM_UI_FMT$BM_S_RST" "$note"
}

# ==== 60-plan.sh ====
# lib/60-plan.sh — the transaction engine.
# Workflows BUILD a plan (ordered steps of description + argv); the engine
# renders it (that rendering IS --dry-run: nothing else happens), then
# snapshot → arm protection → execute → verify → commit-or-rollback.
# A single flock serializes all mutating invocations.

# ---- lock -----------------------------------------------------------------

BM_LOCK_FD=""
bm::lock::acquire() {
  mkdir -p "$BM_RUN_DIR"
  local fd
  exec {fd}>"$BM_RUN_DIR/lock"
  if ! flock -n "$fd"; then
    local holder=""
    holder="$(cat "$BM_RUN_DIR/lockinfo" 2>/dev/null || true)"
    bm::core::die "another $BM_PROG instance is running${holder:+ ($holder)}" "$BM_EX_LOCKED"
  fi
# shellcheck disable=SC2034  # the fd variable pins the lock open for our lifetime
  BM_LOCK_FD="$fd"
  printf 'pid=%s cmd=%s started=%s\n' "$$" "${BM_LOG_OP:-?}" "$(bm::core::timestamp)" \
    >"$BM_RUN_DIR/lockinfo" 2>/dev/null || true
}

# ---- plan model -----------------------------------------------------------

BM_PLAN_DESCS=()
BM_PLAN_CMDS=()

# How the last apply ended, in one word, for the menus to explain:
# noop | dry-run | cancelled | committed | rolled-back | expired | pending | lost
BM_PLAN_OUTCOME=""

bm::plan::reset() {
  BM_PLAN_DESCS=()
  BM_PLAN_CMDS=()
}

bm::plan::add() { # add <description> <argv...>
  local desc="$1"
  shift
  local q
  printf -v q '%q ' "$@"
  BM_PLAN_DESCS+=("$desc")
  BM_PLAN_CMDS+=("$q")
}

bm::plan::size() { printf '%s' "${#BM_PLAN_DESCS[@]}"; }

bm::plan::render() { # human-readable plan
  local i
  if (( ${#BM_PLAN_DESCS[@]} == 0 )); then
    echo "No changes required — system already matches the requested state."
    return 0
  fi
  echo "Plan:"
  for i in "${!BM_PLAN_DESCS[@]}"; do
    printf '  %2d. %s\n' "$((i + 1))" "${BM_PLAN_DESCS[$i]}"
    printf '      $ %s\n' "$(bm::plan::_pretty_cmd "${BM_PLAN_CMDS[$i]}")"
  done
}

# Shell-quote a value for display, but only when it needs it — a plan full of
# backslash-escaped commas is unreadable. The plan is advertised as commands
# an operator can run by hand, so anything a shell would interpret (a profile
# name containing $(...), a semicolon, whitespace) must come out inert.
bm::plan::_shq() {
  local v="$1"
  if [[ "$v" =~ ^[A-Za-z0-9_@%+=:,./-]*$ ]]; then
    printf '%s' "$v"
  else
    printf "'%s'" "${v//\'/\'\\\'\'}"
  fi
}

# Quote every argument of the remaining positional parameters.
bm::plan::_shq_all() {
  local out="" a
  for a in "$@"; do
    [[ -n "$out" ]] && out+=" "
    out+="$(bm::plan::_shq "$a")"
  done
  printf '%s' "$out"
}

# Translate internal step commands into the nmcli invocations they perform,
# so a rendered plan reads as commands an operator could run by hand.
bm::plan::_pretty_cmd() {
  local cmd="${1% }"
  eval "set -- $cmd"
  case "$1" in
    bm::nm::run) shift; printf 'nmcli %s' "$(bm::plan::_shq_all "$@")" ;;
    bm::nm::add_bond)
      printf 'nmcli connection add type bond con-name %s ifname %s bond.options %s ipv4.method disabled ipv6.method ignore' \
        "$(bm::plan::_shq "$2")" "$(bm::plan::_shq "$2")" "$(bm::plan::_shq "$3")" ;;
    bm::nm::add_port)
      printf 'nmcli connection add type ethernet con-name bond-port-%s ifname %s master %s slave-type bond' \
        "$(bm::plan::_shq "$3")" "$(bm::plan::_shq "$3")" "$(bm::plan::_shq "$2")" ;;
    bm::nm::add_vlan)
      printf 'nmcli connection add type vlan con-name %s ifname %s vlan.parent %s vlan.id %s ipv4.method disabled ipv6.method ignore' \
        "$(bm::plan::_shq "$2.$3")" "$(bm::plan::_shq "$2.$3")" "$(bm::plan::_shq "$2")" "$(bm::plan::_shq "$3")" ;;
    bm::nm::modify) shift; printf 'nmcli connection modify %s' "$(bm::plan::_shq_all "$@")" ;;
    bm::nm::up) printf 'nmcli connection up %s' "$(bm::plan::_shq "$2")" ;;
    bm::nm::down) printf 'nmcli connection down %s' "$(bm::plan::_shq "$2")" ;;
    bm::nm::delete) printf 'nmcli connection delete %s' "$(bm::plan::_shq "$2")" ;;
    bm::plan::await_member)
      printf '(wait until %s is enslaved to %s)' "$(bm::plan::_shq "$3")" "$(bm::plan::_shq "$2")" ;;
    *) shift; printf '%s' "$(bm::plan::_shq_all "$@")" ;;
  esac
}

# Step helper usable inside plans: wait until a NIC shows up as a member.
bm::plan::await_member() { # await_member <bond> <nic>
  bm::verify::_settle bm::verify::_member_enslaved "$1" "$2"
}

# Run all steps. Step stdout is routed to stderr so callers can capture this
# function's own output: on failure it prints the failing 0-based step index.
# shellcheck disable=SC2120  # positional params are set via `eval set --`
bm::plan::execute() {
  local i cmd
  for i in "${!BM_PLAN_CMDS[@]}"; do
    cmd="${BM_PLAN_CMDS[$i]}"
    bm::log::info "step $((i + 1))/${#BM_PLAN_CMDS[@]}: ${BM_PLAN_DESCS[$i]}"
    bm::log::say "  [$((i + 1))/${#BM_PLAN_CMDS[@]}] ${BM_PLAN_DESCS[$i]}"
    eval "set -- $cmd"
    if ! "$@" 1>&2; then
      bm::log::error "step $((i + 1)) failed: ${BM_PLAN_DESCS[$i]}"
      printf '%s\n' "$i"
      return 1
    fi
  done
  return 0
}

# ---- SSH egress guard -----------------------------------------------------

# Warn (when checkpoint-protected) or refuse if the change touches the
# device this SSH session rides on. affected devices: bond, members, VLANs.
# Returns 0 = proceed, 1 = refuse (reason already printed). Callers decide
# how to abort so protection armed in the meantime can be disarmed first.
bm::plan::ssh_guard() { # ssh_guard <tier> <affected-devs...>
  local tier="$1"
  shift
  local egress
  egress="$(bm::facts::ssh_egress_dev || true)"
  [[ -n "$egress" ]] || return 0
  local dev
  for dev in "$@"; do
    [[ "$dev" == "$egress" ]] || continue
    if [[ "$tier" == checkpoint ]]; then
      bm::log::say "$(bm::core::c_warn "NOTE: this change touches '$egress', which carries your SSH session.")"
      bm::log::say "$(bm::core::c_warn "NetworkManager will auto-rollback in $(bm::plan::_window)s unless you commit.")"
      return 0
    fi
    if (( BM_FORCE_UNSAFE )); then
      bm::log::say "$(bm::core::c_warn "WARNING: proceeding without checkpoint protection on your SSH egress device ($egress).")"
      return 0
    fi
    printf '%s: %s this change touches %s, which carries your SSH session, and NetworkManager checkpoints are unavailable (tier: %s).\nUse a console, or re-run with --force-unsafe to accept the risk of losing access.\n' \
      "$BM_PROG" "$(bm::core::c_err ERROR:)" "'$egress'" "$tier" >&2
    return 1
  done
  return 0
}

bm::plan::_window() {
  if [[ -n "$BM_ROLLBACK_WINDOW" ]]; then
    printf '%s' "$BM_ROLLBACK_WINDOW"
  else
    bm::config::get ROLLBACK_WINDOW
  fi
}

# ---- apply ----------------------------------------------------------------

# bm::plan::apply <op-name> <summary> <verify-cmd...>
#   - op-name: log tag
#   - summary: one line describing the change (stored in pending state)
#   - verify-cmd: command run after execution; it should populate the
#     bm::verify report. Pass `true` to skip verification.
# Globals consumed: BM_PLAN_* (the plan), BM_PLAN_AFFECTED (array of device
# names the SSH guard should consider).
bm::plan::apply() {
  local op="$1" summary="$2"
  shift 2

  bm::log::set_op "$op"

  if (( ${#BM_PLAN_DESCS[@]} == 0 )); then
    BM_PLAN_OUTCOME=noop
    bm::log::say "Nothing to do — already in the requested state."
    return "$BM_EX_OK"
  fi

  if (( BM_DRY_RUN )); then
    BM_PLAN_OUTCOME=dry-run
    bm::plan::render
    echo
    echo "(dry-run: no commands executed, no files written, no snapshot taken)"
    return "$BM_EX_OK"
  fi

  bm::core::require_root
  bm::log::enable_file
  bm::lock::acquire

  if bm::ckpt::load_pending; then
    bm::core::die "a previous change is still pending (${BM_PENDING_SUMMARY:-unknown}). Run '$BM_PROG commit' or '$BM_PROG rollback' first." "$BM_EX_PRECONDITION"
  fi

  local window tier
  window="$(bm::plan::_window)"
  tier="$(bm::ckpt::probe_tier)"
  bm::plan::ssh_guard "$tier" "${BM_PLAN_AFFECTED[@]:-}" || \
    bm::core::die "aborted (SSH egress guard)" "$BM_EX_PRECONDITION"

  bm::plan::render
  echo
  bm::log::say "Protection tier: $tier (auto-rollback window: ${window}s)"
  bm::log::say "  $(bm::help::tier_sentence "$tier")"
  if ! (( BM_ASSUME_YES )); then
    if ! bm::ui::yesno "Apply this plan?"; then
      BM_PLAN_OUTCOME=cancelled
      bm::log::say "aborted before any change"
      return "$BM_EX_OK"
    fi
  fi

  # NOTE: this function is routinely called in a `|| rc=$?` context, which
  # suspends errexit for the whole call tree — every critical step below is
  # therefore checked explicitly (die still exits reliably).
  local snap
  snap="$(bm::snap::create "$op")" || \
    bm::core::die "snapshot creation failed — aborting before any change" "$BM_EX_ERR"
  bm::log::say "snapshot: $snap"
  bm::ckpt::arm "$window" "$snap" "$summary"
  if [[ "$BM_CKPT_TIER" != "$tier" ]]; then
    # arming fell back a tier; re-check the ssh guard under the real tier.
    # nothing has been changed yet, so on refusal disarm cleanly (commit of
    # zero changes) instead of leaving a timer that would "roll back" later.
    local guard_rc=0
    bm::plan::ssh_guard "$BM_CKPT_TIER" "${BM_PLAN_AFFECTED[@]:-}" || guard_rc=$?
    if (( guard_rc != 0 )); then
      bm::ckpt::commit >/dev/null 2>&1 || true
      bm::core::die "aborted: change touches your SSH egress device and checkpoint protection is unavailable" "$BM_EX_PRECONDITION"
    fi
  fi

  local failed_step=""
  if ! failed_step="$(bm::plan::execute)"; then
    bm::log::say "$(bm::core::c_err "step $((failed_step + 1)) failed — rolling back")"
    bm::ckpt::rollback_pending || bm::log::warn "rollback reported problems; inspect manually"
    bm::log::say "rolled back to snapshot $snap"
    bm::log::say "Your network is back the way it was: the failed step above left nothing half-done."
    BM_PLAN_OUTCOME=rolled-back
    return "$BM_EX_VERIFY"
  fi

  bm::verify::reset
  "$@" || true
  echo
  echo "Verification:"
  bm::verify::render
  echo

  if bm::verify::failed; then
    bm::log::say "$(bm::core::c_err "verification FAILED — rolling back")"
    bm::ckpt::rollback_pending || bm::log::warn "rollback reported problems; inspect manually"
    bm::log::say "rolled back to snapshot $snap"
    bm::log::say "Your network is back the way it was. The FAIL lines above say what did not check out."
    BM_PLAN_OUTCOME=rolled-back
    return "$BM_EX_VERIFY"
  fi

  # Applying consumed part of the rollback window; give the operator (or the
  # next session) a full window to decide from here.
  bm::ckpt::rebudget "$window" || true

  if (( BM_ASSUME_YES )); then
    local crc=0
    bm::ckpt::commit >/dev/null || crc=$?
    if (( crc == BM_EX_CKPT_LOST )); then
      BM_PLAN_OUTCOME=lost
      bm::log::say "$(bm::core::c_err "the checkpoint expired before it could be committed — NetworkManager has most likely rolled this change back")"
      return "$BM_EX_VERIFY"
    fi
    BM_PLAN_OUTCOME=committed
    bm::log::say "$(bm::core::c_ok "change applied and committed (verification passed)")"
    return "$BM_EX_OK"
  fi

  bm::plan::commit_gate "$snap"
}

# No terminal to ask on (or the terminal went away): leave protection armed
# and say exactly how to finish from another session.
bm::plan::_gate_no_tty() {
  bm::log::say "No TTY to confirm on. Protection stays armed:"
  bm::log::say "  confirm with:   $BM_PROG commit"
  bm::log::say "  or revert with: $BM_PROG rollback"
  if [[ "$BM_CKPT_TIER" == snapshot ]]; then
    bm::log::say "$(bm::core::c_warn "Snapshot-only protection: nothing will roll this back automatically.")"
  else
    bm::log::say "Auto-rollback at the deadline if you do neither."
  fi
  BM_PLAN_OUTCOME=pending
  return "$BM_EX_PARTIAL"
}

# The deadline passed while the operator sat at the prompt. On the
# checkpoint tier NetworkManager rolls back by itself. On the deadman tier
# the timer's own rollback cannot help: this process still holds the lock
# (and transient timers may fire late), so it would either be refused or
# find nothing pending. Restore the snapshot here instead of announcing a
# rollback that never happened.
bm::plan::_gate_expired() { # _gate_expired <snapshot-id>
  local snap="$1"
  echo
  BM_PLAN_OUTCOME=expired
  if [[ "$BM_CKPT_TIER" == deadman ]]; then
    if bm::ckpt::rollback_pending; then
      bm::log::say "$(bm::core::c_err "auto-rollback deadline reached — the change has been reverted")"
      bm::log::say "rolled back to snapshot $snap"
    else
      bm::log::say "$(bm::core::c_err "auto-rollback deadline reached — restoring snapshot $snap reported problems; inspect manually")"
    fi
    return "$BM_EX_VERIFY"
  fi
  bm::log::say "$(bm::core::c_err "auto-rollback deadline reached — the change has been reverted")"
  bm::ckpt::clear_pending
  return "$BM_EX_VERIFY"
}

bm::plan::_gate_keep() { # _gate_keep -> rc of the gate
  local crc=0
  bm::ckpt::commit >/dev/null || crc=$?
  if (( crc == BM_EX_CKPT_LOST )); then
    BM_PLAN_OUTCOME=lost
    bm::log::say "$(bm::core::c_err "the checkpoint had already expired — NetworkManager has most likely rolled this change back")"
    bm::log::say "check the result with: $BM_PROG status"
    return "$BM_EX_VERIFY"
  fi
  BM_PLAN_OUTCOME=committed
  bm::log::say "$(bm::core::c_ok "change committed")"
  return "$BM_EX_OK"
}

bm::plan::_gate_undo() { # _gate_undo <snapshot-id>
  bm::ckpt::rollback_pending || bm::log::warn "rollback reported problems"
  bm::log::say "rolled back to snapshot $1"
  BM_PLAN_OUTCOME=rolled-back
  return "$BM_EX_VERIFY"
}

bm::plan::_gate_extend() { # _gate_extend <seconds-left> -> 0 when extended
  local remaining="$1" add=300
  if [[ "$BM_CKPT_TIER" == checkpoint && -n "$BM_CKPT_PATH" ]]; then
    if bm::ckpt::dbus_extend "$BM_CKPT_PATH" $(( remaining + add )); then
      BM_CKPT_DEADLINE=$(( $(bm::core::epoch) + remaining + add ))
      return 0
    fi
  fi
  return 1
}

# Interactive commit gate: count down toward the auto-rollback deadline.
# K (or c) keeps the change, U (or r) undoes it, E adds five minutes on the
# checkpoint tier. End of input on the terminal behaves like having no
# terminal at all: protection stays armed and the way out is printed.
bm::plan::commit_gate() {
  local snap="$1"
  if ! bm::core::is_tty; then
    bm::plan::_gate_no_tty
    return "$BM_EX_PARTIAL"
  fi
  bm::ui::_ensure_init
  if bm::ui::fancy; then
    bm::plan::_gate_fancy "$snap"
    return $?
  fi

  local key remaining now rc
  while :; do
    printf -v now '%(%s)T' -1
    remaining=$(( ${BM_CKPT_DEADLINE:-0} - now ))
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      remaining=999999 # no timer armed; purely manual decision
    fi
    if (( remaining <= 0 )); then
      bm::plan::_gate_expired "$snap"
      return $?
    fi
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      printf '\rVerification passed. c=commit r=rollback : '
    else
      printf '\rVerification passed. c=commit r=rollback e=extend (auto-rollback in %4ds) : ' "$remaining"
    fi
    rc=0
    read -r -t 2 -n 1 key || rc=$?
    if (( rc > 128 )); then
      continue # timeout: refresh the countdown
    fi
    if (( rc != 0 )); then
      echo
      bm::plan::_gate_no_tty
      return "$BM_EX_PARTIAL"
    fi
    echo
    case "$key" in
      c | C | k | K)
        bm::plan::_gate_keep
        return $?
        ;;
      r | R | u | U)
        bm::plan::_gate_undo "$snap"
        return $?
        ;;
      e | E)
        if bm::plan::_gate_extend "$remaining"; then
          bm::log::say "extended by 300s"
        fi
        ;;
    esac
  done
}

bm::plan::_gate_fancy() { # _gate_fancy <snapshot-id>
  local snap="$1" remaining now rc msg="" grc
  bm::ui::gate_intro "$BM_CKPT_TIER"
  bm::ui::_raw_on
  bm::ui::_drain
  while :; do
    printf -v now '%(%s)T' -1
    remaining=$(( ${BM_CKPT_DEADLINE:-0} - now ))
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      remaining=999999
    fi
    if (( remaining <= 0 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      bm::plan::_gate_expired "$snap"
      return $?
    fi
    bm::ui::gate_status "$remaining" "$BM_CKPT_TIER" "$msg"
    rc=0
    bm::ui::read_key 1 || rc=$?
    if (( rc == 2 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      echo
      bm::plan::_gate_no_tty
      return "$BM_EX_PARTIAL"
    fi
    (( rc == 0 )) || continue
    msg=""
    case "$BM_UI_KEY" in
      k | K | c | C)
        bm::ui::_raw_off
        bm::ui::_commit_block
        grc=0
        bm::plan::_gate_keep || grc=$?
        return "$grc"
        ;;
      u | U | r | R)
        bm::ui::_raw_off
        bm::ui::_commit_block
        grc=0
        bm::plan::_gate_undo "$snap" || grc=$?
        return "$grc"
        ;;
      e | E)
        if [[ "$BM_CKPT_TIER" != checkpoint ]]; then
          msg="Extending is only possible with NetworkManager's automatic undo."
        elif bm::plan::_gate_extend "$remaining"; then
          msg="Added 5 minutes."
        else
          msg="Could not extend - decide before the time runs out."
        fi
        ;;
      RESIZE)
        BM_UI_RESIZED=0
        bm::ui::_size
        ;;
      *)
        msg="Press K to keep the change or U to undo it."
        ;;
    esac
  done
}

# ==== 70-workflows.sh ====
# lib/70-workflows.sh — operation workflows.
# Each workflow normalizes its inputs (from CLI flags or TUI prompts — same
# code path), validates through the mode matrix, builds a plan, and hands it
# to the engine. Nothing here calls nmcli directly except through plan steps.

# The workflow spec is one associative array. Keys:
#   bond mode members opts(comma k=v) mtu
#   ip4(dhcp|none|CIDR[,CIDR]) gw4 dns4  ip6(auto|dhcp|none|CIDR[,CIDR]) gw6 dns6
#   vlans (space-separated VID[:ip4=..;gw4=..;dns4=..;ip6=..;gw6=..;dns6=..])
#   activate(0|1)
declare -A BM_SPEC=()

bm::wf::spec_reset() {
  BM_SPEC=()
  BM_SPEC[activate]=1
}

# ---- shared helpers -------------------------------------------------------

bm::wf::_validate_members() { # <bond> <members-csv> ; dies on hard errors
  local bond="$1" members_csv="$2" n master min_speed spd
  bm::core::split_list "$members_csv"
  (( ${#BM_LIST[@]} > 0 )) || bm::core::die "at least one member interface is required" "$BM_EX_USAGE" \
    "name the ports to use, e.g. --members ens1f0,ens1f1 (list them: $BM_PROG nics)"
  min_speed="$(bm::config::get MIN_SPEED_MBPS)"
  for n in "${BM_LIST[@]}"; do
    bm::val::ifname "$n" || bm::core::die "invalid interface name '$n'" "$BM_EX_USAGE" \
      "port names look like eth1 or ens1f0 - list them: $BM_PROG nics"
    bm::facts::nic_exists "$n" || bm::core::die "interface '$n' does not exist" "$BM_EX_PRECONDITION" \
      "$(bm::wf::_nic_hint "$n")"
    bm::facts::nic_allowed "$n" || bm::core::die "interface '$n' is blocked by NIC policy (see $BM_CONF)" "$BM_EX_PRECONDITION" \
      "only ports allowed by NIC_ALLOWLIST_PATTERNS / NIC_BLOCKLIST_PATTERNS can be used - see: $BM_PROG nics --all"
    master="$(bm::facts::nic_bond_master "$n")"
    if [[ -n "$master" && "$master" != "$bond" ]]; then
      bm::core::die "interface '$n' is already enslaved to bond '$master'" "$BM_EX_PRECONDITION" \
        "pick a free port ($BM_PROG nics), or take it out of $master first: $BM_PROG remove-member $master $n"
    fi
    if (( min_speed > 0 )); then
      spd="$(bm::facts::nic_speed "$n")"
      if [[ "$spd" != unknown ]] && (( spd < min_speed )); then
        bm::log::say "$(bm::core::c_warn "warning: $n reports ${spd}Mb/s, below configured minimum ${min_speed}Mb/s")"
      fi
    fi
  done
}

# Build the bond.options string for a create from BM_SPEC (mode+opts),
# applying config defaults. Echoes the options string; validation errors
# go to stderr and the function returns 1.
bm::wf::_build_options() {
  local mode="${BM_SPEC[mode]}"
  local -A opts=()
  opts[mode]="$mode"

  # user-supplied options first
  if [[ -n "${BM_SPEC[opts]:-}" ]]; then
    bm::nm::opts_parse "${BM_SPEC[opts]}" opts
    opts[mode]="$mode"
  fi

  # defaults: link monitoring, LACP tuning
  if [[ -z "${opts[miimon]:-}" && -z "${opts[arp_interval]:-}" ]]; then
    opts[miimon]="$(bm::config::get DEFAULT_MIIMON)"
  fi
  if [[ "$mode" == "802.3ad" ]]; then
    [[ -z "${opts[lacp_rate]:-}" ]] && opts[lacp_rate]="$(bm::config::get DEFAULT_8023AD_LACP_RATE)"
    [[ -z "${opts[xmit_hash_policy]:-}" ]] && opts[xmit_hash_policy]="$(bm::config::get DEFAULT_8023AD_XHP)"
  fi
  # arp monitoring replaces miimon
  if [[ -n "${opts[arp_interval]:-}" && "${opts[arp_interval]}" != 0 ]]; then
    unset "opts[miimon]"
  fi

  local errors
  if ! errors="$(bm::val::option_set "$mode" opts)"; then
    printf '%s\n' "$errors" >&2
    return 1
  fi
  bm::nm::opts_render opts
}

# Append IP configuration steps for a connection to the current plan.
bm::wf::_plan_ip_steps() { # _plan_ip_steps <con-ref> <label> <ip4> <gw4> <dns4> <ip6> <gw6> <dns6>
  local con="$1" label="$2" ip4="$3" gw4="$4" dns4="$5" ip6="$6" gw6="$7" dns6="$8"

  if [[ -n "$ip4" ]]; then
    local m4=static
    case "$ip4" in dhcp | auto) m4=dhcp ;; none | disabled) m4=none ;; esac
    if [[ "$m4" == static ]]; then
      local a
      bm::core::split_list "$ip4"
      for a in "${BM_LIST[@]}"; do
        bm::val::ipv4_cidr "$a" || bm::core::die "invalid IPv4 CIDR '$a'" "$BM_EX_USAGE" \
          "write the address with its prefix, e.g. 10.0.0.10/24 (or use dhcp / none)"
      done
      [[ -n "$gw4" ]] && { bm::val::ipv4_addr "$gw4" || bm::core::die "invalid IPv4 gateway '$gw4'" "$BM_EX_USAGE" \
        "the gateway is a plain address without a prefix, e.g. 10.0.0.1"; }
      [[ -n "$dns4" ]] && { bm::val::ip_list v4 "${dns4// /,}" || bm::core::die "invalid IPv4 DNS list '$dns4'" "$BM_EX_USAGE" \
        "DNS servers are plain addresses, comma-separated, e.g. 10.0.0.53,10.0.0.54"; }
    fi
    bm::nm::ip_args 4 "$m4" "$ip4" "$gw4" "$dns4" || bm::core::die "invalid IPv4 method '$ip4'" "$BM_EX_USAGE" \
      "use dhcp, none, or an address with prefix such as 10.0.0.10/24"
    bm::plan::add "Configure IPv4 ($ip4) on $label" bm::nm::modify "$con" "${BM_NM_IP_ARGS[@]}"
  fi

  if [[ -n "$ip6" ]]; then
    local m6=static
    case "$ip6" in auto) m6=auto ;; dhcp) m6=dhcp ;; none | disabled) m6=none ;; esac
    if [[ "$m6" == static ]]; then
      local a6
      bm::core::split_list "$ip6"
      for a6 in "${BM_LIST[@]}"; do
        bm::val::ipv6_cidr "$a6" || bm::core::die "invalid IPv6 CIDR '$a6'" "$BM_EX_USAGE" \
          "write the address with its prefix, e.g. 2001:db8::10/64 (or use auto / dhcp / none)"
      done
      [[ -n "$gw6" ]] && { bm::val::ipv6_addr "$gw6" || bm::core::die "invalid IPv6 gateway '$gw6'" "$BM_EX_USAGE" \
        "the gateway is a plain address without a prefix, e.g. 2001:db8::1"; }
      [[ -n "$dns6" ]] && { bm::val::ip_list v6 "${dns6// /,}" || bm::core::die "invalid IPv6 DNS list '$dns6'" "$BM_EX_USAGE" \
        "DNS servers are plain addresses, comma-separated, e.g. 2001:db8::53,2001:db8::54"; }
    fi
    if [[ "$m6" == auto ]]; then
      bm::plan::add "Configure IPv6 (SLAAC/auto) on $label" bm::nm::modify "$con" ipv6.method auto
    elif [[ "$m6" == dhcp ]]; then
      # DHCPv6 without SLAAC is a distinct NetworkManager method; mapping it
      # to 'auto' would silently give the operator something else.
      bm::plan::add "Configure IPv6 (DHCPv6) on $label" bm::nm::modify "$con" ipv6.method dhcp
    elif [[ "$m6" == none ]]; then
      bm::plan::add "Disable IPv6 on $label" bm::nm::modify "$con" ipv6.method ignore
    else
      bm::nm::ip_args 6 static "$ip6" "$gw6" "$dns6"
      bm::plan::add "Configure IPv6 ($ip6) on $label" bm::nm::modify "$con" "${BM_NM_IP_ARGS[@]}"
    fi
  fi
}

# Parse one --vlan token: VID[:key=value;key=value...]
# Sets BM_VLAN_ID / BM_VLAN_IP4 / BM_VLAN_GW4 / BM_VLAN_DNS4 / BM_VLAN_IP6 / BM_VLAN_GW6 / BM_VLAN_DNS6
bm::wf::_parse_vlan_token() {
  local tok="$1"
  BM_VLAN_ID="${tok%%:*}"
  BM_VLAN_IP4="" BM_VLAN_GW4="" BM_VLAN_DNS4="" BM_VLAN_IP6="" BM_VLAN_GW6="" BM_VLAN_DNS6=""
  bm::val::vlan_id "$BM_VLAN_ID" || bm::core::die "invalid VLAN id '$BM_VLAN_ID'" "$BM_EX_USAGE" \
    "a VLAN id is a number from 1 to 4094, e.g. 120 or '120:ip4=10.0.0.5/24;gw4=10.0.0.1'"
  [[ "$tok" == *:* ]] || return 0
  local rest="${tok#*:}" kv
  local IFS=';'
  for kv in $rest; do
    case "$kv" in
      ip4=*) BM_VLAN_IP4="${kv#ip4=}" ;;
      gw4=*) BM_VLAN_GW4="${kv#gw4=}" ;;
      dns4=*) BM_VLAN_DNS4="${kv#dns4=}" ;;
      ip6=*) BM_VLAN_IP6="${kv#ip6=}" ;;
      gw6=*) BM_VLAN_GW6="${kv#gw6=}" ;;
      dns6=*) BM_VLAN_DNS6="${kv#dns6=}" ;;
      *) bm::core::die "unknown VLAN setting '$kv' (expected ip4=/gw4=/dns4=/ip6=/gw6=/dns6=)" "$BM_EX_USAGE" \
        "example: '120:ip4=10.0.0.5/24;gw4=10.0.0.1' (quote it - the ';' would end the command)" ;;
    esac
  done
}

# Devices a change to <bond> could disturb: the bond, its current members,
# and its VLAN interfaces. The SSH-egress guard is only as good as this list —
# an operator whose session rides bond0.120 must be warned about a change to
# bond0 just as much as one riding bond0 itself.
bm::wf::_affected_existing() { # _affected_existing <bond>
  local bond="$1"
  BM_PLAN_AFFECTED=("$bond")
  local m
  while IFS= read -r m; do
    [[ -n "$m" ]] && BM_PLAN_AFFECTED+=("$m")
  done < <(bm::facts::bond_members "$bond")
  local rec uuid name dev vid
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r uuid name dev vid <<<"$rec"
    [[ -n "$dev" ]] && BM_PLAN_AFFECTED+=("$dev")
  done < <(bm::nm::vlan_cons "$bond")
}

bm::wf::_affected_from_spec() { # populate BM_PLAN_AFFECTED from BM_SPEC
  BM_PLAN_AFFECTED=("${BM_SPEC[bond]}")
  if [[ -n "${BM_SPEC[members]:-}" ]]; then
    bm::core::split_list "${BM_SPEC[members]}"
    BM_PLAN_AFFECTED+=("${BM_LIST[@]}")
  fi
  local tok
  for tok in ${BM_SPEC[vlans]:-}; do
    BM_PLAN_AFFECTED+=("${BM_SPEC[bond]}.${tok%%:*}")
  done
}

# Hints for "Next step:" lines. They read sysfs and the profile list only,
# so a --dry-run stays free of side effects.
bm::wf::_nic_hint() { # _nic_hint <missing-nic>
  local near
  # shellcheck disable=SC2046  # one NIC name per word is intended
  near="$(bm::core::closest "$1" $(bm::facts::eligible_nics))"
  if [[ -n "$near" ]]; then
    printf "did you mean '%s'? See every port: %s nics" "$near" "$BM_PROG"
  else
    printf 'see the ports this server has: %s nics' "$BM_PROG"
  fi
}

bm::wf::_bond_hint() { # _bond_hint <bond-that-has-no-profile>
  local b="$1" near
  if bm::facts::bond_exists_kernel "$b"; then
    printf "'%s' runs in the kernel but NetworkManager has no saved profile for it (made by hand?); only NetworkManager-managed bonds can be changed here" "$b"
    return 0
  fi
  # shellcheck disable=SC2046
  near="$(bm::core::closest "$b" $(
    { bm::facts::kernel_bonds; bm::nm::bond_cons 2>/dev/null | awk -F'\x1f' '{ print ($3 != "" ? $3 : $2) }'; } | sort -u))"
  if [[ -n "$near" ]]; then
    printf "did you mean '%s'? See every bond: %s list" "$near" "$BM_PROG"
  else
    printf 'see the bonds on this server: %s list' "$BM_PROG"
  fi
}

bm::wf::_mode_hint() { # _mode_hint <bad-mode>
  local m
  m="$(bm::help::mode_alias "$1")"
  if [[ -n "$m" ]]; then
    printf "did you mean '%s'? Not sure which? active-backup works with any switch (%s help modes)" "$m" "$BM_PROG"
  else
    printf 'not sure which? active-backup works with any switch - see: %s help modes' "$BM_PROG"
  fi
}

# Devices a change to <bond> could disturb, plus extras (e.g. a new member):
# what the SSH-egress guard will look at. Fills BM_PLAN_AFFECTED.
bm::wf::affected_devices() { # affected_devices <bond> [extra...]
  bm::wf::_affected_existing "$1"
  shift
  BM_PLAN_AFFECTED+=("$@")
}

# The command line that does the same as the current BM_SPEC — the menus
# show it so a change rehearsed there can be scripted for the rest of the
# fleet. Sets BM_WF_CLI.
BM_WF_CLI=""
BM_WF_ARGV=()
bm::wf::_q() { BM_WF_ARGV+=("$(bm::plan::_shq "$1")"); }

bm::wf::cli_equivalent() { # cli_equivalent <subcommand>
  local sub="$1" tok k
  case "$sub" in
    add-member | remove-member)
      BM_WF_ARGV=("$sub")
      bm::wf::_q "${BM_SPEC[bond]}"
      bm::wf::_q "${BM_SPEC[members]:-}"
      ;;
    swap-member)
      BM_WF_ARGV=(swap-member)
      bm::wf::_q "${BM_SPEC[bond]}"
      BM_WF_ARGV+=(--old); bm::wf::_q "${BM_SPEC[old]:-}"
      BM_WF_ARGV+=(--new); bm::wf::_q "${BM_SPEC[new]:-}"
      ;;
    remove)
      BM_WF_ARGV=(remove)
      bm::wf::_q "${BM_SPEC[bond]}"
      [[ "${BM_SPEC[keep_vlans]:-0}" == 1 ]] && BM_WF_ARGV+=(--keep-vlans)
      ;;
    repair)
      BM_WF_ARGV=(repair)
      bm::wf::_q "${BM_SPEC[bond]}"
      ;;
    clone)
      BM_WF_ARGV=(clone)
      bm::wf::_q "${BM_SPEC[src]:-}"
      bm::wf::_q "${BM_SPEC[bond]}"
      BM_WF_ARGV+=(--members); bm::wf::_q "${BM_SPEC[members]:-}"
      [[ "${BM_SPEC[copy_ip]:-0}" == 1 ]] && BM_WF_ARGV+=(--copy-ip)
      [[ "${BM_SPEC[copy_vlans]:-0}" == 1 ]] && BM_WF_ARGV+=(--copy-vlans)
      ;;
    vlan-add)
      BM_WF_ARGV=(vlan add)
      bm::wf::_q "${BM_SPEC[bond]}"
      bm::wf::_q "${BM_SPEC[vlans]:-}"
      ;;
    vlan-remove)
      BM_WF_ARGV=(vlan remove)
      bm::wf::_q "${BM_SPEC[bond]}"
      bm::wf::_q "${BM_SPEC[vlan_id]:-}"
      ;;
    vlan-modify | create | modify)
      if [[ "$sub" == vlan-modify ]]; then
        BM_WF_ARGV=(vlan modify)
        bm::wf::_q "${BM_SPEC[bond]}"
        bm::wf::_q "${BM_SPEC[vlan_id]:-}"
      else
        BM_WF_ARGV=("$sub")
        bm::wf::_q "${BM_SPEC[bond]}"
        if [[ -n "${BM_SPEC[mode]:-}" ]]; then BM_WF_ARGV+=(--mode); bm::wf::_q "${BM_SPEC[mode]}"; fi
        if [[ -n "${BM_SPEC[members]:-}" ]]; then BM_WF_ARGV+=(--members); bm::wf::_q "${BM_SPEC[members]}"; fi
        if [[ -n "${BM_SPEC[opts]:-}" ]]; then BM_WF_ARGV+=(--opt); bm::wf::_q "${BM_SPEC[opts]}"; fi
        for k in ${BM_SPEC[del_opts]:-}; do BM_WF_ARGV+=(--del-opt); bm::wf::_q "$k"; done
        if [[ -n "${BM_SPEC[mtu]:-}" ]]; then BM_WF_ARGV+=(--mtu); bm::wf::_q "${BM_SPEC[mtu]}"; fi
      fi
      local f
      for f in ip4 gw4 dns4 ip6 gw6 dns6; do
        if [[ -n "${BM_SPEC[$f]:-}" ]]; then BM_WF_ARGV+=("--$f"); bm::wf::_q "${BM_SPEC[$f]}"; fi
      done
      if [[ "$sub" == create ]]; then
        for tok in ${BM_SPEC[vlans]:-}; do BM_WF_ARGV+=(--vlan); bm::wf::_q "$tok"; done
      fi
      [[ "${BM_SPEC[activate]:-1}" == 0 ]] && BM_WF_ARGV+=(--no-activate)
      ;;
    *)
      BM_WF_ARGV=("$sub")
      bm::wf::_q "${BM_SPEC[bond]:-}"
      ;;
  esac
  BM_WF_CLI="$BM_PROG ${BM_WF_ARGV[*]}"
}

# Print the CLI equivalent of the current spec (the TUI teaches the CLI).
bm::wf::print_cli_equivalent() { # print_cli_equivalent <subcommand>
  bm::wf::cli_equivalent "$1"
  bm::log::say ""
  bm::log::say "CLI equivalent: $BM_WF_CLI"
  bm::log::say ""
}

# ---- create ---------------------------------------------------------------

bm::wf::create() {
  local bond="${BM_SPEC[bond]}"
  bm::val::ifname "$bond" || bm::core::die "invalid bond name '$bond'" "$BM_EX_USAGE" \
    "bond names are up to 15 letters, digits, '.', '_' or '-', e.g. bond0"
  [[ -n "${BM_SPEC[mode]:-}" ]] || bm::core::die "--mode is required" "$BM_EX_USAGE" \
    "add --mode active-backup (works with any switch) or --mode 802.3ad (LACP) - see: $BM_PROG help modes"
  bm::val::mode "${BM_SPEC[mode]}" || bm::core::die "unknown mode '${BM_SPEC[mode]}' (valid: ${BM_MODES[*]})" "$BM_EX_USAGE" \
    "$(bm::wf::_mode_hint "${BM_SPEC[mode]}")"

  if bm::facts::bond_exists_kernel "$bond" || bm::nm::bond_con_uuid "$bond" >/dev/null; then
    bm::core::die "bond '$bond' already exists (use 'modify' or a different name)" "$BM_EX_PRECONDITION" \
      "pick a new name, or change the existing one: $BM_PROG modify $bond ..."
  fi
  bm::wf::_validate_members "$bond" "${BM_SPEC[members]:-}"

  local opts
  opts="$(bm::wf::_build_options)" || bm::core::die "invalid bond options (see above)" "$BM_EX_USAGE" \
    "each mode accepts different options - see: $BM_PROG help modes"

  [[ -n "${BM_SPEC[mtu]:-}" ]] && { bm::val::mtu "${BM_SPEC[mtu]}" || bm::core::die "invalid MTU '${BM_SPEC[mtu]}'" "$BM_EX_USAGE" \
    "a number from 68 to 65535: 1500 is normal, 9000 means jumbo frames"; }

  bm::plan::reset
  bm::plan::add "Create bond profile '$bond' ($opts)" bm::nm::add_bond "$bond" "$opts"
  [[ -n "${BM_SPEC[mtu]:-}" ]] && \
    bm::plan::add "Set MTU ${BM_SPEC[mtu]} on $bond" bm::nm::modify "$bond" 802-3-ethernet.mtu "${BM_SPEC[mtu]}"

  local n
  bm::core::split_list "${BM_SPEC[members]}"
  local -a member_arr=("${BM_LIST[@]}")
  for n in "${member_arr[@]}"; do
    bm::plan::add "Add member '$n'" bm::nm::add_port "$bond" "$n"
  done

  bm::wf::_plan_ip_steps "$bond" "$bond" \
    "${BM_SPEC[ip4]:-}" "${BM_SPEC[gw4]:-}" "${BM_SPEC[dns4]:-}" \
    "${BM_SPEC[ip6]:-}" "${BM_SPEC[gw6]:-}" "${BM_SPEC[dns6]:-}"

  local ip_dev="$bond" tok
  for tok in ${BM_SPEC[vlans]:-}; do
    bm::wf::_parse_vlan_token "$tok"
    local vif="$bond.$BM_VLAN_ID"
    bm::val::ifname "$vif" || bm::core::die "VLAN interface name '$vif' exceeds 15 characters" "$BM_EX_USAGE" \
      "use a shorter bond name (the VLAN device is named BOND.VID)"
    bm::plan::add "Create VLAN $BM_VLAN_ID on $bond ($vif)" bm::nm::add_vlan "$bond" "$BM_VLAN_ID"
    bm::wf::_plan_ip_steps "$vif" "$vif" \
      "$BM_VLAN_IP4" "$BM_VLAN_GW4" "$BM_VLAN_DNS4" "$BM_VLAN_IP6" "$BM_VLAN_GW6" "$BM_VLAN_DNS6"
    [[ -n "$BM_VLAN_IP4$BM_VLAN_IP6" ]] && ip_dev="$vif"
  done

  if [[ "${BM_SPEC[activate]}" == 1 ]]; then
    bm::plan::add "Activate bond '$bond'" bm::nm::up "$bond"
    for n in "${member_arr[@]}"; do
      bm::plan::add "Activate member '$n'" bm::nm::up "bond-port-$n"
    done
    for tok in ${BM_SPEC[vlans]:-}; do
      bm::plan::add "Activate VLAN interface '$bond.${tok%%:*}'" bm::nm::up "$bond.${tok%%:*}"
    done
  fi

  bm::wf::_affected_from_spec
  local gw="${BM_SPEC[gw4]:-}"
  [[ "$ip_dev" != "$bond" ]] && gw="${BM_VLAN_GW4:-}"
  local expect_state=up
  [[ "${BM_SPEC[activate]}" == 1 ]] || expect_state=any
  bm::plan::apply create "create bond $bond (${BM_SPEC[mode]}, members ${BM_SPEC[members]})" \
    bm::verify::bond "$bond" "${BM_SPEC[mode]}" "${BM_SPEC[members]}" "$ip_dev" "$gw" "$expect_state"
}

# ---- modify (mode/options/mtu/ip) ----------------------------------------

bm::wf::modify() {
  local bond="${BM_SPEC[bond]}"
  local uuid
  uuid="$(bm::nm::bond_con_uuid "$bond")" || bm::core::die "no NetworkManager bond profile found for '$bond'" "$BM_EX_PRECONDITION" \
    "$(bm::wf::_bond_hint "$bond")"

  bm::plan::reset

  local current_opts new_opts mode
  current_opts="$(bm::nm::con_get "$uuid" bond.options)"
  mode="${BM_SPEC[mode]:-}"
  if [[ -z "$mode" ]]; then
    local -A cur=()
    bm::nm::opts_parse "$current_opts" cur
    # A profile with no explicit mode runs the kernel/NetworkManager default,
    # which is balance-rr — assuming active-backup here would validate the new
    # option set against the wrong matrix and silently change behavior.
    mode="${cur[mode]:-balance-rr}"
    if [[ -z "${cur[mode]:-}" ]]; then
      bm::log::say "$(bm::core::c_warn "note: '$bond' has no explicit bond mode; treating it as the default (balance-rr)")"
    fi
  fi
  bm::val::mode "$mode" || bm::core::die "unknown mode '$mode'" "$BM_EX_USAGE" "$(bm::wf::_mode_hint "$mode")"

  # merge: explicit mode change + --opt pairs + --del-opt keys
  local -a changes=()
  local -A spec_opts=()
  [[ -n "${BM_SPEC[mode]:-}" ]] && changes+=("mode=$mode")
  if [[ -n "${BM_SPEC[opts]:-}" ]]; then
    # Parse rather than split on commas: values such as
    # arp_ip_target=10.0.0.1,10.0.0.2 legitimately contain commas, and a naive
    # split would turn the second address into a bogus option key.
    bm::nm::opts_parse "${BM_SPEC[opts]}" spec_opts
    local kv
    for kv in "${!spec_opts[@]}"; do
      changes+=("$kv=${spec_opts[$kv]}")
    done
  fi
  if [[ -n "${BM_SPEC[del_opts]:-}" ]]; then
    bm::core::split_list "${BM_SPEC[del_opts]}"
    local k
    for k in "${BM_LIST[@]}"; do
      changes+=("$k=")
    done
  fi

  if (( ${#changes[@]} > 0 )); then
    new_opts="$(bm::nm::opts_merge "$current_opts" "${changes[@]}")"
    local -A merged=()
    bm::nm::opts_parse "$new_opts" merged
    # shellcheck disable=SC2034  # merged is consumed by name via nameref
    merged[mode]="$mode"

    # An explicit mode change carries the old mode's options into the merge,
    # where they are no longer valid: switching an 802.3ad bond to
    # active-backup (what a cross-switch migration needs, since LACP cannot
    # span two independent switches) would otherwise fail on the lacp_rate and
    # xmit_hash_policy it is being asked to abandon. Dropping them is what the
    # operator means. Options passed in THIS command are left in place so a
    # contradictory request still fails loudly.
    if [[ -n "${BM_SPEC[mode]:-}" ]]; then
      local -a dropped=()
      local okey
      for okey in "${!merged[@]}"; do
        [[ "$okey" == mode ]] && continue
        bm::val::option_allowed "$mode" "$okey" && continue
        [[ -n "${spec_opts[$okey]:-}" ]] && continue
        unset 'merged[$okey]'
        dropped+=("$okey")
      done
      if (( ${#dropped[@]} > 0 )); then
        bm::log::say "$(bm::core::c_warn "note: dropping option(s) not valid in mode $mode: ${dropped[*]}")"
      fi
    fi

    local errors
    if ! errors="$(bm::val::option_set "$mode" merged)"; then
      printf '%s\n' "$errors" >&2
      bm::core::die "invalid resulting option set" "$BM_EX_USAGE" \
        "each mode accepts different options - see: $BM_PROG help modes"
    fi
    new_opts="$(bm::nm::opts_render merged)"
    if [[ "$new_opts" != "$current_opts" ]]; then
      bm::plan::add "Set bond.options to '$new_opts'" bm::nm::modify "$uuid" bond.options "$new_opts"
    fi
  fi

  if [[ -n "${BM_SPEC[mtu]:-}" ]]; then
    bm::val::mtu "${BM_SPEC[mtu]}" || bm::core::die "invalid MTU '${BM_SPEC[mtu]}'" "$BM_EX_USAGE" \
      "a number from 68 to 65535: 1500 is normal, 9000 means jumbo frames"
    local cur_mtu
    cur_mtu="$(bm::nm::con_get "$uuid" 802-3-ethernet.mtu)"
    if [[ "$cur_mtu" != "${BM_SPEC[mtu]}" ]]; then
      bm::plan::add "Set MTU ${BM_SPEC[mtu]}" bm::nm::modify "$uuid" 802-3-ethernet.mtu "${BM_SPEC[mtu]}"
    fi
  fi

  bm::wf::_plan_ip_steps "$uuid" "$bond" \
    "${BM_SPEC[ip4]:-}" "${BM_SPEC[gw4]:-}" "${BM_SPEC[dns4]:-}" \
    "${BM_SPEC[ip6]:-}" "${BM_SPEC[gw6]:-}" "${BM_SPEC[dns6]:-}"

  if (( $(bm::plan::size) > 0 )) && [[ "${BM_SPEC[activate]}" == 1 ]]; then
    bm::plan::add "Re-activate bond '$bond' to apply changes" bm::nm::up "$uuid"
  fi

  bm::wf::_affected_existing "$bond"
  bm::plan::apply modify "modify bond $bond" \
    bm::verify::bond "$bond" "$mode" "" "$bond" "${BM_SPEC[gw4]:-}"
}

# ---- members --------------------------------------------------------------

bm::wf::add_members() {
  local bond="${BM_SPEC[bond]}" members_csv="${BM_SPEC[members]}"
  local uuid
  uuid="$(bm::nm::bond_con_uuid "$bond")" || bm::core::die "no NetworkManager bond profile found for '$bond'" "$BM_EX_PRECONDITION" \
    "$(bm::wf::_bond_hint "$bond")"
  bm::wf::_validate_members "$bond" "$members_csv"

  bm::plan::reset
  bm::core::split_list "$members_csv"
  local -a new_members=("${BM_LIST[@]}")
  local n
  for n in "${new_members[@]}"; do
    if bm::facts::bond_members "$bond" | grep -qx "$n"; then
      bm::log::say "member $n already enslaved — skipping"
      continue
    fi
    bm::plan::add "Add member '$n'" bm::nm::add_port "$uuid" "$n"
    bm::plan::add "Activate member '$n'" bm::nm::up "bond-port-$n"
  done

  bm::wf::_affected_existing "$bond"
  BM_PLAN_AFFECTED+=("${new_members[@]}")
  bm::plan::apply add-member "add members ($members_csv) to $bond" \
    bm::verify::bond "$bond" "" "$members_csv" "" ""
}

bm::wf::remove_members() {
  local bond="${BM_SPEC[bond]}" members_csv="${BM_SPEC[members]}"
  bm::plan::reset
  bm::core::split_list "$members_csv"
  local -a to_remove=("${BM_LIST[@]}")
  local n rec uuid name dev found
  local -a remaining=()
  mapfile -t remaining < <(bm::facts::bond_members "$bond")

  for n in "${to_remove[@]}"; do
    found=0
    while IFS= read -r rec; do
      IFS=$'\x1f' read -r uuid name dev <<<"$rec"
      if [[ "$dev" == "$n" ]]; then
        bm::plan::add "Remove member profile for '$n' ($name)" bm::nm::delete "$uuid"
        found=1
      fi
    done < <(bm::nm::port_cons "$bond")
    if (( ! found )); then
      bm::log::say "$(bm::core::c_warn "no port profile found for '$n' on $bond — skipping")"
    fi
  done

  # Removing the last member takes the bond down. Warn, and tell verification
  # not to expect an up bond afterwards — otherwise a correct change would
  # fail its own gate and be rolled back.
  local left=0
  for n in "${remaining[@]}"; do
    bm::core::in_list "$n" "${to_remove[@]}" || left=$((left + 1))
  done
  local expect_state=up
  if (( left == 0 )) && (( $(bm::plan::size) > 0 )); then
    expect_state=any
    # A dry-run renders the plan and asks nothing; the confirmation belongs
    # to the real run only.
    if ! (( BM_ASSUME_YES )) && ! (( BM_DRY_RUN )); then
      if ! bm::ui::yesno "Removing these members leaves '$bond' with NO members, which takes it down. Continue?"; then
        BM_PLAN_OUTCOME=cancelled
        return 0
      fi
    fi
  fi

  bm::wf::_affected_existing "$bond"
  bm::plan::apply remove-member "remove members ($members_csv) from $bond" \
    bm::verify::bond "$bond" "" "" "" "" "$expect_state" "$members_csv"
}

# swap: add the new member and wait until it is enslaved BEFORE removing the
# old one, so redundancy never drops below the starting level.
bm::wf::swap_member() {
  local bond="${BM_SPEC[bond]}" old="${BM_SPEC[old]}" new="${BM_SPEC[new]}"
  local uuid
  uuid="$(bm::nm::bond_con_uuid "$bond")" || bm::core::die "no NetworkManager bond profile found for '$bond'" "$BM_EX_PRECONDITION" \
    "$(bm::wf::_bond_hint "$bond")"
  bm::facts::bond_members "$bond" | grep -qx "$old" || \
    bm::core::die "'$old' is not a member of '$bond'" "$BM_EX_PRECONDITION" \
      "--old must be one of its current ports: $(bm::facts::bond_members "$bond" | paste -sd, - | sed 's/,/, /g; s/^$/(none)/')"
  bm::wf::_validate_members "$bond" "$new"

  bm::plan::reset
  bm::plan::add "Add replacement member '$new'" bm::nm::add_port "$uuid" "$new"
  bm::plan::add "Activate member '$new'" bm::nm::up "bond-port-$new"
  bm::plan::add "Wait for '$new' to enslave" bm::plan::await_member "$bond" "$new"

  local rec puuid name dev
  local removed=0
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r puuid name dev <<<"$rec"
    if [[ "$dev" == "$old" ]]; then
      bm::plan::add "Remove old member profile for '$old' ($name)" bm::nm::delete "$puuid"
      removed=1
    fi
  done < <(bm::nm::port_cons "$bond")
  (( removed )) || bm::core::die "no port profile found for '$old' on '$bond' (repair first?)" "$BM_EX_PRECONDITION" \
    "save the bond's real ports as profiles first: $BM_PROG repair $bond"

  bm::wf::_affected_existing "$bond"
  BM_PLAN_AFFECTED+=("$new")
  # Verify both halves of the swap: the new member is in, the old one is out.
  bm::plan::apply swap-member "swap member $old -> $new on $bond" \
    bm::verify::bond "$bond" "" "$new" "" "" up "$old"
}

# ---- remove ---------------------------------------------------------------

bm::wf::remove() {
  local bond="${BM_SPEC[bond]}" keep_vlans="${BM_SPEC[keep_vlans]:-0}"
  local uuid
  uuid="$(bm::nm::bond_con_uuid "$bond" || true)"
  if [[ -z "$uuid" ]] && ! bm::facts::bond_exists_kernel "$bond"; then
    bm::core::die "bond '$bond' not found" "$BM_EX_PRECONDITION" "$(bm::wf::_bond_hint "$bond")"
  fi

  bm::plan::reset
  local rec vuuid vname vdev vid
  if [[ "$keep_vlans" != 1 ]]; then
    while IFS= read -r rec; do
      IFS=$'\x1f' read -r vuuid vname vdev vid <<<"$rec"
      bm::plan::add "Delete VLAN profile '$vname' (VLAN $vid)" bm::nm::delete "$vuuid"
    done < <(bm::nm::vlan_cons "$bond")
  fi
  local puuid pname pdev
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r puuid pname pdev <<<"$rec"
    bm::plan::add "Delete member profile '$pname' ($pdev)" bm::nm::delete "$puuid"
  done < <(bm::nm::port_cons "$bond")
  if [[ -n "$uuid" ]]; then
    bm::plan::add "Delete bond profile '$bond'" bm::nm::delete "$uuid"
  fi

  (( $(bm::plan::size) > 0 )) || {
    BM_PLAN_OUTCOME=noop
    bm::log::say "nothing to remove for '$bond'"
    return "$BM_EX_OK"
  }

  if ! (( BM_DRY_RUN )); then
    bm::ui::confirm_exact "removal of bond '$bond' and its profiles" "$bond" || {
      BM_PLAN_OUTCOME=cancelled
      bm::log::say "cancelled"
      return "$BM_EX_OK"
    }
  fi

  bm::wf::_affected_existing "$bond"
  bm::plan::apply remove "remove bond $bond" true
}

# ---- clone ----------------------------------------------------------------

# Clone copies from the source PROFILE (by uuid) — bond.options, IPv4/IPv6
# settings, VLAN profiles — not from lossy /proc scraping.
bm::wf::clone() {
  local src="${BM_SPEC[src]}" dst="${BM_SPEC[bond]}" members_csv="${BM_SPEC[members]}"
  local copy_ip="${BM_SPEC[copy_ip]:-0}" copy_vlans="${BM_SPEC[copy_vlans]:-0}"

  local src_uuid
  src_uuid="$(bm::nm::bond_con_uuid "$src")" || bm::core::die "no NetworkManager bond profile found for '$src'" "$BM_EX_PRECONDITION" \
    "$(bm::wf::_bond_hint "$src")"
  bm::val::ifname "$dst" || bm::core::die "invalid bond name '$dst'" "$BM_EX_USAGE" \
    "bond names are up to 15 letters, digits, '.', '_' or '-', e.g. bond1"
  if bm::facts::bond_exists_kernel "$dst" || bm::nm::bond_con_uuid "$dst" >/dev/null 2>&1; then
    bm::core::die "bond '$dst' already exists" "$BM_EX_PRECONDITION" "pick a name that is not in use ($BM_PROG list)"
  fi
  bm::wf::_validate_members "$dst" "$members_csv"

  local opts
  opts="$(bm::nm::con_get "$src_uuid" bond.options)"
  [[ -n "$opts" ]] || opts="mode=active-backup,miimon=$(bm::config::get DEFAULT_MIIMON)"

  bm::plan::reset
  bm::plan::add "Create bond profile '$dst' (cloned options: $opts)" bm::nm::add_bond "$dst" "$opts"

  bm::core::split_list "$members_csv"
  local -a new_members=("${BM_LIST[@]}")
  local n
  for n in "${new_members[@]}"; do
    bm::plan::add "Add member '$n'" bm::nm::add_port "$dst" "$n"
  done

  if [[ "$copy_ip" == 1 ]]; then
    local m4 a4 g4 d4
    m4="$(bm::nm::con_get "$src_uuid" ipv4.method)"
    a4="$(bm::nm::con_get "$src_uuid" ipv4.addresses)"
    g4="$(bm::nm::con_get "$src_uuid" ipv4.gateway)"
    d4="$(bm::nm::con_get "$src_uuid" ipv4.dns)"
    case "$m4" in
      auto) bm::plan::add "Copy IPv4 (DHCP)" bm::nm::modify "$dst" ipv4.method auto ;;
      manual)
        bm::plan::add "Copy IPv4 static config ($a4)" bm::nm::modify "$dst" \
          ipv4.method manual ipv4.addresses "$a4" ipv4.gateway "$g4" ipv4.dns "$d4" ;;
    esac
    local m6 a6 g6
    m6="$(bm::nm::con_get "$src_uuid" ipv6.method)"
    a6="$(bm::nm::con_get "$src_uuid" ipv6.addresses)"
    g6="$(bm::nm::con_get "$src_uuid" ipv6.gateway)"
    case "$m6" in
      auto | dhcp) bm::plan::add "Copy IPv6 (auto)" bm::nm::modify "$dst" ipv6.method auto ;;
      manual)
        bm::plan::add "Copy IPv6 static config ($a6)" bm::nm::modify "$dst" \
          ipv6.method manual ipv6.addresses "$a6" ipv6.gateway "$g6" ;;
    esac
  fi

  if [[ "$copy_vlans" == 1 ]]; then
    local rec vuuid vname vdev vid
    while IFS= read -r rec; do
      IFS=$'\x1f' read -r vuuid vname vdev vid <<<"$rec"
      [[ -n "$vid" ]] || continue
      bm::plan::add "Clone VLAN $vid onto $dst" bm::nm::add_vlan "$dst" "$vid"
      local vm4 va4 vg4 vd4
      vm4="$(bm::nm::con_get "$vuuid" ipv4.method)"
      va4="$(bm::nm::con_get "$vuuid" ipv4.addresses)"
      vg4="$(bm::nm::con_get "$vuuid" ipv4.gateway)"
      vd4="$(bm::nm::con_get "$vuuid" ipv4.dns)"
      case "$vm4" in
        auto) bm::plan::add "Copy IPv4 (DHCP) to $dst.$vid" bm::nm::modify "$dst.$vid" ipv4.method auto ;;
        manual)
          bm::plan::add "Copy IPv4 static ($va4) to $dst.$vid" bm::nm::modify "$dst.$vid" \
            ipv4.method manual ipv4.addresses "$va4" ipv4.gateway "$vg4" ipv4.dns "$vd4" ;;
      esac
    done < <(bm::nm::vlan_cons "$src")
  fi

  if [[ "${BM_SPEC[activate]}" == 1 ]]; then
    bm::plan::add "Activate bond '$dst'" bm::nm::up "$dst"
    for n in "${new_members[@]}"; do
      bm::plan::add "Activate member '$n'" bm::nm::up "bond-port-$n"
    done
  fi

  BM_PLAN_AFFECTED=("$dst" "${new_members[@]}")
  # shellcheck disable=SC2034  # src_opts is consumed by name via nameref
  local -A src_opts=()
  bm::nm::opts_parse "$opts" src_opts
  local clone_expect=up
  [[ "${BM_SPEC[activate]}" == 1 ]] || clone_expect=any
  bm::plan::apply clone "clone $src -> $dst (members $members_csv)" \
    bm::verify::bond "$dst" "${src_opts[mode]:-}" "$members_csv" "" "" "$clone_expect"
}

# ---- repair ---------------------------------------------------------------

# Rebuild port profiles from current kernel state: for every enslaved NIC
# lacking a profile, create one; delete port profiles whose NIC is gone.
bm::wf::repair() {
  local bond="${BM_SPEC[bond]}"
  local uuid
  uuid="$(bm::nm::bond_con_uuid "$bond")" || bm::core::die "no NetworkManager bond profile found for '$bond' (create it first)" "$BM_EX_PRECONDITION" \
    "$(bm::wf::_bond_hint "$bond")"
  bm::facts::bond_exists_kernel "$bond" || bm::core::die "bond '$bond' not present in kernel" "$BM_EX_PRECONDITION" \
    "repair reads what the running bond really uses - bring it up first: nmcli connection up $bond"

  local -a kernel_members=()
  mapfile -t kernel_members < <(bm::facts::bond_members "$bond")

  bm::plan::reset
  # profiles referencing NICs that are no longer members (or don't exist)
  local rec puuid pname pdev
  local -a have_profiles=()
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r puuid pname pdev <<<"$rec"
    if [[ -n "$pdev" ]] && bm::core::in_list "$pdev" "${kernel_members[@]:-}"; then
      have_profiles+=("$pdev")
    else
      bm::plan::add "Delete stale port profile '$pname' (device '${pdev:-?}')" bm::nm::delete "$puuid"
    fi
  done < <(bm::nm::port_cons "$bond")

  local n
  for n in "${kernel_members[@]}"; do
    bm::core::in_list "$n" "${have_profiles[@]:-}" && continue
    bm::plan::add "Create missing port profile for member '$n'" bm::nm::add_port "$uuid" "$n"
  done

  BM_PLAN_AFFECTED=("$bond")
  local members_csv
  members_csv="$(bm::core::join , "${kernel_members[@]}")"
  bm::plan::apply repair "repair port profiles of $bond" \
    bm::verify::bond "$bond" "" "$members_csv" "" ""
}

# ---- vlan add/remove ------------------------------------------------------

bm::wf::vlan_add() {
  local bond="${BM_SPEC[bond]}" tok="${BM_SPEC[vlans]}"
  bm::nm::bond_con_uuid "$bond" >/dev/null || bm::core::die "no NetworkManager bond profile found for '$bond'" "$BM_EX_PRECONDITION" \
    "$(bm::wf::_bond_hint "$bond")"
  bm::wf::_parse_vlan_token "$tok"
  local vif="$bond.$BM_VLAN_ID"
  bm::val::ifname "$vif" || bm::core::die "VLAN interface name '$vif' exceeds 15 characters" "$BM_EX_USAGE" \
    "use a shorter bond name (the VLAN device is named BOND.VID)"
  local existing
  existing="$(bm::nm::vlan_cons "$bond" | awk -F'\x1f' -v id="$BM_VLAN_ID" '$4 == id { print $2 }')"
  if [[ -n "$existing" ]]; then
    BM_PLAN_OUTCOME=noop
    bm::log::say "VLAN $BM_VLAN_ID already exists on $bond ($existing) — nothing to do"
    return "$BM_EX_OK"
  fi

  bm::plan::reset
  bm::plan::add "Create VLAN $BM_VLAN_ID on $bond ($vif)" bm::nm::add_vlan "$bond" "$BM_VLAN_ID"
  bm::wf::_plan_ip_steps "$vif" "$vif" \
    "$BM_VLAN_IP4" "$BM_VLAN_GW4" "$BM_VLAN_DNS4" "$BM_VLAN_IP6" "$BM_VLAN_GW6" "$BM_VLAN_DNS6"
  [[ "${BM_SPEC[activate]}" == 1 ]] && bm::plan::add "Activate '$vif'" bm::nm::up "$vif"

  BM_PLAN_AFFECTED=("$bond" "$vif")
  bm::plan::apply vlan-add "add VLAN $BM_VLAN_ID on $bond" \
    bm::verify::bond "$bond" "" "" "$vif" "$BM_VLAN_GW4"
}

# Change IP configuration on an existing VLAN interface.
bm::wf::vlan_modify() { # vlan_modify <vid> ; ip settings come from BM_SPEC
  local bond="${BM_SPEC[bond]}" vid="$1"
  bm::val::vlan_id "$vid" || bm::core::die "invalid VLAN id '$vid'" "$BM_EX_USAGE" \
    "a VLAN id is a number from 1 to 4094"
  local rec vuuid vname vdev v found_uuid="" found_dev=""
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r vuuid vname vdev v <<<"$rec"
    if [[ "$v" == "$vid" ]]; then
      found_uuid="$vuuid"
      found_dev="${vdev:-$bond.$vid}"
      break
    fi
  done < <(bm::nm::vlan_cons "$bond")
  [[ -n "$found_uuid" ]] || bm::core::die "no VLAN $vid found on $bond (use 'vlan add')" "$BM_EX_PRECONDITION" \
    "see the VLANs it has: $BM_PROG vlan list $bond"

  bm::plan::reset
  bm::wf::_plan_ip_steps "$found_uuid" "$found_dev" \
    "${BM_SPEC[ip4]:-}" "${BM_SPEC[gw4]:-}" "${BM_SPEC[dns4]:-}" \
    "${BM_SPEC[ip6]:-}" "${BM_SPEC[gw6]:-}" "${BM_SPEC[dns6]:-}"
  if (( $(bm::plan::size) > 0 )) && [[ "${BM_SPEC[activate]}" == 1 ]]; then
    bm::plan::add "Re-activate '$found_dev' to apply changes" bm::nm::up "$found_uuid"
  fi

  BM_PLAN_AFFECTED=("$bond" "$found_dev")
  bm::plan::apply vlan-modify "modify VLAN $vid on $bond" \
    bm::verify::bond "$bond" "" "" "$found_dev" "${BM_SPEC[gw4]:-}"
}

bm::wf::vlan_remove() {
  local bond="${BM_SPEC[bond]}" vid="${BM_SPEC[vlan_id]}"
  bm::val::vlan_id "$vid" || bm::core::die "invalid VLAN id '$vid'" "$BM_EX_USAGE" \
    "a VLAN id is a number from 1 to 4094"
  bm::plan::reset
  local rec vuuid vname vdev v
  local found=0
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r vuuid vname vdev v <<<"$rec"
    if [[ "$v" == "$vid" ]]; then
      bm::plan::add "Delete VLAN profile '$vname' (VLAN $vid)" bm::nm::delete "$vuuid"
      found=1
    fi
  done < <(bm::nm::vlan_cons "$bond")
  (( found )) || {
    BM_PLAN_OUTCOME=noop
    bm::log::say "no VLAN $vid found on $bond — nothing to do"
    return "$BM_EX_OK"
  }
  BM_PLAN_AFFECTED=("$bond" "$bond.$vid")
  bm::plan::apply vlan-remove "remove VLAN $vid from $bond" true
}

# ==== 75-diag.sh ====
# lib/75-diag.sh — diagnostics and support bundles.
# One parameterized diagnose (basic/extended) instead of two copy-pasted
# workflows; bundles get a file manifest and an optional --redact pass that
# masks IPs and MACs for tickets leaving the site.

bm::diag::run() { # run <bond> <basic|extended> [ping-target]
  local bond="$1" level="${2:-basic}" target="${3:-}"

  echo "=== $bond: kernel bonding state ==="
  if [[ -r "$BM_PROC_ROOT/net/bonding/$bond" ]]; then
    cat "$BM_PROC_ROOT/net/bonding/$bond"
  else
    echo "(no $BM_PROC_ROOT/net/bonding/$bond — bond not present in kernel)"
  fi
  echo

  echo "=== Health assessment ==="
  local health verdict
  health="$(bm::facts::bond_health "$bond")"
  verdict="$(head -n1 <<<"$health")"
  case "$verdict" in
    healthy) echo "verdict: $(bm::core::c_ok healthy)" ;;
    degraded) echo "verdict: $(bm::core::c_warn degraded)" ;;
    *) echo "verdict: $(bm::core::c_err "$verdict")" ;;
  esac
  tail -n +2 <<<"$health" | sed '/^$/d; s/^/  - /'
  echo

  echo "=== Link state ==="
  ip -br link show 2>/dev/null | awk -v b="$bond" '$1 == b || index($1, b ".") == 1 { print }'
  local -a members=()
  mapfile -t members < <(bm::facts::bond_members "$bond")
  local m
  for m in "${members[@]}"; do
    ip -br link show dev "$m" 2>/dev/null || true
  done
  echo

  echo "=== Member detail ==="
  local mii spd dup lf agg
  for m in "${members[@]}"; do
    mii="$(bm::facts::bond_member_mii "$bond" "$m")"
    read -r spd dup <<<"$(bm::facts::bond_member_speed_duplex "$bond" "$m")"
    lf="$(bm::facts::nic_link_failures "$bond" "$m")"
    printf '  %-14s mii=%-8s speed=%-8s duplex=%-6s link_failures=%s' \
      "$m" "$mii" "$spd" "$dup" "$lf"
    if [[ "$(bm::facts::bond_mode "$bond")" == "802.3ad" ]]; then
      agg="$(bm::facts::bond_member_agg_id "$bond" "$m")"
      printf ' agg_id=%s' "$agg"
    fi
    printf '\n'
  done
  echo

  if [[ "$(bm::facts::bond_mode "$bond")" == "802.3ad" ]]; then
    echo "=== LACP (802.3ad) ==="
    bm::facts::bond_lacp_info "$bond" | sed 's/^/  /'
    local partner
    partner="$(bm::facts::bond_lacp_info "$bond" | awk '$1=="partner_mac"{print $2}')"
    if [[ -z "$partner" || "$partner" == "00:00:00:00:00:00" ]]; then
      echo "  $(bm::core::c_warn 'WARNING: no LACP partner — is the switch side configured as an LACP bundle?')"
    fi
    echo
  fi

  echo "=== Addresses ==="
  ip -br addr show 2>/dev/null | awk -v b="$bond" '$1 == b || index($1, b ".") == 1 { print }'
  echo

  # Reachability through the bond (or its VLANs) — enslaved members carry no
  # IP, so per-member ping is not a meaningful test.
  if [[ -z "$target" ]]; then
    read -r target _ <<<"$(bm::facts::default_gw4)"
  fi
  if [[ -n "$target" ]]; then
    echo "=== Reachability ($target) ==="
    local dev
    for dev in "$bond" $(bm::nm::vlan_cons "$bond" | awk -F'\x1f' '{ print $3 }'); do
      [[ -n "$dev" ]] || continue
      if [[ -n "$(bm::facts::dev_addrs "$dev")" ]]; then
        if ping -c 2 -W 2 -I "$dev" "$target" >/dev/null 2>&1; then
          echo "  via $dev: $(bm::core::c_ok reachable)"
        else
          echo "  via $dev: $(bm::core::c_err 'no reply')"
        fi
      fi
    done
    echo
  fi

  if [[ "$level" == extended ]]; then
    echo "=== NetworkManager profiles ==="
    local rec uuid name dev
    while IFS= read -r rec; do
      IFS=$'\x1f' read -r uuid name dev <<<"$rec"
      printf '  bond profile: %s (uuid %s, ifname %s)\n' "$name" "$uuid" "$dev"
    done < <(bm::nm::bond_cons | awk -F'\x1f' -v b="$bond" '$3 == b || $2 == b { print }')
    while IFS= read -r rec; do
      IFS=$'\x1f' read -r uuid name dev <<<"$rec"
      printf '  port profile: %s (uuid %s, ifname %s)\n' "$name" "$uuid" "$dev"
    done < <(bm::nm::port_cons "$bond")
    while IFS= read -r rec; do
      IFS=$'\x1f' read -r uuid name dev vid <<<"$rec" || true
      printf '  vlan profile: %s (uuid %s, ifname %s, vlan %s)\n' "$name" "$uuid" "$dev" "${vid:-?}"
    done < <(bm::nm::vlan_cons "$bond")
    echo

    if bm::core::have_cmd ethtool; then
      echo "=== ethtool driver info ==="
      for m in "${members[@]}"; do
        echo "--- $m ---"
        ethtool -i "$m" 2>&1 || true
      done
      echo
    fi

    if bm::core::have_cmd journalctl; then
      echo "=== Recent NetworkManager log ==="
      journalctl -u NetworkManager -n 100 --no-pager 2>&1 || true
      echo
    fi
  fi
}

# ---- support bundle -------------------------------------------------------

bm::diag::_redact() { # mask IPv4 addresses and MACs on stdin
  sed -E \
    -e 's/([0-9]{1,3}\.){3}[0-9]{1,3}/IP-REDACTED/g' \
    -e 's/([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/MAC-REDACTED/g'
}

# Collect a support bundle. The archive path is returned in BM_BUNDLE_PATH
# (not on stdout): running this inside $(...) would leak the scratch
# directory, see bm::core::ensure_tmpdir.
BM_BUNDLE_PATH=""
bm::diag::bundle() { # bundle [output-path] [redact:0|1] -> BM_BUNDLE_PATH
  local out="${1:-}" redact="${2:-0}"
  BM_BUNDLE_PATH=""
  bm::core::require_root
  mkdir -p "$BM_SUPPORT_DIR"
  local ts dir archive
  ts="$(date +'%Y%m%d-%H%M%S')"
  if ! bm::core::ensure_tmpdir; then
    bm::log::error "could not create a temporary directory in ${TMPDIR:-/tmp}"
    return 1
  fi
  dir="${BM_TMPDIR:?}/bundle-$ts"
  mkdir -p "$dir"
  [[ -n "$out" ]] || out="$BM_SUPPORT_DIR/support_$ts.tar.gz"

  local filter=cat
  [[ "$redact" == 1 ]] && filter=bm::diag::_redact

  { nmcli -f NAME,UUID,TYPE,DEVICE connection show 2>&1 || true; } | "$filter" >"$dir/nm_connections.txt"
  { nmcli device status 2>&1 || true; } | "$filter" >"$dir/nm_dev_status.txt"
  { ip -d -s link show 2>&1 || true; } | "$filter" >"$dir/ip_link.txt"
  { ip addr show 2>&1 || true; } | "$filter" >"$dir/ip_addr.txt"
  { ip route show 2>&1 || true; } | "$filter" >"$dir/ip_route.txt"
  if bm::core::have_cmd journalctl; then
    { journalctl -u NetworkManager -n 1000 --no-pager 2>&1 || true; } | "$filter" >"$dir/nm_journal.txt"
  fi
  { lsmod 2>/dev/null | grep -i bond || true; } >"$dir/modules.txt"

  local b
  for b in "$BM_PROC_ROOT"/net/bonding/*; do
    [[ -r "$b" ]] || continue
    "$filter" <"$b" >"$dir/proc_$(basename "$b").txt"
    bm::diag::run "$(basename "$b")" basic 2>&1 | "$filter" >"$dir/diagnose_$(basename "$b").txt" || true
  done

  [[ -f "$BM_LOG_FILE" ]] && { "$filter" <"$BM_LOG_FILE" >"$dir/bond_manager.log"; }
  [[ -f "$BM_CONF" ]] && cp "$BM_CONF" "$dir/bond_manager.conf"

  {
    printf 'bundle created: %s\n' "$(bm::core::timestamp)"
    printf 'tool version: %s\n' "$BM_VERSION"
    printf 'redacted: %s\n' "$redact"
    printf 'host: %s\n' "$( { [[ "$redact" == 1 ]] && echo REDACTED; } || hostname 2>/dev/null || echo unknown)"
    printf '\nfiles:\n'
    (cd "$dir" && find . -type f -printf '  %P (%s bytes)\n' | LC_ALL=C sort)
  } >"$dir/MANIFEST.txt"

  if ! tar -C "$(dirname "$dir")" -czf "$out" "$(basename "$dir")"; then
    rm -rf "$dir"
    bm::log::error "support bundle archive creation failed ($out)"
    return 1
  fi
  chmod 0640 "$out" 2>/dev/null || true
  rm -rf "$dir"
  bm::log::info "support bundle created at $out (redacted=$redact)"
  BM_BUNDLE_PATH="$out"
}

# ==== 90-cli.sh ====
# lib/90-cli.sh — argument parsing, dispatch, output commands and the TUI.

bm::cli::usage() {
  cat <<EOF
$BM_PROG v$BM_VERSION — safe NetworkManager bond management for RHEL-like systems

New here? Run  sudo $BM_PROG  for guided menus (with a practice mode).
Explain one command: $BM_PROG help COMMAND   Plain-words intro: $BM_PROG help basics

Common tasks:
$(bm::help::common_tasks)

Usage: $BM_PROG [GLOBAL FLAGS] <command> [ARGS]
       $BM_PROG                      (interactive TUI when run on a terminal)

Global flags:
  -n, --dry-run             Render the plan; execute nothing, write nothing
  -y, --yes                 No prompts; auto-commit when verification passes
      --json                Machine-readable output (list/show/status)
      --debug               Mirror log records to stderr
      --quiet               Suppress progress messages
      --no-color            Disable colored output (NO_COLOR is also honored)
      --plain               Plain numbered menus (serial consoles, basic terminals)
      --rollback-window S   Auto-rollback window in seconds (default: config)
      --no-checkpoint       Skip NM checkpoints (fall back to deadman/snapshot)
      --force-unsafe        Allow touching your SSH egress device w/o checkpoint
  -V, --version             Print version
  -h, --help                This help (after a command: help for that command)

Read-only commands (no root, write nothing):
  list                      One line per bond: name, mode, health
  show BOND                 Full bond detail (--json supported)
  status [BOND]             Health summary; exit 0 healthy / 10 degraded / 11 down
  diagnose BOND [--extended] [--target IP]
  verify BOND               Re-run the verification checks against kernel state
  nics [--all]              Network ports: link, speed, bond, "free - good to use"
  doctor                    Environment preflight + protection-tier report
  config show|path          Effective configuration / config file path
  completion bash           Emit bash completion script
  help [COMMAND|TOPIC]      Plain-English help with examples

Change commands (root; guarded by plan → snapshot → checkpoint → verify):
  create BOND --mode MODE --members IF1,IF2 [options]   Create a bond
  modify BOND [--mode MODE] [--opt k=v]... [--del-opt k]... [ip/mtu flags]
  add-member BOND IF[,IF...]
  remove-member BOND IF[,IF...]
  swap-member BOND --old IF --new IF     Add new first, then remove old
  remove BOND [--keep-vlans]             Delete bond + member/VLAN profiles
  vlan add BOND VID[:ip4=..;gw4=..] | vlan modify BOND VID [ip flags]
  vlan remove BOND VID | vlan list BOND
  clone SRC DST --members IF[,IF...] [--copy-ip] [--copy-vlans]
  repair BOND                            Rebuild port profiles from kernel state

Create/modify IP + tuning flags:
  --ip4 dhcp|none|CIDR[,CIDR]  --gw4 A  --dns4 A,B
  --ip6 auto|dhcp|none|CIDR[,CIDR]  --gw6 A  --dns6 A,B
  --mtu N   --opt key=value (repeatable)   --vlan VID[:ip4=..;gw4=..] (repeatable)
  --miimon MS  --primary IF  --lacp-rate fast|slow  --xmit-hash POLICY
  --arp-interval MS --arp-targets IP[,IP]  --min-links N  --no-activate

Safety commands:
  commit                    Confirm a pending change (disarms auto-rollback)
  rollback [--snapshot ID]  Revert pending change, or restore a snapshot
  snapshot create|list|diff ID|restore [ID]|prune
  bundle [--output PATH] [--redact]      Support bundle
  init                      Install default config + logrotate policy

Bond modes: ${BM_MODES[*]}

Exit codes: 0 ok/no-op | 1 error | 2 usage | 3 precondition | 4 locked
            5 verify-failed-and-rolled-back | 6 applied-but-unconfirmed
            10 degraded | 11 down

Legacy flags: --status ≡ status, --export-json PATH ≡ status --json > PATH

Help topics ($BM_PROG help TOPIC): ${BM_HELP_TOPICS[*]}
EOF
}

# A flag that needs a value got none (or got the next flag instead).
bm::cli::_need_arg() { # _need_arg <flag> <value>
  local flag="$1" val="${2:-}" ex=""
  if [[ -n "$val" && "$val" != --* ]]; then
    return 0
  fi
  case "$flag" in
    --mode) ex="--mode active-backup" ;;
    --members) ex="--members ens1f0,ens1f1" ;;
    --opt) ex="--opt miimon=100" ;;
    --del-opt) ex="--del-opt primary" ;;
    --mtu) ex="--mtu 9000" ;;
    --ip4) ex="--ip4 10.0.0.10/24 (or dhcp / none)" ;;
    --gw4) ex="--gw4 10.0.0.1" ;;
    --dns4) ex="--dns4 10.0.0.53,10.0.0.54" ;;
    --ip6) ex="--ip6 2001:db8::10/64 (or auto / dhcp / none)" ;;
    --gw6) ex="--gw6 2001:db8::1" ;;
    --dns6) ex="--dns6 2001:db8::53" ;;
    --vlan) ex="--vlan 120" ;;
    --miimon) ex="--miimon 100" ;;
    --primary) ex="--primary ens1f0" ;;
    --lacp-rate) ex="--lacp-rate fast" ;;
    --xmit-hash) ex="--xmit-hash layer3+4" ;;
    --arp-interval) ex="--arp-interval 1000" ;;
    --arp-targets) ex="--arp-targets 10.0.0.1" ;;
    --min-links) ex="--min-links 1" ;;
    --old) ex="--old ens1f0" ;;
    --new) ex="--new ens2f0" ;;
    --target) ex="--target 10.0.0.1" ;;
    --snapshot) ex="--snapshot $(date +%Y%m%d)-120000 (see: $BM_PROG snapshot list)" ;;
    --output) ex="--output /root/bond-support.tar.gz" ;;
    --rollback-window) ex="--rollback-window 300" ;;
    --export-json) ex="--export-json /var/lib/metrics/bonds.json" ;;
  esac
  bm::core::die "flag '$flag' needs a value" "$BM_EX_USAGE" "${ex:+for example: $ex}"
}

BM_CLI_CHANGE_FLAGS=(--mode --members --opt --del-opt --mtu --ip4 --gw4 --dns4 --ip6 --gw6
  --dns6 --vlan --miimon --primary --lacp-rate --xmit-hash --arp-interval --arp-targets
  --min-links --no-activate --copy-ip --copy-vlans --keep-vlans --old --new)

# What the operator probably meant by an unknown flag or a stray word.
bm::cli::_flag_hint() { # _flag_hint <token>
  local t="$1" m near n all=1
  if [[ "$t" != -* ]]; then
    m="$(bm::help::mode_alias "$t")"
    if [[ -n "$m" ]]; then
      printf "did you mean '--mode %s'?" "$m"
      return 0
    fi
    if bm::val::ipv4_cidr "$t"; then
      printf "did you mean '--ip4 %s'?" "$t"
      return 0
    fi
    bm::core::split_list "$t"
    for n in "${BM_LIST[@]}"; do
      bm::facts::nic_exists "$n" || all=0
    done
    if (( all && ${#BM_LIST[@]} > 0 )); then
      printf "did you mean '--members %s'?" "$t"
      return 0
    fi
    printf 'values go after the flag they belong to, e.g. --mode active-backup - see: %s help %s' \
      "$BM_PROG" "${BM_CUR_CMD:-}"
    return 0
  fi
  near="$(bm::core::closest "$t" "${BM_CLI_CHANGE_FLAGS[@]}")"
  if [[ -n "$near" ]]; then
    printf "did you mean '%s'? (all flags: %s help %s)" "$near" "$BM_PROG" "${BM_CUR_CMD:-}"
  else
    printf 'see the flags this command takes: %s help %s' "$BM_PROG" "${BM_CUR_CMD:-}"
  fi
}

# ---- read-only output commands --------------------------------------------

bm::cli::preflight_read() {
  bm::core::have_cmd nmcli || bm::core::die "nmcli not found; install NetworkManager" "$BM_EX_PRECONDITION" \
    "install it with: dnf install NetworkManager && systemctl enable --now NetworkManager"
}

# Can changes run at all right now? Never dies (the menus ask before every
# wizard). 0 = yes; 3 = no, with BM_CLI_BLOCKER=no-nmcli|not-root|nm-inactive
# and a plain explanation in BM_CLI_BLOCKER_MSG.
BM_CLI_BLOCKER=""
BM_CLI_BLOCKER_MSG=""
bm::cli::mutate_blocker() {
  BM_CLI_BLOCKER=""
  BM_CLI_BLOCKER_MSG=""
  if ! bm::core::have_cmd nmcli; then
    BM_CLI_BLOCKER=no-nmcli
    BM_CLI_BLOCKER_MSG="NetworkManager (nmcli) is not installed, so nothing can be changed."
    return "$BM_EX_PRECONDITION"
  fi
  if ! bm::core::is_root; then
    BM_CLI_BLOCKER=not-root
    BM_CLI_BLOCKER_MSG="You are not root, so changes are not possible. Start bond-manager with sudo to make real changes."
    return "$BM_EX_PRECONDITION"
  fi
  if bm::core::have_cmd systemctl && ! systemctl is-active --quiet NetworkManager; then
    BM_CLI_BLOCKER=nm-inactive
    BM_CLI_BLOCKER_MSG="NetworkManager is not running. Start it first: systemctl enable --now NetworkManager"
    return "$BM_EX_PRECONDITION"
  fi
  return 0
}

bm::cli::preflight_mutate() {
  bm::cli::preflight_read
  # a dry-run only renders the plan: no root, no NM, no module loading needed
  (( BM_DRY_RUN )) && return 0
  bm::core::require_root
  if bm::core::have_cmd systemctl && ! systemctl is-active --quiet NetworkManager; then
    bm::core::die "NetworkManager is not active (systemctl enable --now NetworkManager)" "$BM_EX_PRECONDITION" \
      "start it with: systemctl enable --now NetworkManager"
  fi
  if [[ ! -e "$BM_PROC_ROOT/net/bonding" ]] && bm::core::have_cmd modprobe; then
    modprobe bonding 2>/dev/null || bm::log::warn "could not load bonding module (NM may load it on demand)"
  fi
}

bm::cli::all_bonds() { # kernel bonds ∪ NM bond profiles
  {
    bm::facts::kernel_bonds
    bm::nm::bond_cons | awk -F'\x1f' '{ print ($3 != "" ? $3 : $2) }'
  } | LC_ALL=C sort -u | sed '/^$/d'
}

bm::cli::_bond_json() { # one bond as a JSON object
  local b="$1"
  local mode health verdict
  mode="$(bm::facts::bond_mode "$b")"
  health="$(bm::facts::bond_health "$b")"
  verdict="$(head -n1 <<<"$health")"
  local reasons_json
  reasons_json="$(tail -n +2 <<<"$health" | sed '/^$/d' | bm::json::arr_of_lines)"

  local members_json="" m mii spd dup lf
  while IFS= read -r m; do
    [[ -n "$m" ]] || continue
    mii="$(bm::facts::bond_member_mii "$b" "$m")"
    read -r spd dup <<<"$(bm::facts::bond_member_speed_duplex "$b" "$m")"
    lf="$(bm::facts::nic_link_failures "$b" "$m")"
    [[ -n "$members_json" ]] && members_json+=","
    members_json+="{\"name\":$(bm::json::str "$m"),\"mii\":$(bm::json::str "$mii"),\"speed\":$(bm::json::num_or_str "$spd"),\"duplex\":$(bm::json::str "$dup"),\"link_failures\":$(bm::json::num_or_str "$lf")}"
  done < <(bm::facts::bond_members "$b")

  local addrs_json vlans_json
  addrs_json="$(bm::facts::dev_addrs "$b" | bm::json::arr_of_lines)"
  vlans_json="$(bm::nm::vlan_cons "$b" | awk -F'\x1f' '{ print $3 }' | bm::json::arr_of_lines)"

  local active primary miimon
  active="$(bm::facts::bond_proc_value "$b" "Currently Active Slave")"
  primary="$(bm::facts::bond_proc_value "$b" "Primary Slave")"
  miimon="$(bm::facts::bond_proc_value "$b" "MII Polling Interval (ms)")"

  printf '{"name":%s,"mode":%s,"health":%s,"reasons":%s,"miimon":%s,"active_member":%s,"primary":%s,"members":[%s],"addresses":%s,"vlans":%s}' \
    "$(bm::json::str "$b")" "$(bm::json::str "$mode")" "$(bm::json::str "$verdict")" \
    "$reasons_json" "$(bm::json::num_or_str "${miimon:-unknown}")" \
    "$(bm::json::str "${active:-}")" "$(bm::json::str "${primary:-}")" \
    "$members_json" "$addrs_json" "$vlans_json"
}

bm::cli::_bonds_json_doc() { # full inventory document
  local bonds_json="" b
  while IFS= read -r b; do
    [[ -n "$b" ]] || continue
    [[ -n "$bonds_json" ]] && bonds_json+=","
    bonds_json+="$(bm::cli::_bond_json "$b")"
  done < <(bm::cli::all_bonds)
  printf '{"schema_version":%s,"generated":%s,"host":%s,"tool_version":%s,"bonds":[%s]}\n' \
    "$BM_JSON_SCHEMA_VERSION" "$(bm::json::str "$(bm::core::timestamp)")" \
    "$(bm::json::str "$(hostname 2>/dev/null || echo unknown)")" \
    "$(bm::json::str "$BM_VERSION")" "$bonds_json"
}

bm::cli::cmd_list() {
  bm::cli::preflight_read
  if (( BM_JSON )); then
    bm::cli::_bonds_json_doc
    return "$BM_EX_OK"
  fi
  local b any=0 mode verdict
  while IFS= read -r b; do
    [[ -n "$b" ]] || continue
    any=1
    mode="$(bm::facts::bond_mode "$b")"
    verdict="$(bm::facts::bond_health "$b" | head -n1)"
    printf '%-16s %-16s %s\n' "$b" "$mode" "$verdict"
  done < <(bm::cli::all_bonds)
  (( any )) || echo "No bonds found."
  return "$BM_EX_OK"
}

bm::cli::_show_human() {
  local b="$1"
  local health verdict
  health="$(bm::facts::bond_health "$b")"
  verdict="$(head -n1 <<<"$health")"
  echo "=== $b ==="
  printf 'mode:            %s\n' "$(bm::facts::bond_mode "$b")"
  case "$verdict" in
    healthy) printf 'health:          %s\n' "$(bm::core::c_ok healthy)" ;;
    degraded) printf 'health:          %s\n' "$(bm::core::c_warn degraded)" ;;
    *) printf 'health:          %s\n' "$(bm::core::c_err "$verdict")" ;;
  esac
  tail -n +2 <<<"$health" | sed '/^$/d; s/^/                   - /'
  local miimon active primary
  miimon="$(bm::facts::bond_proc_value "$b" "MII Polling Interval (ms)")"
  active="$(bm::facts::bond_proc_value "$b" "Currently Active Slave")"
  primary="$(bm::facts::bond_proc_value "$b" "Primary Slave")"
  [[ -n "$miimon" ]] && printf 'miimon:          %s ms\n' "$miimon"
  [[ -n "$active" ]] && printf 'active member:   %s\n' "$active"
  [[ -n "$primary" && "$primary" != None ]] && printf 'primary:         %s\n' "$primary"
  echo "members:"
  local m mii spd dup lf
  while IFS= read -r m; do
    [[ -n "$m" ]] || continue
    mii="$(bm::facts::bond_member_mii "$b" "$m")"
    read -r spd dup <<<"$(bm::facts::bond_member_speed_duplex "$b" "$m")"
    lf="$(bm::facts::nic_link_failures "$b" "$m")"
    printf '  %-14s mii=%-8s speed=%-10s duplex=%-6s link_failures=%s\n' \
      "$m" "$mii" "$spd" "$dup" "$lf"
  done < <(bm::facts::bond_members "$b")
  local addrs
  addrs="$(bm::facts::dev_addrs "$b")"
  if [[ -n "$addrs" ]]; then
    echo "addresses:"
    sed 's/^/  /' <<<"$addrs"
  fi
  local rec uuid name dev vid
  local vl=""
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r uuid name dev vid <<<"$rec"
    vl+="  $dev (vlan $vid, profile '$name')"$'\n'
  done < <(bm::nm::vlan_cons "$b")
  if [[ -n "$vl" ]]; then
    echo "vlans:"
    printf '%s' "$vl"
  fi
}

bm::cli::cmd_show() {
  local bond="${1:-}"
  [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG show BOND" "$BM_EX_USAGE"
  bm::cli::preflight_read
  if (( BM_JSON )); then
    printf '{"schema_version":%s,"bond":%s}\n' "$BM_JSON_SCHEMA_VERSION" "$(bm::cli::_bond_json "$bond")"
    return "$BM_EX_OK"
  fi
  bm::cli::_show_human "$bond"
}

bm::cli::cmd_status() {
  local bond="${1:-}"
  bm::cli::preflight_read
  local -a bonds=()
  if [[ -n "$bond" ]]; then
    bonds=("$bond")
  else
    mapfile -t bonds < <(bm::cli::all_bonds)
  fi

  if (( BM_JSON )); then
    if [[ -n "$bond" ]]; then
      printf '{"schema_version":%s,"bonds":[%s]}\n' \
        "$BM_JSON_SCHEMA_VERSION" "$(bm::cli::_bond_json "$bond")"
    else
      bm::cli::_bonds_json_doc
    fi
  fi

  local worst=healthy b verdict
  for b in "${bonds[@]}"; do
    [[ -n "$b" ]] || continue
    verdict="$(bm::facts::bond_health "$b" | head -n1)"
    if ! (( BM_JSON )); then
      bm::cli::_show_human "$b"
      echo
    fi
    case "$verdict" in
      down) worst=down ;;
      degraded) [[ "$worst" == healthy ]] && worst=degraded ;;
    esac
  done
  if (( ${#bonds[@]} == 0 )) && ! (( BM_JSON )); then
    echo "No bonds found."
  fi
  case "$worst" in
    down) return "$BM_EX_DOWN" ;;
    degraded) return "$BM_EX_DEGRADED" ;;
    *) return "$BM_EX_OK" ;;
  esac
}

bm::cli::_doc_check() {
  local level="$1" msg="$2"
  case "$level" in
    ok) printf '[%s] %s\n' "$(bm::core::c_ok ' ok ')" "$msg" ;;
    warn) printf '[%s] %s\n' "$(bm::core::c_warn 'warn')" "$msg" ;;
    fail) printf '[%s] %s\n' "$(bm::core::c_err 'FAIL')" "$msg" ;;
  esac
}

bm::cli::cmd_doctor() {
  bm::log::set_op doctor
  local hard_fail=0
  echo "bond-manager doctor — environment preflight"
  echo

  if bm::core::have_cmd nmcli; then
    bm::cli::_doc_check ok "nmcli present ($(nmcli --version 2>/dev/null | head -n1))"
  else
    bm::cli::_doc_check fail "nmcli not found — install NetworkManager"
    hard_fail=1
  fi
  if bm::core::have_cmd systemctl; then
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
      bm::cli::_doc_check ok "NetworkManager service active"
    else
      bm::cli::_doc_check fail "NetworkManager service not active"
      hard_fail=1
    fi
  else
    bm::cli::_doc_check warn "systemctl not found — cannot verify NetworkManager state"
  fi
  if [[ -e "$BM_PROC_ROOT/net/bonding" ]]; then
    bm::cli::_doc_check ok "bonding kernel module loaded"
  elif bm::core::have_cmd modprobe && modprobe -n bonding >/dev/null 2>&1; then
    bm::cli::_doc_check ok "bonding kernel module available (will load on demand)"
  else
    bm::cli::_doc_check warn "bonding kernel module not detected"
  fi

  local tier
  tier="$(bm::ckpt::probe_tier)"
  case "$tier" in
    checkpoint)
      bm::cli::_doc_check ok "protection tier: checkpoint (NM D-Bus checkpoints with server-side auto-rollback)" ;;
    deadman)
      bm::cli::_doc_check warn "protection tier: deadman (no NM D-Bus checkpoint; transient systemd rollback timer)" ;;
    snapshot)
      bm::cli::_doc_check warn "protection tier: snapshot-only (no busctl, no systemd-run — rollback is manual)" ;;
  esac

  local t
  for t in ip tar ping awk sed; do
    if bm::core::have_cmd "$t"; then
      bm::cli::_doc_check ok "$t present"
    else
      bm::cli::_doc_check fail "required tool '$t' missing"
      hard_fail=1
    fi
  done
  for t in ethtool journalctl flock logger restorecon; do
    if bm::core::have_cmd "$t"; then
      bm::cli::_doc_check ok "$t present"
    else
      bm::cli::_doc_check warn "optional tool '$t' missing"
    fi
  done

  if bm::core::have_cmd getenforce; then
    bm::cli::_doc_check ok "SELinux: $(getenforce 2>/dev/null || echo unknown)"
  fi
  if [[ -f "$BM_CONF" ]]; then
    bm::cli::_doc_check ok "config present: $BM_CONF"
  else
    bm::cli::_doc_check warn "no config file (defaults in effect; run '$BM_PROG init' to install one)"
  fi
  if bm::ckpt::load_pending; then
    local secs_left=$(( ${BM_PENDING_DEADLINE:-0} - $(bm::core::epoch) ))
    bm::cli::_doc_check warn "PENDING CHANGE: ${BM_PENDING_SUMMARY:-?} (auto-rollback in ${secs_left}s) — run '$BM_PROG commit' or '$BM_PROG rollback'"
  fi

  echo
  if (( hard_fail )); then
    echo "verdict: $(bm::core::c_err 'not ready')"
    echo "  Next step: fix the FAIL lines above, then run '$BM_PROG doctor' again."
    return "$BM_EX_PRECONDITION"
  fi
  echo "verdict: $(bm::core::c_ok ready) (protection tier: $tier)"
  echo "  $(bm::help::tier_sentence "$tier")"
  echo "  Next step: '$BM_PROG list' to see your bonds, or 'sudo $BM_PROG' for guided menus."
  return "$BM_EX_OK"
}

bm::cli::cmd_config() {
  case "${1:-show}" in
    path) printf '%s\n' "$BM_CONF" ;;
    show)
      echo "# effective configuration (source: ${BM_CONF}$([[ -f "$BM_CONF" ]] || echo ' — missing, defaults in effect'))"
      local k
      while IFS= read -r k; do
        printf '%s="%s"\n' "$k" "${BM_CFG[$k]}"
      done < <(printf '%s\n' "${!BM_CFG[@]}" | LC_ALL=C sort)
      ;;
    *) bm::core::die "usage: $BM_PROG config show|path" "$BM_EX_USAGE" ;;
  esac
}

# ---- nics ---------------------------------------------------------------------

# Does <nic> carry this session's SSH traffic? True for the egress device
# itself, and for the members of a bond (or of a bond under a VLAN) that is.
bm::cli::_carries_ssh() { # _carries_ssh <nic> <master> <ssh-dev> <ssh-parent>
  local n="$1" master="$2" dev="$3" parent="$4"
  [[ -n "$dev" ]] || return 1
  [[ "$n" == "$dev" ]] && return 0
  [[ -n "$master" && ( "$master" == "$dev" || "$master" == "$parent" ) ]] && return 0
  return 1
}

bm::cli::cmd_nics() {
  local all=0
  while (( $# )); do
    case "$1" in
      --all) all=1; shift ;;
      *) bm::core::die "unknown flag '$1'" "$BM_EX_USAGE" "the only flag is --all" ;;
    esac
  done
  if (( BM_JSON )); then
    bm::core::die "nics has no JSON output yet" "$BM_EX_USAGE" "for bonds use: $BM_PROG --json list"
  fi
  local ssh_dev ssh_parent=""
  ssh_dev="$(bm::facts::ssh_egress_dev || true)"
  if [[ -n "$ssh_dev" ]]; then
    ssh_parent="$(bm::facts::vlan_parent "$ssh_dev")"
  fi

  local d n hidden=0 allowed
  local -a names=()
  for d in "$BM_SYS_ROOT"/class/net/*; do
    [[ -e "$d" ]] || continue
    n="${d##*/}"
    [[ "$n" == lo ]] && continue
    bm::facts::bond_exists_kernel "$n" && continue # a bond is not a port
    if ! bm::facts::nic_allowed "$n" && (( ! all )); then
      hidden=$(( hidden + 1 ))
      continue
    fi
    names+=("$n")
  done

  if (( ${#names[@]} == 0 )); then
    echo "No network ports found that bond-manager may use."
    if (( hidden > 0 )); then
      echo "($hidden hidden by the NIC policy - see them with: $BM_PROG nics --all)"
    fi
    return "$BM_EX_OK"
  fi

  printf '%-15s %-8s %-6s %-10s %-20s %s\n' NIC LINK SPEED IN-BOND ADDRESSES NOTE
  local link speed inbond addrs first extra note active
  local -a free_up=() addr_list=()
  for n in "${names[@]}"; do
    bm::facts::nic_info "$n" || true
    case "$BM_NIC_LINK" in
      up) link=up ;;
      no-link) link="no link" ;;
      off) link=off ;;
      *) link="?" ;;
    esac
    speed="$(bm::help::speed_label "$BM_NIC_SPEED")"
    inbond="${BM_NIC_MASTER:--}"
    mapfile -t addr_list < <(bm::facts::dev_addrs "$n" | grep -v '^fe80:' || true)
    first="${addr_list[0]:-}"
    extra=""
    if (( ${#addr_list[@]} > 1 )); then extra=" +$(( ${#addr_list[@]} - 1 ))"; fi
    addrs="${first:--}$extra"
    allowed=1
    bm::facts::nic_allowed "$n" || allowed=0
    local vpar
    vpar="$(bm::facts::vlan_parent "$n")"
    if (( ! allowed )); then
      note="$(bm::core::c_dim "hidden by the NIC policy")"
    elif [[ -n "$vpar" ]]; then
      note="VLAN interface on $vpar"
      if [[ "$n" == "$ssh_dev" ]]; then note+=" - $(bm::core::c_warn "carries your SSH connection")"; fi
    elif bm::cli::_carries_ssh "$n" "$BM_NIC_MASTER" "$ssh_dev" "$ssh_parent"; then
      note="$(bm::core::c_warn "carries your SSH connection")"
      [[ -n "$BM_NIC_MASTER" ]] && note="$(bm::core::c_warn "in $BM_NIC_MASTER - carries your SSH connection")"
    elif [[ -n "$BM_NIC_MASTER" ]]; then
      active="$(bm::facts::bond_proc_value "$BM_NIC_MASTER" "Currently Active Slave")"
      note="in $BM_NIC_MASTER"
      [[ "$active" == "$n" ]] && note+=" (active)"
    elif [[ -n "$first" ]]; then
      note="$(bm::core::c_warn "has an IP - probably in use")"
    elif [[ "$BM_NIC_LINK" == up ]]; then
      note="$(bm::core::c_ok "free - good to use")"
      free_up+=("$n")
    elif [[ "$BM_NIC_LINK" == no-link ]]; then
      note="$(bm::core::c_warn "free, but no link - cable or switch port?")"
    elif [[ "$BM_NIC_LINK" == off ]]; then
      note="$(bm::core::c_warn "free, but switched off (ip link set $n up)")"
    else
      note="free"
    fi
    printf '%-15s %-8s %-6s %-10s %-20s %s\n' "$n" "$link" "$speed" "$inbond" "$addrs" "$note"
  done

  echo
  if (( ${#free_up[@]} >= 2 )); then
    local b=0
    while bm::facts::bond_exists_kernel "bond$b" || bm::facts::nic_exists "bond$b"; do
      b=$(( b + 1 ))
    done
    echo "Tip: build a bond from two free ports (preview first, -n changes nothing):"
    echo "  $BM_PROG -n create bond$b --mode active-backup --members ${free_up[0]},${free_up[1]}"
  elif (( ${#free_up[@]} == 1 )); then
    echo "Tip: '${free_up[0]}' is free - add it to a bond, or use it to move one: $BM_PROG help swap-member"
  fi
  if (( hidden > 0 )); then
    echo "($hidden more hidden by the NIC policy - see them with: $BM_PROG nics --all)"
  fi
  return "$BM_EX_OK"
}

# ---- help ---------------------------------------------------------------------

bm::cli::cmd_help() {
  local x="${1:-}"
  if [[ -z "$x" ]]; then
    bm::cli::usage
    return "$BM_EX_OK"
  fi
  if bm::help::is_command "$x"; then
    bm::help::command "$x"
    return "$BM_EX_OK"
  fi
  if bm::help::is_topic "$x"; then
    bm::help::topic "$x"
    return "$BM_EX_OK"
  fi
  local sug
  sug="$(bm::help::synonym "$x")"
  if [[ -z "$sug" ]]; then
    sug="$(bm::core::closest "$x" "${BM_HELP_COMMANDS[@]}" "${BM_HELP_TOPICS[@]}")"
  fi
  printf '%s: no help for "%s"\n' "$BM_PROG" "$x" >&2
  if [[ -n "$sug" ]]; then
    printf '  Did you mean: %s help %s\n' "$BM_PROG" "$sug" >&2
  fi
  printf '  Commands: %s\n' "${BM_HELP_COMMANDS[*]}" >&2
  printf '  Topics:   %s\n' "${BM_HELP_TOPICS[*]}" >&2
  return "$BM_EX_USAGE"
}

# ---- mutation command parsers ---------------------------------------------

# Parse shared create/modify flags into BM_SPEC. Consumes "$@" after the
# positional args have been shifted away.
bm::cli::_parse_change_flags() {
  local -a opt_pairs=()
  local -a vlan_tokens=()
  while (( $# )); do
    case "$1" in
      --mode) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[mode]="$2"; shift 2 ;;
      --members) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[members]="$2"; shift 2 ;;
      --opt) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("$2"); shift 2 ;;
      --del-opt) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[del_opts]="${BM_SPEC[del_opts]:-} $2"; shift 2 ;;
      --mtu) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[mtu]="$2"; shift 2 ;;
      --ip4) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[ip4]="$2"; shift 2 ;;
      --gw4) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[gw4]="$2"; shift 2 ;;
      --dns4) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[dns4]="$2"; shift 2 ;;
      --ip6) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[ip6]="$2"; shift 2 ;;
      --gw6) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[gw6]="$2"; shift 2 ;;
      --dns6) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[dns6]="$2"; shift 2 ;;
      --vlan) bm::cli::_need_arg "$1" "${2-}"; vlan_tokens+=("$2"); shift 2 ;;
      --miimon) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("miimon=$2"); shift 2 ;;
      --primary) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("primary=$2"); shift 2 ;;
      --lacp-rate) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("lacp_rate=$2"); shift 2 ;;
      --xmit-hash) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("xmit_hash_policy=$2"); shift 2 ;;
      --arp-interval) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("arp_interval=$2"); shift 2 ;;
      --arp-targets) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("arp_ip_target=$2"); shift 2 ;;
      --min-links) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("min_links=$2"); shift 2 ;;
      --no-activate) BM_SPEC[activate]=0; shift ;;
      --copy-ip) BM_SPEC[copy_ip]=1; shift ;;
      --copy-vlans) BM_SPEC[copy_vlans]=1; shift ;;
      --keep-vlans) BM_SPEC[keep_vlans]=1; shift ;;
      --old) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[old]="$2"; shift 2 ;;
      --new) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[new]="$2"; shift 2 ;;
      *) bm::core::die "unknown flag '$1'" "$BM_EX_USAGE" "$(bm::cli::_flag_hint "$1")" ;;
    esac
  done
  if (( ${#opt_pairs[@]} > 0 )); then
    BM_SPEC[opts]="$(bm::core::join , "${opt_pairs[@]}")"
  fi
  if (( ${#vlan_tokens[@]} > 0 )); then
    BM_SPEC[vlans]="${vlan_tokens[*]}"
  fi
}

bm::cli::cmd_create() {
  local bond="${1:-}"
  [[ -n "$bond" && "$bond" != --* ]] || bm::core::die "usage: $BM_PROG create BOND --mode MODE --members IF1,IF2 [...]" "$BM_EX_USAGE"
  shift
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::cli::_parse_change_flags "$@"
  bm::wf::create
}

bm::cli::cmd_modify() {
  local bond="${1:-}"
  [[ -n "$bond" && "$bond" != --* ]] || bm::core::die "usage: $BM_PROG modify BOND [flags]" "$BM_EX_USAGE"
  shift
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::cli::_parse_change_flags "$@"
  bm::wf::modify
}

bm::cli::cmd_add_member() {
  local bond="${1:-}" members_csv="${2:-}"
  [[ -n "$bond" && -n "$members_csv" ]] || bm::core::die "usage: $BM_PROG add-member BOND IF[,IF...]" "$BM_EX_USAGE"
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[members]="$members_csv"
  bm::wf::add_members
}

bm::cli::cmd_remove_member() {
  local bond="${1:-}" members_csv="${2:-}"
  [[ -n "$bond" && -n "$members_csv" ]] || bm::core::die "usage: $BM_PROG remove-member BOND IF[,IF...]" "$BM_EX_USAGE"
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[members]="$members_csv"
  bm::wf::remove_members
}

bm::cli::cmd_swap_member() {
  local bond="${1:-}"
  [[ -n "$bond" && "$bond" != --* ]] || bm::core::die "usage: $BM_PROG swap-member BOND --old IF --new IF" "$BM_EX_USAGE"
  shift
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::cli::_parse_change_flags "$@"
  [[ -n "${BM_SPEC[old]:-}" && -n "${BM_SPEC[new]:-}" ]] || bm::core::die "swap-member requires --old and --new" "$BM_EX_USAGE"
  bm::wf::swap_member
}

bm::cli::cmd_remove() {
  local bond="${1:-}"
  [[ -n "$bond" && "$bond" != --* ]] || bm::core::die "usage: $BM_PROG remove BOND [--keep-vlans]" "$BM_EX_USAGE"
  shift
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::cli::_parse_change_flags "$@"
  bm::wf::remove
}

bm::cli::cmd_vlan() {
  local action="${1:-}" bond="${2:-}"
  case "$action" in
    list)
      [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG vlan list BOND" "$BM_EX_USAGE"
      bm::cli::preflight_read
      local rec uuid name dev vid
      while IFS= read -r rec; do
        IFS=$'\x1f' read -r uuid name dev vid <<<"$rec"
        printf '%-18s vlan=%-5s profile=%s\n' "$dev" "$vid" "$name"
      done < <(bm::nm::vlan_cons "$bond")
      ;;
    add)
      local tok="${3:-}"
      [[ -n "$bond" && -n "$tok" ]] || bm::core::die "usage: $BM_PROG vlan add BOND VID[:ip4=..;gw4=..]" "$BM_EX_USAGE"
      bm::cli::preflight_mutate
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlans]="$tok"
      bm::wf::vlan_add
      ;;
    modify)
      local vid="${3:-}"
      [[ -n "$bond" && -n "$vid" ]] || bm::core::die "usage: $BM_PROG vlan modify BOND VID [ip flags]" "$BM_EX_USAGE"
      shift 3
      bm::cli::preflight_mutate
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      bm::cli::_parse_change_flags "$@"
      bm::wf::vlan_modify "$vid"
      ;;
    remove)
      local vid2="${3:-}"
      [[ -n "$bond" && -n "$vid2" ]] || bm::core::die "usage: $BM_PROG vlan remove BOND VID" "$BM_EX_USAGE"
      bm::cli::preflight_mutate
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlan_id]="$vid2"
      bm::wf::vlan_remove
      ;;
    *) bm::core::die "usage: $BM_PROG vlan add|modify|remove|list BOND ..." "$BM_EX_USAGE" ;;
  esac
}

bm::cli::cmd_clone() {
  local src="${1:-}" dst="${2:-}"
  [[ -n "$src" && -n "$dst" && "$dst" != --* ]] || bm::core::die "usage: $BM_PROG clone SRC DST --members IF[,IF...] [--copy-ip] [--copy-vlans]" "$BM_EX_USAGE"
  shift 2
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[src]="$src"
  BM_SPEC[bond]="$dst"
  bm::cli::_parse_change_flags "$@"
  [[ -n "${BM_SPEC[members]:-}" ]] || bm::core::die "clone requires --members" "$BM_EX_USAGE"
  bm::wf::clone
}

bm::cli::cmd_repair() {
  local bond="${1:-}"
  [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG repair BOND" "$BM_EX_USAGE"
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::wf::repair
}

bm::cli::cmd_verify() {
  local bond="${1:-}"
  [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG verify BOND" "$BM_EX_USAGE"
  bm::cli::preflight_read
  bm::verify::reset
  local members_csv
  members_csv="$(bm::facts::bond_members "$bond" | paste -sd, -)"
  bm::verify::bond "$bond" "$(bm::facts::bond_mode "$bond")" "$members_csv" "$bond" ""
  bm::verify::render
  bm::verify::failed && return "$BM_EX_ERR"
  return "$BM_EX_OK"
}

bm::cli::cmd_diagnose() {
  local bond="" level=basic target=""
  while (( $# )); do
    case "$1" in
      --extended) level=extended; shift ;;
      --target) bm::cli::_need_arg "$1" "${2-}"; target="$2"; shift 2 ;;
      -*) bm::core::die "unknown flag '$1'" "$BM_EX_USAGE" ;;
      *) bond="$1"; shift ;;
    esac
  done
  [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG diagnose BOND [--extended] [--target IP]" "$BM_EX_USAGE"
  bm::cli::preflight_read
  bm::diag::run "$bond" "$level" "$target"
}

# ---- safety commands ------------------------------------------------------

bm::cli::cmd_commit() {
  if (( BM_DRY_RUN )); then
    if bm::ckpt::load_pending; then
      bm::log::say "[dry-run] would commit the pending change: ${BM_PENDING_SUMMARY:-?} (tier ${BM_PENDING_TIER:-?})"
    else
      bm::log::say "[dry-run] no pending change to commit"
    fi
    return "$BM_EX_OK"
  fi
  bm::core::require_root
  bm::log::enable_file
  bm::log::set_op commit
  bm::lock::acquire
  local rc=0
  bm::ckpt::commit || rc=$?
  case "$rc" in
    0)
      bm::log::say "$(bm::core::c_ok "pending change committed")"
      return "$BM_EX_OK"
      ;;
    "$BM_EX_CKPT_LOST")
      printf '%s: %s the checkpoint was already gone, so NetworkManager has most likely rolled this change back already.\nCheck the current state with: %s status\n' \
        "$BM_PROG" "$(bm::core::c_err ERROR:)" "$BM_PROG" >&2
      return "$BM_EX_VERIFY"
      ;;
    *) return "$BM_EX_PRECONDITION" ;;
  esac
}

bm::cli::cmd_rollback() {
  local snapshot="" deadman=0
  while (( $# )); do
    case "$1" in
      --snapshot) bm::cli::_need_arg "$1" "${2-}"; snapshot="$2"; shift 2 ;;
      --deadman) deadman=1; shift ;;
      *) bm::core::die "usage: $BM_PROG rollback [--snapshot ID]" "$BM_EX_USAGE" ;;
    esac
  done

  if (( BM_DRY_RUN )); then
    if [[ -z "$snapshot" ]] && bm::ckpt::load_pending; then
      bm::log::say "[dry-run] would roll back the pending change: ${BM_PENDING_SUMMARY:-?} (tier ${BM_PENDING_TIER:-?}, snapshot ${BM_PENDING_SNAPSHOT:-?})"
      return "$BM_EX_OK"
    fi
    [[ -n "$snapshot" ]] || snapshot="$(bm::snap::latest)"
    [[ -n "$snapshot" ]] || bm::core::die "no pending change and no snapshots found in $BM_BACKUP_DIR" "$BM_EX_PRECONDITION"
    bm::snap::exists "$snapshot" || bm::core::die "snapshot '$snapshot' not found" "$BM_EX_PRECONDITION"
    bm::log::say "[dry-run] would restore snapshot $snapshot:"
    bm::snap::diff "$snapshot" || true
    return "$BM_EX_OK"
  fi

  bm::core::require_root
  bm::log::enable_file
  bm::log::set_op rollback
  # The deadman timer runs this from systemd while the operator's session may
  # still hold the lock in the commit gate; that race is resolved by whoever
  # gets the lock first, so the deadman waits rather than acting concurrently.
  bm::lock::acquire
  (( deadman )) && bm::log::warn "DEADMAN rollback fired — the operator never confirmed the change"

  local had_pending=0
  bm::ckpt::load_pending && had_pending=1

  # A deadman firing after the operator already committed or rolled back must
  # do nothing: the pending state it was armed for is gone.
  if (( deadman )) && (( ! had_pending )); then
    bm::log::info "deadman: no pending change remains; nothing to roll back"
    return "$BM_EX_OK"
  fi

  if [[ -z "$snapshot" ]] && (( had_pending )); then
    if bm::ckpt::rollback_pending; then
      bm::log::say "$(bm::core::c_ok "pending change rolled back")"
      return "$BM_EX_OK"
    fi
    bm::core::die "rollback of pending change failed — inspect manually" "$BM_EX_ERR"
  fi

  [[ -n "$snapshot" ]] || snapshot="$(bm::snap::latest)"
  [[ -n "$snapshot" ]] || bm::core::die "no pending change and no snapshots found in $BM_BACKUP_DIR" "$BM_EX_PRECONDITION"
  bm::snap::exists "$snapshot" || bm::core::die "snapshot '$snapshot' not found" "$BM_EX_PRECONDITION"

  echo "Restoring snapshot: $snapshot"
  bm::snap::diff "$snapshot" || true
  echo
  if ! (( BM_ASSUME_YES )); then
    bm::ui::yesno "Restore snapshot $snapshot (see change summary above)?" || {
      bm::log::say "cancelled"
      return "$BM_EX_OK"
    }
  fi

  # Restoring an explicit snapshot while a change is pending would leave the
  # checkpoint or deadman timer armed against state it no longer describes:
  # disarm it first so nothing fires later on top of the restored profiles.
  if (( had_pending )); then
    bm::log::warn "disarming pending change protection before an explicit snapshot restore"
    bm::ckpt::commit >/dev/null 2>&1 || true
  fi

  bm::snap::restore "$snapshot"
  return "$BM_EX_OK"
}

bm::cli::cmd_snapshot() {
  local action="${1:-list}"
  shift || true
  case "$action" in
    create)
      if (( BM_DRY_RUN )); then
        bm::log::say "[dry-run] would create a snapshot of $BM_CONN_DIR"
        return "$BM_EX_OK"
      fi
      bm::core::require_root
      bm::log::enable_file
      bm::lock::acquire
      local id
      id="$(bm::snap::create manual)" || bm::core::die "snapshot creation failed" "$BM_EX_ERR"
      echo "snapshot created: $id"
      ;;
    list)
      local rows
      rows="$(bm::snap::list)"
      if [[ -z "$rows" ]]; then
        echo "No snapshots in $BM_BACKUP_DIR"
      else
        printf '%-22s %-28s %s\n' ID CREATED REASON
        printf '%s\n' "$rows" | awk -F'\t' '{ printf "%-22s %-28s %s\n", $1, $2, $3 }'
      fi
      ;;
    diff)
      local id="${1:-}"
      [[ -n "$id" ]] || bm::core::die "usage: $BM_PROG snapshot diff ID" "$BM_EX_USAGE"
      bm::snap::diff "$id"
      ;;
    restore)
      local want="${1:-}"
      if [[ -z "$want" ]]; then
        want="$(bm::snap::latest)"
        [[ -n "$want" ]] || bm::core::die "no snapshots found in $BM_BACKUP_DIR" "$BM_EX_PRECONDITION"
      fi
      bm::cli::cmd_rollback --snapshot "$want"
      ;;
    prune)
      if (( BM_DRY_RUN )); then
        bm::log::say "[dry-run] would prune snapshots beyond the newest $(bm::config::get MAX_BACKUPS)"
        return "$BM_EX_OK"
      fi
      bm::core::require_root
      bm::log::enable_file
      bm::lock::acquire
      bm::snap::prune
      echo "pruned to $(bm::config::get MAX_BACKUPS) newest snapshots"
      ;;
    *) bm::core::die "usage: $BM_PROG snapshot create|list|diff ID|restore [ID]|prune" "$BM_EX_USAGE" ;;
  esac
}

bm::cli::cmd_bundle() {
  local out="" redact=0
  while (( $# )); do
    case "$1" in
      --output) bm::cli::_need_arg "$1" "${2-}"; out="$2"; shift 2 ;;
      --redact) redact=1; shift ;;
      *) bm::core::die "usage: $BM_PROG bundle [--output PATH] [--redact]" "$BM_EX_USAGE" ;;
    esac
  done
  bm::core::require_root
  bm::log::enable_file
  bm::diag::bundle "$out" "$redact" || bm::core::die "support bundle creation failed" "$BM_EX_ERR"
  echo "support bundle: $BM_BUNDLE_PATH"
}

bm::cli::cmd_init() {
  bm::core::require_root
  bm::log::enable_file
  bm::config::install
  echo "initialized (config: $BM_CONF)"
}

# ---- completion -----------------------------------------------------------

bm::cli::cmd_completion() {
  [[ "${1:-bash}" == bash ]] || bm::core::die "only 'bash' completion is available" "$BM_EX_USAGE"
  cat <<'EOF'
# bash completion for bond-manager
_bond_manager() {
  local cur prev commands
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  commands="list show status diagnose doctor nics create modify add-member remove-member swap-member remove vlan clone repair verify snapshot commit rollback bundle init config completion help tui version"
  case "$prev" in
    show|status|diagnose|modify|add-member|remove-member|swap-member|remove|repair|verify|clone)
      COMPREPLY=( $(compgen -W "$(bond-manager list 2>/dev/null | awk '{print $1}')" -- "$cur") )
      return ;;
    --old|--new|--members|--primary)
      COMPREPLY=( $(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur") )
      return ;;
    help)
      COMPREPLY=( $(compgen -W "$commands basics modes lacp safety practice moving glossary keys exit-codes" -- "$cur") )
      return ;;
    --mode)
      COMPREPLY=( $(compgen -W "balance-rr active-backup balance-xor broadcast 802.3ad balance-tlb balance-alb" -- "$cur") )
      return ;;
    vlan)
      COMPREPLY=( $(compgen -W "add modify remove list" -- "$cur") )
      return ;;
    snapshot)
      COMPREPLY=( $(compgen -W "create list diff restore prune" -- "$cur") )
      return ;;
    config)
      COMPREPLY=( $(compgen -W "show path" -- "$cur") )
      return ;;
  esac
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "--dry-run --yes --json --debug --quiet --no-color --plain --rollback-window --no-checkpoint --force-unsafe --help --version" -- "$cur") )
    return
  fi
  COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
}
complete -F _bond_manager bond-manager
EOF
}

# ==== 95-tui.sh ====
# lib/95-tui.sh — the guided menus. Everything here is presentation: every
# change still goes through the same workflow code as the CLI (70), so every
# guard (validation, snapshot, checkpoint, verification) applies identically.
#
# Rules this module lives by:
#   - every action runs in a subshell via bm::tui::run, so a validation error
#     (die = exit) or a lock taken by commit/rollback can never escape into
#     the menus; the menus themselves never take the lock and never die
#   - nothing is typed that could be picked from a list
#   - the operator always sees where they are, what happens next, and how
#     to go back; practice mode (BM_DRY_RUN) is one key away

BM_TUI_OUT=""            # fd duplicating the real stdout
BM_TUI_STTY0=""          # terminal settings when the menus started
BM_TUI_FORCED_PRACTICE=0 # practice because changes are impossible (not root...)
BM_TUI_HOST=""
BM_TUI_TIER=""
BM_TUI_SAFETY_LINE=""
BM_TUI_SSH_DEV=""
BM_TUI_SSH_PARENT=""
BM_TUI_BONDS=()          # every bond: kernel ∪ NetworkManager profiles
BM_TUI_MANAGED=()        # bonds with a NetworkManager profile
BM_TUI_DASH=()           # dashboard lines, full detail
BM_TUI_DASH_SHORT=()     # dashboard lines, one per bond
BM_TUI_MARK=""
BM_TUI_LEFT=0
BM_TUI_LAST_RC=0
BM_TUI_LAST_OUTCOME=""
BM_TUI_IP4="" BM_TUI_GW4="" BM_TUI_DNS4=""
BM_TUI_IP6="" BM_TUI_GW6="" BM_TUI_DNS6=""
BM_TUI_FAMILY=4
BM_TUI_CTX_BOND=""
BM_TUI_CTX_OPT=""
BM_TUI_AFFECTED=()

# ---- lifecycle ----------------------------------------------------------------

bm::tui::main() {
  bm::cli::preflight_read
  bm::ui::init --force
  if (( BM_ASSUME_YES )); then
    BM_ASSUME_YES=0
    bm::ui::warn "-y/--yes is ignored in the menus: every change asks you first."
  fi
  exec {BM_TUI_OUT}>&1
  if bm::ui::fancy; then
    BM_TUI_STTY0="$(stty -g 2>/dev/null || true)"
  fi
  trap 'BM_UI_INTERRUPTED=1' INT
  trap 'BM_UI_RESIZED=1' WINCH
  trap 'bm::core::cleanup; exit 129' HUP
  trap 'bm::core::cleanup; exit 143' TERM

  bm::ui::dim "Checking this server..."
  bm::tui::_refresh
  if ! bm::cli::mutate_blocker; then
    # Already asked for practice (-n)? Then there is nothing to explain yet;
    # the badge says "look only" and switching it off explains why not.
    if ! (( BM_DRY_RUN )); then
      bm::tui::_explain_forced
    fi
    BM_DRY_RUN=1
    BM_TUI_FORCED_PRACTICE=1
  fi

  bm::tui::_loop

  trap - INT WINCH HUP TERM
  bm::tui::_term_reset
  if bm::tui::_pending; then
    bm::ui::warn "A change is still waiting to be kept: \"${BM_PENDING_SUMMARY:-?}\"."
    bm::tui::_pending_how_to
  fi
  bm::ui::dim "Bye. (Tip: '$BM_PROG help' explains every command.)"
  return 0
}

bm::tui::_term_reset() {
  if [[ -n "$BM_TUI_STTY0" && -t 0 ]]; then
    stty "$BM_TUI_STTY0" 2>/dev/null || true
  fi
  BM_TTY_SAVED=""
  if bm::ui::fancy; then
    printf '\033[?25h\033[0m' >&2
  fi
  BM_TTY_CURSOR_HIDDEN=0
  BM_UI_DRAWN=0
  return 0
}

bm::tui::_explain_forced() {
  bm::ui::clear
  bm::ui::heading "Practice mode is on"
  bm::ui::note "$BM_CLI_BLOCKER_MSG"
  bm::ui::note "You can still look at everything, and go through every change to see exactly what it would do - nothing on the server is touched."
  if [[ "$BM_CLI_BLOCKER" == not-root ]]; then
    bm::ui::info "To make real changes: quit (q) and run:  sudo $BM_PROG"
  fi
  bm::ui::pause "Press Enter to continue"
}

# Gather everything the dashboard shows. Slow-ish (nmcli, ip, busctl), so
# it runs on start, after every action and on 'r' — never per keypress.
bm::tui::_refresh() {
  BM_TUI_HOST="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo localhost)"
  BM_TUI_TIER="$(bm::ckpt::probe_tier 2>/dev/null || echo snapshot)"
  BM_TUI_SSH_DEV="$(bm::facts::ssh_egress_dev 2>/dev/null || true)"
  BM_TUI_SSH_PARENT=""
  if [[ -n "$BM_TUI_SSH_DEV" ]]; then
    BM_TUI_SSH_PARENT="$(bm::facts::vlan_parent "$BM_TUI_SSH_DEV")"
  fi
  mapfile -t BM_TUI_BONDS < <(bm::cli::all_bonds 2>/dev/null || true)
  mapfile -t BM_TUI_MANAGED < <(bm::nm::bond_cons 2>/dev/null \
    | awk -F'\x1f' '{ print ($3 != "" ? $3 : $2) }' | LC_ALL=C sort -u | sed '/^$/d')
  case "$BM_TUI_TIER" in
    checkpoint | deadman) BM_TUI_SAFETY_LINE="$BM_S_GREEN$BM_G_OK$BM_S_RST Safety net: $(bm::help::tier_short "$BM_TUI_TIER")" ;;
    *) BM_TUI_SAFETY_LINE="$BM_S_YELLOW$BM_G_WARN Safety net: $(bm::help::tier_short "$BM_TUI_TIER")$BM_S_RST" ;;
  esac
  bm::tui::_build_dash
}

bm::tui::_pending() { # 0 when a change waits to be kept; sets BM_TUI_LEFT
  BM_TUI_LEFT=0
  bm::ckpt::load_pending 2>/dev/null || return 1
  local now dl="${BM_PENDING_DEADLINE:-0}"
  [[ "$dl" =~ ^[0-9]+$ ]] || dl=0
  printf -v now '%(%s)T' -1
  BM_TUI_LEFT=$(( dl - now ))
  if (( BM_TUI_LEFT < 0 )); then BM_TUI_LEFT=0; fi
  return 0
}

bm::tui::_pending_how_to() {
  local at=""
  if [[ "${BM_PENDING_TIER:-}" != snapshot && "${BM_PENDING_DEADLINE:-}" =~ ^[0-9]+$ ]]; then
    printf -v at '%(%H:%M:%S)T' "$BM_PENDING_DEADLINE"
    bm::ui::note "If nobody keeps it, it is undone automatically at $at."
  else
    bm::ui::note "Nothing will undo it automatically on this server."
  fi
  bm::ui::note "Keep it:  sudo $BM_PROG commit      Undo it:  sudo $BM_PROG rollback"
}

bm::tui::_is_managed() { bm::core::in_list "$1" "${BM_TUI_MANAGED[@]:-}"; }

# ---- dashboard ----------------------------------------------------------------

bm::tui::_ssh_mark() { # _ssh_mark <dev> -> BM_TUI_MARK
  BM_TUI_MARK=""
  if [[ -n "$BM_TUI_SSH_DEV" && "$1" == "$BM_TUI_SSH_DEV" ]]; then
    BM_TUI_MARK="  $BM_S_YELLOW$BM_G_LARR your SSH connection$BM_S_RST"
  fi
  return 0
}

bm::tui::_first_addr() { # _first_addr <dev> -> BM_TUI_ADDR ("10.0.0.5/24 +1")
  local -a a=()
  mapfile -t a < <(bm::facts::dev_addrs "$1" 2>/dev/null | grep -v '^fe80:' || true)
  BM_TUI_ADDR="${a[0]:-}"
  if (( ${#a[@]} > 1 )); then BM_TUI_ADDR+=" +$(( ${#a[@]} - 1 ))"; fi
  return 0
}

bm::tui::_build_dash() {
  BM_TUI_DASH=()
  BM_TUI_DASH_SHORT=()
  if (( ${#BM_TUI_BONDS[@]} == 0 )); then
    BM_TUI_DASH=("No bonds on this server yet." "Pick \"Build a new bond\" below to make one.")
    BM_TUI_DASH_SHORT=("${BM_TUI_DASH[@]}")
    return 0
  fi
  local b
  for b in "${BM_TUI_BONDS[@]}"; do
    bm::tui::_dash_bond "$b"
  done
  return 0
}

bm::tui::_dash_bond() {
  local b="$1" health verdict mode short col word line
  if ! bm::facts::bond_exists_kernel "$b"; then
    line="$BM_S_DIM$BM_G_ODOT $b   saved in NetworkManager, not running$BM_S_RST"
    BM_TUI_DASH+=("$line")
    BM_TUI_DASH_SHORT+=("$line")
    return 0
  fi
  health="$(bm::facts::bond_health "$b")"
  verdict="${health%%$'\n'*}"
  local -a reasons=() members=()
  mapfile -t reasons < <(tail -n +2 <<<"$health" | sed '/^$/d')
  mode="$(bm::facts::bond_mode "$b")"
  short="$(bm::help::mode_short "$mode")"
  case "$verdict" in
    healthy) col="$BM_S_GREEN" ;;
    degraded) col="$BM_S_YELLOW" ;;
    *) col="$BM_S_RED" ;;
  esac
  word="$(bm::help::health_word "$verdict")"
  bm::tui::_first_addr "$b"
  bm::tui::_ssh_mark "$b"
  BM_TUI_DASH+=("$col$BM_G_DOT$BM_S_RST $BM_S_BOLD$b$BM_S_RST  $mode ($short)  $col$word$BM_S_RST${BM_TUI_ADDR:+   $BM_TUI_ADDR}$BM_TUI_MARK")
  local short_mark="$BM_TUI_MARK"

  mapfile -t members < <(bm::facts::bond_members "$b")
  local active i m mii tree link spd act up=0 n=${#members[@]}
  active="$(bm::facts::bond_proc_value "$b" "Currently Active Slave")"
  local -a vl=()
  mapfile -t vl < <(bm::facts::kernel_vlans | awk -v p="$b" '$3 == p')
  for i in "${!members[@]}"; do
    m="${members[$i]}"
    tree="$BM_G_TEE"
    if (( i == n - 1 && ${#vl[@]} == 0 )); then tree="$BM_G_END"; fi
    mii="$(bm::facts::bond_member_mii "$b" "$m")"
    if [[ "$mii" == up ]]; then
      link="${BM_S_GREEN}up$BM_S_RST     "
      up=$(( up + 1 ))
    else
      link="${BM_S_RED}no link$BM_S_RST"
    fi
    bm::facts::nic_info "$m" || true
    spd="$(bm::help::speed_label "$BM_NIC_SPEED")"
    act=""
    if [[ "$mode" == active-backup && "$m" == "$active" ]]; then act="  (active)"; fi
    bm::tui::_ssh_mark "$m"
    BM_TUI_DASH+=("   $BM_S_DIM$tree$BM_S_RST $m  $link  $spd$act$BM_TUI_MARK")
  done
  local v vdev vid
  for i in "${!vl[@]}"; do
    read -r vdev vid _ <<<"${vl[$i]}"
    tree="$BM_G_TEE"
    if (( i == ${#vl[@]} - 1 )); then tree="$BM_G_END"; fi
    bm::tui::_first_addr "$vdev"
    bm::tui::_ssh_mark "$vdev"
    if [[ -n "$BM_TUI_MARK" ]]; then short_mark="$BM_TUI_MARK"; fi
    v="   $BM_S_DIM$tree$BM_S_RST VLAN $vid ($vdev)${BM_TUI_ADDR:+  $BM_TUI_ADDR}$BM_TUI_MARK"
    BM_TUI_DASH+=("$v")
  done
  if [[ "$verdict" != healthy && ${#reasons[@]} -gt 0 ]]; then
    local what
    what="$(bm::help::explain_reason "${reasons[0]}" | head -n1)"
    BM_TUI_DASH+=("     $BM_S_YELLOW$BM_G_WARN $what$BM_S_RST")
  fi
  BM_TUI_DASH_SHORT+=("$col$BM_G_DOT$BM_S_RST $BM_S_BOLD$b$BM_S_RST  $mode  $col$word$BM_S_RST  ($up of $n ports up)$short_mark")
  return 0
}

bm::tui::_badge() { # -> BM_TUI_BADGE
  if (( BM_DRY_RUN )); then
    if (( BM_TUI_FORCED_PRACTICE )); then
      BM_TUI_BADGE="$BM_S_BADGE_PRACTICE PRACTICE (look only) $BM_S_RST"
    else
      BM_TUI_BADGE="$BM_S_BADGE_PRACTICE PRACTICE $BM_S_RST"
    fi
  else
    BM_TUI_BADGE="$BM_S_BADGE_LIVE LIVE $BM_S_RST"
  fi
}

# Header of the home menu: redrawn every second (the pending countdown),
# built only from cached facts plus one small file read.
bm::tui::_home_header() {
  local -a body=()
  local max="$BM_UI_HDR_MAX" banner=0
  bm::tui::_badge
  if bm::tui::_pending; then
    body+=("$BM_S_YELLOW$BM_S_BOLD$BM_G_WARN A change is waiting for you: ${BM_PENDING_SUMMARY:-?}$BM_S_RST")
    if [[ "${BM_PENDING_TIER:-}" == snapshot ]]; then
      body+=("  Nothing undoes it automatically - keep or undo it (first item below).")
    else
      bm::ui::fmt_secs "$BM_TUI_LEFT"
      body+=("  Undone automatically in $BM_S_BOLD$BM_UI_FMT$BM_S_RST unless you keep it (first item below).")
    fi
    body+=("")
    banner=3
  fi
  if (( max < 5 + banner )); then
    # no room for the box: one line that still says the essentials
    local line="$BM_S_BOLD$BM_PROG$BM_S_RST $BM_G_SEP $BM_TUI_HOST $BM_G_SEP ${#BM_TUI_BONDS[@]} bond(s) $BM_TUI_BADGE"
    if (( banner )); then
      line+="  $BM_S_YELLOW$BM_G_WARN change waiting$BM_S_RST"
    fi
    BM_UI_HDR=("$line")
    return 0
  fi
  local room=$(( max - 4 - banner ))
  if (( ${#BM_TUI_DASH[@]} <= room )); then
    body+=("${BM_TUI_DASH[@]}")
  elif (( ${#BM_TUI_DASH_SHORT[@]} <= room )); then
    body+=("${BM_TUI_DASH_SHORT[@]}")
  else
    local keep=$(( room - 1 ))
    if (( keep < 0 )); then keep=0; fi
    body+=("${BM_TUI_DASH_SHORT[@]:0:keep}")
    body+=("$BM_S_DIM...and $(( ${#BM_TUI_DASH_SHORT[@]} - keep )) more (see \"Check my bonds\")$BM_S_RST")
  fi
  body+=("")
  if (( BM_DRY_RUN )); then
    body+=("$BM_S_CYAN$BM_G_OK$BM_S_RST Practice mode: nothing on this server will be changed.")
  else
    body+=("$BM_TUI_SAFETY_LINE")
  fi
  bm::ui::box_lines "$BM_PROG $BM_VERSION $BM_G_SEP $BM_TUI_HOST" "$BM_TUI_BADGE" "" "${body[@]}"
  BM_UI_HDR=("${BM_UI_LINES[@]}")
}

# ---- home -----------------------------------------------------------------------

bm::tui::_loop() {
  local -a items
  while :; do
    if (( BM_UI_EOF )); then
      break
    fi
    bm::ui::clear
    items=()
    if bm::tui::_pending; then
      bm::ui::fmt_secs "$BM_TUI_LEFT"
      items+=(pending "Keep or undo the last change"$'\t'"$BM_UI_FMT left")
    fi
    items+=(
      check "Check my bonds"$'\t'"health, problems explained"
      move "Move a bond to a new switch"$'\t'"one cable at a time, no outage"
      build "Build a new bond"
      change "Change a bond"$'\t'"ports, mode, IP, VLANs..."
      fix "Fix a bond that looks wrong"
      safety "Undo & safety"$'\t'"waiting change, backup copies"
      tools "Tools"$'\t'"network ports, server check, support bundle"
      help "Help: what is all this?"
    )
    if (( BM_DRY_RUN )); then
      items+=(practice "Practice mode is ON"$'\t'"nothing is changed - pick to switch off")
    else
      items+=(practice "Practice mode is OFF"$'\t'"pick to try things without changing anything")
    fi
    items+=(quit "Quit")
    BM_UI_INTERRUPTED=0
    if ! bm::ui::menu --header bm::tui::_home_header --refresh 1 --keys "q p r ?" \
      --footer "$BM_G_UP$BM_G_DN move $BM_G_SEP Enter choose $BM_G_SEP 1-9 jump $BM_G_SEP p practice $BM_G_SEP r refresh $BM_G_SEP ? help $BM_G_SEP q quit" \
      -- "What do you want to do?" "${items[@]}"; then
      if (( BM_UI_EOF )); then
        break
      fi
      if (( BM_UI_INTERRUPTED )); then
        BM_UI_INTERRUPTED=0
        if bm::tui::_confirm_quit; then break; fi
      fi
      continue
    fi
    case "$BM_UI_REPLY" in
      key:q | quit)
        if bm::tui::_confirm_quit; then break; fi
        ;;
      key:p | practice) bm::tui::_toggle_practice ;;
      key:r) bm::ui::dim "Refreshing..."; bm::tui::_refresh ;;
      "key:?" | help) bm::tui::help_menu ;;
      pending) bm::tui::pending_screen ;;
      check) bm::tui::check_menu ;;
      move) bm::tui::move_wizard ;;
      build) bm::tui::build_wizard ;;
      change) bm::tui::change_menu ;;
      fix) bm::tui::fix_wizard ;;
      safety) bm::tui::safety_menu ;;
      tools) bm::tui::tools_menu ;;
    esac
  done
}

bm::tui::_confirm_quit() {
  if bm::tui::_pending; then
    bm::ui::warn "A change is still waiting to be kept: \"${BM_PENDING_SUMMARY:-?}\"."
    bm::tui::_pending_how_to
    bm::ui::yesno "Quit anyway?"
    return $?
  fi
  return 0
}

bm::tui::_toggle_practice() {
  if (( BM_DRY_RUN )); then
    if ! bm::cli::mutate_blocker; then
      bm::ui::heading "Practice mode has to stay on"
      bm::ui::note "$BM_CLI_BLOCKER_MSG"
      bm::ui::pause
      return 0
    fi
    bm::ui::heading "Switch practice mode off?"
    bm::ui::note "Changes will then really happen on this server - always with the plan shown first and the safety net armed."
    if bm::ui::yesno "Switch to LIVE mode?"; then
      BM_DRY_RUN=0
      BM_TUI_FORCED_PRACTICE=0
    fi
  else
    BM_DRY_RUN=1
  fi
  return 0
}

# ---- running actions ------------------------------------------------------------

bm::tui::_emit_outcome() { printf '%s' "${BM_PLAN_OUTCOME:-}" >&3 2>/dev/null || true; }

# EXIT trap of an action's subshell: report the outcome, and clean up what
# the action created there (its temp directory, a terminal left raw) — the
# subshell does not run the program's own EXIT trap. A scratch directory the
# subshell merely inherited belongs to the menu process and is left alone.
BM_TUI_INHERITED_TMPDIR=""
bm::tui::_action_exit() {
  bm::tui::_emit_outcome
  if [[ -n "$BM_TMPDIR" && "$BM_TMPDIR" == "$BM_TUI_INHERITED_TMPDIR" ]]; then
    BM_TMPDIR=""
  fi
  bm::core::cleanup
}

# Run one action in a subshell. kind: change (network change; checks it can
# run first), safety (commit/rollback/snapshots/bundle), look (read-only).
# Results: BM_TUI_LAST_RC, BM_TUI_LAST_OUTCOME. Never fails.
bm::tui::run() { # run <kind> <function> [args...]
  local kind="$1"
  shift
  local rc=0 out=""
  BM_PLAN_OUTCOME=""
  BM_UI_INTERRUPTED=0
  printf '\n' >&2
  out="$( (
    BM_TUI_INHERITED_TMPDIR="$BM_TMPDIR"
    trap bm::tui::_action_exit EXIT
    if [[ "$kind" == change ]]; then
      bm::cli::preflight_mutate
    fi
    "$@"
  ) 3>&1 1>&"$BM_TUI_OUT")" || rc=$?
  bm::tui::_term_reset
  if (( BM_UI_INTERRUPTED )) && (( rc == 0 || rc > 128 )); then
    rc=130
  fi
  BM_UI_INTERRUPTED=0
  BM_TUI_LAST_RC="$rc"
  BM_TUI_LAST_OUTCOME="$out"
  return 0
}

# Explain how the last action ended, then wait for Enter.
bm::tui::result() { # result [kind]
  local kind="${1:-change}" rc="$BM_TUI_LAST_RC" glyph
  printf '\n' >&2
  if [[ "$kind" == look ]] && (( rc == 0 || rc == BM_EX_DEGRADED || rc == BM_EX_DOWN || rc == 1 )); then
    bm::ui::pause
    return 0
  fi
  bm::help::explain_rc "$rc" "$BM_TUI_LAST_OUTCOME" "$BM_DRY_RUN"
  case "$BM_HELP_STYLE" in
    ok) glyph="$BM_G_OK" ;;
    err) glyph="$BM_G_BAD" ;;
    warn) glyph="$BM_G_WARN" ;;
    *) glyph="$BM_G_SEP" ;;
  esac
  local -a lines=("$BM_S_BOLD$glyph $BM_HELP_TITLE$BM_S_RST")
  local l
  for l in "${BM_HELP_LINES[@]}"; do
    bm::ui::width
    bm::ui::wrap $(( BM_UI_W - 6 )) "$l"
    lines+=("${BM_UI_WRAPPED[@]}")
  done
  if bm::tui::_pending && (( rc == BM_EX_PARTIAL || rc == 130 )); then
    local at=""
    if [[ "${BM_PENDING_TIER:-}" != snapshot && "${BM_PENDING_DEADLINE:-}" =~ ^[0-9]+$ ]]; then
      printf -v at '%(%H:%M:%S)T' "$BM_PENDING_DEADLINE"
      lines+=("It will be undone automatically at $at unless you keep it:" "main menu > \"Keep or undo the last change\".")
    else
      lines+=("Keep or undo it: main menu > \"Keep or undo the last change\".")
    fi
  fi
  bm::ui::box --title "Result" --style "$BM_HELP_STYLE" -- "${lines[@]}"
  bm::ui::pause
  if [[ "$kind" != look ]]; then
    bm::tui::_refresh
  fi
  return 0
}

# Changes need root, a running NetworkManager and no other change waiting.
# 0 = go ahead (possibly switched to practice), 1 = back.
bm::tui::ready_to_change() {
  if (( BM_DRY_RUN )); then
    return 0
  fi
  if ! bm::cli::mutate_blocker; then
    bm::ui::heading "This change cannot be made right now"
    bm::ui::note "$BM_CLI_BLOCKER_MSG"
    if ! bm::ui::menu -- "What now?" \
      practice "Continue in practice mode"$'\t'"see the exact plan, change nothing" \
      back "Back"; then
      return 1
    fi
    if [[ "$BM_UI_REPLY" == practice ]]; then
      BM_DRY_RUN=1
      return 0
    fi
    return 1
  fi
  if bm::tui::_pending; then
    bm::ui::heading "Finish the last change first"
    bm::ui::note "A change is still waiting to be kept or undone: \"${BM_PENDING_SUMMARY:-?}\". Only one change can be in flight at a time."
    bm::tui::pending_screen
    if bm::tui::_pending; then
      return 1
    fi
  fi
  return 0
}

# ---- validators (18-val, with messages a person can act on) --------------------

bm::tui::_v_ipv4_cidr() {
  local v="$1" a
  bm::core::split_list "$v"
  for a in "${BM_LIST[@]}"; do
    if ! bm::val::ipv4_cidr "$a"; then
      if bm::val::ipv4_addr "$a"; then
        BM_UI_VERR="Add the prefix length after a slash, e.g. $a/24."
      else
        BM_UI_VERR="'$a' is not an IPv4 address with a prefix like 10.0.0.10/24."
      fi
      return 1
    fi
  done
  return 0
}

bm::tui::_v_ipv4_addr() {
  if bm::val::ipv4_addr "$1"; then return 0; fi
  if [[ "$1" == */* ]]; then
    BM_UI_VERR="The gateway is a plain address - leave out the /prefix."
  else
    BM_UI_VERR="'$1' is not an IPv4 address like 10.0.0.1."
  fi
  return 1
}

bm::tui::_v_dns4() {
  if bm::val::ip_list v4 "${1// /,}"; then return 0; fi
  BM_UI_VERR="Type plain addresses separated by commas, e.g. 10.0.0.53,10.0.0.54."
  return 1
}

bm::tui::_v_ipv6_cidr() {
  local v="$1" a
  bm::core::split_list "$v"
  for a in "${BM_LIST[@]}"; do
    if ! bm::val::ipv6_cidr "$a"; then
      if bm::val::ipv6_addr "$a"; then
        BM_UI_VERR="Add the prefix length after a slash, e.g. $a/64."
      else
        BM_UI_VERR="'$a' is not an IPv6 address with a prefix like 2001:db8::10/64."
      fi
      return 1
    fi
  done
  return 0
}

bm::tui::_v_ipv6_addr() {
  if bm::val::ipv6_addr "$1"; then return 0; fi
  if [[ "$1" == */* ]]; then
    BM_UI_VERR="The gateway is a plain address - leave out the /prefix."
  else
    BM_UI_VERR="'$1' is not an IPv6 address like 2001:db8::1."
  fi
  return 1
}

bm::tui::_v_dns6() {
  if bm::val::ip_list v6 "${1// /,}"; then return 0; fi
  BM_UI_VERR="Type plain IPv6 addresses separated by commas, e.g. 2001:db8::53."
  return 1
}

bm::tui::_v_bond_name() {
  local v="$1"
  if ! bm::val::ifname "$v"; then
    BM_UI_VERR="Use up to 15 letters, digits, '.', '_' or '-', e.g. bond0."
    return 1
  fi
  if bm::facts::nic_exists "$v" || bm::core::in_list "$v" "${BM_TUI_BONDS[@]:-}"; then
    BM_UI_VERR="'$v' already exists - pick another name."
    return 1
  fi
  return 0
}

bm::tui::_v_vlan_new() {
  local v="$1"
  if ! bm::val::vlan_id "$v"; then
    BM_UI_VERR="A VLAN id is a number from 1 to 4094."
    return 1
  fi
  if [[ -n "$BM_TUI_CTX_BOND" ]] && bm::nm::vlan_cons "$BM_TUI_CTX_BOND" 2>/dev/null \
    | awk -F'\x1f' -v id="$v" '$4 == id { f = 1 } END { exit !f }'; then
    BM_UI_VERR="VLAN $v already exists on $BM_TUI_CTX_BOND."
    return 1
  fi
  if (( ${#BM_TUI_CTX_BOND} + 1 + ${#v} > 15 )); then
    BM_UI_VERR="$BM_TUI_CTX_BOND.$v would be longer than 15 characters."
    return 1
  fi
  return 0
}

bm::tui::_v_mtu() {
  if bm::val::mtu "$1"; then return 0; fi
  BM_UI_VERR="A number from 68 to 65535 (1500 is normal, 9000 is jumbo)."
  return 1
}

bm::tui::_v_opt_value() {
  if bm::val::option_value "$BM_TUI_CTX_OPT" "$1"; then return 0; fi
  BM_UI_VERR="That value is not valid for $BM_TUI_CTX_OPT. $(bm::help::option_help "$BM_TUI_CTX_OPT")"
  return 1
}

bm::tui::_v_ipv4_target() {
  if [[ -z "$1" ]] || bm::val::ipv4_addr "$1"; then return 0; fi
  BM_UI_VERR="Type an IPv4 address like 10.0.0.1, or leave it empty."
  return 1
}

# ---- pickers --------------------------------------------------------------------

bm::tui::_next_bond_name() { # -> BM_UI_REPLY-free: prints e.g. bond1
  local i=0
  while bm::facts::nic_exists "bond$i" || bm::core::in_list "bond$i" "${BM_TUI_BONDS[@]:-}"; do
    i=$(( i + 1 ))
  done
  printf 'bond%s' "$i"
}

bm::tui::_bond_label() { # _bond_label <bond> -> BM_TUI_LABEL
  local b="$1" mode verdict members
  if bm::facts::bond_exists_kernel "$b"; then
    mode="$(bm::facts::bond_mode "$b")"
    verdict="$(bm::facts::bond_health "$b" | head -n1)"
    members="$(bm::facts::bond_members "$b" | paste -sd, - | sed 's/,/, /g')"
    BM_TUI_LABEL="$b"$'\t'"$mode $BM_G_SEP $(bm::help::health_word "$verdict") $BM_G_SEP ports: ${members:-none}"
  else
    BM_TUI_LABEL="$b"$'\t'"saved, not running"
  fi
  bm::tui::_ssh_mark "$b"
  local -a mem=()
  mapfile -t mem < <(bm::facts::bond_members "$b")
  if [[ -n "$BM_TUI_MARK" || ( -n "$BM_TUI_SSH_PARENT" && "$BM_TUI_SSH_PARENT" == "$b" ) ]] \
    || { [[ -n "$BM_TUI_SSH_DEV" ]] && bm::core::in_list "$BM_TUI_SSH_DEV" "${mem[@]:-}"; }; then
    BM_TUI_LABEL+=" $BM_G_SEP your SSH connection"
  fi
  return 0
}

bm::tui::pick_bond() { # pick_bond [--managed] <title> -> BM_UI_REPLY
  local managed=0
  if [[ "${1:-}" == --managed ]]; then
    managed=1
    shift
  fi
  local title="$1" b
  local -a items=() skipped=()
  for b in "${BM_TUI_BONDS[@]}"; do
    if (( managed )) && ! bm::tui::_is_managed "$b"; then
      skipped+=("$b")
      continue
    fi
    bm::tui::_bond_label "$b"
    items+=("$b" "$BM_TUI_LABEL")
  done
  if (( ${#items[@]} == 0 )); then
    if (( ${#skipped[@]} > 0 )); then
      bm::ui::warn "The bonds on this server (${skipped[*]}) are not managed by NetworkManager - they were made by hand or by another tool, so bond-manager cannot change them safely."
    else
      bm::ui::note "There are no bonds on this server yet. Pick \"Build a new bond\" in the main menu to make one."
    fi
    bm::ui::pause
    return 1
  fi
  if (( ${#skipped[@]} > 0 )); then
    bm::ui::dim "Not shown (not managed by NetworkManager): ${skipped[*]}"
  fi
  if (( ${#items[@]} == 2 )); then
    BM_UI_REPLY="${items[0]}"
    bm::ui::note "Using $BM_UI_REPLY (the only bond)."
    return 0
  fi
  bm::ui::menu -- "$title" "${items[@]}"
}

# pick_nics --free|--members BOND [--single] [--min N] [--max N]
#           [--exclude a,b] -- TITLE     -> BM_UI_REPLY (comma list)
bm::tui::pick_nics() {
  local src="" bond="" single=0 min=1 max=0 exclude=""
  while (( $# )); do
    case "$1" in
      --free) src=free; shift ;;
      --members) src=members; bond="$2"; shift 2 ;;
      --single) single=1; shift ;;
      --min) min="$2"; shift 2 ;;
      --max) max="$2"; shift 2 ;;
      --exclude) exclude="$2"; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  local title="$1" n
  local -a cands=() items=() inbond=() risky_ip=() risky_ssh=() risky_link=()
  if [[ "$src" == members ]]; then
    mapfile -t cands < <(bm::facts::bond_members "$bond")
  else
    mapfile -t cands < <(bm::facts::eligible_nics)
  fi
  local active=""
  if [[ "$src" == members ]]; then
    active="$(bm::facts::bond_proc_value "$bond" "Currently Active Slave")"
  fi
  for n in "${cands[@]}"; do
    [[ -n "$n" ]] || continue
    if [[ ",$exclude," == *",$n,"* ]]; then continue; fi
    # VLAN devices (eth0.100) match the NIC patterns but are not ports
    if [[ "$src" == free && "$n" == *.* ]]; then continue; fi
    bm::facts::nic_info "$n" || continue
    if [[ "$src" == free && -n "$BM_NIC_MASTER" ]]; then
      inbond+=("$n ($BM_NIC_MASTER)")
      continue
    fi
    local label="" notes="" link spd
    case "$BM_NIC_LINK" in
      up) link=up ;;
      no-link) link="NO LINK"; risky_link+=("$n") ;;
      off) link="switched off"; risky_link+=("$n") ;;
      *) link="link ?" ;;
    esac
    spd="$(bm::help::speed_label "$BM_NIC_SPEED")"
    notes="$link $BM_G_SEP $spd"
    if [[ "$src" == members && "$n" == "$active" ]]; then notes+=" $BM_G_SEP active now"; fi
    if [[ "$src" == free ]]; then
      bm::tui::_first_addr "$n"
      if [[ -n "$BM_TUI_ADDR" ]]; then
        notes+=" $BM_G_SEP has IP $BM_TUI_ADDR (in use?)"
        risky_ip+=("$n")
      fi
      if [[ "$n" == "$BM_TUI_SSH_DEV" ]]; then
        notes+=" $BM_G_SEP YOUR SSH CONNECTION"
        risky_ssh+=("$n")
      elif [[ -z "$BM_TUI_ADDR" && "$BM_NIC_LINK" == up ]]; then
        notes+=" $BM_G_SEP free"
      fi
    elif [[ "$n" == "$BM_TUI_SSH_DEV" ]]; then
      notes+=" $BM_G_SEP your SSH connection"
    fi
    label="$n"$'\t'"$notes"
    items+=("$n" "$label")
  done
  if (( ${#items[@]} == 0 )); then
    if [[ "$src" == members ]]; then
      bm::ui::warn "$bond has no ports that can be picked."
    else
      bm::ui::warn "There are no free network ports to use."
      if (( ${#inbond[@]} > 0 )); then
        bm::ui::note "Already in a bond: ${inbond[*]}."
      fi
      bm::ui::note "Plug in a port (or check the NIC policy in $BM_CONF), then try again. '$BM_PROG nics --all' lists every port."
    fi
    bm::ui::pause
    return 1
  fi
  if (( ${#inbond[@]} > 0 )); then
    bm::ui::dim "Not shown - already in a bond: ${inbond[*]}"
  fi
  while :; do
    if (( single )); then
      bm::ui::menu -- "$title" "${items[@]}" || return 1
    else
      local -a copt=(--min "$min")
      if (( max > 0 )); then copt+=(--max "$max"); fi
      bm::ui::checklist "${copt[@]}" -- "$title" "${items[@]}" || return 1
    fi
    local picked="$BM_UI_REPLY" p warned=0
    local -a plist=()
    bm::core::split_list "$picked"
    plist=("${BM_LIST[@]}")
    for p in "${plist[@]}"; do
      if bm::core::in_list "$p" "${risky_ssh[@]:-}"; then
        bm::ui::warn "$p carries your SSH connection. Putting it into a bond changes how it is set up, which will cut your session (the safety net then undoes it)."
        warned=1
      elif bm::core::in_list "$p" "${risky_ip[@]:-}"; then
        bm::ui::warn "$p has an IP address, so something probably uses it. Putting it into a bond removes that address."
        warned=1
      elif bm::core::in_list "$p" "${risky_link[@]:-}"; then
        bm::ui::warn "$p has no link right now (cable unplugged, or switch port off). It will not carry traffic until it has one."
        warned=1
      fi
    done
    if (( warned )); then
      if ! bm::ui::yesno "Use ${picked//,/, } anyway?"; then
        (( BM_UI_EOF )) && return 1
        continue
      fi
    fi
    BM_UI_REPLY="$picked"
    return 0
  done
}

# Mode picker with the safe choice first. -> BM_UI_REPLY
bm::tui::pick_mode() { # pick_mode [--current MODE]
  local cur=""
  if [[ "${1:-}" == --current ]]; then cur="$2"; fi
  local c1="" c2=""
  [[ "$cur" == active-backup ]] && c1=" (current)"
  [[ "$cur" == 802.3ad ]] && c2=" (current)"
  while :; do
    if ! bm::ui::menu --default "${cur:-active-backup}" -- "How should the ports work together?" \
      active-backup "active-backup - simple failover$c1"$'\t'"recommended if unsure $BM_G_SEP any switch" \
      802.3ad "802.3ad - LACP, all ports busy$c2"$'\t'"the switch MUST be set up for LACP" \
      more "Other modes (advanced)..."; then
      return 1
    fi
    if [[ "$BM_UI_REPLY" == more ]]; then
      local -a items=()
      local m mark
      for m in balance-alb balance-tlb balance-xor balance-rr broadcast; do
        mark=""
        [[ "$m" == "$cur" ]] && mark=" (current)"
        items+=("$m" "$m$mark"$'\t'"$(bm::help::mode_label "$m")")
      done
      bm::ui::menu -- "Other modes" "${items[@]}" || continue
      local picked="$BM_UI_REPLY"
      if [[ "$(bm::help::mode_switch_needs "$picked")" == static ]]; then
        bm::ui::warn "$picked needs the switch ports set up as a static port-channel (no LACP). Without that, traffic will be lost."
        bm::ui::yesno "Is the switch set up for it?" || continue
      fi
      BM_UI_REPLY="$picked"
      return 0
    fi
    if [[ "$BM_UI_REPLY" == 802.3ad && "$cur" != 802.3ad ]]; then
      bm::ui::note "LACP is a deal between this server AND the switch: the switch ports must be configured as one LACP bundle (port-channel / LAG) first."
      if ! bm::ui::yesno "Has the network team set up these switch ports for LACP?"; then
        (( BM_UI_EOF )) && return 1
        bm::ui::note "Without that the bond comes up but passes no traffic (bond-manager's checks would notice and undo it)."
        if ! bm::ui::menu -- "What now?" \
          ab "Use active-backup instead (recommended)"$'\t'"works with any switch" \
          lacp "Use 802.3ad anyway"$'\t'"the switch is ready" \
          back "Back"; then
          continue
        fi
        case "$BM_UI_REPLY" in
          ab) BM_UI_REPLY="active-backup" ;;
          lacp) BM_UI_REPLY=802.3ad ;;
          *) continue ;;
        esac
      fi
    fi
    return 0
  done
}

# Ask for IPv4 settings -> BM_TUI_IP4/GW4/DNS4 (IP4 dhcp|none|CIDR|"" = keep)
bm::tui::ask_ip4() { # ask_ip4 [--keep] [--vlan-option] <what>
  local keep=0 vlan=0
  while (( $# )); do
    case "$1" in
      --keep) keep=1; shift ;;
      --vlan-option) vlan=1; shift ;;
      *) break ;;
    esac
  done
  local what="$1"
  BM_TUI_IP4="" BM_TUI_GW4="" BM_TUI_DNS4=""
  local -a items=(
    dhcp "Automatic (DHCP)"$'\t'"a DHCP server hands out the address"
    static "Fixed address"$'\t'"you type it, e.g. 10.0.0.10/24"
  )
  if (( vlan )); then
    items+=(vlan "On a VLAN (tagged network)"$'\t'"only if the network team gave you a VLAN id")
  fi
  items+=(none "No IPv4 address"$'\t'"the bond carries no IPv4 itself")
  if (( keep )); then
    items+=(keep "Leave it as it is")
  fi
  bm::ui::menu -- "IPv4 address for $what" "${items[@]}" || return 1
  case "$BM_UI_REPLY" in
    dhcp) BM_TUI_IP4=dhcp ;;
    none) BM_TUI_IP4=none ;;
    keep) BM_TUI_IP4="" ;;
    vlan) BM_TUI_IP4=vlan ;;
    static)
      bm::ui::input --validate bm::tui::_v_ipv4_cidr --example "10.0.0.10/24" \
        -- "Address with prefix" || return 1
      BM_TUI_IP4="$BM_UI_REPLY"
      bm::ui::input --optional --validate bm::tui::_v_ipv4_addr --example "10.0.0.1" \
        -- "Gateway (router) - Enter for none" || return 1
      BM_TUI_GW4="$BM_UI_REPLY"
      bm::ui::input --optional --validate bm::tui::_v_dns4 --example "10.0.0.53,10.0.0.54" \
        -- "DNS servers - Enter for none" || return 1
      BM_TUI_DNS4="$BM_UI_REPLY"
      ;;
  esac
  return 0
}

# Ask for IPv6 settings -> BM_TUI_IP6/GW6/DNS6 (IP6 auto|dhcp|none|CIDR|"" = keep)
bm::tui::ask_ip6() { # ask_ip6 [--keep] <what>
  local keep=0
  if [[ "${1:-}" == --keep ]]; then
    keep=1
    shift
  fi
  local what="$1"
  BM_TUI_IP6="" BM_TUI_GW6="" BM_TUI_DNS6=""
  local -a items=(
    auto "Automatic (SLAAC)"$'\t'"the router announces the network - the usual choice"
    dhcp "DHCPv6"$'\t'"a DHCPv6 server hands out the address"
    static "Fixed address"$'\t'"you type it, e.g. 2001:db8::10/64"
    none "No IPv6"$'\t'"IPv6 switched off here"
  )
  if (( keep )); then
    items+=(keep "Leave it as it is")
  fi
  bm::ui::menu -- "IPv6 address for $what" "${items[@]}" || return 1
  case "$BM_UI_REPLY" in
    auto) BM_TUI_IP6=auto ;;
    dhcp) BM_TUI_IP6=dhcp ;;
    none) BM_TUI_IP6=none ;;
    keep) BM_TUI_IP6="" ;;
    static)
      bm::ui::input --validate bm::tui::_v_ipv6_cidr --example "2001:db8::10/64" \
        -- "Address with prefix" || return 1
      BM_TUI_IP6="$BM_UI_REPLY"
      bm::ui::input --optional --validate bm::tui::_v_ipv6_addr --example "2001:db8::1" \
        -- "Gateway (router) - Enter for none" || return 1
      BM_TUI_GW6="$BM_UI_REPLY"
      bm::ui::input --optional --validate bm::tui::_v_dns6 --example "2001:db8::53" \
        -- "DNS servers - Enter for none" || return 1
      BM_TUI_DNS6="$BM_UI_REPLY"
      ;;
  esac
  return 0
}

bm::tui::_ip6_words() { # describe BM_TUI_IP6/GW6/DNS6 -> BM_TUI_WORDS
  case "$BM_TUI_IP6" in
    auto) BM_TUI_WORDS="automatic (SLAAC)" ;;
    dhcp) BM_TUI_WORDS="DHCPv6" ;;
    none) BM_TUI_WORDS="none (IPv6 off)" ;;
    "") BM_TUI_WORDS="unchanged" ;;
    *) BM_TUI_WORDS="$BM_TUI_IP6${BM_TUI_GW6:+, gateway $BM_TUI_GW6}${BM_TUI_DNS6:+, DNS $BM_TUI_DNS6}" ;;
  esac
}

# IPv4 or IPv6? -> BM_TUI_FAMILY (4|6)
bm::tui::_pick_family() { # _pick_family <what>
  bm::ui::menu -- "Which address of $1?" \
    v4 "IPv4 address"$'\t'"e.g. 10.0.0.10/24" \
    v6 "IPv6 address"$'\t'"e.g. 2001:db8::10/64" || return 1
  BM_TUI_FAMILY=4
  if [[ "$BM_UI_REPLY" == v6 ]]; then BM_TUI_FAMILY=6; fi
  return 0
}

bm::tui::_ip4_words() { # describe BM_TUI_IP4/GW4/DNS4 -> BM_TUI_WORDS
  case "$BM_TUI_IP4" in
    dhcp) BM_TUI_WORDS="automatic (DHCP)" ;;
    none) BM_TUI_WORDS="none" ;;
    "") BM_TUI_WORDS="unchanged" ;;
    *) BM_TUI_WORDS="$BM_TUI_IP4${BM_TUI_GW4:+, gateway $BM_TUI_GW4}${BM_TUI_DNS4:+, DNS $BM_TUI_DNS4}" ;;
  esac
}

# ---- review ---------------------------------------------------------------------

# Show what is about to happen in plain words, the safety net, early SSH
# warnings, and the equivalent command. BM_TUI_AFFECTED holds the devices the
# change touches. rc: 0 continue, 1 back, 2 cancel.
bm::tui::review() { # review <subcommand> <summary-line>...
  local sub="$1"
  shift
  local -a lines=("$@")
  lines+=("")
  if (( BM_DRY_RUN )); then
    lines+=("PRACTICE: you will see the exact plan, and nothing is changed.")
  else
    lines+=("$(bm::help::tier_sentence "$BM_TUI_TIER")")
  fi
  local d touched=""
  if [[ -n "$BM_TUI_SSH_DEV" ]]; then
    for d in "${BM_TUI_AFFECTED[@]:-}"; do
      if [[ "$d" == "$BM_TUI_SSH_DEV" || ( -n "$BM_TUI_SSH_PARENT" && "$d" == "$BM_TUI_SSH_PARENT" ) ]]; then
        touched="$BM_TUI_SSH_DEV"
      fi
    done
  fi
  bm::ui::heading "Check before you go"
  local -a wrapped=()
  local l
  bm::ui::width
  for l in "${lines[@]}"; do
    bm::ui::wrap $(( BM_UI_W - 6 )) "$l"
    wrapped+=("${BM_UI_WRAPPED[@]}")
  done
  bm::ui::box --title "You are about to" --style info -- "${wrapped[@]}"
  if [[ -n "$touched" ]] && ! (( BM_DRY_RUN )); then
    if [[ "$BM_TUI_TIER" == checkpoint ]]; then
      bm::ui::warn "This touches $touched, which carries your SSH connection. If it cuts you off: wait - it is undone automatically, then you can reconnect."
    else
      bm::ui::err "This touches $touched, which carries your SSH connection, and this server has no automatic undo. bond-manager will refuse it here - make this change from the server console instead."
    fi
  fi
  bm::wf::cli_equivalent "$sub"
  local cmd="$BM_WF_CLI"
  if (( BM_DRY_RUN )); then
    cmd="$BM_PROG -n ${BM_WF_CLI#"$BM_PROG "}"
  fi
  # never wrapped: it has to stay copy-pasteable
  printf '  %sSame thing as a command:%s\n    %s%s%s\n' "$BM_S_DIM" "$BM_S_RST" "$BM_S_CYAN" "$cmd" "$BM_S_RST" >&2
  local go="Continue - show me the exact plan"
  if ! bm::ui::menu --default go -- "Ready?" \
    go "$go"$'\t'"nothing happens until you say yes" \
    back "Go back and change something" \
    cancel "Cancel"; then
    (( BM_UI_EOF )) && return 2
    return 1
  fi
  case "$BM_UI_REPLY" in
    go) return 0 ;;
    back) return 1 ;;
  esac
  return 2
}

# ---- check ------------------------------------------------------------------------

bm::tui::_health_report() { # plain-words health of every bond (read-only)
  local b health verdict r n=0
  local -a reasons=()
  if (( ${#BM_TUI_BONDS[@]} == 0 )); then
    echo "There are no bonds on this server yet."
    echo "Pick \"Build a new bond\" in the main menu to make one."
    return 0
  fi
  for b in "${BM_TUI_BONDS[@]}"; do
    if ! bm::facts::bond_exists_kernel "$b"; then
      echo "$BM_G_ODOT $b: saved in NetworkManager but not running."
      echo
      continue
    fi
    health="$(bm::facts::bond_health "$b")"
    verdict="${health%%$'\n'*}"
    mapfile -t reasons < <(tail -n +2 <<<"$health" | sed '/^$/d')
    case "$verdict" in
      healthy) printf '%s %s is healthy.\n' "$(bm::core::c_ok "$BM_G_OK")" "$b" ;;
      degraded) printf '%s %s needs attention:\n' "$(bm::core::c_warn "$BM_G_WARN")" "$b"; n=$(( n + 1 )) ;;
      *) printf '%s %s is DOWN:\n' "$(bm::core::c_err "$BM_G_BAD")" "$b"; n=$(( n + 1 )) ;;
    esac
    printf '    mode: %s - %s\n' "$(bm::facts::bond_mode "$b")" "$(bm::help::mode_label "$(bm::facts::bond_mode "$b")")"
    printf '    ports: %s\n' "$(bm::facts::bond_members "$b" | paste -sd, - | sed 's/,/, /g; s/^$/none/')"
    for r in "${reasons[@]}"; do
      bm::help::explain_reason "$r" | sed '1s/^/    - /; 2s/^/      /'
    done
    echo
  done
  if (( n == 0 )); then
    echo "All good."
  fi
  return 0
}

bm::tui::check_menu() {
  local bond target
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::ui::heading "Check my bonds"
    bm::ui::menu -- "What would you like to see?" \
      quick "Quick health check (all bonds)"$'\t'"problems explained in plain words" \
      look "Look closely at one bond"$'\t'"ports, LACP, addresses, a ping test" \
      deep "Deep check of one bond"$'\t'"adds saved profiles, driver info, recent log" \
      verify "Re-run the safety checks on one bond" \
      nics "List the network ports" || return 0
    case "$BM_UI_REPLY" in
      quick)
        bm::tui::run look bm::tui::_health_report
        bm::tui::result look
        ;;
      look | deep)
        local which="$BM_UI_REPLY"
        bm::tui::pick_bond "Which bond?" || continue
        bond="$BM_UI_REPLY"
        target=""
        if [[ "$which" == deep ]]; then
          bm::ui::input --optional --validate bm::tui::_v_ipv4_target --example "10.0.0.1" \
            -- "Address to ping - Enter for the default gateway" || continue
          target="$BM_UI_REPLY"
          bm::tui::run look bm::diag::run "$bond" extended "$target"
        else
          bm::tui::run look bm::diag::run "$bond" basic ""
        fi
        bm::tui::result look
        ;;
      verify)
        bm::tui::pick_bond "Which bond?" || continue
        bm::tui::run look bm::cli::cmd_verify "$BM_UI_REPLY"
        bm::tui::result look
        ;;
      nics)
        bm::tui::run look bm::cli::cmd_nics
        bm::tui::result look
        ;;
    esac
  done
}

# ---- move (swap) --------------------------------------------------------------------

bm::tui::move_wizard() {
  bm::ui::heading "Move a bond to a new switch"
  bm::ui::note "A bond keeps working when one cable is gone, so you move one cable at a time: plug a free port into the new switch, then swap it in for an old port. The new port is added and must really work BEFORE the old one is removed - the server never loses its connection."
  bm::tui::ready_to_change || return 0
  bm::tui::pick_bond --managed "Which bond are you moving?" || return 0
  local bond="$BM_UI_REPLY" mode switched=0 step=1 old="" new="" rc
  mode="$(bm::facts::bond_mode "$bond")"
  BM_TUI_CTX_BOND="$bond"

  if [[ "$mode" == 802.3ad ]]; then
    bm::ui::heading "LACP and the move" "$bond runs 802.3ad"
    bm::ui::note "During the move one cable is on the old switch and one on the new. LACP only works if both switches act as ONE (MLAG / vPC / a stack). Otherwise the bond will not aggregate across them."
    bm::ui::menu -- "Are the old and the new switch one LACP group?" \
      yes "Yes - they act as one switch (MLAG/vPC/stack)" \
      ab "No / not sure - switch $bond to active-backup first"$'\t'"recommended" \
      back "Back" || return 0
    case "$BM_UI_REPLY" in
      back) return 0 ;;
      ab)
        bm::wf::spec_reset
        BM_SPEC[bond]="$bond"
        BM_SPEC[mode]="active-backup"
        bm::wf::affected_devices "$bond"
        BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
        rc=0
        bm::tui::review modify "Switch $bond from 802.3ad (LACP) to active-backup (simple failover)" \
          "LACP-only options are dropped automatically." \
          "Switch it back to 802.3ad once both cables are on the new switch." || rc=$?
        (( rc == 0 )) || return 0
        bm::tui::run change bm::wf::modify
        bm::tui::result change
        if ! bm::tui::_went_well; then
          return 0
        fi
        switched=1
        ;;
    esac
  fi

  while (( step >= 1 && step <= 3 )); do
    (( BM_UI_EOF )) && return 0
    case "$step" in
      1)
        bm::ui::heading "Which cable moves?" "Step 1 of 3"
        bm::ui::note "Pick the port whose cable is still on the OLD switch."
        if ! bm::tui::pick_nics --members "$bond" --single -- "Port to replace"; then
          step=0
          continue
        fi
        old="$BM_UI_REPLY"
        step=2
        ;;
      2)
        bm::ui::heading "Which port replaces it?" "Step 2 of 3"
        bm::ui::note "Pick the free port that is now cabled to the NEW switch."
        if ! bm::tui::pick_nics --free --single --exclude "$old" -- "New port for $bond"; then
          step=1
          continue
        fi
        new="$BM_UI_REPLY"
        bm::facts::nic_info "$new" || true
        local nlink="$BM_NIC_LINK" nspd="$BM_NIC_SPEED"
        bm::facts::nic_info "$old" || true
        if [[ "$nlink" != up ]]; then
          bm::ui::warn "$new has no link right now. The swap waits for it to join the bond; without a link it cannot, and the swap is undone (your connection may wobble until then)."
          bm::ui::menu -- "What now?" \
            other "Pick another port" \
            again "Check again (I just plugged it in)" \
            anyway "Continue anyway" || { step=1; continue; }
          case "$BM_UI_REPLY" in
            other) continue ;;
            again)
              bm::facts::nic_info "$new" || true
              if [[ "$BM_NIC_LINK" != up ]]; then
                bm::ui::warn "Still no link on $new."
                continue
              fi
              bm::ui::ok "$new has a link now."
              ;;
          esac
        elif [[ "$nspd" != unknown && "$BM_NIC_SPEED" != unknown && "$nspd" != "$BM_NIC_SPEED" ]]; then
          bm::ui::warn "$new runs at $(bm::help::speed_label "$nspd") but $old at $(bm::help::speed_label "$BM_NIC_SPEED"). It works, but the bond is uneven until the other cable moves too."
        fi
        step=3
        ;;
      3)
        bm::wf::spec_reset
        BM_SPEC[bond]="$bond"
        BM_SPEC[old]="$old"
        BM_SPEC[new]="$new"
        bm::wf::affected_devices "$bond" "$new"
        BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
        rc=0
        bm::tui::review swap-member "Swap $old out of $bond and $new in." \
          "Order: add $new, wait until the kernel really uses it, THEN remove $old." \
          "$bond keeps working the whole time." || rc=$?
        case "$rc" in
          1) step=2; continue ;;
          2) return 0 ;;
        esac
        bm::tui::run change bm::wf::swap_member
        bm::tui::result change
        if bm::tui::_went_well && [[ -n "$(bm::facts::bond_members "$bond")" ]]; then
          if bm::ui::yesno --default y "Move another cable of $bond too?"; then
            old="" new=""
            step=1
            continue
          fi
        fi
        step=4
        ;;
    esac
  done
  if (( switched )); then
    bm::ui::heading "Remember"
    bm::ui::note "$bond now runs active-backup. Once every cable is on the new switch and its ports are set up for LACP, switch it back: Change a bond > Change how it works > 802.3ad."
    bm::ui::pause
  fi
  return 0
}

# Did the last action succeed (or, in practice mode, render its plan)?
bm::tui::_went_well() {
  (( BM_TUI_LAST_RC == 0 )) || return 1
  case "$BM_TUI_LAST_OUTCOME" in
    committed | dry-run | noop) return 0 ;;
  esac
  return 1
}

# ---- build (create) -------------------------------------------------------------------

bm::tui::build_wizard() {
  bm::ui::heading "Build a new bond"
  bm::ui::note "A bond joins two or more network ports into one connection that survives a cable or switch failure. Five short questions; Esc goes back one step."
  bm::tui::ready_to_change || return 0
  local step=1 name="" ports="" mode="" mtu="" rc vid=""
  local ip4="" gw4="" dns4="" vtok="" ipwords=""
  BM_TUI_CTX_BOND=""
  while (( step >= 1 && step <= 6 )); do
    (( BM_UI_EOF )) && return 0
    case "$step" in
      1)
        bm::ui::heading "Name" "Step 1 of 5"
        bm::ui::note "The name the server uses for the bond. bond0, bond1... is the convention."
        if ! bm::ui::input --default "${name:-$(bm::tui::_next_bond_name)}" \
          --validate bm::tui::_v_bond_name -- "Bond name"; then
          step=0
          continue
        fi
        name="$BM_UI_REPLY"
        BM_TUI_CTX_BOND="$name"
        step=2
        ;;
      2)
        bm::ui::heading "Ports" "Step 2 of 5"
        bm::ui::note "Pick the network ports to join. Two is usual - ideally cabled to two different switches."
        if ! bm::tui::pick_nics --free --min 1 -- "Ports for $name"; then
          step=1
          continue
        fi
        ports="$BM_UI_REPLY"
        if [[ "$ports" != *,* ]]; then
          bm::ui::warn "One port works, but there is no spare yet. You can add one later (Change a bond > Add a port)."
        fi
        step=3
        ;;
      3)
        bm::ui::heading "How the ports work together" "Step 3 of 5"
        if ! bm::tui::pick_mode; then
          step=2
          continue
        fi
        mode="$BM_UI_REPLY"
        step=4
        ;;
      4)
        bm::ui::heading "Address" "Step 4 of 5"
        bm::ui::note "How does this bond get its IPv4 address? Pick \"On a VLAN\" only if the network team gave you a VLAN id for this server."
        if ! bm::tui::ask_ip4 --vlan-option "$name"; then
          step=3
          continue
        fi
        vtok=""
        if [[ "$BM_TUI_IP4" == vlan ]]; then
          if ! bm::ui::input --validate bm::tui::_v_vlan_new --example 120 -- "VLAN id"; then
            continue
          fi
          vid="$BM_UI_REPLY"
          if ! bm::tui::ask_ip4 "VLAN $vid ($name.$vid)"; then
            continue
          fi
          vtok="$vid"
          if [[ "$BM_TUI_IP4" != none ]]; then
            vtok+=":ip4=$BM_TUI_IP4${BM_TUI_GW4:+;gw4=$BM_TUI_GW4}${BM_TUI_DNS4:+;dns4=$BM_TUI_DNS4}"
          fi
          bm::tui::_ip4_words
          ip4=none gw4="" dns4=""
          BM_TUI_WORDS="on VLAN $vid: $BM_TUI_WORDS"
        else
          ip4="$BM_TUI_IP4" gw4="$BM_TUI_GW4" dns4="$BM_TUI_DNS4"
          bm::tui::_ip4_words
        fi
        ipwords="$BM_TUI_WORDS"
        step=5
        ;;
      5)
        bm::ui::heading "Anything else?" "Step 5 of 5"
        if ! bm::ui::menu --default finish -- "Extras (optional)" \
          finish "No, that's all"$'\t'"go to the summary" \
          mtu "Jumbo frames (bigger packets)"$'\t'"MTU ${mtu:-1500}; only if the switches allow it"; then
          step=4
          continue
        fi
        if [[ "$BM_UI_REPLY" == mtu ]]; then
          bm::ui::note "MTU is the largest packet size. 1500 is normal; 9000 (\"jumbo frames\") only helps if every switch in the path is set up for it - otherwise things break in odd ways."
          if bm::ui::input --default "${mtu:-9000}" --validate bm::tui::_v_mtu -- "MTU"; then
            mtu="$BM_UI_REPLY"
            if [[ "$mtu" == 1500 ]]; then mtu=""; fi
          fi
          continue
        fi
        step=6
        ;;
      6)
        bm::wf::spec_reset
        BM_SPEC[bond]="$name"
        BM_SPEC[mode]="$mode"
        BM_SPEC[members]="$ports"
        [[ -n "$ip4" ]] && BM_SPEC[ip4]="$ip4"
        [[ -n "$gw4" ]] && BM_SPEC[gw4]="$gw4"
        [[ -n "$dns4" ]] && BM_SPEC[dns4]="$dns4"
        [[ -n "$vtok" ]] && BM_SPEC[vlans]="$vtok"
        [[ -n "$mtu" ]] && BM_SPEC[mtu]="$mtu"
        BM_TUI_AFFECTED=("$name")
        bm::core::split_list "$ports"
        BM_TUI_AFFECTED+=("${BM_LIST[@]}")
        [[ -n "$vid" && -n "$vtok" ]] && BM_TUI_AFFECTED+=("$name.$vid")
        local -a sum=("Build bond $name from: ${ports//,/, }"
          "How it works: $mode - $(bm::help::mode_label "$mode")"
          "IPv4: $ipwords"
          "IPv6: not set here - add it afterwards with Change a bond > IP address.")
        [[ -n "$mtu" ]] && sum+=("MTU: $mtu")
        rc=0
        bm::tui::review create "${sum[@]}" || rc=$?
        case "$rc" in
          1) step=5; continue ;;
          2) return 0 ;;
        esac
        bm::tui::run change bm::wf::create
        bm::tui::result change
        step=7
        ;;
    esac
  done
  return 0
}

# ---- change ---------------------------------------------------------------------------

bm::tui::_cur_opts() { # current bond.options of a managed bond -> BM_TUI_OPTS
  local uuid
  BM_TUI_OPTS=""
  uuid="$(bm::nm::bond_con_uuid "$1" 2>/dev/null)" || return 1
  BM_TUI_OPTS="$(bm::nm::con_get "$uuid" bond.options 2>/dev/null || true)"
  return 0
}

bm::tui::_cur_mode() { # kernel mode, else the saved one -> BM_TUI_MODE
  BM_TUI_MODE="$(bm::facts::bond_mode "$1")"
  if [[ "$BM_TUI_MODE" == unknown ]]; then
    bm::tui::_cur_opts "$1" || true
    BM_TUI_MODE="$(sed -n 's/.*mode=\([^,]*\).*/\1/p' <<<"$BM_TUI_OPTS")"
    [[ -n "$BM_TUI_MODE" ]] || BM_TUI_MODE=balance-rr
  fi
  return 0
}

# Review + run a modify of <bond> built in BM_SPEC.
bm::tui::_apply_modify() { # _apply_modify <bond> <summary-line>...
  local bond="$1" rc=0
  shift
  bm::wf::affected_devices "$bond"
  BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
  bm::tui::review modify "$@" || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::modify
  bm::tui::result change
}

bm::tui::change_menu() {
  bm::ui::heading "Change a bond"
  bm::tui::ready_to_change || return 0
  bm::tui::pick_bond --managed "Which bond?" || return 0
  local bond="$BM_UI_REPLY" mode members count
  BM_TUI_CTX_BOND="$bond"
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::tui::_cur_mode "$bond"
    mode="$BM_TUI_MODE"
    members="$(bm::facts::bond_members "$bond" | paste -sd, - | sed 's/,/, /g')"
    count="$(bm::facts::bond_members "$bond" | grep -c . || true)"
    local -a items=(
      add "Add a port"$'\t'"now: ${members:-none}"
      remove "Remove a port"
      mode "Change how it works (mode)"$'\t'"now: $mode ($(bm::help::mode_short "$mode"))"
    )
    case "$mode" in
      active-backup | balance-tlb | balance-alb)
        items+=(primary "Preferred port"$'\t'"the port to use whenever it has a link") ;;
    esac
    items+=(
      ip "IP address"
      mtu "MTU (packet size)"
      vlan "VLANs"$'\t'"add, change, remove"
      opt "Advanced option"$'\t'"link checks, LACP rate, hashing..."
      clone "Copy onto other ports"$'\t'"a new bond with the same settings"
      delete "Delete this bond"
    )
    bm::ui::heading "Change $bond"
    bm::ui::menu -- "What do you want to change?" "${items[@]}" || return 0
    case "$BM_UI_REPLY" in
      add) bm::tui::_change_add "$bond" ;;
      remove) bm::tui::_change_remove "$bond" "$count" ;;
      mode) bm::tui::_change_mode "$bond" "$mode" ;;
      primary) bm::tui::_change_primary "$bond" ;;
      ip) bm::tui::_change_ip "$bond" ;;
      mtu) bm::tui::_change_mtu "$bond" ;;
      vlan) bm::tui::_change_vlan "$bond" ;;
      opt) bm::tui::_change_opt "$bond" "$mode" ;;
      clone) bm::tui::_change_clone "$bond" ;;
      delete)
        bm::tui::_change_delete "$bond"
        if ! bm::core::in_list "$bond" "${BM_TUI_BONDS[@]:-}"; then
          return 0
        fi
        ;;
    esac
  done
}

bm::tui::_change_add() {
  local bond="$1" rc=0
  bm::ui::heading "Add a port to $bond"
  bm::tui::pick_nics --free --min 1 -- "Ports to add" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[members]="$BM_UI_REPLY"
  bm::wf::affected_devices "$bond"
  bm::core::split_list "$BM_UI_REPLY"
  BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}" "${BM_LIST[@]}")
  bm::tui::review add-member "Add ${BM_SPEC[members]//,/, } to $bond." \
    "For 802.3ad, the new switch port must join the same LACP bundle." || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::add_members
  bm::tui::result change
}

bm::tui::_change_remove() {
  local bond="$1" count="$2" rc=0
  bm::ui::heading "Remove a port from $bond"
  if (( count <= 1 )); then
    bm::ui::note "$bond has only one port left. Removing it would take the bond down - to get rid of the whole bond, use \"Delete this bond\" instead."
    bm::ui::pause
    return 0
  fi
  bm::ui::note "The bond keeps running on the ports that stay. To REPLACE a port, use \"Move a bond to a new switch\" instead - it adds the new one first."
  bm::tui::pick_nics --members "$bond" --min 1 --max $(( count - 1 )) -- "Ports to remove" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[members]="$BM_UI_REPLY"
  bm::wf::affected_devices "$bond"
  BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
  bm::core::split_list "$BM_UI_REPLY"
  local left=$(( count - ${#BM_LIST[@]} ))
  local -a sum=("Remove ${BM_SPEC[members]//,/, } from $bond.")
  if (( left == 1 )); then
    sum+=("Afterwards $bond has one port left: it works, but has no spare.")
  fi
  bm::tui::review remove-member "${sum[@]}" || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::remove_members
  bm::tui::result change
}

bm::tui::_change_mode() {
  local bond="$1" cur="$2"
  bm::ui::heading "Change how $bond works"
  bm::tui::pick_mode --current "$cur" || return 0
  local new="$BM_UI_REPLY"
  if [[ "$new" == "$cur" ]]; then
    bm::ui::note "$bond already runs $cur - nothing to change."
    bm::ui::pause
    return 0
  fi
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[mode]="$new"
  local -a sum=("Switch $bond from $cur to $new." "$(bm::help::mode_label "$new")"
    "Options that only made sense in $cur are dropped automatically.")
  if [[ "$new" == 802.3ad ]]; then
    BM_SPEC[opts]="lacp_rate=$(bm::config::get DEFAULT_8023AD_LACP_RATE),xmit_hash_policy=$(bm::config::get DEFAULT_8023AD_XHP)"
    sum+=("LACP settings: ${BM_SPEC[opts]//,/, } (the defaults).")
  fi
  bm::tui::_apply_modify "$bond" "${sum[@]}"
}

bm::tui::_change_primary() {
  local bond="$1" m
  bm::ui::heading "Preferred port for $bond"
  bm::ui::note "With a preferred port, $bond uses it whenever it has a link and falls back to the others only when it fails."
  local -a items=()
  while IFS= read -r m; do
    [[ -n "$m" ]] && items+=("$m" "$m")
  done < <(bm::facts::bond_members "$bond")
  items+=(none "No preference"$'\t'"any working port will do")
  bm::ui::menu -- "Preferred port" "${items[@]}" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  if [[ "$BM_UI_REPLY" == none ]]; then
    BM_SPEC[del_opts]="primary"
    bm::tui::_apply_modify "$bond" "Remove the preferred port of $bond."
  else
    BM_SPEC[opts]="primary=$BM_UI_REPLY"
    bm::tui::_apply_modify "$bond" "Make $BM_UI_REPLY the preferred port of $bond."
  fi
}

bm::tui::_change_ip() {
  local bond="$1"
  bm::ui::heading "IP address of $bond"
  local carries=0
  if [[ -n "$BM_TUI_SSH_DEV" && ( "$BM_TUI_SSH_DEV" == "$bond" ) ]]; then carries=1; fi
  if (( carries )); then
    bm::ui::warn "You are connected through $bond. Changing its address ends this session. Afterwards: open a NEW session to the new address and run 'sudo $BM_PROG commit' before the countdown runs out - otherwise the change is undone (which is the safety net working)."
  fi
  bm::tui::_pick_family "$bond" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  if [[ "$BM_TUI_FAMILY" == 6 ]]; then
    bm::tui::ask_ip6 --keep "$bond" || return 0
    [[ -n "$BM_TUI_IP6" ]] || return 0
    BM_SPEC[ip6]="$BM_TUI_IP6"
    [[ -n "$BM_TUI_GW6" ]] && BM_SPEC[gw6]="$BM_TUI_GW6"
    [[ -n "$BM_TUI_DNS6" ]] && BM_SPEC[dns6]="$BM_TUI_DNS6"
    bm::tui::_ip6_words
    bm::tui::_apply_modify "$bond" "Set the IPv6 address of $bond: $BM_TUI_WORDS."
    return 0
  fi
  bm::tui::ask_ip4 --keep "$bond" || return 0
  if [[ -z "$BM_TUI_IP4" ]]; then
    return 0
  fi
  BM_SPEC[ip4]="$BM_TUI_IP4"
  [[ -n "$BM_TUI_GW4" ]] && BM_SPEC[gw4]="$BM_TUI_GW4"
  [[ -n "$BM_TUI_DNS4" ]] && BM_SPEC[dns4]="$BM_TUI_DNS4"
  bm::tui::_ip4_words
  bm::tui::_apply_modify "$bond" "Set the IPv4 address of $bond: $BM_TUI_WORDS."
}

bm::tui::_change_mtu() {
  local bond="$1" cur
  bm::ui::heading "MTU of $bond"
  bm::ui::note "MTU is the largest packet size. 1500 is normal; 9000 (\"jumbo frames\") only helps if every switch in the path is set up for it."
  bm::facts::nic_info "$bond" || true
  cur="$BM_NIC_MTU"
  [[ "$cur" =~ ^[0-9]+$ ]] || cur=1500
  bm::ui::input --default "$cur" --validate bm::tui::_v_mtu -- "MTU" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[mtu]="$BM_UI_REPLY"
  bm::tui::_apply_modify "$bond" "Set the MTU of $bond to $BM_UI_REPLY (now $cur)."
}

bm::tui::_change_vlan() {
  local bond="$1" rec vuuid vname vdev vid rc
  bm::ui::heading "VLANs on $bond"
  local -a vitems=()
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r vuuid vname vdev vid <<<"$rec"
    [[ -n "$vid" ]] && vitems+=("$vid" "VLAN $vid"$'\t'"${vdev:-$bond.$vid}")
  done < <(bm::nm::vlan_cons "$bond" 2>/dev/null || true)
  if (( ${#vitems[@]} > 0 )); then
    local -a shown=()
    local i
    for ((i = 0; i < ${#vitems[@]}; i += 2)); do shown+=("${vitems[i]}"); done
    bm::ui::note "VLANs now: ${shown[*]}"
  else
    bm::ui::note "$bond has no VLANs yet."
  fi
  local -a items=(add "Add a VLAN")
  if (( ${#vitems[@]} > 0 )); then
    items+=(modify "Change a VLAN's IP address" remove "Remove a VLAN")
  fi
  bm::ui::menu -- "What do you want to do?" "${items[@]}" || return 0
  case "$BM_UI_REPLY" in
    add)
      bm::ui::note "The switch ports must carry this VLAN (tagged/trunk) for it to work."
      BM_TUI_CTX_BOND="$bond"
      bm::ui::input --validate bm::tui::_v_vlan_new --example 120 -- "VLAN id" || return 0
      vid="$BM_UI_REPLY"
      bm::tui::ask_ip4 "VLAN $vid ($bond.$vid)" || return 0
      local -a settings=()
      if [[ "$BM_TUI_IP4" != none ]]; then
        settings+=("ip4=$BM_TUI_IP4")
        [[ -n "$BM_TUI_GW4" ]] && settings+=("gw4=$BM_TUI_GW4")
        [[ -n "$BM_TUI_DNS4" ]] && settings+=("dns4=$BM_TUI_DNS4")
      fi
      bm::tui::_ip4_words
      local v4words="$BM_TUI_WORDS" v6words="none"
      BM_TUI_IP6=""
      if bm::ui::yesno "Give VLAN $vid an IPv6 address too?"; then
        bm::tui::ask_ip6 "VLAN $vid ($bond.$vid)" || return 0
        if [[ "$BM_TUI_IP6" != none ]]; then
          settings+=("ip6=$BM_TUI_IP6")
          [[ -n "$BM_TUI_GW6" ]] && settings+=("gw6=$BM_TUI_GW6")
          [[ -n "$BM_TUI_DNS6" ]] && settings+=("dns6=$BM_TUI_DNS6")
        fi
        bm::tui::_ip6_words
        v6words="$BM_TUI_WORDS"
      fi
      (( BM_UI_EOF )) && return 0
      local tok="$vid"
      if (( ${#settings[@]} > 0 )); then
        tok+=":$(bm::core::join ';' "${settings[@]}")"
      fi
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlans]="$tok"
      BM_TUI_AFFECTED=("$bond.$vid")
      rc=0
      bm::tui::review vlan-add "Add VLAN $vid to $bond (device $bond.$vid)." "IPv4: $v4words" "IPv6: $v6words" || rc=$?
      (( rc == 0 )) || return 0
      bm::tui::run change bm::wf::vlan_add
      bm::tui::result change
      ;;
    modify)
      bm::ui::menu -- "Which VLAN?" "${vitems[@]}" || return 0
      vid="$BM_UI_REPLY"
      bm::tui::_pick_family "VLAN $vid" || return 0
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlan_id]="$vid"
      local fam="IPv4"
      if [[ "$BM_TUI_FAMILY" == 6 ]]; then
        fam="IPv6"
        bm::tui::ask_ip6 --keep "VLAN $vid" || return 0
        [[ -n "$BM_TUI_IP6" ]] || return 0
        BM_SPEC[ip6]="$BM_TUI_IP6"
        [[ -n "$BM_TUI_GW6" ]] && BM_SPEC[gw6]="$BM_TUI_GW6"
        [[ -n "$BM_TUI_DNS6" ]] && BM_SPEC[dns6]="$BM_TUI_DNS6"
        bm::tui::_ip6_words
      else
        bm::tui::ask_ip4 --keep "VLAN $vid" || return 0
        [[ -n "$BM_TUI_IP4" ]] || return 0
        BM_SPEC[ip4]="$BM_TUI_IP4"
        [[ -n "$BM_TUI_GW4" ]] && BM_SPEC[gw4]="$BM_TUI_GW4"
        [[ -n "$BM_TUI_DNS4" ]] && BM_SPEC[dns4]="$BM_TUI_DNS4"
        bm::tui::_ip4_words
      fi
      BM_TUI_AFFECTED=("$bond.$vid")
      rc=0
      bm::tui::review vlan-modify "Set the $fam address of VLAN $vid on $bond: $BM_TUI_WORDS." || rc=$?
      (( rc == 0 )) || return 0
      bm::tui::run change bm::wf::vlan_modify "$vid"
      bm::tui::result change
      ;;
    remove)
      bm::ui::menu -- "Which VLAN?" "${vitems[@]}" || return 0
      vid="$BM_UI_REPLY"
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlan_id]="$vid"
      BM_TUI_AFFECTED=("$bond.$vid")
      rc=0
      bm::tui::review vlan-remove "Remove VLAN $vid ($bond.$vid) and its settings." || rc=$?
      (( rc == 0 )) || return 0
      bm::tui::run change bm::wf::vlan_remove
      bm::tui::result change
      ;;
  esac
}

bm::tui::_change_opt() {
  local bond="$1" mode="$2" k v
  bm::ui::heading "Advanced options of $bond"
  bm::ui::note "Only change these if you know you need to (or the network team asked). Every value is checked before anything happens."
  bm::tui::_cur_opts "$bond" || true
  local -A cur=()
  bm::nm::opts_parse "$BM_TUI_OPTS" cur
  bm::ui::menu -- "What do you want to do?" \
    set "Set an option" \
    del "Remove an option"$'\t'"back to the kernel default" || return 0
  local -a items=()
  if [[ "$BM_UI_REPLY" == del ]]; then
    for k in "${!cur[@]}"; do
      [[ "$k" == mode ]] && continue
      items+=("$k" "$k=${cur[$k]}")
    done
    if (( ${#items[@]} == 0 )); then
      bm::ui::note "$bond has no options set besides its mode."
      bm::ui::pause
      return 0
    fi
    bm::ui::menu -- "Remove which option?" "${items[@]}" || return 0
    bm::wf::spec_reset
    BM_SPEC[bond]="$bond"
    BM_SPEC[del_opts]="$BM_UI_REPLY"
    bm::tui::_apply_modify "$bond" "Remove option $BM_UI_REPLY from $bond (back to the default)."
    return 0
  fi
  for k in $(bm::val::opts_for_mode "$mode"); do
    v="${cur[$k]:-}"
    items+=("$k" "$k${v:+ = $v}"$'\t'"$(bm::help::option_help "$k")")
  done
  bm::ui::menu -- "Which option?" "${items[@]}" || return 0
  k="$BM_UI_REPLY"
  BM_TUI_CTX_OPT="$k"
  bm::ui::note "$(bm::help::option_help "$k")"
  bm::ui::input --default "${cur[$k]:-}" --validate bm::tui::_v_opt_value -- "Value for $k" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[opts]="$k=$BM_UI_REPLY"
  bm::tui::_apply_modify "$bond" "Set $k=$BM_UI_REPLY on $bond."
}

bm::tui::_change_clone() {
  local bond="$1" name ports rc=0
  bm::ui::heading "Copy $bond onto other ports"
  bm::ui::note "Makes a NEW bond with the same mode and options as $bond, on ports you pick. Handy to rebuild a bond on new hardware."
  bm::ui::input --default "$(bm::tui::_next_bond_name)" --validate bm::tui::_v_bond_name -- "Name of the new bond" || return 0
  name="$BM_UI_REPLY"
  bm::tui::pick_nics --free --min 1 -- "Ports for $name" || return 0
  ports="$BM_UI_REPLY"
  bm::wf::spec_reset
  BM_SPEC[src]="$bond"
  BM_SPEC[bond]="$name"
  BM_SPEC[members]="$ports"
  if bm::ui::yesno --default y "Copy the VLANs of $bond too?"; then
    BM_SPEC[copy_vlans]=1
  fi
  (( BM_UI_EOF )) && return 0
  bm::ui::note "Copying the IP address makes sense only if $bond is going away: two bonds with the same address conflict."
  if bm::ui::yesno "Copy the IP address of $bond too?"; then
    BM_SPEC[copy_ip]=1
  fi
  (( BM_UI_EOF )) && return 0
  bm::core::split_list "$ports"
  BM_TUI_AFFECTED=("$name" "${BM_LIST[@]}")
  local -a sum=("Build $name on ${ports//,/, } with the settings of $bond.")
  [[ "${BM_SPEC[copy_vlans]:-0}" == 1 ]] && sum+=("VLANs are copied.")
  [[ "${BM_SPEC[copy_ip]:-0}" == 1 ]] && sum+=("The IP address is copied.")
  bm::tui::review clone "${sum[@]}" || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::clone
  bm::tui::result change
}

bm::tui::_change_delete() {
  local bond="$1" rc=0
  bm::ui::heading "Delete $bond"
  bm::ui::note "This deletes the saved settings of $bond, its ports and its VLANs. The ports become free again."
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::wf::affected_devices "$bond"
  BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
  bm::tui::review remove "Delete $bond with its port and VLAN settings." \
    "You will be asked to type the name to confirm." || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::remove
  bm::tui::result change
}

# ---- fix (repair) ---------------------------------------------------------------------

bm::tui::_repair_preview() { # dry-run repair of $1 (runs inside bm::tui::run)
  BM_DRY_RUN=1
  BM_SPEC[bond]="$1"
  bm::wf::repair
}

bm::tui::fix_wizard() {
  bm::ui::heading "Fix a bond that looks wrong"
  bm::ui::note "Bonds drift: a port gets added by hand and never saved, or a saved port no longer exists. Then the next reboot brings the bond back wrong. This compares what the bond REALLY uses right now with what is saved, and fixes the saved side."
  bm::tui::pick_bond --managed "Which bond looks wrong?" || return 0
  local bond="$BM_UI_REPLY"
  if ! bm::facts::bond_exists_kernel "$bond"; then
    bm::ui::warn "$bond is not running, so there is nothing to compare against. Bring it up first (nmcli connection up $bond), then try again."
    bm::ui::pause
    return 0
  fi
  bm::ui::heading "Looking at $bond"
  bm::wf::spec_reset
  bm::tui::run look bm::tui::_repair_preview "$bond"
  if (( BM_TUI_LAST_RC != 0 )); then
    bm::tui::result change
    return 0
  fi
  if [[ "$BM_TUI_LAST_OUTCOME" == noop ]]; then
    bm::ui::ok "The saved settings already match what $bond really uses - nothing to fix there."
    local health
    health="$(bm::facts::bond_health "$bond")"
    if [[ "${health%%$'\n'*}" != healthy ]]; then
      bm::ui::note "If $bond still misbehaves, the cause is outside the settings:"
      local r
      while IFS= read -r r; do
        [[ -n "$r" ]] || continue
        bm::ui::block "$(bm::help::explain_reason "$r" | sed '1s/^/- /; 2s/^/  /')"
      done < <(tail -n +2 <<<"$health")
    fi
    bm::ui::pause
    return 0
  fi
  bm::ui::note "Above is exactly what the fix would do."
  if (( BM_DRY_RUN )); then
    bm::ui::note "(Practice mode: switch it off with p on the main menu to apply the fix.)"
    bm::ui::pause
    return 0
  fi
  bm::ui::menu -- "Fix it?" \
    go "Fix it for real"$'\t'"you will see the plan once more and be asked" \
    back "Not now" || return 0
  [[ "$BM_UI_REPLY" == go ]] || return 0
  bm::tui::ready_to_change || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::tui::run change bm::wf::repair
  bm::tui::result change
}

# ---- undo & safety ------------------------------------------------------------------

bm::tui::pending_screen() {
  if ! bm::tui::_pending; then
    bm::ui::note "No change is waiting - nothing to keep or undo."
    bm::ui::pause
    return 0
  fi
  local -a lines=("Change: ${BM_PENDING_SUMMARY:-?}")
  if [[ "${BM_PENDING_TIER:-}" == snapshot ]]; then
    lines+=("Nothing undoes it automatically on this server.")
  else
    bm::ui::fmt_secs "$BM_TUI_LEFT"
    lines+=("It is undone automatically in $BM_UI_FMT unless you keep it.")
  fi
  lines+=("Keep it if everything works (can you still reach what you need?).")
  bm::ui::heading "The last change is waiting for you"
  bm::ui::box --title "Keep or undo?" --style warn -- "${lines[@]}"
  if (( BM_DRY_RUN )); then
    bm::ui::dim "(Practice mode is on: keep/undo will only be shown, not done.)"
  fi
  bm::ui::menu -- "What do you want to do?" \
    keep "Keep it"$'\t'"the change stays" \
    undo "Undo it now"$'\t'"put everything back as it was" \
    back "Decide later" || return 0
  case "$BM_UI_REPLY" in
    keep)
      bm::tui::run safety bm::cli::cmd_commit
      BM_TUI_LAST_OUTCOME=committed
      if (( BM_TUI_LAST_RC == BM_EX_VERIFY )); then BM_TUI_LAST_OUTCOME=lost; fi
      if (( BM_DRY_RUN )); then BM_TUI_LAST_OUTCOME=dry-run; fi
      bm::tui::result safety
      ;;
    undo)
      bm::tui::run safety bm::cli::cmd_rollback
      if (( BM_TUI_LAST_RC == 0 )); then
        BM_TUI_LAST_OUTCOME=""
        if (( BM_DRY_RUN )); then BM_TUI_LAST_OUTCOME=dry-run; fi
      fi
      bm::tui::result safety
      ;;
  esac
  return 0
}

bm::tui::snapshots_menu() {
  local -a rows=() items=()
  local r id created reason
  mapfile -t rows < <(bm::snap::list 2>/dev/null || true)
  bm::ui::heading "Backup copies (snapshots)"
  bm::ui::note "A backup copy of all saved network settings is taken automatically before every change."
  if (( ${#rows[@]} == 0 )); then
    if [[ -d "$BM_BACKUP_DIR" && ! -r "$BM_BACKUP_DIR" ]]; then
      bm::ui::note "The backup folder can only be read by root."
    else
      bm::ui::note "There are no backup copies yet."
    fi
    bm::ui::pause
    return 0
  fi
  for r in "${rows[@]}"; do
    IFS=$'\t' read -r id created reason <<<"$r"
    items+=("$id" "$id"$'\t'"${created:-?} $BM_G_SEP ${reason:-?}")
  done
  bm::ui::menu -- "Which copy?" "${items[@]}" || return 0
  id="$BM_UI_REPLY"
  bm::ui::menu -- "Copy $id" \
    diff "What would change if I restored it" \
    restore "Restore it"$'\t'"you see the changes first and are asked" \
    back "Back" || return 0
  case "$BM_UI_REPLY" in
    diff)
      bm::tui::run look bm::cli::cmd_snapshot diff "$id"
      bm::tui::result look
      ;;
    restore)
      bm::tui::run safety bm::cli::cmd_rollback --snapshot "$id"
      bm::tui::result safety
      ;;
  esac
  return 0
}

bm::tui::safety_menu() {
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::ui::heading "Undo & safety"
    local -a items=()
    if bm::tui::_pending; then
      bm::ui::fmt_secs "$BM_TUI_LEFT"
      items+=(pending "Keep or undo the waiting change"$'\t'"$BM_UI_FMT left")
    fi
    items+=(
      snapshots "Backup copies"$'\t'"see, compare, restore"
      save "Save a backup copy now"
      how "How does the safety net work?"
    )
    bm::ui::menu -- "What do you want to do?" "${items[@]}" || return 0
    case "$BM_UI_REPLY" in
      pending) bm::tui::pending_screen ;;
      snapshots) bm::tui::snapshots_menu ;;
      save)
        bm::tui::run safety bm::cli::cmd_snapshot create
        bm::tui::result safety
        ;;
      how)
        bm::ui::block "$(bm::help::topic safety)"
        bm::ui::pause
        ;;
    esac
  done
}

# ---- tools & help -------------------------------------------------------------------

bm::tui::tools_menu() {
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::ui::heading "Tools"
    bm::ui::menu -- "Pick a tool" \
      nics "Network ports on this server"$'\t'"which are free, which have a link" \
      doctor "Server check"$'\t'"is everything ready? which safety net?" \
      bundle "Support bundle"$'\t'"one file with everything support needs" \
      config "Show settings" \
      cheat "Command-line cheat sheet"$'\t'"the same jobs, as commands" || return 0
    case "$BM_UI_REPLY" in
      nics)
        bm::tui::run look bm::cli::cmd_nics
        bm::tui::result look
        ;;
      doctor)
        bm::tui::run look bm::cli::cmd_doctor
        bm::tui::result look
        ;;
      bundle)
        local -a args=()
        if bm::ui::yesno "Hide IP and MAC addresses (for a ticket that leaves the site)?"; then
          args+=(--redact)
        fi
        (( BM_UI_EOF )) && return 0
        bm::tui::run safety bm::cli::cmd_bundle "${args[@]}"
        bm::tui::result safety
        ;;
      config)
        bm::tui::run look bm::cli::cmd_config show
        bm::tui::result look
        ;;
      cheat)
        bm::ui::heading "Command-line cheat sheet"
        bm::ui::block "$(bm::help::common_tasks)"
        bm::ui::note "Every change in the menus also shows its own command line. '$BM_PROG help COMMAND' explains any command with examples."
        bm::ui::pause
        ;;
    esac
  done
}

bm::tui::help_menu() {
  local t
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::ui::heading "Help"
    local -a items=()
    for t in "${BM_HELP_TOPICS[@]}"; do
      items+=("$t" "$(bm::help::topic_title "$t")")
    done
    items+=(commands "Help for one command")
    bm::ui::menu -- "What would you like to know?" "${items[@]}" || return 0
    if [[ "$BM_UI_REPLY" == commands ]]; then
      local -a citems=()
      for t in "${BM_HELP_COMMANDS[@]}"; do
        citems+=("$t" "$t")
      done
      bm::ui::menu -- "Which command?" "${citems[@]}" || continue
      printf '\n' >&2
      bm::ui::block "$(bm::help::command "$BM_UI_REPLY")"
    else
      printf '\n' >&2
      bm::ui::block "$(bm::help::topic "$BM_UI_REPLY")"
    fi
    bm::ui::pause
  done
}

# ==== 99-main.sh ====
# lib/99-main.sh — the entrypoint: global flag parsing and dispatch to the
# commands (90-cli) or the interactive menus (95-tui). It sits last so that
# dispatching to every other module is a downward call.

bm::main() {
  bm::core::init_traps
  if (( $# )); then
    printf -v BM_CMDLINE '%q ' "$@"
  fi

  local -a args=()
  local legacy_export=""
  local legacy_status=0
  local want_help=0
  while (( $# )); do
    case "$1" in
      -n | --dry-run) BM_DRY_RUN=1; shift ;;
      -y | --yes) BM_ASSUME_YES=1; shift ;;
      --json) BM_JSON=1; shift ;;
      --debug) BM_DEBUG=1; shift ;;
      --quiet) BM_QUIET=1; shift ;;
      --no-color) BM_NO_COLOR=1; shift ;;
      --plain) BM_PLAIN=1; shift ;;
      --rollback-window) bm::cli::_need_arg "$1" "${2-}"; BM_ROLLBACK_WINDOW="$2"; shift 2 ;;
      --no-checkpoint) BM_NO_CHECKPOINT=1; shift ;;
      --force-unsafe) BM_FORCE_UNSAFE=1; shift ;;
      -V | --version) printf '%s %s\n' "$BM_PROG" "$BM_VERSION"; return 0 ;;
      -h | --help) want_help=1; shift ;;
      --status) legacy_status=1; shift ;;                       # v2.x compat
      --export-json) bm::cli::_need_arg "$1" "${2-}"; legacy_export="$2"; shift 2 ;; # v2.x compat
      --) shift; while (( $# )); do args+=("$1"); shift; done ;;
      *) args+=("$1"); shift ;;
    esac
  done

  bm::core::init_color
  bm::config::load

  # --help anywhere: before a command it is the overview, after one it is
  # that command's own help (so "swap-member --help" does what people expect).
  if (( want_help )); then
    if [[ -n "${args[0]:-}" ]] && bm::help::is_command "${args[0]}"; then
      bm::help::command "${args[0]}"
    else
      bm::cli::usage
    fi
    return 0
  fi
  # The deadman timer re-executes this program from systemd, so BM_SELF must
  # be the entrypoint that was actually invoked ($0) — not the module file
  # that happens to define bm::main, which is what BASH_SOURCE[0] resolves to
  # under the dev entrypoint (and is not executable).
  BM_SELF="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  if [[ ! -x "$BM_SELF" ]]; then
    BM_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
  fi

  if [[ -n "$BM_ROLLBACK_WINDOW" ]] && ! bm::val::uint "$BM_ROLLBACK_WINDOW" 10 86400; then
    bm::core::die "--rollback-window must be 10..86400 seconds" "$BM_EX_USAGE"
  fi

  # legacy one-flag invocations
  if [[ -n "$legacy_export" ]]; then
    bm::cli::preflight_read
    mkdir -p "$(dirname "$legacy_export")"
    BM_JSON=1
    bm::cli::_bonds_json_doc >"$legacy_export"
    echo "JSON written to $legacy_export"
    if (( legacy_status )); then
      BM_JSON=0
      local lrc=0
      bm::cli::cmd_status || lrc=$?
      return "$lrc"
    fi
    return 0
  fi
  if (( legacy_status )); then
    args=(status)
  fi

  local cmd="${args[0]:-}"
  local -a rest=("${args[@]:1}")
  BM_CUR_CMD="$(bm::help::canonical "$cmd" 2>/dev/null || true)"

  if [[ -z "$cmd" ]]; then
    if bm::core::is_tty; then
      local trc=0
      bm::tui::main || trc=$?
      return "$trc"
    fi
    bm::cli::usage >&2
    return "$BM_EX_USAGE"
  fi

  local rc=0
  case "$cmd" in
    list) bm::cli::cmd_list "${rest[@]}" || rc=$? ;;
    show) bm::cli::cmd_show "${rest[@]}" || rc=$? ;;
    status) bm::cli::cmd_status "${rest[@]}" || rc=$? ;;
    diagnose) bm::cli::cmd_diagnose "${rest[@]}" || rc=$? ;;
    doctor) bm::cli::cmd_doctor "${rest[@]}" || rc=$? ;;
    create) bm::cli::cmd_create "${rest[@]}" || rc=$? ;;
    modify) bm::cli::cmd_modify "${rest[@]}" || rc=$? ;;
    add-member) bm::cli::cmd_add_member "${rest[@]}" || rc=$? ;;
    remove-member) bm::cli::cmd_remove_member "${rest[@]}" || rc=$? ;;
    swap-member) bm::cli::cmd_swap_member "${rest[@]}" || rc=$? ;;
    remove | delete) bm::cli::cmd_remove "${rest[@]}" || rc=$? ;;
    vlan) bm::cli::cmd_vlan "${rest[@]}" || rc=$? ;;
    clone) bm::cli::cmd_clone "${rest[@]}" || rc=$? ;;
    repair) bm::cli::cmd_repair "${rest[@]}" || rc=$? ;;
    verify) bm::cli::cmd_verify "${rest[@]}" || rc=$? ;;
    snapshot) bm::cli::cmd_snapshot "${rest[@]}" || rc=$? ;;
    commit) bm::cli::cmd_commit "${rest[@]}" || rc=$? ;;
    rollback) bm::cli::cmd_rollback "${rest[@]}" || rc=$? ;;
    bundle | support-bundle) bm::cli::cmd_bundle "${rest[@]}" || rc=$? ;;
    init) bm::cli::cmd_init "${rest[@]}" || rc=$? ;;
    config) bm::cli::cmd_config "${rest[@]}" || rc=$? ;;
    completion) bm::cli::cmd_completion "${rest[@]}" || rc=$? ;;
    nics) bm::cli::cmd_nics "${rest[@]}" || rc=$? ;;
    tui) bm::tui::main || rc=$? ;;
    help) bm::cli::cmd_help "${rest[@]}" || rc=$? ;;
    version) printf '%s %s\n' "$BM_PROG" "$BM_VERSION" ;;
    *)
      printf '%s: unknown command "%s"\n' "$BM_PROG" "$cmd" >&2
      local sug
      sug="$(bm::help::suggest_command "$cmd")"
      if [[ -n "$sug" ]]; then
        printf '  Did you mean: %s %s\n' "$BM_PROG" "$sug" >&2
      fi
      printf '  See every command: %s help   (or run %s with no arguments for menus)\n' \
        "$BM_PROG" "$BM_PROG" >&2
      rc="$BM_EX_USAGE"
      ;;
  esac
  return "$rc"
}

# ==== entrypoint ====
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  bm::main "$@"
fi
