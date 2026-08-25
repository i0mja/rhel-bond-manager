#!/usr/bin/env bash
# bond-manager v3.0.0 — safe NetworkManager bond management for RHEL-like systems.
# SPDX-License-Identifier: MIT
#
# GENERATED FILE — built from lib/*.sh by build/build.sh (`make dist`).
# Edit the modules in lib/, not this file. Section markers below map
# stack traces on a production box back to the source module.
set -Eeuo pipefail

# ==== 00-core.sh ====
# lib/00-core.sh — constants, exit codes, error handling, shared helpers.
# Modules define functions and defaults only; no I/O happens at source time.

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
  if [[ ! -f "$BM_CONF" ]]; then
    local tmp
    tmp="$(bm::core::tmpdir)/conf"
    bm::config::default_text >"$tmp"
    install -m 0640 -o root -g root "$tmp" "$BM_CONF"
    bm::log::say "installed default config at $BM_CONF"
  else
    bm::log::say "config already present at $BM_CONF (left unchanged)"
  fi
  local tmp2
  tmp2="$(bm::core::tmpdir)/logrotate"
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

# One-line operator guidance per mode, used by help and the TUI.
declare -A BM_MODE_HELP=(
  [balance-rr]="Round-robin. Needs switch EtherChannel/static LAG; can reorder packets."
  [active-backup]="Failover: one active member, others standby. No switch config needed."
  [balance-xor]="Hash-based load balance. Needs switch EtherChannel/static LAG."
  [broadcast]="Transmit everything on all members. Special-purpose fault tolerance."
  [802.3ad]="LACP aggregation. Switch ports MUST be configured as an LACP bundle."
  [balance-tlb]="Adaptive transmit balance. No switch config needed."
  [balance-alb]="Adaptive tx+rx balance (ARP negotiation). No switch config needed."
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

# ==== 50-ui.sh ====
# lib/50-ui.sh — interactive widgets: whiptail when available on a TTY,
# plain prompts otherwise. Contract: every widget returns 0 with the result
# on stdout, or non-zero on cancel. Callers must use `if ! v=$(...)` so a
# cancel can never trip the ERR trap.

BM_UI_WHIPTAIL=0

bm::ui::init() {
  if bm::core::have_cmd whiptail && bm::core::is_tty && [[ "${BM_PLAIN:-0}" != 1 ]]; then
    BM_UI_WHIPTAIL=1
  fi
}

bm::ui::title() {
  local mode="LIVE"
  (( BM_DRY_RUN )) && mode="DRY-RUN"
  printf '%s v%s (%s)' "$BM_PROG" "$BM_VERSION" "$mode"
}

bm::ui::msg() {
  local msg="$1"
  if (( BM_UI_WHIPTAIL )); then
    whiptail --title "$(bm::ui::title)" --scrolltext --msgbox "$msg" 22 78
  else
    printf '\n%b\n\n' "$msg"
    local _
    read -r -p "Press Enter to continue... " _ || true
  fi
}

bm::ui::yesno() { # yesno <question> -> 0 yes / 1 no
  local msg="$1"
  if (( BM_ASSUME_YES )); then
    return 0
  fi
  if (( BM_UI_WHIPTAIL )); then
    whiptail --title "$(bm::ui::title)" --yesno "$msg" 20 78
    return $?
  fi
  local ans
  read -r -p "$msg [y/N]: " ans || true
  [[ "${ans,,}" == y || "${ans,,}" == yes ]]
}

bm::ui::input() { # input <prompt> [default] -> value on stdout, rc=1 on cancel
  local prompt="$1" def="${2:-}"
  if (( BM_UI_WHIPTAIL )); then
    local out
    out="$(whiptail --title "$(bm::ui::title)" --inputbox "$prompt" 12 74 "$def" \
      3>&1 1>&2 2>&3)" || return 1
    printf '%s\n' "$out"
    return 0
  fi
  local v
  read -r -p "$prompt${def:+ [$def]}: " v || return 1
  [[ -z "$v" ]] && v="$def"
  printf '%s\n' "$v"
}

bm::ui::menu() { # menu <title> <tag> <desc> [<tag> <desc> ...]
  local title="$1"
  shift
  if (( BM_UI_WHIPTAIL )); then
    local out
    out="$(whiptail --title "$(bm::ui::title)" --menu "$title" 22 84 12 "$@" \
      3>&1 1>&2 2>&3)" || return 1
    printf '%s\n' "$out"
    return 0
  fi
  printf '\n%s\n\n' "$title" >&2
  local -a tags=()
  local i=1
  while (( $# >= 2 )); do
    printf '  %2d) %-18s %s\n' "$i" "$1" "$2" >&2
    tags+=("$1")
    i=$((i + 1))
    shift 2
  done
  local sel
  read -r -p "Select [1-${#tags[@]}]: " sel || return 1
  if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#tags[@]} )); then
    printf '%s\n' "${tags[$((sel - 1))]}"
    return 0
  fi
  # allow typing the tag itself
  if bm::core::in_list "$sel" "${tags[@]}"; then
    printf '%s\n' "$sel"
    return 0
  fi
  return 1
}

# NIC picker: shows eligible NICs with state/speed/driver; multi-select.
# Echoes selected NICs space-separated.
bm::ui::pick_nics() { # pick_nics <title> [exclude-csv]
  local title="$1" exclude="${2:-}"
  local -a eligible=()
  local n master
  bm::core::split_list "$exclude"
  local -a excl=("${BM_LIST[@]}")
  while IFS= read -r n; do
    [[ -z "$n" ]] && continue
    bm::core::in_list "$n" "${excl[@]:-}" && continue
    eligible+=("$n")
  done < <(bm::facts::eligible_nics)
  (( ${#eligible[@]} > 0 )) || {
    bm::ui::msg "No eligible NICs found. Adjust NIC_ALLOWLIST_PATTERNS / NIC_BLOCKLIST_PATTERNS in $BM_CONF."
    return 1
  }

  local -a items=()
  local info state spd drv
  for n in "${eligible[@]}"; do
    state="$(bm::facts::nic_state "$n")"
    spd="$(bm::facts::nic_speed "$n")"
    drv="$(bm::facts::nic_driver "$n")"
    master="$(bm::facts::nic_bond_master "$n")"
    info="state=$state speed=${spd}Mb/s driver=$drv"
    [[ -n "$master" ]] && info+=" IN-BOND:$master"
    items+=("$n" "$info")
  done

  if (( BM_UI_WHIPTAIL )); then
    local -a witems=()
    local i
    for ((i = 0; i < ${#items[@]}; i += 2)); do
      witems+=("${items[$i]}" "${items[$((i + 1))]}" OFF)
    done
    local out
    out="$(whiptail --title "$(bm::ui::title)" --checklist "$title" 22 84 12 \
      "${witems[@]}" 3>&1 1>&2 2>&3)" || return 1
    out="${out//\"/}"
    [[ -n "$out" ]] || return 1
    printf '%s\n' "$out"
    return 0
  fi

  {
    printf '\n%s\n\n' "$title"
    local j
    for ((j = 0; j < ${#items[@]}; j += 2)); do
      printf '  %-16s %s\n' "${items[$j]}" "${items[$((j + 1))]}"
    done
    printf '\n'
  } >&2
  local raw
  read -r -p "Interfaces (space-separated): " raw || return 1
  raw="$(tr -s ' ' <<<"$raw")"
  raw="${raw# }"
  raw="${raw% }"
  [[ -n "$raw" ]] || return 1
  printf '%s\n' "$raw"
}

bm::ui::pick_bond() { # menu over known bonds (kernel + NM profiles)
  local -a bonds=()
  local b
  while IFS= read -r b; do
    [[ -n "$b" ]] && bonds+=("$b")
  done < <(
    {
      bm::facts::kernel_bonds
      bm::nm::bond_cons | awk -F'\x1f' '{ print ($3 != "" ? $3 : $2) }'
    } | LC_ALL=C sort -u
  )
  (( ${#bonds[@]} > 0 )) || {
    bm::ui::msg "No bonds found on this system."
    return 1
  }
  local -a items=()
  for b in "${bonds[@]}"; do
    items+=("$b" "mode=$(bm::facts::bond_mode "$b")")
  done
  bm::ui::menu "Select a bond:" "${items[@]}"
}

bm::ui::confirm_exact() { # require typing an exact string (destructive ops)
  local what="$1" expected="$2"
  (( BM_ASSUME_YES )) && return 0
  local got
  if ! got="$(bm::ui::input "Type '$expected' to confirm $what")"; then
    return 1
  fi
  [[ "$got" == "$expected" ]]
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
    bm::log::say "Nothing to do — already in the requested state."
    return "$BM_EX_OK"
  fi

  if (( BM_DRY_RUN )); then
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
  if ! (( BM_ASSUME_YES )); then
    if ! bm::ui::yesno "Apply this plan?"; then
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
    return "$BM_EX_VERIFY"
  fi

  # Applying consumed part of the rollback window; give the operator (or the
  # next session) a full window to decide from here.
  bm::ckpt::rebudget "$window" || true

  if (( BM_ASSUME_YES )); then
    local crc=0
    bm::ckpt::commit >/dev/null || crc=$?
    if (( crc == BM_EX_CKPT_LOST )); then
      bm::log::say "$(bm::core::c_err "the checkpoint expired before it could be committed — NetworkManager has most likely rolled this change back")"
      return "$BM_EX_VERIFY"
    fi
    bm::log::say "$(bm::core::c_ok "change applied and committed (verification passed)")"
    return "$BM_EX_OK"
  fi

  bm::plan::commit_gate "$snap"
}

# Interactive commit gate: count down toward the auto-rollback deadline.
bm::plan::commit_gate() {
  local snap="$1"
  if ! bm::core::is_tty; then
    # non-interactive without --yes: keep protection armed and instruct
    bm::log::say "No TTY to confirm on. Protection stays armed:"
    bm::log::say "  confirm with:   $BM_PROG commit"
    bm::log::say "  or revert with: $BM_PROG rollback"
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      bm::log::say "$(bm::core::c_warn "Snapshot-only protection: nothing will roll this back automatically.")"
    else
      bm::log::say "Auto-rollback at the deadline if you do neither."
    fi
    return "$BM_EX_PARTIAL"
  fi

  local key remaining
  while :; do
    remaining=$(( ${BM_CKPT_DEADLINE:-0} - $(bm::core::epoch) ))
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      remaining=999999 # no timer armed; purely manual decision
    fi
    if (( remaining <= 0 )); then
      echo
      bm::log::say "$(bm::core::c_err "auto-rollback deadline reached — the change has been reverted")"
      bm::ckpt::clear_pending
      return "$BM_EX_VERIFY"
    fi
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      printf '\rVerification passed. c=commit r=rollback : '
    else
      printf '\rVerification passed. c=commit r=rollback e=extend (auto-rollback in %4ds) : ' "$remaining"
    fi
    if read -r -t 2 -n 1 key; then
      echo
      case "$key" in
        c | C)
          local crc=0
          bm::ckpt::commit >/dev/null || crc=$?
          if (( crc == BM_EX_CKPT_LOST )); then
            bm::log::say "$(bm::core::c_err "the checkpoint had already expired — NetworkManager has most likely rolled this change back")"
            bm::log::say "check the result with: $BM_PROG status"
            return "$BM_EX_VERIFY"
          fi
          bm::log::say "$(bm::core::c_ok "change committed")"
          return "$BM_EX_OK"
          ;;
        r | R)
          bm::ckpt::rollback_pending || bm::log::warn "rollback reported problems"
          bm::log::say "rolled back to snapshot $snap"
          return "$BM_EX_VERIFY"
          ;;
        e | E)
          if [[ "$BM_CKPT_TIER" == checkpoint && -n "$BM_CKPT_PATH" ]]; then
            local add=300
            if bm::ckpt::dbus_extend "$BM_CKPT_PATH" $(( remaining + add )); then
              BM_CKPT_DEADLINE=$(( $(bm::core::epoch) + remaining + add ))
              bm::log::say "extended by ${add}s"
            fi
          fi
          ;;
      esac
    fi
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
  (( ${#BM_LIST[@]} > 0 )) || bm::core::die "at least one member interface is required" "$BM_EX_USAGE"
  min_speed="$(bm::config::get MIN_SPEED_MBPS)"
  for n in "${BM_LIST[@]}"; do
    bm::val::ifname "$n" || bm::core::die "invalid interface name '$n'" "$BM_EX_USAGE"
    bm::facts::nic_exists "$n" || bm::core::die "interface '$n' does not exist" "$BM_EX_PRECONDITION"
    bm::facts::nic_allowed "$n" || bm::core::die "interface '$n' is blocked by NIC policy (see $BM_CONF)" "$BM_EX_PRECONDITION"
    master="$(bm::facts::nic_bond_master "$n")"
    if [[ -n "$master" && "$master" != "$bond" ]]; then
      bm::core::die "interface '$n' is already enslaved to bond '$master'" "$BM_EX_PRECONDITION"
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
        bm::val::ipv4_cidr "$a" || bm::core::die "invalid IPv4 CIDR '$a'" "$BM_EX_USAGE"
      done
      [[ -n "$gw4" ]] && { bm::val::ipv4_addr "$gw4" || bm::core::die "invalid IPv4 gateway '$gw4'" "$BM_EX_USAGE"; }
      [[ -n "$dns4" ]] && { bm::val::ip_list v4 "${dns4// /,}" || bm::core::die "invalid IPv4 DNS list '$dns4'" "$BM_EX_USAGE"; }
    fi
    bm::nm::ip_args 4 "$m4" "$ip4" "$gw4" "$dns4" || bm::core::die "invalid IPv4 method '$ip4'" "$BM_EX_USAGE"
    bm::plan::add "Configure IPv4 ($ip4) on $label" bm::nm::modify "$con" "${BM_NM_IP_ARGS[@]}"
  fi

  if [[ -n "$ip6" ]]; then
    local m6=static
    case "$ip6" in auto) m6=auto ;; dhcp) m6=dhcp ;; none | disabled) m6=none ;; esac
    if [[ "$m6" == static ]]; then
      local a6
      bm::core::split_list "$ip6"
      for a6 in "${BM_LIST[@]}"; do
        bm::val::ipv6_cidr "$a6" || bm::core::die "invalid IPv6 CIDR '$a6'" "$BM_EX_USAGE"
      done
      [[ -n "$gw6" ]] && { bm::val::ipv6_addr "$gw6" || bm::core::die "invalid IPv6 gateway '$gw6'" "$BM_EX_USAGE"; }
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
  bm::val::vlan_id "$BM_VLAN_ID" || bm::core::die "invalid VLAN id '$BM_VLAN_ID'" "$BM_EX_USAGE"
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
      *) bm::core::die "unknown VLAN setting '$kv' (expected ip4=/gw4=/dns4=/ip6=/gw6=/dns6=)" "$BM_EX_USAGE" ;;
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

# Print the CLI equivalent of the current spec (the TUI teaches the CLI).
bm::wf::print_cli_equivalent() { # print_cli_equivalent <subcommand>
  local sub="$1"
  local out="$BM_PROG $sub ${BM_SPEC[bond]}"
  [[ -n "${BM_SPEC[mode]:-}" ]] && out+=" --mode ${BM_SPEC[mode]}"
  [[ -n "${BM_SPEC[members]:-}" ]] && out+=" --members ${BM_SPEC[members]}"
  [[ -n "${BM_SPEC[opts]:-}" ]] && out+=" --opt '${BM_SPEC[opts]}'"
  [[ -n "${BM_SPEC[mtu]:-}" ]] && out+=" --mtu ${BM_SPEC[mtu]}"
  [[ -n "${BM_SPEC[ip4]:-}" ]] && out+=" --ip4 ${BM_SPEC[ip4]}"
  [[ -n "${BM_SPEC[gw4]:-}" ]] && out+=" --gw4 ${BM_SPEC[gw4]}"
  [[ -n "${BM_SPEC[dns4]:-}" ]] && out+=" --dns4 ${BM_SPEC[dns4]}"
  [[ -n "${BM_SPEC[ip6]:-}" ]] && out+=" --ip6 ${BM_SPEC[ip6]}"
  [[ -n "${BM_SPEC[gw6]:-}" ]] && out+=" --gw6 ${BM_SPEC[gw6]}"
  [[ -n "${BM_SPEC[dns6]:-}" ]] && out+=" --dns6 ${BM_SPEC[dns6]}"
  local tok
  for tok in ${BM_SPEC[vlans]:-}; do
    out+=" --vlan '$tok'"
  done
  bm::log::say ""
  bm::log::say "CLI equivalent: $out"
  bm::log::say ""
}

# ---- create ---------------------------------------------------------------

bm::wf::create() {
  local bond="${BM_SPEC[bond]}"
  bm::val::ifname "$bond" || bm::core::die "invalid bond name '$bond'" "$BM_EX_USAGE"
  [[ -n "${BM_SPEC[mode]:-}" ]] || bm::core::die "--mode is required" "$BM_EX_USAGE"
  bm::val::mode "${BM_SPEC[mode]}" || bm::core::die "unknown mode '${BM_SPEC[mode]}' (valid: ${BM_MODES[*]})" "$BM_EX_USAGE"

  if bm::facts::bond_exists_kernel "$bond" || bm::nm::bond_con_uuid "$bond" >/dev/null; then
    bm::core::die "bond '$bond' already exists (use 'modify' or a different name)" "$BM_EX_PRECONDITION"
  fi
  bm::wf::_validate_members "$bond" "${BM_SPEC[members]:-}"

  local opts
  opts="$(bm::wf::_build_options)" || bm::core::die "invalid bond options (see above)" "$BM_EX_USAGE"

  [[ -n "${BM_SPEC[mtu]:-}" ]] && { bm::val::mtu "${BM_SPEC[mtu]}" || bm::core::die "invalid MTU '${BM_SPEC[mtu]}'" "$BM_EX_USAGE"; }

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
    bm::val::ifname "$vif" || bm::core::die "VLAN interface name '$vif' exceeds 15 characters" "$BM_EX_USAGE"
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
  uuid="$(bm::nm::bond_con_uuid "$bond")" || bm::core::die "no NetworkManager bond profile found for '$bond'" "$BM_EX_PRECONDITION"

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
  bm::val::mode "$mode" || bm::core::die "unknown mode '$mode'" "$BM_EX_USAGE"

  # merge: explicit mode change + --opt pairs + --del-opt keys
  local -a changes=()
  [[ -n "${BM_SPEC[mode]:-}" ]] && changes+=("mode=$mode")
  if [[ -n "${BM_SPEC[opts]:-}" ]]; then
    # Parse rather than split on commas: values such as
    # arp_ip_target=10.0.0.1,10.0.0.2 legitimately contain commas, and a naive
    # split would turn the second address into a bogus option key.
    local -A spec_opts=()
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
    local errors
    if ! errors="$(bm::val::option_set "$mode" merged)"; then
      printf '%s\n' "$errors" >&2
      bm::core::die "invalid resulting option set" "$BM_EX_USAGE"
    fi
    new_opts="$(bm::nm::opts_render merged)"
    if [[ "$new_opts" != "$current_opts" ]]; then
      bm::plan::add "Set bond.options to '$new_opts'" bm::nm::modify "$uuid" bond.options "$new_opts"
    fi
  fi

  if [[ -n "${BM_SPEC[mtu]:-}" ]]; then
    bm::val::mtu "${BM_SPEC[mtu]}" || bm::core::die "invalid MTU '${BM_SPEC[mtu]}'" "$BM_EX_USAGE"
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
  uuid="$(bm::nm::bond_con_uuid "$bond")" || bm::core::die "no NetworkManager bond profile found for '$bond'" "$BM_EX_PRECONDITION"
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
      bm::ui::yesno "Removing these members leaves '$bond' with NO members, which takes it down. Continue?" || return 0
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
  uuid="$(bm::nm::bond_con_uuid "$bond")" || bm::core::die "no NetworkManager bond profile found for '$bond'" "$BM_EX_PRECONDITION"
  bm::facts::bond_members "$bond" | grep -qx "$old" || \
    bm::core::die "'$old' is not a member of '$bond'" "$BM_EX_PRECONDITION"
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
  (( removed )) || bm::core::die "no port profile found for '$old' on '$bond' (repair first?)" "$BM_EX_PRECONDITION"

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
    bm::core::die "bond '$bond' not found" "$BM_EX_PRECONDITION"
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
    bm::log::say "nothing to remove for '$bond'"
    return "$BM_EX_OK"
  }

  if ! (( BM_DRY_RUN )); then
    bm::ui::confirm_exact "removal of bond '$bond' and its profiles" "$bond" || {
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
  src_uuid="$(bm::nm::bond_con_uuid "$src")" || bm::core::die "no NetworkManager bond profile found for '$src'" "$BM_EX_PRECONDITION"
  bm::val::ifname "$dst" || bm::core::die "invalid bond name '$dst'" "$BM_EX_USAGE"
  if bm::facts::bond_exists_kernel "$dst" || bm::nm::bond_con_uuid "$dst" >/dev/null 2>&1; then
    bm::core::die "bond '$dst' already exists" "$BM_EX_PRECONDITION"
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
  uuid="$(bm::nm::bond_con_uuid "$bond")" || bm::core::die "no NetworkManager bond profile found for '$bond' (create it first)" "$BM_EX_PRECONDITION"
  bm::facts::bond_exists_kernel "$bond" || bm::core::die "bond '$bond' not present in kernel" "$BM_EX_PRECONDITION"

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
  bm::nm::bond_con_uuid "$bond" >/dev/null || bm::core::die "no NetworkManager bond profile found for '$bond'" "$BM_EX_PRECONDITION"
  bm::wf::_parse_vlan_token "$tok"
  local vif="$bond.$BM_VLAN_ID"
  bm::val::ifname "$vif" || bm::core::die "VLAN interface name '$vif' exceeds 15 characters" "$BM_EX_USAGE"
  local existing
  existing="$(bm::nm::vlan_cons "$bond" | awk -F'\x1f' -v id="$BM_VLAN_ID" '$4 == id { print $2 }')"
  if [[ -n "$existing" ]]; then
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
  bm::val::vlan_id "$vid" || bm::core::die "invalid VLAN id '$vid'" "$BM_EX_USAGE"
  local rec vuuid vname vdev v found_uuid="" found_dev=""
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r vuuid vname vdev v <<<"$rec"
    if [[ "$v" == "$vid" ]]; then
      found_uuid="$vuuid"
      found_dev="${vdev:-$bond.$vid}"
      break
    fi
  done < <(bm::nm::vlan_cons "$bond")
  [[ -n "$found_uuid" ]] || bm::core::die "no VLAN $vid found on $bond (use 'vlan add')" "$BM_EX_PRECONDITION"

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
  bm::val::vlan_id "$vid" || bm::core::die "invalid VLAN id '$vid'" "$BM_EX_USAGE"
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

bm::diag::bundle() { # bundle [output-path] [redact:0|1]
  local out="${1:-}" redact="${2:-0}"
  bm::core::require_root
  mkdir -p "$BM_SUPPORT_DIR"
  local ts dir archive
  ts="$(date +'%Y%m%d-%H%M%S')"
  dir="$(bm::core::tmpdir)/bundle-$ts"
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
  printf '%s\n' "$out"
}

# ==== 90-cli.sh ====
# lib/90-cli.sh — argument parsing, dispatch, output commands and the TUI.

bm::cli::usage() {
  cat <<EOF
$BM_PROG v$BM_VERSION — safe NetworkManager bond management for RHEL-like systems

Usage: $BM_PROG [GLOBAL FLAGS] <command> [ARGS]
       $BM_PROG                      (interactive TUI when run on a terminal)

Global flags:
  -n, --dry-run             Render the plan; execute nothing, write nothing
  -y, --yes                 No prompts; auto-commit when verification passes
      --json                Machine-readable output (list/show/status)
      --debug               Mirror log records to stderr
      --quiet               Suppress progress messages
      --no-color            Disable colored output (NO_COLOR is also honored)
      --plain               Force plain prompts (skip whiptail)
      --rollback-window S   Auto-rollback window in seconds (default: config)
      --no-checkpoint       Skip NM checkpoints (fall back to deadman/snapshot)
      --force-unsafe        Allow touching your SSH egress device w/o checkpoint
  -V, --version             Print version
  -h, --help                This help

Read-only commands (no root, write nothing):
  list                      One line per bond: name, mode, health
  show BOND                 Full bond detail (--json supported)
  status [BOND]             Health summary; exit 0 healthy / 10 degraded / 11 down
  diagnose BOND [--extended] [--target IP]
  verify BOND               Re-run the verification checks against kernel state
  doctor                    Environment preflight + protection-tier report
  config show|path          Effective configuration / config file path
  completion bash           Emit bash completion script

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
EOF
}

# ---- read-only output commands --------------------------------------------

bm::cli::preflight_read() {
  bm::core::have_cmd nmcli || bm::core::die "nmcli not found; install NetworkManager" "$BM_EX_PRECONDITION"
}

bm::cli::preflight_mutate() {
  bm::cli::preflight_read
  # a dry-run only renders the plan: no root, no NM, no module loading needed
  (( BM_DRY_RUN )) && return 0
  bm::core::require_root
  if bm::core::have_cmd systemctl && ! systemctl is-active --quiet NetworkManager; then
    bm::core::die "NetworkManager is not active (systemctl enable --now NetworkManager)" "$BM_EX_PRECONDITION"
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
  for t in ethtool journalctl whiptail flock logger restorecon; do
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
    return "$BM_EX_PRECONDITION"
  fi
  echo "verdict: $(bm::core::c_ok ready) (protection tier: $tier)"
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

# ---- mutation command parsers ---------------------------------------------

# Parse shared create/modify flags into BM_SPEC. Consumes "$@" after the
# positional args have been shifted away.
bm::cli::_parse_change_flags() {
  local -a opt_pairs=()
  local -a vlan_tokens=()
  while (( $# )); do
    case "$1" in
      --mode) BM_SPEC[mode]="${2:?}"; shift 2 ;;
      --members) BM_SPEC[members]="${2:?}"; shift 2 ;;
      --opt) opt_pairs+=("${2:?}"); shift 2 ;;
      --del-opt) BM_SPEC[del_opts]="${BM_SPEC[del_opts]:-} ${2:?}"; shift 2 ;;
      --mtu) BM_SPEC[mtu]="${2:?}"; shift 2 ;;
      --ip4) BM_SPEC[ip4]="${2:?}"; shift 2 ;;
      --gw4) BM_SPEC[gw4]="${2:?}"; shift 2 ;;
      --dns4) BM_SPEC[dns4]="${2:?}"; shift 2 ;;
      --ip6) BM_SPEC[ip6]="${2:?}"; shift 2 ;;
      --gw6) BM_SPEC[gw6]="${2:?}"; shift 2 ;;
      --dns6) BM_SPEC[dns6]="${2:?}"; shift 2 ;;
      --vlan) vlan_tokens+=("${2:?}"); shift 2 ;;
      --miimon) opt_pairs+=("miimon=${2:?}"); shift 2 ;;
      --primary) opt_pairs+=("primary=${2:?}"); shift 2 ;;
      --lacp-rate) opt_pairs+=("lacp_rate=${2:?}"); shift 2 ;;
      --xmit-hash) opt_pairs+=("xmit_hash_policy=${2:?}"); shift 2 ;;
      --arp-interval) opt_pairs+=("arp_interval=${2:?}"); shift 2 ;;
      --arp-targets) opt_pairs+=("arp_ip_target=${2:?}"); shift 2 ;;
      --min-links) opt_pairs+=("min_links=${2:?}"); shift 2 ;;
      --no-activate) BM_SPEC[activate]=0; shift ;;
      --copy-ip) BM_SPEC[copy_ip]=1; shift ;;
      --copy-vlans) BM_SPEC[copy_vlans]=1; shift ;;
      --keep-vlans) BM_SPEC[keep_vlans]=1; shift ;;
      --old) BM_SPEC[old]="${2:?}"; shift 2 ;;
      --new) BM_SPEC[new]="${2:?}"; shift 2 ;;
      *) bm::core::die "unknown flag '$1'" "$BM_EX_USAGE" ;;
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
      --target) target="${2:?}"; shift 2 ;;
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
      --snapshot) snapshot="${2:?}"; shift 2 ;;
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
      --output) out="${2:?}"; shift 2 ;;
      --redact) redact=1; shift ;;
      *) bm::core::die "usage: $BM_PROG bundle [--output PATH] [--redact]" "$BM_EX_USAGE" ;;
    esac
  done
  bm::core::require_root
  bm::log::enable_file
  local path
  path="$(bm::diag::bundle "$out" "$redact")" || bm::core::die "support bundle creation failed" "$BM_EX_ERR"
  echo "support bundle: $path"
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
  commands="list show status diagnose doctor create modify add-member remove-member swap-member remove vlan clone repair verify snapshot commit rollback bundle init config completion help"
  case "$prev" in
    show|status|diagnose|modify|add-member|remove-member|swap-member|remove|repair|verify)
      COMPREPLY=( $(compgen -W "$(bond-manager list 2>/dev/null | awk '{print $1}')" -- "$cur") )
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

# ---- TUI ------------------------------------------------------------------

bm::cli::tui_create() {
  bm::wf::spec_reset
  local bond
  if ! bond="$(bm::ui::input "New bond name" "bond0")"; then return 0; fi
  BM_SPEC[bond]="$bond"

  local -a mode_items=()
  local m
  for m in "${BM_MODES[@]}"; do
    mode_items+=("$m" "${BM_MODE_HELP[$m]}")
  done
  local mode
  if ! mode="$(bm::ui::menu "Bond mode:" "${mode_items[@]}")"; then return 0; fi
  BM_SPEC[mode]="$mode"

  local members
  if ! members="$(bm::ui::pick_nics "Select member interfaces for $bond")"; then return 0; fi
  BM_SPEC[members]="${members// /,}"

  local ipmode
  if ! ipmode="$(bm::ui::menu "IPv4 configuration:" \
    dhcp "DHCP" static "Static address" none "No IPv4 on the bond")"; then return 0; fi
  case "$ipmode" in
    dhcp) BM_SPEC[ip4]=dhcp ;;
    none) BM_SPEC[ip4]=none ;;
    static)
      local addr gw dns
      if ! addr="$(bm::ui::input "IPv4 address/prefix (e.g. 10.0.0.10/24)")"; then return 0; fi
      if ! gw="$(bm::ui::input "IPv4 gateway (blank for none)")"; then return 0; fi
      if ! dns="$(bm::ui::input "DNS servers, comma-separated (blank for none)")"; then return 0; fi
      BM_SPEC[ip4]="$addr"
      [[ -n "$gw" ]] && BM_SPEC[gw4]="$gw"
      [[ -n "$dns" ]] && BM_SPEC[dns4]="$dns"
      ;;
  esac

  if bm::ui::yesno "Add a VLAN on top of $bond?"; then
    local vid
    if ! vid="$(bm::ui::input "VLAN ID (1-4094)")"; then return 0; fi
    local vtok="$vid"
    if bm::ui::yesno "Put the IP on the VLAN interface instead of the bond?"; then
      local vaddr vgw
      if ! vaddr="$(bm::ui::input "VLAN IPv4 address/prefix (or 'dhcp')")"; then return 0; fi
      if [[ "$vaddr" == dhcp ]]; then
        vtok+=":ip4=dhcp"
      else
        if ! vgw="$(bm::ui::input "VLAN IPv4 gateway (blank for none)")"; then return 0; fi
        vtok+=":ip4=$vaddr${vgw:+;gw4=$vgw}"
      fi
      BM_SPEC[ip4]=none
      unset "BM_SPEC[gw4]" "BM_SPEC[dns4]"
    fi
    BM_SPEC[vlans]="$vtok"
  fi

  bm::wf::print_cli_equivalent create
  local rc=0
  ( bm::wf::create ) || rc=$?
  bm::cli::_tui_show_rc "$rc"
}

# TUI workflows run in a subshell (see the '( bm::wf::... )' call sites) so a
# validation failure — which calls bm::core::die, i.e. exit — returns the
# operator to the menu instead of dropping them out of the program.
bm::cli::_tui_show_rc() {
  local rc="$1"
  case "$rc" in
    0) : ;;
    "$BM_EX_VERIFY") bm::ui::msg "The change FAILED verification and was rolled back." ;;
    *) bm::ui::msg "Operation ended with exit code $rc (see $BM_LOG_FILE)." ;;
  esac
}

bm::cli::tui_edit() {
  local bond
  if ! bond="$(bm::ui::pick_bond)"; then return 0; fi
  local action
  if ! action="$(bm::ui::menu "Edit '$bond':" \
    add "Add member interfaces" \
    remove "Remove member interfaces" \
    tune "Change mode / bond options" \
    vlan "Add a VLAN" \
    ip "Change IPv4/IPv6 on the bond" \
    back "Back")"; then return 0; fi
  local rc=0
  case "$action" in
    back) return 0 ;;
    add)
      local members
      if ! members="$(bm::ui::pick_nics "Interfaces to add to $bond")"; then return 0; fi
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[members]="${members// /,}"
      bm::wf::print_cli_equivalent add-member
      ( bm::wf::add_members ) || rc=$?
      ;;
    remove)
      local cur
      cur="$(bm::facts::bond_members "$bond" | paste -sd' ' -)"
      local rem
      if ! rem="$(bm::ui::input "Members to remove (current: ${cur:-none})")"; then return 0; fi
      [[ -n "$rem" ]] || return 0
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[members]="${rem// /,}"
      bm::wf::print_cli_equivalent remove-member
      ( bm::wf::remove_members ) || rc=$?
      ;;
    tune)
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      local newmode
      if ! newmode="$(bm::ui::input "New mode (blank to keep; one of: ${BM_MODES[*]})")"; then return 0; fi
      [[ -n "$newmode" ]] && BM_SPEC[mode]="$newmode"
      local opts
      if ! opts="$(bm::ui::input "Options to set, comma-separated key=value (blank for none)")"; then return 0; fi
      [[ -n "$opts" ]] && BM_SPEC[opts]="$opts"
      bm::wf::print_cli_equivalent modify
      ( bm::wf::modify ) || rc=$?
      ;;
    vlan)
      local vid
      if ! vid="$(bm::ui::input "VLAN ID to add on $bond")"; then return 0; fi
      [[ -n "$vid" ]] || return 0
      local vtok="$vid" vaddr vgw
      if bm::ui::yesno "Configure IPv4 on the new VLAN interface?"; then
        if ! vaddr="$(bm::ui::input "IPv4 address/prefix (or 'dhcp')")"; then return 0; fi
        if [[ "$vaddr" == dhcp ]]; then
          vtok+=":ip4=dhcp"
        elif [[ -n "$vaddr" ]]; then
          if ! vgw="$(bm::ui::input "IPv4 gateway (blank for none)")"; then return 0; fi
          vtok+=":ip4=$vaddr${vgw:+;gw4=$vgw}"
        fi
      fi
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlans]="$vtok"
      bm::log::say "CLI equivalent: $BM_PROG vlan add $bond '$vtok'"
      ( bm::wf::vlan_add ) || rc=$?
      ;;
    ip)
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      local ipmode
      if ! ipmode="$(bm::ui::menu "IPv4 configuration:" \
        dhcp "DHCP" static "Static address" none "Disable IPv4" keep "Leave IPv4 unchanged")"; then return 0; fi
      case "$ipmode" in
        dhcp) BM_SPEC[ip4]=dhcp ;;
        none) BM_SPEC[ip4]=none ;;
        static)
          local addr gw dns
          if ! addr="$(bm::ui::input "IPv4 address/prefix")"; then return 0; fi
          if ! gw="$(bm::ui::input "IPv4 gateway (blank for none)")"; then return 0; fi
          if ! dns="$(bm::ui::input "DNS servers (blank for none)")"; then return 0; fi
          BM_SPEC[ip4]="$addr"
          [[ -n "$gw" ]] && BM_SPEC[gw4]="$gw"
          [[ -n "$dns" ]] && BM_SPEC[dns4]="$dns"
          ;;
      esac
      bm::wf::print_cli_equivalent modify
      ( bm::wf::modify ) || rc=$?
      ;;
  esac
  bm::cli::_tui_show_rc "$rc"
}

bm::cli::tui_loop() {
  bm::ui::init
  while :; do
    local choice
    if ! choice="$(bm::ui::menu "Main menu — $(bm::ui::title)" \
      status "Status: all bonds (health, members, addresses)" \
      diagnose "Status: diagnose a bond" \
      extended "Status: extended diagnostics" \
      create "Change: create a new bond" \
      edit "Change: edit an existing bond" \
      delete "Change: remove a bond" \
      swap "Migration: swap a member NIC (add new, then remove old)" \
      clone "Migration: clone a bond to new NICs" \
      repair "Repair: rebuild member profiles from kernel state" \
      snapshots "Safety: snapshots (list / restore)" \
      pending "Safety: commit or roll back a pending change" \
      bundle "Support: create a support bundle" \
      doctor "About: environment doctor" \
      quit "Exit")"; then
      break
    fi
    local rc=0
    case "$choice" in
      status)
        local out
        out="$(bm::cli::cmd_status 2>&1 || true)"
        bm::ui::msg "${out:-No bonds found.}"
        ;;
      diagnose | extended)
        local bond target
        if bond="$(bm::ui::pick_bond)"; then
          if ! target="$(bm::ui::input "Ping target (blank = default gateway)")"; then target=""; fi
          local lvl=basic
          [[ "$choice" == extended ]] && lvl=extended
          bm::ui::msg "$(bm::diag::run "$bond" "$lvl" "$target" 2>&1 || true)"
        fi
        ;;
      create) bm::cli::tui_create ;;
      edit) bm::cli::tui_edit ;;
      delete)
        local bond
        if bond="$(bm::ui::pick_bond)"; then
          bm::wf::spec_reset
          BM_SPEC[bond]="$bond"
          bm::log::say "CLI equivalent: $BM_PROG remove $bond"
          ( bm::wf::remove ) || rc=$?
          bm::cli::_tui_show_rc "$rc"
        fi
        ;;
      swap)
        local bond old new
        if bond="$(bm::ui::pick_bond)"; then
          local cur
          cur="$(bm::facts::bond_members "$bond" | paste -sd' ' -)"
          if old="$(bm::ui::input "Member to replace (current: ${cur:-none})")" && [[ -n "$old" ]]; then
            if new="$(bm::ui::pick_nics "Replacement NIC for $old" "$old")" && [[ -n "$new" ]]; then
              new="${new%% *}"
              bm::wf::spec_reset
              BM_SPEC[bond]="$bond"
              BM_SPEC[old]="$old"
              BM_SPEC[new]="$new"
              bm::log::say "CLI equivalent: $BM_PROG swap-member $bond --old $old --new $new"
              ( bm::wf::swap_member ) || rc=$?
              bm::cli::_tui_show_rc "$rc"
            fi
          fi
        fi
        ;;
      clone)
        local src dst members
        if src="$(bm::ui::pick_bond)"; then
          if dst="$(bm::ui::input "New bond name" "bond1")" && [[ -n "$dst" ]]; then
            if members="$(bm::ui::pick_nics "Member interfaces for $dst")"; then
              bm::wf::spec_reset
              BM_SPEC[src]="$src"
              BM_SPEC[bond]="$dst"
              BM_SPEC[members]="${members// /,}"
              bm::ui::yesno "Copy IP configuration from $src?" && BM_SPEC[copy_ip]=1
              bm::ui::yesno "Clone VLANs from $src?" && BM_SPEC[copy_vlans]=1
              bm::log::say "CLI equivalent: $BM_PROG clone $src $dst --members ${BM_SPEC[members]}${BM_SPEC[copy_ip]:+ --copy-ip}${BM_SPEC[copy_vlans]:+ --copy-vlans}"
              ( bm::wf::clone ) || rc=$?
              bm::cli::_tui_show_rc "$rc"
            fi
          fi
        fi
        ;;
      repair)
        local bond
        if bond="$(bm::ui::pick_bond)"; then
          bm::wf::spec_reset
          BM_SPEC[bond]="$bond"
          bm::log::say "CLI equivalent: $BM_PROG repair $bond"
          ( bm::wf::repair ) || rc=$?
          bm::cli::_tui_show_rc "$rc"
        fi
        ;;
      snapshots)
        local out
        out="$(bm::cli::cmd_snapshot list 2>&1 || true)"
        bm::ui::msg "$out"
        if bm::ui::yesno "Restore a snapshot now?"; then
          local id
          if id="$(bm::ui::input "Snapshot ID (blank = most recent)")"; then
            if [[ -n "$id" ]]; then
              bm::cli::cmd_rollback --snapshot "$id" || rc=$?
            else
              bm::cli::cmd_rollback || rc=$?
            fi
            bm::cli::_tui_show_rc "$rc"
          fi
        fi
        ;;
      pending)
        if bm::ckpt::load_pending; then
          if bm::ui::yesno "Pending change: ${BM_PENDING_SUMMARY:-?}. Commit it? (No = roll back)"; then
            bm::cli::cmd_commit || rc=$?
          else
            bm::cli::cmd_rollback || rc=$?
          fi
          bm::cli::_tui_show_rc "$rc"
        else
          bm::ui::msg "No pending change."
        fi
        ;;
      bundle)
        local out
        if bm::ui::yesno "Redact IPs/MACs from the bundle (for off-site tickets)?"; then
          out="$(bm::cli::cmd_bundle --redact 2>&1 || true)"
        else
          out="$(bm::cli::cmd_bundle 2>&1 || true)"
        fi
        bm::ui::msg "$out"
        ;;
      doctor)
        bm::ui::msg "$(bm::cli::cmd_doctor 2>&1 || true)"
        ;;
      quit) break ;;
    esac
  done
}

# ---- main -----------------------------------------------------------------

bm::main() {
  bm::core::init_traps

  local -a args=()
  local legacy_export=""
  local legacy_status=0
  while (( $# )); do
    case "$1" in
      -n | --dry-run) BM_DRY_RUN=1; shift ;;
      -y | --yes) BM_ASSUME_YES=1; shift ;;
      --json) BM_JSON=1; shift ;;
      --debug) BM_DEBUG=1; shift ;;
      --quiet) BM_QUIET=1; shift ;;
      --no-color) BM_NO_COLOR=1; shift ;;
      --plain) BM_PLAIN=1; shift ;;
      --rollback-window) BM_ROLLBACK_WINDOW="${2:?}"; shift 2 ;;
      --no-checkpoint) BM_NO_CHECKPOINT=1; shift ;;
      --force-unsafe) BM_FORCE_UNSAFE=1; shift ;;
      -V | --version) printf '%s %s\n' "$BM_PROG" "$BM_VERSION"; return 0 ;;
      -h | --help) bm::cli::usage; return 0 ;;
      --status) legacy_status=1; shift ;;                       # v2.x compat
      --export-json) legacy_export="${2:?}"; shift 2 ;;          # v2.x compat
      --) shift; while (( $# )); do args+=("$1"); shift; done ;;
      *) args+=("$1"); shift ;;
    esac
  done

  bm::core::init_color
  bm::config::load
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

  if [[ -z "$cmd" ]]; then
    if bm::core::is_tty; then
      bm::cli::preflight_read
      bm::cli::tui_loop
      return 0
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
    tui) bm::cli::preflight_read; bm::cli::tui_loop || rc=$? ;;
    help) bm::cli::usage ;;
    version) printf '%s %s\n' "$BM_PROG" "$BM_VERSION" ;;
    *)
      printf '%s: unknown command "%s"\n\n' "$BM_PROG" "$cmd" >&2
      bm::cli::usage >&2
      rc="$BM_EX_USAGE"
      ;;
  esac
  return "$rc"
}

# ==== entrypoint ====
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  bm::main "$@"
fi
