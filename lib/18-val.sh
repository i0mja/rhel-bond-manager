# lib/18-val.sh — input validators and the bond-mode option matrix.
# The matrix is the single source of truth for which bond.options are valid
# per mode; both the CLI and the TUI validate through it.
# shellcheck shell=bash
[[ -n "${BM_LIB_VAL:-}" ]] && return 0
BM_LIB_VAL=1

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
