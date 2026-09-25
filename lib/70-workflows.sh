# lib/70-workflows.sh — operation workflows.
# Each workflow normalizes its inputs (from CLI flags or TUI prompts — same
# code path), validates through the mode matrix, builds a plan, and hands it
# to the engine. Nothing here calls nmcli directly except through plan steps.
# shellcheck shell=bash
[[ -n "${BM_LIB_WF:-}" ]] && return 0
BM_LIB_WF=1

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
