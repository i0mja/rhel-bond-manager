# lib/25-nm.sh — the only module that talks to nmcli.
# Rules: every invocation is an argv array through bm::nm::run (logged,
# dry-run aware); terse output is split with an escape-aware state machine
# (nmcli escapes ':' as '\:' and '\' as '\\'); connections are addressed by
# UUID so operations never depend on profile naming conventions.
# shellcheck shell=bash
[[ -n "${BM_LIB_NM:-}" ]] && return 0
BM_LIB_NM=1

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

bm::nm::device_delete() { bm::nm::run device delete "$1"; } # software devices only

bm::nm::device_disconnect() { bm::nm::run device disconnect "$1"; }

# Every profile with the interface it binds to: lines
# "ifname<US>uuid<US>type<US>active-device".
bm::nm::ifname_index() {
  local rec uuid name type dev ifname
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r uuid name type dev <<<"$rec"
    ifname="$(bm::nm::con_get "$uuid" connection.interface-name)"
    printf '%s\x1f%s\x1f%s\x1f%s\n' "${ifname:-$dev}" "$uuid" "$type" "$dev"
  done < <(bm::nm::con_list)
}

# A profile's settings, for telling whether it changed: the lower-case
# setting lines only (upper-case sections are runtime state), without the
# activation timestamp.
bm::nm::con_settings() { # con_settings <uuid>
  nmcli -t connection show "$1" 2>/dev/null \
    | grep -v -e '^[A-Z]' -e '^connection\.timestamp[:=]' | LC_ALL=C sort || true
}

# Build the nmcli property arguments for an IP spec and store them in the
# global array BM_NM_IP_ARGS. family: 4|6; method: dhcp|auto|none|static.
bm::nm::ip_args() { # ip_args <4|6> <method> <addrs> <gw> <dns>
  local fam="$1" method="$2" addrs="$3" gw="$4" dns="$5"
  BM_NM_IP_ARGS=()
  local p="ipv$fam"
  # Leaving a fixed address drops it (and its gateway): NetworkManager keeps
  # ipv4.addresses next to DHCP, and refuses them with 'disabled'. A gateway
  # or DNS list of "none" clears it.
  case "$method" in
    dhcp | auto)
      BM_NM_IP_ARGS+=("$p.method" auto "$p.addresses" "" "$p.gateway" "")
      ;;
    none | disabled)
      # ipv4 has had 'disabled' forever; ipv6 uses 'ignore' for NM < 1.20
      if [[ "$fam" == 6 ]]; then
        BM_NM_IP_ARGS+=("$p.method" ignore "$p.addresses" "" "$p.gateway" "")
      else
        BM_NM_IP_ARGS+=("$p.method" disabled "$p.addresses" "" "$p.gateway" "")
      fi
      ;;
    static)
      BM_NM_IP_ARGS+=("$p.method" manual "$p.addresses" "$addrs")
      if [[ "$gw" == none ]]; then
        BM_NM_IP_ARGS+=("$p.gateway" "")
      elif [[ -n "$gw" ]]; then
        BM_NM_IP_ARGS+=("$p.gateway" "$gw")
      fi
      ;;
    *)
      return 1
      ;;
  esac
  if [[ "$dns" == none ]]; then
    BM_NM_IP_ARGS+=("$p.dns" "")
  elif [[ -n "$dns" ]]; then
    bm::core::split_list "$dns"
    BM_NM_IP_ARGS+=("$p.dns" "$(bm::core::join , "${BM_LIST[@]}")")
  fi
  return 0
}
