# lib/20-facts.sh — read-only inventory of NICs and bonds from /proc, /sys
# and the routing table. All paths go through BM_PROC_ROOT/BM_SYS_ROOT so the
# test suite can point them at fixture trees.
# shellcheck shell=bash
[[ -n "${BM_LIB_FACTS:-}" ]] && return 0
BM_LIB_FACTS=1

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
