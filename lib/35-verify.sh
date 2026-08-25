# lib/35-verify.sh — post-apply verification gate.
# Produces a structured pass/warn/fail report; the plan engine commits only
# when nothing failed. Checks run against kernel state (/proc, /sys) and the
# routing table — the ground truth, not what nmcli believes.
# shellcheck shell=bash
[[ -n "${BM_LIB_VERIFY:-}" ]] && return 0
BM_LIB_VERIFY=1

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
