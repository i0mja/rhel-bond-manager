#!/usr/bin/env bats
# bm::verify::bond — the gate that decides commit vs rollback. Its two
# trailing parameters (expect-state and absent-members) are what keep a
# legitimately-down bond from being rolled back, and what proves a member
# really left the bond; both are table-driven here.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
  bm::config::set LINK_SETTLE_TIMEOUT 0   # no waiting for fixtures to "settle"
}

report() { # the accumulated report as "<level> <message>" lines
  local i
  for i in "${!BM_VERIFY_LEVELS[@]}"; do
    printf '%s %s\n' "${BM_VERIFY_LEVELS[$i]}" "${BM_VERIFY_MSGS[$i]}"
  done
}

fresh_world() {
  rm -rf "$BM_PROC_ROOT/net/bonding" "$BM_SYS_ROOT/class/net"
  mkdir -p "$BM_PROC_ROOT/net/bonding" "$BM_SYS_ROOT/class/net"
}

@test "expect-state matrix: 'up' fails what 'any' only warns about" {
  local world expect verdict msg out
  while IFS='|' read -r world expect verdict msg; do
    [[ -n "$world" ]] || continue
    fresh_world
    case "$world" in
      healthy) scenario_bond0_healthy ;;
      down) scenario_bond0_down ;;
      absent) : ;;
    esac

    bm::verify::reset
    bm::verify::bond bond0 "" "" "" "" "$expect"
    out="$(report)"

    if [[ "$verdict" == failed ]]; then
      bm::verify::failed || {
        printf 'case %s/%s: expected a FAIL\n%s\n' "$world" "$expect" "$out" >&2
        return 1
      }
    else
      if bm::verify::failed; then
        printf 'case %s/%s: expected no FAIL\n%s\n' "$world" "$expect" "$out" >&2
        return 1
      fi
    fi
    assert_contains "$out" "$msg"
  done <<'ROWS'
healthy|up|clean|pass bond 'bond0' operstate is up
healthy|any|clean|pass bond 'bond0' operstate is up
down|up|failed|fail bond 'bond0' operstate is 'down'
down|any|clean|warn bond 'bond0' operstate is 'down' (not expected to be up after this change)
absent|up|failed|fail bond 'bond0' not present in kernel (/proc/net/bonding)
absent|any|clean|warn bond 'bond0' is not present in the kernel
ROWS
}

@test "expect-state defaults to 'up' when the parameter is omitted" {
  scenario_bond0_down
  bm::verify::reset
  bm::verify::bond bond0
  bm::verify::failed
  assert_contains "$(report)" "fail bond 'bond0' operstate is 'down'"
}

@test "absent-members: a member that is still enslaved is a failure" {
  scenario_bond0_healthy      # members eth0,eth1
  bm::verify::reset
  bm::verify::bond bond0 "" "" "" "" up eth1
  bm::verify::failed
  assert_contains "$(report)" "fail member eth1 is still enslaved to bond0"
}

@test "absent-members: a member that is gone passes" {
  scenario_bond0_healthy
  write_proc_bond bond0 eth0 eth0     # eth1 released
  bm::verify::reset
  bm::verify::bond bond0 "" "" "" "" up eth1
  ! bm::verify::failed
  assert_contains "$(report)" "pass member eth1 is no longer enslaved to bond0"
}

@test "absent-members: every NIC in the csv is checked" {
  scenario_bond0_healthy
  bm::verify::reset
  bm::verify::bond bond0 "" "" "" "" up "eth1,eth9"
  local out
  out="$(report)"
  assert_contains "$out" "fail member eth1 is still enslaved to bond0"
  assert_contains "$out" "pass member eth9 is no longer enslaved to bond0"
}

@test "absent-members combines with expect-state any (last member removed)" {
  # what `remove-member` of the final member looks like: bond down, empty
  scenario_bond0_healthy
  write_proc_bond bond0 none
  printf 'down\n' >"$BM_SYS_ROOT/class/net/bond0/operstate"
  bm::verify::reset
  bm::verify::bond bond0 "" "" "" "" any "eth0,eth1"
  ! bm::verify::failed
  local out
  out="$(report)"
  assert_contains "$out" "pass member eth0 is no longer enslaved to bond0"
  assert_contains "$out" "pass member eth1 is no longer enslaved to bond0"
}

@test "swap shape: new member present AND old member absent in one report" {
  scenario_bond0_healthy
  write_proc_bond bond0 eth0 eth0 eth2
  mk_sys_nic eth2 up 1000 52:54:00:12:34:03
  bm::verify::reset
  bm::verify::bond bond0 "" eth2 "" "" up eth1
  ! bm::verify::failed
  local out
  out="$(report)"
  assert_contains "$out" "pass member eth2 enslaved, MII up"
  assert_contains "$out" "pass member eth1 is no longer enslaved to bond0"
}

@test "empty absent-members list is skipped entirely" {
  scenario_bond0_healthy
  bm::verify::reset
  bm::verify::bond bond0 "" "" "" "" up ""
  ! bm::verify::failed
  assert_not_contains "$(report)" "no longer enslaved"
}

@test "wanted members still fail when they never enslave" {
  scenario_bond0_healthy
  bm::verify::reset
  bm::verify::bond bond0 "" eth7 "" "" any
  bm::verify::failed
  assert_contains "$(report)" "fail member eth7 is not enslaved to bond0"
}

@test "mode mismatch is a failure regardless of expect-state" {
  scenario_bond0_healthy
  bm::verify::reset
  bm::verify::bond bond0 802.3ad "" "" "" any
  bm::verify::failed
  assert_contains "$(report)" "fail mode is 'active-backup', expected '802.3ad'"
}
