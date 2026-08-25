#!/usr/bin/env bats
# bm::facts::* — /proc + /sys parsers against realistic fixtures.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

mode_of_raw() { # write a minimal proc file with a raw mode line, normalize it
  printf 'Bonding Mode: %s\n' "$1" >"$BM_PROC_ROOT/net/bonding/bondX"
  bm::facts::bond_mode bondX
}

@test "bond_mode: normalizes every kernel mode string" {
  [ "$(mode_of_raw 'load balancing (round-robin)')" = "balance-rr" ]
  [ "$(mode_of_raw 'fault-tolerance (active-backup)')" = "active-backup" ]
  [ "$(mode_of_raw 'fault-tolerance (active-backup) (fail_over_mac active)')" = "active-backup" ]
  [ "$(mode_of_raw 'load balancing (xor)')" = "balance-xor" ]
  [ "$(mode_of_raw 'fault-tolerance (broadcast)')" = "broadcast" ]
  [ "$(mode_of_raw 'IEEE 802.3ad Dynamic link aggregation')" = "802.3ad" ]
  [ "$(mode_of_raw 'transmit load balancing')" = "balance-tlb" ]
  [ "$(mode_of_raw 'adaptive load balancing')" = "balance-alb" ]
}

@test "bond_mode: missing bond reports unknown" {
  [ "$(bm::facts::bond_mode nosuchbond)" = "unknown" ]
}

@test "bond_members: lists members in proc order" {
  scenario_bond0_healthy
  run bm::facts::bond_members bond0
  [ "${lines[0]}" = "eth0" ]
  [ "${lines[1]}" = "eth1" ]
  [ "${#lines[@]}" -eq 2 ]
}

@test "bond_member_mii: per-member status" {
  scenario_bond0_degraded
  [ "$(bm::facts::bond_member_mii bond0 eth0)" = "up" ]
  [ "$(bm::facts::bond_member_mii bond0 eth1)" = "down" ]
  [ "$(bm::facts::bond_member_mii bond0 eth9)" = "unknown" ]
}

@test "bond_member_speed_duplex: parses per-slave section" {
  scenario_bond0_healthy
  [ "$(bm::facts::bond_member_speed_duplex bond0 eth0)" = "1000 full" ]
  scenario_bond0_degraded
  [ "$(bm::facts::bond_member_speed_duplex bond0 eth1)" = "Unknown Unknown" ]
}

@test "nic_link_failures: reads per-slave counter" {
  scenario_bond0_degraded
  [ "$(bm::facts::nic_link_failures bond0 eth0)" = "1" ]
  [ "$(bm::facts::nic_link_failures bond0 eth1)" = "3" ]
}

@test "bond_proc_value: bond-level fields" {
  scenario_bond0_healthy
  [ "$(bm::facts::bond_proc_value bond0 'Currently Active Slave')" = "eth0" ]
  [ "$(bm::facts::bond_proc_value bond0 'MII Polling Interval (ms)')" = "100" ]
  [ "$(bm::facts::bond_proc_value bond0 'Primary Slave')" = "None" ]
}

@test "bond_lacp_info: parses the tab-indented aggregator block" {
  scenario_bond1_8023ad
  run bm::facts::bond_lacp_info bond1
  assert_contains "$output" "aggregator_id 1"
  assert_contains "$output" "ports 2"
  assert_contains "$output" "partner_mac 02:aa:bb:cc:dd:01"
}

@test "bond_member_agg_id: per-member aggregator" {
  scenario_bond1_8023ad
  [ "$(bm::facts::bond_member_agg_id bond1 ens1f0)" = "1" ]
  [ "$(bm::facts::bond_member_agg_id bond1 ens1f1)" = "1" ]
}

@test "nic facts from sysfs: state, speed, mac, master" {
  scenario_bond0_healthy
  bm::facts::nic_exists eth0
  [ "$(bm::facts::nic_state eth0)" = "up" ]
  [ "$(bm::facts::nic_speed eth0)" = "1000" ]
  [ "$(bm::facts::nic_mac eth0)" = "52:54:00:12:34:01" ]
  [ "$(bm::facts::nic_bond_master eth0)" = "bond0" ]
  [ -z "$(bm::facts::nic_bond_master bond0)" ]
  bm::facts::nic_is_physical eth0
  run bm::facts::nic_is_physical bond0
  [ "$status" -ne 0 ]
}

@test "nic_allowed: allow/block policy" {
  bm::facts::nic_allowed eth0
  bm::facts::nic_allowed ens1f0
  bm::facts::nic_allowed enp3s0
  run bm::facts::nic_allowed lo;       [ "$status" -ne 0 ]
  run bm::facts::nic_allowed veth1234; [ "$status" -ne 0 ]
  run bm::facts::nic_allowed docker0;  [ "$status" -ne 0 ]
  run bm::facts::nic_allowed bond0;    [ "$status" -ne 0 ]
  run bm::facts::nic_allowed wlp2s0;   [ "$status" -ne 0 ]
}

@test "kernel_bonds: lists proc entries" {
  scenario_bond0_healthy
  scenario_bond1_8023ad
  run bm::facts::kernel_bonds
  assert_contains "$output" "bond0"
  assert_contains "$output" "bond1"
}

# ---- health verdicts -------------------------------------------------------

@test "health: active-backup all-up is healthy with no reasons" {
  scenario_bond0_healthy
  run bm::facts::bond_health bond0
  [ "${lines[0]}" = "healthy" ]
  [ "${#lines[@]}" -eq 1 ]
}

@test "health: one member MII down => degraded, single precise reason" {
  scenario_bond0_degraded
  run bm::facts::bond_health bond0
  [ "${lines[0]}" = "degraded" ]
  assert_contains "$output" "member eth1 MII status is 'down'"
  # the kernel's 'Unknown' speed/duplex must NOT produce bogus reasons
  assert_not_contains "$output" "speed mismatch"
  assert_not_contains "$output" "duplex"
}

@test "health: bond operstate down => down" {
  scenario_bond0_down
  run bm::facts::bond_health bond0
  [ "${lines[0]}" = "down" ]
  assert_contains "$output" "bond operstate is 'down'"
}

@test "health: bond absent from kernel => down" {
  run bm::facts::bond_health bond7
  [ "${lines[0]}" = "down" ]
  assert_contains "$output" "not present in kernel"
}

@test "health: no member has link => down" {
  scenario_bond0_healthy
  # flip both members down in the proc file
  sed -i 's/^MII Status: up$/MII Status: down/' "$BM_PROC_ROOT/net/bonding/bond0"
  run bm::facts::bond_health bond0
  [ "${lines[0]}" = "down" ]
  assert_contains "$output" "no member has link"
}

@test "health: 802.3ad with partner is healthy" {
  scenario_bond1_8023ad
  run bm::facts::bond_health bond1
  [ "${lines[0]}" = "healthy" ]
}

@test "health: 802.3ad zero partner mac => degraded (no LACP partner)" {
  scenario_bond1_8023ad_no_partner
  run bm::facts::bond_health bond1
  [ "${lines[0]}" = "degraded" ]
  assert_contains "$output" "no LACP partner"
}

@test "health: member speed mismatch degrades" {
  scenario_bond0_healthy
  sed -i '0,/^Speed: 1000 Mbps$/s//Speed: 100 Mbps/' "$BM_PROC_ROOT/net/bonding/bond0"
  run bm::facts::bond_health bond0
  [ "${lines[0]}" = "degraded" ]
  assert_contains "$output" "speed mismatch"
}

@test "health: half duplex degrades" {
  scenario_bond0_healthy
  sed -i '0,/^Duplex: full$/s//Duplex: half/' "$BM_PROC_ROOT/net/bonding/bond0"
  run bm::facts::bond_health bond0
  [ "${lines[0]}" = "degraded" ]
  assert_contains "$output" "duplex is 'half'"
}
