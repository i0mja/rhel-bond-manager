#!/usr/bin/env bats
# End-to-end diagnose against fixtures (kernel state, health, LACP, ping).

load ../helpers

setup() {
  setup_sandbox
}

@test "diagnose: healthy active-backup bond" {
  scenario_bond0_healthy
  stub_ip_file link "bond0            UP             52:54:00:12:34:01 <BROADCAST,MULTICAST,MASTER,UP,LOWER_UP>"
  stub_ip_file link_eth0 "eth0             UP             52:54:00:12:34:01 <BROADCAST,MULTICAST,SLAVE,UP,LOWER_UP>"
  stub_ip_file link_eth1 "eth1             UP             52:54:00:12:34:02 <BROADCAST,MULTICAST,SLAVE,UP,LOWER_UP>"
  stub_ip_file addr "bond0            UP             10.0.0.5/24"
  stub_ip_file addr_bond0 "bond0            UP             10.0.0.5/24"

  run_cli diagnose bond0 --target 10.0.0.1
  [ "$status" -eq 0 ]
  assert_contains "$output" "=== bond0: kernel bonding state ==="
  assert_contains "$output" "Bonding Mode: fault-tolerance (active-backup)"
  assert_contains "$output" "verdict: healthy"
  echo "$output" | grep -Eq 'eth0 +mii=up +speed=1000 +duplex=full +link_failures=0'
  echo "$output" | grep -Eq 'eth1 +mii=up'
  assert_contains "$output" "=== Reachability (10.0.0.1) ==="
  assert_contains "$output" "via bond0: reachable"
  grep -q "ping -c 2 -W 2 -I bond0 10.0.0.1" "$BM_TEST_CALLS"
}

@test "diagnose: degraded bond lists the failing member" {
  scenario_bond0_degraded
  run_cli diagnose bond0 --target 10.0.0.1
  [ "$status" -eq 0 ]
  assert_contains "$output" "verdict: degraded"
  assert_contains "$output" "- member eth1 MII status is 'down'"
  echo "$output" | grep -Eq 'eth1 +mii=down +speed=Unknown +duplex=Unknown +link_failures=3'
}

@test "diagnose: bond missing from kernel says so" {
  run_cli diagnose bond7
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond not present in kernel"
  assert_contains "$output" "verdict: down"
}

@test "diagnose: unreachable target is reported" {
  scenario_bond0_healthy
  stub_ip_file addr_bond0 "bond0            UP             10.0.0.5/24"
  export BM_STUB_PING_RC=1
  run_cli diagnose bond0 --target 10.0.0.1
  [ "$status" -eq 0 ]
  assert_contains "$output" "via bond0: no reply"
}

@test "diagnose: no target defaults to the IPv4 default gateway" {
  scenario_bond0_healthy
  stub_ip_file route4_default "default via 10.0.0.254 dev bond0 proto dhcp metric 300"
  stub_ip_file addr_bond0 "bond0            UP             10.0.0.5/24"
  run_cli diagnose bond0
  [ "$status" -eq 0 ]
  assert_contains "$output" "=== Reachability (10.0.0.254) ==="
  assert_contains "$output" "via bond0: reachable"
}

@test "diagnose: 802.3ad shows LACP info and per-member aggregator ids" {
  scenario_bond1_8023ad
  run_cli diagnose bond1 --target 10.0.0.1
  [ "$status" -eq 0 ]
  assert_contains "$output" "=== LACP (802.3ad) ==="
  assert_contains "$output" "aggregator_id 1"
  assert_contains "$output" "ports 2"
  assert_contains "$output" "partner_mac 02:aa:bb:cc:dd:01"
  echo "$output" | grep -Eq 'ens1f0 .*agg_id=1'
  assert_not_contains "$output" "no LACP partner"
}

@test "diagnose: 802.3ad without partner prints the switch-side warning" {
  scenario_bond1_8023ad_no_partner
  run_cli diagnose bond1 --target 10.0.0.1
  [ "$status" -eq 0 ]
  assert_contains "$output" "verdict: degraded"
  assert_contains "$output" "WARNING: no LACP partner"
  assert_contains "$output" "partner_mac 00:00:00:00:00:00"
}

@test "diagnose --extended: NM profiles, ethtool and journal sections" {
  scenario_bond0_healthy
  stub_nm_bond0_profile
  run_cli diagnose bond0 --extended --target 10.0.0.1
  [ "$status" -eq 0 ]
  assert_contains "$output" "=== NetworkManager profiles ==="
  assert_contains "$output" "bond profile: bond0 (uuid 11111111-1111-1111-1111-111111111111, ifname bond0)"
  assert_contains "$output" "port profile: bond-port-eth0"
  assert_contains "$output" "port profile: bond-port-eth1"
  assert_contains "$output" "=== ethtool driver info ==="
  assert_contains "$output" "driver: stub-nic"
  assert_contains "$output" "=== Recent NetworkManager log ==="
  assert_contains "$output" "stub journal"
  grep -q "^ethtool -i eth0" "$BM_TEST_CALLS"
  grep -q "^journalctl -u NetworkManager" "$BM_TEST_CALLS"
}

@test "diagnose without a bond argument rc 2" {
  run_cli diagnose
  [ "$status" -eq 2 ]
  assert_contains "$output" "usage: bond-manager diagnose BOND"
}
