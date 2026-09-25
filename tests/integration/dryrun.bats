#!/usr/bin/env bats
# End-to-end dry-run: full plan rendering with zero side effects, idempotent
# modify, and mode-matrix rejection through the real CLI.

load ../helpers

setup() {
  setup_sandbox
  scenario_bond0_healthy
  mk_sys_nic eth2 up 1000 52:54:00:12:34:03
  mk_sys_nic eth3 up 1000 52:54:00:12:34:04
}

# Everything the sandbox could possibly accrete during a mutation.
assert_nothing_touched() {
  # no mutating external commands at all; only read-only nmcli listings allowed
  run grep -Ev '^nmcli -t -f [^ ]+ connection show$|^nmcli -g [^ ]+ connection show ' "$BM_TEST_CALLS"
  [ -z "$output" ]
  # no profile written, no snapshot, no lock/pending state, no log file
  [ -z "$(ls -A "$BM_CONN_DIR")" ]
  [ -z "$(ls -A "$BM_BACKUP_DIR")" ]
  [ -z "$(ls -A "$BM_RUN_DIR")" ]
  [ ! -e "$BM_LOG_FILE" ]
}

@test "dry-run create: renders the complete plan and touches nothing" {
  run_cli --dry-run create bond9 --mode active-backup \
    --members eth2,eth3 \
    --ip4 10.0.0.5/24 --gw4 10.0.0.1 --dns4 10.0.0.53 \
    --mtu 9000 --miimon 200 \
    --vlan "42:ip4=10.42.0.5/24;gw4=10.42.0.1"
  [ "$status" -eq 0 ]

  assert_contains "$output" "Plan:"
  assert_contains "$output" "Create bond profile 'bond9' (mode=active-backup,miimon=200)"
  assert_contains "$output" 'nmcli connection add type bond con-name bond9 ifname bond9 bond.options mode=active-backup,miimon=200 ipv4.method disabled ipv6.method ignore'
  assert_contains "$output" "Set MTU 9000 on bond9"
  assert_contains "$output" "Add member 'eth2'"
  assert_contains "$output" "nmcli connection add type ethernet con-name bond-port-eth2 ifname eth2 master bond9 slave-type bond"
  assert_contains "$output" "Add member 'eth3'"
  assert_contains "$output" "Configure IPv4 (10.0.0.5/24) on bond9"
  assert_contains "$output" "ipv4.method manual ipv4.addresses 10.0.0.5/24 ipv4.gateway 10.0.0.1 ipv4.dns 10.0.0.53"
  assert_contains "$output" "Create VLAN 42 on bond9 (bond9.42)"
  assert_contains "$output" "Configure IPv4 (10.42.0.5/24) on bond9.42"
  assert_contains "$output" "Activate bond 'bond9'"
  assert_contains "$output" "Activate member 'eth2'"
  assert_contains "$output" "Activate VLAN interface 'bond9.42'"
  assert_contains "$output" "(dry-run: no commands executed, no files written, no snapshot taken)"

  assert_nothing_touched
}

@test "dry-run create: 802.3ad defaults are filled from config" {
  run_cli --dry-run create bond9 --mode 802.3ad --members eth2,eth3
  [ "$status" -eq 0 ]
  assert_contains "$output" "mode=802.3ad,lacp_rate=fast,miimon=100,xmit_hash_policy=layer3+4"
  assert_nothing_touched
}

@test "dry-run create: existing bond is a precondition failure, rc 3" {
  run_cli --dry-run create bond0 --mode active-backup --members eth2
  [ "$status" -eq 3 ]
  assert_contains "$output" "bond 'bond0' already exists"
}

@test "dry-run create: member enslaved elsewhere is refused, rc 3" {
  # eth0 is enslaved to bond0 in the sysfs skeleton
  run_cli --dry-run create bond9 --mode active-backup --members eth0
  [ "$status" -eq 3 ]
  assert_contains "$output" "already enslaved to bond 'bond0'"
}

@test "dry-run create: NIC policy blocks a blocklisted member, rc 3" {
  mk_sys_nic veth99 up 1000
  run_cli --dry-run create bond9 --mode active-backup --members veth99
  [ "$status" -eq 3 ]
  assert_contains "$output" "blocked by NIC policy"
}

@test "dry-run create: nonexistent member is refused, rc 3" {
  run_cli --dry-run create bond9 --mode active-backup --members eth7
  [ "$status" -eq 3 ]
  assert_contains "$output" "interface 'eth7' does not exist"
}

@test "dry-run create: invalid IPv4 CIDR rc 2" {
  run_cli --dry-run create bond9 --mode active-backup --members eth2 --ip4 999.0.0.1/24
  [ "$status" -eq 2 ]
  assert_contains "$output" "invalid IPv4 CIDR"
}

@test "dry-run create: invalid VLAN id rc 2" {
  run_cli --dry-run create bond9 --mode active-backup --members eth2 --vlan 4095
  [ "$status" -eq 2 ]
  assert_contains "$output" "invalid VLAN id '4095'"
}

# ---- mode matrix through the real CLI --------------------------------------

@test "CLI rejects arp monitoring for 802.3ad, rc 2" {
  run_cli --dry-run create bond9 --mode 802.3ad --members eth2,eth3 \
    --arp-interval 100 --arp-targets 10.0.0.1
  [ "$status" -eq 2 ]
  assert_contains "$output" "arp monitoring is not supported in mode 802.3ad"
  assert_contains "$output" "invalid bond options"
  assert_nothing_touched
}

@test "CLI rejects --primary for balance-xor, rc 2" {
  run_cli --dry-run create bond9 --mode balance-xor --members eth2,eth3 --primary eth2
  [ "$status" -eq 2 ]
  assert_contains "$output" "option 'primary' is not valid for mode balance-xor"
}

@test "CLI rejects --lacp-rate outside 802.3ad, rc 2" {
  run_cli --dry-run create bond9 --mode active-backup --members eth2,eth3 --lacp-rate fast
  [ "$status" -eq 2 ]
  assert_contains "$output" "option 'lacp_rate' is not valid for mode active-backup"
}

@test "CLI rejects arp_interval without targets, rc 2" {
  run_cli --dry-run create bond9 --mode active-backup --members eth2,eth3 \
    --opt arp_interval=100,miimon=0
  [ "$status" -eq 2 ]
  assert_contains "$output" "arp_interval requires arp_ip_target"
}

@test "CLI accepts arp monitoring for active-backup (miimon auto-dropped)" {
  run_cli --dry-run create bond9 --mode active-backup --members eth2,eth3 \
    --arp-interval 100 --arp-targets 10.0.0.1,10.0.0.2
  [ "$status" -eq 0 ]
  assert_contains "$output" "arp_interval=100,arp_ip_target=10.0.0.1,10.0.0.2"
  assert_not_contains "$output" "miimon"
}

@test "dry-run modify: switching to ARP link checks drops miimon (and back again)" {
  stub_nm_bond0_profile                                  # mode=active-backup,miimon=100
  run_cli --dry-run modify bond0 --arp-interval 1000 --arp-targets 10.0.0.1,10.0.0.2
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond.options mode=active-backup,arp_interval=1000,arp_ip_target=10.0.0.1,10.0.0.2"
  assert_contains "$output" "ARP link checks replace miimon"

  stub_nm_conn 11111111-1111-1111-1111-111111111111 \
    connection.id=bond0 connection.type=bond connection.interface-name=bond0 \
    'bond.options=mode=active-backup,arp_interval=1000,arp_ip_target=10.0.0.1'
  run_cli --dry-run modify bond0 --miimon 100
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond.options mode=active-backup,miimon=100"
  assert_contains "$output" "MII link checks replace ARP"
  refute grep -q 'bond.options .*arp_ip_target' <<<"$output"
}

@test "CLI rejects unknown mode, rc 2" {
  run_cli --dry-run create bond9 --mode round-robin --members eth2
  [ "$status" -eq 2 ]
  assert_contains "$output" "unknown mode 'round-robin'"
}

# ---- dry-run modify --------------------------------------------------------

@test "dry-run modify: idempotent options => 'Nothing to do', rc 0" {
  stub_nm_bond0_profile
  run_cli --dry-run modify bond0 --opt miimon=100
  [ "$status" -eq 0 ]
  assert_contains "$output" "Nothing to do — already in the requested state."
  assert_nothing_touched
}

@test "dry-run modify: explicitly restating the current mode is also a no-op" {
  stub_nm_bond0_profile
  run_cli --dry-run modify bond0 --opt miimon=100 --mode active-backup
  [ "$status" -eq 0 ]
  assert_contains "$output" "Nothing to do"
}

@test "dry-run modify: a real change renders exactly that plan step" {
  stub_nm_bond0_profile
  run_cli --dry-run modify bond0 --opt miimon=250
  [ "$status" -eq 0 ]
  assert_contains "$output" "Plan:"
  assert_contains "$output" "Set bond.options to 'mode=active-backup,miimon=250'"
  assert_contains "$output" "nmcli connection modify 11111111-1111-1111-1111-111111111111 bond.options mode=active-backup,miimon=250"
  assert_contains "$output" "Re-activate bond 'bond0' to apply changes"
  assert_contains "$output" "(dry-run: no commands executed, no files written, no snapshot taken)"
  assert_nothing_touched
}

@test "dry-run modify: --ip4 dhcp drops the old fixed address and gateway" {
  stub_nm_bond0_profile
  run_cli --dry-run modify bond0 --ip4 dhcp
  [ "$status" -eq 0 ]
  assert_contains "$output" "ipv4.method auto ipv4.addresses '' ipv4.gateway ''"
}

@test "dry-run modify: --gw4 none and --dns4 none clear them (shown quoted, so it can be pasted)" {
  stub_nm_bond0_profile
  run_cli --dry-run modify bond0 --ip4 10.0.5.10/24 --gw4 none --dns4 none
  [ "$status" -eq 0 ]
  assert_contains "$output" "ipv4.method manual ipv4.addresses 10.0.5.10/24 ipv4.gateway '' ipv4.dns ''"
  run_cli --dry-run modify bond0 --ip6 2001:db8::10/64 --gw6 none --dns6 none
  [ "$status" -eq 0 ]
  assert_contains "$output" "ipv6.gateway '' ipv6.dns ''"
}

@test "dry-run create: spaces inside a --vlan value do not split it into two VLANs" {
  run_cli --dry-run create bond9 --mode active-backup --members eth2,eth3 \
    --vlan "120: ip4=10.0.0.5/24; dns4=10.0.0.53, 10.0.0.54"
  [ "$status" -eq 0 ]
  assert_not_contains "$output" "invalid VLAN id"
  assert_contains "$output" "ipv4.dns 10.0.0.53,10.0.0.54"
}

@test "dry-run modify: --del-opt removes a key from the rendered options" {
  stub_nm_conn 55555555-5555-5555-5555-555555555555 \
    connection.id=bond0 connection.type=bond connection.interface-name=bond0 \
    "bond.options=mode=active-backup,miimon=100,primary=eth0"
  run_cli --dry-run modify bond0 --del-opt primary
  [ "$status" -eq 0 ]
  assert_contains "$output" "Set bond.options to 'mode=active-backup,miimon=100'"
}

@test "dry-run modify: invalid resulting option set rc 2" {
  stub_nm_bond0_profile
  run_cli --dry-run modify bond0 --opt lacp_rate=fast
  [ "$status" -eq 2 ]
  assert_contains "$output" "option 'lacp_rate' is not valid for mode active-backup"
  assert_contains "$output" "invalid resulting option set"
}

@test "modify a bond without an NM profile rc 3" {
  run_cli --dry-run modify bond7 --opt miimon=100
  [ "$status" -eq 3 ]
  assert_contains "$output" "no NetworkManager bond profile found for 'bond7'"
}

@test "dry-run remove: renders deletions for bond, ports and vlans" {
  stub_nm_bond0_profile
  stub_nm_conn 44444444-4444-4444-4444-444444444444 \
    connection.id=bond0.42 connection.type=vlan connection.interface-name=bond0.42 \
    vlan.parent=bond0 vlan.id=42
  run_cli --dry-run remove bond0
  [ "$status" -eq 0 ]
  assert_contains "$output" "Delete VLAN profile 'bond0.42' (VLAN 42)"
  assert_contains "$output" "Delete member profile 'bond-port-eth0' (eth0)"
  assert_contains "$output" "Delete member profile 'bond-port-eth1' (eth1)"
  assert_contains "$output" "Delete bond profile 'bond0'"
  assert_contains "$output" "nmcli connection delete 11111111-1111-1111-1111-111111111111"
  assert_nothing_touched
}

@test "dry-run vlan add: existing VLAN is a no-op, rc 0" {
  stub_nm_bond0_profile
  stub_nm_conn 44444444-4444-4444-4444-444444444444 \
    connection.id=bond0.42 connection.type=vlan connection.interface-name=bond0.42 \
    vlan.parent=bond0 vlan.id=42
  run_cli --dry-run vlan add bond0 42
  [ "$status" -eq 0 ]
  assert_contains "$output" "VLAN 42 already exists on bond0"
}
