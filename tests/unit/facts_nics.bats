#!/usr/bin/env bats
# bm::facts link/NIC/VLAN helpers behind `nics` and the menus.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "nic_link: operstate is the fallback" {
  mk_sys_nic eth2 up
  mk_sys_nic eth3 down
  [ "$(bm::facts::nic_link eth2)" = "up" ]
  [ "$(bm::facts::nic_link eth3)" = "no-link" ]
  [ "$(bm::facts::nic_link nosuch)" = "unknown" ]
}

@test "nic_link: carrier wins over operstate" {
  mk_sys_nic eth2 up
  printf '0\n' >"$BM_SYS_ROOT/class/net/eth2/carrier"
  [ "$(bm::facts::nic_link eth2)" = "no-link" ]
  printf '1\n' >"$BM_SYS_ROOT/class/net/eth2/carrier"
  [ "$(bm::facts::nic_link eth2)" = "up" ]
}

@test "nic_link: an administratively down port is 'off'" {
  mk_sys_nic eth2 down
  printf '0x1002\n' >"$BM_SYS_ROOT/class/net/eth2/flags"
  [ "$(bm::facts::nic_link eth2)" = "off" ]
  printf '0x1003\n' >"$BM_SYS_ROOT/class/net/eth2/flags"
  [ "$(bm::facts::nic_link eth2)" = "no-link" ]
}

@test "nic_info: link, speed, bond and MTU in one call" {
  install_sysfs_skeleton
  bm::facts::nic_info eth0
  [ "$BM_NIC_LINK" = "up" ]
  [ "$BM_NIC_SPEED" = "1000" ]
  [ "$BM_NIC_MASTER" = "bond0" ]
  [ "$BM_NIC_MTU" = "1500" ]
}

@test "nic_info: bogus speeds read as unknown" {
  mk_sys_nic eth2 down -1
  bm::facts::nic_info eth2
  [ "$BM_NIC_SPEED" = "unknown" ]
  printf '4294967295\n' >"$BM_SYS_ROOT/class/net/eth2/speed"
  bm::facts::nic_info eth2
  [ "$BM_NIC_SPEED" = "unknown" ]
  refute bm::facts::nic_info nosuch
}

@test "kernel_vlans / vlan_parent read /proc/net/vlan/config" {
  install_sysfs_skeleton
  install_proc_bond proc_bonding_active_backup_healthy bond0
  mkdir -p "$BM_PROC_ROOT/net/vlan"
  cat >"$BM_PROC_ROOT/net/vlan/config" <<'CFG'
VLAN Dev name	 | VLAN ID
Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD
bond0.120      | 120  | bond0
eth5.7         | 7  | eth5
CFG
  run bm::facts::kernel_vlans
  [ "${lines[0]}" = "bond0.120 120 bond0" ]
  [ "${lines[1]}" = "eth5.7 7 eth5" ]
  [ "$(bm::facts::vlan_parent bond0.120)" = "bond0" ]
  [ -z "$(bm::facts::vlan_parent eth0)" ]
}

@test "vlan_parent: falls back to the bond name when the kernel list is absent" {
  install_sysfs_skeleton
  install_proc_bond proc_bonding_active_backup_healthy bond0
  [ "$(bm::facts::vlan_parent bond0.300)" = "bond0" ]
  [ -z "$(bm::facts::vlan_parent nosuch.5)" ]
}
