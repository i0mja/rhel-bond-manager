#!/usr/bin/env bats
# bm::wf::cli_equivalent — the command line the menus show for every change.
# It is advertised as "the same thing as a command", so it must be a command
# that actually works.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
  bm::wf::spec_reset
}

@test "add-member / remove-member take the ports positionally" {
  BM_SPEC[bond]=bond0
  BM_SPEC[members]=eth2,eth3
  bm::wf::cli_equivalent add-member
  [ "$BM_WF_CLI" = "bond-manager add-member bond0 eth2,eth3" ]
  bm::wf::cli_equivalent remove-member
  [ "$BM_WF_CLI" = "bond-manager remove-member bond0 eth2,eth3" ]
}

@test "swap-member" {
  BM_SPEC[bond]=bond0 BM_SPEC[old]=ens1f0 BM_SPEC[new]=ens2f0
  bm::wf::cli_equivalent swap-member
  [ "$BM_WF_CLI" = "bond-manager swap-member bond0 --old ens1f0 --new ens2f0" ]
}

@test "create: everything, with the VLAN token quoted" {
  BM_SPEC[bond]=bond9 BM_SPEC[mode]=802.3ad BM_SPEC[members]=eth2,eth3
  BM_SPEC[ip4]=none BM_SPEC[mtu]=9000
  BM_SPEC[vlans]='120:ip4=10.0.0.5/24;gw4=10.0.0.1'
  bm::wf::cli_equivalent create
  [ "$BM_WF_CLI" = "bond-manager create bond9 --mode 802.3ad --members eth2,eth3 --mtu 9000 --ip4 none --vlan '120:ip4=10.0.0.5/24;gw4=10.0.0.1'" ]
}

@test "modify: options, deleted options and --no-activate" {
  BM_SPEC[bond]=bond0 BM_SPEC[opts]=miimon=50 BM_SPEC[del_opts]=" primary updelay"
  BM_SPEC[activate]=0
  bm::wf::cli_equivalent modify
  [ "$BM_WF_CLI" = "bond-manager modify bond0 --opt miimon=50 --del-opt primary --del-opt updelay --no-activate" ]
}

@test "vlan add / modify / remove, clone, repair, remove" {
  BM_SPEC[bond]=bond0 BM_SPEC[vlans]=120
  bm::wf::cli_equivalent vlan-add
  [ "$BM_WF_CLI" = "bond-manager vlan add bond0 120" ]
  BM_SPEC[vlan_id]=120 BM_SPEC[ip4]=dhcp
  bm::wf::cli_equivalent vlan-modify
  [ "$BM_WF_CLI" = "bond-manager vlan modify bond0 120 --ip4 dhcp" ]
  bm::wf::cli_equivalent vlan-remove
  [ "$BM_WF_CLI" = "bond-manager vlan remove bond0 120" ]
  bm::wf::spec_reset
  BM_SPEC[src]=bond0 BM_SPEC[bond]=bond1 BM_SPEC[members]=eth2 BM_SPEC[copy_vlans]=1
  bm::wf::cli_equivalent clone
  [ "$BM_WF_CLI" = "bond-manager clone bond0 bond1 --members eth2 --copy-vlans" ]
  bm::wf::cli_equivalent repair
  [ "$BM_WF_CLI" = "bond-manager repair bond1" ]
  BM_SPEC[keep_vlans]=1
  bm::wf::cli_equivalent remove
  [ "$BM_WF_CLI" = "bond-manager remove bond1 --keep-vlans" ]
}

@test "values a shell would interpret are quoted" {
  BM_SPEC[bond]='bond0' BM_SPEC[members]='eth2;reboot'
  bm::wf::cli_equivalent add-member
  [ "$BM_WF_CLI" = "bond-manager add-member bond0 'eth2;reboot'" ]
}

@test "the shown command is one the CLI accepts (add-member, the v3.0 bug)" {
  scenario_bond0_healthy
  mk_sys_nic eth2 up 1000
  stub_nm_bond0_profile
  BM_SPEC[bond]=bond0 BM_SPEC[members]=eth2
  bm::wf::cli_equivalent add-member
  eval "set -- ${BM_WF_CLI#bond-manager }"
  run_cli -n "$@"
  [ "$status" -eq 0 ]
  assert_contains "$output" "Add member 'eth2'"
}
