#!/usr/bin/env bats
# bm::nm::opts_parse / opts_render / opts_merge — bond.options handling.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "opts_parse: basic key=value tokens" {
  declare -A o=()
  bm::nm::opts_parse "mode=active-backup,miimon=100,primary=eth0" o
  [ "${#o[@]}" -eq 3 ]
  [ "${o[mode]}" = "active-backup" ]
  [ "${o[miimon]}" = "100" ]
  [ "${o[primary]}" = "eth0" ]
}

@test "opts_parse: arp_ip_target keeps its embedded commas" {
  declare -A o=()
  bm::nm::opts_parse "mode=active-backup,arp_interval=100,arp_ip_target=10.0.0.1,10.0.0.2,192.168.9.1,arp_validate=all" o
  [ "${o[arp_ip_target]}" = "10.0.0.1,10.0.0.2,192.168.9.1" ]
  [ "${o[arp_validate]}" = "all" ]
  [ "${o[arp_interval]}" = "100" ]
}

@test "opts_parse: empty string yields empty set" {
  declare -A o=()
  bm::nm::opts_parse "" o
  [ "${#o[@]}" -eq 0 ]
}

@test "opts_render: mode first, remaining keys sorted deterministically" {
  declare -A o=(
    [xmit_hash_policy]="layer3+4"
    [mode]="802.3ad"
    [miimon]="100"
    [lacp_rate]="fast"
  )
  run bm::nm::opts_render o
  [ "$output" = "mode=802.3ad,lacp_rate=fast,miimon=100,xmit_hash_policy=layer3+4" ]
}

@test "opts_render: render is stable across repeated calls" {
  declare -A o=([mode]="balance-xor" [b_opt]="2" [a_opt]="1" [c_opt]="3")
  local first second
  first="$(bm::nm::opts_render o)"
  second="$(bm::nm::opts_render o)"
  [ "$first" = "$second" ]
  [ "$first" = "mode=balance-xor,a_opt=1,b_opt=2,c_opt=3" ]
}

@test "opts round-trip: parse(render(x)) == x including commas in values" {
  declare -A o=(
    [mode]="active-backup"
    [arp_interval]="250"
    [arp_ip_target]="10.0.0.1,10.0.0.2"
    [primary]="eth0"
  )
  local rendered
  rendered="$(bm::nm::opts_render o)"
  declare -A back=()
  bm::nm::opts_parse "$rendered" back
  [ "${#back[@]}" -eq 4 ]
  [ "${back[mode]}" = "active-backup" ]
  [ "${back[arp_interval]}" = "250" ]
  [ "${back[arp_ip_target]}" = "10.0.0.1,10.0.0.2" ]
  [ "${back[primary]}" = "eth0" ]
}

@test "opts_merge: override + add keys" {
  run bm::nm::opts_merge "mode=active-backup,miimon=100" "miimon=250" "updelay=200"
  [ "$output" = "mode=active-backup,miimon=250,updelay=200" ]
}

@test "opts_merge: 'key=' deletes the key" {
  run bm::nm::opts_merge "mode=active-backup,miimon=100,primary=eth0" "primary="
  [ "$output" = "mode=active-backup,miimon=100" ]
}

@test "opts_merge: replace miimon with arp monitoring in one merge" {
  run bm::nm::opts_merge "mode=active-backup,miimon=100" \
    "miimon=" "arp_interval=250" "arp_ip_target=10.0.0.1,10.0.0.9"
  [ "$output" = "mode=active-backup,arp_interval=250,arp_ip_target=10.0.0.1,10.0.0.9" ]
}

@test "opts_merge: no changes returns normalized current string" {
  run bm::nm::opts_merge "miimon=100,mode=active-backup"
  [ "$output" = "mode=active-backup,miimon=100" ]
}
