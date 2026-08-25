#!/usr/bin/env bats
# The bond-mode option matrix: table-driven accept/reject across all 7 modes.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "mode validator accepts all 7 modes and rejects garbage" {
  local m
  for m in balance-rr active-backup balance-xor broadcast 802.3ad balance-tlb balance-alb; do
    bm::val::mode "$m"
  done
  run bm::val::mode "round-robin"
  [ "$status" -ne 0 ]
  run bm::val::mode ""
  [ "$status" -ne 0 ]
  run bm::val::mode "802.3AD"
  [ "$status" -ne 0 ]
}

@test "option matrix: table-driven allowed/rejected per mode" {
  # mode|allowed(csv)|rejected(csv)
  local table=(
    "balance-rr|miimon,arp_interval,arp_ip_target,packets_per_slave|primary,lacp_rate,xmit_hash_policy,min_links,fail_over_mac"
    "active-backup|miimon,arp_interval,primary,primary_reselect,fail_over_mac,arp_all_targets|lacp_rate,xmit_hash_policy,min_links,packets_per_slave"
    "balance-xor|miimon,arp_interval,xmit_hash_policy|primary,lacp_rate,fail_over_mac,tlb_dynamic_lb"
    "broadcast|miimon,arp_interval,arp_validate|xmit_hash_policy,primary,lacp_rate,min_links"
    "802.3ad|miimon,lacp_rate,xmit_hash_policy,min_links,ad_select,ad_actor_system,ad_user_port_key|arp_interval,arp_ip_target,primary,fail_over_mac,packets_per_slave"
    "balance-tlb|miimon,primary,primary_reselect,tlb_dynamic_lb,xmit_hash_policy|arp_interval,arp_ip_target,lacp_rate,min_links"
    "balance-alb|miimon,primary,primary_reselect|arp_interval,arp_ip_target,lacp_rate,xmit_hash_policy,tlb_dynamic_lb"
  )
  local row mode allowed rejected key
  for row in "${table[@]}"; do
    IFS='|' read -r mode allowed rejected <<<"$row"
    IFS=',' read -r -a ok_keys <<<"$allowed"
    IFS=',' read -r -a bad_keys <<<"$rejected"
    for key in "${ok_keys[@]}"; do
      bm::val::option_allowed "$mode" "$key" || {
        echo "expected '$key' to be allowed for $mode" >&2
        return 1
      }
    done
    for key in "${bad_keys[@]}"; do
      if bm::val::option_allowed "$mode" "$key"; then
        echo "expected '$key' to be REJECTED for $mode" >&2
        return 1
      fi
    done
  done
}

@test "common options are allowed in every mode" {
  local m k
  for m in balance-rr active-backup balance-xor broadcast 802.3ad balance-tlb balance-alb; do
    for k in miimon updelay downdelay use_carrier num_grat_arp resend_igmp all_slaves_active lp_interval; do
      bm::val::option_allowed "$m" "$k"
    done
  done
}

# ---- option_set: cross-option constraints ----------------------------------

@test "option_set: valid active-backup arp-monitoring set passes" {
  declare -A o=(
    [arp_interval]="100"
    [arp_ip_target]="10.0.0.1,10.0.0.2"
    [miimon]="0"
  )
  run bm::val::option_set active-backup o
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "option_set: arp monitoring rejected for 802.3ad" {
  declare -A o=([arp_interval]="100" [arp_ip_target]="10.0.0.1")
  run bm::val::option_set 802.3ad o
  [ "$status" -ne 0 ]
  assert_contains "$output" "arp monitoring is not supported in mode 802.3ad"
}

@test "option_set: arp monitoring rejected for balance-tlb and balance-alb" {
  local m
  for m in balance-tlb balance-alb; do
    declare -A o=([arp_interval]="100" [arp_ip_target]="10.0.0.1")
    run bm::val::option_set "$m" o
    [ "$status" -ne 0 ]
    assert_contains "$output" "arp monitoring is not supported in mode $m"
    unset o
  done
}

@test "option_set: arp_interval without arp_ip_target is rejected" {
  declare -A o=([arp_interval]="100")
  run bm::val::option_set active-backup o
  [ "$status" -ne 0 ]
  assert_contains "$output" "arp_interval requires arp_ip_target"
}

@test "option_set: arp_ip_target without arp_interval is rejected" {
  declare -A o=([arp_ip_target]="10.0.0.1")
  run bm::val::option_set active-backup o
  [ "$status" -ne 0 ]
  assert_contains "$output" "arp_ip_target requires arp_interval"
}

@test "option_set: miimon and arp_interval both non-zero is rejected" {
  declare -A o=(
    [miimon]="100"
    [arp_interval]="100"
    [arp_ip_target]="10.0.0.1"
  )
  run bm::val::option_set active-backup o
  [ "$status" -ne 0 ]
  assert_contains "$output" "mutually exclusive"
}

@test "option_set: primary restricted to active-backup/tlb/alb" {
  local m
  for m in active-backup balance-tlb balance-alb; do
    declare -A o=([primary]="eth0")
    run bm::val::option_set "$m" o
    [ "$status" -eq 0 ]
    unset o
  done
  for m in balance-rr balance-xor broadcast 802.3ad; do
    declare -A o=([primary]="eth0")
    run bm::val::option_set "$m" o
    [ "$status" -ne 0 ]
    assert_contains "$output" "primary"
    unset o
  done
}

@test "option_set: unknown mode is rejected outright" {
  declare -A o=()
  run bm::val::option_set no-such-mode o
  [ "$status" -ne 0 ]
  assert_contains "$output" "unknown bond mode"
}

@test "option_set: healthy 802.3ad tuning set passes" {
  declare -A o=(
    [miimon]="100"
    [lacp_rate]="fast"
    [xmit_hash_policy]="layer3+4"
    [min_links]="1"
    [ad_actor_system]="02:00:00:00:00:01"
  )
  run bm::val::option_set 802.3ad o
  [ "$status" -eq 0 ]
}

# ---- option_value: per-key format checks -----------------------------------

@test "option_value: rejects malformed values" {
  run bm::val::option_value miimon "abc";               [ "$status" -ne 0 ]
  run bm::val::option_value lacp_rate "medium";         [ "$status" -ne 0 ]
  run bm::val::option_value xmit_hash_policy "layer9";  [ "$status" -ne 0 ]
  run bm::val::option_value ad_actor_system "02:00:00"; [ "$status" -ne 0 ]
  run bm::val::option_value arp_ip_target "10.0.0.999"; [ "$status" -ne 0 ]
  run bm::val::option_value primary "bad name";         [ "$status" -ne 0 ]
  run bm::val::option_value use_carrier "2";            [ "$status" -ne 0 ]
}

@test "option_value: accepts well-formed values" {
  bm::val::option_value miimon 100
  bm::val::option_value lacp_rate slow
  bm::val::option_value lacp_rate 1
  bm::val::option_value xmit_hash_policy vlan+srcmac
  bm::val::option_value ad_actor_system "02:aa:bb:cc:dd:ee"
  bm::val::option_value arp_ip_target "10.0.0.1,192.168.0.1"
  bm::val::option_value primary_reselect better
  bm::val::option_value fail_over_mac follow
  bm::val::option_value arp_validate filter_backup
}
