#!/usr/bin/env bats
# End-to-end basics: version/help, usage errors, unknown commands.

load ../helpers

setup() {
  setup_sandbox
}

@test "--version prints name and version, rc 0" {
  run_cli --version
  [ "$status" -eq 0 ]
  [ "$output" = "bond-manager 3.1.0" ]
}

@test "version subcommand matches -V" {
  run_cli version
  [ "$status" -eq 0 ]
  [ "$output" = "bond-manager 3.1.0" ]
}

@test "--help shows commands, modes and exit-code contract, rc 0" {
  run_cli --help
  [ "$status" -eq 0 ]
  assert_contains "$output" "Usage: bond-manager"
  assert_contains "$output" "create BOND --mode MODE"
  assert_contains "$output" "balance-rr active-backup balance-xor broadcast 802.3ad balance-tlb balance-alb"
  assert_contains "$output" "10 degraded | 11 down"
  assert_contains "$output" "Legacy flags: --status"
}

@test "no command on a non-TTY prints usage, rc 2" {
  run_cli
  [ "$status" -eq 2 ]
  assert_contains "$output" "Usage: bond-manager"
}

@test "unknown command rc 2" {
  run_cli frobnicate
  [ "$status" -eq 2 ]
  assert_contains "$output" 'unknown command "frobnicate"'
}

@test "create without arguments rc 2" {
  run_cli create
  [ "$status" -eq 2 ]
  assert_contains "$output" "usage: bond-manager create BOND"
}

@test "show without bond rc 2" {
  run_cli show
  [ "$status" -eq 2 ]
  assert_contains "$output" "usage: bond-manager show BOND"
}

@test "create with unknown flag rc 2" {
  run_cli --dry-run create bond9 --mode active-backup --members eth0,eth1 --bogus-flag x
  [ "$status" -eq 2 ]
  assert_contains "$output" "unknown flag '--bogus-flag'"
}

@test "diagnose with unknown flag rc 2" {
  run_cli diagnose bond0 --bogus
  [ "$status" -eq 2 ]
  assert_contains "$output" "unknown flag '--bogus'"
}

@test "vlan with bad action rc 2" {
  run_cli vlan explode bond0
  [ "$status" -eq 2 ]
  assert_contains "$output" "usage: bond-manager vlan"
}

@test "snapshot with bad action rc 2" {
  run_cli snapshot explode
  [ "$status" -eq 2 ]
  assert_contains "$output" "usage: bond-manager snapshot"
}

@test "swap-member without --old/--new rc 2" {
  run_cli --dry-run swap-member bond0
  [ "$status" -eq 2 ]
  assert_contains "$output" "requires --old and --new"
}

@test "--rollback-window out of range rc 2" {
  run_cli --rollback-window 5 list
  [ "$status" -eq 2 ]
  assert_contains "$output" "--rollback-window must be 10..86400"
}

@test "config path prints the (overridden) config path" {
  run_cli config path
  [ "$status" -eq 0 ]
  [ "$output" = "$BM_CONF" ]
}

@test "config show renders effective configuration" {
  run_cli config show
  [ "$status" -eq 0 ]
  assert_contains "$output" 'DEFAULT_MIIMON="100"'
  assert_contains "$output" 'ROLLBACK_WINDOW="120"'
  assert_contains "$output" "defaults in effect"
}

@test "completion bash emits a completion script" {
  run_cli completion bash
  [ "$status" -eq 0 ]
  assert_contains "$output" "complete -F _bond_manager bond-manager"
}
