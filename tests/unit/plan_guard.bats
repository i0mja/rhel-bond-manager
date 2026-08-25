#!/usr/bin/env bats
# bm::plan::ssh_guard — the tier-aware decision itself, including the pure
# snapshot tier (unreachable from an integration test on a host that has
# systemd-run) and the contract that it RETURNS rather than exits, so the
# caller can disarm protection it already armed before aborting.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "guard: no SSH session => proceed" {
  run bm::plan::ssh_guard snapshot bond0 eth0
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "guard: session on an unrelated device => proceed" {
  stub_ssh_session 10.1.2.3 ens9
  run bm::plan::ssh_guard snapshot bond0 eth0 eth1
  [ "$status" -eq 0 ]
}

@test "guard: checkpoint tier warns but proceeds" {
  stub_ssh_session 10.1.2.3 bond0
  run bm::plan::ssh_guard checkpoint bond0 eth0
  [ "$status" -eq 0 ]
  assert_contains "$output" "NOTE: this change touches 'bond0', which carries your SSH session."
  assert_contains "$output" "auto-rollback in 120s"
}

@test "guard: snapshot tier refuses" {
  stub_ssh_session 10.1.2.3 bond0
  run bm::plan::ssh_guard snapshot bond0 eth0
  [ "$status" -eq 1 ]
  assert_contains "$output" "checkpoints are unavailable (tier: snapshot)"
  assert_contains "$output" "Use a console, or re-run with --force-unsafe"
}

@test "guard: deadman tier refuses" {
  stub_ssh_session 10.1.2.3 bond0
  run bm::plan::ssh_guard deadman bond0
  [ "$status" -eq 1 ]
  assert_contains "$output" "(tier: deadman)"
}

@test "guard: refusal RETURNS to the caller instead of exiting" {
  # the caller has already armed protection by the time it re-checks the
  # guard; a die() here would leave a timer armed against an unchanged host
  stub_ssh_session 10.1.2.3 bond0
  local rc=0
  bm::plan::ssh_guard snapshot bond0 2>/dev/null || rc=$?
  local reached_next_statement=1      # unreachable if the guard exited
  [ "$rc" -eq 1 ]
  [ "$reached_next_statement" -eq 1 ]
}

@test "guard: --force-unsafe converts the refusal into a warning" {
  stub_ssh_session 10.1.2.3 bond0
  BM_FORCE_UNSAFE=1
  run bm::plan::ssh_guard snapshot bond0
  [ "$status" -eq 0 ]
  assert_contains "$output" "WARNING: proceeding without checkpoint protection"
}

@test "guard: any device in the affected list counts (member or VLAN)" {
  stub_ssh_session 10.1.2.3 bond0.120
  run bm::plan::ssh_guard deadman bond0 eth0 eth1 bond0.120
  [ "$status" -eq 1 ]
  assert_contains "$output" "this change touches 'bond0.120'"

  stub_ssh_session 10.1.2.3 eth1
  run bm::plan::ssh_guard deadman bond0 eth0 eth1
  [ "$status" -eq 1 ]
  assert_contains "$output" "this change touches 'eth1'"
}

@test "guard: the warning quotes the configured rollback window" {
  stub_ssh_session 10.1.2.3 bond0
  BM_ROLLBACK_WINDOW=600
  run bm::plan::ssh_guard checkpoint bond0
  [ "$status" -eq 0 ]
  assert_contains "$output" "auto-rollback in 600s"
}
