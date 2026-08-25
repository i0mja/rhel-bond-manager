#!/usr/bin/env bats
# bm::ckpt::* — protection-tier probing and D-Bus checkpoint plumbing
# (exercises the busctl stub's Ping + CheckpointCreate contract).

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "probe_tier: busctl Ping ok => checkpoint" {
  [ "$(bm::ckpt::probe_tier)" = "checkpoint" ]
  grep -q "busctl .*org.freedesktop.DBus.Peer Ping" "$BM_TEST_CALLS"
}

@test "probe_tier: NM D-Bus unreachable => deadman (systemd-run present)" {
  export BM_STUB_BUSCTL_PING_RC=1
  [ "$(bm::ckpt::probe_tier)" = "deadman" ]
}

@test "probe_tier: --no-checkpoint forces deadman" {
  BM_NO_CHECKPOINT=1
  [ "$(bm::ckpt::probe_tier)" = "deadman" ]
}

@test "dbus_create: parses the checkpoint object path from busctl reply" {
  run bm::ckpt::dbus_create 120
  [ "$status" -eq 0 ]
  [ "$output" = "/org/freedesktop/NetworkManager/Checkpoint/1" ]
  grep -q "busctl call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager CheckpointCreate aouu 0 120 6" "$BM_TEST_CALLS"
}

@test "dbus_create: busctl failure is reported as rc!=0" {
  export BM_STUB_CKPT_CREATE_RC=1
  run bm::ckpt::dbus_create 120
  [ "$status" -ne 0 ]
}

@test "pending state: arm/load/commit round-trip" {
  require_root
  bm::ckpt::arm 120 20240101-000000 "unit-test change"
  [ -f "$BM_RUN_DIR/pending.state" ]
  bm::ckpt::load_pending
  [ "$BM_PENDING_TIER" = "checkpoint" ]
  [ "$BM_PENDING_PATH" = "/org/freedesktop/NetworkManager/Checkpoint/1" ]
  [ "$BM_PENDING_SNAPSHOT" = "20240101-000000" ]
  [ "$BM_PENDING_SUMMARY" = "unit-test change" ]
  bm::ckpt::commit >/dev/null
  [ ! -f "$BM_RUN_DIR/pending.state" ]
  grep -q "busctl .*CheckpointDestroy" "$BM_TEST_CALLS"
}

@test "commit with no pending state returns 1" {
  run bm::ckpt::commit
  [ "$status" -eq 1 ]
  assert_contains "$output" "no pending change"
}
