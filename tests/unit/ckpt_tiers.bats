#!/usr/bin/env bats
# bm::ckpt::* — the protection ladder itself: which tier a host gets, what
# arming records, and what commit/rollback/rebudget do to it. These paths
# decide whether an operator can get their network back, so every branch is
# pinned here rather than left to the integration tests.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
  # main() sets BM_SELF from $0; unit tests call the module directly.
  BM_SELF="$BM_ARTIFACT"
}

# ---- tier probing ----------------------------------------------------------

@test "probe_tier: busctl present but NM D-Bus silent => deadman" {
  export BM_STUB_BUSCTL_PING_RC=1
  [ "$(bm::ckpt::probe_tier)" = "deadman" ]
  assert_called 'busctl .*org.freedesktop.DBus.Peer Ping'
}

@test "probe_tier: no busctl at all => deadman (systemd-run present)" {
  # have_cmd is the module's own capability question; answering 'no' for
  # busctl is exactly what a host without systemd-bus tooling looks like.
  bm::core::have_cmd() { [[ "$1" != busctl ]]; }
  [ "$(bm::ckpt::probe_tier)" = "deadman" ]
  assert_not_called '^busctl '
}

@test "probe_tier: neither busctl nor systemd-run => snapshot" {
  bm::core::have_cmd() { [[ "$1" != busctl && "$1" != systemd-run ]]; }
  [ "$(bm::ckpt::probe_tier)" = "snapshot" ]
  assert_not_called '^busctl '
  assert_not_called '^systemd-run '
}

@test "probe_tier: --no-checkpoint skips tier 1 without probing D-Bus" {
  BM_NO_CHECKPOINT=1
  [ "$(bm::ckpt::probe_tier)" = "deadman" ]
  # the point of --no-checkpoint is that NetworkManager is never asked
  assert_not_called '^busctl '
}

@test "probe_tier: --no-checkpoint with no systemd-run => snapshot" {
  BM_NO_CHECKPOINT=1
  bm::core::have_cmd() { [[ "$1" != systemd-run ]]; }
  [ "$(bm::ckpt::probe_tier)" = "snapshot" ]
  assert_not_called '^busctl '
}

# ---- arming ----------------------------------------------------------------

@test "arm (checkpoint): pending state records tier, path, snapshot, deadline, summary" {
  require_root
  local before
  before="$(date +%s)"
  bm::ckpt::arm 120 20240101-000000 "create bond9 (active-backup, members eth2,eth3)"

  [ "$BM_CKPT_TIER" = "checkpoint" ]
  local f="$BM_RUN_DIR/pending.state"
  [ -f "$f" ]
  run cat "$f"
  assert_contains "$output" "tier=checkpoint"
  assert_contains "$output" "checkpoint_path=/org/freedesktop/NetworkManager/Checkpoint/1"
  assert_contains "$output" "deadman_unit="
  assert_contains "$output" "snapshot=20240101-000000"
  assert_contains "$output" "summary=create bond9 (active-backup, members eth2,eth3)"
  assert_contains "$output" "pid=$$"
  grep -Eq '^created=[0-9]{4}-[0-9]{2}-[0-9]{2}T' "$f"

  # the deadline is a full window into the future, not a bare timeout value
  local deadline
  deadline="$(sed -n 's/^deadline=//p' "$f")"
  (( deadline >= before + 120 && deadline <= before + 125 ))

  # a new session can read it all back
  bm::ckpt::load_pending
  [ "$BM_PENDING_TIER" = "checkpoint" ]
  [ "$BM_PENDING_SNAPSHOT" = "20240101-000000" ]
  [ "$BM_PENDING_DEADLINE" = "$deadline" ]
}

@test "arm: CheckpointCreate failure falls back to the deadman timer" {
  require_root
  export BM_STUB_CKPT_CREATE_RC=1
  bm::ckpt::arm 90 20240101-000000 "fallback change"
  [ "$BM_CKPT_TIER" = "deadman" ]
  [ -n "$BM_CKPT_UNIT" ]
  [ -z "$BM_CKPT_PATH" ]
  grep -q "tier=deadman" "$BM_RUN_DIR/pending.state"
  grep -q "deadman_unit=$BM_CKPT_UNIT" "$BM_RUN_DIR/pending.state"
  assert_called '^systemd-run .*--on-active=90s'
}

@test "arm: checkpoint and deadman both unavailable => snapshot-only tier" {
  require_root
  export BM_STUB_CKPT_CREATE_RC=1
  export BM_STUB_SYSTEMD_RUN_RC=1
  bm::ckpt::arm 90 20240101-000000 "snapshot-only change"
  [ "$BM_CKPT_TIER" = "snapshot" ]
  [ -z "$BM_CKPT_UNIT" ]
  grep -q "tier=snapshot" "$BM_RUN_DIR/pending.state"
}

# ---- deadman timer ---------------------------------------------------------

@test "deadman_arm: schedules this program to roll the snapshot back" {
  run bm::ckpt::deadman_arm 120 20240101-000000
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^bond-manager-deadman-[0-9]+-[0-9]+$ ]]
  assert_called "^systemd-run --collect --unit $output --on-active=120s $BM_ARTIFACT rollback --snapshot 20240101-000000 --deadman --yes$"
}

@test "deadman_arm: refuses to arm when BM_SELF is not an executable path" {
  # A timer pointed at an unrunnable path is protection that never fires —
  # strictly worse than honestly falling back a tier.
  BM_SELF=""
  run bm::ckpt::deadman_arm 120 20240101-000000
  [ "$status" -ne 0 ]
  assert_not_called '^systemd-run '

  BM_SELF="$BM_TEST_SANDBOX/not-executable"
  printf '#!/bin/sh\n' >"$BM_SELF"       # present, but chmod-less
  run bm::ckpt::deadman_arm 120 20240101-000000
  [ "$status" -ne 0 ]
  assert_not_called '^systemd-run '
}

@test "arm: an unrunnable BM_SELF degrades the deadman tier to snapshot" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1     # no checkpoints => deadman tier
  BM_SELF="$BM_TEST_SANDBOX/not-executable"
  printf '#!/bin/sh\n' >"$BM_SELF"
  bm::ckpt::arm 90 20240101-000000 "unrunnable self"
  [ "$BM_CKPT_TIER" = "snapshot" ]
  assert_not_called '^systemd-run '
}

@test "deadman_cancel: stops both timer and service units" {
  bm::ckpt::deadman_cancel bond-manager-deadman-1-2
  assert_called '^systemctl stop bond-manager-deadman-1-2.timer$'
  assert_called '^systemctl stop bond-manager-deadman-1-2.service$'
  assert_called '^systemctl reset-failed bond-manager-deadman-1-2.service$'
}

# ---- commit ----------------------------------------------------------------

@test "commit: a lost checkpoint reports BM_EX_CKPT_LOST, not success" {
  require_root
  export BM_STUB_CKPT_DESTROY_RC=1     # the checkpoint is already gone
  bm::ckpt::arm 120 20240101-000000 "doomed change"
  run bm::ckpt::commit
  [ "$status" -eq "$BM_EX_CKPT_LOST" ]
  [ "$status" -eq 2 ]
  # the pending state is still cleared: there is nothing left to disarm
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "commit: successful CheckpointDestroy returns 0 and clears the state" {
  require_root
  bm::ckpt::arm 120 20240101-000000 "good change"
  run bm::ckpt::commit
  [ "$status" -eq 0 ]
  [ ! -f "$BM_RUN_DIR/pending.state" ]
  assert_called '^busctl call .*CheckpointDestroy o /org/freedesktop/NetworkManager/Checkpoint/1$'
}

@test "commit (deadman tier): cancels the timer and clears the state" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1
  bm::ckpt::arm 120 20240101-000000 "timer change"
  [ "$BM_CKPT_TIER" = "deadman" ]
  local unit="$BM_CKPT_UNIT"
  run bm::ckpt::commit
  [ "$status" -eq 0 ]
  [ ! -f "$BM_RUN_DIR/pending.state" ]
  assert_called "^systemctl stop $unit.timer$"
}

# ---- rebudget --------------------------------------------------------------

@test "rebudget (checkpoint): extends the rollback timeout and rewrites the state" {
  require_root
  bm::ckpt::arm 120 20240101-000000 "change"
  local old_deadline="$BM_CKPT_DEADLINE"
  run bm::ckpt::rebudget 600
  [ "$status" -eq 0 ]
  assert_called '^busctl call .*CheckpointAdjustRollbackTimeout ou /org/freedesktop/NetworkManager/Checkpoint/1 600$'
  bm::ckpt::load_pending
  (( BM_PENDING_DEADLINE > old_deadline ))
}

@test "rebudget (deadman): cancels the old timer and arms a fresh one" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1
  bm::ckpt::arm 120 20240101-000000 "change"
  local first="$BM_CKPT_UNIT"
  bm::ckpt::rebudget 600
  [ "$BM_CKPT_UNIT" != "$first" ]
  assert_call_order \
    "^systemd-run --collect --unit $first " \
    "^systemctl stop $first.timer$" \
    "^systemd-run --collect --unit $BM_CKPT_UNIT --on-active=600s"
  grep -q "deadman_unit=$BM_CKPT_UNIT" "$BM_RUN_DIR/pending.state"
}

@test "rebudget: snapshot tier has no timer to move" {
  require_root
  BM_CKPT_TIER=snapshot
  run bm::ckpt::rebudget 600
  [ "$status" -eq 0 ]
  assert_not_called 'CheckpointAdjustRollbackTimeout'
}

# ---- rollback --------------------------------------------------------------

@test "rollback_pending (checkpoint): asks NM to roll back and clears the state" {
  require_root
  bm::ckpt::arm 120 20240101-000000 "change"
  run bm::ckpt::rollback_pending
  [ "$status" -eq 0 ]
  assert_called '^busctl call .*CheckpointRollback o /org/freedesktop/NetworkManager/Checkpoint/1$'
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "rollback_pending: a dead checkpoint falls back to restoring the snapshot" {
  require_root
  printf '[connection]\nid=bond0\n' >"$BM_CONN_DIR/bond0.nmconnection"
  local snap
  snap="$(bm::snap::create pre-change 2>/dev/null)"
  bm::ckpt::arm 120 "$snap" "change"
  export BM_STUB_CKPT_ROLLBACK_RC=1    # checkpoint expired server-side
  printf 'stray\n' >"$BM_CONN_DIR/bond9.nmconnection"

  run bm::ckpt::rollback_pending
  [ "$status" -eq 0 ]
  [ ! -e "$BM_CONN_DIR/bond9.nmconnection" ]   # snapshot restore really ran
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "rollback_pending: nothing pending returns non-zero" {
  run bm::ckpt::rollback_pending
  [ "$status" -ne 0 ]
}
