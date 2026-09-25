#!/usr/bin/env bats
# bm::plan commit gate: how an unanswered or unanswerable "keep this change?"
# ends. The rollback itself is stubbed — these tests pin the gate's decisions.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
  ROLLED_BACK=0
  bm::ckpt::rollback_pending() { ROLLED_BACK=1; bm::ckpt::clear_pending; return 0; }
}

@test "deadline on the deadman tier: the gate restores the snapshot itself" {
  # The deadman timer cannot do it: this process holds the lock, and by the
  # time the timer fires the pending state is gone. v3.0 announced a
  # rollback here that never happened.
  seed_pending deadman 20240101-000000 "modify bond0"
  BM_CKPT_TIER=deadman
  local rc=0
  bm::plan::_gate_expired 20240101-000000 >"$BATS_TEST_TMPDIR/out" 2>&1 || rc=$?
  [ "$rc" -eq 5 ]
  [ "$ROLLED_BACK" -eq 1 ]
  [ "$BM_PLAN_OUTCOME" = "expired" ]
  grep -q "the change has been reverted" "$BATS_TEST_TMPDIR/out"
  [ ! -e "$BM_RUN_DIR/pending.state" ]
}

@test "deadline on the deadman tier: a failed restore is reported, not hidden" {
  seed_pending deadman 20240101-000000
  BM_CKPT_TIER=deadman
  bm::ckpt::rollback_pending() { return 1; }
  local rc=0
  bm::plan::_gate_expired 20240101-000000 >"$BATS_TEST_TMPDIR/out" 2>&1 || rc=$?
  [ "$rc" -eq 5 ]
  grep -q "reported problems; inspect manually" "$BATS_TEST_TMPDIR/out"
  refute grep -q "the change has been reverted" "$BATS_TEST_TMPDIR/out"
}

@test "deadline on the checkpoint tier: NetworkManager rolls back, the gate only clears state" {
  seed_pending checkpoint
  BM_CKPT_TIER=checkpoint
  local rc=0
  bm::plan::_gate_expired x >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 5 ]
  [ "$ROLLED_BACK" -eq 0 ]
  [ ! -e "$BM_RUN_DIR/pending.state" ]
}

@test "no terminal: protection stays armed, exit 6, outcome pending" {
  BM_CKPT_TIER=checkpoint
  local rc=0
  bm::plan::_gate_no_tty >"$BATS_TEST_TMPDIR/out" 2>&1 || rc=$?
  [ "$rc" -eq 6 ]
  [ "$BM_PLAN_OUTCOME" = "pending" ]
  grep -q "confirm with:   bond-manager commit" "$BATS_TEST_TMPDIR/out"
}

@test "keep after the checkpoint expired is reported as lost, not committed" {
  bm::ckpt::commit() { return "$BM_EX_CKPT_LOST"; }
  local rc=0
  bm::plan::_gate_keep >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 5 ]
  [ "$BM_PLAN_OUTCOME" = "lost" ]
}

@test "keep and undo set their outcomes" {
  bm::ckpt::commit() { return 0; }
  bm::plan::_gate_keep >/dev/null 2>&1
  [ "$BM_PLAN_OUTCOME" = "committed" ]
  local rc=0
  bm::plan::_gate_undo snap1 >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 5 ]
  [ "$ROLLED_BACK" -eq 1 ]
  [ "$BM_PLAN_OUTCOME" = "rolled-back" ]
}

@test "E on the checkpoint tier saves the new deadline for other sessions and the menus" {
  seed_pending checkpoint 20240101-000000 "modify bond0"
  BM_CKPT_TIER=checkpoint BM_CKPT_PATH=/org/freedesktop/NetworkManager/Checkpoint/1
  BM_CKPT_SNAPSHOT=20240101-000000 BM_CKPT_SUMMARY="modify bond0"
  bm::ckpt::dbus_extend() { return 0; }
  local before
  before="$(bm::core::epoch)"
  bm::plan::_gate_extend 60
  bm::ckpt::load_pending
  (( BM_PENDING_DEADLINE >= before + 360 ))
  [ "$BM_PENDING_SNAPSHOT" = "20240101-000000" ]
  [ "$BM_PENDING_SUMMARY" = "modify bond0" ]
}
