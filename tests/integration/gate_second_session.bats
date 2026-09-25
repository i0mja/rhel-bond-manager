#!/usr/bin/env bats
# The commit gate while it waits, seen from a second session. A change to the
# address you are logged in on freezes the first session rather than ending
# it, so its gate keeps waiting; the way out is a new session, which must be
# able to keep or undo the change. The gate therefore waits without holding
# the lock (pending.state still refuses any new change), and notices when
# the change is settled elsewhere.

load ../helpers

setup() {
  python3 -c 'import pty' 2>/dev/null || skip "needs python3 with the pty module"
  setup_sandbox
  scenario_bond0_healthy
  stub_nm_bond0_profile
  set_conf LINK_SETTLE_TIMEOUT 0
  PTY="$TESTS_DIR/tools/pty-drive"
}

# Start `modify` in a pseudo-terminal and leave it waiting at the gate.
start_at_gate() { # start_at_gate plain|fancy <seconds-the-terminal-stays-idle>
  local -a mode=()
  if [[ "$1" == plain ]]; then mode=(--plain); fi
  timeout 90 "$PTY" @expect:"Apply this plan?" 'y\r' "@wait:$2" -- \
    env TERM=xterm LANG=C LC_ALL=C "$BM_ARTIFACT" "${mode[@]}" modify bond0 --opt miimon=50 \
    >"$BATS_TEST_TMPDIR/gate.out" 2>&1 &
  GATE_PID=$!
  # waiting at the gate = a change is pending and nobody holds the lock
  local i
  for i in $(seq 300); do
    if [[ -f "$BM_RUN_DIR/pending.state" ]] && flock -n "$BM_RUN_DIR/lock" true 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "the gate never started waiting" >&2
  return 1
}

gate_screen() {
  wait "$GATE_PID" || true
  screen="$(sed -E $'s/\x1b\\[[0-9;?]*[A-Za-z]//g' "$BATS_TEST_TMPDIR/gate.out" | tr -d '\r')"
}

@test "second session: commit keeps the change while the first session waits at the gate" {
  require_root
  start_at_gate plain 3
  run "$BM_ARTIFACT" commit
  [ "$status" -eq 0 ]
  assert_contains "$output" "pending change committed"
  gate_screen
  assert_contains "$screen" "The change was kept from another session."
  assert_contains "$screen" "PTY-EXIT 0"
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "second session: rollback undoes it, and the waiting gate says so (exit 5)" {
  require_root
  start_at_gate fancy 3
  run "$BM_ARTIFACT" rollback
  [ "$status" -eq 0 ]
  gate_screen
  assert_contains "$screen" "The change was undone from another session."
  assert_contains "$screen" "PTY-EXIT 5"
}

@test "second session: a new change is still refused while one waits (exit 3, not 4)" {
  require_root
  start_at_gate plain 3
  run "$BM_ARTIFACT" -y modify bond0 --opt miimon=70
  [ "$status" -eq 3 ]
  assert_contains "$output" "a previous change is still pending"
  run "$BM_ARTIFACT" commit        # let the gate finish
  gate_screen
}

@test "deadman timer firing while the gate waits: the timer undoes it, the gate reports it" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1   # deadman tier
  start_at_gate fancy 3
  local unit snap
  unit="$(sed -n 's/^deadman_unit=//p' "$BM_RUN_DIR/pending.state")"
  snap="$(sed -n 's/^snapshot=//p' "$BM_RUN_DIR/pending.state")"
  run env BM_STUB_SYSTEMCTL_SELF="$unit" "$BM_ARTIFACT" rollback --snapshot "$snap" --deadman --yes
  [ "$status" -eq 0 ]
  gate_screen
  assert_contains "$screen" "The safety net undid the change: its time ran out."
  assert_contains "$screen" "PTY-EXIT 5"
}
