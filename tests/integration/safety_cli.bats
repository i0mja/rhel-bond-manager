#!/usr/bin/env bats
# End-to-end: the commands an operator reaches for after a change — commit,
# rollback, snapshot restore/prune — plus the dry-run contract for all of
# them (a dry run must write nothing at all) and the locking they take.

load ../helpers

setup() {
  setup_sandbox
  scenario_bond0_healthy
  stub_nm_bond0_profile
  set_conf LINK_SETTLE_TIMEOUT 0
  printf '[connection]\nid=bond0\ntype=bond\n' >"$BM_CONN_DIR/bond0.nmconnection"
}

make_snapshot() { # -> echoes the new snapshot id
  local out
  out="$("$BM_ARTIFACT" snapshot create 2>/dev/null)"
  printf '%s' "${out##*: }"
}

# Forget the traces a real command left, so the dry-run assertions below
# measure only what the dry run itself did.
clear_side_effects() {
  : >"$BM_TEST_CALLS"
  rm -f "$BM_LOG_FILE" "$BM_RUN_DIR/lock" "$BM_RUN_DIR/lockinfo"
}

# Apply a real change and stop at the confirmation gate, the way a scripted
# (non-TTY) run without --yes does: protection stays armed, state persists.
apply_leaving_pending() {
  run bash -c "printf 'y\n' | '$BM_ARTIFACT' modify bond0 --opt miimon=250"
  [ "$status" -eq 6 ]
  [ -f "$BM_RUN_DIR/pending.state" ]
}

# ---- commit ----------------------------------------------------------------

@test "commit: a real pending change is committed, exit 0, state cleared" {
  apply_leaving_pending
  assert_contains "$output" "confirm with:   bond-manager commit"

  run_cli commit
  [ "$status" -eq 0 ]
  assert_contains "$output" "pending change committed"
  assert_called '^busctl call .*CheckpointDestroy o /org/freedesktop/NetworkManager/Checkpoint/1$'
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "commit: a checkpoint that is already gone exits 5 and says so" {
  seed_pending checkpoint 20240101-000000 "modify bond0"
  export BM_STUB_CKPT_DESTROY_RC=1
  run_cli commit
  [ "$status" -eq 5 ]
  assert_contains "$output" "the checkpoint was already gone"
  assert_contains "$output" "most likely rolled this change back already"
  assert_contains "$output" "bond-manager status"
  # nothing is left pending: there is no protection left to disarm
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "commit: nothing pending is a precondition error, exit 3" {
  run_cli commit
  [ "$status" -eq 3 ]
  assert_contains "$output" "no pending change to commit"
}

@test "commit (deadman tier): cancels the timer units" {
  seed_pending deadman 20240101-000000 "modify bond0"
  run_cli commit
  [ "$status" -eq 0 ]
  assert_called '^systemctl stop bond-manager-deadman-4242-1700000000.timer$'
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "commit: takes the lock and refuses to run concurrently, exit 4" {
  seed_pending checkpoint 20240101-000000 "modify bond0"
  exec 9>"$BM_RUN_DIR/lock"
  flock -n 9
  run_cli commit
  exec 9>&-
  [ "$status" -eq 4 ]
  assert_contains "$output" "another bond-manager instance is running"
  [ -f "$BM_RUN_DIR/pending.state" ]      # untouched
}

# ---- rollback --------------------------------------------------------------

@test "rollback: a pending change is reverted and the state cleared, exit 0" {
  apply_leaving_pending
  run_cli rollback
  [ "$status" -eq 0 ]
  assert_contains "$output" "pending change rolled back"
  assert_called '^busctl call .*CheckpointRollback o /org/freedesktop/NetworkManager/Checkpoint/1$'
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "rollback --snapshot ID: disarms the pending protection before restoring" {
  local snap
  snap="$(make_snapshot)"
  [ -n "$snap" ]
  seed_pending checkpoint "$snap" "modify bond0"
  printf 'stray\n' >"$BM_CONN_DIR/bond9.nmconnection"

  run_cli -y rollback --snapshot "$snap"
  [ "$status" -eq 0 ]

  # disarm FIRST, restore second — a timer left armed would fire later, on
  # top of profiles it knows nothing about
  assert_call_order \
    '^busctl call .*CheckpointDestroy ' \
    '^nmcli connection reload$'
  grep -q 'disarming pending change protection' "$BM_LOG_FILE"
  [ ! -f "$BM_RUN_DIR/pending.state" ]
  [ ! -e "$BM_CONN_DIR/bond9.nmconnection" ]      # the restore really ran
}

@test "rollback --snapshot ID with nothing pending just restores" {
  local snap
  snap="$(make_snapshot)"
  printf 'stray\n' >"$BM_CONN_DIR/bond9.nmconnection"
  run_cli -y rollback --snapshot "$snap"
  [ "$status" -eq 0 ]
  [ ! -e "$BM_CONN_DIR/bond9.nmconnection" ]
  assert_not_called 'CheckpointDestroy'
}

@test "rollback --deadman with no pending state is a silent no-op, exit 0" {
  local snap
  snap="$(make_snapshot)"
  local before
  before="$(tree_state "$BM_CONN_DIR" "$BM_BACKUP_DIR")"
  printf 'stray\n' >"$BM_CONN_DIR/bond9.nmconnection"

  run_cli -y rollback --deadman
  [ "$status" -eq 0 ]
  # the operator already committed or rolled back; the timer must do nothing
  assert_not_called '^nmcli connection reload$'
  assert_not_called 'CheckpointRollback'
  assert_not_contains "$output" "Restoring snapshot"
  [ -e "$BM_CONN_DIR/bond9.nmconnection" ]
  rm -f "$BM_CONN_DIR/bond9.nmconnection"
  [ "$(tree_state "$BM_CONN_DIR" "$BM_BACKUP_DIR")" = "$before" ]
  grep -q 'no pending change remains' "$BM_LOG_FILE"
}

@test "rollback --deadman with a pending change does roll it back" {
  apply_leaving_pending
  run_cli -y rollback --deadman
  [ "$status" -eq 0 ]
  assert_called '^busctl call .*CheckpointRollback'
  grep -q 'DEADMAN rollback fired' "$BM_LOG_FILE"
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "rollback: no pending change and no snapshots is a precondition error" {
  run_cli -y rollback
  [ "$status" -eq 3 ]
  assert_contains "$output" "no pending change and no snapshots found"
}

@test "rollback --snapshot: an unknown id is a precondition error, exit 3" {
  make_snapshot >/dev/null
  run_cli -y rollback --snapshot 19700101-000000
  [ "$status" -eq 3 ]
  assert_contains "$output" "snapshot '19700101-000000' not found"
}

# ---- snapshot subcommands --------------------------------------------------

@test "snapshot restore: no snapshots at all gives a clean error, exit 3" {
  run_cli -y snapshot restore
  [ "$status" -eq 3 ]
  assert_contains "$output" "no snapshots found in $BM_BACKUP_DIR"
  # a clean precondition error, not a stack trace or an empty-id restore
  assert_not_contains "$output" "not found\nERROR"
  assert_no_nmcli_mutations
}

@test "snapshot restore: the newest snapshot is restored by default" {
  make_snapshot >/dev/null
  printf 'stray\n' >"$BM_CONN_DIR/bond9.nmconnection"
  run_cli -y snapshot restore
  [ "$status" -eq 0 ]
  [ ! -e "$BM_CONN_DIR/bond9.nmconnection" ]
}

@test "snapshot create/list/prune round-trip" {
  local a b
  a="$(make_snapshot)"
  b="$(make_snapshot)"
  run_cli snapshot list
  [ "$status" -eq 0 ]
  assert_contains "$output" "$a"
  assert_contains "$output" "$b"
  assert_contains "$output" "manual"

  printf 'MAX_BACKUPS="1"\n' >>"$BM_CONF"
  touch -d '2020-01-01 00:00:01' "$BM_BACKUP_DIR/conn-$a.tar.gz"
  run_cli snapshot prune
  [ "$status" -eq 0 ]
  [ ! -e "$BM_BACKUP_DIR/conn-$a.tar.gz" ]
  [ -e "$BM_BACKUP_DIR/conn-$b.tar.gz" ]
}

@test "snapshot prune: keeps the snapshot a pending change depends on" {
  local a b
  a="$(make_snapshot)"
  b="$(make_snapshot)"
  touch -d '2020-01-01 00:00:01' "$BM_BACKUP_DIR/conn-$a.tar.gz"
  printf 'MAX_BACKUPS="1"\n' >>"$BM_CONF"
  seed_pending checkpoint "$a" "modify bond0"
  run_cli snapshot prune
  [ "$status" -eq 0 ]
  [ -e "$BM_BACKUP_DIR/conn-$a.tar.gz" ]
  [ -e "$BM_BACKUP_DIR/conn-$b.tar.gz" ]
}

@test "snapshot create: takes the lock, exit 4 when held" {
  exec 9>"$BM_RUN_DIR/lock"
  flock -n 9
  run_cli snapshot create
  exec 9>&-
  [ "$status" -eq 4 ]
  [ -z "$(ls "$BM_BACKUP_DIR"/conn-*.tar.gz 2>/dev/null || true)" ]
}

# ---- dry-run safety --------------------------------------------------------

# Nothing under the writable roots may change, no external command may mutate,
# and no log file may appear.
assert_dry_run_wrote_nothing() { # assert_dry_run_wrote_nothing <before-state>
  [ "$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR" "$BM_RUN_DIR")" = "$1" ]
  assert_no_nmcli_mutations
  assert_not_called '^busctl '
  assert_not_called '^systemd-run '
  [ ! -e "$BM_LOG_FILE" ]
  [ ! -e "$BM_RUN_DIR/lock" ]
  [ ! -e "$BM_RUN_DIR/lockinfo" ]
}

@test "dry-run commit: reports the pending change and writes nothing" {
  seed_pending checkpoint 20240101-000000 "modify bond0"
  local before
  before="$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR" "$BM_RUN_DIR")"
  run_cli --dry-run commit
  [ "$status" -eq 0 ]
  assert_contains "$output" "[dry-run] would commit the pending change: modify bond0 (tier checkpoint)"
  assert_dry_run_wrote_nothing "$before"
}

@test "dry-run commit with nothing pending: exit 0, writes nothing" {
  local before
  before="$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR" "$BM_RUN_DIR")"
  run_cli --dry-run commit
  [ "$status" -eq 0 ]
  assert_contains "$output" "[dry-run] no pending change to commit"
  assert_dry_run_wrote_nothing "$before"
}

@test "dry-run rollback: reports what would be reverted and writes nothing" {
  seed_pending checkpoint 20240101-000000 "modify bond0"
  local before
  before="$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR" "$BM_RUN_DIR")"
  run_cli --dry-run rollback
  [ "$status" -eq 0 ]
  assert_contains "$output" "[dry-run] would roll back the pending change: modify bond0"
  assert_dry_run_wrote_nothing "$before"
}

@test "dry-run rollback --snapshot: shows the diff, takes no pre-restore snapshot" {
  local snap
  snap="$(make_snapshot)"
  printf 'stray\n' >"$BM_CONN_DIR/bond9.nmconnection"
  clear_side_effects
  local before
  before="$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR" "$BM_RUN_DIR")"

  run_cli --dry-run rollback --snapshot "$snap"
  [ "$status" -eq 0 ]
  assert_contains "$output" "[dry-run] would restore snapshot $snap"
  assert_contains "$output" "+ bond9.nmconnection"
  [ -e "$BM_CONN_DIR/bond9.nmconnection" ]
  assert_dry_run_wrote_nothing "$before"
}

@test "dry-run snapshot create: writes no archive" {
  local before
  before="$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR" "$BM_RUN_DIR")"
  run_cli --dry-run snapshot create
  [ "$status" -eq 0 ]
  assert_contains "$output" "[dry-run] would create a snapshot"
  assert_dry_run_wrote_nothing "$before"
}

@test "dry-run snapshot prune: deletes nothing" {
  local a b
  a="$(make_snapshot)"
  b="$(make_snapshot)"
  printf 'MAX_BACKUPS="1"\n' >>"$BM_CONF"
  touch -d '2020-01-01 00:00:01' "$BM_BACKUP_DIR/conn-$a.tar.gz"
  clear_side_effects
  local before
  before="$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR" "$BM_RUN_DIR")"

  run_cli --dry-run snapshot prune
  [ "$status" -eq 0 ]
  assert_contains "$output" "[dry-run] would prune snapshots beyond the newest 1"
  [ -e "$BM_BACKUP_DIR/conn-$a.tar.gz" ]
  [ -e "$BM_BACKUP_DIR/conn-$b.tar.gz" ]
  assert_dry_run_wrote_nothing "$before"
}

@test "dry-run snapshot restore: no pre-restore snapshot, no reload" {
  local snap
  snap="$(make_snapshot)"
  clear_side_effects
  local before
  before="$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR" "$BM_RUN_DIR")"
  run_cli --dry-run snapshot restore "$snap"
  [ "$status" -eq 0 ]
  assert_dry_run_wrote_nothing "$before"
}

# ---- status ----------------------------------------------------------------

@test "status BOND --json: the document is scoped to the named bond" {
  scenario_bond1_8023ad_no_partner
  run_cli_stdout --json status bond1
  [ "$status" -eq 10 ]                       # bond1 is degraded
  assert_valid_json "$output"
  [ "$(printf '%s' "$output" | jq -r '.bonds | length')" = "1" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds[0].name')" = "bond1" ]

  run_cli_stdout --json status bond0
  [ "$status" -eq 0 ]                        # bond0 is healthy
  [ "$(printf '%s' "$output" | jq -r '.bonds | length')" = "1" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds[0].name')" = "bond0" ]
}
