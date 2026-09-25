#!/usr/bin/env bats
# End-to-end mutating runs through the transaction engine: step ordering,
# step failure, verification failure, and the rollback that must follow.
#
# The nmcli stub's hook stands in for NetworkManager + the kernel: it rewrites
# /proc/net/bonding in response to the commands the plan issues, so the
# verification gate sees a world that actually reacted to the change.

load ../helpers

setup() {
  setup_sandbox
  scenario_bond0_healthy                       # bond0: eth0, eth1, all up
  mk_sys_nic eth2 up 1000 52:54:00:12:34:03
  mk_sys_nic eth3 up 1000 52:54:00:12:34:04
  stub_nm_bond0_profile                        # bond0 + bond-port-eth0/eth1
  set_conf LINK_SETTLE_TIMEOUT 0               # fixtures settle instantly
  BOND0_UUID=11111111-1111-1111-1111-111111111111
  PORT_ETH1_UUID=33333333-3333-3333-3333-333333333333
}

# The kernel enslaving eth2 when its port profile is activated, and releasing
# eth1 when its profile is deleted.
hook_swap_eth1_to_eth2() {
  install_nmcli_hook <<'HOOK'
case "$*" in
  *"connection up bond-port-eth2"*)
    "$BM_TEST_MKPROC" "$BM_PROC_ROOT/net/bonding/bond0" eth0 eth0 eth1 eth2 ;;
  *"connection delete 33333333-3333-3333-3333-333333333333"*)
    "$BM_TEST_MKPROC" "$BM_PROC_ROOT/net/bonding/bond0" eth0 eth0 eth2 ;;
esac
HOOK
}

# ---- swap-member ordering: the defining safety invariant --------------------

@test "swap-member: the replacement is added and up BEFORE the old port is deleted" {
  require_root
  hook_swap_eth1_to_eth2
  run_cli -y swap-member bond0 --old eth1 --new eth2
  [ "$status" -eq 0 ]

  # redundancy never dips: add -> activate -> (wait for enslavement) -> delete
  assert_call_order \
    "^nmcli connection add type ethernet con-name bond-port-eth2 ifname eth2 master $BOND0_UUID slave-type bond$" \
    '^nmcli -w [0-9]+ connection up bond-port-eth2$' \
    "^nmcli connection delete $PORT_ETH1_UUID$"

  assert_contains "$output" "Wait for 'eth2' to enslave"
  assert_contains "$output" "change applied and committed"
}

@test "swap-member: the old port is NOT deleted when the replacement never enslaves" {
  require_root
  # no hook: eth2 is never enslaved, so the await step times out and fails
  run_cli -y swap-member bond0 --old eth1 --new eth2
  [ "$status" -eq 5 ]
  assert_called '^nmcli connection add type ethernet con-name bond-port-eth2 '
  assert_not_called "^nmcli connection delete $PORT_ETH1_UUID$"
  assert_contains "$output" "step 3 failed"
  assert_contains "$output" "rolling back"
}

@test "swap-member: verification proves the new member is in and the old one out" {
  require_root
  hook_swap_eth1_to_eth2
  run_cli -y swap-member bond0 --old eth1 --new eth2
  [ "$status" -eq 0 ]
  assert_contains "$output" "member eth2 enslaved, MII up"
  assert_contains "$output" "member eth1 is no longer enslaved to bond0"
}

@test "swap-member: a still-enslaved old member fails verification and rolls back" {
  require_root
  # the delete goes through but the kernel keeps eth1 enslaved (stale profile
  # elsewhere, driver refusing release): the change must not be committed
  install_nmcli_hook <<'HOOK'
case "$*" in
  *"connection up bond-port-eth2"*)
    "$BM_TEST_MKPROC" "$BM_PROC_ROOT/net/bonding/bond0" eth0 eth0 eth1 eth2 ;;
esac
HOOK
  run_cli -y swap-member bond0 --old eth1 --new eth2
  [ "$status" -eq 5 ]
  assert_contains "$output" "member eth1 is still enslaved to bond0"
  assert_contains "$output" "verification FAILED"
  assert_called '^busctl call .*CheckpointRollback'
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

# ---- step failure ----------------------------------------------------------

@test "step failure: the run exits 5, rolls back and leaves nothing pending" {
  require_root
  export BM_STUB_NMCLI_FAIL_RE='connection up'
  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 5 ]
  assert_contains "$output" "step 2 failed"
  assert_contains "$output" "rolling back"
  assert_contains "$output" "rolled back to snapshot"
  # the change was protected by a checkpoint, so NM undoes it server-side
  assert_called '^busctl call .*CheckpointRollback o /org/freedesktop/NetworkManager/Checkpoint/1$'
  [ ! -f "$BM_RUN_DIR/pending.state" ]
  # a snapshot was taken before the first mutating step
  [ -n "$(ls -A "$BM_BACKUP_DIR")" ]
}

@test "step failure: verification never runs after a failed step" {
  require_root
  export BM_STUB_NMCLI_FAIL_RE='connection modify'
  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 5 ]
  assert_contains "$output" "step 1 failed"
  assert_not_contains "$output" "Verification:"
  assert_not_called '^nmcli -w [0-9]+ connection up'
}

@test "step failure without checkpoints: the snapshot is restored instead" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1          # no NM D-Bus => deadman tier
  export BM_STUB_NMCLI_FAIL_RE='connection up'
  printf '[connection]\nid=bond0\n' >"$BM_CONN_DIR/bond0.nmconnection"
  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 5 ]
  assert_contains "$output" "rolling back"
  # the deadman timer is cancelled and the snapshot put back
  assert_called '^systemctl stop bond-manager-deadman-'
  assert_called '^nmcli connection reload$'
  # restoring is itself undoable: the pre-restore snapshot is on disk
  grep -lq 'reason=pre-restore-of-' "$BM_BACKUP_DIR"/conn-*.manifest
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

# ---- verification failure --------------------------------------------------

@test "verification failure: a bond that never comes up is rolled back, exit 5" {
  require_root
  scenario_bond0_down                 # members fine, bond operstate down
  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 5 ]
  # the plan really ran — this is a revert, not a refusal
  assert_called '^nmcli connection modify .* bond.options mode=active-backup,miimon=250$'
  assert_contains "$output" "bond 'bond0' operstate is 'down'"
  assert_contains "$output" "verification FAILED"
  assert_contains "$output" "rolled back to snapshot"
  assert_called '^busctl call .*CheckpointRollback'
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "verification failure: a bond that never appears in the kernel rolls back" {
  require_root
  run_cli -y create bond9 --mode active-backup --members eth2,eth3
  [ "$status" -eq 5 ]
  assert_contains "$output" "bond 'bond9' not present in kernel"
  assert_contains "$output" "verification FAILED"
  assert_called '^busctl call .*CheckpointRollback'
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "verification failure: the checkpoint is never destroyed (nothing committed)" {
  require_root
  scenario_bond0_down
  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 5 ]
  assert_not_called 'CheckpointDestroy'
}

# ---- successful apply ------------------------------------------------------

@test "successful apply: snapshot, arm, execute, verify, commit — exit 0" {
  require_root
  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 0 ]
  assert_call_order \
    '^busctl call .*CheckpointCreate aouu 0 120 6$' \
    '^nmcli connection modify .* bond.options mode=active-backup,miimon=250$' \
    '^busctl call .*CheckpointAdjustRollbackTimeout ou .* 120$' \
    '^busctl call .*CheckpointDestroy '
  assert_contains "$output" "Protection tier: checkpoint"
  assert_contains "$output" "change applied and committed"
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "successful apply: the rollback window is re-budgeted after verification" {
  require_root
  # applying consumes the window; without a re-budget the operator could be
  # left with seconds (or nothing) to decide
  run_cli -y --rollback-window 300 modify bond0 --opt miimon=250
  [ "$status" -eq 0 ]
  assert_called '^busctl call .*CheckpointAdjustRollbackTimeout ou /org/freedesktop/NetworkManager/Checkpoint/1 300$'
}

@test "no-op plan: nothing is snapshotted, armed or executed" {
  require_root
  run_cli -y modify bond0 --opt miimon=100
  [ "$status" -eq 0 ]
  assert_contains "$output" "Nothing to do"
  assert_no_nmcli_mutations
  assert_not_called '^busctl '
  [ -z "$(ls -A "$BM_BACKUP_DIR")" ]
}

# ---- the confirmation gate on a non-TTY ------------------------------------

@test "no TTY and no --yes: protection stays armed and the run exits 6" {
  require_root
  run bash -c "printf 'y\n' | '$BM_ARTIFACT' modify bond0 --opt miimon=250"
  [ "$status" -eq 6 ]
  assert_contains "$output" "No TTY to confirm on. Protection stays armed:"
  assert_contains "$output" "confirm with:   bond-manager commit"
  assert_contains "$output" "or revert with: bond-manager rollback"
  assert_contains "$output" "Auto-rollback at the deadline if you do neither."
  [ -f "$BM_RUN_DIR/pending.state" ]
  grep -q '^tier=checkpoint$' "$BM_RUN_DIR/pending.state"
}

@test "no TTY, snapshot-only tier: no auto-rollback is promised" {
  require_root
  # nothing is armed that could revert this on its own — saying otherwise
  # would leave an operator waiting for a rollback that never comes
  export BM_STUB_BUSCTL_PING_RC=1
  export BM_STUB_SYSTEMD_RUN_RC=1
  run bash -c "printf 'y\n' | '$BM_ARTIFACT' modify bond0 --opt miimon=250"
  [ "$status" -eq 6 ]
  # (the banner announces the probed tier; arming then fell back to snapshot)
  assert_contains "$output" "Snapshot-only protection: nothing will roll this back automatically."
  assert_not_contains "$output" "Auto-rollback at the deadline"
  grep -q '^tier=snapshot$' "$BM_RUN_DIR/pending.state"
}

# ---- expect-state driven workflows -----------------------------------------

@test "--no-activate: a bond left down verifies with expect-state any, exit 0" {
  require_root
  run_cli -y create bond9 --mode active-backup --members eth2,eth3 --no-activate
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond 'bond9' is not present in the kernel"
  assert_contains "$output" "change applied and committed"
  assert_not_called '^nmcli -w [0-9]+ connection up bond9$'
  assert_not_called 'CheckpointRollback'
}

@test "remove-member: removing the last member is a success, not a rollback" {
  require_root
  # bond0 with a single member; releasing it takes the bond down, which is
  # the correct outcome and must not fail its own verification gate
  write_proc_bond bond0 eth0 eth0
  install_nmcli_hook <<'HOOK'
case "$*" in
  *"connection delete 22222222-2222-2222-2222-222222222222"*)
    "$BM_TEST_MKPROC" "$BM_PROC_ROOT/net/bonding/bond0" none
    printf 'down\n' >"$BM_SYS_ROOT/class/net/bond0/operstate" ;;
esac
HOOK
  run_cli -y remove-member bond0 eth0
  [ "$status" -eq 0 ]
  assert_contains "$output" "member eth0 is no longer enslaved to bond0"
  assert_contains "$output" "not expected to be up after this change"
  assert_contains "$output" "change applied and committed"
  assert_not_called 'CheckpointRollback'
}

@test "remove-member: a member that stays enslaved fails verification" {
  require_root
  write_proc_bond bond0 eth0 eth0
  run_cli -y remove-member bond0 eth0          # no hook: the kernel keeps it
  [ "$status" -eq 5 ]
  assert_contains "$output" "member eth0 is still enslaved to bond0"
  assert_called '^busctl call .*CheckpointRollback'
}

# ---- workflow input handling ----------------------------------------------

@test "modify: a profile with no explicit mode is treated as balance-rr" {
  # the kernel/NetworkManager default. Assuming active-backup would validate
  # the new option set against the wrong matrix.
  stub_nm_conn 66666666-6666-6666-6666-666666666666 \
    connection.id=bond0 connection.type=bond connection.interface-name=bond0 \
    "bond.options=miimon=100"
  rm -f "$BM_STUB_NM_DIR/11111111-1111-1111-1111-111111111111.conn"
  run_cli --dry-run modify bond0 --primary eth0
  [ "$status" -eq 2 ]
  assert_contains "$output" "treating it as the default (balance-rr)"
  assert_contains "$output" "option 'primary' is not valid for mode balance-rr"
}

@test "modify: --opt values containing commas survive the merge" {
  # arp_ip_target=a,b is one option with a comma-separated value; splitting
  # on commas would invent an option named after the second address
  run_cli --dry-run modify bond0 \
    --opt 'arp_interval=200,arp_ip_target=10.0.0.1,10.0.0.2' --del-opt miimon
  [ "$status" -eq 0 ]
  assert_contains "$output" "Set bond.options to 'mode=active-backup,arp_interval=200,arp_ip_target=10.0.0.1,10.0.0.2'"
}

@test "modify: --ip6 dhcp maps to DHCPv6, not SLAAC" {
  run_cli --dry-run modify bond0 --ip6 dhcp
  [ "$status" -eq 0 ]
  assert_contains "$output" "Configure IPv6 (DHCPv6) on bond0"
  assert_contains "$output" "ipv6.method dhcp"
  assert_not_contains "$output" "ipv6.method auto"
}

@test "modify: --ip6 none disables IPv6 the way old NetworkManager understands" {
  run_cli --dry-run modify bond0 --ip6 none
  [ "$status" -eq 0 ]
  assert_contains "$output" "ipv6.method ignore"
}

# ---- pending-change interlock ---------------------------------------------

@test "a pending change blocks a new one until it is committed or rolled back" {
  require_root
  seed_pending checkpoint 20240101-000000 "modify bond0"
  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 3 ]
  assert_contains "$output" "a previous change is still pending (modify bond0)"
  assert_no_nmcli_mutations
}

# --- switch migration: mode changes carry stale options ----------------------

@test "modify --mode drops options that only belonged to the old mode" {
  scenario_bond0_healthy
  stub_nm_conn 11111111-1111-1111-1111-111111111111 \
    connection.id=bond0 connection.type=bond connection.interface-name=bond0 \
    "bond.options=mode=802.3ad,lacp_rate=fast,miimon=100,xmit_hash_policy=layer3+4"
  # Going 802.3ad -> active-backup is what a cross-switch migration needs;
  # the carried-over LACP options must not block it.
  run_cli -n modify bond0 --mode active-backup
  [ "$status" -eq 0 ]
  # inspect the resulting option string itself: the drop notice above it
  # legitimately names the options being removed
  local opts
  opts="$(printf '%s\n' "$output" | sed -n "s/.*Set bond.options to '\\(.*\\)'.*/\\1/p")"
  [ -n "$opts" ]
  assert_contains "$opts" "mode=active-backup"
  assert_contains "$opts" "miimon=100"
  [[ "$opts" != *"lacp_rate"* ]]
  [[ "$opts" != *"xmit_hash_policy"* ]]
}

@test "modify --mode reports which stale options it dropped" {
  scenario_bond0_healthy
  stub_nm_conn 11111111-1111-1111-1111-111111111111 \
    connection.id=bond0 connection.type=bond connection.interface-name=bond0 \
    "bond.options=mode=802.3ad,lacp_rate=fast,miimon=100,xmit_hash_policy=layer3+4"
  run_cli -n modify bond0 --mode active-backup
  assert_contains "$output" "dropping option(s) not valid in mode active-backup"
}

@test "modify --mode still rejects an option the caller explicitly contradicts" {
  scenario_bond0_healthy
  stub_nm_conn 11111111-1111-1111-1111-111111111111 \
    connection.id=bond0 connection.type=bond connection.interface-name=bond0 \
    "bond.options=mode=802.3ad,lacp_rate=fast,miimon=100,xmit_hash_policy=layer3+4"
  # asking for active-backup AND lacp_rate in the same breath is a mistake,
  # not an inheritance: it must fail rather than be silently dropped
  run_cli -n modify bond0 --mode active-backup --lacp-rate fast
  [ "$status" -eq 2 ]
  assert_contains "$output" "not valid for mode active-backup"
}

@test "modify without --mode leaves an unrelated option set untouched" {
  scenario_bond0_healthy
  stub_nm_conn 11111111-1111-1111-1111-111111111111 \
    connection.id=bond0 connection.type=bond connection.interface-name=bond0 \
    "bond.options=mode=802.3ad,lacp_rate=fast,miimon=100,xmit_hash_policy=layer3+4"
  run_cli -n modify bond0 --opt miimon=50
  [ "$status" -eq 0 ]
  # no mode change -> nothing is dropped
  assert_contains "$output" "lacp_rate=fast"
  assert_contains "$output" "xmit_hash_policy=layer3+4"
  assert_contains "$output" "miimon=50"
}
