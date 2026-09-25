#!/usr/bin/env bats
# The SSH egress guard: refuse to touch the device carrying the operator's own
# session unless NetworkManager can undo it server-side. The guard is only as
# good as the affected-device list, so the VLAN and member cases are pinned
# here too — an operator whose session rides bond0.120 loses it just as hard
# when bond0 is reconfigured.

load ../helpers

setup() {
  setup_sandbox
  scenario_bond0_healthy
  mk_sys_nic eth2 up 1000 52:54:00:12:34:03
  stub_nm_bond0_profile
  set_conf LINK_SETTLE_TIMEOUT 0
}

stub_vlan_120() {
  stub_nm_conn 44444444-4444-4444-4444-444444444444 \
    connection.id=bond0.120 connection.type=vlan \
    connection.interface-name=bond0.120 vlan.parent=bond0 vlan.id=120
}

# ---- refusal ---------------------------------------------------------------

@test "guard: refuses a change to the SSH egress bond when checkpoints are unavailable" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1            # deadman tier
  stub_ssh_session 10.1.2.3 bond0

  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 3 ]
  assert_contains "$output" "this change touches 'bond0', which carries your SSH session"
  assert_contains "$output" "tier: deadman"
  assert_contains "$output" "re-run with --force-unsafe"
  # refused before anything at all happened
  assert_no_nmcli_mutations
  assert_not_called '^systemd-run '
  [ -z "$(ls -A "$BM_BACKUP_DIR")" ]
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "guard: sees VLAN interfaces — a session on bond0.120 protects bond0" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1
  stub_vlan_120
  stub_ssh_session 10.1.2.3 bond0.120

  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 3 ]
  assert_contains "$output" "this change touches 'bond0.120', which carries your SSH session"
  assert_no_nmcli_mutations
  [ -z "$(ls -A "$BM_BACKUP_DIR")" ]
}

@test "guard: sees member NICs — a session on eth0 protects a swap on bond0" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1
  stub_ssh_session 10.1.2.3 eth0

  run_cli -y swap-member bond0 --old eth1 --new eth2
  [ "$status" -eq 3 ]
  assert_contains "$output" "this change touches 'eth0', which carries your SSH session"
  assert_no_nmcli_mutations
}

@test "guard: --no-checkpoint on the egress device is refused as well" {
  require_root
  stub_ssh_session 10.1.2.3 bond0
  run_cli -y --no-checkpoint modify bond0 --opt miimon=250
  [ "$status" -eq 3 ]
  assert_contains "$output" "tier: deadman"
  assert_not_called '^busctl '
  assert_no_nmcli_mutations
}

@test "guard: a device the change does not touch is not protected" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1
  mk_sys_nic ens9 up 1000 52:54:00:12:34:09
  stub_ssh_session 10.1.2.3 ens9

  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 0 ]
  assert_contains "$output" "change applied and committed"
  assert_not_contains "$output" "carries your SSH session"
}

@test "guard: no SSH session at all means no guard" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1
  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 0 ]
  assert_not_contains "$output" "carries your SSH session"
}

# ---- override and warn paths -----------------------------------------------

@test "guard: --force-unsafe accepts the risk and applies the change" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1
  stub_ssh_session 10.1.2.3 bond0

  run_cli -y --force-unsafe modify bond0 --opt miimon=250
  [ "$status" -eq 0 ]
  assert_contains "$output" "WARNING: proceeding without checkpoint protection on your SSH egress device (bond0)"
  assert_called '^nmcli connection modify .* bond.options mode=active-backup,miimon=250$'
  assert_contains "$output" "change applied and committed"
}

@test "guard: under checkpoint protection it only warns" {
  require_root
  stub_ssh_session 10.1.2.3 bond0            # busctl answers => checkpoint tier
  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 0 ]
  assert_contains "$output" "NOTE: this change touches 'bond0', which carries your SSH session."
  assert_contains "$output" "NetworkManager will auto-rollback in 120s unless you commit."
  assert_not_contains "$output" "re-run with --force-unsafe"
  assert_called '^nmcli connection modify .* bond.options mode=active-backup,miimon=250$'
}

@test "guard: a checkpoint that cannot be created is re-checked, and disarmed on refusal" {
  require_root
  # probe says 'checkpoint' (D-Bus answers) so the first guard pass only
  # warns — but CheckpointCreate then fails and the run falls back to the
  # deadman tier, where the same change is unacceptable.
  export BM_STUB_CKPT_CREATE_RC=1
  stub_ssh_session 10.1.2.3 bond0

  run_cli -y modify bond0 --opt miimon=250
  [ "$status" -eq 3 ]
  assert_contains "$output" "checkpoint protection is unavailable"
  # nothing was applied, and the timer armed in the meantime is cancelled
  assert_no_nmcli_mutations
  assert_called '^systemd-run '
  assert_called '^systemctl stop bond-manager-deadman-'
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "guard: the dry-run path is never blocked (it changes nothing)" {
  export BM_STUB_BUSCTL_PING_RC=1
  stub_ssh_session 10.1.2.3 bond0
  run_cli --dry-run modify bond0 --opt miimon=250
  [ "$status" -eq 0 ]
  assert_contains "$output" "Set bond.options to 'mode=active-backup,miimon=250'"
  assert_no_nmcli_mutations
}
