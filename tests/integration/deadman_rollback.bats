#!/usr/bin/env bats
# The deadman timer (tier 2) firing: what `rollback --snapshot ID --deadman
# --yes`, run by systemd when nobody kept a change, really puts back.
#
# Restoring the saved profiles is not enough: NetworkManager's reload does
# not touch connections that are already active, so a change that cut the
# SSH session would stay live. After the restore the rollback must bring the
# affected connections up again from the restored profiles, delete what the
# change created, and say so when it cannot.
#
# Two things make that observable here. The fake NetworkManager keeps its
# profiles in the directory snapshots are taken of (BM_STUB_NM_DIR =
# BM_CONN_DIR), so a restore really changes what nmcli reports. And the
# timer's rollback runs "inside" its systemd unit (BM_STUB_SYSTEMCTL_SELF):
# stopping <unit>.service from there kills the rollback itself, as systemd
# would.

load ../helpers

setup() {
  setup_sandbox
  export BM_STUB_NM_DIR="$BM_CONN_DIR"
  mkdir -p "$BM_STUB_NM_DIR"
  scenario_bond0_healthy                       # bond0 = eth0 (active) + eth1
  stub_nm_bond0_profile
  mk_sys_nic eth2 up 1000 52:54:00:12:34:03
  mk_sys_nic eth3 up 1000 52:54:00:12:34:04
  set_conf LINK_SETTLE_TIMEOUT 0
  export BM_STUB_BUSCTL_PING_RC=1              # no checkpoints: the deadman tier
  hook_nm_database
}

BOND0=11111111-1111-1111-1111-111111111111
PORT_ETH0=22222222-2222-2222-2222-222222222222
PORT_ETH1=33333333-3333-3333-3333-333333333333

# NetworkManager's profile store (add / modify / delete) and the kernel's
# reaction to the create and remove used below.
hook_nm_database() {
  install_nmcli_hook <<'HOOK'
db="$BM_STUB_NM_DIR"
a=("$@")
while [[ "${a[0]:-}" == -w ]]; do a=("${a[@]:2}"); done
[[ "${a[0]:-}" == connection ]] || exit 0
verb="${a[1]:-}"
rest=("${a[@]:2}")
find_conn() {
  local f
  for f in "$db"/*.conn; do
    if grep -qx "connection.uuid=$1" "$f" || grep -qx "connection.id=$1" "$f"; then
      printf '%s' "$f"
      return 0
    fi
  done
  return 1
}
case "$verb" in
  add)
    declare -A kv=()
    i=0
    while (( i + 1 < ${#rest[@]} )); do kv[${rest[i]}]="${rest[i+1]}"; i=$(( i + 2 )); done
    uuid="$(printf '%08x-aaaa-4000-8000-%012x' "$RANDOM$RANDOM" "$RANDOM$RANDOM")"
    type="${kv[type]:-}"
    [[ "$type" == ethernet ]] && type=802-3-ethernet
    {
      printf 'connection.uuid=%s\nconnection.id=%s\n' "$uuid" "${kv[con-name]:-}"
      printf 'connection.type=%s\nconnection.interface-name=%s\n' "$type" "${kv[ifname]:-}"
      if [[ -n "${kv[master]:-}" ]]; then
        printf 'connection.master=%s\nconnection.slave-type=bond\n' "${kv[master]}"
      fi
      if [[ -n "${kv[bond.options]:-}" ]]; then printf 'bond.options=%s\n' "${kv[bond.options]}"; fi
      if [[ -n "${kv[vlan.parent]:-}" ]]; then
        printf 'vlan.parent=%s\nvlan.id=%s\n' "${kv[vlan.parent]}" "${kv[vlan.id]:-}"
      fi
    } >"$db/$uuid.conn"
    ;;
  modify)
    f="$(find_conn "${rest[0]}")" || exit 0
    i=1
    while (( i + 1 < ${#rest[@]} )); do
      grep -v "^${rest[i]}=" "$f" >"$f.new" || true
      printf '%s=%s\n' "${rest[i]}" "${rest[i+1]}" >>"$f.new"
      mv "$f.new" "$f"
      i=$(( i + 2 ))
    done
    ;;
  delete)
    f="$(find_conn "${rest[0]}")" && rm -f "$f"
    if [[ "${rest[0]}" == 11111111-1111-1111-1111-111111111111 ]]; then
      rm -rf "$BM_SYS_ROOT/class/net/bond0" "$BM_PROC_ROOT/net/bonding/bond0"
    fi
    ;;
  up)
    if [[ "${rest[0]}" == bond0.120 ]]; then
      mkdir -p "$BM_SYS_ROOT/class/net/bond0.120"
      printf 'up\n' >"$BM_SYS_ROOT/class/net/bond0.120/operstate"
    fi
    if [[ "${rest[0]}" == bond9 ]]; then
      mkdir -p "$BM_SYS_ROOT/class/net/bond9"
      printf 'up\n' >"$BM_SYS_ROOT/class/net/bond9/operstate"
      printf '1500\n' >"$BM_SYS_ROOT/class/net/bond9/mtu"
      "$BM_TEST_MKPROC" "$BM_PROC_ROOT/net/bonding/bond9" eth2 eth2 eth3
    fi
    ;;
esac
exit 0
HOOK
}

state() { sed -n "s/^$1=//p" "$BM_RUN_DIR/pending.state"; }

# Run what the timer runs, the way systemd runs it: inside its unit.
fire_deadman() {
  local unit snap
  unit="$(state deadman_unit)"
  snap="$(state snapshot)"
  [ -n "$unit" ]
  [ -n "$snap" ]
  : >"$BM_TEST_CALLS"
  run env BM_STUB_SYSTEMCTL_SELF="$unit" "$BM_ARTIFACT" rollback --snapshot "$snap" --deadman --yes
}

leave_pending() { # leave_pending <answers> <command...>: apply, stop at the gate (no TTY)
  local answers="$1"
  shift
  run bash -c 'printf "%b" "$1" | "${@:2}"' _ "$answers" "$BM_ARTIFACT" "$@"
  [ "$status" -eq 6 ]
  [ "$(state tier)" = deadman ]
}

@test "deadman after modify: the saved settings come back AND bond0 is brought up with them" {
  require_root
  leave_pending 'y\n' modify bond0 --opt miimon=250
  grep -q 'miimon=250' "$BM_CONN_DIR/$BOND0.conn"
  assert_contains " $(state affected) " " bond0 "

  fire_deadman
  [ "$status" -eq 0 ]
  refute grep -q 'miimon=250' "$BM_CONN_DIR/$BOND0.conn"
  assert_call_order \
    '^nmcli connection reload$' \
    "^nmcli -w [0-9]+ connection up $BOND0\$" \
    "^nmcli -w [0-9]+ connection up $PORT_ETH0\$"
  assert_called "^nmcli -w [0-9]+ connection up $PORT_ETH1\$"
  assert_contains "$output" "brought up again: bond0"
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "deadman: the timer's rollback does not stop its own systemd unit" {
  require_root
  leave_pending 'y\n' modify bond0 --opt miimon=250
  local unit
  unit="$(state deadman_unit)"
  fire_deadman
  [ "$status" -eq 0 ]
  assert_called "^systemctl stop $unit.timer\$"
  assert_not_called "^systemctl stop $unit.service\$"
  assert_contains "$output" "restored snapshot"
}

@test "deadman after create: the new bond is deleted, not brought back up" {
  require_root
  leave_pending 'y\n' create bond9 --mode active-backup --members eth2,eth3
  [ -d "$BM_SYS_ROOT/class/net/bond9" ]
  assert_contains " $(state affected) " " bond9 "

  fire_deadman
  [ "$status" -eq 0 ]
  refute grep -rqx 'connection.interface-name=bond9' "$BM_CONN_DIR"
  assert_call_order '^nmcli connection reload$' '^nmcli device delete bond9$'
  assert_not_called '^nmcli .*connection up'
  assert_contains "$output" "removed what the change created: bond9"
}

@test "deadman after remove: the deleted bond and its ports come back up" {
  require_root
  leave_pending 'bond0\ny\n' remove bond0
  [ ! -e "$BM_CONN_DIR/$BOND0.conn" ]

  fire_deadman
  [ "$status" -eq 0 ]
  [ -e "$BM_CONN_DIR/$BOND0.conn" ]
  [ -e "$BM_CONN_DIR/$PORT_ETH0.conn" ]
  assert_call_order \
    '^nmcli connection reload$' \
    "^nmcli -w [0-9]+ connection up $BOND0\$" \
    "^nmcli -w [0-9]+ connection up $PORT_ETH0\$"
  assert_called "^nmcli -w [0-9]+ connection up $PORT_ETH1\$"
}

@test "deadman after vlan add: the VLAN is deleted and bond0 is left alone" {
  require_root
  leave_pending 'y\n' vlan add bond0 120
  [ -d "$BM_SYS_ROOT/class/net/bond0.120" ]

  fire_deadman
  [ "$status" -eq 0 ]
  refute grep -rqx 'connection.interface-name=bond0.120' "$BM_CONN_DIR"
  assert_called '^nmcli device delete bond0.120$'
  # the restore did not change bond0's profile: no needless blip on it
  assert_not_called '^nmcli .*connection up'
}

@test "deadman: a connection that will not come up is reported, with the command to retry" {
  require_root
  leave_pending 'y\n' modify bond0 --opt miimon=250
  export BM_STUB_NMCLI_FAIL_RE="connection up $BOND0"
  fire_deadman
  [ "$status" -ne 0 ]
  refute grep -q 'miimon=250' "$BM_CONN_DIR/$BOND0.conn"   # the profiles are still restored
  assert_contains "$output" "could not bring bond0 up again"
  assert_contains "$output" "nmcli connection up $BOND0"
  [ ! -f "$BM_RUN_DIR/pending.state" ]
}

@test "rollback of a waiting change from another session re-applies it too" {
  require_root
  leave_pending 'y\n' modify bond0 --opt miimon=250
  : >"$BM_TEST_CALLS"
  run_cli rollback
  [ "$status" -eq 0 ]
  refute grep -q 'miimon=250' "$BM_CONN_DIR/$BOND0.conn"
  assert_call_order '^nmcli connection reload$' "^nmcli -w [0-9]+ connection up $BOND0\$"
}

@test "deadman: a state file from 3.0 (no affected list) still restores, and says what to re-apply" {
  require_root
  leave_pending 'y\n' modify bond0 --opt miimon=250
  sed -i '/^affected=/d' "$BM_RUN_DIR/pending.state"
  fire_deadman
  [ "$status" -eq 0 ]
  refute grep -q 'miimon=250' "$BM_CONN_DIR/$BOND0.conn"
  assert_not_called '^nmcli .*connection up'
  assert_contains "$output" "nmcli connection up"
}
