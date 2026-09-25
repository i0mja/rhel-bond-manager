#!/usr/bin/env bats
# `bond-manager nics`: every port with a plain verdict on whether it can be
# used. Read-only, no root, and it never talks to NetworkManager.

load ../helpers

setup() {
  setup_sandbox
  scenario_bond0_healthy                     # bond0 = eth0 (active) + eth1
  mk_sys_nic eth2 up 1000 52:54:00:12:34:03
  mk_sys_nic eth3 down 1000 52:54:00:12:34:04
  mk_sys_nic eth4 up 10000 52:54:00:12:34:05
  stub_ip_file addr_eth4 "eth4 UP 192.168.1.5/24 fe80::5054:ff:fe12:3405/64"
  mkdir -p "$BM_SYS_ROOT/class/net/docker0"   # blocked by the NIC policy
  printf 'up\n' >"$BM_SYS_ROOT/class/net/docker0/operstate"
}

row() { # row <nic> -> the output line for that NIC
  printf '%s\n' "$output" | grep -E "^$1 "
}

@test "nics: a plain verdict per port" {
  run_cli nics
  [ "$status" -eq 0 ]
  assert_contains "${lines[0]}" "NIC"
  assert_contains "$(row eth0)" "in bond0 (active)"
  assert_contains "$(row eth1)" "in bond0"
  assert_contains "$(row eth2)" "free - good to use"
  assert_contains "$(row eth3)" "free, but no link - cable or switch port?"
  assert_contains "$(row eth4)" "has an IP - probably in use"
  assert_contains "$(row eth4)" "192.168.1.5/24"
  assert_not_contains "$(row eth4)" "+1"            # link-local is not "an IP"
  assert_contains "$(row eth4)" "10G"
}

@test "nics: the port carrying the SSH session is called out" {
  stub_ssh_session 10.9.9.9 eth2
  run_cli nics
  assert_contains "$(row eth2)" "carries your SSH connection"
}

@test "nics: members of the bond carrying SSH are called out too" {
  stub_ssh_session 10.9.9.9 bond0
  run_cli nics
  assert_contains "$(row eth0)" "in bond0 - carries your SSH connection"
  assert_contains "$(row eth1)" "carries your SSH connection"
}

@test "nics: a port whose VLAN carries the SSH session is not called free" {
  mkdir -p "$BM_PROC_ROOT/net/vlan"
  printf 'VLAN Dev name | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\neth2.100 | 100 | eth2\n' \
    >"$BM_PROC_ROOT/net/vlan/config"
  mk_sys_nic eth2.100 up 1000 52:54:00:12:34:03
  stub_ssh_session 10.9.9.9 eth2.100
  run_cli nics
  [ "$status" -eq 0 ]
  assert_contains "$(row eth2)" "carries your SSH connection (through eth2.100)"
  assert_not_contains "$(row eth2)" "free"
  assert_not_contains "$output" "--members eth2"
}

@test "nics: on an 80-column terminal the notes wrap under their own column" {
  python3 -c 'import pty' 2>/dev/null || skip "needs python3 with the pty module"
  stub_ssh_session 10.9.9.9 bond0
  run timeout 60 "$TESTS_DIR/tools/pty-drive" --size 80x30 -- "$BM_ARTIFACT" nics
  [ "$status" -eq 0 ]
  local text col
  text="$(printf '%s' "$output" | sed -E $'s/\x1b\\[[0-9;?]*[A-Za-z]//g' | tr -d '\r' | grep -v '^PTY-EXIT')"
  refute grep -q '.\{80\}' <<<"$text"              # nothing spills past the edge
  assert_contains "$text" "  bond-manager help swap-member"
  col="$(head -n 1 <<<"$text" | awk '{ print index($0, "NOTE") - 1 }')"
  (( col > 0 ))
  # eth0's note continues on the next line, indented to the NOTE column
  grep -A1 '^eth0 ' <<<"$text" | tail -n 1 | grep -Eq "^ {$col}[^ ]"
}

@test "nics: the tip builds a create command from two free ports" {
  mk_sys_nic eth5 up 1000 52:54:00:12:34:06
  run_cli nics
  assert_contains "$output" "bond-manager -n create bond1 --mode active-backup --members eth2,eth5"
}

@test "nics: policy-hidden devices are counted, and shown with --all" {
  run_cli nics
  assert_not_contains "$output" "docker0"
  assert_contains "$output" "(1 more hidden by the NIC policy - see them with: bond-manager nics --all)"
  run_cli nics --all
  [ "$status" -eq 0 ]
  assert_contains "$(row docker0)" "hidden by the NIC policy"
}

@test "nics: read-only - no nmcli, nothing written" {
  run_cli nics
  [ "$status" -eq 0 ]
  assert_not_called '^nmcli '
  [ -z "$(ls -A "$BM_RUN_DIR")" ]
  [ -z "$(ls -A "$BM_BACKUP_DIR")" ]
  [ ! -e "$BM_LOG_FILE" ]
}

@test "nics: bad flags and --json are usage errors with a pointer" {
  run_cli nics --bogus
  [ "$status" -eq 2 ]
  run_cli --json nics
  [ "$status" -eq 2 ]
  assert_contains "$output" "bond-manager --json list"
}
