#!/usr/bin/env bats
# Help routing and the "what to do next" layer on errors: every mistake a
# newcomer makes gets a pointer, and none of it changes the stable ERROR
# lines, exit codes, or the purity of a dry run.

load ../helpers

setup() {
  setup_sandbox
  scenario_bond0_healthy
  mk_sys_nic eth2 up 1000 52:54:00:12:34:03
  mk_sys_nic eth3 up 1000 52:54:00:12:34:04
  stub_nm_bond0_profile
}

# Only read-only nmcli listings may appear in the call log.
assert_only_listings() {
  run grep -Ev '^nmcli -t -f [^ ]+ connection show$|^nmcli -g [^ ]+ connection show ' "$BM_TEST_CALLS"
  [ -z "$output" ]
  [ -z "$(ls -A "$BM_BACKUP_DIR")" ]
  [ -z "$(ls -A "$BM_RUN_DIR")" ]
}

@test "usage: keeps its contract lines and leads with the common tasks" {
  run_cli --help
  [ "$status" -eq 0 ]
  assert_contains "$output" "New here? Run  sudo bond-manager"
  assert_contains "$output" "Common tasks:"
  assert_contains "$output" "bond-manager swap-member BOND --old IF --new IF"
  assert_contains "$output" "nics [--all]"
  assert_contains "$output" "help [COMMAND|TOPIC]"
  assert_contains "$output" "Help topics (bond-manager help TOPIC): basics"
}

@test "help COMMAND and COMMAND --help are the same page" {
  run_cli help swap-member
  [ "$status" -eq 0 ]
  local page="$output"
  assert_contains "$page" "bond-manager swap-member - replace a bond port"
  assert_contains "$page" "bond-manager -n swap-member bond0 --old ens1f0 --new ens2f0"
  run_cli swap-member --help
  [ "$status" -eq 0 ]
  [ "$output" = "$page" ]
  run_cli --help swap-member
  [ "$output" = "$page" ]
}

@test "--help after a subcommand word still finds the command" {
  run_cli vlan add --help
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond-manager vlan - add, change, remove or list VLANs"
  run_cli delete --help
  assert_contains "$output" "bond-manager remove - delete a bond"
}

@test "--help wins over an invalid --rollback-window" {
  run_cli --rollback-window 1 create --help
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond-manager create - build a new bond"
}

@test "help TOPIC explains in plain words" {
  run_cli help modes
  [ "$status" -eq 0 ]
  assert_contains "$output" "Not sure? Pick active-backup."
  run_cli help basics
  assert_contains "$output" "WHAT IS A BOND?"
}

@test "help for an unknown word: rc 2 and a suggestion" {
  run_cli help swapmember
  [ "$status" -eq 2 ]
  assert_contains "$output" 'no help for "swapmember"'
  assert_contains "$output" "Did you mean: bond-manager help swap-member"
}

@test "unknown command: suggestion by spelling and by meaning, still rc 2" {
  run_cli statsu
  [ "$status" -eq 2 ]
  assert_contains "$output" 'unknown command "statsu"'
  assert_contains "$output" "Did you mean: bond-manager status"
  run_cli move
  [ "$status" -eq 2 ]
  assert_contains "$output" "Did you mean: bond-manager swap-member"
  run_cli undo
  assert_contains "$output" "Did you mean: bond-manager rollback"
}

@test "a mode typed without --mode: pointed at the flag" {
  run_cli -n create bond9 active-backup
  [ "$status" -eq 2 ]
  assert_contains "$output" "unknown flag 'active-backup'"
  assert_contains "$output" "Next step: did you mean '--mode active-backup'?"
}

@test "ports typed without --members: pointed at the flag" {
  run_cli -n create bond9 --mode active-backup eth2,eth3
  [ "$status" -eq 2 ]
  assert_contains "$output" "did you mean '--members eth2,eth3'?"
}

@test "misspelled flag: the closest real flag" {
  run_cli -n create bond9 --memebrs eth2
  [ "$status" -eq 2 ]
  assert_contains "$output" "unknown flag '--memebrs'"
  assert_contains "$output" "did you mean '--members'?"
}

@test "a flag without its value is a usage error with an example" {
  run_cli -n create bond9 --mode
  [ "$status" -eq 2 ]
  assert_contains "$output" "flag '--mode' needs a value"
  assert_contains "$output" "for example: --mode active-backup"
  run_cli -n create bond9 --members --mode active-backup
  [ "$status" -eq 2 ]
  assert_contains "$output" "flag '--members' needs a value"
  run_cli diagnose bond0 --target
  [ "$status" -eq 2 ]
  run_cli --rollback-window
  [ "$status" -eq 2 ]
}

@test "mode aliases are suggested" {
  run_cli -n create bond9 --mode lacp --members eth2,eth3
  [ "$status" -eq 2 ]
  assert_contains "$output" "unknown mode 'lacp'"
  assert_contains "$output" "did you mean '802.3ad'?"
}

@test "a port that does not exist: the closest name and the nics command" {
  run_cli -n create bond9 --mode active-backup --members eth22
  [ "$status" -eq 3 ]
  assert_contains "$output" "interface 'eth22' does not exist"
  assert_contains "$output" "did you mean 'eth2'? See every port: bond-manager nics"
  assert_only_listings
}

@test "a port already in another bond: how to free it" {
  run_cli -n create bond9 --mode active-backup --members eth0,eth2
  [ "$status" -eq 3 ]
  assert_contains "$output" "already enslaved to bond 'bond0'"
  assert_contains "$output" "bond-manager remove-member bond0 eth0"
}

@test "a bond that does not exist: the closest bond" {
  run_cli -n modify bond00 --mtu 9000
  [ "$status" -eq 3 ]
  assert_contains "$output" "no NetworkManager bond profile found for 'bond00'"
  assert_contains "$output" "did you mean 'bond0'?"
  assert_only_listings
}

@test "a bond the kernel runs but NetworkManager does not manage is explained" {
  rm -f "$BM_STUB_NM_DIR"/*.conn
  run_cli -n modify bond0 --mtu 9000
  [ "$status" -eq 3 ]
  assert_contains "$output" "runs in the kernel but NetworkManager has no saved profile"
}

@test "swap-member --old that is not a member lists the real members" {
  run_cli -n swap-member bond0 --old eth9 --new eth2
  [ "$status" -eq 3 ]
  assert_contains "$output" "--old must be one of its current ports: eth0, eth1"
}

@test "bad addresses explain the expected format" {
  run_cli -n create bond9 --mode active-backup --members eth2 --ip4 10.0.0.5
  [ "$status" -eq 2 ]
  assert_contains "$output" "invalid IPv4 CIDR '10.0.0.5'"
  assert_contains "$output" "e.g. 10.0.0.10/24"
}

@test "not root: re-run the same command with sudo" {
  [[ "$EUID" -ne 0 ]] || skip "needs a non-root user"
  run_cli swap-member bond0 --old eth0 --new eth2
  [ "$status" -eq 3 ]
  assert_contains "$output" "this operation must be run as root"
  assert_contains "$output" "sudo bond-manager swap-member bond0 --old eth0 --new eth2"
}

@test "not root: a backup folder only root can read is said so, not 'no snapshots'" {
  [[ "$EUID" -ne 0 ]] || skip "needs a non-root user"
  chmod 000 "$BM_BACKUP_DIR"
  run_cli snapshot list
  chmod 755 "$BM_BACKUP_DIR"
  [ "$status" -eq 3 ]
  assert_contains "$output" "can only be read by root"
  assert_contains "$output" "sudo bond-manager snapshot list"
  assert_not_contains "$output" "No snapshots"
}

@test "doctor ends with a next step" {
  run_cli doctor
  assert_contains "$output" "Next step:"
}

@test "bad IPv6 DNS servers are rejected with the expected format" {
  run_cli -n create bond9 --mode active-backup --members eth2 \
    --ip6 2001:db8::5/64 --dns6 not-an-address
  [ "$status" -eq 2 ]
  assert_contains "$output" "invalid IPv6 DNS list 'not-an-address'"
  assert_contains "$output" "e.g. 2001:db8::53"
  run_cli -n create bond9 --mode active-backup --members eth2 \
    --ip6 2001:db8::5/64 --dns6 2001:db8::53,2001:db8::54
  [ "$status" -eq 0 ]
}
