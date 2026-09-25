#!/usr/bin/env bats
# bm::core — "Next step" hints on errors, did-you-mean matching, and the
# terminal restore that runs on every exit.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "edit_distance: classic cases" {
  bm::core::edit_distance kitten sitting
  [ "$BM_EDIT_DIST" -eq 3 ]
  bm::core::edit_distance status statsu
  [ "$BM_EDIT_DIST" -eq 2 ]
  bm::core::edit_distance "" abc
  [ "$BM_EDIT_DIST" -eq 3 ]
  bm::core::edit_distance same same
  [ "$BM_EDIT_DIST" -eq 0 ]
}

@test "closest: typos and prefixes match, nonsense does not" {
  [ "$(bm::core::closest statsu list show status)" = "status" ]
  [ "$(bm::core::closest swap-membr swap-member remove-member)" = "swap-member" ]
  [ "$(bm::core::closest diag list diagnose doctor)" = "diagnose" ]
  [ "$(bm::core::closest STATUS list status)" = "status" ]
  [ -z "$(bm::core::closest frobnicate list status show)" ]
  [ -z "$(bm::core::closest "" list status)" ]
}

@test "die: the ERROR line is unchanged and the hint gets its own line" {
  run bm::core::die "something broke" 2 "do this next"
  [ "$status" -eq 2 ]
  [ "${lines[0]}" = "bond-manager: ERROR: something broke" ]
  [ "${lines[1]}" = "  Next step: do this next" ]
}

@test "die: a usage error points at the command's own help" {
  BM_CUR_CMD=swap-member
  run bm::core::die "swap-member requires --old and --new" "$BM_EX_USAGE"
  [ "$status" -eq 2 ]
  assert_contains "$output" "Next step: see examples: bond-manager help swap-member"
}

@test "die: without a hint or a command there is no Next step line" {
  run bm::core::die "plain failure" 1
  [ "$status" -eq 1 ]
  [ "${#lines[@]}" -eq 1 ]
}

@test "require_root: suggests re-running the same command with sudo" {
  [[ "$EUID" -ne 0 ]] || skip "needs a non-root user"
  BM_CMDLINE="swap-member bond0 --old eth0 --new eth2 "
  run bm::core::require_root
  [ "$status" -eq 3 ]
  assert_contains "$output" "this operation must be run as root"
  assert_contains "$output" "sudo bond-manager swap-member bond0 --old eth0 --new eth2"
}

@test "term_restore: harmless without a terminal, clears the saved state" {
  BM_TTY_SAVED="bogus-settings"
  BM_TTY_CURSOR_HIDDEN=0
  bm::core::term_restore
  [ -z "$BM_TTY_SAVED" ]
}
