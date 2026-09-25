#!/usr/bin/env bats
# The commands that use a scratch directory leave nothing behind in $TMPDIR:
# `init`, `bundle`, and `bundle` started from the menus (where the action runs
# in a subshell). Up to 3.1 each of these leaked a bond-manager.XXXXXX dir.
# All of them need root (install -o root, reading NetworkManager state).

load ../helpers

setup() {
  setup_sandbox
  scenario_bond0_healthy
  stub_nm_bond0_profile
  export TMPDIR="$BATS_TEST_TMPDIR/tmp"
  mkdir -p "$TMPDIR"
}

leftovers() {
  find "$TMPDIR" -mindepth 1 -maxdepth 1 -name 'bond-manager.*'
}

@test "init: no temp directory left behind" {
  require_root
  run_cli init
  [ "$status" -eq 0 ]
  [ -f "$BM_CONF" ]
  [ -f "$BM_LOGROTATE_CONF" ]
  [ -z "$(leftovers)" ]
}

@test "bundle: no temp directory left behind, and the archive is complete" {
  require_root
  run_cli bundle --output "$BM_TEST_SANDBOX/support.tar.gz"
  [ "$status" -eq 0 ]
  assert_contains "$output" "support bundle: $BM_TEST_SANDBOX/support.tar.gz"
  tar -tzf "$BM_TEST_SANDBOX/support.tar.gz" | grep -q 'MANIFEST.txt$'
  [ -z "$(leftovers)" ]
}

@test "bundle from the menus: no temp directory left behind" {
  require_root
  run timeout 30 bash -c 'printf "tools\nbundle\nn\n\nq\nq\n" | "$1" tui' _ "$BM_ARTIFACT"
  [ "$status" -eq 0 ]
  assert_contains "$output" "support bundle: "
  [ -z "$(leftovers)" ]
}
