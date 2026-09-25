#!/usr/bin/env bats
# bm::core::ensure_tmpdir / bm::core::cleanup — the private scratch directory
# is made in the calling shell and removed on exit. Up to 3.1 every caller
# used $(bm::core::tmpdir), so the path only existed in a subshell and every
# `init` and `bundle` leaked a /tmp/bond-manager.XXXXXX directory.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
  export TMPDIR="$BATS_TEST_TMPDIR/tmp"
  mkdir -p "$TMPDIR"
}

ours() { # the scratch directories currently in $TMPDIR
  find "$TMPDIR" -mindepth 1 -maxdepth 1 -name 'bond-manager.*' | wc -l
}

@test "ensure_tmpdir: creates one directory, visible in this shell, and reuses it" {
  bm::core::ensure_tmpdir
  local first="$BM_TMPDIR"
  [ -d "$first" ]
  [[ "$first" == "$TMPDIR"/bond-manager.* ]]
  bm::core::ensure_tmpdir
  [ "$BM_TMPDIR" = "$first" ]
  [ "$(ours)" -eq 1 ]
}

@test "ensure_tmpdir: prints nothing (it is not meant for \$(...))" {
  run bm::core::ensure_tmpdir
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "cleanup: removes the directory and forgets it" {
  bm::core::ensure_tmpdir
  : >"$BM_TMPDIR/some-file"
  bm::core::cleanup
  [ -z "$BM_TMPDIR" ]
  [ "$(ours)" -eq 0 ]
}

@test "ensure_tmpdir: a directory removed underneath it is made again" {
  bm::core::ensure_tmpdir
  rm -rf "$BM_TMPDIR"
  bm::core::ensure_tmpdir
  [ -d "$BM_TMPDIR" ]
  [ "$(ours)" -eq 1 ]
}

@test "ensure_tmpdir: fails cleanly when no directory can be made" {
  export TMPDIR="$BATS_TEST_TMPDIR/does/not/exist"
  local rc=0
  bm::core::ensure_tmpdir 2>/dev/null || rc=$?
  [ "$rc" -ne 0 ]
  [ -z "$BM_TMPDIR" ]
}

@test "cleanup: never deletes a directory ensure_tmpdir did not make" {
  mkdir -p "$BATS_TEST_TMPDIR/precious"
  BM_TMPDIR="$BATS_TEST_TMPDIR/precious"
  bm::core::cleanup
  [ -d "$BATS_TEST_TMPDIR/precious" ]
}

@test "an action run by the menus cleans up its own subshell" {
  # bm::tui::run executes every action in a subshell, which does not run the
  # program's EXIT trap — its own trap has to remove what the action made.
  exec {BM_TUI_OUT}>&1
  bm::tui::run look bm::core::ensure_tmpdir 2>/dev/null
  [ "$BM_TUI_LAST_RC" -eq 0 ]
  [ -z "$BM_TMPDIR" ] # the parent never saw it...
  [ "$(ours)" -eq 0 ] # ...and it is gone anyway
}

@test "no caller captures the scratch directory in a command substitution" {
  run grep -nE '\$\(\s*bm::core::(ensure_)?tmpdir' "$BM_ROOT"/lib/*.sh
  [ "$status" -eq 1 ]
  run grep -nE 'bm::core::tmpdir\b' "$BM_ROOT"/lib/*.sh
  [ "$status" -eq 1 ]
}
