#!/usr/bin/env bats
# The guided menus on a real (pseudo-)terminal: arrow keys, boxes, colors,
# Ctrl-C, and the terminal handed back intact. A pipe only ever gets the
# plain numbered menus (tui_plain.bats); this file drives the fancy mode
# through tests/tools/pty-drive (python3 standard library).

load ../helpers

setup() {
  python3 -c 'import pty' 2>/dev/null || skip "needs python3 with the pty module"
  setup_sandbox
  scenario_bond0_healthy
  stub_nm_bond0_profile
  mk_sys_nic eth2 up 1000 52:54:00:12:34:03
  mk_sys_nic eth3 up 1000 52:54:00:12:34:04
  set_conf LINK_SETTLE_TIMEOUT 0
  PTY="$TESTS_DIR/tools/pty-drive"
}

# a UTF-8 locale bash can actually use (C.UTF-8 ships with glibc >= 2.35)
utf8_or_skip() {
  LC_ALL=C.UTF-8 bash -c 't="●"; (( ${#t} == 1 ))' 2>/dev/null || skip "no usable C.UTF-8 locale"
}

# The raw output is full of color/cursor escapes; $screen is the same text
# with them removed, which is what the content assertions look at.
strip_escapes() {
  screen="$(printf '%s' "$output" | sed -E $'s/\x1b\\[[0-9;?]*[A-Za-z]//g')"
}

drive() { # drive <env...> -- <steps...>; runs the artifact in a pty
  local -a envs=()
  while [[ "$1" != "--" ]]; do envs+=("$1"); shift; done
  shift
  run timeout 90 "$PTY" "$@" -- env "${envs[@]}" "$BM_ARTIFACT" --dry-run
  strip_escapes
}

pty_run() { # pty_run <steps...> -- <command...>
  run timeout 90 "$PTY" "$@"
  strip_escapes
}

@test "pty: the home screen is a boxed dashboard with an arrow-key menu" {
  utf8_or_skip
  drive TERM=xterm LANG=C.UTF-8 LC_ALL=C.UTF-8 -- @expect:"What do you want to do?" q
  [ "$status" -eq 0 ]
  assert_contains "$screen" "┌─ bond-manager 3.1.0"
  assert_contains "$screen" "PRACTICE"
  assert_contains "$screen" "● bond0"
  assert_contains "$screen" "├─ eth0"
  assert_contains "$screen" "❯"
  assert_contains "$screen" "Enter choose"
  assert_contains "$screen" "PTY-EXIT 0"
}

@test "pty: arrow keys and Enter open a wizard; Esc goes back" {
  utf8_or_skip
  drive TERM=xterm LANG=C.UTF-8 LC_ALL=C.UTF-8 -- \
    @expect:"What do you want to do?" '\x1b[B' '\x1b[B' '\r' \
    @expect:"Step 1 of 5" '\x1b' @expect:"What do you want to do?" q
  [ "$status" -eq 0 ]
  assert_contains "$screen" "What do you want to do? › Build a new bond"
  assert_contains "$screen" "Bond name"
  assert_contains "$screen" "PTY-EXIT 0"
}

@test "pty: a number jumps straight to an item" {
  utf8_or_skip
  drive TERM=xterm LANG=C.UTF-8 LC_ALL=C.UTF-8 -- \
    @expect:"What do you want to do?" 8 @expect:"What would you like to know?" \
    '\x1b' @expect:"What do you want to do?" q
  [ "$status" -eq 0 ]
  assert_contains "$screen" "What do you want to do? › Help: what is all this?"
  assert_contains "$screen" "PTY-EXIT 0"
}

@test "pty: Ctrl-C backs out of a wizard, and quits from the home screen" {
  utf8_or_skip
  drive TERM=xterm LANG=C.UTF-8 LC_ALL=C.UTF-8 -- \
    @expect:"What do you want to do?" 3 @expect:"Step 1 of 5" \
    '\x03' @expect:"What do you want to do?" '\x03' @wait:1
  [ "$status" -eq 0 ]
  assert_contains "$screen" "Bye."
  assert_contains "$screen" "PTY-EXIT 0"
}

@test "pty: one Ctrl-C backs out of one screen, not the whole wizard a second later" {
  utf8_or_skip
  # Ctrl-C at the port list goes back to the name; after waiting there, Enter
  # must lead to the port list again (the wizard did not unwind to home)
  drive TERM=xterm LANG=C.UTF-8 LC_ALL=C.UTF-8 -- \
    @expect:"What do you want to do?" 3 @expect:"Bond name" '\r' @expect:"Ports for" \
    '\x03' @expect:"Bond name" @wait:3 '\r' @expect:"Ports for" \
    '\x03' @expect:"Bond name" @wait:1.5 '\x03' @expect:"What do you want to do?" q
  [ "$status" -eq 0 ]
  assert_contains "$screen" "PTY-EXIT 0"
}

@test "pty: Ctrl-C at a plain prompt goes back (plain mode on a terminal)" {
  drive TERM=dumb LANG=C LC_ALL=C -- \
    @expect:"Choose 1-10" 'build\r' @expect:"Bond name" '\x03' @expect:"Choose 1-10" 'q\r'
  [ "$status" -eq 0 ]
  assert_contains "$screen" "PTY-EXIT 0"
}

@test "pty: the terminal is handed back with echo, line mode and a visible cursor" {
  utf8_or_skip
  pty_run @expect:"What do you want to do?" 3 @expect:"Step 1 of 5" '\x03' \
    @expect:"What do you want to do?" q -- \
    env TERM=xterm LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    bash -c '"$0" --dry-run; rc=$?; echo; echo "STTY: $(stty -a | tr "\n" " ")"; exit $rc' "$BM_ARTIFACT"
  [ "$status" -eq 0 ]
  assert_contains "$screen" "PTY-EXIT 0"
  local stty_line
  stty_line="$(printf '%s\n' "$screen" | grep '^STTY: ')"
  [[ " $stty_line " =~ [[:space:]\;]icanon[[:space:]\;] ]]
  [[ " $stty_line " =~ [[:space:]\;]echo[[:space:]\;] ]]
  # the last cursor instruction the program sent is "show"
  local last_hide last_show
  last_hide="$(printf '%s' "$output" | grep -ob $'\e\\[?25l' | tail -n1 | cut -d: -f1)"
  last_show="$(printf '%s' "$output" | grep -ob $'\e\\[?25h' | tail -n1 | cut -d: -f1)"
  [ -n "$last_show" ]
  (( ${last_show:-0} > ${last_hide:-0} ))
}

@test "pty: without a UTF-8 locale the boxes fall back to ASCII" {
  drive TERM=xterm LANG=C LC_ALL=C -- @expect:"What do you want to do?" q
  [ "$status" -eq 0 ]
  assert_contains "$screen" "+- bond-manager 3.1.0"
  assert_not_contains "$screen" "┌"
  assert_not_contains "$screen" "❯"
  assert_contains "$screen" "PTY-EXIT 0"
}

@test "pty: TERM=dumb gets the plain numbered menus even on a terminal" {
  drive TERM=dumb LANG=C LC_ALL=C -- @expect:"Choose 1-10" 'q\r'
  [ "$status" -eq 0 ]
  assert_contains "$screen" " 1) Check my bonds"
  assert_contains "$screen" "PTY-EXIT 0"
}

@test "pty: a live change shows the countdown gate, and K keeps it" {
  require_root
  utf8_or_skip
  pty_run @expect:"Apply this plan?" 'y\r' @expect:"Auto-undo in" k -- \
    env TERM=xterm LANG=C.UTF-8 LC_ALL=C.UTF-8 "$BM_ARTIFACT" modify bond0 --opt miimon=50
  [ "$status" -eq 0 ]
  assert_contains "$screen" "┌─ Keep this change?"
  assert_contains "$screen" "All checks passed - your change is live."
  assert_contains "$screen" "change committed"
  assert_contains "$screen" "PTY-EXIT 0"
  [ ! -e "$BM_RUN_DIR/pending.state" ]
}

@test "pty: U at the gate undoes the change (exit 5)" {
  require_root
  pty_run @expect:"Apply this plan?" 'y\r' @expect:"Auto-undo in" u -- \
    env TERM=xterm LANG=C LC_ALL=C "$BM_ARTIFACT" modify bond0 --opt miimon=50
  [ "$status" -eq 0 ]
  assert_contains "$screen" "rolled back to snapshot"
  assert_contains "$screen" "PTY-EXIT 5"
  [ ! -e "$BM_RUN_DIR/pending.state" ]
}

@test "pty: a key typed while the change runs never answers the plain gate" {
  require_root
  # "k" arrives with the "y" that starts the change; the gate must not take it
  pty_run @expect:"Apply this plan?" 'y\rk' @expect:"Verification passed" @wait:2.5 u -- \
    env TERM=xterm LANG=C LC_ALL=C "$BM_ARTIFACT" --plain modify bond0 --opt miimon=50
  [ "$status" -eq 0 ]
  assert_not_contains "$screen" "change committed"
  assert_contains "$screen" "rolled back to snapshot"
  assert_contains "$screen" "PTY-EXIT 5"
}

@test "pty: a quick double Enter on the home screen never keeps a waiting change" {
  require_root
  seed_pending checkpoint 20240101-000000 "modify bond bond0"
  # the first Enter opens "Keep or undo?"; the second one, typed ahead, must
  # not answer it, and Enter there means "decide later"
  pty_run @expect:"What do you want to do?" '\r\r' @expect:"Decide later" @wait:1.5 '\r' \
    @expect:"What do you want to do?" q @wait:1 'y\r' -- \
    env TERM=xterm LANG=C LC_ALL=C "$BM_ARTIFACT"
  assert_not_contains "$screen" "pending change committed"
  [ -f "$BM_RUN_DIR/pending.state" ]
}

@test "pty: any other key at the plain gate says which keys to press" {
  require_root
  pty_run @expect:"Apply this plan?" 'y\r' @expect:"Verification passed" @wait:0.5 x \
    @expect:"Press c (or K) to keep the change" u -- \
    env TERM=xterm LANG=C LC_ALL=C "$BM_ARTIFACT" --plain modify bond0 --opt miimon=50
  [ "$status" -eq 0 ]
  assert_contains "$screen" "PTY-EXIT 5"
}
