#!/usr/bin/env bats
# bm::ui — the pure pieces of the terminal toolkit: text measuring and
# fitting, key decoding, and menu cursor maths.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
  bm::ui::init --force
}

@test "init: without a terminal the toolkit is plain and 7-bit ASCII" {
  [ "$BM_UI_MODE" = "plain" ]
  [ "$BM_UI_UTF8" -eq 0 ]
  [ "$BM_G_DOT" = "*" ]
  [ "$BM_G_TL" = "+" ]
  [ -z "$BM_S_RED" ] # NO_COLOR
}

@test "vlen: counts visible characters, not color codes" {
  bm::ui::vlen $'\e[1;31mabc\e[0m'
  [ "$BM_UI_VLEN" -eq 3 ]
  bm::ui::vlen ""
  [ "$BM_UI_VLEN" -eq 0 ]
}

@test "fit: short text untouched, long text cut with an ellipsis" {
  bm::ui::fit "hello" 10
  [ "$BM_UI_FIT" = "hello" ]
  bm::ui::fit "hello world" 6
  [ "$BM_UI_FIT" = "hello~" ]
  bm::ui::fit $'\e[1mhello world\e[0m' 6
  bm::ui::vlen "$BM_UI_FIT"
  [ "$BM_UI_VLEN" -eq 6 ]
}

@test "pad: pads to the exact width" {
  bm::ui::pad "ab" 5
  [ "$BM_UI_FIT" = "ab   " ]
}

@test "fmt_secs: m:ss, never negative" {
  bm::ui::fmt_secs 0
  [ "$BM_UI_FMT" = "0:00" ]
  bm::ui::fmt_secs 59
  [ "$BM_UI_FMT" = "0:59" ]
  bm::ui::fmt_secs 112
  [ "$BM_UI_FMT" = "1:52" ]
  bm::ui::fmt_secs -5
  [ "$BM_UI_FMT" = "0:00" ]
}

@test "wrap: breaks on words and hard-breaks words longer than the line" {
  bm::ui::wrap 10 "one two three four"
  [ "${BM_UI_WRAPPED[0]}" = "one two" ]
  [ "${BM_UI_WRAPPED[1]}" = "three four" ]
  bm::ui::wrap 4 "abcdefghij"
  [ "${BM_UI_WRAPPED[0]}" = "abcd" ]
  [ "${BM_UI_WRAPPED[2]}" = "ij" ]
}

@test "box_lines: every line is exactly the box width" {
  BM_UI_COLS=40
  bm::ui::box_lines "Title" " BADGE " "" "short" "a much longer line that will certainly be cut to fit"
  local l
  for l in "${BM_UI_LINES[@]}"; do
    bm::ui::vlen "$l"
    [ "$BM_UI_VLEN" -eq 39 ]
  done
  assert_contains "${BM_UI_LINES[0]}" "Title"
  assert_contains "${BM_UI_LINES[0]}" "BADGE"
}

key_of() { # key_of <printf-format> -> BM_UI_KEY, rc in KEY_RC
  KEY_RC=0
  bm::ui::read_key < <(printf "$1") || KEY_RC=$?
}

@test "read_key: arrows, paging and home/end sequences" {
  key_of '\033[A';  [ "$BM_UI_KEY" = "UP" ]
  key_of '\033[B';  [ "$BM_UI_KEY" = "DOWN" ]
  key_of '\033OH';  [ "$BM_UI_KEY" = "HOME" ]
  key_of '\033[F';  [ "$BM_UI_KEY" = "END" ]
  key_of '\033[5~'; [ "$BM_UI_KEY" = "PGUP" ]
  key_of '\033[6~'; [ "$BM_UI_KEY" = "PGDN" ]
  key_of '\033[1;5A'; [ "$BM_UI_KEY" = "UNKNOWN" ]
}

@test "read_key: plain keys, Enter, Space, Backspace and a lone Esc" {
  key_of 'x';      [ "$BM_UI_KEY" = "x" ]
  key_of '\n';     [ "$BM_UI_KEY" = "ENTER" ]
  key_of ' ';      [ "$BM_UI_KEY" = "SPACE" ]
  key_of '\177';   [ "$BM_UI_KEY" = "BACKSPACE" ]
  key_of '\033';   [ "$BM_UI_KEY" = "ESC" ]
  [ "$KEY_RC" -eq 0 ]
}

@test "read_key: end of input is rc 2 and sets BM_UI_EOF" {
  local rc=0
  bm::ui::read_key </dev/null || rc=$?
  [ "$rc" -eq 2 ]
  [ "$BM_UI_EOF" -eq 1 ]
}

@test "_nav: wraps around, pages and jumps" {
  BM_UI_SEL=0
  bm::ui::_nav UP 5 3;   [ "$BM_UI_SEL" -eq 4 ]
  bm::ui::_nav DOWN 5 3; [ "$BM_UI_SEL" -eq 0 ]
  bm::ui::_nav END 5 3;  [ "$BM_UI_SEL" -eq 4 ]
  bm::ui::_nav PGUP 5 3; [ "$BM_UI_SEL" -eq 1 ]
  bm::ui::_nav PGUP 5 3; [ "$BM_UI_SEL" -eq 0 ]
  bm::ui::_nav PGDN 5 3; [ "$BM_UI_SEL" -eq 3 ]
  bm::ui::_nav PGDN 5 3; [ "$BM_UI_SEL" -eq 4 ]
  bm::ui::_nav HOME 5 3; [ "$BM_UI_SEL" -eq 0 ]
  bm::ui::_nav j 5 3;    [ "$BM_UI_SEL" -eq 1 ]
}

@test "_view: keeps the cursor inside the viewport" {
  BM_UI_TOP=0
  bm::ui::_view 7 10 4;   [ "$BM_UI_TOP" -eq 4 ]
  bm::ui::_view 2 10 4;   [ "$BM_UI_TOP" -eq 2 ]
  BM_UI_TOP=4
  bm::ui::_view 2 10 4 1; [ "$BM_UI_TOP" -eq 1 ]   # shows the heading above
  BM_UI_TOP=9
  bm::ui::_view 9 10 4;   [ "$BM_UI_TOP" -eq 6 ]   # never past the end
}
