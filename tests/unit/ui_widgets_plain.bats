#!/usr/bin/env bats
# bm::ui widgets in plain mode (no terminal): what a serial console, --plain
# or a script sees. Widgets are called directly, not via `run`, because they
# answer through globals (BM_UI_REPLY...).

load ../helpers

setup() {
  setup_sandbox
  load_artifact
  BM_PLAIN=1
  bm::ui::init --force
}

@test "menu: picks by number" {
  bm::ui::menu -- "Fruit" a "Apple" b "Banana" <<<"2" 2>/dev/null
  [ "$BM_UI_REPLY" = "b" ]
}

@test "menu: picks by tag" {
  bm::ui::menu -- "Fruit" a "Apple" b "Banana" <<<"a" 2>/dev/null
  [ "$BM_UI_REPLY" = "a" ]
}

@test "menu: asks again after nonsense or an out-of-range number" {
  local err="$BATS_TEST_TMPDIR/err"
  bm::ui::menu -- "Fruit" a "Apple" b "Banana" < <(printf 'zzz\n9\n1\n') 2>"$err"
  [ "$BM_UI_REPLY" = "a" ]
  grep -q "Please type a number from 1 to 2" "$err"
}

@test "menu: q goes back without flagging end of input" {
  local rc=0
  bm::ui::menu -- "Fruit" a "Apple" <<<"q" 2>/dev/null || rc=$?
  [ "$rc" -eq 1 ]
  [ "$BM_UI_EOF" -eq 0 ]
}

@test "menu: end of input cancels and flags BM_UI_EOF" {
  local rc=0
  bm::ui::menu -- "Fruit" a "Apple" </dev/null 2>/dev/null || rc=$?
  [ "$rc" -eq 1 ]
  [ "$BM_UI_EOF" -eq 1 ]
}

@test "menu: Enter takes the default" {
  bm::ui::menu --default b -- "Fruit" a "Apple" b "Banana" <<<"" 2>/dev/null
  [ "$BM_UI_REPLY" = "b" ]
}

@test "menu: headings are shown but not numbered" {
  local err="$BATS_TEST_TMPDIR/err"
  bm::ui::menu -- "Fruit" - "Sweet ones" a "Apple" b "Banana" <<<"2" 2>"$err"
  [ "$BM_UI_REPLY" = "b" ]
  grep -q "Sweet ones" "$err"
  grep -q " 2) Banana" "$err"
}

@test "menu: --keys return key:<k>, and q means quit there" {
  bm::ui::menu --keys "q p" -- "Home" a "Apple" <<<"p" 2>/dev/null
  [ "$BM_UI_REPLY" = "key:p" ]
  bm::ui::menu --keys "q p" -- "Home" a "Apple" <<<"q" 2>/dev/null
  [ "$BM_UI_REPLY" = "key:q" ]
}

@test "menu: notes after a TAB are shown in brackets" {
  local err="$BATS_TEST_TMPDIR/err"
  bm::ui::menu -- "Fruit" a "Apple"$'\t'"red or green" <<<"1" 2>"$err"
  grep -q "Apple  (red or green)" "$err"
}

@test "checklist: enforces the minimum, accepts numbers and tags" {
  local err="$BATS_TEST_TMPDIR/err"
  bm::ui::checklist --min 2 -- "Ports" a "A" b "B" c "C" < <(printf '1\n1 b\n') 2>"$err"
  [ "$BM_UI_REPLY" = "a,b" ]
  [ "${#BM_UI_REPLY_LIST[@]}" -eq 2 ]
  grep -q "Please pick at least 2" "$err"
}

@test "checklist: enforces the maximum" {
  bm::ui::checklist --max 1 -- "Ports" a "A" b "B" < <(printf '1 2\n2\n') 2>/dev/null
  [ "$BM_UI_REPLY" = "b" ]
}

@test "checklist: Enter keeps what is already ticked" {
  bm::ui::checklist --on b -- "Ports" a "A" b "B" <<<"" 2>/dev/null
  [ "$BM_UI_REPLY" = "b" ]
}

@test "checklist: an unknown entry is explained, not accepted" {
  local err="$BATS_TEST_TMPDIR/err"
  bm::ui::checklist -- "Ports" a "A" b "B" < <(printf 'zz\n1\n') 2>"$err"
  [ "$BM_UI_REPLY" = "a" ]
  grep -q '"zz" is not on the list' "$err"
}

only_ok() { [[ "$1" == ok* ]] || { BM_UI_VERR="must start with ok"; return 1; }; }

@test "input: the validator's message is shown and the question asked again" {
  local err="$BATS_TEST_TMPDIR/err"
  bm::ui::input --validate only_ok -- "Word" < <(printf 'bad\nokay\n') 2>"$err"
  [ "$BM_UI_REPLY" = "okay" ]
  grep -q "must start with ok" "$err"
}

@test "input: Enter takes the default; surrounding spaces are trimmed" {
  bm::ui::input --default bond0 -- "Name" <<<"" 2>/dev/null
  [ "$BM_UI_REPLY" = "bond0" ]
  bm::ui::input -- "Name" <<<"  bond7  " 2>/dev/null
  [ "$BM_UI_REPLY" = "bond7" ]
}

@test "input: --optional accepts an empty answer, required does not" {
  bm::ui::input --optional -- "Gateway" <<<"" 2>/dev/null
  [ -z "$BM_UI_REPLY" ]
  bm::ui::input -- "Name" < <(printf '\nbond3\n') 2>/dev/null
  [ "$BM_UI_REPLY" = "bond3" ]
}

@test "input: q goes back" {
  local rc=0
  bm::ui::input -- "Name" <<<"q" 2>/dev/null || rc=$?
  [ "$rc" -eq 1 ]
}

@test "yesno: exactly the historical answers count as yes" {
  bm::ui::yesno "Apply?" <<<"y"
  bm::ui::yesno "Apply?" <<<"yes"
  bm::ui::yesno "Apply?" <<<"Y"
  refute bm::ui::yesno "Apply?" <<<""
  refute bm::ui::yesno "Apply?" <<<"n"
  refute bm::ui::yesno "Apply?" <<<"yep"
  refute bm::ui::yesno "Apply?" </dev/null
}

@test "yesno: --yes answers without reading anything" {
  BM_ASSUME_YES=1
  bm::ui::yesno "Apply?" </dev/null
}

@test "yesno --default y: Enter is yes, end of input is still no" {
  bm::ui::yesno --default y "Again?" <<<""
  refute bm::ui::yesno --default y "Again?" <<<"n"
  refute bm::ui::yesno --default y "Again?" </dev/null
}

@test "confirm_exact: only the exact name confirms" {
  bm::ui::confirm_exact "removal of bond0" bond0 <<<"bond0" 2>/dev/null
  refute bm::ui::confirm_exact "removal of bond0" bond0 <<<"bond1" 2>/dev/null
}
