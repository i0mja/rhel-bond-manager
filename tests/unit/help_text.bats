#!/usr/bin/env bats
# bm::help — the plain-English text the CLI and the menus share. These tests
# keep it complete: every command, topic, mode, health reason and exit code
# has an explanation, and all of it reads on a 80-column ASCII console.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "every command has help that starts with its name and shows examples" {
  local c out
  for c in "${BM_HELP_COMMANDS[@]}"; do
    out="$(bm::help::command "$c")"
    [[ "$out" == "bond-manager $c - "* ]] || { echo "bad first line for $c"; return 1; }
  done
  for c in create modify swap-member add-member remove-member vlan repair; do
    assert_contains "$(bm::help::command "$c")" "Examples:"
    assert_contains "$(bm::help::command "$c")" "bond-manager -n "
  done
}

@test "aliases resolve; unknown words do not" {
  [ "$(bm::help::canonical delete)" = "remove" ]
  [ "$(bm::help::canonical support-bundle)" = "bundle" ]
  refute bm::help::canonical frobnicate
  refute bm::help::command frobnicate
}

@test "every topic has text and a title" {
  local t
  for t in "${BM_HELP_TOPICS[@]}"; do
    [ -n "$(bm::help::topic "$t")" ]
    [ "$(bm::help::topic_title "$t")" != "$t" ]
  done
  refute bm::help::topic nosuchtopic
}

@test "help text is 7-bit ASCII and fits 79 columns" {
  local x
  # measure with the real paths, not the (long) sandbox ones
  BM_CONF=/etc/bond_manager.conf BM_LOG_FILE=/var/log/bond_manager.log
  for x in "${BM_HELP_COMMANDS[@]}"; do
    bm::help::command "$x" >>"$BATS_TEST_TMPDIR/all"
  done
  for x in "${BM_HELP_TOPICS[@]}"; do
    bm::help::topic "$x" >>"$BATS_TEST_TMPDIR/all"
  done
  bm::help::common_tasks >>"$BATS_TEST_TMPDIR/all"
  run awk 'length > 79' "$BATS_TEST_TMPDIR/all"
  [ -z "$output" ]
  run env LC_ALL=C grep -n '[^[:print:][:space:]]' "$BATS_TEST_TMPDIR/all"
  [ -z "$output" ]
}

@test "every mode has a plain sentence and a nickname" {
  local m
  for m in "${BM_MODES[@]}"; do
    [ "$(bm::help::mode_label "$m")" != "$m" ]
    [ -n "$(bm::help::mode_short "$m")" ]
  done
}

@test "mode_alias: what people type becomes a real mode" {
  [ "$(bm::help::mode_alias lacp)" = "802.3ad" ]
  [ "$(bm::help::mode_alias LACP)" = "802.3ad" ]
  [ "$(bm::help::mode_alias failover)" = "active-backup" ]
  [ "$(bm::help::mode_alias round-robin)" = "balance-rr" ]
  [ "$(bm::help::mode_alias balance-alb)" = "balance-alb" ]
  [ -z "$(bm::help::mode_alias banana)" ]
}

@test "suggest_command: by meaning first, then by spelling" {
  [ "$(bm::help::suggest_command move)" = "swap-member" ]
  [ "$(bm::help::suggest_command undo)" = "rollback" ]
  [ "$(bm::help::suggest_command statsu)" = "status" ]
  [ -z "$(bm::help::suggest_command frobnicate)" ]
}

@test "explain_reason: every health reason gets plain words and a next step" {
  local r out
  local -a reasons=(
    "bond device not present in kernel"
    "bond operstate is 'down'"
    "bond has no members"
    "member eth1 MII status is 'down'"
    "member speed mismatch (1000 vs 10000)"
    "member eth1 duplex is 'half'"
    "no member has link"
    "no LACP partner (switch side not aggregating?)"
    "LACP partner churn state is 'churned'"
  )
  for r in "${reasons[@]}"; do
    out="$(bm::help::explain_reason "$r")"
    [ "$(printf '%s\n' "$out" | wc -l)" -eq 2 ]
    [[ "$out" != "$r"* ]] || { echo "no explanation for: $r"; return 1; }
    assert_contains "$out" "What to do: "
    assert_not_contains "$out" "diagnose BOND"
  done
}

@test "explain_reason: the facts module has no reason this file does not know" {
  # bond_health's reasons are listed above; a new one must be added there
  # (and explained) — this count makes forgetting it fail loudly.
  [ "$(grep -c 'reasons+=(' "$BM_ROOT/lib/20-facts.sh")" -eq 7 ]
}

@test "explain_rc: every exit code and outcome has its own words" {
  local c
  for c in "0 committed" "0 dry-run" "0 cancelled" "0 noop" "2 x" "3 x" "4 x" \
    "5 x" "5 expired" "5 lost" "6 x" "130 x" "10 x" "11 x"; do
    bm::help::explain_rc ${c% *} "${c#* }" 0
    [[ "$BM_HELP_TITLE" != "Something went wrong"* ]] || { echo "generic text for $c"; return 1; }
  done
  bm::help::explain_rc 0 dry-run 1
  assert_contains "$BM_HELP_TITLE" "nothing was changed"
  bm::help::explain_rc 42 "" 0
  assert_contains "$BM_HELP_TITLE" "code 42"
}

@test "speed_label: human units" {
  [ "$(bm::help::speed_label 1000)" = "1G" ]
  [ "$(bm::help::speed_label 10000)" = "10G" ]
  [ "$(bm::help::speed_label 2500)" = "2.5G" ]
  [ "$(bm::help::speed_label 100)" = "100M" ]
  [ "$(bm::help::speed_label unknown)" = "-" ]
}
