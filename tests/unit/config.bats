#!/usr/bin/env bats
# bm::config::load — line-parsed (never sourced) config file handling.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "config: absent file leaves built-in defaults" {
  bm::config::load
  [ "$(bm::config::get DEFAULT_MIIMON)" = "100" ]
  [ "$(bm::config::get MAX_BACKUPS)" = "10" ]
  [ "$(bm::config::get ROLLBACK_WINDOW)" = "120" ]
}

@test "config: valid file overrides defaults (quotes stripped)" {
  cat >"$BM_CONF" <<'EOF'
# comment line
DEFAULT_MIIMON="250"
MAX_BACKUPS=5
LOGROTATE_FREQUENCY='daily'
DEFAULT_8023AD_LACP_RATE="slow"
ROLLBACK_WINDOW="300"   # trailing comment
EOF
  bm::config::load
  [ "$(bm::config::get DEFAULT_MIIMON)" = "250" ]
  [ "$(bm::config::get MAX_BACKUPS)" = "5" ]
  [ "$(bm::config::get LOGROTATE_FREQUENCY)" = "daily" ]
  [ "$(bm::config::get DEFAULT_8023AD_LACP_RATE)" = "slow" ]
  [ "$(bm::config::get ROLLBACK_WINDOW)" = "300" ]
}

@test "config: unknown keys are ignored with a warning" {
  printf 'TOTALLY_UNKNOWN_KEY="1"\nDEFAULT_MIIMON="222"\n' >"$BM_CONF"
  run bm::config::load
  [ "$status" -eq 0 ]
  assert_contains "$output" "ignoring unknown key 'TOTALLY_UNKNOWN_KEY'"
}

@test "config: invalid values are rejected, default kept" {
  cat >"$BM_CONF" <<'EOF'
DEFAULT_MIIMON="not-a-number"
LOGROTATE_FREQUENCY="hourly"
DEFAULT_8023AD_LACP_RATE="medium"
EOF
  bm::config::load
  [ "$(bm::config::get DEFAULT_MIIMON)" = "100" ]
  [ "$(bm::config::get LOGROTATE_FREQUENCY)" = "weekly" ]
  [ "$(bm::config::get DEFAULT_8023AD_LACP_RATE)" = "fast" ]
}

@test "config: malformed lines are reported and skipped" {
  cat >"$BM_CONF" <<'EOF'
this is not a key value line
lowercase=notallowed
DEFAULT_MIIMON="150"
EOF
  run bm::config::load
  [ "$status" -eq 0 ]
  assert_contains "$output" "ignoring malformed line"
}

@test "config: shell injection payload is never executed (unknown key)" {
  local pwned="$BM_TEST_SANDBOX/pwned"
  printf 'INJECT=$(touch %s)\n' "$pwned" >"$BM_CONF"
  run bm::config::load
  [ "$status" -eq 0 ]
  [ ! -e "$pwned" ]
  assert_contains "$output" "ignoring unknown key 'INJECT'"
}

@test "config: command substitution in a known key is inert data" {
  local pwned="$BM_TEST_SANDBOX/pwned2"
  # numeric key: value fails validation, and nothing runs either way
  printf 'DEFAULT_MIIMON=$(touch %s)\n' "$pwned" >"$BM_CONF"
  bm::config::load
  [ ! -e "$pwned" ]
  [ "$(bm::config::get DEFAULT_MIIMON)" = "100" ]
}

@test "config: backtick payload in pattern keys is rejected" {
  local pwned="$BM_TEST_SANDBOX/pwned3"
  printf 'NIC_ALLOWLIST_PATTERNS="`touch %s`"\n' "$pwned" >"$BM_CONF"
  run bm::config::load
  [ "$status" -eq 0 ]
  [ ! -e "$pwned" ]
  assert_contains "$output" "rejecting invalid value for 'NIC_ALLOWLIST_PATTERNS'"
}

@test "config: \$( ) payload in pattern keys is rejected, file untouched" {
  local pwned="$BM_TEST_SANDBOX/pwned4"
  printf 'NIC_BLOCKLIST_PATTERNS="$(touch %s)"\n' "$pwned" >"$BM_CONF"
  bm::config::load
  [ ! -e "$pwned" ]
  # default blocklist still in effect
  assert_contains "$(bm::config::get NIC_BLOCKLIST_PATTERNS)" "^veth.*"
}

@test "config: a benign pattern override IS applied" {
  printf 'NIC_ALLOWLIST_PATTERNS="^lab[0-9]+$"\n' >"$BM_CONF"
  bm::config::load
  [ "$(bm::config::get NIC_ALLOWLIST_PATTERNS)" = '^lab[0-9]+$' ]
}

@test "config: default_text round-trips through the parser cleanly" {
  bm::config::default_text >"$BM_CONF"
  run bm::config::load
  [ "$status" -eq 0 ]
  # a clean load prints no warnings at all
  [ -z "$output" ]
}
