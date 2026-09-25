#!/usr/bin/env bats
# End-to-end: list / show / status against fixtures, JSON output, legacy flags.

load ../helpers

setup() {
  setup_sandbox
}

@test "list (human): one line per bond with mode and health" {
  scenario_bond0_healthy
  scenario_bond1_8023ad
  run_cli list
  [ "$status" -eq 0 ]
  echo "$output" | grep -Eq '^bond0 +active-backup +healthy$'
  echo "$output" | grep -Eq '^bond1 +802\.3ad +healthy$'
}

@test "list (human): no bonds" {
  run_cli list
  [ "$status" -eq 0 ]
  [ "$output" = "No bonds found." ]
}

@test "list --json: valid JSON document with full bond inventory" {
  scenario_bond0_healthy
  scenario_bond1_8023ad_no_partner
  stub_nm_bond0_profile
  run_cli_stdout --json list
  [ "$status" -eq 0 ]
  assert_valid_json "$output"
  [ "$(printf '%s' "$output" | jq -r '.schema_version')" = "1" ]
  [ "$(printf '%s' "$output" | jq -r '.tool_version')" = "3.1.0" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds | length')" = "2" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds[] | select(.name=="bond0") | .health')" = "healthy" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds[] | select(.name=="bond0") | .mode')" = "active-backup" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds[] | select(.name=="bond0") | .members | length')" = "2" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds[] | select(.name=="bond0") | .members[0].name')" = "eth0" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds[] | select(.name=="bond0") | .members[0].mii')" = "up" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds[] | select(.name=="bond0") | .miimon')" = "100" ]
  [ "$(printf '%s' "$output" | jq -r '.bonds[] | select(.name=="bond1") | .health')" = "degraded" ]
  # the 802.3ad fixture has no partner AND reports churn in its per-port
  # sections; both must surface as distinct reasons
  printf '%s' "$output" | jq -e '.bonds[] | select(.name=="bond1") | .reasons | map(select(test("no LACP partner"))) | length == 1' >/dev/null
  printf '%s' "$output" | jq -e '.bonds[] | select(.name=="bond1") | .reasons | map(select(test("churn"))) | length == 1' >/dev/null
}

@test "show BOND (human): full detail" {
  scenario_bond0_healthy
  stub_ip_file addr_bond0 "bond0           UP             10.0.0.5/24"
  run_cli show bond0
  [ "$status" -eq 0 ]
  assert_contains "$output" "=== bond0 ==="
  assert_contains "$output" "mode:            active-backup"
  assert_contains "$output" "health:          healthy"
  assert_contains "$output" "active member:   eth0"
  assert_contains "$output" "miimon:          100 ms"
  echo "$output" | grep -Eq 'eth0 +mii=up +speed=1000 +duplex=full +link_failures=0'
  echo "$output" | grep -Eq 'eth1 +mii=up'
  assert_contains "$output" "10.0.0.5/24"
}

@test "show BOND --json: valid single-bond document" {
  scenario_bond0_degraded
  run_cli_stdout --json show bond0
  [ "$status" -eq 0 ]
  assert_valid_json "$output"
  [ "$(printf '%s' "$output" | jq -r '.bond.name')" = "bond0" ]
  [ "$(printf '%s' "$output" | jq -r '.bond.health')" = "degraded" ]
  [ "$(printf '%s' "$output" | jq -r '.bond.members[1].mii')" = "down" ]
  [ "$(printf '%s' "$output" | jq -r '.bond.members[1].link_failures')" = "3" ]
}

@test "show --json includes vlans discovered from NM profiles" {
  scenario_bond0_healthy
  stub_nm_bond0_profile
  stub_nm_conn 44444444-4444-4444-4444-444444444444 \
    connection.id=bond0.42 connection.type=vlan connection.interface-name=bond0.42 \
    vlan.parent=bond0 vlan.id=42
  run_cli_stdout --json show bond0
  [ "$status" -eq 0 ]
  assert_valid_json "$output"
  [ "$(printf '%s' "$output" | jq -r '.bond.vlans[0]')" = "bond0.42" ]
}

@test "status: healthy bond exits 0" {
  scenario_bond0_healthy
  run_cli status
  [ "$status" -eq 0 ]
  assert_contains "$output" "health:          healthy"
}

@test "status: degraded bond exits 10" {
  scenario_bond0_degraded
  run_cli status
  [ "$status" -eq 10 ]
  assert_contains "$output" "health:          degraded"
  assert_contains "$output" "member eth1 MII status is 'down'"
}

@test "status: down bond exits 11" {
  scenario_bond0_down
  run_cli status
  [ "$status" -eq 11 ]
  assert_contains "$output" "bond operstate is 'down'"
}

@test "status BOND: scopes the verdict to one bond" {
  scenario_bond0_healthy
  scenario_bond1_8023ad_no_partner
  run_cli status bond0
  [ "$status" -eq 0 ]
  run_cli status bond1
  [ "$status" -eq 10 ]
}

@test "status --json: document plus health exit code" {
  scenario_bond0_degraded
  run_cli_stdout --json status
  [ "$status" -eq 10 ]
  assert_valid_json "$output"
}

@test "status with no bonds: rc 0, friendly message" {
  run_cli status
  [ "$status" -eq 0 ]
  assert_contains "$output" "No bonds found."
}

# ---- v2.x compatibility ----------------------------------------------------

@test "legacy --status behaves like the status command (degraded rc 10)" {
  scenario_bond0_degraded
  run_cli --status
  [ "$status" -eq 10 ]
  assert_contains "$output" "health:          degraded"
}

@test "legacy --export-json PATH writes a valid JSON file" {
  scenario_bond0_healthy
  local out="$BM_TEST_SANDBOX/export/inventory.json"
  run_cli --export-json "$out"
  [ "$status" -eq 0 ]
  assert_contains "$output" "JSON written to $out"
  [ -f "$out" ]
  python3 -m json.tool "$out" >/dev/null
  [ "$(jq -r '.bonds[0].name' "$out")" = "bond0" ]
  [ "$(jq -r '.bonds[0].health' "$out")" = "healthy" ]
}

@test "legacy --status --export-json PATH does both and keeps the health exit code" {
  scenario_bond0_degraded
  local out="$BM_TEST_SANDBOX/inventory.json"
  run_cli --status --export-json "$out"
  # a monitoring caller must still learn the bond is degraded (10), not 0
  [ "$status" -eq 10 ]
  [ -f "$out" ]
  python3 -m json.tool "$out" >/dev/null
  assert_contains "$output" "health:          degraded"
}

@test "verify command re-runs the gate against kernel state" {
  scenario_bond0_healthy
  run_cli verify bond0
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond 'bond0' exists in kernel"
  assert_contains "$output" "mode is active-backup"
  assert_contains "$output" "member eth0 enslaved, MII up"
}
