#!/usr/bin/env bats
# bm::facts::* — the two read-only facts the safety engine leans on:
# which device carries this SSH session (the egress guard), and the LACP
# churn state (health verdicts). Both are recovered from awkward sources:
# sudo strips SSH_CONNECTION, and the kernel prints churn per port.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

# ---- SSH egress detection --------------------------------------------------

@test "ssh_egress_dev: SSH_CONNECTION names the peer, routing names the device" {
  stub_ip_file route_get "10.1.2.3 via 10.0.0.1 dev bond0 src 10.0.0.5 uid 0" "    cache"
  export SSH_CONNECTION="10.1.2.3 54321 10.0.0.5 22"
  [ "$(bm::facts::ssh_egress_dev)" = "bond0" ]
  assert_called '^ip route get 10.1.2.3$'
}

@test "ssh_egress_dev: falls back to SSH_CLIENT when sudo stripped SSH_CONNECTION" {
  # sudo's default env_reset keeps SSH_CLIENT on many configurations while
  # dropping SSH_CONNECTION; concluding "not over SSH" there would silently
  # disable the guard for the exact operators it protects.
  stub_ip_file route_get "10.9.9.9 via 10.0.0.1 dev bond0.120 src 10.0.0.5 uid 0"
  unset SSH_CONNECTION
  export SSH_CLIENT="10.9.9.9 54321 22"
  [ "$(bm::facts::ssh_egress_dev)" = "bond0.120" ]
  assert_called '^ip route get 10.9.9.9$'
}

@test "ssh_egress_dev: SSH_CONNECTION wins over SSH_CLIENT" {
  stub_ip_file route_get "x via y dev bond0 src z"
  export SSH_CONNECTION="10.1.2.3 54321 10.0.0.5 22"
  export SSH_CLIENT="10.9.9.9 54321 22"
  bm::facts::ssh_egress_dev >/dev/null
  assert_called '^ip route get 10.1.2.3$'
  assert_not_called '^ip route get 10.9.9.9$'
}

@test "ssh_egress_dev: last resort is the who(1) record for our terminal" {
  stub_ip_file route_get "10.4.4.4 via 10.0.0.1 dev bond0 src 10.0.0.5"
  export BM_STUB_PS_TTY="pts/9"
  export BM_STUB_WHO_LINES="root     pts/9        2026-08-25 10:00 (10.4.4.4)"
  [ "$(bm::facts::ssh_egress_dev)" = "bond0" ]
  assert_called '^ip route get 10.4.4.4$'
}

@test "ssh_egress_dev: a who record for a different tty is ignored" {
  stub_ip_file route_get "10.4.4.4 via 10.0.0.1 dev bond0 src 10.0.0.5"
  export BM_STUB_PS_TTY="pts/9"
  export BM_STUB_WHO_LINES="root     pts/1        2026-08-25 10:00 (10.4.4.4)"
  [ -z "$(bm::facts::ssh_egress_dev)" ]
  assert_not_called '^ip route get'
}

@test "ssh_egress_dev: a hostname in the who record is not fed to ip route get" {
  stub_ip_file route_get "unused dev bond0"
  export BM_STUB_PS_TTY="pts/9"
  export BM_STUB_WHO_LINES="root     pts/9        2026-08-25 10:00 (workstation.example.com)"
  [ -z "$(bm::facts::ssh_egress_dev)" ]
  assert_not_called '^ip route get'
}

@test "ssh_egress_dev: a local console session has no egress device" {
  export BM_STUB_WHO_LINES=""
  [ -z "$(bm::facts::ssh_egress_dev)" ]
}

@test "ssh_egress_dev: a peer with no route yields nothing (guard stays quiet)" {
  export SSH_CONNECTION="10.1.2.3 54321 10.0.0.5 22"
  [ -z "$(bm::facts::ssh_egress_dev)" ]   # no route_get fixture => no output
}

@test "route_dev_for: picks the dev field out of an ip route get line" {
  stub_ip_file route_get "10.1.2.3 via 10.0.0.1 dev bond0.4000 src 10.0.0.5 uid 0" "    cache"
  [ "$(bm::facts::route_dev_for 10.1.2.3)" = "bond0.4000" ]
}

# ---- LACP churn ------------------------------------------------------------

@test "bond_lacp_info: churn state comes from the per-port sections" {
  # The bond-level '802.3ad info' block ends where the first port section
  # begins, so churn can only be read from the port sections themselves.
  scenario_bond1_8023ad
  install_proc_bond proc_bonding_8023ad_churned bond1
  run bm::facts::bond_lacp_info bond1
  [ "$status" -eq 0 ]
  assert_contains "$output" "aggregator_id 1"
  assert_contains "$output" "partner_mac 02:aa:bb:cc:dd:01"
  assert_contains "$output" "actor_churn churned"
  assert_contains "$output" "partner_churn churned"
}

@test "bond_lacp_info: a settled aggregation reports churn state none" {
  scenario_bond1_8023ad
  run bm::facts::bond_lacp_info bond1
  assert_contains "$output" "actor_churn none"
  assert_contains "$output" "partner_churn none"
}

@test "health: churn degrades a bond that otherwise has a healthy partner" {
  # isolates churn from the 'no LACP partner' reason: the partner MAC is real
  scenario_bond1_8023ad
  install_proc_bond proc_bonding_8023ad_churned bond1
  run bm::facts::bond_health bond1
  [ "${lines[0]}" = "degraded" ]
  assert_contains "$output" "LACP partner churn state is 'churned'"
  assert_not_contains "$output" "no LACP partner"
}

@test "health: 802.3ad without churn stays healthy" {
  scenario_bond1_8023ad
  run bm::facts::bond_health bond1
  [ "${lines[0]}" = "healthy" ]
  assert_not_contains "$output" "churn"
}
