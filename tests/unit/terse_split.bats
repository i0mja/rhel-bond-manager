#!/usr/bin/env bats
# bm::nm::terse_split — escape-aware splitting of `nmcli -t` output.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "terse_split: plain fields" {
  bm::nm::terse_split "uuid-1:bond0:bond:bond0"
  [ "${#BM_FIELDS[@]}" -eq 4 ]
  [ "${BM_FIELDS[0]}" = "uuid-1" ]
  [ "${BM_FIELDS[1]}" = "bond0" ]
  [ "${BM_FIELDS[2]}" = "bond" ]
  [ "${BM_FIELDS[3]}" = "bond0" ]
}

@test "terse_split: escaped colon stays inside a field" {
  bm::nm::terse_split 'name\:with\:colons:uuid-2'
  [ "${#BM_FIELDS[@]}" -eq 2 ]
  [ "${BM_FIELDS[0]}" = "name:with:colons" ]
  [ "${BM_FIELDS[1]}" = "uuid-2" ]
}

@test "terse_split: escaped backslash decodes to one backslash" {
  bm::nm::terse_split 'back\\slash:x'
  [ "${#BM_FIELDS[@]}" -eq 2 ]
  [ "${BM_FIELDS[0]}" = 'back\slash' ]
  [ "${BM_FIELDS[1]}" = "x" ]
}

@test "terse_split: backslash-then-colon combinations round-trip" {
  # raw value:  a\:b\c   — nmcli would emit  a\\\:b\\c
  local raw='a\:b\c'
  local escaped
  escaped="${raw//\\/\\\\}"     # '\' -> '\\'
  escaped="${escaped//:/\\:}"   # ':' -> '\:'
  bm::nm::terse_split "${escaped}:second"
  [ "${#BM_FIELDS[@]}" -eq 2 ]
  [ "${BM_FIELDS[0]}" = "$raw" ]
  [ "${BM_FIELDS[1]}" = "second" ]
}

@test "terse_split: empty fields are preserved" {
  bm::nm::terse_split "a::c:"
  [ "${#BM_FIELDS[@]}" -eq 4 ]
  [ "${BM_FIELDS[0]}" = "a" ]
  [ "${BM_FIELDS[1]}" = "" ]
  [ "${BM_FIELDS[2]}" = "c" ]
  [ "${BM_FIELDS[3]}" = "" ]
}

@test "terse_split: single field without separators" {
  bm::nm::terse_split "lonely"
  [ "${#BM_FIELDS[@]}" -eq 1 ]
  [ "${BM_FIELDS[0]}" = "lonely" ]
}

@test "terse_split: round-trips the nmcli stub's own escaping" {
  # end-to-end: a profile name containing ':' and '\' survives listing + split
  stub_nm_conn aaaaaaaa-0000-0000-0000-000000000001 \
    'connection.id=vlan: uplink\prod' connection.type=vlan \
    connection.interface-name=bond0.10
  local line
  line="$(nmcli -t -f connection.id,connection.type connection show)"
  bm::nm::terse_split "$line"
  [ "${BM_FIELDS[0]}" = 'vlan: uplink\prod' ]
  [ "${BM_FIELDS[1]}" = "vlan" ]
}
