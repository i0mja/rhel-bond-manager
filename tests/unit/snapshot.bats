#!/usr/bin/env bats
# bm::snap::* — snapshot create/manifest/stray-file/restore logic against a
# temp BM_CONN_DIR + BM_BACKUP_DIR.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
  # seed connection profiles
  printf '[connection]\nid=bond0\ntype=bond\n' >"$BM_CONN_DIR/bond0.nmconnection"
  printf '[connection]\nid=bond-port-eth0\n'   >"$BM_CONN_DIR/bond-port-eth0.nmconnection"
}

@test "snapshot create: writes archive + manifest listing every file" {
  require_root
  local id
  id="$(bm::snap::create test-reason 2>/dev/null)"
  [ -n "$id" ]
  [ -f "$BM_BACKUP_DIR/conn-$id.tar.gz" ]
  [ -f "$BM_BACKUP_DIR/conn-$id.manifest" ]
  run cat "$BM_BACKUP_DIR/conn-$id.manifest"
  assert_contains "$output" "id=$id"
  assert_contains "$output" "reason=test-reason"
  assert_contains "$output" "bond0.nmconnection"
  assert_contains "$output" "bond-port-eth0.nmconnection"
  # manifest records sha256 sums
  grep -Eq "^file=[0-9a-f]{64}	bond0.nmconnection$" "$BM_BACKUP_DIR/conn-$id.manifest"
}

@test "snapshot list/latest: shows id, created, reason" {
  require_root
  local id
  id="$(bm::snap::create listing 2>/dev/null)"
  run bm::snap::list
  assert_contains "$output" "$id"
  assert_contains "$output" "listing"
  [ "$(bm::snap::latest)" = "$id" ]
}

@test "stray_files: file created after the snapshot is listed" {
  require_root
  local id
  id="$(bm::snap::create base 2>/dev/null)"
  run bm::snap::stray_files "$id"
  [ -z "$output" ]
  printf 'stray\n' >"$BM_CONN_DIR/bond9.nmconnection"
  run bm::snap::stray_files "$id"
  [ "$output" = "bond9.nmconnection" ]
}

@test "snapshot diff: reports created and modified profiles" {
  require_root
  local id
  id="$(bm::snap::create base 2>/dev/null)"
  printf 'stray\n' >"$BM_CONN_DIR/bond9.nmconnection"
  printf 'changed\n' >>"$BM_CONN_DIR/bond0.nmconnection"
  run bm::snap::diff "$id"
  assert_contains "$output" "+ bond9.nmconnection"
  assert_contains "$output" "~ bond0.nmconnection"
}

@test "restore: deletes stray files and restores original content" {
  require_root
  local orig
  orig="$(cat "$BM_CONN_DIR/bond0.nmconnection")"
  local id
  id="$(bm::snap::create base 2>/dev/null)"

  # mutate the world after the snapshot
  printf 'stray profile\n' >"$BM_CONN_DIR/bond9.nmconnection"
  printf 'tampered\n' >"$BM_CONN_DIR/bond0.nmconnection"

  run bm::snap::restore "$id"
  [ "$status" -eq 0 ]

  [ ! -e "$BM_CONN_DIR/bond9.nmconnection" ]                    # stray removed
  [ "$(cat "$BM_CONN_DIR/bond0.nmconnection")" = "$orig" ]      # content back
  [ -e "$BM_CONN_DIR/bond-port-eth0.nmconnection" ]
  # NetworkManager was told to reload, via the nmcli stub
  grep -q "nmcli connection reload" "$BM_TEST_CALLS"
  # the restore is itself undoable: a pre-restore snapshot exists
  run bm::snap::list
  assert_contains "$output" "pre-restore-of-$id"
}

@test "restore: unknown snapshot dies with precondition rc=3" {
  require_root
  run bm::snap::restore 19700101-000000
  [ "$status" -eq 3 ]
  assert_contains "$output" "not found"
}

@test "restore honors dry-run: nothing deleted, nothing extracted" {
  require_root
  local id
  id="$(bm::snap::create base 2>/dev/null)"
  printf 'stray\n' >"$BM_CONN_DIR/bond9.nmconnection"
  printf 'tampered\n' >"$BM_CONN_DIR/bond0.nmconnection"
  BM_DRY_RUN=1
  run bm::snap::restore "$id"
  [ "$status" -eq 0 ]
  [ -e "$BM_CONN_DIR/bond9.nmconnection" ]
  [ "$(cat "$BM_CONN_DIR/bond0.nmconnection")" = "tampered" ]
}

@test "prune: keeps only MAX_BACKUPS newest archives" {
  require_root
  bm::config::set MAX_BACKUPS 2
  local id1 id2 id3
  id1="$(bm::snap::create one 2>/dev/null)"
  id2="$(bm::snap::create two 2>/dev/null)"
  id3="$(bm::snap::create three 2>/dev/null)"
  # force unambiguous mtime ordering (ids can share the same second)
  touch -d '2020-01-01 00:00:01' "$BM_BACKUP_DIR/conn-$id1.tar.gz"
  touch -d '2020-01-01 00:00:02' "$BM_BACKUP_DIR/conn-$id2.tar.gz"
  touch -d '2020-01-01 00:00:03' "$BM_BACKUP_DIR/conn-$id3.tar.gz"
  bm::snap::prune
  [ ! -e "$BM_BACKUP_DIR/conn-$id1.tar.gz" ]
  [ ! -e "$BM_BACKUP_DIR/conn-$id1.manifest" ]
  [ -e "$BM_BACKUP_DIR/conn-$id2.tar.gz" ]
  [ -e "$BM_BACKUP_DIR/conn-$id3.tar.gz" ]
}

@test "legacy archive without manifest is listed as legacy" {
  require_root
  tar -C "$BM_CONN_DIR" -czf "$BM_BACKUP_DIR/conn-20200101-010101.tar.gz" .
  run bm::snap::list
  assert_contains "$output" "20200101-010101"
  assert_contains "$output" "legacy"
}
