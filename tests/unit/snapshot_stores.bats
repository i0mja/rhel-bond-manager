#!/usr/bin/env bats
# bm::snap::* — the second profile store (RHEL 8's ifcfg-rh directory), the
# failure path of a restore, and prune's protection rules. A snapshot that
# quietly skips the ifcfg store, or a restore that reports success after tar
# failed, leaves a host with no way back — so these are pinned hard.

load ../helpers

setup() {
  setup_sandbox
  load_artifact

  # RHEL 9+ keyfile store
  printf '[connection]\nid=bond0\ntype=bond\n' >"$BM_CONN_DIR/bond0.nmconnection"

  # RHEL 8 ifcfg store: four files NetworkManager owns...
  printf 'DEVICE=bond0\nBONDING_OPTS="mode=active-backup miimon=100"\nONBOOT=yes\n' \
    >"$BM_IFCFG_DIR/ifcfg-bond0"
  printf 'DEVICE=eth0\nMASTER=bond0\nSLAVE=yes\nONBOOT=yes\n' >"$BM_IFCFG_DIR/ifcfg-eth0"
  printf '10.20.0.0/16 via 10.0.0.254 dev bond0\n' >"$BM_IFCFG_DIR/route-bond0"
  printf 'IEEE_8021X_PASSWORD=hunter2\n' >"$BM_IFCFG_DIR/keys-bond0"
  # ...and two that it does not: the legacy network-scripts helpers, which
  # share the directory and must never be archived, deleted or reverted.
  printf '#!/bin/bash\n# legacy ifup helper\n' >"$BM_IFCFG_DIR/ifup-eth"
  printf '# shared shell functions\n' >"$BM_IFCFG_DIR/network-functions"
}

archived_ifcfg() { # sorted member list of the ifcfg archive
  tar -tzf "$BM_BACKUP_DIR/conn-$1.ifcfg.tar.gz" | LC_ALL=C sort | tr '\n' ' '
}

# ---- ifcfg coverage --------------------------------------------------------

@test "create: archives the ifcfg store alongside the keyfile store" {
  require_root
  local id
  id="$(bm::snap::create both-stores 2>/dev/null)"
  [ -f "$BM_BACKUP_DIR/conn-$id.tar.gz" ]
  [ -f "$BM_BACKUP_DIR/conn-$id.ifcfg.tar.gz" ]
  [ "$(archived_ifcfg "$id")" = "ifcfg-bond0 ifcfg-eth0 keys-bond0 route-bond0 " ]
}

@test "create: only NetworkManager's ifcfg patterns are archived" {
  require_root
  local id out
  id="$(bm::snap::create patterns 2>/dev/null)"
  out="$(archived_ifcfg "$id")"
  assert_not_contains "$out" "network-functions"
  assert_not_contains "$out" "ifup-eth"
}

@test "create: the manifest records ifcfg files with checksums and the store path" {
  require_root
  local id m
  id="$(bm::snap::create manifested 2>/dev/null)"
  m="$BM_BACKUP_DIR/conn-$id.manifest"
  grep -q "ifcfg_dir=$BM_IFCFG_DIR" "$m"
  grep -Eq "^ifcfg_file=[0-9a-f]{64}	ifcfg-bond0$" "$m"
  grep -Eq "^ifcfg_file=[0-9a-f]{64}	keys-bond0$" "$m"
  grep -Eq "^file=[0-9a-f]{64}	bond0.nmconnection$" "$m"
  # the legacy helpers are not recorded either
  run grep -c 'network-functions' "$m"
  [ "$output" = "0" ]
}

@test "create: an empty ifcfg store produces no companion archive" {
  require_root
  rm -f "$BM_IFCFG_DIR"/*
  local id
  id="$(bm::snap::create keyfile-only 2>/dev/null)"
  [ -f "$BM_BACKUP_DIR/conn-$id.tar.gz" ]
  [ ! -e "$BM_BACKUP_DIR/conn-$id.ifcfg.tar.gz" ]
}

@test "stray_ifcfg_files: an ifcfg profile created after the snapshot is reported" {
  require_root
  local id
  id="$(bm::snap::create base 2>/dev/null)"
  run bm::snap::stray_ifcfg_files "$id"
  [ -z "$output" ]
  printf 'DEVICE=bond9\n' >"$BM_IFCFG_DIR/ifcfg-bond9"
  printf 'ONBOOT=no\n' >"$BM_IFCFG_DIR/ifup-post"    # not NM's: not a stray
  run bm::snap::stray_ifcfg_files "$id"
  [ "$output" = "ifcfg-bond9" ]
}

@test "diff: lists ifcfg profiles that a restore would delete" {
  require_root
  local id
  id="$(bm::snap::create base 2>/dev/null)"
  printf 'DEVICE=bond9\n' >"$BM_IFCFG_DIR/ifcfg-bond9"
  run bm::snap::diff "$id"
  assert_contains "$output" "ifcfg profiles created since snapshot"
  assert_contains "$output" "+ ifcfg-bond9"
}

@test "restore: reverts ifcfg profiles, deletes ifcfg strays, spares foreign files" {
  require_root
  local id
  id="$(bm::snap::create base 2>/dev/null)"

  # the world moves on after the snapshot
  printf 'DEVICE=bond9\nONBOOT=yes\n' >"$BM_IFCFG_DIR/ifcfg-bond9"     # created
  printf 'DEVICE=bond0\nONBOOT=no\n' >"$BM_IFCFG_DIR/ifcfg-bond0"      # edited
  rm -f "$BM_IFCFG_DIR/route-bond0"                                     # deleted
  printf '# local edit\n' >>"$BM_IFCFG_DIR/network-functions"           # not ours

  run bm::snap::restore "$id"
  [ "$status" -eq 0 ]

  [ ! -e "$BM_IFCFG_DIR/ifcfg-bond9" ]                     # stray removed
  grep -q 'ONBOOT=yes' "$BM_IFCFG_DIR/ifcfg-bond0"         # edit reverted
  grep -q 'BONDING_OPTS' "$BM_IFCFG_DIR/ifcfg-bond0"
  [ -f "$BM_IFCFG_DIR/route-bond0" ]                       # deletion undone
  [ -f "$BM_IFCFG_DIR/keys-bond0" ]
  # the legacy helper keeps the local edit — bond-manager never touches it
  grep -q '# local edit' "$BM_IFCFG_DIR/network-functions"
  [ -f "$BM_IFCFG_DIR/ifup-eth" ]
}

@test "restore: dry-run writes nothing in either store" {
  require_root
  local id
  id="$(bm::snap::create base 2>/dev/null)"
  local before
  before="$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR")"
  printf 'DEVICE=bond9\n' >"$BM_IFCFG_DIR/ifcfg-bond9"
  BM_DRY_RUN=1
  run bm::snap::restore "$id"
  [ "$status" -eq 0 ]
  [ -e "$BM_IFCFG_DIR/ifcfg-bond9" ]              # stray still there
  rm -f "$BM_IFCFG_DIR/ifcfg-bond9"
  [ "$(tree_state "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR")" = "$before" ]
}

# ---- restore failures ------------------------------------------------------

@test "restore: a corrupt keyfile archive fails loudly and names the fallback" {
  require_root
  local id
  id="$(bm::snap::create base 2>/dev/null)"
  printf 'this is not a gzip stream' >"$BM_BACKUP_DIR/conn-$id.tar.gz"

  run bm::snap::restore "$id"
  [ "$status" -ne 0 ]
  assert_contains "$output" "restore FAILED"
  # the operator is told which snapshot holds the state from before the attempt
  [[ "$output" =~ before\ this\ attempt\ is\ snapshot\ ([0-9a-zA-Z-]+) ]]
  local pre="${BASH_REMATCH[1]}"
  [ -f "$BM_BACKUP_DIR/conn-$pre.tar.gz" ]
  assert_not_contains "$output" "restored snapshot $id"
}

@test "restore: a corrupt ifcfg archive fails loudly too" {
  require_root
  local id
  id="$(bm::snap::create base 2>/dev/null)"
  printf 'garbage' >"$BM_BACKUP_DIR/conn-$id.ifcfg.tar.gz"

  run bm::snap::restore "$id"
  [ "$status" -ne 0 ]
  assert_contains "$output" "restore FAILED"
  assert_contains "$output" "ifcfg"
  assert_not_contains "$output" "restored snapshot $id"
}

# ---- prune protection ------------------------------------------------------

# Three snapshots with unambiguous mtimes: oldest .. newest.
three_snapshots() {
  SNAP1="$(bm::snap::create one 2>/dev/null)"
  SNAP2="$(bm::snap::create two 2>/dev/null)"
  SNAP3="$(bm::snap::create three 2>/dev/null)"
  touch -d '2020-01-01 00:00:01' "$BM_BACKUP_DIR/conn-$SNAP1.tar.gz"
  touch -d '2020-01-01 00:00:02' "$BM_BACKUP_DIR/conn-$SNAP2.tar.gz"
  touch -d '2020-01-01 00:00:03' "$BM_BACKUP_DIR/conn-$SNAP3.tar.gz"
}

@test "prune: never deletes the snapshot a pending change would roll back to" {
  require_root
  bm::config::set MAX_BACKUPS 1
  three_snapshots
  seed_pending checkpoint "$SNAP1" "pending change protecting the oldest snapshot"

  bm::snap::prune

  # protected, even though it is the oldest and MAX_BACKUPS is 1
  [ -e "$BM_BACKUP_DIR/conn-$SNAP1.tar.gz" ]
  [ -e "$BM_BACKUP_DIR/conn-$SNAP1.manifest" ]
  # protection does not consume the budget: the newest is still kept
  [ -e "$BM_BACKUP_DIR/conn-$SNAP3.tar.gz" ]
  # the unreferenced middle one is the one that goes
  [ ! -e "$BM_BACKUP_DIR/conn-$SNAP2.tar.gz" ]
  [ ! -e "$BM_BACKUP_DIR/conn-$SNAP2.manifest" ]
  [ ! -e "$BM_BACKUP_DIR/conn-$SNAP2.ifcfg.tar.gz" ]
}

@test "prune: BM_SNAP_PROTECT_ID and explicit arguments are honored" {
  require_root
  bm::config::set MAX_BACKUPS 1
  three_snapshots
  BM_SNAP_PROTECT_ID="$SNAP2"
  bm::snap::prune "$SNAP1"
  [ -e "$BM_BACKUP_DIR/conn-$SNAP1.tar.gz" ]
  [ -e "$BM_BACKUP_DIR/conn-$SNAP2.tar.gz" ]
  [ -e "$BM_BACKUP_DIR/conn-$SNAP3.tar.gz" ]
}

@test "prune: with nothing protected the budget is enforced strictly" {
  require_root
  bm::config::set MAX_BACKUPS 1
  three_snapshots
  bm::snap::prune
  [ ! -e "$BM_BACKUP_DIR/conn-$SNAP1.tar.gz" ]
  [ ! -e "$BM_BACKUP_DIR/conn-$SNAP2.tar.gz" ]
  [ -e "$BM_BACKUP_DIR/conn-$SNAP3.tar.gz" ]
}

@test "create: pruning during a snapshot cannot delete the snapshot being read" {
  require_root
  bm::config::set MAX_BACKUPS 1
  three_snapshots
  seed_pending checkpoint "$SNAP3" "pending"
  # a restore takes a pre-restore snapshot, which prunes; the snapshot it is
  # about to extract must survive that
  run bm::snap::restore "$SNAP1"
  [ "$status" -eq 0 ]
  [ -e "$BM_BACKUP_DIR/conn-$SNAP1.tar.gz" ]
}
