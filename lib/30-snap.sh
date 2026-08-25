# lib/30-snap.sh — connection-profile snapshots with manifests, and a
# reconciling restore: profiles created after the snapshot are deleted (with
# confirmation) so restoring actually undoes creates, not just edits.
#
# Two profile stores are covered, because NetworkManager's default storage
# differs across the supported releases:
#   - keyfile: $BM_CONN_DIR (/etc/NetworkManager/system-connections) — RHEL 9+
#   - ifcfg:   $BM_IFCFG_DIR (/etc/sysconfig/network-scripts) — RHEL 8's
#     ifcfg-rh plugin, where nmcli writes ifcfg-*/keys-*/route-*/rule-* files
# A snapshot without the ifcfg store would silently fail to protect a RHEL 8
# host. Only NetworkManager's own file patterns are touched there — never the
# legacy scripts that share the directory.
# shellcheck shell=bash
[[ -n "${BM_LIB_SNAP:-}" ]] && return 0
BM_LIB_SNAP=1

# Snapshot ids that prune must never delete (the pending change's snapshot,
# and the snapshot a restore is currently reading).
BM_SNAP_PROTECT_ID=""

bm::snap::_dir() { printf '%s' "$BM_BACKUP_DIR"; }

bm::snap::path() { # path <id> -> keyfile archive path
  printf '%s/conn-%s.tar.gz' "$(bm::snap::_dir)" "$1"
}
bm::snap::ifcfg_path() { # path <id> -> ifcfg archive path
  printf '%s/conn-%s.ifcfg.tar.gz' "$(bm::snap::_dir)" "$1"
}
bm::snap::manifest_path() {
  printf '%s/conn-%s.manifest' "$(bm::snap::_dir)" "$1"
}

bm::snap::exists() { [[ -f "$(bm::snap::path "$1")" ]]; }

# ifcfg files NetworkManager owns. Everything else in that directory (the
# legacy ifup/ifdown helpers on RHEL 8) is deliberately left alone.
bm::snap::_ifcfg_files() {
  [[ -d "$BM_IFCFG_DIR" ]] || return 0
  (cd "$BM_IFCFG_DIR" 2>/dev/null &&
    find . -maxdepth 1 -type f \
      \( -name 'ifcfg-*' -o -name 'keys-*' -o -name 'route-*' -o -name 'route6-*' -o -name 'rule-*' -o -name 'rule6-*' \) \
      -printf '%P\n' | LC_ALL=C sort)
}

bm::snap::_keyfile_files() {
  [[ -d "$BM_CONN_DIR" ]] || return 0
  (cd "$BM_CONN_DIR" 2>/dev/null && find . -type f -printf '%P\n' | LC_ALL=C sort)
}

# Create a snapshot; echoes the snapshot id.
bm::snap::create() { # create [reason]
  local reason="${1:-manual}"
  bm::core::require_root
  mkdir -p "$(bm::snap::_dir)"
  chmod 0750 "$(bm::snap::_dir)" 2>/dev/null || true
  local id
  id="$(date +'%Y%m%d-%H%M%S')"
  # avoid collisions within the same second
  while bm::snap::exists "$id"; do id="${id}x"; done
  local archive ifcfg_archive manifest
  archive="$(bm::snap::path "$id")"
  ifcfg_archive="$(bm::snap::ifcfg_path "$id")"
  manifest="$(bm::snap::manifest_path "$id")"

  local -a ifcfg_files=()
  mapfile -t ifcfg_files < <(bm::snap::_ifcfg_files)

  {
    printf '# bond-manager snapshot manifest\n'
    printf 'id=%s\n' "$id"
    printf 'version=%s\n' "$BM_VERSION"
    printf 'created=%s\n' "$(bm::core::timestamp)"
    printf 'host=%s\n' "$(hostname 2>/dev/null || echo unknown)"
    printf 'reason=%s\n' "$reason"
    printf 'keyfile_dir=%s\n' "$BM_CONN_DIR"
    printf 'ifcfg_dir=%s\n' "$BM_IFCFG_DIR"
    local f
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      printf 'file=%s\t%s\n' "$(sha256sum "$BM_CONN_DIR/$f" 2>/dev/null | awk '{print $1}')" "$f"
    done < <(bm::snap::_keyfile_files)
    for f in "${ifcfg_files[@]}"; do
      [[ -n "$f" ]] || continue
      printf 'ifcfg_file=%s\t%s\n' "$(sha256sum "$BM_IFCFG_DIR/$f" 2>/dev/null | awk '{print $1}')" "$f"
    done
  } >"$manifest"
  chmod 0640 "$manifest"

  if ! tar -C "$BM_CONN_DIR" -czf "$archive" . 2>/dev/null; then
    rm -f "$archive" "$ifcfg_archive" "$manifest"
    bm::log::error "snapshot archive creation failed for $BM_CONN_DIR"
    return 1
  fi
  chmod 0640 "$archive"

  if (( ${#ifcfg_files[@]} > 0 )); then
    if ! tar -C "$BM_IFCFG_DIR" -czf "$ifcfg_archive" "${ifcfg_files[@]}" 2>/dev/null; then
      rm -f "$archive" "$ifcfg_archive" "$manifest"
      bm::log::error "snapshot archive creation failed for $BM_IFCFG_DIR"
      return 1
    fi
    chmod 0640 "$ifcfg_archive"
    bm::log::info "snapshot $id includes ${#ifcfg_files[@]} ifcfg profile file(s)"
  fi

  bm::log::info "snapshot $id created ($archive) reason=$reason"
  bm::snap::prune "$id"
  printf '%s\n' "$id"
}

bm::snap::list() { # newest first: "id  created  reason"
  local m id created reason line
  for m in $(ls -1t "$(bm::snap::_dir)"/conn-*.manifest 2>/dev/null || true); do
    id="" created="" reason=""
    while IFS= read -r line; do
      case "$line" in
        id=*) id="${line#id=}" ;;
        created=*) created="${line#created=}" ;;
        reason=*) reason="${line#reason=}" ;;
      esac
    done <"$m"
    [[ -n "$id" ]] && printf '%s\t%s\t%s\n' "$id" "$created" "$reason"
  done
  # archives from v2.x have no manifest; list them too
  local a
  for a in "$(bm::snap::_dir)"/conn-*.tar.gz; do
    [[ -e "$a" ]] || continue
    id="$(basename "$a")"
    id="${id#conn-}"
    id="${id%.tar.gz}"
    [[ "$id" == *.ifcfg ]] && continue
    [[ -f "$(bm::snap::manifest_path "$id")" ]] && continue
    printf '%s\t%s\t%s\n' "$id" "(no manifest)" "legacy"
  done
}

bm::snap::latest() {
  bm::snap::list | head -n1 | awk -F'\t' '{print $1}'
}

bm::snap::_manifest_files() { # keyfile paths recorded in a manifest
  local id="$1"
  awk -F'\t' '/^file=/ { print $2 }' "$(bm::snap::manifest_path "$id")" 2>/dev/null
}

bm::snap::_manifest_ifcfg_files() { # ifcfg paths recorded in a manifest
  local id="$1"
  awk -F'\t' '/^ifcfg_file=/ { print $2 }' "$(bm::snap::manifest_path "$id")" 2>/dev/null
}

bm::snap::_current_files() { bm::snap::_keyfile_files; }

# Files present now but absent from the snapshot (i.e. created after it).
bm::snap::stray_files() { # stray_files <id>
  local id="$1"
  [[ -f "$(bm::snap::manifest_path "$id")" ]] || return 0
  comm -23 <(bm::snap::_current_files) <(bm::snap::_manifest_files "$id" | LC_ALL=C sort)
}

bm::snap::stray_ifcfg_files() { # stray_ifcfg_files <id>
  local id="$1"
  [[ -f "$(bm::snap::manifest_path "$id")" ]] || return 0
  comm -23 <(bm::snap::_ifcfg_files) <(bm::snap::_manifest_ifcfg_files "$id" | LC_ALL=C sort)
}

bm::snap::diff() { # human summary of snapshot vs current state
  local id="$1"
  bm::snap::exists "$id" || bm::core::die "snapshot '$id' not found" "$BM_EX_PRECONDITION"
  if [[ ! -f "$(bm::snap::manifest_path "$id")" ]]; then
    echo "(legacy snapshot without manifest: file-level diff unavailable)"
    return 0
  fi
  local added removed
  added="$(bm::snap::stray_files "$id")"
  removed="$(comm -13 <(bm::snap::_current_files) <(bm::snap::_manifest_files "$id" | LC_ALL=C sort))"
  local changed="" f sum cur
  while IFS=$'\t' read -r sum f; do
    [[ -n "$f" && -f "$BM_CONN_DIR/$f" ]] || continue
    cur="$(sha256sum "$BM_CONN_DIR/$f" 2>/dev/null | awk '{print $1}')"
    [[ -n "$sum" && "$cur" != "$sum" ]] && changed+="$f"$'\n'
  done < <(awk -F'\t' '/^file=/ { sub(/^file=/, "", $1); print $1 "\t" $2 }' "$(bm::snap::manifest_path "$id")")

  local ifcfg_added
  ifcfg_added="$(bm::snap::stray_ifcfg_files "$id")"

  local any=0
  if [[ -n "$added" ]]; then
    any=1
    echo "Profiles created since snapshot (would be DELETED on restore):"
    sed 's/^/  + /' <<<"$added"
  fi
  if [[ -n "$ifcfg_added" ]]; then
    any=1
    echo "ifcfg profiles created since snapshot (would be DELETED on restore):"
    sed 's/^/  + /' <<<"$ifcfg_added"
  fi
  if [[ -n "$removed" ]]; then
    any=1
    echo "Profiles removed since snapshot (would be recreated on restore):"
    sed 's/^/  - /' <<<"$removed"
  fi
  if [[ -n "$changed" ]]; then
    any=1
    echo "Profiles modified since snapshot (would be reverted on restore):"
    sed 's/^/  ~ /' <<<"${changed%$'\n'}"
  fi
  (( any )) || echo "No differences between snapshot $id and current profiles."
}

# Reconciling restore. Deletes stray profile files, takes a pre-restore
# snapshot, untars, restores SELinux contexts and reloads NetworkManager.
# Callers are responsible for showing bm::snap::stray_files and confirming
# with the operator BEFORE calling this (the UI layer sits above this module).
bm::snap::restore() { # restore <id>
  local id="$1"
  bm::core::require_root
  bm::snap::exists "$id" || bm::core::die "snapshot '$id' not found" "$BM_EX_PRECONDITION"

  # A dry-run must not write anything at all — check before the pre-restore
  # snapshot, which is itself a real write.
  if (( BM_DRY_RUN )); then
    bm::log::say "[dry-run] would restore snapshot $id into $BM_CONN_DIR (and $BM_IFCFG_DIR)"
    bm::snap::diff "$id" || true
    return 0
  fi

  local stray stray_ifcfg
  stray="$(bm::snap::stray_files "$id")"
  stray_ifcfg="$(bm::snap::stray_ifcfg_files "$id")"

  # the restore itself is undoable: snapshot current state first. Protect the
  # snapshot we are about to read so pruning cannot delete it underneath us.
  local prev_protect="$BM_SNAP_PROTECT_ID"
  BM_SNAP_PROTECT_ID="$id"
  local pre
  pre="$(bm::snap::create "pre-restore-of-$id")" || {
    BM_SNAP_PROTECT_ID="$prev_protect"
    bm::core::die "could not snapshot current state — refusing to restore" "$BM_EX_ERR"
  }
  BM_SNAP_PROTECT_ID="$prev_protect"
  bm::log::say "current state saved as snapshot $pre"

  local f
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    rm -f "$BM_CONN_DIR/$f"
    bm::log::info "restore: removed stray profile $f"
  done <<<"$stray"
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    rm -f "$BM_IFCFG_DIR/$f"
    bm::log::info "restore: removed stray ifcfg profile $f"
  done <<<"$stray_ifcfg"

  # An unchecked extraction here would report success after the strays are
  # already gone, leaving the host with fewer profiles than either state.
  if ! tar -C "$BM_CONN_DIR" -xzf "$(bm::snap::path "$id")"; then
    bm::log::error "restore: extracting $(bm::snap::path "$id") failed"
    bm::core::die "restore FAILED while extracting snapshot $id — profiles may be incomplete. The state from before this attempt is snapshot $pre." "$BM_EX_ERR"
  fi
  if [[ -f "$(bm::snap::ifcfg_path "$id")" ]]; then
    if ! tar -C "$BM_IFCFG_DIR" -xzf "$(bm::snap::ifcfg_path "$id")"; then
      bm::log::error "restore: extracting $(bm::snap::ifcfg_path "$id") failed"
      bm::core::die "restore FAILED while extracting ifcfg profiles of snapshot $id — profiles may be incomplete. The state from before this attempt is snapshot $pre." "$BM_EX_ERR"
    fi
  fi

  if bm::core::have_cmd restorecon; then
    restorecon -RF "$BM_CONN_DIR" 2>/dev/null || true
    [[ -d "$BM_IFCFG_DIR" ]] && restorecon -RF "$BM_IFCFG_DIR" 2>/dev/null || true
  fi
  bm::nm::reload
  bm::log::info "restored snapshot $id"
  bm::log::say "restored snapshot $id (previous state: snapshot $pre)"
}

# Delete snapshots beyond MAX_BACKUPS, oldest first. Snapshots referenced by
# a pending change (or named via BM_SNAP_PROTECT_ID / the extra arguments) are
# never deleted: pruning the snapshot a rollback depends on would destroy the
# only way back.
bm::snap::prune() { # prune [protected-id...]
  local keep
  keep="$(bm::config::get MAX_BACKUPS)"
  [[ "$keep" =~ ^[0-9]+$ ]] || keep=10
  local -a protected=("$@")
  [[ -n "$BM_SNAP_PROTECT_ID" ]] && protected+=("$BM_SNAP_PROTECT_ID")
  local pending
  pending="$(bm::snap::_pending_snapshot_id)"
  [[ -n "$pending" ]] && protected+=("$pending")

  # newest first, excluding the companion ifcfg archives
  local -a archives=()
  mapfile -t archives < <(
    local a
    for a in "$(bm::snap::_dir)"/conn-*.tar.gz; do
      [[ -e "$a" ]] || continue
      [[ "$a" == *.ifcfg.tar.gz ]] && continue
      printf '%s\n' "$a"
    done | while IFS= read -r a; do
      printf '%s\t%s\n' "$(stat -c '%Y' "$a" 2>/dev/null || echo 0)" "$a"
    done | LC_ALL=C sort -rn -k1,1 | cut -f2-
  )
  local i id kept=0
  for ((i = 0; i < ${#archives[@]}; i++)); do
    id="$(basename "${archives[$i]}")"
    id="${id#conn-}"
    id="${id%.tar.gz}"
    if bm::core::in_list "$id" "${protected[@]:-}"; then
      continue    # protected snapshots are kept and do not consume the budget
    fi
    kept=$((kept + 1))
    (( kept > keep )) || continue
    rm -f "${archives[$i]}" "$(bm::snap::ifcfg_path "$id")" "$(bm::snap::manifest_path "$id")"
    bm::log::info "pruned old snapshot $id"
  done
}

# The snapshot id recorded in the pending-change state file, if any. Read as
# plain data rather than through the checkpoint module, which layers above.
bm::snap::_pending_snapshot_id() {
  local f="$BM_RUN_DIR/pending.state" line
  [[ -f "$f" ]] || return 0
  while IFS= read -r line; do
    case "$line" in
      snapshot=*) printf '%s' "${line#snapshot=}"; return 0 ;;
    esac
  done <"$f"
  return 0
}
