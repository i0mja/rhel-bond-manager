# lib/33-ckpt.sh — change protection tiers.
#   T1 "checkpoint": NetworkManager D-Bus checkpoint via busctl. NM itself
#      rolls back device + profile state server-side if we never confirm —
#      safe even when the change severs the SSH session driving it.
#   T2 "deadman":    transient systemd timer that runs `bond-manager rollback`
#      against the snapshot if not cancelled in time.
#   T3 "snapshot":   tar snapshot only (always taken in every tier).
# Pending-change state lives in $BM_RUN_DIR/pending.state so a NEW session
# can `bond-manager commit` / `bond-manager rollback` after a disconnect.
# shellcheck shell=bash
[[ -n "${BM_LIB_CKPT:-}" ]] && return 0
BM_LIB_CKPT=1

BM_NM_DBUS_DEST="org.freedesktop.NetworkManager"
BM_NM_DBUS_PATH="/org/freedesktop/NetworkManager"
BM_NM_DBUS_IFACE="org.freedesktop.NetworkManager"
# NMCheckpointCreateFlags: DELETE_NEW_CONNECTIONS(2) | DISCONNECT_NEW_DEVICES(4)
# — this is what lets a rollback undo a *create*, not just an edit.
BM_CKPT_FLAGS=6

BM_CKPT_AFFECTED=""   # devices the armed change touches (saved in pending.state)
BM_PENDING_AFFECTED=""
BM_CKPT_IN_DEADMAN=0  # 1 inside the timer's own rollback (see deadman_cancel)

bm::ckpt::state_file() { printf '%s/pending.state' "$BM_RUN_DIR"; }

# Which tier can this host support right now?
bm::ckpt::probe_tier() {
  if (( BM_NO_CHECKPOINT )); then
    if bm::core::have_cmd systemd-run; then echo deadman; else echo snapshot; fi
    return
  fi
  if bm::core::have_cmd busctl && \
     busctl --timeout=3 call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" \
       org.freedesktop.DBus.Peer Ping >/dev/null 2>&1; then
    echo checkpoint
    return
  fi
  if bm::core::have_cmd systemd-run; then
    echo deadman
    return
  fi
  echo snapshot
}

# ---- T1: NM checkpoints ---------------------------------------------------

bm::ckpt::dbus_create() { # dbus_create <timeout-secs> -> checkpoint object path
  local timeout="$1" out
  out="$(busctl call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" "$BM_NM_DBUS_IFACE" \
    CheckpointCreate aouu 0 "$timeout" "$BM_CKPT_FLAGS" 2>&1)" || {
    bm::log::warn "CheckpointCreate failed: $out"
    return 1
  }
  # reply: o "/org/freedesktop/NetworkManager/Checkpoint/N"
  local path
  path="$(sed -n 's/^o "\(.*\)"$/\1/p' <<<"$out")"
  [[ -n "$path" ]] || {
    bm::log::warn "could not parse checkpoint path from: $out"
    return 1
  }
  printf '%s\n' "$path"
}

bm::ckpt::dbus_destroy() { # commit: drop the checkpoint, keep the changes
  busctl call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" "$BM_NM_DBUS_IFACE" \
    CheckpointDestroy o "$1" >/dev/null 2>&1
}

bm::ckpt::dbus_rollback() {
  busctl call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" "$BM_NM_DBUS_IFACE" \
    CheckpointRollback o "$1" >/dev/null 2>&1
}

bm::ckpt::dbus_extend() { # add seconds to the rollback timeout
  busctl call "$BM_NM_DBUS_DEST" "$BM_NM_DBUS_PATH" "$BM_NM_DBUS_IFACE" \
    CheckpointAdjustRollbackTimeout ou "$1" "$2" >/dev/null 2>&1
}

# ---- T2: deadman timer ----------------------------------------------------

bm::ckpt::deadman_arm() { # deadman_arm <timeout-secs> <snapshot-id> -> unit name
  local timeout="$1" snap="$2"
  # The timer runs this program from systemd, with no shell and no cwd: an
  # unrunnable path would arm protection that silently never fires, which is
  # worse than honestly falling back a tier.
  if [[ -z "$BM_SELF" || ! -x "$BM_SELF" ]]; then
    bm::log::warn "deadman: '$BM_SELF' is not an executable path; cannot arm a timer"
    return 1
  fi
  local unit
  unit="bond-manager-deadman-$$-$(date +%s)"
  systemd-run --collect --unit "$unit" --on-active="${timeout}s" \
    --timer-property=AccuracySec=1s \
    "$BM_SELF" rollback --snapshot "$snap" --deadman --yes >/dev/null 2>&1 || return 1
  printf '%s\n' "$unit"
}

bm::ckpt::deadman_cancel() {
  local unit="$1"
  systemctl stop "${unit}.timer" >/dev/null 2>&1 || true
  # The timer's own rollback runs as ${unit}.service. Stopping that service
  # from inside it makes systemd kill every process of the unit, the
  # rollback included, before it has restored anything.
  if (( BM_CKPT_IN_DEADMAN )); then
    return 0
  fi
  systemctl stop "${unit}.service" >/dev/null 2>&1 || true
  systemctl reset-failed "${unit}.service" >/dev/null 2>&1 || true
}

# ---- pending-change state -------------------------------------------------

# arm: create protection before the first mutating step.
# Writes the state file and sets:
#   BM_CKPT_TIER, BM_CKPT_PATH (T1), BM_CKPT_UNIT (T2), BM_CKPT_DEADLINE
bm::ckpt::arm() { # arm <timeout-secs> <snapshot-id> <summary>
  local timeout="$1" snap="$2" summary="$3"
  BM_CKPT_TIER="$(bm::ckpt::probe_tier)"
  BM_CKPT_PATH=""
  BM_CKPT_UNIT=""
  BM_CKPT_DEADLINE=$(( $(bm::core::epoch) + timeout ))

  case "$BM_CKPT_TIER" in
    checkpoint)
      if ! BM_CKPT_PATH="$(bm::ckpt::dbus_create "$timeout")"; then
        bm::log::warn "checkpoint creation failed; falling back"
        if bm::core::have_cmd systemd-run; then
          BM_CKPT_TIER=deadman
        else
          BM_CKPT_TIER=snapshot
        fi
      fi
      ;;
  esac
  if [[ "$BM_CKPT_TIER" == deadman ]]; then
    if ! BM_CKPT_UNIT="$(bm::ckpt::deadman_arm "$timeout" "$snap")"; then
      bm::log::warn "deadman timer creation failed; snapshot-only protection"
      BM_CKPT_TIER=snapshot
    fi
  fi

  BM_CKPT_SNAPSHOT="$snap"
  BM_CKPT_SUMMARY="$summary"
  bm::ckpt::_write_state
  bm::log::info "armed tier=$BM_CKPT_TIER checkpoint=$BM_CKPT_PATH unit=$BM_CKPT_UNIT snapshot=$snap timeout=${timeout}s"
}

# Persist the pending-change state so a NEW session can commit or roll back.
bm::ckpt::_write_state() {
  mkdir -p "$BM_RUN_DIR"
  chmod 0750 "$BM_RUN_DIR" 2>/dev/null || true
  {
    printf 'tier=%s\n' "${BM_CKPT_TIER:-}"
    printf 'checkpoint_path=%s\n' "${BM_CKPT_PATH:-}"
    printf 'deadman_unit=%s\n' "${BM_CKPT_UNIT:-}"
    printf 'snapshot=%s\n' "${BM_CKPT_SNAPSHOT:-}"
    printf 'deadline=%s\n' "${BM_CKPT_DEADLINE:-0}"
    printf 'created=%s\n' "$(bm::core::timestamp)"
    printf 'pid=%s\n' "$$"
    printf 'summary=%s\n' "${BM_CKPT_SUMMARY:-}"
    printf 'affected=%s\n' "${BM_CKPT_AFFECTED:-}"
  } >"$(bm::ckpt::state_file)"
  chmod 0640 "$(bm::ckpt::state_file)" 2>/dev/null || true
}

# Load pending state into BM_PENDING_* variables. Returns 1 if none.
bm::ckpt::load_pending() {
  local f
  f="$(bm::ckpt::state_file)"
  [[ -f "$f" ]] || return 1
  BM_PENDING_TIER="" BM_PENDING_PATH="" BM_PENDING_UNIT=""
  BM_PENDING_SNAPSHOT="" BM_PENDING_DEADLINE="" BM_PENDING_SUMMARY=""
  BM_PENDING_AFFECTED="" # absent in state written by 3.0
  local line
  while IFS= read -r line; do
    case "$line" in
      tier=*) BM_PENDING_TIER="${line#tier=}" ;;
      checkpoint_path=*) BM_PENDING_PATH="${line#checkpoint_path=}" ;;
      deadman_unit=*) BM_PENDING_UNIT="${line#deadman_unit=}" ;;
      snapshot=*) BM_PENDING_SNAPSHOT="${line#snapshot=}" ;;
      deadline=*) BM_PENDING_DEADLINE="${line#deadline=}" ;;
      summary=*) BM_PENDING_SUMMARY="${line#summary=}" ;;
      affected=*) BM_PENDING_AFFECTED="${line#affected=}" ;;
    esac
  done <"$f"
  return 0
}

bm::ckpt::clear_pending() { rm -f "$(bm::ckpt::state_file)"; }

# Reset the auto-rollback deadline to a full window. Applying a plan consumes
# real time (each activation can take up to ACTIVATE_TIMEOUT), so without this
# the operator would get whatever is left of the window to decide — sometimes
# nothing at all on a slow bond. Called once verification has passed.
bm::ckpt::rebudget() { # rebudget <seconds>
  local secs="$1"
  case "${BM_CKPT_TIER:-}" in
    checkpoint)
      [[ -n "${BM_CKPT_PATH:-}" ]] || return 0
      bm::ckpt::dbus_extend "$BM_CKPT_PATH" "$secs" || {
        bm::log::warn "could not extend the checkpoint rollback timeout"
        return 1
      }
      ;;
    deadman)
      [[ -n "${BM_CKPT_UNIT:-}" ]] || return 0
      local snap="${BM_CKPT_SNAPSHOT:-}"
      [[ -n "$snap" ]] || return 0
      bm::ckpt::deadman_cancel "$BM_CKPT_UNIT"
      local unit
      if unit="$(bm::ckpt::deadman_arm "$secs" "$snap")"; then
        BM_CKPT_UNIT="$unit"
      else
        bm::log::warn "could not re-arm the deadman timer after applying"
        return 1
      fi
      ;;
    *) return 0 ;;
  esac
  BM_CKPT_DEADLINE=$(( $(bm::core::epoch) + secs ))
  bm::ckpt::_write_state
  bm::log::info "rollback deadline re-budgeted to ${secs}s after apply"
  return 0
}

# commit: keep the applied changes, disarm all protection.
# Returns 0 when protection was genuinely disarmed, 1 when there was nothing
# pending, and BM_EX_CKPT_LOST (2) when the checkpoint had already gone —
# which on NetworkManager means the rollback timeout expired and the change
# was reverted server-side. Reporting that as "committed" would tell the
# operator their change is live when it is not.
BM_EX_CKPT_LOST=2

bm::ckpt::commit() {
  bm::ckpt::load_pending || {
    bm::log::say "no pending change to commit"
    return 1
  }
  local rc=0
  case "$BM_PENDING_TIER" in
    checkpoint)
      if [[ -n "$BM_PENDING_PATH" ]]; then
        if ! bm::ckpt::dbus_destroy "$BM_PENDING_PATH"; then
          bm::log::warn "CheckpointDestroy failed for $BM_PENDING_PATH — the checkpoint no longer exists, so NetworkManager has most likely already rolled the change back"
          rc="$BM_EX_CKPT_LOST"
        fi
      fi
      ;;
    deadman)
      [[ -n "$BM_PENDING_UNIT" ]] && bm::ckpt::deadman_cancel "$BM_PENDING_UNIT"
      ;;
  esac
  bm::ckpt::clear_pending
  if (( rc == 0 )); then
    bm::log::info "committed pending change (tier=$BM_PENDING_TIER)"
  else
    bm::log::error "commit could not disarm the checkpoint (tier=$BM_PENDING_TIER); change may have been auto-rolled-back"
  fi
  return "$rc"
}

# rollback: revert the pending change through whichever tier is armed.
bm::ckpt::rollback_pending() {
  bm::ckpt::load_pending || return 1
  local ok=0
  case "$BM_PENDING_TIER" in
    checkpoint)
      if [[ -n "$BM_PENDING_PATH" ]] && bm::ckpt::dbus_rollback "$BM_PENDING_PATH"; then
        ok=1
      else
        bm::log::warn "checkpoint rollback failed (expired?); falling back to snapshot restore"
      fi
      ;;
    deadman)
      [[ -n "$BM_PENDING_UNIT" ]] && bm::ckpt::deadman_cancel "$BM_PENDING_UNIT"
      ;;
  esac
  if (( ! ok )) && [[ -n "$BM_PENDING_SNAPSHOT" ]]; then
    local -a devs=()
    read -r -a devs <<<"$BM_PENDING_AFFECTED" || true
    local before=""
    if (( ${#devs[@]} > 0 )); then
      before="$(bm::ckpt::profiles_of "${devs[@]}")"
    fi
    bm::snap::restore "$BM_PENDING_SNAPSHOT"
    ok=1
    bm::ckpt::clear_pending
    if (( ${#devs[@]} > 0 )); then
      bm::ckpt::reapply "$before" || ok=0
    else
      bm::ckpt::_problem "the saved settings are restored, but this change did not record which connections it touched (it was armed by an older version): running connections keep their settings until brought up again, e.g. nmcli connection up NAME"
    fi
  fi
  bm::ckpt::clear_pending
  (( ok ))
}

# ---- after a snapshot restore -------------------------------------------------
# NetworkManager's reload only re-reads profiles: active connections keep
# running with what the change applied, so a change that cut the SSH session
# would stay live. The profiles of the devices the change touched are
# fingerprinted before the restore; afterwards, in this order:
#   1. a VLAN or bond device whose profile the restore removed (the change
#      created it) is deleted;
#   2. a port whose profile the restore removed but that is still in a bond
#      is released;
#   3. every profile the restore brought back or changed is brought up again:
#      bonds first, then all of their ports and VLANs (NetworkManager does
#      not reliably re-attach them to a re-activated bond), then other ports,
#      then other VLANs.
# Profiles the restore did not change are left alone: no needless blip on
# the connection carrying the session.

bm::ckpt::_problem() { # logged, and shown: a half-finished rollback must not go unnoticed
  bm::log::warn "$1"
  bm::log::say "$(bm::core::c_warn "WARNING: $1")"
}

bm::ckpt::profiles_of() { # profiles_of <dev...> -> "dev<US>uuid<US>type<US>sum" lines
  local index d line ifname uuid type active pick psum
  index="$(bm::nm::ifname_index)"
  for d in "$@"; do
    [[ -n "$d" ]] || continue
    pick=""
    while IFS=$'\x1f' read -r ifname uuid type active; do
      [[ "$ifname" == "$d" ]] || continue
      if [[ -z "$pick" || "$active" == "$d" ]]; then pick="$uuid"$'\x1f'"$type"; fi
    done <<<"$index"
    if [[ -n "$pick" ]]; then
      psum="$(bm::nm::con_settings "${pick%%$'\x1f'*}" | cksum)"
      printf '%s\x1f%s\x1f%s\n' "$d" "$pick" "$psum"
    else
      printf '%s\x1f\x1f\x1f\n' "$d"
    fi
  done
}

bm::ckpt::reapply() { # reapply <profiles_of output from before the restore>
  local before="$1" after d buuid btype bsum auuid atype asum rec
  local -a del_vlan=() del_bond=() release=() up_bond=() up_port=() up_vlan=()
  local -A seen=()
  local -a devs=()
  while IFS=$'\x1f' read -r d _ _ _; do
    [[ -n "$d" && -z "${seen[$d]:-}" ]] || continue
    seen[$d]=1
    devs+=("$d")
  done <<<"$before"
  (( ${#devs[@]} > 0 )) || return 0
  after="$(bm::ckpt::profiles_of "${devs[@]}")"
  local -A was_uuid=() was_type=() was_sum=()
  while IFS=$'\x1f' read -r d buuid btype bsum; do
    [[ -n "$d" ]] || continue
    was_uuid[$d]="$buuid" was_type[$d]="$btype" was_sum[$d]="$bsum"
  done <<<"$before"

  while IFS=$'\x1f' read -r d auuid atype asum; do
    [[ -n "$d" ]] || continue
    buuid="${was_uuid[$d]:-}" btype="${was_type[$d]:-}" bsum="${was_sum[$d]:-}"
    if [[ -n "$auuid" ]]; then
      [[ "$auuid" == "$buuid" && "$asum" == "$bsum" ]] && continue # untouched
      case "$atype" in
        bond) up_bond+=("$d"$'\x1f'"$auuid") ;;
        vlan) up_vlan+=("$d"$'\x1f'"$auuid") ;;
        *) up_port+=("$d"$'\x1f'"$auuid") ;;
      esac
    elif [[ -n "$buuid" ]]; then
      if bm::facts::bond_exists_kernel "$d"; then
        del_bond+=("$d")
      elif [[ "$btype" == vlan && -e "$BM_SYS_ROOT/class/net/$d" ]]; then
        del_vlan+=("$d")
      elif bm::facts::nic_info "$d" && [[ -n "$BM_NIC_MASTER" ]]; then
        release+=("$d")
      fi
    fi
  done <<<"$after"

  # a re-activated bond takes its ports and VLANs down with it: bring every
  # one of them back, changed or not
  local rec2 puuid pname pdev vuuid vname vdev vid
  for rec in "${up_bond[@]}"; do
    d="${rec%%$'\x1f'*}"
    while IFS= read -r rec2; do
      IFS=$'\x1f' read -r puuid pname pdev <<<"$rec2"
      [[ -n "$puuid" ]] && up_port+=("${pdev:-$pname}"$'\x1f'"$puuid")
    done < <(bm::nm::port_cons "$d")
    while IFS= read -r rec2; do
      IFS=$'\x1f' read -r vuuid vname vdev vid <<<"$rec2"
      [[ -n "$vuuid" ]] && up_vlan+=("${vdev:-$vname}"$'\x1f'"$vuuid")
    done < <(bm::nm::vlan_cons "$d")
  done

  local failed=0
  local -a done_del=() done_up=() done_rel=()
  for d in "${del_vlan[@]}" "${del_bond[@]}"; do
    [[ -n "$d" ]] || continue
    if bm::nm::device_delete "$d" >/dev/null 2>&1; then
      done_del+=("$d")
    else
      bm::ckpt::_problem "could not delete $d, which the change created - retry with: nmcli device delete $d"
      failed=1
    fi
  done
  for d in "${release[@]}"; do
    [[ -n "$d" ]] || continue
    if bm::nm::device_disconnect "$d" >/dev/null 2>&1; then
      done_rel+=("$d")
    else
      bm::ckpt::_problem "could not take $d out of its bond - retry with: nmcli device disconnect $d"
      failed=1
    fi
  done
  local -A upped=()
  local uuid
  for rec in "${up_bond[@]}" "${up_port[@]}" "${up_vlan[@]}"; do
    [[ -n "$rec" ]] || continue
    d="${rec%%$'\x1f'*}" uuid="${rec#*$'\x1f'}"
    [[ -z "${upped[$uuid]:-}" ]] || continue
    upped[$uuid]=1
    if [[ "$(bm::nm::con_get "$uuid" connection.autoconnect)" == no ]]; then
      bm::log::say "left down (its profile does not start by itself): $d"
      continue
    fi
    if bm::nm::up "$uuid" >/dev/null 2>&1; then
      done_up+=("$d")
    else
      bm::ckpt::_problem "could not bring $d up again with the restored settings - retry with: nmcli connection up $uuid"
      failed=1
    fi
  done
  if (( ${#done_del[@]} > 0 )); then
    bm::log::say "removed what the change created: $(bm::core::join ', ' "${done_del[@]}")"
  fi
  if (( ${#done_rel[@]} > 0 )); then
    bm::log::say "taken out of their bond again: $(bm::core::join ', ' "${done_rel[@]}")"
  fi
  if (( ${#done_up[@]} > 0 )); then
    bm::log::say "brought up again: $(bm::core::join ', ' "${done_up[@]}")"
  fi
  (( ! failed ))
}
