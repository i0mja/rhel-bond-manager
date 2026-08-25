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
    "$BM_SELF" rollback --snapshot "$snap" --deadman --yes >/dev/null 2>&1 || return 1
  printf '%s\n' "$unit"
}

bm::ckpt::deadman_cancel() {
  local unit="$1"
  systemctl stop "${unit}.timer" >/dev/null 2>&1 || true
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
  local line
  while IFS= read -r line; do
    case "$line" in
      tier=*) BM_PENDING_TIER="${line#tier=}" ;;
      checkpoint_path=*) BM_PENDING_PATH="${line#checkpoint_path=}" ;;
      deadman_unit=*) BM_PENDING_UNIT="${line#deadman_unit=}" ;;
      snapshot=*) BM_PENDING_SNAPSHOT="${line#snapshot=}" ;;
      deadline=*) BM_PENDING_DEADLINE="${line#deadline=}" ;;
      summary=*) BM_PENDING_SUMMARY="${line#summary=}" ;;
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
    bm::snap::restore "$BM_PENDING_SNAPSHOT"
    ok=1
  fi
  bm::ckpt::clear_pending
  (( ok ))
}
