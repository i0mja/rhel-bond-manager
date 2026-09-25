# lib/60-plan.sh — the transaction engine.
# Workflows BUILD a plan (ordered steps of description + argv); the engine
# renders it (that rendering IS --dry-run: nothing else happens), then
# snapshot → arm protection → execute → verify → commit-or-rollback.
# A single flock serializes all mutating invocations.
# shellcheck shell=bash
[[ -n "${BM_LIB_PLAN:-}" ]] && return 0
BM_LIB_PLAN=1

# ---- lock -----------------------------------------------------------------

BM_LOCK_FD=""
bm::lock::acquire() {
  mkdir -p "$BM_RUN_DIR"
  local fd
  exec {fd}>"$BM_RUN_DIR/lock"
  if ! flock -n "$fd"; then
    local holder=""
    holder="$(cat "$BM_RUN_DIR/lockinfo" 2>/dev/null || true)"
    bm::core::die "another $BM_PROG instance is running${holder:+ ($holder)}" "$BM_EX_LOCKED"
  fi
# shellcheck disable=SC2034  # the fd variable pins the lock open for our lifetime
  BM_LOCK_FD="$fd"
  printf 'pid=%s cmd=%s started=%s\n' "$$" "${BM_LOG_OP:-?}" "$(bm::core::timestamp)" \
    >"$BM_RUN_DIR/lockinfo" 2>/dev/null || true
}

# The commit gate lets go of the lock while it waits for the operator, so a
# second session can commit or roll back (a change to the address you are
# logged in on leaves the first session frozen, not gone) and the deadman
# timer can do its job. pending.state still refuses any new change.
bm::lock::release() {
  [[ -n "$BM_LOCK_FD" ]] || return 0
  rm -f "$BM_RUN_DIR/lockinfo"
  flock -u "$BM_LOCK_FD" 2>/dev/null || true
  exec {BM_LOCK_FD}>&-
  BM_LOCK_FD=""
}

bm::lock::retake() { # retake [wait-seconds] -> 1 when another session keeps it
  [[ -z "$BM_LOCK_FD" ]] || return 0
  local fd
  exec {fd}>"$BM_RUN_DIR/lock"
  if ! flock -w "${1:-30}" "$fd"; then
    exec {fd}>&-
    return 1
  fi
  BM_LOCK_FD="$fd"
  printf 'pid=%s cmd=%s started=%s\n' "$$" "${BM_LOG_OP:-?}" "$(bm::core::timestamp)" \
    >"$BM_RUN_DIR/lockinfo" 2>/dev/null || true
}

# ---- plan model -----------------------------------------------------------

BM_PLAN_DESCS=()
BM_PLAN_CMDS=()

# How the last apply ended, in one word, for the menus to explain:
# noop | dry-run | cancelled | committed | rolled-back | expired | pending | lost
# | gone (settled by another session while the gate waited, how unknown)
BM_PLAN_OUTCOME=""

bm::plan::reset() {
  BM_PLAN_DESCS=()
  BM_PLAN_CMDS=()
}

bm::plan::add() { # add <description> <argv...>
  local desc="$1"
  shift
  local q
  printf -v q '%q ' "$@"
  BM_PLAN_DESCS+=("$desc")
  BM_PLAN_CMDS+=("$q")
}

bm::plan::size() { printf '%s' "${#BM_PLAN_DESCS[@]}"; }

bm::plan::render() { # human-readable plan
  local i
  if (( ${#BM_PLAN_DESCS[@]} == 0 )); then
    echo "No changes required — system already matches the requested state."
    return 0
  fi
  echo "Plan:"
  for i in "${!BM_PLAN_DESCS[@]}"; do
    printf '  %2d. %s\n' "$((i + 1))" "${BM_PLAN_DESCS[$i]}"
    printf '      $ %s\n' "$(bm::plan::_pretty_cmd "${BM_PLAN_CMDS[$i]}")"
  done
}

# Shell-quote a value for display, but only when it needs it — a plan full of
# backslash-escaped commas is unreadable. The plan is advertised as commands
# an operator can run by hand, so anything a shell would interpret (a profile
# name containing $(...), a semicolon, whitespace) must come out inert.
bm::plan::_shq() {
  local v="$1"
  if [[ -n "$v" && "$v" =~ ^[A-Za-z0-9_@%+=:,./-]*$ ]]; then # '' must show
    printf '%s' "$v"
  else
    printf "'%s'" "${v//\'/\'\\\'\'}"
  fi
}

# Quote every argument of the remaining positional parameters.
bm::plan::_shq_all() {
  local out="" a
  for a in "$@"; do
    [[ -n "$out" ]] && out+=" "
    out+="$(bm::plan::_shq "$a")"
  done
  printf '%s' "$out"
}

# Translate internal step commands into the nmcli invocations they perform,
# so a rendered plan reads as commands an operator could run by hand.
bm::plan::_pretty_cmd() {
  local cmd="${1% }"
  eval "set -- $cmd"
  case "$1" in
    bm::nm::run) shift; printf 'nmcli %s' "$(bm::plan::_shq_all "$@")" ;;
    bm::nm::add_bond)
      printf 'nmcli connection add type bond con-name %s ifname %s bond.options %s ipv4.method disabled ipv6.method ignore' \
        "$(bm::plan::_shq "$2")" "$(bm::plan::_shq "$2")" "$(bm::plan::_shq "$3")" ;;
    bm::nm::add_port)
      printf 'nmcli connection add type ethernet con-name bond-port-%s ifname %s master %s slave-type bond' \
        "$(bm::plan::_shq "$3")" "$(bm::plan::_shq "$3")" "$(bm::plan::_shq "$2")" ;;
    bm::nm::add_vlan)
      printf 'nmcli connection add type vlan con-name %s ifname %s vlan.parent %s vlan.id %s ipv4.method disabled ipv6.method ignore' \
        "$(bm::plan::_shq "$2.$3")" "$(bm::plan::_shq "$2.$3")" "$(bm::plan::_shq "$2")" "$(bm::plan::_shq "$3")" ;;
    bm::nm::modify) shift; printf 'nmcli connection modify %s' "$(bm::plan::_shq_all "$@")" ;;
    bm::nm::up) printf 'nmcli connection up %s' "$(bm::plan::_shq "$2")" ;;
    bm::nm::down) printf 'nmcli connection down %s' "$(bm::plan::_shq "$2")" ;;
    bm::nm::delete) printf 'nmcli connection delete %s' "$(bm::plan::_shq "$2")" ;;
    bm::plan::await_member)
      printf '(wait until %s is enslaved to %s)' "$(bm::plan::_shq "$3")" "$(bm::plan::_shq "$2")" ;;
    *) shift; printf '%s' "$(bm::plan::_shq_all "$@")" ;;
  esac
}

# Step helper usable inside plans: wait until a NIC shows up as a member.
bm::plan::await_member() { # await_member <bond> <nic>
  bm::verify::_settle bm::verify::_member_enslaved "$1" "$2"
}

# Run all steps. Step stdout is routed to stderr so callers can capture this
# function's own output: on failure it prints the failing 0-based step index.
# shellcheck disable=SC2120  # positional params are set via `eval set --`
bm::plan::execute() {
  local i cmd
  for i in "${!BM_PLAN_CMDS[@]}"; do
    cmd="${BM_PLAN_CMDS[$i]}"
    bm::log::info "step $((i + 1))/${#BM_PLAN_CMDS[@]}: ${BM_PLAN_DESCS[$i]}"
    bm::log::say "  [$((i + 1))/${#BM_PLAN_CMDS[@]}] ${BM_PLAN_DESCS[$i]}"
    eval "set -- $cmd"
    if ! "$@" 1>&2; then
      bm::log::error "step $((i + 1)) failed: ${BM_PLAN_DESCS[$i]}"
      printf '%s\n' "$i"
      return 1
    fi
  done
  return 0
}

# ---- SSH egress guard -----------------------------------------------------

# Warn (when checkpoint-protected) or refuse if the change touches the
# device this SSH session rides on. affected devices: bond, members, VLANs.
# Returns 0 = proceed, 1 = refuse (reason already printed). Callers decide
# how to abort so protection armed in the meantime can be disarmed first.
bm::plan::ssh_guard() { # ssh_guard <tier> <affected-devs...>
  local tier="$1"
  shift
  local egress parent
  egress="$(bm::facts::ssh_egress_dev || true)"
  [[ -n "$egress" ]] || return 0
  # A session on eth2.100 dies just as surely when eth2 goes into a bond.
  parent="$(bm::facts::vlan_parent "$egress")"
  local dev hit="" via=""
  for dev in "$@"; do
    if [[ "$dev" == "$egress" ]]; then hit="$egress" via=""; break; fi
    if [[ -n "$parent" && "$dev" == "$parent" && -z "$hit" ]]; then hit="$parent" via=" (through $egress)"; fi
  done
  [[ -n "$hit" ]] || return 0
  if [[ "$tier" == checkpoint ]]; then
    bm::log::say "$(bm::core::c_warn "NOTE: this change touches '$hit', which carries your SSH session$via.")"
    bm::log::say "$(bm::core::c_warn "NetworkManager will auto-rollback in $(bm::plan::_window)s unless you commit.")"
    return 0
  fi
  if (( BM_FORCE_UNSAFE )); then
    bm::log::say "$(bm::core::c_warn "WARNING: proceeding without checkpoint protection on your SSH egress device ($egress).")"
    return 0
  fi
  printf '%s: %s this change touches %s, which carries your SSH session%s, and NetworkManager checkpoints are unavailable (tier: %s).\nUse a console, or re-run with --force-unsafe to accept the risk of losing access.\n' \
    "$BM_PROG" "$(bm::core::c_err ERROR:)" "'$hit'" "$via" "$tier" >&2
  return 1
}

bm::plan::_window() {
  if [[ -n "$BM_ROLLBACK_WINDOW" ]]; then
    printf '%s' "$BM_ROLLBACK_WINDOW"
  else
    bm::config::get ROLLBACK_WINDOW
  fi
}

# ---- apply ----------------------------------------------------------------

# bm::plan::apply <op-name> <summary> <verify-cmd...>
#   - op-name: log tag
#   - summary: one line describing the change (stored in pending state)
#   - verify-cmd: command run after execution; it should populate the
#     bm::verify report. Pass `true` to skip verification.
# Globals consumed: BM_PLAN_* (the plan), BM_PLAN_AFFECTED (array of device
# names the SSH guard should consider).
bm::plan::apply() {
  local op="$1" summary="$2"
  shift 2

  bm::log::set_op "$op"

  if (( ${#BM_PLAN_DESCS[@]} == 0 )); then
    BM_PLAN_OUTCOME=noop
    bm::log::say "Nothing to do — already in the requested state."
    return "$BM_EX_OK"
  fi

  if (( BM_DRY_RUN )); then
    BM_PLAN_OUTCOME=dry-run
    bm::plan::render
    echo
    echo "(dry-run: no commands executed, no files written, no snapshot taken)"
    return "$BM_EX_OK"
  fi

  bm::core::require_root
  bm::log::enable_file
  bm::lock::acquire

  if bm::ckpt::load_pending; then
    bm::core::die "a previous change is still pending (${BM_PENDING_SUMMARY:-unknown}). Run '$BM_PROG commit' or '$BM_PROG rollback' first." "$BM_EX_PRECONDITION"
  fi

  local window tier
  window="$(bm::plan::_window)"
  tier="$(bm::ckpt::probe_tier)"
  bm::plan::ssh_guard "$tier" "${BM_PLAN_AFFECTED[@]:-}" || \
    bm::core::die "aborted (SSH egress guard)" "$BM_EX_PRECONDITION"

  bm::plan::render
  echo
  bm::log::say "Protection tier: $tier (auto-rollback window: ${window}s)"
  bm::log::say "  $(bm::help::tier_sentence "$tier")"
  if ! (( BM_ASSUME_YES )); then
    if ! bm::ui::yesno "Apply this plan?"; then
      BM_PLAN_OUTCOME=cancelled
      bm::log::say "aborted before any change"
      return "$BM_EX_OK"
    fi
  fi

  # NOTE: this function is routinely called in a `|| rc=$?` context, which
  # suspends errexit for the whole call tree — every critical step below is
  # therefore checked explicitly (die still exits reliably).
  local snap
  snap="$(bm::snap::create "$op")" || \
    bm::core::die "snapshot creation failed — aborting before any change" "$BM_EX_ERR"
  bm::log::say "snapshot: $snap"
  # saved with the pending state: a rollback re-applies these connections
  BM_CKPT_AFFECTED="${BM_PLAN_AFFECTED[*]:-}"
  bm::ckpt::arm "$window" "$snap" "$summary"
  if [[ "$BM_CKPT_TIER" != "$tier" ]]; then
    # arming fell back a tier; re-check the ssh guard under the real tier.
    # nothing has been changed yet, so on refusal disarm cleanly (commit of
    # zero changes) instead of leaving a timer that would "roll back" later.
    local guard_rc=0
    bm::plan::ssh_guard "$BM_CKPT_TIER" "${BM_PLAN_AFFECTED[@]:-}" || guard_rc=$?
    if (( guard_rc != 0 )); then
      bm::ckpt::commit >/dev/null 2>&1 || true
      bm::core::die "aborted: change touches your SSH egress device and checkpoint protection is unavailable" "$BM_EX_PRECONDITION"
    fi
  fi

  local failed_step=""
  if ! failed_step="$(bm::plan::execute)"; then
    bm::log::say "$(bm::core::c_err "step $((failed_step + 1)) failed — rolling back")"
    if bm::ckpt::rollback_pending; then
      bm::log::say "rolled back to snapshot $snap"
      bm::log::say "Your network is back the way it was: the failed step above left nothing half-done."
    else
      bm::log::say "rolled back to snapshot $snap"
      bm::log::warn "rollback reported problems (see above); inspect manually"
    fi
    BM_PLAN_OUTCOME=rolled-back
    return "$BM_EX_VERIFY"
  fi

  bm::verify::reset
  "$@" || true
  echo
  echo "Verification:"
  bm::verify::render
  echo

  if bm::verify::failed; then
    bm::log::say "$(bm::core::c_err "verification FAILED — rolling back")"
    if bm::ckpt::rollback_pending; then
      bm::log::say "rolled back to snapshot $snap"
      bm::log::say "Your network is back the way it was. The FAIL lines above say what did not check out."
    else
      bm::log::say "rolled back to snapshot $snap"
      bm::log::warn "rollback reported problems (see above); inspect manually"
    fi
    BM_PLAN_OUTCOME=rolled-back
    return "$BM_EX_VERIFY"
  fi

  # Applying consumed part of the rollback window; give the operator (or the
  # next session) a full window to decide from here.
  bm::ckpt::rebudget "$window" || true

  if (( BM_ASSUME_YES )); then
    local crc=0
    bm::ckpt::commit >/dev/null || crc=$?
    if (( crc == BM_EX_CKPT_LOST )); then
      BM_PLAN_OUTCOME=lost
      bm::log::say "$(bm::core::c_err "the checkpoint expired before it could be committed — NetworkManager has most likely rolled this change back")"
      return "$BM_EX_VERIFY"
    fi
    BM_PLAN_OUTCOME=committed
    bm::log::say "$(bm::core::c_ok "change applied and committed (verification passed)")"
    return "$BM_EX_OK"
  fi

  bm::plan::commit_gate "$snap"
}

# No terminal to ask on (or the terminal went away): leave protection armed
# and say exactly how to finish from another session.
bm::plan::_gate_no_tty() {
  bm::log::say "No TTY to confirm on. Protection stays armed:"
  bm::log::say "  confirm with:   $BM_PROG commit"
  bm::log::say "  or revert with: $BM_PROG rollback"
  if [[ "$BM_CKPT_TIER" == snapshot ]]; then
    bm::log::say "$(bm::core::c_warn "Snapshot-only protection: nothing will roll this back automatically.")"
  else
    bm::log::say "Auto-rollback at the deadline if you do neither."
  fi
  BM_PLAN_OUTCOME=pending
  return "$BM_EX_PARTIAL"
}

# The deadline passed while the operator sat at the prompt. On the
# checkpoint tier NetworkManager rolls back by itself. On the deadman tier
# the timer's own rollback cannot help: this process still holds the lock
# (and transient timers may fire late), so it would either be refused or
# find nothing pending. Restore the snapshot here instead of announcing a
# rollback that never happened.
bm::plan::_gate_expired() { # _gate_expired <snapshot-id>
  local snap="$1"
  echo
  BM_PLAN_OUTCOME=expired
  if [[ "$BM_CKPT_TIER" == deadman ]]; then
    if bm::ckpt::rollback_pending; then
      bm::log::say "$(bm::core::c_err "auto-rollback deadline reached — the change has been reverted")"
      bm::log::say "rolled back to snapshot $snap"
    else
      bm::log::say "$(bm::core::c_err "auto-rollback deadline reached — restoring snapshot $snap reported problems; inspect manually")"
    fi
    return "$BM_EX_VERIFY"
  fi
  bm::log::say "$(bm::core::c_err "auto-rollback deadline reached — the change has been reverted")"
  bm::ckpt::clear_pending
  return "$BM_EX_VERIFY"
}

bm::plan::_gate_keep() { # _gate_keep -> rc of the gate
  local crc=0
  bm::ckpt::commit >/dev/null || crc=$?
  if (( crc == BM_EX_CKPT_LOST )); then
    BM_PLAN_OUTCOME=lost
    bm::log::say "$(bm::core::c_err "the checkpoint had already expired — NetworkManager has most likely rolled this change back")"
    bm::log::say "check the result with: $BM_PROG status"
    return "$BM_EX_VERIFY"
  fi
  BM_PLAN_OUTCOME=committed
  bm::log::say "$(bm::core::c_ok "change committed")"
  return "$BM_EX_OK"
}

bm::plan::_gate_undo() { # _gate_undo <snapshot-id>
  bm::ckpt::rollback_pending || bm::log::warn "rollback reported problems"
  bm::log::say "rolled back to snapshot $1"
  BM_PLAN_OUTCOME=rolled-back
  return "$BM_EX_VERIFY"
}

bm::plan::_gate_extend() { # _gate_extend <seconds-left> -> 0 when extended
  local remaining="$1" add=300
  if [[ "$BM_CKPT_TIER" == checkpoint && -n "$BM_CKPT_PATH" ]]; then
    if bm::ckpt::dbus_extend "$BM_CKPT_PATH" $(( remaining + add )); then
      BM_CKPT_DEADLINE=$(( $(bm::core::epoch) + remaining + add ))
      bm::ckpt::_write_state # other sessions and the menus count down from it
      return 0
    fi
  fi
  return 1
}

# While the gate waits it holds no lock, so the change can be settled
# elsewhere. 0 = settled (BM_GATE_SETTLED says how), 1 = still ours to decide.
BM_GATE_SETTLED=""
bm::plan::_gate_settled() { # _gate_settled <snapshot-id>
  if bm::ckpt::load_pending && [[ "${BM_PENDING_SNAPSHOT:-}" == "$1" ]]; then
    return 1
  fi
  BM_GATE_SETTLED="$(bm::ckpt::settled_how "$1")"
  return 0
}

bm::plan::_gate_report_settled() { # -> rc of the gate
  echo
  case "$BM_GATE_SETTLED" in
    kept)
      BM_PLAN_OUTCOME=committed
      bm::log::say "$(bm::core::c_ok "The change was kept from another session.")"
      return "$BM_EX_OK" ;;
    timer)
      BM_PLAN_OUTCOME=expired
      bm::log::say "$(bm::core::c_warn "The safety net undid the change: its time ran out.")"
      return "$BM_EX_VERIFY" ;;
    undone)
      BM_PLAN_OUTCOME=rolled-back
      bm::log::say "$(bm::core::c_warn "The change was undone from another session.")"
      return "$BM_EX_VERIFY" ;;
    restored)
      BM_PLAN_OUTCOME=rolled-back
      bm::log::say "$(bm::core::c_warn "A backup copy was restored from another session; this change is no longer waiting.")"
      return "$BM_EX_VERIFY" ;;
    *)
      BM_PLAN_OUTCOME=gone
      bm::log::say "$(bm::core::c_warn "The change is no longer waiting: it was settled from another session.")"
      return "$BM_EX_OK" ;;
  esac
}

# Take the lock back before acting on the operator's answer, then make sure
# the change is still waiting. rc 0 = go ahead, 1 = settled meanwhile
# (reported; the gate returns BM_GATE_RC), 2 = the lock is busy.
BM_GATE_RC=0
bm::plan::_gate_claim() { # _gate_claim <snapshot-id> [wait-seconds]
  if ! bm::lock::retake "${2:-30}"; then
    return 2
  fi
  if bm::plan::_gate_settled "$1"; then
    BM_GATE_RC=0
    bm::plan::_gate_report_settled || BM_GATE_RC=$?
    return 1
  fi
  return 0
}

# Interactive commit gate: count down toward the auto-rollback deadline.
# K (or c) keeps the change, U (or r) undoes it, E adds five minutes on the
# checkpoint tier. End of input on the terminal behaves like having no
# terminal at all: protection stays armed and the way out is printed.
bm::plan::commit_gate() {
  local snap="$1"
  if ! bm::core::is_tty; then
    bm::plan::_gate_no_tty
    return "$BM_EX_PARTIAL"
  fi
  bm::ui::_ensure_init
  if bm::ui::fancy; then
    bm::plan::_gate_fancy "$snap"
    return $?
  fi

  local key remaining now rc crc
  # Keys typed while the plan ran are not answers: the operator has not seen
  # the verification result yet.
  while IFS= read -rsn1 -t 0.01 key; do :; done
  bm::lock::release
  while :; do
    if bm::plan::_gate_settled "$snap"; then
      bm::plan::_gate_report_settled
      return $?
    fi
    printf -v now '%(%s)T' -1
    remaining=$(( ${BM_CKPT_DEADLINE:-0} - now ))
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      remaining=999999 # no timer armed; purely manual decision
    fi
    if (( remaining <= 0 )); then
      # the deadman timer may be restoring right now: wait for it
      crc=0
      bm::plan::_gate_claim "$snap" 120 || crc=$?
      if (( crc == 1 )); then return "$BM_GATE_RC"; fi
      bm::plan::_gate_expired "$snap"
      return $?
    fi
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      printf '\rVerification passed. c=commit r=rollback : '
    elif [[ "$BM_CKPT_TIER" == checkpoint ]]; then
      printf '\rVerification passed. c=commit r=rollback e=extend (auto-rollback in %4ds) : ' "$remaining"
    else # only a checkpoint can be extended
      printf '\rVerification passed. c=commit r=rollback (auto-rollback in %4ds) : ' "$remaining"
    fi
    rc=0
    read -r -t 2 -n 1 key || rc=$?
    if (( rc > 128 )); then
      continue # timeout: refresh the countdown
    fi
    if (( rc != 0 )); then
      echo
      bm::plan::_gate_no_tty
      return "$BM_EX_PARTIAL"
    fi
    echo
    case "$key" in
      c | C | k | K | r | R | u | U | e | E)
        crc=0
        bm::plan::_gate_claim "$snap" || crc=$?
        if (( crc == 1 )); then return "$BM_GATE_RC"; fi
        if (( crc == 2 )); then
          bm::log::say "Another bond-manager is busy right now; press the key again in a moment."
          continue
        fi
        ;;
    esac
    case "$key" in
      c | C | k | K)
        bm::plan::_gate_keep
        return $?
        ;;
      r | R | u | U)
        bm::plan::_gate_undo "$snap"
        return $?
        ;;
      e | E)
        if bm::plan::_gate_extend "$remaining"; then
          bm::log::say "extended by 300s"
        else
          bm::log::say "Only a NetworkManager checkpoint can be extended; this change is protected differently."
        fi
        bm::lock::release
        ;;
      *)
        bm::log::say "Press c (or K) to keep the change, r (or U) to undo it."
        ;;
    esac
  done
}

bm::plan::_gate_fancy() { # _gate_fancy <snapshot-id>
  local snap="$1" remaining now rc msg="" grc crc cols
  bm::ui::_size
  cols="$BM_UI_COLS"
  bm::ui::gate_intro "$BM_CKPT_TIER"
  bm::ui::_raw_on
  bm::ui::_drain
  bm::lock::release
  while :; do
    # nothing traps SIGWINCH here: look at the size every tick, and redraw
    # everything after a resize (the old lines have reflowed)
    bm::ui::_size
    if [[ "$BM_UI_COLS" != "$cols" ]]; then
      cols="$BM_UI_COLS"
      printf '\033[H\033[2J' >&2
      bm::ui::gate_intro "$BM_CKPT_TIER"
    fi
    if bm::plan::_gate_settled "$snap"; then
      bm::ui::_raw_off
      bm::ui::_commit_block
      bm::plan::_gate_report_settled
      return $?
    fi
    printf -v now '%(%s)T' -1
    remaining=$(( ${BM_CKPT_DEADLINE:-0} - now ))
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      remaining=999999
    fi
    if (( remaining <= 0 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      crc=0
      bm::plan::_gate_claim "$snap" 120 || crc=$?
      if (( crc == 1 )); then return "$BM_GATE_RC"; fi
      bm::plan::_gate_expired "$snap"
      return $?
    fi
    bm::ui::gate_status "$remaining" "$BM_CKPT_TIER" "$msg"
    rc=0
    bm::ui::read_key 1 || rc=$?
    if (( rc == 2 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      echo
      bm::plan::_gate_no_tty
      return "$BM_EX_PARTIAL"
    fi
    (( rc == 0 )) || continue
    msg=""
    case "$BM_UI_KEY" in
      k | K | c | C | u | U | r | R | e | E)
        crc=0
        bm::plan::_gate_claim "$snap" 5 >/dev/null 2>&1 || crc=$?
        if (( crc == 2 )); then
          msg="Another bond-manager is busy right now; press the key again in a moment."
          continue
        fi
        if (( crc == 1 )); then
          bm::ui::_raw_off
          bm::ui::_commit_block
          bm::plan::_gate_report_settled || true
          return "$BM_GATE_RC"
        fi
        ;;
    esac
    case "$BM_UI_KEY" in
      k | K | c | C)
        bm::ui::_raw_off
        bm::ui::_commit_block
        grc=0
        bm::plan::_gate_keep || grc=$?
        return "$grc"
        ;;
      u | U | r | R)
        bm::ui::_raw_off
        bm::ui::_commit_block
        grc=0
        bm::plan::_gate_undo "$snap" || grc=$?
        return "$grc"
        ;;
      e | E)
        if [[ "$BM_CKPT_TIER" != checkpoint ]]; then
          msg="Extending is only possible with NetworkManager's automatic undo."
        elif bm::plan::_gate_extend "$remaining"; then
          msg="Added 5 minutes."
        else
          msg="Could not extend - decide before the time runs out."
        fi
        bm::lock::release
        ;;
      RESIZE)
        BM_UI_RESIZED=0
        bm::ui::_size
        ;;
      *)
        msg="Press K to keep the change or U to undo it."
        ;;
    esac
  done
}
