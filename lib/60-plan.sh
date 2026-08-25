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

# ---- plan model -----------------------------------------------------------

BM_PLAN_DESCS=()
BM_PLAN_CMDS=()

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
  if [[ "$v" =~ ^[A-Za-z0-9_@%+=:,./-]*$ ]]; then
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
  local egress
  egress="$(bm::facts::ssh_egress_dev || true)"
  [[ -n "$egress" ]] || return 0
  local dev
  for dev in "$@"; do
    [[ "$dev" == "$egress" ]] || continue
    if [[ "$tier" == checkpoint ]]; then
      bm::log::say "$(bm::core::c_warn "NOTE: this change touches '$egress', which carries your SSH session.")"
      bm::log::say "$(bm::core::c_warn "NetworkManager will auto-rollback in $(bm::plan::_window)s unless you commit.")"
      return 0
    fi
    if (( BM_FORCE_UNSAFE )); then
      bm::log::say "$(bm::core::c_warn "WARNING: proceeding without checkpoint protection on your SSH egress device ($egress).")"
      return 0
    fi
    printf '%s: %s this change touches %s, which carries your SSH session, and NetworkManager checkpoints are unavailable (tier: %s).\nUse a console, or re-run with --force-unsafe to accept the risk of losing access.\n' \
      "$BM_PROG" "$(bm::core::c_err ERROR:)" "'$egress'" "$tier" >&2
    return 1
  done
  return 0
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
    bm::log::say "Nothing to do — already in the requested state."
    return "$BM_EX_OK"
  fi

  if (( BM_DRY_RUN )); then
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
  if ! (( BM_ASSUME_YES )); then
    if ! bm::ui::yesno "Apply this plan?"; then
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
    bm::ckpt::rollback_pending || bm::log::warn "rollback reported problems; inspect manually"
    bm::log::say "rolled back to snapshot $snap"
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
    bm::ckpt::rollback_pending || bm::log::warn "rollback reported problems; inspect manually"
    bm::log::say "rolled back to snapshot $snap"
    return "$BM_EX_VERIFY"
  fi

  # Applying consumed part of the rollback window; give the operator (or the
  # next session) a full window to decide from here.
  bm::ckpt::rebudget "$window" || true

  if (( BM_ASSUME_YES )); then
    local crc=0
    bm::ckpt::commit >/dev/null || crc=$?
    if (( crc == BM_EX_CKPT_LOST )); then
      bm::log::say "$(bm::core::c_err "the checkpoint expired before it could be committed — NetworkManager has most likely rolled this change back")"
      return "$BM_EX_VERIFY"
    fi
    bm::log::say "$(bm::core::c_ok "change applied and committed (verification passed)")"
    return "$BM_EX_OK"
  fi

  bm::plan::commit_gate "$snap"
}

# Interactive commit gate: count down toward the auto-rollback deadline.
bm::plan::commit_gate() {
  local snap="$1"
  if ! bm::core::is_tty; then
    # non-interactive without --yes: keep protection armed and instruct
    bm::log::say "No TTY to confirm on. Protection stays armed:"
    bm::log::say "  confirm with:   $BM_PROG commit"
    bm::log::say "  or revert with: $BM_PROG rollback"
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      bm::log::say "$(bm::core::c_warn "Snapshot-only protection: nothing will roll this back automatically.")"
    else
      bm::log::say "Auto-rollback at the deadline if you do neither."
    fi
    return "$BM_EX_PARTIAL"
  fi

  local key remaining
  while :; do
    remaining=$(( ${BM_CKPT_DEADLINE:-0} - $(bm::core::epoch) ))
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      remaining=999999 # no timer armed; purely manual decision
    fi
    if (( remaining <= 0 )); then
      echo
      bm::log::say "$(bm::core::c_err "auto-rollback deadline reached — the change has been reverted")"
      bm::ckpt::clear_pending
      return "$BM_EX_VERIFY"
    fi
    if [[ "$BM_CKPT_TIER" == snapshot ]]; then
      printf '\rVerification passed. c=commit r=rollback : '
    else
      printf '\rVerification passed. c=commit r=rollback e=extend (auto-rollback in %4ds) : ' "$remaining"
    fi
    if read -r -t 2 -n 1 key; then
      echo
      case "$key" in
        c | C)
          local crc=0
          bm::ckpt::commit >/dev/null || crc=$?
          if (( crc == BM_EX_CKPT_LOST )); then
            bm::log::say "$(bm::core::c_err "the checkpoint had already expired — NetworkManager has most likely rolled this change back")"
            bm::log::say "check the result with: $BM_PROG status"
            return "$BM_EX_VERIFY"
          fi
          bm::log::say "$(bm::core::c_ok "change committed")"
          return "$BM_EX_OK"
          ;;
        r | R)
          bm::ckpt::rollback_pending || bm::log::warn "rollback reported problems"
          bm::log::say "rolled back to snapshot $snap"
          return "$BM_EX_VERIFY"
          ;;
        e | E)
          if [[ "$BM_CKPT_TIER" == checkpoint && -n "$BM_CKPT_PATH" ]]; then
            local add=300
            if bm::ckpt::dbus_extend "$BM_CKPT_PATH" $(( remaining + add )); then
              BM_CKPT_DEADLINE=$(( $(bm::core::epoch) + remaining + add ))
              bm::log::say "extended by ${add}s"
            fi
          fi
          ;;
      esac
    fi
  done
}
