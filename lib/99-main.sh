# lib/99-main.sh — the entrypoint: global flag parsing and dispatch to the
# commands (90-cli) or the interactive menus (95-tui). It sits last so that
# dispatching to every other module is a downward call.
# shellcheck shell=bash
[[ -n "${BM_LIB_MAIN:-}" ]] && return 0
BM_LIB_MAIN=1

bm::main() {
  bm::core::init_traps
  if (( $# )); then
    printf -v BM_CMDLINE '%q ' "$@"
  fi

  local -a args=()
  local legacy_export=""
  local legacy_status=0
  local want_help=0
  while (( $# )); do
    case "$1" in
      -n | --dry-run) BM_DRY_RUN=1; shift ;;
      -y | --yes) BM_ASSUME_YES=1; shift ;;
      --json) BM_JSON=1; shift ;;
      --debug) BM_DEBUG=1; shift ;;
      --quiet) BM_QUIET=1; shift ;;
      --no-color) BM_NO_COLOR=1; shift ;;
      --plain) BM_PLAIN=1; shift ;;
      --rollback-window) bm::cli::_need_arg "$1" "${2-}"; BM_ROLLBACK_WINDOW="$2"; shift 2 ;;
      --no-checkpoint) BM_NO_CHECKPOINT=1; shift ;;
      --force-unsafe) BM_FORCE_UNSAFE=1; shift ;;
      -V | --version) printf '%s %s\n' "$BM_PROG" "$BM_VERSION"; return 0 ;;
      -h | --help) want_help=1; shift ;;
      --status) legacy_status=1; shift ;;                       # v2.x compat
      --export-json) bm::cli::_need_arg "$1" "${2-}"; legacy_export="$2"; shift 2 ;; # v2.x compat
      --) shift; while (( $# )); do args+=("$1"); shift; done ;;
      *) args+=("$1"); shift ;;
    esac
  done

  bm::core::init_color
  bm::config::load

  # --help anywhere: before a command it is the overview, after one it is
  # that command's own help (so "swap-member --help" does what people expect).
  if (( want_help )); then
    if [[ -n "${args[0]:-}" ]] && bm::help::is_command "${args[0]}"; then
      bm::help::command "${args[0]}"
    else
      bm::cli::usage
    fi
    return 0
  fi
  # The deadman timer re-executes this program from systemd, so BM_SELF must
  # be the entrypoint that was actually invoked ($0) — not the module file
  # that happens to define bm::main, which is what BASH_SOURCE[0] resolves to
  # under the dev entrypoint (and is not executable).
  BM_SELF="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  if [[ ! -x "$BM_SELF" ]]; then
    BM_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
  fi

  if [[ -n "$BM_ROLLBACK_WINDOW" ]] && ! bm::val::uint "$BM_ROLLBACK_WINDOW" 10 86400; then
    bm::core::die "--rollback-window must be 10..86400 seconds" "$BM_EX_USAGE"
  fi

  # legacy one-flag invocations
  if [[ -n "$legacy_export" ]]; then
    bm::cli::preflight_read
    mkdir -p "$(dirname "$legacy_export")"
    BM_JSON=1
    bm::cli::_bonds_json_doc >"$legacy_export"
    echo "JSON written to $legacy_export"
    if (( legacy_status )); then
      BM_JSON=0
      local lrc=0
      bm::cli::cmd_status || lrc=$?
      return "$lrc"
    fi
    return 0
  fi
  if (( legacy_status )); then
    args=(status)
  fi

  local cmd="${args[0]:-}"
  local -a rest=("${args[@]:1}")
  BM_CUR_CMD="$(bm::help::canonical "$cmd" 2>/dev/null || true)"

  if [[ -z "$cmd" ]]; then
    if bm::core::is_tty; then
      local trc=0
      bm::tui::main || trc=$?
      return "$trc"
    fi
    bm::cli::usage >&2
    return "$BM_EX_USAGE"
  fi

  local rc=0
  case "$cmd" in
    list) bm::cli::cmd_list "${rest[@]}" || rc=$? ;;
    show) bm::cli::cmd_show "${rest[@]}" || rc=$? ;;
    status) bm::cli::cmd_status "${rest[@]}" || rc=$? ;;
    diagnose) bm::cli::cmd_diagnose "${rest[@]}" || rc=$? ;;
    doctor) bm::cli::cmd_doctor "${rest[@]}" || rc=$? ;;
    create) bm::cli::cmd_create "${rest[@]}" || rc=$? ;;
    modify) bm::cli::cmd_modify "${rest[@]}" || rc=$? ;;
    add-member) bm::cli::cmd_add_member "${rest[@]}" || rc=$? ;;
    remove-member) bm::cli::cmd_remove_member "${rest[@]}" || rc=$? ;;
    swap-member) bm::cli::cmd_swap_member "${rest[@]}" || rc=$? ;;
    remove | delete) bm::cli::cmd_remove "${rest[@]}" || rc=$? ;;
    vlan) bm::cli::cmd_vlan "${rest[@]}" || rc=$? ;;
    clone) bm::cli::cmd_clone "${rest[@]}" || rc=$? ;;
    repair) bm::cli::cmd_repair "${rest[@]}" || rc=$? ;;
    verify) bm::cli::cmd_verify "${rest[@]}" || rc=$? ;;
    snapshot) bm::cli::cmd_snapshot "${rest[@]}" || rc=$? ;;
    commit) bm::cli::cmd_commit "${rest[@]}" || rc=$? ;;
    rollback) bm::cli::cmd_rollback "${rest[@]}" || rc=$? ;;
    bundle | support-bundle) bm::cli::cmd_bundle "${rest[@]}" || rc=$? ;;
    init) bm::cli::cmd_init "${rest[@]}" || rc=$? ;;
    config) bm::cli::cmd_config "${rest[@]}" || rc=$? ;;
    completion) bm::cli::cmd_completion "${rest[@]}" || rc=$? ;;
    nics) bm::cli::cmd_nics "${rest[@]}" || rc=$? ;;
    tui) bm::tui::main || rc=$? ;;
    help) bm::cli::cmd_help "${rest[@]}" || rc=$? ;;
    version) printf '%s %s\n' "$BM_PROG" "$BM_VERSION" ;;
    *)
      printf '%s: unknown command "%s"\n' "$BM_PROG" "$cmd" >&2
      local sug
      sug="$(bm::help::suggest_command "$cmd")"
      if [[ -n "$sug" ]]; then
        printf '  Did you mean: %s %s\n' "$BM_PROG" "$sug" >&2
      fi
      printf '  See every command: %s help   (or run %s with no arguments for menus)\n' \
        "$BM_PROG" "$BM_PROG" >&2
      rc="$BM_EX_USAGE"
      ;;
  esac
  return "$rc"
}
