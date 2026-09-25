# lib/95-tui.sh — the guided menus. Everything here is presentation: every
# change still goes through the same workflow code as the CLI (70), so every
# guard (validation, snapshot, checkpoint, verification) applies identically.
#
# Rules this module lives by:
#   - every action runs in a subshell via bm::tui::run, so a validation error
#     (die = exit) or a lock taken by commit/rollback can never escape into
#     the menus; the menus themselves never take the lock and never die
#   - nothing is typed that could be picked from a list
#   - the operator always sees where they are, what happens next, and how
#     to go back; practice mode (BM_DRY_RUN) is one key away
# shellcheck shell=bash
[[ -n "${BM_LIB_TUI:-}" ]] && return 0
BM_LIB_TUI=1

BM_TUI_OUT=""            # fd duplicating the real stdout
BM_TUI_STTY0=""          # terminal settings when the menus started
BM_TUI_FORCED_PRACTICE=0 # practice because changes are impossible (not root...)
BM_TUI_HOST=""
BM_TUI_TIER=""
BM_TUI_SAFETY_LINE=""
BM_TUI_SSH_DEV=""
BM_TUI_SSH_PARENT=""
BM_TUI_BONDS=()          # every bond: kernel ∪ NetworkManager profiles
BM_TUI_MANAGED=()        # bonds with a NetworkManager profile
BM_TUI_DASH=()           # dashboard lines, full detail
BM_TUI_DASH_SHORT=()     # dashboard lines, one per bond
BM_TUI_MARK=""
BM_TUI_LEFT=0
BM_TUI_LAST_RC=0
BM_TUI_LAST_OUTCOME=""
BM_TUI_IP4="" BM_TUI_GW4="" BM_TUI_DNS4=""
BM_TUI_IP6="" BM_TUI_GW6="" BM_TUI_DNS6=""
BM_TUI_FAMILY=4
BM_TUI_CTX_BOND=""
BM_TUI_CTX_OPT=""
BM_TUI_AFFECTED=()

# ---- lifecycle ----------------------------------------------------------------

bm::tui::main() {
  bm::cli::preflight_read
  bm::ui::init --force
  if (( BM_ASSUME_YES )); then
    BM_ASSUME_YES=0
    bm::ui::warn "-y/--yes is ignored in the menus: every change asks you first."
  fi
  exec {BM_TUI_OUT}>&1
  if bm::ui::fancy; then
    BM_TUI_STTY0="$(stty -g 2>/dev/null || true)"
  fi
  trap 'BM_UI_INTERRUPTED=1' INT
  trap 'BM_UI_RESIZED=1' WINCH
  trap 'bm::core::cleanup; exit 129' HUP
  trap 'bm::core::cleanup; exit 143' TERM

  bm::ui::dim "Checking this server..."
  bm::tui::_refresh
  if ! bm::cli::mutate_blocker; then
    # Already asked for practice (-n)? Then there is nothing to explain yet;
    # the badge says "look only" and switching it off explains why not.
    if ! (( BM_DRY_RUN )); then
      bm::tui::_explain_forced
    fi
    BM_DRY_RUN=1
    BM_TUI_FORCED_PRACTICE=1
  fi

  bm::tui::_loop

  trap - INT WINCH HUP TERM
  bm::tui::_term_reset
  if bm::tui::_pending; then
    bm::ui::warn "A change is still waiting to be kept: \"${BM_PENDING_SUMMARY:-?}\"."
    bm::tui::_pending_how_to
  fi
  bm::ui::dim "Bye. (Tip: '$BM_PROG help' explains every command.)"
  return 0
}

bm::tui::_term_reset() {
  if [[ -n "$BM_TUI_STTY0" && -t 0 ]]; then
    stty "$BM_TUI_STTY0" 2>/dev/null || true
  fi
  BM_TTY_SAVED=""
  if bm::ui::fancy; then
    printf '\033[?25h\033[0m' >&2
  fi
  BM_TTY_CURSOR_HIDDEN=0
  BM_UI_DRAWN=0
  return 0
}

bm::tui::_explain_forced() {
  bm::ui::clear
  bm::ui::heading "Practice mode is on"
  bm::ui::note "$BM_CLI_BLOCKER_MSG"
  bm::ui::note "You can still look at everything, and go through every change to see exactly what it would do - nothing on the server is touched."
  if [[ "$BM_CLI_BLOCKER" == not-root ]]; then
    bm::ui::info "To make real changes: quit (q) and run:  sudo $BM_PROG"
  fi
  bm::ui::pause "Press Enter to continue"
}

# Gather everything the dashboard shows. Slow-ish (nmcli, ip, busctl), so
# it runs on start, after every action and on 'r' — never per keypress.
bm::tui::_refresh() {
  BM_TUI_HOST="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo localhost)"
  BM_TUI_TIER="$(bm::ckpt::probe_tier 2>/dev/null || echo snapshot)"
  BM_TUI_SSH_DEV="$(bm::facts::ssh_egress_dev 2>/dev/null || true)"
  BM_TUI_SSH_PARENT=""
  if [[ -n "$BM_TUI_SSH_DEV" ]]; then
    BM_TUI_SSH_PARENT="$(bm::facts::vlan_parent "$BM_TUI_SSH_DEV")"
  fi
  mapfile -t BM_TUI_BONDS < <(bm::cli::all_bonds 2>/dev/null || true)
  mapfile -t BM_TUI_MANAGED < <(bm::nm::bond_cons 2>/dev/null \
    | awk -F'\x1f' '{ print ($3 != "" ? $3 : $2) }' | LC_ALL=C sort -u | sed '/^$/d')
  case "$BM_TUI_TIER" in
    checkpoint | deadman) BM_TUI_SAFETY_LINE="$BM_S_GREEN$BM_G_OK$BM_S_RST Safety net: $(bm::help::tier_short "$BM_TUI_TIER")" ;;
    *) BM_TUI_SAFETY_LINE="$BM_S_YELLOW$BM_G_WARN Safety net: $(bm::help::tier_short "$BM_TUI_TIER")$BM_S_RST" ;;
  esac
  bm::tui::_build_dash
}

bm::tui::_pending() { # 0 when a change waits to be kept; sets BM_TUI_LEFT
  BM_TUI_LEFT=0
  bm::ckpt::load_pending 2>/dev/null || return 1
  local now dl="${BM_PENDING_DEADLINE:-0}"
  [[ "$dl" =~ ^[0-9]+$ ]] || dl=0
  printf -v now '%(%s)T' -1
  BM_TUI_LEFT=$(( dl - now ))
  if (( BM_TUI_LEFT < 0 )); then BM_TUI_LEFT=0; fi
  return 0
}

bm::tui::_pending_how_to() {
  local at=""
  if [[ "${BM_PENDING_TIER:-}" != snapshot && "${BM_PENDING_DEADLINE:-}" =~ ^[0-9]+$ ]]; then
    printf -v at '%(%H:%M:%S)T' "$BM_PENDING_DEADLINE"
    bm::ui::note "If nobody keeps it, it is undone automatically at $at."
  else
    bm::ui::note "Nothing will undo it automatically on this server."
  fi
  bm::ui::note "Keep it:  sudo $BM_PROG commit      Undo it:  sudo $BM_PROG rollback"
}

bm::tui::_is_managed() { bm::core::in_list "$1" "${BM_TUI_MANAGED[@]:-}"; }

# ---- dashboard ----------------------------------------------------------------

bm::tui::_ssh_mark() { # _ssh_mark <dev> -> BM_TUI_MARK
  BM_TUI_MARK=""
  if [[ -n "$BM_TUI_SSH_DEV" && "$1" == "$BM_TUI_SSH_DEV" ]]; then
    BM_TUI_MARK="  $BM_S_YELLOW$BM_G_LARR your SSH connection$BM_S_RST"
  fi
  return 0
}

bm::tui::_first_addr() { # _first_addr <dev> -> BM_TUI_ADDR ("10.0.0.5/24 +1")
  local -a a=()
  mapfile -t a < <(bm::facts::dev_addrs "$1" 2>/dev/null | grep -v '^fe80:' || true)
  BM_TUI_ADDR="${a[0]:-}"
  if (( ${#a[@]} > 1 )); then BM_TUI_ADDR+=" +$(( ${#a[@]} - 1 ))"; fi
  return 0
}

bm::tui::_build_dash() {
  BM_TUI_DASH=()
  BM_TUI_DASH_SHORT=()
  if (( ${#BM_TUI_BONDS[@]} == 0 )); then
    BM_TUI_DASH=("No bonds on this server yet." "Pick \"Build a new bond\" below to make one.")
    BM_TUI_DASH_SHORT=("${BM_TUI_DASH[@]}")
    return 0
  fi
  local b
  for b in "${BM_TUI_BONDS[@]}"; do
    bm::tui::_dash_bond "$b"
  done
  return 0
}

bm::tui::_dash_bond() {
  local b="$1" health verdict mode short col word line
  if ! bm::facts::bond_exists_kernel "$b"; then
    line="$BM_S_DIM$BM_G_ODOT $b   saved in NetworkManager, not running$BM_S_RST"
    BM_TUI_DASH+=("$line")
    BM_TUI_DASH_SHORT+=("$line")
    return 0
  fi
  health="$(bm::facts::bond_health "$b")"
  verdict="${health%%$'\n'*}"
  local -a reasons=() members=()
  mapfile -t reasons < <(tail -n +2 <<<"$health" | sed '/^$/d')
  mode="$(bm::facts::bond_mode "$b")"
  short="$(bm::help::mode_short "$mode")"
  case "$verdict" in
    healthy) col="$BM_S_GREEN" ;;
    degraded) col="$BM_S_YELLOW" ;;
    *) col="$BM_S_RED" ;;
  esac
  word="$(bm::help::health_word "$verdict")"
  bm::tui::_first_addr "$b"
  bm::tui::_ssh_mark "$b"
  BM_TUI_DASH+=("$col$BM_G_DOT$BM_S_RST $BM_S_BOLD$b$BM_S_RST  $mode ($short)  $col$word$BM_S_RST${BM_TUI_ADDR:+   $BM_TUI_ADDR}$BM_TUI_MARK")
  local short_mark="$BM_TUI_MARK"

  mapfile -t members < <(bm::facts::bond_members "$b")
  local active i m mii tree link spd act up=0 n=${#members[@]}
  active="$(bm::facts::bond_proc_value "$b" "Currently Active Slave")"
  local -a vl=()
  mapfile -t vl < <(bm::facts::kernel_vlans | awk -v p="$b" '$3 == p')
  for i in "${!members[@]}"; do
    m="${members[$i]}"
    tree="$BM_G_TEE"
    if (( i == n - 1 && ${#vl[@]} == 0 )); then tree="$BM_G_END"; fi
    mii="$(bm::facts::bond_member_mii "$b" "$m")"
    if [[ "$mii" == up ]]; then
      link="${BM_S_GREEN}up$BM_S_RST     "
      up=$(( up + 1 ))
    else
      link="${BM_S_RED}no link$BM_S_RST"
    fi
    bm::facts::nic_info "$m" || true
    spd="$(bm::help::speed_label "$BM_NIC_SPEED")"
    act=""
    if [[ "$mode" == active-backup && "$m" == "$active" ]]; then act="  (active)"; fi
    bm::tui::_ssh_mark "$m"
    BM_TUI_DASH+=("   $BM_S_DIM$tree$BM_S_RST $m  $link  $spd$act$BM_TUI_MARK")
  done
  local v vdev vid
  for i in "${!vl[@]}"; do
    read -r vdev vid _ <<<"${vl[$i]}"
    tree="$BM_G_TEE"
    if (( i == ${#vl[@]} - 1 )); then tree="$BM_G_END"; fi
    bm::tui::_first_addr "$vdev"
    bm::tui::_ssh_mark "$vdev"
    if [[ -n "$BM_TUI_MARK" ]]; then short_mark="$BM_TUI_MARK"; fi
    v="   $BM_S_DIM$tree$BM_S_RST VLAN $vid ($vdev)${BM_TUI_ADDR:+  $BM_TUI_ADDR}$BM_TUI_MARK"
    BM_TUI_DASH+=("$v")
  done
  if [[ "$verdict" != healthy && ${#reasons[@]} -gt 0 ]]; then
    local what
    what="$(bm::help::explain_reason "${reasons[0]}" | head -n1)"
    BM_TUI_DASH+=("     $BM_S_YELLOW$BM_G_WARN $what$BM_S_RST")
  fi
  BM_TUI_DASH_SHORT+=("$col$BM_G_DOT$BM_S_RST $BM_S_BOLD$b$BM_S_RST  $mode  $col$word$BM_S_RST  ($up of $n ports up)$short_mark")
  return 0
}

bm::tui::_badge() { # -> BM_TUI_BADGE
  if (( BM_DRY_RUN )); then
    if (( BM_TUI_FORCED_PRACTICE )); then
      BM_TUI_BADGE="$BM_S_BADGE_PRACTICE PRACTICE (look only) $BM_S_RST"
    else
      BM_TUI_BADGE="$BM_S_BADGE_PRACTICE PRACTICE $BM_S_RST"
    fi
  else
    BM_TUI_BADGE="$BM_S_BADGE_LIVE LIVE $BM_S_RST"
  fi
}

# Header of the home menu: redrawn every second (the pending countdown),
# built only from cached facts plus one small file read.
bm::tui::_home_header() {
  local -a body=()
  local max="$BM_UI_HDR_MAX" banner=0
  bm::tui::_badge
  if bm::tui::_pending; then
    body+=("$BM_S_YELLOW$BM_S_BOLD$BM_G_WARN A change is waiting for you: ${BM_PENDING_SUMMARY:-?}$BM_S_RST")
    if [[ "${BM_PENDING_TIER:-}" == snapshot ]]; then
      body+=("  Nothing undoes it automatically - keep or undo it (first item below).")
    else
      bm::ui::fmt_secs "$BM_TUI_LEFT"
      body+=("  Undone automatically in $BM_S_BOLD$BM_UI_FMT$BM_S_RST unless you keep it (first item below).")
    fi
    body+=("")
    banner=3
  fi
  if (( max < 5 + banner )); then
    # no room for the box: one line that still says the essentials
    local line="$BM_S_BOLD$BM_PROG$BM_S_RST $BM_G_SEP $BM_TUI_HOST $BM_G_SEP ${#BM_TUI_BONDS[@]} bond(s) $BM_TUI_BADGE"
    if (( banner )); then
      line+="  $BM_S_YELLOW$BM_G_WARN change waiting$BM_S_RST"
    fi
    BM_UI_HDR=("$line")
    return 0
  fi
  local room=$(( max - 4 - banner ))
  if (( ${#BM_TUI_DASH[@]} <= room )); then
    body+=("${BM_TUI_DASH[@]}")
  elif (( ${#BM_TUI_DASH_SHORT[@]} <= room )); then
    body+=("${BM_TUI_DASH_SHORT[@]}")
  else
    local keep=$(( room - 1 ))
    if (( keep < 0 )); then keep=0; fi
    body+=("${BM_TUI_DASH_SHORT[@]:0:keep}")
    body+=("$BM_S_DIM...and $(( ${#BM_TUI_DASH_SHORT[@]} - keep )) more (see \"Check my bonds\")$BM_S_RST")
  fi
  body+=("")
  if (( BM_DRY_RUN )); then
    body+=("$BM_S_CYAN$BM_G_OK$BM_S_RST Practice mode: nothing on this server will be changed.")
  else
    body+=("$BM_TUI_SAFETY_LINE")
  fi
  bm::ui::box_lines "$BM_PROG $BM_VERSION $BM_G_SEP $BM_TUI_HOST" "$BM_TUI_BADGE" "" "${body[@]}"
  BM_UI_HDR=("${BM_UI_LINES[@]}")
}

# ---- home -----------------------------------------------------------------------

bm::tui::_loop() {
  local -a items
  while :; do
    if (( BM_UI_EOF )); then
      break
    fi
    bm::ui::clear
    items=()
    if bm::tui::_pending; then
      bm::ui::fmt_secs "$BM_TUI_LEFT"
      items+=(pending "Keep or undo the last change"$'\t'"$BM_UI_FMT left")
    fi
    items+=(
      check "Check my bonds"$'\t'"health, problems explained"
      move "Move a bond to a new switch"$'\t'"one cable at a time, no outage"
      build "Build a new bond"
      change "Change a bond"$'\t'"ports, mode, IP, VLANs..."
      fix "Fix a bond that looks wrong"
      safety "Undo & safety"$'\t'"waiting change, backup copies"
      tools "Tools"$'\t'"network ports, server check, support bundle"
      help "Help: what is all this?"
    )
    if (( BM_DRY_RUN )); then
      items+=(practice "Practice mode is ON"$'\t'"nothing is changed - pick to switch off")
    else
      items+=(practice "Practice mode is OFF"$'\t'"pick to try things without changing anything")
    fi
    items+=(quit "Quit")
    BM_UI_INTERRUPTED=0
    if ! bm::ui::menu --header bm::tui::_home_header --refresh 1 --keys "q p r ?" \
      --footer "$BM_G_UP$BM_G_DN move $BM_G_SEP Enter choose $BM_G_SEP 1-9 jump $BM_G_SEP p practice $BM_G_SEP r refresh $BM_G_SEP ? help $BM_G_SEP q quit" \
      -- "What do you want to do?" "${items[@]}"; then
      if (( BM_UI_EOF )); then
        break
      fi
      if (( BM_UI_INTERRUPTED )); then
        BM_UI_INTERRUPTED=0
        if bm::tui::_confirm_quit; then break; fi
      fi
      continue
    fi
    case "$BM_UI_REPLY" in
      key:q | quit)
        if bm::tui::_confirm_quit; then break; fi
        ;;
      key:p | practice) bm::tui::_toggle_practice ;;
      key:r) bm::ui::dim "Refreshing..."; bm::tui::_refresh ;;
      "key:?" | help) bm::tui::help_menu ;;
      pending) bm::tui::pending_screen ;;
      check) bm::tui::check_menu ;;
      move) bm::tui::move_wizard ;;
      build) bm::tui::build_wizard ;;
      change) bm::tui::change_menu ;;
      fix) bm::tui::fix_wizard ;;
      safety) bm::tui::safety_menu ;;
      tools) bm::tui::tools_menu ;;
    esac
  done
}

bm::tui::_confirm_quit() {
  if bm::tui::_pending; then
    bm::ui::warn "A change is still waiting to be kept: \"${BM_PENDING_SUMMARY:-?}\"."
    bm::tui::_pending_how_to
    bm::ui::yesno "Quit anyway?"
    return $?
  fi
  return 0
}

bm::tui::_toggle_practice() {
  if (( BM_DRY_RUN )); then
    if ! bm::cli::mutate_blocker; then
      bm::ui::heading "Practice mode has to stay on"
      bm::ui::note "$BM_CLI_BLOCKER_MSG"
      bm::ui::pause
      return 0
    fi
    bm::ui::heading "Switch practice mode off?"
    bm::ui::note "Changes will then really happen on this server - always with the plan shown first and the safety net armed."
    if bm::ui::yesno "Switch to LIVE mode?"; then
      BM_DRY_RUN=0
      BM_TUI_FORCED_PRACTICE=0
    fi
  else
    BM_DRY_RUN=1
  fi
  return 0
}

# ---- running actions ------------------------------------------------------------

bm::tui::_emit_outcome() { printf '%s' "${BM_PLAN_OUTCOME:-}" >&3 2>/dev/null || true; }

# EXIT trap of an action's subshell: report the outcome, and clean up what
# the action created there (its temp directory, a terminal left raw) — the
# subshell does not run the program's own EXIT trap. A scratch directory the
# subshell merely inherited belongs to the menu process and is left alone.
BM_TUI_INHERITED_TMPDIR=""
bm::tui::_action_exit() {
  bm::tui::_emit_outcome
  if [[ -n "$BM_TMPDIR" && "$BM_TMPDIR" == "$BM_TUI_INHERITED_TMPDIR" ]]; then
    BM_TMPDIR=""
  fi
  bm::core::cleanup
}

# Run one action in a subshell. kind: change (network change; checks it can
# run first), safety (commit/rollback/snapshots/bundle), look (read-only).
# Results: BM_TUI_LAST_RC, BM_TUI_LAST_OUTCOME. Never fails.
bm::tui::run() { # run <kind> <function> [args...]
  local kind="$1"
  shift
  local rc=0 out=""
  BM_PLAN_OUTCOME=""
  BM_UI_INTERRUPTED=0
  printf '\n' >&2
  out="$( (
    BM_TUI_INHERITED_TMPDIR="$BM_TMPDIR"
    trap bm::tui::_action_exit EXIT
    if [[ "$kind" == change ]]; then
      bm::cli::preflight_mutate
    fi
    "$@"
  ) 3>&1 1>&"$BM_TUI_OUT")" || rc=$?
  bm::tui::_term_reset
  if (( BM_UI_INTERRUPTED )) && (( rc == 0 || rc > 128 )); then
    rc=130
  fi
  BM_UI_INTERRUPTED=0
  BM_TUI_LAST_RC="$rc"
  BM_TUI_LAST_OUTCOME="$out"
  return 0
}

# Explain how the last action ended, then wait for Enter.
bm::tui::result() { # result [kind]
  local kind="${1:-change}" rc="$BM_TUI_LAST_RC" glyph
  printf '\n' >&2
  if [[ "$kind" == look ]] && (( rc == 0 || rc == BM_EX_DEGRADED || rc == BM_EX_DOWN || rc == 1 )); then
    bm::ui::pause
    return 0
  fi
  local waiting=0 tier=""
  if bm::tui::_pending; then
    waiting=1
    tier="${BM_PENDING_TIER:-}"
  fi
  bm::help::explain_rc "$rc" "$BM_TUI_LAST_OUTCOME" "$BM_DRY_RUN" "$tier"
  case "$BM_HELP_STYLE" in
    ok) glyph="$BM_G_OK" ;;
    err) glyph="$BM_G_BAD" ;;
    warn) glyph="$BM_G_WARN" ;;
    *) glyph="$BM_G_SEP" ;;
  esac
  local -a lines=("$BM_S_BOLD$glyph $BM_HELP_TITLE$BM_S_RST")
  local l
  for l in "${BM_HELP_LINES[@]}"; do
    bm::ui::width
    bm::ui::wrap $(( BM_UI_W - 6 )) "$l"
    lines+=("${BM_UI_WRAPPED[@]}")
  done
  if (( waiting )) && (( rc == BM_EX_PARTIAL || rc == 130 )); then
    local at=""
    if [[ "${BM_PENDING_TIER:-}" != snapshot && "${BM_PENDING_DEADLINE:-}" =~ ^[0-9]+$ ]]; then
      printf -v at '%(%H:%M:%S)T' "$BM_PENDING_DEADLINE"
      lines+=("It will be undone automatically at $at unless you keep it:" "main menu > \"Keep or undo the last change\".")
    else
      lines+=("Keep or undo it: main menu > \"Keep or undo the last change\".")
    fi
  fi
  bm::ui::box --title "Result" --style "$BM_HELP_STYLE" -- "${lines[@]}"
  bm::ui::pause
  if [[ "$kind" != look ]]; then
    bm::tui::_refresh
  fi
  return 0
}

# Changes need root, a running NetworkManager and no other change waiting.
# 0 = go ahead (possibly switched to practice), 1 = back.
bm::tui::ready_to_change() {
  if (( BM_DRY_RUN )); then
    return 0
  fi
  if ! bm::cli::mutate_blocker; then
    bm::ui::heading "This change cannot be made right now"
    bm::ui::note "$BM_CLI_BLOCKER_MSG"
    if ! bm::ui::menu -- "What now?" \
      practice "Continue in practice mode"$'\t'"see the exact plan, change nothing" \
      back "Back"; then
      return 1
    fi
    if [[ "$BM_UI_REPLY" == practice ]]; then
      BM_DRY_RUN=1
      return 0
    fi
    return 1
  fi
  if bm::tui::_pending; then
    bm::ui::heading "Finish the last change first"
    bm::ui::note "A change is still waiting to be kept or undone: \"${BM_PENDING_SUMMARY:-?}\". Only one change can be in flight at a time."
    bm::tui::pending_screen
    if bm::tui::_pending; then
      return 1
    fi
  fi
  return 0
}

# ---- validators (18-val, with messages a person can act on) --------------------

bm::tui::_v_ipv4_cidr() {
  local v="$1" a
  bm::core::split_list "$v"
  for a in "${BM_LIST[@]}"; do
    if ! bm::val::ipv4_cidr "$a"; then
      if bm::val::ipv4_addr "$a"; then
        BM_UI_VERR="Add the prefix length after a slash, e.g. $a/24."
      else
        BM_UI_VERR="'$a' is not an IPv4 address with a prefix like 10.0.0.10/24."
      fi
      return 1
    fi
  done
  return 0
}

bm::tui::_v_ipv4_addr() {
  [[ "$1" == none ]] && return 0 # removes the current value
  if bm::val::ipv4_addr "$1"; then return 0; fi
  if [[ "$1" == */* ]]; then
    BM_UI_VERR="The gateway is a plain address - leave out the /prefix."
  else
    BM_UI_VERR="'$1' is not an IPv4 address like 10.0.0.1."
  fi
  return 1
}

bm::tui::_v_dns4() {
  [[ "$1" == none ]] && return 0 # removes the current value
  if bm::val::ip_list v4 "${1// /,}"; then return 0; fi
  BM_UI_VERR="Type plain addresses separated by commas, e.g. 10.0.0.53,10.0.0.54."
  return 1
}

bm::tui::_v_ipv6_cidr() {
  local v="$1" a
  bm::core::split_list "$v"
  for a in "${BM_LIST[@]}"; do
    if ! bm::val::ipv6_cidr "$a"; then
      if bm::val::ipv6_addr "$a"; then
        BM_UI_VERR="Add the prefix length after a slash, e.g. $a/64."
      else
        BM_UI_VERR="'$a' is not an IPv6 address with a prefix like 2001:db8::10/64."
      fi
      return 1
    fi
  done
  return 0
}

bm::tui::_v_ipv6_addr() {
  [[ "$1" == none ]] && return 0 # removes the current value
  if bm::val::ipv6_addr "$1"; then return 0; fi
  if [[ "$1" == */* ]]; then
    BM_UI_VERR="The gateway is a plain address - leave out the /prefix."
  else
    BM_UI_VERR="'$1' is not an IPv6 address like 2001:db8::1."
  fi
  return 1
}

bm::tui::_v_dns6() {
  [[ "$1" == none ]] && return 0 # removes the current value
  if bm::val::ip_list v6 "${1// /,}"; then return 0; fi
  BM_UI_VERR="Type plain IPv6 addresses separated by commas, e.g. 2001:db8::53."
  return 1
}

bm::tui::_v_bond_name() {
  local v="$1"
  if ! bm::val::ifname "$v"; then
    BM_UI_VERR="Use up to 15 letters, digits, '.', '_' or '-', e.g. bond0."
    return 1
  fi
  if bm::facts::nic_exists "$v" || bm::core::in_list "$v" "${BM_TUI_BONDS[@]:-}"; then
    BM_UI_VERR="'$v' already exists - pick another name."
    return 1
  fi
  return 0
}

bm::tui::_v_vlan_new() {
  local v="$1"
  if ! bm::val::vlan_id "$v"; then
    BM_UI_VERR="A VLAN id is a number from 1 to 4094."
    return 1
  fi
  if [[ -n "$BM_TUI_CTX_BOND" ]] && bm::nm::vlan_cons "$BM_TUI_CTX_BOND" 2>/dev/null \
    | awk -F'\x1f' -v id="$v" '$4 == id { f = 1 } END { exit !f }'; then
    BM_UI_VERR="VLAN $v already exists on $BM_TUI_CTX_BOND."
    return 1
  fi
  if (( ${#BM_TUI_CTX_BOND} + 1 + ${#v} > 15 )); then
    BM_UI_VERR="$BM_TUI_CTX_BOND.$v would be longer than 15 characters."
    return 1
  fi
  return 0
}

bm::tui::_v_mtu() {
  if bm::val::mtu "$1"; then return 0; fi
  BM_UI_VERR="A number from 68 to 65535 (1500 is normal, 9000 is jumbo)."
  return 1
}

bm::tui::_v_opt_value() {
  if bm::val::option_value "$BM_TUI_CTX_OPT" "$1"; then return 0; fi
  BM_UI_VERR="That value is not valid for $BM_TUI_CTX_OPT. $(bm::help::option_help "$BM_TUI_CTX_OPT")"
  return 1
}

bm::tui::_v_ipv4_target() {
  if [[ -z "$1" ]] || bm::val::ipv4_addr "$1"; then return 0; fi
  BM_UI_VERR="Type an IPv4 address like 10.0.0.1, or leave it empty."
  return 1
}

# ---- pickers --------------------------------------------------------------------

bm::tui::_next_bond_name() { # -> BM_UI_REPLY-free: prints e.g. bond1
  local i=0
  while bm::facts::nic_exists "bond$i" || bm::core::in_list "bond$i" "${BM_TUI_BONDS[@]:-}"; do
    i=$(( i + 1 ))
  done
  printf 'bond%s' "$i"
}

bm::tui::_bond_label() { # _bond_label <bond> -> BM_TUI_LABEL
  local b="$1" mode verdict members
  if bm::facts::bond_exists_kernel "$b"; then
    mode="$(bm::facts::bond_mode "$b")"
    verdict="$(bm::facts::bond_health "$b" | head -n1)"
    members="$(bm::facts::bond_members "$b" | paste -sd, - | sed 's/,/, /g')"
    BM_TUI_LABEL="$b"$'\t'"$mode $BM_G_SEP $(bm::help::health_word "$verdict") $BM_G_SEP ports: ${members:-none}"
  else
    BM_TUI_LABEL="$b"$'\t'"saved, not running"
  fi
  bm::tui::_ssh_mark "$b"
  local -a mem=()
  mapfile -t mem < <(bm::facts::bond_members "$b")
  if [[ -n "$BM_TUI_MARK" || ( -n "$BM_TUI_SSH_PARENT" && "$BM_TUI_SSH_PARENT" == "$b" ) ]] \
    || { [[ -n "$BM_TUI_SSH_DEV" ]] && bm::core::in_list "$BM_TUI_SSH_DEV" "${mem[@]:-}"; }; then
    BM_TUI_LABEL+=" $BM_G_SEP your SSH connection"
  fi
  return 0
}

bm::tui::pick_bond() { # pick_bond [--managed] <title> -> BM_UI_REPLY
  local managed=0
  if [[ "${1:-}" == --managed ]]; then
    managed=1
    shift
  fi
  local title="$1" b
  local -a items=() skipped=()
  for b in "${BM_TUI_BONDS[@]}"; do
    if (( managed )) && ! bm::tui::_is_managed "$b"; then
      skipped+=("$b")
      continue
    fi
    bm::tui::_bond_label "$b"
    items+=("$b" "$BM_TUI_LABEL")
  done
  if (( ${#items[@]} == 0 )); then
    if (( ${#skipped[@]} > 0 )); then
      bm::ui::warn "The bonds on this server (${skipped[*]}) are not managed by NetworkManager - they were made by hand or by another tool, so bond-manager cannot change them safely."
    else
      bm::ui::note "There are no bonds on this server yet. Pick \"Build a new bond\" in the main menu to make one."
    fi
    bm::ui::pause
    return 1
  fi
  if (( ${#skipped[@]} > 0 )); then
    bm::ui::dim "Not shown (not managed by NetworkManager): ${skipped[*]}"
  fi
  if (( ${#items[@]} == 2 )); then
    BM_UI_REPLY="${items[0]}"
    bm::ui::note "Using $BM_UI_REPLY (the only bond)."
    return 0
  fi
  bm::ui::menu -- "$title" "${items[@]}"
}

# pick_nics --free|--members BOND [--single] [--min N] [--max N]
#           [--exclude a,b] -- TITLE     -> BM_UI_REPLY (comma list)
bm::tui::pick_nics() {
  local src="" bond="" single=0 min=1 max=0 exclude=""
  while (( $# )); do
    case "$1" in
      --free) src=free; shift ;;
      --members) src=members; bond="$2"; shift 2 ;;
      --single) single=1; shift ;;
      --min) min="$2"; shift 2 ;;
      --max) max="$2"; shift 2 ;;
      --exclude) exclude="$2"; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  local title="$1" n
  local -a cands=() items=() inbond=() risky_ip=() risky_ssh=() risky_link=()
  if [[ "$src" == members ]]; then
    mapfile -t cands < <(bm::facts::bond_members "$bond")
  else
    mapfile -t cands < <(bm::facts::eligible_nics)
  fi
  local active=""
  if [[ "$src" == members ]]; then
    active="$(bm::facts::bond_proc_value "$bond" "Currently Active Slave")"
  fi
  for n in "${cands[@]}"; do
    [[ -n "$n" ]] || continue
    if [[ ",$exclude," == *",$n,"* ]]; then continue; fi
    # VLAN devices (eth0.100) match the NIC patterns but are not ports
    if [[ "$src" == free && "$n" == *.* ]]; then continue; fi
    bm::facts::nic_info "$n" || continue
    if [[ "$src" == free && -n "$BM_NIC_MASTER" ]]; then
      inbond+=("$n ($BM_NIC_MASTER)")
      continue
    fi
    local label="" notes="" link spd
    # no link only matters for a port being added; removing or replacing
    # a dead port is exactly what it needs
    case "$BM_NIC_LINK" in
      up) link=up ;;
      no-link) link="NO LINK"; [[ "$src" == free ]] && risky_link+=("$n") ;;
      off) link="switched off"; [[ "$src" == free ]] && risky_link+=("$n") ;;
      *) link="link ?" ;;
    esac
    local ssh_here=0
    if [[ "$n" == "$BM_TUI_SSH_DEV" || ( -n "$BM_TUI_SSH_PARENT" && "$n" == "$BM_TUI_SSH_PARENT" ) ]]; then
      ssh_here=1 # the session runs on this port, or on a VLAN on it
    fi
    spd="$(bm::help::speed_label "$BM_NIC_SPEED")"
    notes="$link $BM_G_SEP $spd"
    if [[ "$src" == members && "$n" == "$active" ]]; then notes+=" $BM_G_SEP active now"; fi
    if [[ "$src" == free ]]; then
      bm::tui::_first_addr "$n"
      if [[ -n "$BM_TUI_ADDR" ]]; then
        notes+=" $BM_G_SEP has IP $BM_TUI_ADDR (in use?)"
        risky_ip+=("$n")
      fi
      if (( ssh_here )); then
        notes+=" $BM_G_SEP YOUR SSH CONNECTION"
        risky_ssh+=("$n")
      elif [[ -z "$BM_TUI_ADDR" && "$BM_NIC_LINK" == up ]]; then
        notes+=" $BM_G_SEP free"
      fi
    elif (( ssh_here )); then
      notes+=" $BM_G_SEP your SSH connection"
    fi
    label="$n"$'\t'"$notes"
    items+=("$n" "$label")
  done
  if (( ${#items[@]} == 0 )); then
    if [[ "$src" == members ]]; then
      bm::ui::warn "$bond has no ports that can be picked."
    else
      bm::ui::warn "There are no free network ports to use."
      if (( ${#inbond[@]} > 0 )); then
        bm::ui::note "Already in a bond: ${inbond[*]}."
      fi
      bm::ui::note "Plug in a port (or check the NIC policy in $BM_CONF), then try again. '$BM_PROG nics --all' lists every port."
    fi
    bm::ui::pause
    return 1
  fi
  if (( ${#inbond[@]} > 0 )); then
    bm::ui::dim "Not shown - already in a bond: ${inbond[*]}"
  fi
  while :; do
    if (( single )); then
      bm::ui::menu -- "$title" "${items[@]}" || return 1
    else
      local -a copt=(--min "$min")
      if (( max > 0 )); then copt+=(--max "$max"); fi
      bm::ui::checklist "${copt[@]}" -- "$title" "${items[@]}" || return 1
    fi
    local picked="$BM_UI_REPLY" p warned=0
    local -a plist=()
    bm::core::split_list "$picked"
    plist=("${BM_LIST[@]}")
    for p in "${plist[@]}"; do
      if bm::core::in_list "$p" "${risky_ssh[@]:-}"; then
        bm::ui::warn "$p carries your SSH connection. Putting it into a bond changes how it is set up, which will cut your session (the safety net then undoes it)."
        warned=1
      elif bm::core::in_list "$p" "${risky_ip[@]:-}"; then
        bm::ui::warn "$p has an IP address, so something probably uses it. Putting it into a bond removes that address."
        warned=1
      elif bm::core::in_list "$p" "${risky_link[@]:-}"; then
        bm::ui::warn "$p has no link right now (cable unplugged, or switch port off). It will not carry traffic until it has one."
        warned=1
      fi
    done
    if (( warned )); then
      if ! bm::ui::yesno "Use ${picked//,/, } anyway?"; then
        (( BM_UI_EOF )) && return 1
        continue
      fi
    fi
    BM_UI_REPLY="$picked"
    return 0
  done
}

# Mode picker with the safe choice first. -> BM_UI_REPLY
bm::tui::pick_mode() { # pick_mode [--current MODE]
  local cur=""
  if [[ "${1:-}" == --current ]]; then cur="$2"; fi
  local c1="" c2=""
  [[ "$cur" == active-backup ]] && c1=" (current)"
  [[ "$cur" == 802.3ad ]] && c2=" (current)"
  while :; do
    if ! bm::ui::menu --default "${cur:-active-backup}" -- "How should the ports work together?" \
      active-backup "active-backup - simple failover$c1"$'\t'"recommended if unsure $BM_G_SEP any switch" \
      802.3ad "802.3ad - LACP, all ports busy$c2"$'\t'"the switch MUST be set up for LACP" \
      more "Other modes (advanced)..."; then
      return 1
    fi
    if [[ "$BM_UI_REPLY" == more ]]; then
      local -a items=()
      local m mark
      for m in balance-alb balance-tlb balance-xor balance-rr broadcast; do
        mark=""
        [[ "$m" == "$cur" ]] && mark=" (current)"
        items+=("$m" "$m$mark"$'\t'"$(bm::help::mode_label "$m")")
      done
      bm::ui::menu -- "Other modes" "${items[@]}" || continue
      local picked="$BM_UI_REPLY"
      if [[ "$(bm::help::mode_switch_needs "$picked")" == static ]]; then
        bm::ui::warn "$picked needs the switch ports set up as a static port-channel (no LACP). Without that, traffic will be lost."
        bm::ui::yesno "Is the switch set up for it?" || continue
      fi
      BM_UI_REPLY="$picked"
      return 0
    fi
    if [[ "$BM_UI_REPLY" == 802.3ad && "$cur" != 802.3ad ]]; then
      bm::ui::note "LACP is a deal between this server AND the switch: the switch ports must be configured as one LACP bundle (port-channel / LAG) first."
      if ! bm::ui::yesno "Has the network team set up these switch ports for LACP?"; then
        (( BM_UI_EOF )) && return 1
        bm::ui::note "Without that the bond comes up but passes no traffic (bond-manager's checks would notice and undo it)."
        if ! bm::ui::menu -- "What now?" \
          ab "Use active-backup instead (recommended)"$'\t'"works with any switch" \
          lacp "Use 802.3ad anyway"$'\t'"the switch is ready" \
          back "Back"; then
          continue
        fi
        case "$BM_UI_REPLY" in
          ab) BM_UI_REPLY="active-backup" ;;
          lacp) BM_UI_REPLY=802.3ad ;;
          *) continue ;;
        esac
      fi
    fi
    return 0
  done
}

# Ask for IPv4 settings -> BM_TUI_IP4/GW4/DNS4 (IP4 dhcp|none|CIDR|"" = keep)
# A typed list ("10.0.0.53, 10.0.0.54" or with spaces) as one comma list, so
# it survives being put into a command line or a --vlan value.
bm::tui::_csv() { # _csv <text> -> BM_TUI_CSV
  bm::core::split_list "$1"
  BM_TUI_CSV="$(bm::core::join , "${BM_LIST[@]}")"
}

# Gateway or DNS for an existing profile: Enter keeps what it has, "none"
# removes it. -> BM_TUI_KEPT ("" = unchanged, "none", or the new value)
bm::tui::_ask_kept() { # _ask_kept <validator> <example> <label> [current]
  local v="$1" ex="$2" label="$3" cur="${4:-}"
  if [[ -n "$cur" ]]; then
    bm::ui::input --default "$cur" --validate "$v" --example "$ex" \
      -- "$label - Enter keeps $cur, none removes it" || return 1
  else
    bm::ui::input --optional --validate "$v" --example "$ex" -- "$label - Enter for none" || return 1
  fi
  BM_TUI_KEPT="$BM_UI_REPLY"
  if [[ -n "$BM_TUI_KEPT" && "$BM_TUI_KEPT" != none ]]; then
    bm::tui::_csv "$BM_TUI_KEPT"
    BM_TUI_KEPT="$BM_TUI_CSV"
  fi
  if [[ -n "$cur" && "$BM_TUI_KEPT" == "$cur" ]]; then BM_TUI_KEPT=""; fi
  return 0
}

bm::tui::ask_ip4() { # ask_ip4 [--keep] [--vlan-option] [--profile UUID] <what>
  local keep=0 vlan=0 profile=""
  while (( $# )); do
    case "$1" in
      --keep) keep=1; shift ;;
      --vlan-option) vlan=1; shift ;;
      --profile) profile="$2"; shift 2 ;;
      *) break ;;
    esac
  done
  local what="$1" cur_gw="" cur_dns=""
  BM_TUI_IP4="" BM_TUI_GW4="" BM_TUI_DNS4=""
  if [[ -n "$profile" ]]; then
    cur_gw="$(bm::nm::con_get "$profile" ipv4.gateway)"
    cur_dns="$(bm::nm::con_get "$profile" ipv4.dns)"
  fi
  local -a items=(
    dhcp "Automatic (DHCP)"$'\t'"a DHCP server hands out the address"
    static "Fixed address"$'\t'"you type it, e.g. 10.0.0.10/24"
  )
  if (( vlan )); then
    items+=(vlan "On a VLAN (tagged network)"$'\t'"only if the network team gave you a VLAN id")
  fi
  items+=(none "No IPv4 address"$'\t'"the bond carries no IPv4 itself")
  if (( keep )); then
    items+=(keep "Leave it as it is")
  fi
  bm::ui::menu -- "IPv4 address for $what" "${items[@]}" || return 1
  case "$BM_UI_REPLY" in
    dhcp) BM_TUI_IP4=dhcp ;;
    none) BM_TUI_IP4=none ;;
    keep) BM_TUI_IP4="" ;;
    vlan) BM_TUI_IP4=vlan ;;
    static)
      bm::ui::input --validate bm::tui::_v_ipv4_cidr --example "10.0.0.10/24" \
        -- "Address with prefix" || return 1
      bm::tui::_csv "$BM_UI_REPLY"
      BM_TUI_IP4="$BM_TUI_CSV"
      bm::tui::_ask_kept bm::tui::_v_ipv4_addr "10.0.0.1" "Gateway (router)" "$cur_gw" || return 1
      BM_TUI_GW4="$BM_TUI_KEPT"
      bm::tui::_ask_kept bm::tui::_v_dns4 "10.0.0.53,10.0.0.54" "DNS servers" "$cur_dns" || return 1
      BM_TUI_DNS4="$BM_TUI_KEPT"
      ;;
  esac
  return 0
}

# Ask for IPv6 settings -> BM_TUI_IP6/GW6/DNS6 (IP6 auto|dhcp|none|CIDR|"" = keep)
bm::tui::ask_ip6() { # ask_ip6 [--keep] [--profile UUID] <what>
  local keep=0 profile=""
  while (( $# )); do
    case "$1" in
      --keep) keep=1; shift ;;
      --profile) profile="$2"; shift 2 ;;
      *) break ;;
    esac
  done
  local what="$1" cur_gw="" cur_dns=""
  BM_TUI_IP6="" BM_TUI_GW6="" BM_TUI_DNS6=""
  if [[ -n "$profile" ]]; then
    cur_gw="$(bm::nm::con_get "$profile" ipv6.gateway)"
    cur_dns="$(bm::nm::con_get "$profile" ipv6.dns)"
  fi
  local -a items=(
    auto "Automatic (SLAAC)"$'\t'"the router announces the network - the usual choice"
    dhcp "DHCPv6"$'\t'"a DHCPv6 server hands out the address"
    static "Fixed address"$'\t'"you type it, e.g. 2001:db8::10/64"
    none "No IPv6"$'\t'"IPv6 switched off here"
  )
  if (( keep )); then
    items+=(keep "Leave it as it is")
  fi
  bm::ui::menu -- "IPv6 address for $what" "${items[@]}" || return 1
  case "$BM_UI_REPLY" in
    auto) BM_TUI_IP6=auto ;;
    dhcp) BM_TUI_IP6=dhcp ;;
    none) BM_TUI_IP6=none ;;
    keep) BM_TUI_IP6="" ;;
    static)
      bm::ui::input --validate bm::tui::_v_ipv6_cidr --example "2001:db8::10/64" \
        -- "Address with prefix" || return 1
      bm::tui::_csv "$BM_UI_REPLY"
      BM_TUI_IP6="$BM_TUI_CSV"
      bm::tui::_ask_kept bm::tui::_v_ipv6_addr "2001:db8::1" "Gateway (router)" "$cur_gw" || return 1
      BM_TUI_GW6="$BM_TUI_KEPT"
      bm::tui::_ask_kept bm::tui::_v_dns6 "2001:db8::53" "DNS servers" "$cur_dns" || return 1
      BM_TUI_DNS6="$BM_TUI_KEPT"
      ;;
  esac
  return 0
}

bm::tui::_ip6_words() { # describe BM_TUI_IP6/GW6/DNS6 -> BM_TUI_WORDS
  case "$BM_TUI_IP6" in
    auto) BM_TUI_WORDS="automatic (SLAAC)" ;;
    dhcp) BM_TUI_WORDS="DHCPv6" ;;
    none) BM_TUI_WORDS="none (IPv6 off)" ;;
    "") BM_TUI_WORDS="unchanged" ;;
    *) BM_TUI_WORDS="$BM_TUI_IP6$(bm::tui::_extra_words "$BM_TUI_GW6" "$BM_TUI_DNS6")" ;;
  esac
}

# IPv4 or IPv6? -> BM_TUI_FAMILY (4|6)
bm::tui::_pick_family() { # _pick_family <what>
  bm::ui::menu -- "Which address of $1?" \
    v4 "IPv4 address"$'\t'"e.g. 10.0.0.10/24" \
    v6 "IPv6 address"$'\t'"e.g. 2001:db8::10/64" || return 1
  BM_TUI_FAMILY=4
  if [[ "$BM_UI_REPLY" == v6 ]]; then BM_TUI_FAMILY=6; fi
  return 0
}

bm::tui::_ip4_words() { # describe BM_TUI_IP4/GW4/DNS4 -> BM_TUI_WORDS
  case "$BM_TUI_IP4" in
    dhcp) BM_TUI_WORDS="automatic (DHCP)" ;;
    none) BM_TUI_WORDS="none" ;;
    "") BM_TUI_WORDS="unchanged" ;;
    *) BM_TUI_WORDS="$BM_TUI_IP4$(bm::tui::_extra_words "$BM_TUI_GW4" "$BM_TUI_DNS4")" ;;
  esac
}

bm::tui::_extra_words() { # _extra_words <gw> <dns> -> ", gateway X, DNS Y" ("none" = removed)
  local out=""
  case "$1" in "") ;; none) out+=", no gateway" ;; *) out+=", gateway $1" ;; esac
  case "$2" in "") ;; none) out+=", no DNS servers" ;; *) out+=", DNS $2" ;; esac
  printf '%s' "$out"
}

# ---- review ---------------------------------------------------------------------

# Show what is about to happen in plain words, the safety net, early SSH
# warnings, and the equivalent command. BM_TUI_AFFECTED holds the devices the
# change touches. rc: 0 continue, 1 back, 2 cancel.
bm::tui::review() { # review <subcommand> <summary-line>...
  local sub="$1"
  shift
  local -a lines=("$@")
  lines+=("")
  if (( BM_DRY_RUN )); then
    lines+=("PRACTICE: you will see the exact plan, and nothing is changed.")
  else
    lines+=("$(bm::help::tier_sentence "$BM_TUI_TIER")")
  fi
  local d touched=""
  if [[ -n "$BM_TUI_SSH_DEV" ]]; then
    for d in "${BM_TUI_AFFECTED[@]:-}"; do
      if [[ "$d" == "$BM_TUI_SSH_DEV" || ( -n "$BM_TUI_SSH_PARENT" && "$d" == "$BM_TUI_SSH_PARENT" ) ]]; then
        touched="$BM_TUI_SSH_DEV"
      fi
    done
  fi
  bm::ui::heading "Check before you go"
  local -a wrapped=()
  local l
  bm::ui::width
  for l in "${lines[@]}"; do
    bm::ui::wrap $(( BM_UI_W - 6 )) "$l"
    wrapped+=("${BM_UI_WRAPPED[@]}")
  done
  bm::ui::box --title "You are about to" --style info -- "${wrapped[@]}"
  if [[ -n "$touched" ]] && ! (( BM_DRY_RUN )); then
    if [[ "$BM_TUI_TIER" == checkpoint ]]; then
      bm::ui::warn "This touches $touched, which carries your SSH connection. If it cuts you off: wait - it is undone automatically, then you can reconnect."
    else
      bm::ui::err "This touches $touched, which carries your SSH connection, and this server has no automatic undo. bond-manager will refuse it here - make this change from the server console instead."
    fi
  fi
  bm::wf::cli_equivalent "$sub"
  local cmd="$BM_WF_CLI"
  if (( BM_DRY_RUN )); then
    cmd="$BM_PROG -n ${BM_WF_CLI#"$BM_PROG "}"
  fi
  # never wrapped: it has to stay copy-pasteable
  printf '  %sSame thing as a command:%s\n    %s%s%s\n' "$BM_S_DIM" "$BM_S_RST" "$BM_S_CYAN" "$cmd" "$BM_S_RST" >&2
  local go="Continue - show me the exact plan"
  if ! bm::ui::menu --default go -- "Ready?" \
    go "$go"$'\t'"nothing happens until you say yes" \
    back "Go back and change something" \
    cancel "Cancel"; then
    (( BM_UI_EOF )) && return 2
    return 1
  fi
  case "$BM_UI_REPLY" in
    go) return 0 ;;
    back) return 1 ;;
  esac
  return 2
}

# ---- check ------------------------------------------------------------------------

bm::tui::_health_report() { # plain-words health of every bond (read-only)
  local b health verdict r n=0
  local -a reasons=()
  if (( ${#BM_TUI_BONDS[@]} == 0 )); then
    echo "There are no bonds on this server yet."
    echo "Pick \"Build a new bond\" in the main menu to make one."
    return 0
  fi
  for b in "${BM_TUI_BONDS[@]}"; do
    if ! bm::facts::bond_exists_kernel "$b"; then
      echo "$BM_G_ODOT $b: saved in NetworkManager but not running."
      echo
      continue
    fi
    health="$(bm::facts::bond_health "$b")"
    verdict="${health%%$'\n'*}"
    mapfile -t reasons < <(tail -n +2 <<<"$health" | sed '/^$/d')
    case "$verdict" in
      healthy) printf '%s %s is healthy.\n' "$(bm::core::c_ok "$BM_G_OK")" "$b" ;;
      degraded) printf '%s %s needs attention:\n' "$(bm::core::c_warn "$BM_G_WARN")" "$b"; n=$(( n + 1 )) ;;
      *) printf '%s %s is DOWN:\n' "$(bm::core::c_err "$BM_G_BAD")" "$b"; n=$(( n + 1 )) ;;
    esac
    printf '    mode: %s - %s\n' "$(bm::facts::bond_mode "$b")" "$(bm::help::mode_label "$(bm::facts::bond_mode "$b")")"
    printf '    ports: %s\n' "$(bm::facts::bond_members "$b" | paste -sd, - | sed 's/,/, /g; s/^$/none/')"
    for r in "${reasons[@]}"; do
      bm::help::explain_reason "$r" | sed '1s/^/    - /; 2s/^/      /'
    done
    echo
  done
  if (( n == 0 )); then
    echo "All good."
  fi
  return 0
}

bm::tui::check_menu() {
  local bond target
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::ui::heading "Check my bonds"
    bm::ui::menu -- "What would you like to see?" \
      quick "Quick health check (all bonds)"$'\t'"problems explained in plain words" \
      look "Look closely at one bond"$'\t'"ports, LACP, addresses, a ping test" \
      deep "Deep check of one bond"$'\t'"adds saved profiles, driver info, recent log" \
      verify "Re-run the safety checks on one bond" \
      nics "List the network ports" || return 0
    case "$BM_UI_REPLY" in
      quick)
        bm::tui::run look bm::tui::_health_report
        bm::tui::result look
        ;;
      look | deep)
        local which="$BM_UI_REPLY"
        bm::tui::pick_bond "Which bond?" || continue
        bond="$BM_UI_REPLY"
        target=""
        if [[ "$which" == deep ]]; then
          bm::ui::input --optional --validate bm::tui::_v_ipv4_target --example "10.0.0.1" \
            -- "Address to ping - Enter for the default gateway" || continue
          target="$BM_UI_REPLY"
          bm::tui::run look bm::diag::run "$bond" extended "$target"
        else
          bm::tui::run look bm::diag::run "$bond" basic ""
        fi
        bm::tui::result look
        ;;
      verify)
        bm::tui::pick_bond "Which bond?" || continue
        bm::tui::run look bm::cli::cmd_verify "$BM_UI_REPLY"
        bm::tui::result look
        ;;
      nics)
        bm::tui::run look bm::cli::cmd_nics
        bm::tui::result look
        ;;
    esac
  done
}

# ---- move (swap) --------------------------------------------------------------------

bm::tui::move_wizard() {
  bm::ui::heading "Move a bond to a new switch"
  bm::ui::note "A bond keeps working when one cable is gone, so you move one cable at a time: plug a free port into the new switch, then swap it in for an old port. The new port is added and must really work BEFORE the old one is removed - the server never loses its connection."
  bm::tui::ready_to_change || return 0
  bm::tui::pick_bond --managed "Which bond are you moving?" || return 0
  local bond="$BM_UI_REPLY" mode switched=0 step=1 old="" new="" rc
  mode="$(bm::facts::bond_mode "$bond")"
  BM_TUI_CTX_BOND="$bond"

  if [[ "$mode" == 802.3ad ]]; then
    bm::ui::heading "LACP and the move" "$bond runs 802.3ad"
    bm::ui::note "During the move one cable is on the old switch and one on the new. LACP only works if both switches act as ONE (MLAG / vPC / a stack). Otherwise the bond will not aggregate across them."
    bm::ui::menu -- "Are the old and the new switch one LACP group?" \
      yes "Yes - they act as one switch (MLAG/vPC/stack)" \
      ab "No / not sure - switch $bond to active-backup first"$'\t'"recommended" \
      back "Back" || return 0
    case "$BM_UI_REPLY" in
      back) return 0 ;;
      ab)
        bm::wf::spec_reset
        BM_SPEC[bond]="$bond"
        BM_SPEC[mode]="active-backup"
        bm::wf::affected_devices "$bond"
        BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
        rc=0
        bm::tui::review modify "Switch $bond from 802.3ad (LACP) to active-backup (simple failover)" \
          "LACP-only options are dropped automatically." \
          "Switch it back to 802.3ad once both cables are on the new switch." || rc=$?
        (( rc == 0 )) || return 0
        bm::tui::run change bm::wf::modify
        bm::tui::result change
        if ! bm::tui::_went_well; then
          return 0
        fi
        switched=1
        ;;
    esac
  fi

  while (( step >= 1 && step <= 3 )); do
    (( BM_UI_EOF )) && return 0
    case "$step" in
      1)
        bm::ui::heading "Which cable moves?" "Step 1 of 3"
        bm::ui::note "Pick the port whose cable is still on the OLD switch."
        if ! bm::tui::pick_nics --members "$bond" --single -- "Port to replace"; then
          step=0
          continue
        fi
        old="$BM_UI_REPLY"
        step=2
        ;;
      2)
        bm::ui::heading "Which port replaces it?" "Step 2 of 3"
        bm::ui::note "Pick the free port that is now cabled to the NEW switch."
        if ! bm::tui::pick_nics --free --single --exclude "$old" -- "New port for $bond"; then
          step=1
          continue
        fi
        new="$BM_UI_REPLY"
        bm::facts::nic_info "$new" || true
        local nlink="$BM_NIC_LINK" nspd="$BM_NIC_SPEED"
        bm::facts::nic_info "$old" || true
        if [[ "$nlink" != up ]]; then
          bm::ui::warn "$new has no link right now. The swap waits for it to join the bond; without a link it cannot, and the swap is undone (your connection may wobble until then)."
          bm::ui::menu -- "What now?" \
            other "Pick another port" \
            again "Check again (I just plugged it in)" \
            anyway "Continue anyway" || { step=1; continue; }
          case "$BM_UI_REPLY" in
            other) continue ;;
            again)
              bm::facts::nic_info "$new" || true
              if [[ "$BM_NIC_LINK" != up ]]; then
                bm::ui::warn "Still no link on $new."
                continue
              fi
              bm::ui::ok "$new has a link now."
              ;;
          esac
        elif [[ "$nspd" != unknown && "$BM_NIC_SPEED" != unknown && "$nspd" != "$BM_NIC_SPEED" ]]; then
          bm::ui::warn "$new runs at $(bm::help::speed_label "$nspd") but $old at $(bm::help::speed_label "$BM_NIC_SPEED"). It works, but the bond is uneven until the other cable moves too."
        fi
        step=3
        ;;
      3)
        bm::wf::spec_reset
        BM_SPEC[bond]="$bond"
        BM_SPEC[old]="$old"
        BM_SPEC[new]="$new"
        bm::wf::affected_devices "$bond" "$new"
        BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
        rc=0
        bm::tui::review swap-member "Swap $old out of $bond and $new in." \
          "Order: add $new, wait until the kernel really uses it, THEN remove $old." \
          "$bond keeps working the whole time." || rc=$?
        case "$rc" in
          1) step=2; continue ;;
          2) return 0 ;;
        esac
        bm::tui::run change bm::wf::swap_member
        bm::tui::result change
        if bm::tui::_went_well && [[ -n "$(bm::facts::bond_members "$bond")" ]]; then
          if bm::ui::yesno --default y "Move another cable of $bond too?"; then
            old="" new=""
            step=1
            continue
          fi
        fi
        step=4
        ;;
    esac
  done
  if (( switched )); then
    bm::ui::heading "Remember"
    bm::ui::note "$bond now runs active-backup. Once every cable is on the new switch and its ports are set up for LACP, switch it back: Change a bond > Change how it works > 802.3ad."
    bm::ui::pause
  fi
  return 0
}

# Did the last action succeed (or, in practice mode, render its plan)?
bm::tui::_went_well() {
  (( BM_TUI_LAST_RC == 0 )) || return 1
  case "$BM_TUI_LAST_OUTCOME" in
    committed | dry-run | noop) return 0 ;;
  esac
  return 1
}

# ---- build (create) -------------------------------------------------------------------

bm::tui::build_wizard() {
  bm::ui::heading "Build a new bond"
  bm::ui::note "A bond joins two or more network ports into one connection that survives a cable or switch failure. Five short questions; Esc goes back one step."
  bm::tui::ready_to_change || return 0
  local step=1 name="" ports="" mode="" mtu="" rc vid=""
  local ip4="" gw4="" dns4="" vtok="" ipwords=""
  BM_TUI_CTX_BOND=""
  while (( step >= 1 && step <= 6 )); do
    (( BM_UI_EOF )) && return 0
    case "$step" in
      1)
        bm::ui::heading "Name" "Step 1 of 5"
        bm::ui::note "The name the server uses for the bond. bond0, bond1... is the convention."
        if ! bm::ui::input --default "${name:-$(bm::tui::_next_bond_name)}" \
          --validate bm::tui::_v_bond_name -- "Bond name"; then
          step=0
          continue
        fi
        name="$BM_UI_REPLY"
        BM_TUI_CTX_BOND="$name"
        step=2
        ;;
      2)
        bm::ui::heading "Ports" "Step 2 of 5"
        bm::ui::note "Pick the network ports to join. Two is usual - ideally cabled to two different switches."
        if ! bm::tui::pick_nics --free --min 1 -- "Ports for $name"; then
          step=1
          continue
        fi
        ports="$BM_UI_REPLY"
        if [[ "$ports" != *,* ]]; then
          bm::ui::warn "One port works, but there is no spare yet. You can add one later (Change a bond > Add a port)."
        fi
        step=3
        ;;
      3)
        bm::ui::heading "How the ports work together" "Step 3 of 5"
        if ! bm::tui::pick_mode; then
          step=2
          continue
        fi
        mode="$BM_UI_REPLY"
        step=4
        ;;
      4)
        bm::ui::heading "Address" "Step 4 of 5"
        bm::ui::note "How does this bond get its IPv4 address? Pick \"On a VLAN\" only if the network team gave you a VLAN id for this server."
        if ! bm::tui::ask_ip4 --vlan-option "$name"; then
          step=3
          continue
        fi
        vtok=""
        if [[ "$BM_TUI_IP4" == vlan ]]; then
          if ! bm::ui::input --validate bm::tui::_v_vlan_new --example 120 -- "VLAN id"; then
            continue
          fi
          vid="$BM_UI_REPLY"
          if ! bm::tui::ask_ip4 "VLAN $vid ($name.$vid)"; then
            continue
          fi
          vtok="$vid"
          if [[ "$BM_TUI_IP4" != none ]]; then
            vtok+=":ip4=$BM_TUI_IP4${BM_TUI_GW4:+;gw4=$BM_TUI_GW4}${BM_TUI_DNS4:+;dns4=$BM_TUI_DNS4}"
          fi
          bm::tui::_ip4_words
          ip4=none gw4="" dns4=""
          BM_TUI_WORDS="on VLAN $vid: $BM_TUI_WORDS"
        else
          ip4="$BM_TUI_IP4" gw4="$BM_TUI_GW4" dns4="$BM_TUI_DNS4"
          bm::tui::_ip4_words
        fi
        ipwords="$BM_TUI_WORDS"
        step=5
        ;;
      5)
        bm::ui::heading "Anything else?" "Step 5 of 5"
        if ! bm::ui::menu --default finish -- "Extras (optional)" \
          finish "No, that's all"$'\t'"go to the summary" \
          mtu "Jumbo frames (bigger packets)"$'\t'"MTU ${mtu:-1500}; only if the switches allow it"; then
          step=4
          continue
        fi
        if [[ "$BM_UI_REPLY" == mtu ]]; then
          bm::ui::note "MTU is the largest packet size. 1500 is normal; 9000 (\"jumbo frames\") only helps if every switch in the path is set up for it - otherwise things break in odd ways."
          if bm::ui::input --default "${mtu:-9000}" --validate bm::tui::_v_mtu -- "MTU"; then
            mtu="$BM_UI_REPLY"
            if [[ "$mtu" == 1500 ]]; then mtu=""; fi
          fi
          continue
        fi
        step=6
        ;;
      6)
        bm::wf::spec_reset
        BM_SPEC[bond]="$name"
        BM_SPEC[mode]="$mode"
        BM_SPEC[members]="$ports"
        [[ -n "$ip4" ]] && BM_SPEC[ip4]="$ip4"
        [[ -n "$gw4" ]] && BM_SPEC[gw4]="$gw4"
        [[ -n "$dns4" ]] && BM_SPEC[dns4]="$dns4"
        [[ -n "$vtok" ]] && BM_SPEC[vlans]="$vtok"
        [[ -n "$mtu" ]] && BM_SPEC[mtu]="$mtu"
        BM_TUI_AFFECTED=("$name")
        bm::core::split_list "$ports"
        BM_TUI_AFFECTED+=("${BM_LIST[@]}")
        [[ -n "$vid" && -n "$vtok" ]] && BM_TUI_AFFECTED+=("$name.$vid")
        local -a sum=("Build bond $name from: ${ports//,/, }"
          "How it works: $mode - $(bm::help::mode_label "$mode")"
          "IPv4: $ipwords"
          "IPv6: not set here - add it afterwards with Change a bond > IP address.")
        [[ -n "$mtu" ]] && sum+=("MTU: $mtu")
        rc=0
        bm::tui::review create "${sum[@]}" || rc=$?
        case "$rc" in
          1) step=5; continue ;;
          2) return 0 ;;
        esac
        bm::tui::run change bm::wf::create
        bm::tui::result change
        step=7
        ;;
    esac
  done
  return 0
}

# ---- change ---------------------------------------------------------------------------

bm::tui::_cur_opts() { # current bond.options of a managed bond -> BM_TUI_OPTS
  local uuid
  BM_TUI_OPTS=""
  uuid="$(bm::nm::bond_con_uuid "$1" 2>/dev/null)" || return 1
  BM_TUI_OPTS="$(bm::nm::con_get "$uuid" bond.options 2>/dev/null || true)"
  return 0
}

bm::tui::_cur_mode() { # kernel mode, else the saved one -> BM_TUI_MODE
  BM_TUI_MODE="$(bm::facts::bond_mode "$1")"
  if [[ "$BM_TUI_MODE" == unknown ]]; then
    bm::tui::_cur_opts "$1" || true
    BM_TUI_MODE="$(sed -n 's/.*mode=\([^,]*\).*/\1/p' <<<"$BM_TUI_OPTS")"
    [[ -n "$BM_TUI_MODE" ]] || BM_TUI_MODE=balance-rr
  fi
  return 0
}

# Review + run a modify of <bond> built in BM_SPEC.
bm::tui::_apply_modify() { # _apply_modify <bond> <summary-line>...
  local bond="$1" rc=0
  shift
  bm::wf::affected_devices "$bond"
  BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
  bm::tui::review modify "$@" || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::modify
  bm::tui::result change
}

bm::tui::change_menu() {
  bm::ui::heading "Change a bond"
  bm::tui::ready_to_change || return 0
  bm::tui::pick_bond --managed "Which bond?" || return 0
  local bond="$BM_UI_REPLY" mode members count
  BM_TUI_CTX_BOND="$bond"
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::tui::_cur_mode "$bond"
    mode="$BM_TUI_MODE"
    members="$(bm::facts::bond_members "$bond" | paste -sd, - | sed 's/,/, /g')"
    count="$(bm::facts::bond_members "$bond" | grep -c . || true)"
    local -a items=(
      add "Add a port"$'\t'"now: ${members:-none}"
      remove "Remove a port"
      mode "Change how it works (mode)"$'\t'"now: $mode ($(bm::help::mode_short "$mode"))"
    )
    case "$mode" in
      active-backup | balance-tlb | balance-alb)
        items+=(primary "Preferred port"$'\t'"the port to use whenever it has a link") ;;
    esac
    items+=(
      ip "IP address"
      mtu "MTU (packet size)"
      vlan "VLANs"$'\t'"add, change, remove"
      opt "Advanced option"$'\t'"link checks, LACP rate, hashing..."
      clone "Copy onto other ports"$'\t'"a new bond with the same settings"
      delete "Delete this bond"
    )
    bm::ui::heading "Change $bond"
    bm::ui::menu -- "What do you want to change?" "${items[@]}" || return 0
    case "$BM_UI_REPLY" in
      add) bm::tui::_change_add "$bond" ;;
      remove) bm::tui::_change_remove "$bond" "$count" ;;
      mode) bm::tui::_change_mode "$bond" "$mode" ;;
      primary) bm::tui::_change_primary "$bond" ;;
      ip) bm::tui::_change_ip "$bond" ;;
      mtu) bm::tui::_change_mtu "$bond" ;;
      vlan) bm::tui::_change_vlan "$bond" ;;
      opt) bm::tui::_change_opt "$bond" "$mode" ;;
      clone) bm::tui::_change_clone "$bond" ;;
      delete)
        bm::tui::_change_delete "$bond"
        if ! bm::core::in_list "$bond" "${BM_TUI_BONDS[@]:-}"; then
          return 0
        fi
        ;;
    esac
  done
}

bm::tui::_change_add() {
  local bond="$1" rc=0
  bm::ui::heading "Add a port to $bond"
  bm::tui::pick_nics --free --min 1 -- "Ports to add" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[members]="$BM_UI_REPLY"
  bm::wf::affected_devices "$bond"
  bm::core::split_list "$BM_UI_REPLY"
  BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}" "${BM_LIST[@]}")
  bm::tui::review add-member "Add ${BM_SPEC[members]//,/, } to $bond." \
    "For 802.3ad, the new switch port must join the same LACP bundle." || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::add_members
  bm::tui::result change
}

bm::tui::_change_remove() {
  local bond="$1" count="$2" rc=0
  bm::ui::heading "Remove a port from $bond"
  if (( count <= 1 )); then
    bm::ui::note "$bond has only one port left. Removing it would take the bond down - to get rid of the whole bond, use \"Delete this bond\" instead."
    bm::ui::pause
    return 0
  fi
  bm::ui::note "The bond keeps running on the ports that stay. To REPLACE a port, use \"Move a bond to a new switch\" instead - it adds the new one first."
  bm::tui::pick_nics --members "$bond" --min 1 --max $(( count - 1 )) -- "Ports to remove" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[members]="$BM_UI_REPLY"
  bm::wf::affected_devices "$bond"
  BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
  bm::core::split_list "$BM_UI_REPLY"
  local left=$(( count - ${#BM_LIST[@]} ))
  local -a sum=("Remove ${BM_SPEC[members]//,/, } from $bond.")
  if (( left == 1 )); then
    sum+=("Afterwards $bond has one port left: it works, but has no spare.")
  fi
  bm::tui::review remove-member "${sum[@]}" || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::remove_members
  bm::tui::result change
}

bm::tui::_change_mode() {
  local bond="$1" cur="$2"
  bm::ui::heading "Change how $bond works"
  bm::tui::pick_mode --current "$cur" || return 0
  local new="$BM_UI_REPLY"
  if [[ "$new" == "$cur" ]]; then
    bm::ui::note "$bond already runs $cur - nothing to change."
    bm::ui::pause
    return 0
  fi
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[mode]="$new"
  local -a sum=("Switch $bond from $cur to $new." "$(bm::help::mode_label "$new")"
    "Options that only made sense in $cur are dropped automatically.")
  if [[ "$new" == 802.3ad ]]; then
    BM_SPEC[opts]="lacp_rate=$(bm::config::get DEFAULT_8023AD_LACP_RATE),xmit_hash_policy=$(bm::config::get DEFAULT_8023AD_XHP)"
    sum+=("LACP settings: ${BM_SPEC[opts]//,/, } (the defaults).")
  fi
  bm::tui::_apply_modify "$bond" "${sum[@]}"
}

bm::tui::_change_primary() {
  local bond="$1" m
  bm::ui::heading "Preferred port for $bond"
  bm::ui::note "With a preferred port, $bond uses it whenever it has a link and falls back to the others only when it fails."
  local -a items=()
  while IFS= read -r m; do
    [[ -n "$m" ]] && items+=("$m" "$m")
  done < <(bm::facts::bond_members "$bond")
  items+=(none "No preference"$'\t'"any working port will do")
  bm::ui::menu -- "Preferred port" "${items[@]}" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  if [[ "$BM_UI_REPLY" == none ]]; then
    BM_SPEC[del_opts]="primary"
    bm::tui::_apply_modify "$bond" "Remove the preferred port of $bond."
  else
    BM_SPEC[opts]="primary=$BM_UI_REPLY"
    bm::tui::_apply_modify "$bond" "Make $BM_UI_REPLY the preferred port of $bond."
  fi
}

bm::tui::_change_ip() {
  local bond="$1"
  bm::ui::heading "IP address of $bond"
  local carries=0
  if [[ -n "$BM_TUI_SSH_DEV" && ( "$BM_TUI_SSH_DEV" == "$bond" ) ]]; then carries=1; fi
  if (( carries )); then
    bm::ui::warn "You are connected through $bond. Changing its address ends this session. Afterwards: open a NEW session to the new address and run 'sudo $BM_PROG commit' before the countdown runs out - otherwise the change is undone (which is the safety net working)."
  fi
  bm::tui::_pick_family "$bond" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  local profile
  profile="$(bm::nm::bond_con_uuid "$bond" || true)"
  if [[ "$BM_TUI_FAMILY" == 6 ]]; then
    bm::tui::ask_ip6 --keep --profile "$profile" "$bond" || return 0
    [[ -n "$BM_TUI_IP6" ]] || return 0
    BM_SPEC[ip6]="$BM_TUI_IP6"
    [[ -n "$BM_TUI_GW6" ]] && BM_SPEC[gw6]="$BM_TUI_GW6"
    [[ -n "$BM_TUI_DNS6" ]] && BM_SPEC[dns6]="$BM_TUI_DNS6"
    bm::tui::_ip6_words
    bm::tui::_apply_modify "$bond" "Set the IPv6 address of $bond: $BM_TUI_WORDS."
    return 0
  fi
  bm::tui::ask_ip4 --keep --profile "$profile" "$bond" || return 0
  if [[ -z "$BM_TUI_IP4" ]]; then
    return 0
  fi
  BM_SPEC[ip4]="$BM_TUI_IP4"
  [[ -n "$BM_TUI_GW4" ]] && BM_SPEC[gw4]="$BM_TUI_GW4"
  [[ -n "$BM_TUI_DNS4" ]] && BM_SPEC[dns4]="$BM_TUI_DNS4"
  bm::tui::_ip4_words
  bm::tui::_apply_modify "$bond" "Set the IPv4 address of $bond: $BM_TUI_WORDS."
}

bm::tui::_change_mtu() {
  local bond="$1" cur
  bm::ui::heading "MTU of $bond"
  bm::ui::note "MTU is the largest packet size. 1500 is normal; 9000 (\"jumbo frames\") only helps if every switch in the path is set up for it."
  bm::facts::nic_info "$bond" || true
  cur="$BM_NIC_MTU"
  [[ "$cur" =~ ^[0-9]+$ ]] || cur=1500
  bm::ui::input --default "$cur" --validate bm::tui::_v_mtu -- "MTU" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[mtu]="$BM_UI_REPLY"
  bm::tui::_apply_modify "$bond" "Set the MTU of $bond to $BM_UI_REPLY (now $cur)."
}

bm::tui::_change_vlan() {
  local bond="$1" rec vuuid vname vdev vid rc
  bm::ui::heading "VLANs on $bond"
  local -a vitems=()
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r vuuid vname vdev vid <<<"$rec"
    [[ -n "$vid" ]] && vitems+=("$vid" "VLAN $vid"$'\t'"${vdev:-$bond.$vid}")
  done < <(bm::nm::vlan_cons "$bond" 2>/dev/null || true)
  if (( ${#vitems[@]} > 0 )); then
    local -a shown=()
    local i
    for ((i = 0; i < ${#vitems[@]}; i += 2)); do shown+=("${vitems[i]}"); done
    bm::ui::note "VLANs now: ${shown[*]}"
  else
    bm::ui::note "$bond has no VLANs yet."
  fi
  local -a items=(add "Add a VLAN")
  if (( ${#vitems[@]} > 0 )); then
    items+=(modify "Change a VLAN's IP address" remove "Remove a VLAN")
  fi
  bm::ui::menu -- "What do you want to do?" "${items[@]}" || return 0
  case "$BM_UI_REPLY" in
    add)
      bm::ui::note "The switch ports must carry this VLAN (tagged/trunk) for it to work."
      BM_TUI_CTX_BOND="$bond"
      bm::ui::input --validate bm::tui::_v_vlan_new --example 120 -- "VLAN id" || return 0
      vid="$BM_UI_REPLY"
      bm::tui::ask_ip4 "VLAN $vid ($bond.$vid)" || return 0
      local -a settings=()
      if [[ "$BM_TUI_IP4" != none ]]; then
        settings+=("ip4=$BM_TUI_IP4")
        [[ -n "$BM_TUI_GW4" ]] && settings+=("gw4=$BM_TUI_GW4")
        [[ -n "$BM_TUI_DNS4" ]] && settings+=("dns4=$BM_TUI_DNS4")
      fi
      bm::tui::_ip4_words
      local v4words="$BM_TUI_WORDS" v6words="none"
      BM_TUI_IP6=""
      if bm::ui::yesno "Give VLAN $vid an IPv6 address too?"; then
        bm::tui::ask_ip6 "VLAN $vid ($bond.$vid)" || return 0
        if [[ "$BM_TUI_IP6" != none ]]; then
          settings+=("ip6=$BM_TUI_IP6")
          [[ -n "$BM_TUI_GW6" ]] && settings+=("gw6=$BM_TUI_GW6")
          [[ -n "$BM_TUI_DNS6" ]] && settings+=("dns6=$BM_TUI_DNS6")
        fi
        bm::tui::_ip6_words
        v6words="$BM_TUI_WORDS"
      fi
      (( BM_UI_EOF )) && return 0
      local tok="$vid"
      if (( ${#settings[@]} > 0 )); then
        tok+=":$(bm::core::join ';' "${settings[@]}")"
      fi
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlans]="$tok"
      BM_TUI_AFFECTED=("$bond.$vid")
      rc=0
      bm::tui::review vlan-add "Add VLAN $vid to $bond (device $bond.$vid)." "IPv4: $v4words" "IPv6: $v6words" || rc=$?
      (( rc == 0 )) || return 0
      bm::tui::run change bm::wf::vlan_add
      bm::tui::result change
      ;;
    modify)
      bm::ui::menu -- "Which VLAN?" "${vitems[@]}" || return 0
      vid="$BM_UI_REPLY"
      bm::tui::_pick_family "VLAN $vid" || return 0
      local vprof="" vrec vu vv
      while IFS= read -r vrec; do
        IFS=$'\x1f' read -r vu _ _ vv <<<"$vrec"
        if [[ "$vv" == "$vid" ]]; then vprof="$vu"; fi
      done < <(bm::nm::vlan_cons "$bond")
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlan_id]="$vid"
      local fam="IPv4"
      if [[ "$BM_TUI_FAMILY" == 6 ]]; then
        fam="IPv6"
        bm::tui::ask_ip6 --keep --profile "$vprof" "VLAN $vid" || return 0
        [[ -n "$BM_TUI_IP6" ]] || return 0
        BM_SPEC[ip6]="$BM_TUI_IP6"
        [[ -n "$BM_TUI_GW6" ]] && BM_SPEC[gw6]="$BM_TUI_GW6"
        [[ -n "$BM_TUI_DNS6" ]] && BM_SPEC[dns6]="$BM_TUI_DNS6"
        bm::tui::_ip6_words
      else
        bm::tui::ask_ip4 --keep --profile "$vprof" "VLAN $vid" || return 0
        [[ -n "$BM_TUI_IP4" ]] || return 0
        BM_SPEC[ip4]="$BM_TUI_IP4"
        [[ -n "$BM_TUI_GW4" ]] && BM_SPEC[gw4]="$BM_TUI_GW4"
        [[ -n "$BM_TUI_DNS4" ]] && BM_SPEC[dns4]="$BM_TUI_DNS4"
        bm::tui::_ip4_words
      fi
      BM_TUI_AFFECTED=("$bond.$vid")
      rc=0
      bm::tui::review vlan-modify "Set the $fam address of VLAN $vid on $bond: $BM_TUI_WORDS." || rc=$?
      (( rc == 0 )) || return 0
      bm::tui::run change bm::wf::vlan_modify "$vid"
      bm::tui::result change
      ;;
    remove)
      bm::ui::menu -- "Which VLAN?" "${vitems[@]}" || return 0
      vid="$BM_UI_REPLY"
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlan_id]="$vid"
      BM_TUI_AFFECTED=("$bond.$vid")
      rc=0
      bm::tui::review vlan-remove "Remove VLAN $vid ($bond.$vid) and its settings." || rc=$?
      (( rc == 0 )) || return 0
      bm::tui::run change bm::wf::vlan_remove
      bm::tui::result change
      ;;
  esac
}

bm::tui::_change_opt() {
  local bond="$1" mode="$2" k v
  bm::ui::heading "Advanced options of $bond"
  bm::ui::note "Only change these if you know you need to (or the network team asked). Every value is checked before anything happens."
  bm::tui::_cur_opts "$bond" || true
  local -A cur=()
  bm::nm::opts_parse "$BM_TUI_OPTS" cur
  bm::ui::menu -- "What do you want to do?" \
    set "Set an option" \
    del "Remove an option"$'\t'"back to the kernel default" || return 0
  local -a items=()
  if [[ "$BM_UI_REPLY" == del ]]; then
    for k in "${!cur[@]}"; do
      [[ "$k" == mode ]] && continue
      items+=("$k" "$k=${cur[$k]}")
    done
    if (( ${#items[@]} == 0 )); then
      bm::ui::note "$bond has no options set besides its mode."
      bm::ui::pause
      return 0
    fi
    bm::ui::menu -- "Remove which option?" "${items[@]}" || return 0
    bm::wf::spec_reset
    BM_SPEC[bond]="$bond"
    BM_SPEC[del_opts]="$BM_UI_REPLY"
    bm::tui::_apply_modify "$bond" "Remove option $BM_UI_REPLY from $bond (back to the default)."
    return 0
  fi
  for k in $(bm::val::opts_for_mode "$mode"); do
    v="${cur[$k]:-}"
    items+=("$k" "$k${v:+ = $v}"$'\t'"$(bm::help::option_help "$k")")
  done
  bm::ui::menu -- "Which option?" "${items[@]}" || return 0
  k="$BM_UI_REPLY"
  BM_TUI_CTX_OPT="$k"
  bm::ui::note "$(bm::help::option_help "$k")"
  bm::ui::input --default "${cur[$k]:-}" --validate bm::tui::_v_opt_value -- "Value for $k" || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[opts]="$k=$BM_UI_REPLY"
  bm::tui::_apply_modify "$bond" "Set $k=$BM_UI_REPLY on $bond."
}

bm::tui::_change_clone() {
  local bond="$1" name ports rc=0
  bm::ui::heading "Copy $bond onto other ports"
  bm::ui::note "Makes a NEW bond with the same mode and options as $bond, on ports you pick. Handy to rebuild a bond on new hardware."
  bm::ui::input --default "$(bm::tui::_next_bond_name)" --validate bm::tui::_v_bond_name -- "Name of the new bond" || return 0
  name="$BM_UI_REPLY"
  bm::tui::pick_nics --free --min 1 -- "Ports for $name" || return 0
  ports="$BM_UI_REPLY"
  bm::wf::spec_reset
  BM_SPEC[src]="$bond"
  BM_SPEC[bond]="$name"
  BM_SPEC[members]="$ports"
  if bm::ui::yesno --default y "Copy the VLANs of $bond too?"; then
    BM_SPEC[copy_vlans]=1
  fi
  (( BM_UI_EOF )) && return 0
  bm::ui::note "Copying the IP address makes sense only if $bond is going away: two bonds with the same address conflict."
  if bm::ui::yesno "Copy the IP address of $bond too?"; then
    BM_SPEC[copy_ip]=1
  fi
  (( BM_UI_EOF )) && return 0
  bm::core::split_list "$ports"
  BM_TUI_AFFECTED=("$name" "${BM_LIST[@]}")
  local -a sum=("Build $name on ${ports//,/, } with the settings of $bond.")
  [[ "${BM_SPEC[copy_vlans]:-0}" == 1 ]] && sum+=("VLANs are copied.")
  [[ "${BM_SPEC[copy_ip]:-0}" == 1 ]] && sum+=("The IP address is copied.")
  bm::tui::review clone "${sum[@]}" || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::clone
  bm::tui::result change
}

bm::tui::_change_delete() {
  local bond="$1" rc=0
  bm::ui::heading "Delete $bond"
  bm::ui::note "This deletes the saved settings of $bond, its ports and its VLANs. The ports become free again."
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::wf::affected_devices "$bond"
  BM_TUI_AFFECTED=("${BM_PLAN_AFFECTED[@]}")
  bm::tui::review remove "Delete $bond with its port and VLAN settings." \
    "You will be asked to type the name to confirm." || rc=$?
  (( rc == 0 )) || return 0
  bm::tui::run change bm::wf::remove
  bm::tui::result change
}

# ---- fix (repair) ---------------------------------------------------------------------

bm::tui::_repair_preview() { # dry-run repair of $1 (runs inside bm::tui::run)
  BM_DRY_RUN=1
  BM_SPEC[bond]="$1"
  bm::wf::repair
}

bm::tui::fix_wizard() {
  bm::ui::heading "Fix a bond that looks wrong"
  bm::ui::note "Bonds drift: a port gets added by hand and never saved, or a saved port no longer exists. Then the next reboot brings the bond back wrong. This compares what the bond REALLY uses right now with what is saved, and fixes the saved side."
  bm::tui::pick_bond --managed "Which bond looks wrong?" || return 0
  local bond="$BM_UI_REPLY"
  if ! bm::facts::bond_exists_kernel "$bond"; then
    bm::ui::warn "$bond is not running, so there is nothing to compare against. Bring it up first (nmcli connection up $bond), then try again."
    bm::ui::pause
    return 0
  fi
  bm::ui::heading "Looking at $bond"
  bm::wf::spec_reset
  bm::tui::run look bm::tui::_repair_preview "$bond"
  if (( BM_TUI_LAST_RC != 0 )); then
    bm::tui::result change
    return 0
  fi
  if [[ "$BM_TUI_LAST_OUTCOME" == noop ]]; then
    bm::ui::ok "The saved settings already match what $bond really uses - nothing to fix there."
    local health
    health="$(bm::facts::bond_health "$bond")"
    if [[ "${health%%$'\n'*}" != healthy ]]; then
      bm::ui::note "If $bond still misbehaves, the cause is outside the settings:"
      local r
      while IFS= read -r r; do
        [[ -n "$r" ]] || continue
        bm::ui::block "$(bm::help::explain_reason "$r" | sed '1s/^/- /; 2s/^/  /')"
      done < <(tail -n +2 <<<"$health")
    fi
    bm::ui::pause
    return 0
  fi
  bm::ui::note "Above is exactly what the fix would do."
  if (( BM_DRY_RUN )); then
    bm::ui::note "(Practice mode: switch it off with p on the main menu to apply the fix.)"
    bm::ui::pause
    return 0
  fi
  bm::ui::menu -- "Fix it?" \
    go "Fix it for real"$'\t'"you will see the plan once more and be asked" \
    back "Not now" || return 0
  [[ "$BM_UI_REPLY" == go ]] || return 0
  bm::tui::ready_to_change || return 0
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::tui::run change bm::wf::repair
  bm::tui::result change
}

# ---- undo & safety ------------------------------------------------------------------

bm::tui::pending_screen() {
  if ! bm::tui::_pending; then
    bm::ui::note "No change is waiting - nothing to keep or undo."
    bm::ui::pause
    return 0
  fi
  local -a lines=("Change: ${BM_PENDING_SUMMARY:-?}")
  if [[ "${BM_PENDING_TIER:-}" == snapshot ]]; then
    lines+=("Nothing undoes it automatically on this server.")
  else
    bm::ui::fmt_secs "$BM_TUI_LEFT"
    lines+=("It is undone automatically in $BM_UI_FMT unless you keep it.")
  fi
  lines+=("Keep it if everything works (can you still reach what you need?).")
  bm::ui::heading "The last change is waiting for you"
  bm::ui::box --title "Keep or undo?" --style warn -- "${lines[@]}"
  if (( BM_DRY_RUN )); then
    bm::ui::dim "(Practice mode is on: keep/undo will only be shown, not done.)"
  fi
  bm::ui::menu -- "What do you want to do?" \
    keep "Keep it"$'\t'"the change stays" \
    undo "Undo it now"$'\t'"put everything back as it was" \
    back "Decide later" || return 0
  # The menus hold no lock while this screen waits: meanwhile the safety net
  # may have undone the change, or another session kept or undid it.
  if [[ "$BM_UI_REPLY" == keep || "$BM_UI_REPLY" == undo ]] && ! bm::tui::_pending; then
    BM_TUI_LAST_RC=0 BM_TUI_LAST_OUTCOME=gone
    bm::tui::result safety
    return 0
  fi
  case "$BM_UI_REPLY" in
    keep)
      bm::tui::run safety bm::cli::cmd_commit
      if (( BM_TUI_LAST_RC == BM_EX_PRECONDITION )) && ! bm::tui::_pending; then
        BM_TUI_LAST_RC=0 BM_TUI_LAST_OUTCOME=gone # settled in between
      else
        BM_TUI_LAST_OUTCOME=committed
        if (( BM_TUI_LAST_RC == BM_EX_VERIFY )); then BM_TUI_LAST_OUTCOME=lost; fi
        if (( BM_DRY_RUN )); then BM_TUI_LAST_OUTCOME=dry-run; fi
      fi
      bm::tui::result safety
      ;;
    undo)
      bm::tui::run safety bm::cli::undo_pending
      if (( BM_TUI_LAST_RC == 0 )) && [[ "$BM_TUI_LAST_OUTCOME" != gone ]]; then
        BM_TUI_LAST_OUTCOME=undone
        if (( BM_DRY_RUN )); then BM_TUI_LAST_OUTCOME=dry-run; fi
      fi
      bm::tui::result safety
      ;;
  esac
  return 0
}

bm::tui::snapshots_menu() {
  local -a rows=() items=()
  local r id created reason
  mapfile -t rows < <(bm::snap::list 2>/dev/null || true)
  bm::ui::heading "Backup copies (snapshots)"
  bm::ui::note "A backup copy of all saved network settings is taken automatically before every change."
  if (( ${#rows[@]} == 0 )); then
    if [[ -d "$BM_BACKUP_DIR" && ! -r "$BM_BACKUP_DIR" ]]; then
      bm::ui::note "The backup folder can only be read by root."
    else
      bm::ui::note "There are no backup copies yet."
    fi
    bm::ui::pause
    return 0
  fi
  for r in "${rows[@]}"; do
    IFS=$'\t' read -r id created reason <<<"$r"
    items+=("$id" "$id"$'\t'"${created:-?} $BM_G_SEP ${reason:-?}")
  done
  bm::ui::menu -- "Which copy?" "${items[@]}" || return 0
  id="$BM_UI_REPLY"
  bm::ui::menu -- "Copy $id" \
    diff "What would change if I restored it" \
    restore "Restore it"$'\t'"you see the changes first and are asked" \
    back "Back" || return 0
  case "$BM_UI_REPLY" in
    diff)
      bm::tui::run look bm::cli::cmd_snapshot diff "$id"
      bm::tui::result look
      ;;
    restore)
      bm::tui::run safety bm::cli::cmd_rollback --snapshot "$id"
      bm::tui::result safety
      ;;
  esac
  return 0
}

bm::tui::safety_menu() {
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::ui::heading "Undo & safety"
    local -a items=()
    if bm::tui::_pending; then
      bm::ui::fmt_secs "$BM_TUI_LEFT"
      items+=(pending "Keep or undo the waiting change"$'\t'"$BM_UI_FMT left")
    fi
    items+=(
      snapshots "Backup copies"$'\t'"see, compare, restore"
      save "Save a backup copy now"
      how "How does the safety net work?"
    )
    bm::ui::menu -- "What do you want to do?" "${items[@]}" || return 0
    case "$BM_UI_REPLY" in
      pending) bm::tui::pending_screen ;;
      snapshots) bm::tui::snapshots_menu ;;
      save)
        bm::tui::run safety bm::cli::cmd_snapshot create
        bm::tui::result safety
        ;;
      how)
        bm::ui::block "$(bm::help::topic safety)"
        bm::ui::pause
        ;;
    esac
  done
}

# ---- tools & help -------------------------------------------------------------------

bm::tui::tools_menu() {
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::ui::heading "Tools"
    bm::ui::menu -- "Pick a tool" \
      nics "Network ports on this server"$'\t'"which are free, which have a link" \
      doctor "Server check"$'\t'"is everything ready? which safety net?" \
      bundle "Support bundle"$'\t'"one file with everything support needs" \
      config "Show settings" \
      cheat "Command-line cheat sheet"$'\t'"the same jobs, as commands" || return 0
    case "$BM_UI_REPLY" in
      nics)
        bm::tui::run look bm::cli::cmd_nics
        bm::tui::result look
        ;;
      doctor)
        bm::tui::run look bm::cli::cmd_doctor
        bm::tui::result look
        ;;
      bundle)
        local -a args=()
        if bm::ui::yesno "Hide IP and MAC addresses (for a ticket that leaves the site)?"; then
          args+=(--redact)
        fi
        (( BM_UI_EOF )) && return 0
        bm::tui::run safety bm::cli::cmd_bundle "${args[@]}"
        bm::tui::result safety
        ;;
      config)
        bm::tui::run look bm::cli::cmd_config show
        bm::tui::result look
        ;;
      cheat)
        bm::ui::heading "Command-line cheat sheet"
        bm::ui::block "$(bm::help::common_tasks)"
        bm::ui::note "Every change in the menus also shows its own command line. '$BM_PROG help COMMAND' explains any command with examples."
        bm::ui::pause
        ;;
    esac
  done
}

bm::tui::help_menu() {
  local t
  while :; do
    (( BM_UI_EOF )) && return 0
    bm::ui::heading "Help"
    local -a items=()
    for t in "${BM_HELP_TOPICS[@]}"; do
      items+=("$t" "$(bm::help::topic_title "$t")")
    done
    items+=(commands "Help for one command")
    bm::ui::menu -- "What would you like to know?" "${items[@]}" || return 0
    if [[ "$BM_UI_REPLY" == commands ]]; then
      local -a citems=()
      for t in "${BM_HELP_COMMANDS[@]}"; do
        citems+=("$t" "$t")
      done
      bm::ui::menu -- "Which command?" "${citems[@]}" || continue
      printf '\n' >&2
      bm::ui::block "$(bm::help::command "$BM_UI_REPLY")"
    else
      printf '\n' >&2
      bm::ui::block "$(bm::help::topic "$BM_UI_REPLY")"
    fi
    bm::ui::pause
  done
}
