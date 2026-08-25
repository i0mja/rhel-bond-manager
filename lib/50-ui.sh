# lib/50-ui.sh — interactive widgets: whiptail when available on a TTY,
# plain prompts otherwise. Contract: every widget returns 0 with the result
# on stdout, or non-zero on cancel. Callers must use `if ! v=$(...)` so a
# cancel can never trip the ERR trap.
# shellcheck shell=bash
[[ -n "${BM_LIB_UI:-}" ]] && return 0
BM_LIB_UI=1

BM_UI_WHIPTAIL=0

bm::ui::init() {
  if bm::core::have_cmd whiptail && bm::core::is_tty && [[ "${BM_PLAIN:-0}" != 1 ]]; then
    BM_UI_WHIPTAIL=1
  fi
}

bm::ui::title() {
  local mode="LIVE"
  (( BM_DRY_RUN )) && mode="DRY-RUN"
  printf '%s v%s (%s)' "$BM_PROG" "$BM_VERSION" "$mode"
}

bm::ui::msg() {
  local msg="$1"
  if (( BM_UI_WHIPTAIL )); then
    whiptail --title "$(bm::ui::title)" --scrolltext --msgbox "$msg" 22 78
  else
    printf '\n%b\n\n' "$msg"
    local _
    read -r -p "Press Enter to continue... " _ || true
  fi
}

bm::ui::yesno() { # yesno <question> -> 0 yes / 1 no
  local msg="$1"
  if (( BM_ASSUME_YES )); then
    return 0
  fi
  if (( BM_UI_WHIPTAIL )); then
    whiptail --title "$(bm::ui::title)" --yesno "$msg" 20 78
    return $?
  fi
  local ans
  read -r -p "$msg [y/N]: " ans || true
  [[ "${ans,,}" == y || "${ans,,}" == yes ]]
}

bm::ui::input() { # input <prompt> [default] -> value on stdout, rc=1 on cancel
  local prompt="$1" def="${2:-}"
  if (( BM_UI_WHIPTAIL )); then
    local out
    out="$(whiptail --title "$(bm::ui::title)" --inputbox "$prompt" 12 74 "$def" \
      3>&1 1>&2 2>&3)" || return 1
    printf '%s\n' "$out"
    return 0
  fi
  local v
  read -r -p "$prompt${def:+ [$def]}: " v || return 1
  [[ -z "$v" ]] && v="$def"
  printf '%s\n' "$v"
}

bm::ui::menu() { # menu <title> <tag> <desc> [<tag> <desc> ...]
  local title="$1"
  shift
  if (( BM_UI_WHIPTAIL )); then
    local out
    out="$(whiptail --title "$(bm::ui::title)" --menu "$title" 22 84 12 "$@" \
      3>&1 1>&2 2>&3)" || return 1
    printf '%s\n' "$out"
    return 0
  fi
  printf '\n%s\n\n' "$title" >&2
  local -a tags=()
  local i=1
  while (( $# >= 2 )); do
    printf '  %2d) %-18s %s\n' "$i" "$1" "$2" >&2
    tags+=("$1")
    i=$((i + 1))
    shift 2
  done
  local sel
  read -r -p "Select [1-${#tags[@]}]: " sel || return 1
  if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#tags[@]} )); then
    printf '%s\n' "${tags[$((sel - 1))]}"
    return 0
  fi
  # allow typing the tag itself
  if bm::core::in_list "$sel" "${tags[@]}"; then
    printf '%s\n' "$sel"
    return 0
  fi
  return 1
}

# NIC picker: shows eligible NICs with state/speed/driver; multi-select.
# Echoes selected NICs space-separated.
bm::ui::pick_nics() { # pick_nics <title> [exclude-csv]
  local title="$1" exclude="${2:-}"
  local -a eligible=()
  local n master
  bm::core::split_list "$exclude"
  local -a excl=("${BM_LIST[@]}")
  while IFS= read -r n; do
    [[ -z "$n" ]] && continue
    bm::core::in_list "$n" "${excl[@]:-}" && continue
    eligible+=("$n")
  done < <(bm::facts::eligible_nics)
  (( ${#eligible[@]} > 0 )) || {
    bm::ui::msg "No eligible NICs found. Adjust NIC_ALLOWLIST_PATTERNS / NIC_BLOCKLIST_PATTERNS in $BM_CONF."
    return 1
  }

  local -a items=()
  local info state spd drv
  for n in "${eligible[@]}"; do
    state="$(bm::facts::nic_state "$n")"
    spd="$(bm::facts::nic_speed "$n")"
    drv="$(bm::facts::nic_driver "$n")"
    master="$(bm::facts::nic_bond_master "$n")"
    info="state=$state speed=${spd}Mb/s driver=$drv"
    [[ -n "$master" ]] && info+=" IN-BOND:$master"
    items+=("$n" "$info")
  done

  if (( BM_UI_WHIPTAIL )); then
    local -a witems=()
    local i
    for ((i = 0; i < ${#items[@]}; i += 2)); do
      witems+=("${items[$i]}" "${items[$((i + 1))]}" OFF)
    done
    local out
    out="$(whiptail --title "$(bm::ui::title)" --checklist "$title" 22 84 12 \
      "${witems[@]}" 3>&1 1>&2 2>&3)" || return 1
    out="${out//\"/}"
    [[ -n "$out" ]] || return 1
    printf '%s\n' "$out"
    return 0
  fi

  {
    printf '\n%s\n\n' "$title"
    local j
    for ((j = 0; j < ${#items[@]}; j += 2)); do
      printf '  %-16s %s\n' "${items[$j]}" "${items[$((j + 1))]}"
    done
    printf '\n'
  } >&2
  local raw
  read -r -p "Interfaces (space-separated): " raw || return 1
  raw="$(tr -s ' ' <<<"$raw")"
  raw="${raw# }"
  raw="${raw% }"
  [[ -n "$raw" ]] || return 1
  printf '%s\n' "$raw"
}

bm::ui::pick_bond() { # menu over known bonds (kernel + NM profiles)
  local -a bonds=()
  local b
  while IFS= read -r b; do
    [[ -n "$b" ]] && bonds+=("$b")
  done < <(
    {
      bm::facts::kernel_bonds
      bm::nm::bond_cons | awk -F'\x1f' '{ print ($3 != "" ? $3 : $2) }'
    } | LC_ALL=C sort -u
  )
  (( ${#bonds[@]} > 0 )) || {
    bm::ui::msg "No bonds found on this system."
    return 1
  }
  local -a items=()
  for b in "${bonds[@]}"; do
    items+=("$b" "mode=$(bm::facts::bond_mode "$b")")
  done
  bm::ui::menu "Select a bond:" "${items[@]}"
}

bm::ui::confirm_exact() { # require typing an exact string (destructive ops)
  local what="$1" expected="$2"
  (( BM_ASSUME_YES )) && return 0
  local got
  if ! got="$(bm::ui::input "Type '$expected' to confirm $what")"; then
    return 1
  fi
  [[ "$got" == "$expected" ]]
}
