# lib/50-ui.sh — the terminal toolkit: menus, checklists, text input, boxes
# and prompts, in pure bash (no whiptail, no dialog, nothing to install).
#
# Two modes, picked once by bm::ui::init:
#   fancy  a real terminal: arrow-key menus, colors, boxes, in-place redraw
#   plain  numbered prompts, 7-bit ASCII — serial consoles, --plain, pipes
#
# Contract for every widget: the answer goes into BM_UI_REPLY (and
# BM_UI_REPLY_LIST for multi-select), never through $(...) — widgets run in
# the caller's shell so terminal state and colors stay consistent. Return
# code 0 = answered, 1 = cancelled (Esc / q / back / Ctrl-C / end of input).
# On end of input BM_UI_EOF=1 is also set and every loop must stop.
#
# Everything is drawn on stderr and read from stdin, so stdout (plans,
# verification reports) stays in order and is never hidden behind a dialog.
# shellcheck shell=bash
[[ -n "${BM_LIB_UI:-}" ]] && return 0
BM_LIB_UI=1

BM_UI_MODE=""          # fancy | plain ("" = not yet initialised)
BM_UI_UTF8=0
BM_UI_ROWS=24
BM_UI_COLS=80
BM_UI_REPLY=""
BM_UI_REPLY_LIST=()
BM_UI_KEY=""
BM_UI_EOF=0
BM_UI_INTERRUPTED=0 # set by the menus' INT trap; a widget that acts on it clears it
BM_UI_INT_SEEN=0    # the last widget was left with Ctrl-C (the home screen asks to quit)
BM_UI_RESIZED=0
BM_UI_DRAWN=0          # height of the block currently drawn in place
BM_UI_VERR=""          # a validator's own error message
BM_UI_SEL=0            # menu cursor (position among selectable items)
BM_UI_TOP=0            # menu viewport start (item index)
BM_UI_HDR=()           # lines a --header function fills in
BM_UI_HDR_MAX=0        # how many header lines fit (set before calling it)
BM_UI_LINES=()         # scratch: lines of a frame
BM_UI_WRAPPED=()
BM_UI_VLEN=0
BM_UI_FIT=""
BM_UI_FMT=""
BM_UI_ROW=""
BM_UI_W=80
BM_UI_CHECKED=0
BM_UI_RULE=""

# ---- setup ------------------------------------------------------------------

bm::ui::_fancy_capable() {
  [[ "${BM_PLAIN:-0}" != 1 ]] || return 1
  [[ -t 0 && -t 1 && -t 2 ]] || return 1
  case "${TERM:-}" in
    "" | dumb | unknown | vt52) return 1 ;;
  esac
  local tty
  tty="$(readlink "/proc/$$/fd/0" 2>/dev/null || true)"
  case "$tty" in
    /dev/ttyS* | /dev/ttyAMA* | /dev/ttyUSB* | /dev/hvc* | /dev/ttysclp*) return 1 ;;
  esac
  stty -g >/dev/null 2>&1 || return 1
  return 0
}

bm::ui::init() { # init [--force]
  if [[ -n "$BM_UI_MODE" && "${1:-}" != --force ]]; then
    return 0
  fi
  BM_UI_MODE=plain
  if bm::ui::_fancy_capable; then
    BM_UI_MODE=fancy
  fi
  BM_UI_UTF8=0
  if [[ "$BM_UI_MODE" == fancy && "${BM_ASCII:-0}" != 1 && "${TERM:-}" != linux ]]; then
    # A UTF-8 locale that is not actually installed leaves bash in "C",
    # where this is three bytes long — the glyphs would come out as junk.
    local t='●'
    if (( ${#t} == 1 )); then
      BM_UI_UTF8=1
    fi
  fi
  bm::ui::_glyphs
  bm::ui::_styles
  bm::ui::_size
  return 0
}

bm::ui::_ensure_init() {
  if [[ -z "$BM_UI_MODE" ]]; then
    bm::ui::init
  fi
  return 0
}

bm::ui::fancy() { [[ "$BM_UI_MODE" == fancy ]]; }

bm::ui::_glyphs() {
  if (( BM_UI_UTF8 )); then
    BM_G_H='─' BM_G_V='│' BM_G_TL='┌' BM_G_TR='┐' BM_G_BL='└' BM_G_BR='┘'
    BM_G_TEE='├─' BM_G_END='└─' BM_G_DOT='●' BM_G_ODOT='○' BM_G_OK='✔' BM_G_BAD='✖'
    BM_G_PTR='❯' BM_G_LARR='←' BM_G_UP='▲' BM_G_DN='▼' BM_G_SEP='·' BM_G_ELL='…'
    BM_G_WARN='!' BM_G_ON='[x]' BM_G_OFF='[ ]' BM_G_ARROW='›' BM_G_BAR='━'
  else
    BM_G_H='-' BM_G_V='|' BM_G_TL='+' BM_G_TR='+' BM_G_BL='+' BM_G_BR='+'
    BM_G_TEE='|-' BM_G_END='`-' BM_G_DOT='*' BM_G_ODOT='o' BM_G_OK='[ok]' BM_G_BAD='x'
    BM_G_PTR='>' BM_G_LARR='<-' BM_G_UP='^' BM_G_DN='v' BM_G_SEP='-' BM_G_ELL='~'
    BM_G_WARN='!' BM_G_ON='[x]' BM_G_OFF='[ ]' BM_G_ARROW='>' BM_G_BAR='='
  fi
}

# SGR sequences as plain variables, so building a frame never forks. Colors
# follow BM_COLOR (NO_COLOR, --no-color, TERM=dumb); in fancy mode bold,
# dim and reverse stay on without color — they are emphasis, not hue.
bm::ui::_styles() {
  local e=$'\033['
  BM_S_RST="" BM_S_BOLD="" BM_S_DIM="" BM_S_REV=""
  BM_S_RED="" BM_S_GREEN="" BM_S_YELLOW="" BM_S_CYAN=""
  BM_S_BADGE_LIVE="" BM_S_BADGE_PRACTICE=""
  if (( BM_COLOR )) || [[ "$BM_UI_MODE" == fancy ]]; then
    BM_S_RST="${e}0m" BM_S_BOLD="${e}1m" BM_S_DIM="${e}2m" BM_S_REV="${e}7m"
    BM_S_BADGE_LIVE="${e}1;7m" BM_S_BADGE_PRACTICE="${e}1;7m"
  fi
  if (( BM_COLOR )); then
    BM_S_RED="${e}31m" BM_S_GREEN="${e}32m" BM_S_YELLOW="${e}33m"
    BM_S_CYAN="${e}36m"
    BM_S_BADGE_LIVE="${e}1;97;41m" BM_S_BADGE_PRACTICE="${e}1;30;43m"
  fi
}

bm::ui::_size() {
  local r="" c="" sz=""
  if [[ -t 0 ]] && sz="$(stty size 2>/dev/null)"; then
    read -r r c <<<"$sz" || true
  fi
  if ! [[ "$r" =~ ^[0-9]+$ ]] || (( r < 8 )); then r="${LINES:-}"; fi
  if ! [[ "$c" =~ ^[0-9]+$ ]] || (( c < 20 )); then c="${COLUMNS:-}"; fi
  if ! [[ "$r" =~ ^[0-9]+$ ]] || (( r < 8 )); then r=24; fi
  if ! [[ "$c" =~ ^[0-9]+$ ]] || (( c < 20 )); then c=80; fi
  BM_UI_ROWS="$r"
  BM_UI_COLS="$c"
  return 0
}

bm::ui::width() { # usable width for boxes and wrapped text -> BM_UI_W
  local w=$(( BM_UI_COLS - 1 ))
  if (( w > 100 )); then w=100; fi
  if (( w < 30 )); then w=30; fi
  BM_UI_W="$w"
}

# ---- text helpers (pure; unit-testable) ------------------------------------

bm::ui::vlen() { # vlen <text> -> BM_UI_VLEN, visible characters (SGR ignored)
  local s="$1" re=$'\033\\[[0-9;]*m'
  while [[ "$s" =~ $re ]]; do
    s="${s/"${BASH_REMATCH[0]}"/}"
  done
  BM_UI_VLEN=${#s}
}

# Cut <text> to at most <width> visible characters, ending in an ellipsis when
# something was cut. Escape sequences are copied through untouched.
bm::ui::fit() { # fit <text> <width> -> BM_UI_FIT
  local s="$1" w="$2"
  bm::ui::vlen "$s"
  if (( BM_UI_VLEN <= w )); then
    BM_UI_FIT="$s"
    return 0
  fi
  local out="" i=0 n=${#s} ch count=0 seq
  while (( i < n && count < w - 1 )); do
    ch="${s:i:1}"
    if [[ "$ch" == $'\033' && "${s:i+1:1}" == "[" ]]; then
      seq="${s:i}"
      seq="${seq%%m*}m"
      out+="$seq"
      i=$(( i + ${#seq} ))
      continue
    fi
    out+="$ch"
    count=$(( count + 1 ))
    i=$(( i + 1 ))
  done
  BM_UI_FIT="$out$BM_G_ELL$BM_S_RST"
}

bm::ui::pad() { # pad <text> <width> -> BM_UI_FIT, fitted and right-padded
  bm::ui::fit "$1" "$2"
  bm::ui::vlen "$BM_UI_FIT"
  local gap=$(( $2 - BM_UI_VLEN ))
  if (( gap > 0 )); then
    printf -v BM_UI_FIT '%s%*s' "$BM_UI_FIT" "$gap" ""
  fi
}

bm::ui::fmt_secs() { # fmt_secs <seconds> -> BM_UI_FMT "m:ss"
  local s="$1"
  if (( s < 0 )); then s=0; fi
  printf -v BM_UI_FMT '%d:%02d' $(( s / 60 )) $(( s % 60 ))
}

# Word-wrap plain text into BM_UI_WRAPPED (one element per line).
bm::ui::wrap() { # wrap <width> <text>
  local w="$1" text="$2" line="" word
  BM_UI_WRAPPED=()
  local -a words=()
  read -r -a words <<<"$text" || true
  for word in "${words[@]}"; do
    while (( ${#word} > w )); do
      if [[ -n "$line" ]]; then
        BM_UI_WRAPPED+=("$line")
        line=""
      fi
      BM_UI_WRAPPED+=("${word:0:w}")
      word="${word:w}"
    done
    if [[ -z "$line" ]]; then
      line="$word"
    elif (( ${#line} + 1 + ${#word} <= w )); then
      line+=" $word"
    else
      BM_UI_WRAPPED+=("$line")
      line="$word"
    fi
  done
  if [[ -n "$line" || ${#BM_UI_WRAPPED[@]} -eq 0 ]]; then
    BM_UI_WRAPPED+=("$line")
  fi
}

# ---- output primitives --------------------------------------------------------

bm::ui::_out() { printf '%s\n' "$@" >&2; }

# Answers read from a pipe are not echoed by a terminal; echo them so a
# scripted session (or a test transcript) reads like a real one.
bm::ui::_echo_piped() {
  if [[ ! -t 0 ]]; then
    printf '%s\n' "$1" >&2
  fi
  return 0
}

bm::ui::clear() { # fresh screen (fancy) or a visual break (plain)
  bm::ui::_ensure_init
  BM_UI_DRAWN=0
  if bm::ui::fancy; then
    printf '\033[H\033[2J' >&2
  else
    printf '\n' >&2
  fi
}

bm::ui::_para() { # _para <indent> <style> <text> — wrapped paragraph
  local indent="$1" style="$2" text="$3" l
  bm::ui::width
  bm::ui::wrap $(( BM_UI_W - ${#indent} )) "$text"
  for l in "${BM_UI_WRAPPED[@]}"; do
    printf '%s%s%s%s\n' "$indent" "$style" "$l" "${style:+$BM_S_RST}" >&2
  done
}

bm::ui::heading() { # heading <title> [step info, e.g. "Step 2 of 5"]
  bm::ui::_ensure_init
  local t="$1" step="${2:-}"
  printf '\n' >&2
  if bm::ui::fancy; then
    printf '%s%s%s %s%s%s%s\n' "$BM_S_CYAN" "$BM_G_BAR$BM_G_BAR" "$BM_S_RST" \
      "$BM_S_BOLD" "$t" "$BM_S_RST" "${step:+  $BM_S_DIM$step$BM_S_RST}" >&2
  else
    printf '== %s%s ==\n' "$t" "${step:+ ($step)}" >&2
  fi
}

bm::ui::note() { bm::ui::_ensure_init; bm::ui::_para "  " "" "$*"; }
bm::ui::dim() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_DIM" "$*"; }
bm::ui::ok() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_GREEN" "$BM_G_OK $*"; }
bm::ui::warn() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_YELLOW" "$BM_G_WARN $*"; }
bm::ui::err() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_RED" "$BM_G_BAD $*"; }
bm::ui::info() { bm::ui::_ensure_init; bm::ui::_para "  " "$BM_S_CYAN" "$*"; }

# Print literal lines (command output, help text) indented, untouched.
bm::ui::block() { # block <text>
  local l
  while IFS= read -r l; do
    printf '  %s\n' "$l" >&2
  done <<<"$1"
}

# Long text one screenful at a time, so its start does not scroll away on
# consoles with little or no scrollback (a Linux VT, iLO/iDRAC, serial).
# Only on a terminal: a piped session gets it all at once, as before.
bm::ui::page() { # page <text>
  bm::ui::_ensure_init
  local -a plines=()
  mapfile -t plines <<<"$1"
  bm::ui::_size
  local per=$(( BM_UI_ROWS - 3 )) i=0 ans rc
  if [[ ! -t 0 ]] || (( per < 5 || ${#plines[@]} <= per + 1 )); then
    bm::ui::block "$1"
    return 0
  fi
  while (( i < ${#plines[@]} )); do
    printf '  %s\n' "${plines[@]:i:per}" >&2
    i=$(( i + per ))
    (( i < ${#plines[@]} )) || break
    printf '%s-- more: Enter for the next page, q to stop (%d of %d lines) --%s' \
      "$BM_S_DIM" "$i" "${#plines[@]}" "$BM_S_RST" >&2
    rc=0
    bm::ui::_read_line || rc=$?
    ans="$BM_UI_LINE"
    printf '\r\033[K' >&2
    if (( rc != 0 )) || [[ "${ans,,}" == q* ]]; then
      (( rc == 1 )) && BM_UI_EOF=1
      break
    fi
  done
  return 0
}

# A bordered box. Lines are fitted to the width (never wrap).
bm::ui::box() { # box [--title T] [--badge B] [--style ok|warn|err|info] -- line...
  bm::ui::_ensure_init
  local title="" badge="" style=""
  while (( $# )); do
    case "$1" in
      --title) title="$2"; shift 2 ;;
      --badge) badge="$2"; shift 2 ;;
      --style) style="$2"; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  bm::ui::box_lines "$title" "$badge" "$style" "$@"
  printf '%s\n' "${BM_UI_LINES[@]}" >&2
}

# Build a box into BM_UI_LINES (so menus can embed it in their frame).
bm::ui::box_lines() { # box_lines <title> <badge> <style> line...
  local title="$1" badge="$2" style="$3"
  shift 3
  bm::ui::width
  local w="$BM_UI_W" bc="" inner l
  case "$style" in
    ok) bc="$BM_S_GREEN" ;;
    warn) bc="$BM_S_YELLOW" ;;
    err) bc="$BM_S_RED" ;;
    info) bc="$BM_S_CYAN" ;;
  esac
  inner=$(( w - 4 ))
  BM_UI_LINES=()
  # top border: ┌─ title ──── badge ─┐
  local top="$BM_G_TL$BM_G_H" used=2 rest
  if [[ -n "$title" ]]; then
    bm::ui::fit "$title" $(( inner - 12 ))
    top+=" $BM_S_RST$BM_S_BOLD$BM_UI_FIT$BM_S_RST$bc "
    bm::ui::vlen "$BM_UI_FIT"
    used=$(( used + BM_UI_VLEN + 2 ))
  fi
  local blen=0
  if [[ -n "$badge" ]]; then
    bm::ui::vlen "$badge"
    blen=$(( BM_UI_VLEN + 2 ))
  fi
  rest=$(( w - used - blen - 2 ))
  if (( rest < 1 )); then rest=1; fi
  local fill
  printf -v fill '%*s' "$rest" ""
  fill="${fill// /$BM_G_H}"
  top+="$fill"
  if [[ -n "$badge" ]]; then
    top+=" $BM_S_RST$badge$bc "
  fi
  top+="$BM_G_H$BM_G_TR"
  BM_UI_LINES+=("$bc$top$BM_S_RST")
  for l in "$@"; do
    bm::ui::pad "$l" "$inner"
    BM_UI_LINES+=("$bc$BM_G_V$BM_S_RST $BM_UI_FIT$BM_S_RST $bc$BM_G_V$BM_S_RST")
  done
  printf -v fill '%*s' $(( w - 2 )) ""
  fill="${fill// /$BM_G_H}"
  BM_UI_LINES+=("$bc$BM_G_BL$fill$BM_G_BR$BM_S_RST")
}

# Draw a block in place of the previous one (fancy): one printf per frame,
# relative cursor movement, every line fitted so nothing ever wraps.
bm::ui::_frame() { # _frame line...
  local out="" l
  local -i n=0
  bm::ui::width
  if (( BM_UI_DRAWN > 0 )); then
    out+=$'\r'$'\033['"${BM_UI_DRAWN}A"
  fi
  for l in "$@"; do
    bm::ui::fit "$l" $(( BM_UI_COLS - 1 ))
    out+=$'\r'"$BM_UI_FIT$BM_S_RST"$'\033[K\n'
    n=$(( n + 1 ))
  done
  out+=$'\033[J'
  printf '%s' "$out" >&2
  BM_UI_DRAWN=$n
}

bm::ui::_commit_block() { BM_UI_DRAWN=0; }

# ---- keyboard ---------------------------------------------------------------

bm::ui::_raw_on() {
  bm::ui::fancy || return 0
  if [[ -z "$BM_TTY_SAVED" ]]; then
    BM_TTY_SAVED="$(stty -g 2>/dev/null || true)"
  fi
  # susp undef: Ctrl-Z would stop the menus with the cursor hidden and the
  # terminal raw; the saved settings bring it back when the menus let go
  stty -echo -icanon min 1 time 0 susp undef 2>/dev/null || true
  printf '\033[?25l' >&2
  BM_TTY_CURSOR_HIDDEN=1
}

bm::ui::_raw_off() { bm::core::term_restore; }

# One line of input -> BM_UI_LINE. rc 0 = a line, 1 = end of input, 2 =
# Ctrl-C. A trapped Ctrl-C does not interrupt bash's line read, so on a
# terminal the line is read in 1-second slices with the flag checked in
# between (what is typed so far stays in the terminal's line buffer).
bm::ui::_read_line() {
  local line rc
  BM_UI_LINE=""
  if [[ ! -t 0 ]]; then
    IFS= read -r line || return 1
    BM_UI_LINE="$line"
    return 0
  fi
  while :; do
    rc=0
    IFS= read -r -t 1 line || rc=$?
    if (( BM_UI_INTERRUPTED )); then
      BM_UI_INTERRUPTED=0
      BM_UI_INT_SEEN=1
      printf '\n' >&2
      return 2
    fi
    if (( rc == 0 )); then
      BM_UI_LINE="$line"
      return 0
    fi
    (( rc > 128 )) || return 1
  done
}

bm::ui::_drain() { # discard type-ahead so a stray key never answers a prompt
  bm::ui::fancy || return 0
  local _k
  while IFS= read -rsn1 -t 0.01 _k; do :; done
  return 0
}

# Read one key into BM_UI_KEY. Named keys: UP DOWN LEFT RIGHT HOME END PGUP
# PGDN DELETE ENTER SPACE TAB BACKSPACE ESC CTRL_U CTRL_D INTERRUPT RESIZE
# UNKNOWN; anything else is the character itself.
# rc: 0 key, 1 timeout, 2 end of input (BM_UI_EOF=1).
bm::ui::read_key() { # read_key [timeout-seconds]
  local t="${1:-}" k="" k2="" k3="" c="" seq="" rc=0
  BM_UI_KEY=""
  if [[ -n "$t" ]]; then
    IFS= read -rsn1 -t "$t" k || rc=$?
  else
    IFS= read -rsn1 k || rc=$?
  fi
  if (( rc > 128 )); then
    if (( BM_UI_INTERRUPTED )); then
      # consumed here: left set, every later widget would "go back" on its
      # first idle second, unwinding the whole wizard
      BM_UI_INTERRUPTED=0
      BM_UI_INT_SEEN=1
      BM_UI_KEY=INTERRUPT
      return 0
    fi
    if (( BM_UI_RESIZED )); then
      BM_UI_KEY=RESIZE
      return 0
    fi
    return 1
  fi
  if (( rc != 0 )); then
    BM_UI_EOF=1
    BM_UI_KEY=EOF
    return 2
  fi
  case "$k" in
    "" | $'\r' | $'\n') BM_UI_KEY=ENTER ;;
    " ") BM_UI_KEY=SPACE ;;
    $'\t') BM_UI_KEY=TAB ;;
    $'\x7f' | $'\b') BM_UI_KEY=BACKSPACE ;;
    $'\x15') BM_UI_KEY=CTRL_U ;;
    $'\x04') BM_UI_KEY=CTRL_D ;;
    $'\033')
      if ! IFS= read -rsn1 -t 0.1 k2; then
        BM_UI_KEY=ESC
        return 0
      fi
      case "$k2" in
        "[" | O)
          if ! IFS= read -rsn1 -t 0.1 k3; then
            BM_UI_KEY=ESC
            return 0
          fi
          case "$k3" in
            A) BM_UI_KEY=UP ;;
            B) BM_UI_KEY=DOWN ;;
            C) BM_UI_KEY=RIGHT ;;
            D) BM_UI_KEY=LEFT ;;
            H) BM_UI_KEY=HOME ;;
            F) BM_UI_KEY=END ;;
            [0-9])
              seq="$k3"
              while IFS= read -rsn1 -t 0.1 c; do
                if [[ "$c" == "~" || "$c" == [A-Za-z] ]]; then
                  break
                fi
                seq+="$c"
                if (( ${#seq} > 6 )); then
                  break
                fi
              done
              case "$seq" in
                1 | 7) BM_UI_KEY=HOME ;;
                4 | 8) BM_UI_KEY=END ;;
                5) BM_UI_KEY=PGUP ;;
                6) BM_UI_KEY=PGDN ;;
                3) BM_UI_KEY=DELETE ;;
                *) BM_UI_KEY=UNKNOWN ;;
              esac
              ;;
            *) BM_UI_KEY=UNKNOWN ;;
          esac
          ;;
        *) BM_UI_KEY=ESC ;;
      esac
      ;;
    *) BM_UI_KEY="$k" ;;
  esac
  return 0
}

# ---- menu -------------------------------------------------------------------

# Pure cursor maths: move BM_UI_SEL among <count> selectable items.
bm::ui::_nav() { # _nav <key> <count> <page>
  local key="$1" count="$2" page="$3"
  if (( count <= 0 )); then
    BM_UI_SEL=0
    return 0
  fi
  case "$key" in
    UP | k) BM_UI_SEL=$(( (BM_UI_SEL - 1 + count) % count )) ;;
    DOWN | j | TAB) BM_UI_SEL=$(( (BM_UI_SEL + 1) % count )) ;;
    HOME | g) BM_UI_SEL=0 ;;
    END | G) BM_UI_SEL=$(( count - 1 )) ;;
    PGUP) BM_UI_SEL=$(( BM_UI_SEL - page )); if (( BM_UI_SEL < 0 )); then BM_UI_SEL=0; fi ;;
    PGDN) BM_UI_SEL=$(( BM_UI_SEL + page )); if (( BM_UI_SEL > count - 1 )); then BM_UI_SEL=$(( count - 1 )); fi ;;
  esac
  return 0
}

# Keep item <idx> inside a viewport of <vis> rows over <total> items.
bm::ui::_view() { # _view <idx> <total> <vis> [heading-above 0|1]
  local idx="$1" total="$2" vis="$3" head="${4:-0}"
  if (( idx < BM_UI_TOP )); then
    BM_UI_TOP=$idx
    if (( head && idx > 0 )); then BM_UI_TOP=$(( idx - 1 )); fi
  fi
  if (( idx >= BM_UI_TOP + vis )); then
    BM_UI_TOP=$(( idx - vis + 1 ))
  fi
  if (( BM_UI_TOP > total - vis )); then BM_UI_TOP=$(( total - vis )); fi
  if (( BM_UI_TOP < 0 )); then BM_UI_TOP=0; fi
  return 0
}

# Shared by menu and checklist: parse "TAG LABEL..." pairs.
bm::ui::_items() {
  _tags=()
  _labels=()
  _sel_idx=()
  local i=0
  while (( $# >= 2 )); do
    _tags+=("$1")
    _labels+=("$2")
    if [[ "$1" != "-" ]]; then
      _sel_idx+=("$i")
    fi
    i=$(( i + 1 ))
    shift 2
  done
}

# One item row for fancy frames: "  ❯ 1  Label   note" -> BM_UI_ROW
bm::ui::_item_row() { # _item_row <selected 0|1> <number-or-empty> <label> [mark]
  local selected="$1" num="$2" label="$3" mark="${4:-}" main note=""
  main="${label%%$'\t'*}"
  if [[ "$label" == *$'\t'* ]]; then
    note="${label#*$'\t'}"
  fi
  local ptr="  " numtxt="   "
  if [[ -n "$num" ]]; then
    printf -v numtxt '%-2s ' "$num"
  fi
  if (( selected )); then
    ptr="$BM_S_CYAN$BM_G_PTR$BM_S_RST "
    BM_UI_ROW=" $ptr$BM_S_DIM$numtxt$BM_S_RST$mark$BM_S_REV$BM_S_BOLD $main $BM_S_RST${note:+  $BM_S_DIM$note$BM_S_RST}"
  else
    BM_UI_ROW=" $ptr$BM_S_DIM$numtxt$BM_S_RST$mark $main ${note:+  $BM_S_DIM$note$BM_S_RST}"
  fi
}

# menu [--default TAG] [--header FN] [--refresh S] [--keys "p r ?"]
#      [--footer TEXT] -- TITLE TAG LABEL [TAG LABEL ...]
# A TAG of "-" is a non-selectable heading. LABEL may be "main<TAB>note".
# Keys listed in --keys return rc 0 with BM_UI_REPLY="key:<k>".
bm::ui::menu() {
  bm::ui::_ensure_init
  local def="" header="" refresh="" keys="" footer=""
  while (( $# )); do
    case "$1" in
      --default) def="$2"; shift 2 ;;
      --header) header="$2"; shift 2 ;;
      --refresh) refresh="$2"; shift 2 ;;
      --keys) keys="$2"; shift 2 ;;
      --footer) footer="$2"; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  local title="$1"
  shift
  local -a _tags=() _labels=() _sel_idx=()
  bm::ui::_items "$@"
  BM_UI_REPLY=""
  local count=${#_sel_idx[@]}
  if (( count == 0 )); then
    return 1
  fi
  BM_UI_SEL=0
  local p
  if [[ -n "$def" ]]; then
    for p in "${!_sel_idx[@]}"; do
      if [[ "${_tags[${_sel_idx[$p]}]}" == "$def" ]]; then
        BM_UI_SEL=$p
      fi
    done
  fi
  if bm::ui::fancy; then
    bm::ui::_menu_fancy
  else
    bm::ui::_menu_plain
  fi
}

bm::ui::_menu_plain() {
  local i n=0
  if [[ -n "$header" ]]; then
    BM_UI_HDR_MAX=40
    BM_UI_HDR=()
    "$header"
    if (( ${#BM_UI_HDR[@]} > 0 )); then
      printf '%s\n' "${BM_UI_HDR[@]}" >&2
    fi
  fi
  printf '\n%s%s%s\n' "$BM_S_BOLD" "$title" "$BM_S_RST" >&2
  for i in "${!_tags[@]}"; do
    if [[ "${_tags[$i]}" == "-" ]]; then
      printf '   %s\n' "${_labels[$i]}" >&2
      continue
    fi
    n=$(( n + 1 ))
    local main="${_labels[$i]%%$'\t'*}" note=""
    if [[ "${_labels[$i]}" == *$'\t'* ]]; then note="${_labels[$i]#*$'\t'}"; fi
    printf '  %2d) %s%s\n' "$n" "$main" "${note:+  ($note)}" >&2
  done
  local extra="" qword=back own_quit=0
  if [[ " $keys " == *" q "* ]]; then
    qword=quit
  fi
  for i in "${_sel_idx[@]}"; do
    if [[ "${_tags[$i]}" == quit ]]; then own_quit=1; fi
  done
  # q always works; list it only when the menu has no Quit item of its own
  if (( ! own_quit )); then
    printf '   q) %s\n' "${qword^}" >&2
  fi
  local k
  local -a keylist=()
  read -r -a keylist <<<"$keys" || true # an array, so '?' is never a glob
  for k in "${keylist[@]}"; do
    case "$k" in
      p) extra+="   p) practice on/off" ;;
      r) extra+="   r) refresh" ;;
      "?") extra+="   ?) help" ;;
    esac
  done
  if [[ -n "$extra" ]]; then
    printf '%s\n' "$extra" >&2
  fi
  local defnum=$(( BM_UI_SEL + 1 )) ans
  while :; do
    if [[ -n "$def" ]]; then
      printf 'Choose 1-%d [%d] (q = %s): ' "$count" "$defnum" "$qword" >&2
    else
      printf 'Choose 1-%d (q = %s): ' "$count" "$qword" >&2
    fi
    local lrc=0
    bm::ui::_read_line || lrc=$?
    if (( lrc == 2 )); then return 1; fi # Ctrl-C: back
    if (( lrc != 0 )); then
      printf '\n' >&2
      BM_UI_EOF=1
      return 1
    fi
    ans="$BM_UI_LINE"
    bm::ui::_echo_piped "$ans"
    ans="${ans#"${ans%%[![:space:]]*}"}"
    ans="${ans%"${ans##*[![:space:]]}"}"
    if [[ -z "$ans" && -n "$def" ]]; then
      ans="$defnum"
    fi
    if [[ -n "$ans" && " $keys " == *" $ans "* ]]; then
      BM_UI_REPLY="key:$ans"
      return 0
    fi
    case "${ans,,}" in
      q | back | 0 | quit | exit) return 1 ;;
    esac
    if [[ "$ans" =~ ^[0-9]{1,6}$ ]] && (( 10#$ans >= 1 && 10#$ans <= count )); then
      BM_UI_SEL=$(( 10#$ans - 1 )) # 10#: "010" is ten, not octal eight
      BM_UI_REPLY="${_tags[${_sel_idx[$BM_UI_SEL]}]}"
      return 0
    fi
    for i in "${_sel_idx[@]}"; do
      if [[ "${_tags[$i]}" == "$ans" ]]; then
        BM_UI_REPLY="$ans"
        return 0
      fi
    done
    printf '  Please type a number from 1 to %d (or q).\n' "$count" >&2
  done
}

# Build the frame for the current menu state into BM_UI_LINES.
bm::ui::_menu_lines() {
  local total=${#_tags[@]} i vis avail hdr_n
  BM_UI_LINES=()
  local -a hdr=()
  if [[ -n "$header" ]]; then
    # the choices come first: the header gets what the items leave over
    local want=$total half=$(( BM_UI_ROWS / 2 ))
    if (( half < 6 )); then half=6; fi
    if (( want > half )); then want=$half; fi
    BM_UI_HDR_MAX=$(( BM_UI_ROWS - 3 - want ))
    BM_UI_HDR=()
    "$header"
    hdr=("${BM_UI_HDR[@]}")
    BM_UI_LINES=() # the header may have used it as scratch space
  fi
  hdr_n=${#hdr[@]}
  avail=$(( BM_UI_ROWS - 1 - hdr_n - 3 ))
  vis=$total
  if (( vis > avail )); then
    vis=$(( avail - 2 ))
    if (( vis < 3 )); then vis=3; fi
  fi
  local cur=${_sel_idx[$BM_UI_SEL]} head=0
  if (( cur > 0 )) && [[ "${_tags[$((cur - 1))]}" == "-" ]]; then head=1; fi
  bm::ui::_view "$cur" "$total" "$vis" "$head"
  if (( hdr_n > 0 )); then
    BM_UI_LINES+=("${hdr[@]}")
  fi
  BM_UI_LINES+=("$BM_S_BOLD$title$BM_S_RST")
  if (( vis < total )); then
    if (( BM_UI_TOP > 0 )); then
      BM_UI_LINES+=("    $BM_S_DIM$BM_G_UP $BM_UI_TOP more$BM_S_RST")
    else
      BM_UI_LINES+=("")
    fi
  fi
  local end=$(( BM_UI_TOP + vis )) num p
  for ((i = BM_UI_TOP; i < end && i < total; i++)); do
    if [[ "${_tags[$i]}" == "-" ]]; then
      BM_UI_LINES+=("   $BM_S_DIM${_labels[$i]}$BM_S_RST")
      continue
    fi
    num=""
    for p in "${!_sel_idx[@]}"; do
      if (( _sel_idx[p] == i )); then
        if (( p < 9 )); then num=$(( p + 1 )); fi
        break
      fi
    done
    bm::ui::_item_row $(( i == cur )) "$num" "${_labels[$i]}"
    BM_UI_LINES+=("$BM_UI_ROW")
  done
  if (( vis < total )); then
    if (( end < total )); then
      BM_UI_LINES+=("    $BM_S_DIM$BM_G_DN $(( total - end )) more$BM_S_RST")
    else
      BM_UI_LINES+=("")
    fi
  fi
  local hint="$BM_G_UP$BM_G_DN move $BM_G_SEP Enter choose $BM_G_SEP 1-9 jump $BM_G_SEP Esc back"
  if [[ -n "$footer" ]]; then
    hint="$footer"
  fi
  BM_UI_LINES+=(" $BM_S_DIM$hint$BM_S_RST")
}

bm::ui::_menu_fancy() {
  local cur rc redraw=1
  BM_UI_TOP=0
  BM_UI_DRAWN=0
  bm::ui::_raw_on
  while :; do
    if (( redraw )); then
      bm::ui::_menu_lines
      bm::ui::_frame "${BM_UI_LINES[@]}"
    fi
    redraw=1
    rc=0
    bm::ui::read_key "${refresh:-1}" || rc=$?
    if (( rc == 2 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      BM_UI_EOF=1
      return 1
    fi
    if (( rc == 1 )); then
      # timeout: only a live header (countdown, --refresh) needs a redraw
      if [[ -z "$refresh" ]]; then redraw=0; fi
      continue
    fi
    case "$BM_UI_KEY" in
      RESIZE)
        BM_UI_RESIZED=0
        bm::ui::_size
        printf '\033[H\033[2J' >&2
        BM_UI_DRAWN=0
        continue
        ;;
      INTERRUPT)
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 1
        ;;
    esac
    if [[ ${#BM_UI_KEY} == 1 && " $keys " == *" $BM_UI_KEY "* ]]; then
      bm::ui::_raw_off
      bm::ui::_commit_block
      BM_UI_REPLY="key:$BM_UI_KEY"
      return 0
    fi
    case "$BM_UI_KEY" in
      ENTER | RIGHT | l | SPACE)
        cur=${_sel_idx[$BM_UI_SEL]}
        BM_UI_REPLY="${_tags[$cur]}"
        bm::ui::_frame "$BM_S_DIM$title$BM_S_RST $BM_G_ARROW ${_labels[$cur]%%$'\t'*}"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 0
        ;;
      [1-9])
        if (( BM_UI_KEY <= count )); then
          BM_UI_SEL=$(( BM_UI_KEY - 1 ))
          cur=${_sel_idx[$BM_UI_SEL]}
          BM_UI_REPLY="${_tags[$cur]}"
          bm::ui::_frame "$BM_S_DIM$title$BM_S_RST $BM_G_ARROW ${_labels[$cur]%%$'\t'*}"
          bm::ui::_raw_off
          bm::ui::_commit_block
          return 0
        fi
        ;;
      ESC | q | Q | LEFT | h | BACKSPACE | CTRL_D)
        bm::ui::_frame "$BM_S_DIM$title $BM_G_ARROW (back)$BM_S_RST"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 1
        ;;
      *)
        bm::ui::_nav "$BM_UI_KEY" "$count" 8
        ;;
    esac
  done
}

# ---- checklist ----------------------------------------------------------------

# checklist [--min N] [--max N] [--on TAG,TAG] [--header FN] -- TITLE TAG LABEL...
# Result: BM_UI_REPLY_LIST (tags, in list order), BM_UI_REPLY (comma-joined).
bm::ui::checklist() {
  bm::ui::_ensure_init
  local min=1 max=0 on="" header="" footer=""
  while (( $# )); do
    case "$1" in
      --min) min="$2"; shift 2 ;;
      --max) max="$2"; shift 2 ;;
      --on) on="$2"; shift 2 ;;
      --header) header="$2"; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  local title="$1"
  shift
  local -a _tags=() _labels=() _sel_idx=() _chk=()
  bm::ui::_items "$@"
  local count=${#_sel_idx[@]} i p
  (( count > 0 )) || return 1
  if (( max <= 0 || max > count )); then max=$count; fi
  for i in "${!_tags[@]}"; do
    _chk[i]=0
    if [[ ",$on," == *",${_tags[$i]},"* ]]; then _chk[i]=1; fi
  done
  BM_UI_REPLY=""
  BM_UI_REPLY_LIST=()
  BM_UI_SEL=0
  local rc=0
  if bm::ui::fancy; then
    bm::ui::_check_fancy || rc=$?
  else
    bm::ui::_check_plain || rc=$?
  fi
  (( rc == 0 )) || return "$rc"
  for p in "${_sel_idx[@]}"; do
    if (( _chk[p] )); then
      BM_UI_REPLY_LIST+=("${_tags[$p]}")
    fi
  done
  BM_UI_REPLY="$(bm::core::join , "${BM_UI_REPLY_LIST[@]}")"
  return 0
}

bm::ui::_check_count() {
  local p n=0
  for p in "${_sel_idx[@]}"; do
    if (( _chk[p] )); then n=$(( n + 1 )); fi
  done
  BM_UI_CHECKED=$n
}

bm::ui::_check_rule() { # the min/max rule in words
  if (( min == max )); then
    BM_UI_RULE="pick exactly $min"
  elif (( max >= count )); then
    BM_UI_RULE="pick at least $min"
  else
    BM_UI_RULE="pick $min to $max"
  fi
}

bm::ui::_check_plain() {
  local ans tok n i p ok
  bm::ui::_check_rule
  while :; do
    printf '\n%s%s%s  (%s)\n' "$BM_S_BOLD" "$title" "$BM_S_RST" "$BM_UI_RULE" >&2
    n=0
    for i in "${!_tags[@]}"; do
      if [[ "${_tags[$i]}" == "-" ]]; then
        printf '   %s\n' "${_labels[$i]}" >&2
        continue
      fi
      n=$(( n + 1 ))
      local mark="$BM_G_OFF" main="${_labels[$i]%%$'\t'*}" note=""
      if (( _chk[i] )); then mark="$BM_G_ON"; fi
      if [[ "${_labels[$i]}" == *$'\t'* ]]; then note="${_labels[$i]#*$'\t'}"; fi
      printf '  %2d) %s %s%s\n' "$n" "$mark" "$main" "${note:+  ($note)}" >&2
    done
    bm::ui::_check_count
    if (( BM_UI_CHECKED > 0 )); then
      printf 'Type the numbers to pick, e.g. 1 2 (Enter = keep ticked, q = back): ' >&2
    else
      printf 'Type the numbers to pick, e.g. 1 2 (q = back): ' >&2
    fi
    local lrc=0
    bm::ui::_read_line || lrc=$?
    if (( lrc == 2 )); then return 1; fi # Ctrl-C: back
    if (( lrc != 0 )); then
      printf '\n' >&2
      BM_UI_EOF=1
      return 1
    fi
    ans="$BM_UI_LINE"
    bm::ui::_echo_piped "$ans"
    case "${ans,,}" in
      q | back) return 1 ;;
    esac
    if [[ -n "${ans//[[:space:],]/}" ]]; then
      local -a newchk=()
      for i in "${!_tags[@]}"; do newchk[i]=0; done
      ok=1
      local -a toks=()
      read -r -a toks <<<"${ans//,/ }" || true
      for tok in "${toks[@]}"; do
        local found=0
        if [[ "$tok" =~ ^[0-9]{1,6}$ ]] && (( 10#$tok >= 1 && 10#$tok <= count )); then
          newchk[${_sel_idx[$((10#$tok - 1))]}]=1
          found=1
        else
          for p in "${_sel_idx[@]}"; do
            if [[ "${_tags[$p]}" == "$tok" ]]; then
              newchk[p]=1
              found=1
            fi
          done
        fi
        if (( ! found )); then
          printf '  "%s" is not on the list - use the numbers shown.\n' "$tok" >&2
          ok=0
        fi
      done
      (( ok )) || continue
      _chk=("${newchk[@]}")
    fi
    bm::ui::_check_count
    if (( BM_UI_CHECKED < min || BM_UI_CHECKED > max )); then
      printf '  Please %s.\n' "$BM_UI_RULE" >&2
      continue
    fi
    return 0
  done
}

bm::ui::_check_fancy() {
  local total=${#_tags[@]} vis i num p cur rc msg=""
  bm::ui::_check_rule
  BM_UI_TOP=0
  BM_UI_DRAWN=0
  bm::ui::_raw_on
  while :; do
    BM_UI_LINES=()
    local -a hdr=()
    if [[ -n "$header" ]]; then
      BM_UI_HDR_MAX=6
      BM_UI_HDR=()
      "$header"
      hdr=("${BM_UI_HDR[@]}")
    fi
    vis=$(( BM_UI_ROWS - 6 - ${#hdr[@]} ))
    if (( vis > total )); then vis=$total; fi
    if (( vis < 3 )); then vis=3; fi
    cur=${_sel_idx[$BM_UI_SEL]}
    bm::ui::_view "$cur" "$total" "$vis"
    local -a frame=()
    if (( ${#hdr[@]} > 0 )); then frame+=("${hdr[@]}"); fi
    bm::ui::_check_count
    frame+=("$BM_S_BOLD$title$BM_S_RST  $BM_S_DIM($BM_UI_RULE; $BM_UI_CHECKED picked)$BM_S_RST")
    if (( vis < total )); then
      if (( BM_UI_TOP > 0 )); then frame+=("    $BM_S_DIM$BM_G_UP $BM_UI_TOP more$BM_S_RST"); else frame+=(""); fi
    fi
    for ((i = BM_UI_TOP; i < BM_UI_TOP + vis && i < total; i++)); do
      if [[ "${_tags[$i]}" == "-" ]]; then
        frame+=("   $BM_S_DIM${_labels[$i]}$BM_S_RST")
        continue
      fi
      num=""
      for p in "${!_sel_idx[@]}"; do
        if (( _sel_idx[p] == i )); then
          if (( p < 9 )); then num=$(( p + 1 )); fi
          break
        fi
      done
      local mark="$BM_G_OFF"
      if (( _chk[i] )); then mark="$BM_S_GREEN$BM_G_ON$BM_S_RST"; fi
      bm::ui::_item_row $(( i == cur )) "$num" "${_labels[$i]}" "$mark"
      frame+=("$BM_UI_ROW")
    done
    if (( vis < total )); then
      if (( BM_UI_TOP + vis < total )); then
        frame+=("    $BM_S_DIM$BM_G_DN $(( total - BM_UI_TOP - vis )) more$BM_S_RST")
      else
        frame+=("")
      fi
    fi
    if [[ -n "$msg" ]]; then
      frame+=(" $BM_S_YELLOW$BM_G_WARN $msg$BM_S_RST")
    else
      frame+=(" $BM_S_DIM""Space tick $BM_G_SEP 1-9 tick $BM_G_SEP a all $BM_G_SEP n none $BM_G_SEP Enter done $BM_G_SEP Esc back$BM_S_RST")
    fi
    bm::ui::_frame "${frame[@]}"
    msg=""
    rc=0
    bm::ui::read_key 1 || rc=$?
    if (( rc == 2 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      return 1
    fi
    (( rc == 0 )) || continue
    case "$BM_UI_KEY" in
      RESIZE)
        BM_UI_RESIZED=0
        bm::ui::_size
        printf '\n' >&2
        BM_UI_DRAWN=0
        ;;
      SPACE | x)
        _chk[cur]=$(( 1 - _chk[cur] ))
        ;;
      [1-9])
        if (( BM_UI_KEY <= count )); then
          BM_UI_SEL=$(( BM_UI_KEY - 1 ))
          p=${_sel_idx[$BM_UI_SEL]}
          _chk[p]=$(( 1 - _chk[p] ))
        fi
        ;;
      a | A)
        for p in "${_sel_idx[@]}"; do _chk[p]=1; done
        ;;
      n | N)
        for p in "${_sel_idx[@]}"; do _chk[p]=0; done
        ;;
      ENTER | RIGHT)
        bm::ui::_check_count
        if (( BM_UI_CHECKED < min || BM_UI_CHECKED > max )); then
          msg="Please $BM_UI_RULE (Space ticks the highlighted line)."
          continue
        fi
        local picked=""
        for p in "${_sel_idx[@]}"; do
          if (( _chk[p] )); then picked+="${picked:+, }${_tags[$p]}"; fi
        done
        bm::ui::_frame "$BM_S_DIM$title$BM_S_RST $BM_G_ARROW $picked"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 0
        ;;
      ESC | q | Q | LEFT | CTRL_D | INTERRUPT)
        bm::ui::_frame "$BM_S_DIM$title $BM_G_ARROW (back)$BM_S_RST"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 1
        ;;
      *)
        bm::ui::_nav "$BM_UI_KEY" "$count" 8
        ;;
    esac
  done
}

# ---- text input ---------------------------------------------------------------

# input [--default V] [--validate FN] [--error MSG] [--example EX] [--optional]
#       -- PROMPT
# FN "<value>" returns 0 when acceptable; it may set BM_UI_VERR to explain.
bm::ui::input() {
  bm::ui::_ensure_init
  local def="" validate="" errmsg="" example="" optional=0
  while (( $# )); do
    case "$1" in
      --default) def="$2"; shift 2 ;;
      --validate) validate="$2"; shift 2 ;;
      --error) errmsg="$2"; shift 2 ;;
      --example) example="$2"; shift 2 ;;
      --optional) optional=1; shift ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  local prompt="$1"
  BM_UI_REPLY=""
  if bm::ui::fancy; then
    bm::ui::_input_fancy
  else
    bm::ui::_input_plain
  fi
}

# Shared acceptance check: sets _why when the value is refused.
bm::ui::_input_ok() { # _input_ok <value>
  local v="$1"
  _why=""
  if [[ -z "$v" ]]; then
    if (( optional )); then return 0; fi
    _why="Please type something (or go back)."
    return 1
  fi
  if [[ -n "$validate" ]]; then
    BM_UI_VERR=""
    if ! "$validate" "$v"; then
      _why="${BM_UI_VERR:-${errmsg:-That does not look right.}}"
      if [[ -n "$example" ]]; then
        _why+=" Example: $example"
      fi
      return 1
    fi
  fi
  return 0
}

bm::ui::_input_plain() {
  local v _why
  if [[ -n "$example" ]]; then
    printf '  (example: %s)\n' "$example" >&2
  fi
  while :; do
    if [[ -n "$def" ]]; then
      printf '%s [%s]: ' "$prompt" "$def" >&2
    elif (( optional )); then
      printf '%s (Enter = none): ' "$prompt" >&2
    else
      printf '%s: ' "$prompt" >&2
    fi
    local lrc=0
    bm::ui::_read_line || lrc=$?
    if (( lrc == 2 )); then return 1; fi # Ctrl-C: back
    if (( lrc != 0 )); then
      printf '\n' >&2
      BM_UI_EOF=1
      return 1
    fi
    v="$BM_UI_LINE"
    bm::ui::_echo_piped "$v"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    case "$v" in
      q | back) return 1 ;;
    esac
    if [[ -z "$v" ]]; then v="$def"; fi
    if bm::ui::_input_ok "$v"; then
      BM_UI_REPLY="$v"
      return 0
    fi
    printf '  %s\n' "$_why" >&2
  done
}

bm::ui::_input_fancy() {
  local buf="$def" rc _why="" shown
  BM_UI_DRAWN=0
  bm::ui::_raw_on
  while :; do
    local -a frame=("$BM_S_BOLD$prompt$BM_S_RST")
    shown="$buf"
    if (( ${#buf} > BM_UI_COLS - 8 )); then
      shown="$BM_G_ELL${buf: -$(( BM_UI_COLS - 10 ))}"
    fi
    frame+=("  $BM_S_CYAN$BM_G_ARROW$BM_S_RST $shown$BM_S_REV $BM_S_RST")
    if [[ -n "$_why" ]]; then
      frame+=("  $BM_S_RED$BM_G_BAD $_why$BM_S_RST")
    elif [[ -n "$example" ]]; then
      frame+=("  $BM_S_DIM""example: $example $BM_G_SEP Enter OK $BM_G_SEP Esc back$BM_S_RST")
    else
      frame+=("  $BM_S_DIM""Enter OK $BM_G_SEP Esc back$BM_S_RST")
    fi
    bm::ui::_frame "${frame[@]}"
    rc=0
    bm::ui::read_key 1 || rc=$?
    if (( rc == 2 )); then
      bm::ui::_raw_off
      bm::ui::_commit_block
      return 1
    fi
    (( rc == 0 )) || continue
    case "$BM_UI_KEY" in
      ENTER)
        buf="${buf#"${buf%%[![:space:]]*}"}"
        buf="${buf%"${buf##*[![:space:]]}"}"
        if bm::ui::_input_ok "$buf"; then
          BM_UI_REPLY="$buf"
          bm::ui::_frame "$BM_S_DIM$prompt$BM_S_RST $BM_G_ARROW ${buf:-(none)}"
          bm::ui::_raw_off
          bm::ui::_commit_block
          return 0
        fi
        ;;
      ESC | CTRL_D | INTERRUPT)
        bm::ui::_frame "$BM_S_DIM$prompt $BM_G_ARROW (back)$BM_S_RST"
        bm::ui::_raw_off
        bm::ui::_commit_block
        return 1
        ;;
      BACKSPACE)
        buf="${buf%?}"
        _why=""
        ;;
      CTRL_U)
        buf=""
        _why=""
        ;;
      SPACE)
        buf+=" "
        _why=""
        ;;
      RESIZE)
        BM_UI_RESIZED=0
        bm::ui::_size
        ;;
      *)
        if (( ${#BM_UI_KEY} == 1 )) && [[ "$BM_UI_KEY" == [[:print:]] ]]; then
          buf+="$BM_UI_KEY"
          _why=""
        fi
        ;;
    esac
  done
}

# ---- prompts ------------------------------------------------------------------

# yesno [--default y|n] <question> -> 0 yes / 1 no. Always a typed line
# (y + Enter): one stray keypress must never apply a plan. The plain path is
# byte-for-byte the historical behavior scripts and tests rely on.
bm::ui::yesno() {
  local def=n
  if [[ "${1:-}" == --default ]]; then
    def="${2:-n}"
    shift 2
  fi
  local msg="$1"
  if (( BM_ASSUME_YES )); then
    return 0
  fi
  bm::ui::_ensure_init
  local ans="" hint="[y/N]" rc=0
  if [[ "$def" == y ]]; then hint="[Y/n]"; fi
  # read -p only shows its prompt on a terminal; keep that, so a scripted
  # transcript reads as before
  if bm::ui::fancy; then
    bm::ui::_drain
    [[ -t 0 ]] && printf '%s' "$BM_S_BOLD$msg$BM_S_RST $hint: " >&2
  elif [[ -t 0 ]]; then
    printf '%s' "$msg $hint: " >&2
  fi
  bm::ui::_read_line || rc=$?
  ans="$BM_UI_LINE"
  if (( rc == 2 )); then return 1; fi # Ctrl-C is a no
  if (( rc != 0 )); then
    # end of input: no answer, so no (an explicit y is needed either way)
    return 1
  fi
  if [[ -z "$ans" && "$def" == y ]]; then
    return 0
  fi
  [[ "${ans,,}" == y || "${ans,,}" == yes ]]
}

bm::ui::confirm_exact() { # require typing an exact string (destructive ops)
  local what="$1" expected="$2"
  if (( BM_ASSUME_YES )); then
    return 0
  fi
  bm::ui::_ensure_init
  bm::ui::note "This cannot be undone with a key press. To be sure it is not a slip of the finger, type the name exactly as shown."
  if ! bm::ui::input -- "Type '$expected' to confirm $what"; then
    return 1
  fi
  [[ "$BM_UI_REPLY" == "$expected" ]]
}

bm::ui::pause() { # pause [prompt]
  bm::ui::_ensure_init
  local prompt="${1:-Press Enter to go back}" rc
  if bm::ui::fancy; then
    printf '%s%s%s' "$BM_S_DIM" "$prompt" "$BM_S_RST" >&2
    bm::ui::_raw_on
    while :; do
      rc=0
      bm::ui::read_key 1 || rc=$?
      if (( rc == 2 )); then break; fi
      (( rc == 0 )) || continue
      case "$BM_UI_KEY" in
        ENTER | ESC | SPACE | q | Q | INTERRUPT | CTRL_D | LEFT) break ;;
      esac
    done
    bm::ui::_raw_off
    printf '\r\033[K' >&2
  else
    printf '%s... ' "$prompt" >&2
    rc=0
    bm::ui::_read_line || rc=$?
    if (( rc == 1 )); then
      BM_UI_EOF=1
    fi
    if (( rc != 2 )); then printf '\n' >&2; fi

  fi
  return 0
}

bm::ui::msg() { # msg <text> — show text, then wait for Enter
  bm::ui::_ensure_init
  printf '\n%b\n\n' "$1" >&2
  bm::ui::pause
}

# ---- commit gate ------------------------------------------------------------

bm::ui::gate_intro() { # gate_intro <tier>
  bm::ui::_ensure_init
  local tier="$1" t
  local -a lines=("$BM_S_GREEN$BM_G_OK All checks passed - your change is live.$BM_S_RST" "") text=()
  if [[ "$tier" == snapshot ]]; then
    text=("Nothing will undo it automatically on this server.")
  else
    text=("If you do nothing, it is UNDONE automatically when the time runs out."
      "That is the safety net: if this change cut your connection, just wait.")
  fi
  # wrapped, not cut: on a narrow terminal (a tmux split, a phone) these
  # sentences are the point of the box
  bm::ui::width
  for t in "${text[@]}"; do
    bm::ui::wrap $(( BM_UI_W - 4 )) "$t"
    lines+=("${BM_UI_WRAPPED[@]}")
  done
  lines+=("")
  case "$tier" in
    snapshot) lines+=("  K  keep it       U  undo it now (restore the backup copy)") ;;
    checkpoint) lines+=("  K  keep it       U  undo it now       E  5 more minutes") ;;
    *) lines+=("  K  keep it       U  undo it now") ;;
  esac
  printf '\n' >&2
  bm::ui::box --title "Keep this change?" --style ok -- "${lines[@]}"
  BM_UI_DRAWN=0
}

bm::ui::gate_status() { # gate_status <seconds-left> <tier> [message]
  local left="$1" tier="$2" m="${3:-}" col="$BM_S_GREEN" ext="" note=""
  if [[ "$tier" == checkpoint ]]; then ext="  [E]+5 min"; fi
  if [[ -n "$m" ]]; then note="  $BM_S_YELLOW$m$BM_S_RST"; fi
  if [[ "$tier" == snapshot ]]; then
    bm::ui::_frame "$BM_S_BOLD""Keep this change?$BM_S_RST  [K]eep  [U]ndo" "$note"
    return 0
  fi
  bm::ui::fmt_secs "$left"
  if (( left <= 20 )); then
    col="$BM_S_RED"
  elif (( left <= 60 )); then
    col="$BM_S_YELLOW"
  fi
  # the countdown first: on a narrow terminal the end of the line is cut
  bm::ui::_frame "Auto-undo in $col$BM_S_BOLD$BM_UI_FMT$BM_S_RST   ${BM_S_BOLD}[K]eep  [U]ndo$ext$BM_S_RST" "$note"
}
