# lib/40-json.sh — correct JSON emission in pure bash.
# Strings are escaped per RFC 8259 including control characters (\u00XX).
# Documents carry schema_version so consumers can detect format changes.
# shellcheck shell=bash
[[ -n "${BM_LIB_JSON:-}" ]] && return 0
BM_LIB_JSON=1

BM_JSON_SCHEMA_VERSION=1

bm::json::escape() {
  local s="$1" out="" c i o
  for ((i = 0; i < ${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      '"') out+='\"' ;;
      '\') out+='\\' ;;
      $'\n') out+='\n' ;;
      $'\r') out+='\r' ;;
      $'\t') out+='\t' ;;
      *)
        printf -v o '%d' "'$c"
        if (( o > 0 && o < 32 )); then
          printf -v c '\\u%04x' "$o"
        fi
        out+="$c"
        ;;
    esac
  done
  printf '%s' "$out"
}

bm::json::str() { printf '"%s"' "$(bm::json::escape "$1")"; }

bm::json::num_or_str() { # numbers stay numbers, everything else is a string
  if [[ "$1" =~ ^-?[0-9]+$ ]]; then
    printf '%s' "$1"
  else
    bm::json::str "$1"
  fi
}

bm::json::bool() { # bool <0|1|true|false>
  case "$1" in
    1 | true) printf 'true' ;;
    *) printf 'false' ;;
  esac
}

# Join pre-rendered JSON values into an array.
bm::json::arr() {
  local out="" v
  for v in "$@"; do
    [[ -n "$out" ]] && out+=","
    out+="$v"
  done
  printf '[%s]' "$out"
}

# Array of strings from lines on stdin.
bm::json::arr_of_lines() {
  local out="" line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ -n "$out" ]] && out+=","
    out+="$(bm::json::str "$line")"
  done
  printf '[%s]' "$out"
}
