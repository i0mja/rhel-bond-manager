# lib/10-log.sh — structured logging to file, journal (via logger), and stderr.
# File logging is off by default so read-only commands never write anywhere;
# the plan engine and mutating commands call bm::log::enable_file first.
# shellcheck shell=bash
[[ -n "${BM_LIB_LOG:-}" ]] && return 0
BM_LIB_LOG=1

BM_LOG_TO_FILE=0
BM_LOG_OP=""   # operation tag included in every record, e.g. op=create

bm::log::enable_file() {
  BM_LOG_TO_FILE=1
  mkdir -p "$(dirname "$BM_LOG_FILE")" 2>/dev/null || true
}

bm::log::set_op() { BM_LOG_OP="$1"; }

bm::log::_emit() { # _emit <LEVEL> <message...>
  local level="$1"
  shift || true
  local tag=""
  [[ -n "$BM_LOG_OP" ]] && tag=" op=$BM_LOG_OP"
  local line
  line="[$(bm::core::timestamp)] [$level]$tag $*"
  if (( BM_LOG_TO_FILE )); then
    printf '%s\n' "$line" >>"$BM_LOG_FILE" 2>/dev/null || true
    if bm::core::have_cmd logger; then
      logger -t "$BM_PROG" -- "[$level]$tag $*" 2>/dev/null || true
    fi
  fi
  if (( BM_DEBUG )); then
    printf '%s\n' "$line" >&2
  fi
}

bm::log::info()  { bm::log::_emit INFO "$@"; }
bm::log::warn()  { bm::log::_emit WARN "$@"; }
bm::log::error() { bm::log::_emit ERROR "$@"; }
bm::log::debug() { (( BM_DEBUG )) && bm::log::_emit DEBUG "$@"; return 0; }

# User-facing progress line (suppressed by --quiet, never by --json parsing
# concerns: goes to stderr so stdout stays machine-readable).
bm::log::say() {
  (( BM_QUIET )) && return 0
  printf '%s\n' "$*" >&2
}

bm::log::render_logrotate() {
  cat <<EOF
# Managed by ${BM_PROG} v${BM_VERSION}
${BM_LOG_FILE} {
    $(bm::config::get LOGROTATE_FREQUENCY)
    rotate $(bm::config::get LOGROTATE_ROTATE)
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF
}
