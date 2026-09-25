# lib/15-config.sh — /etc/bond_manager.conf handling.
# The file is parsed line-by-line against a key allowlist and NEVER sourced,
# so a writable config can no longer inject shell that runs as root.
# v2.x key names are kept verbatim for compatibility.
# shellcheck shell=bash
[[ -n "${BM_LIB_CONFIG:-}" ]] && return 0
BM_LIB_CONFIG=1

declare -A BM_CFG=(
  [DEFAULT_MIIMON]="100"
  [DEFAULT_8023AD_LACP_RATE]="fast"
  [DEFAULT_8023AD_XHP]="layer3+4"
  [MAX_BACKUPS]="10"
  [LOGROTATE_FREQUENCY]="weekly"
  [LOGROTATE_ROTATE]="12"
  [NIC_ALLOWLIST_PATTERNS]="^(ens|enp|eno|eth|em|p[0-9]+p)[0-9].*"
  [NIC_BLOCKLIST_PATTERNS]="^lo\$ ^veth.* ^docker.* ^br-.* ^virbr.* ^vnet.* ^tun.* ^tap.* ^nm-.* ^wl.* ^bond.* ^team.* ^ovs.* ^cali.* ^flannel.* ^cni.*"
  [ROLLBACK_WINDOW]="120"
  [ACTIVATE_TIMEOUT]="45"
  [LINK_SETTLE_TIMEOUT]="15"
  [MIN_SPEED_MBPS]="0"
)

bm::config::get() { printf '%s' "${BM_CFG[$1]:-}"; }
bm::config::set() { BM_CFG["$1"]="$2"; }

bm::config::_valid_value() { # _valid_value <key> <value>
  local key="$1" val="$2"
  case "$key" in
    DEFAULT_MIIMON | MAX_BACKUPS | LOGROTATE_ROTATE | ROLLBACK_WINDOW | \
      ACTIVATE_TIMEOUT | LINK_SETTLE_TIMEOUT | MIN_SPEED_MBPS)
      [[ "$val" =~ ^[0-9]+$ ]] ;;
    DEFAULT_8023AD_LACP_RATE) [[ "$val" == fast || "$val" == slow ]] ;;
    DEFAULT_8023AD_XHP)
      bm::core::in_list "$val" layer2 layer2+3 layer3+4 encap2+3 encap3+4 vlan+srcmac ;;
    LOGROTATE_FREQUENCY) bm::core::in_list "$val" daily weekly monthly ;;
    NIC_ALLOWLIST_PATTERNS | NIC_BLOCKLIST_PATTERNS)
      # Regex lists: reject anything that could smuggle shell metacharacters
      # into contexts beyond [[ =~ ]].
      [[ "$val" != *'`'* && "$val" != *'$('* ]] ;;
    *) return 1 ;;
  esac
}

# Parse the config file. Unknown keys and malformed lines are reported to
# stderr (once) and ignored; valid keys override the built-in defaults.
bm::config::load() {
  [[ -r "$BM_CONF" ]] || return 0
  local line key val n=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    # strip comments and surrounding whitespace
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    if [[ ! "$line" =~ ^([A-Z0-9_]+)=(.*)$ ]]; then
      bm::log::say "$(bm::core::c_warn "config: ignoring malformed line $n in $BM_CONF")"
      continue
    fi
    key="${BASH_REMATCH[1]}"
    val="${BASH_REMATCH[2]}"
    # strip one layer of matching quotes
    if [[ "$val" == \"*\" || "$val" == \'*\' ]]; then
      val="${val:1:${#val}-2}"
    fi
    if [[ -z "${BM_CFG[$key]+x}" ]]; then
      bm::log::say "$(bm::core::c_warn "config: ignoring unknown key '$key' (line $n)")"
      continue
    fi
    if ! bm::config::_valid_value "$key" "$val"; then
      bm::log::say "$(bm::core::c_warn "config: rejecting invalid value for '$key' (line $n)")"
      continue
    fi
    BM_CFG["$key"]="$val"
  done <"$BM_CONF"
}

bm::config::default_text() {
  cat <<'EOF'
# /etc/bond_manager.conf — bond-manager configuration.
#
# This file is parsed (KEY="value" per line), not executed. Unknown keys and
# invalid values are ignored with a warning.

# Bond tuning defaults
DEFAULT_MIIMON="100"
DEFAULT_8023AD_LACP_RATE="fast"       # fast|slow
DEFAULT_8023AD_XHP="layer3+4"         # layer2|layer2+3|layer3+4|encap2+3|encap3+4

# Snapshots / log rotation
MAX_BACKUPS="10"
LOGROTATE_FREQUENCY="weekly"          # daily|weekly|monthly
LOGROTATE_ROTATE="12"

# NIC selection policy (space-separated ERE patterns)
NIC_ALLOWLIST_PATTERNS="^(ens|enp|eno|eth|em|p[0-9]+p)[0-9].*"
NIC_BLOCKLIST_PATTERNS="^lo$ ^veth.* ^docker.* ^br-.* ^virbr.* ^vnet.* ^tun.* ^tap.* ^nm-.* ^wl.* ^bond.* ^team.* ^ovs.* ^cali.* ^flannel.* ^cni.*"

# Safety engine
ROLLBACK_WINDOW="120"                 # seconds before auto-rollback of an unconfirmed change
ACTIVATE_TIMEOUT="45"                 # seconds to wait for nmcli activation
LINK_SETTLE_TIMEOUT="15"              # seconds to wait for links to settle before verify

# Warn when a selected member NIC reports less than this speed in Mb/s (0 = off)
MIN_SPEED_MBPS="0"
EOF
}

# Install the default config and logrotate policy (only `init` calls this).
bm::config::install() {
  bm::core::require_root
  bm::core::ensure_tmpdir || bm::core::die "could not create a temporary directory in ${TMPDIR:-/tmp}" "$BM_EX_ERR"
  if [[ ! -f "$BM_CONF" ]]; then
    local tmp
    tmp="${BM_TMPDIR:?}/conf"
    bm::config::default_text >"$tmp"
    install -m 0640 -o root -g root "$tmp" "$BM_CONF"
    bm::log::say "installed default config at $BM_CONF"
  else
    bm::log::say "config already present at $BM_CONF (left unchanged)"
  fi
  local tmp2
  tmp2="${BM_TMPDIR:?}/logrotate"
  bm::log::render_logrotate >"$tmp2"
  if [[ ! -f "$BM_LOGROTATE_CONF" ]] || ! cmp -s "$tmp2" "$BM_LOGROTATE_CONF"; then
    install -m 0644 -o root -g root "$tmp2" "$BM_LOGROTATE_CONF"
    bm::log::say "installed logrotate policy at $BM_LOGROTATE_CONF"
  fi
  mkdir -p "$BM_BACKUP_DIR" "$BM_SUPPORT_DIR"
  chmod 0750 "$BM_BACKUP_DIR" "$BM_SUPPORT_DIR" 2>/dev/null || true
}
