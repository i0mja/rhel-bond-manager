#!/usr/bin/env bash
# RHEL Bond Manager (Revised UX/TUI - Professional)
# Interactive NetworkManager bond helper for RHEL-like 8/9
# SPDX-License-Identifier: MIT
# shellcheck shell=bash

set -Eeuo pipefail

VERSION="2.1.0"

# -----------------------------
# Constants & Paths
# -----------------------------
LOG_FILE="/var/log/bond_manager.log"
BACKUP_DIR="/var/backups/bond_manager"
SUPPORT_DIR="/var/log/bond_manager/support"
LOGROTATE_CONF="/etc/logrotate.d/bond_manager"
CONN_DIR="/etc/NetworkManager/system-connections"
CONFIG_FILE="/etc/bond_manager.conf"
MAX_BACKUPS=10

# -----------------------------
# Runtime flags (default)
# -----------------------------
DRY_RUN=false
DEBUG=false
FLAG_STATUS=false
EXPORT_JSON_PATH=""

# -----------------------------
# Default tunables (may be overridden by CONFIG_FILE)
# -----------------------------
DEFAULT_MIIMON="100"
DEFAULT_8023AD_LACP_RATE="fast"
DEFAULT_8023AD_XHP="layer3+4"

LOGROTATE_FREQUENCY="weekly"
LOGROTATE_ROTATE="12"

# NIC selection policy (ERE patterns, space-separated).
NIC_ALLOWLIST_PATTERNS="^(ens|enp|eth)[0-9].*"
NIC_BLOCKLIST_PATTERNS="^lo$ ^veth.* ^docker.* ^br-.* ^virbr.* ^vnet.* ^tun.* ^tap.* ^nm-.* ^wl.* ^bond.* ^team.* ^ovs.*"

# -----------------------------
# Utilities
# -----------------------------
timestamp() { date +'%Y-%m-%dT%H:%M:%S%z'; }

_log_common() {
  local level="$1"; shift || true
  local msg="$*"
  local line="[$(timestamp)] [$level] $msg"
  mkdir -p "$(dirname "$LOG_FILE")"
  printf '%s\n' "$line" >> "$LOG_FILE" || true
  if [[ "$DEBUG" == "true" ]]; then
    printf '%s\n' "$line" >&2
  fi
}

log_info()  { _log_common INFO  "$*"; }
log_warn()  { _log_common WARN  "$*"; }
log_error() { _log_common ERROR "$*"; }

die() { log_error "$*"; echo "ERROR: $*" >&2; exit 1; }

on_error() {
  local line="$1"
  local cmd="$2"
  log_error "Line $line failed: $cmd"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

require_root() { [[ $EUID -eq 0 ]] || die "This utility must be run as root."; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

run_nmcli() {
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "DRY-RUN nmcli $*"
    echo "[DRY-RUN] nmcli $*"
    return 0
  fi
  log_info "nmcli $*"
  nmcli "$@"
}

run_cmd() { log_info "RUN $*"; "$@"; }

write_text_if_changed() {
  local path="$1" text="$2" tmp
  tmp="$(mktemp)"
  printf '%s\n' "$text" > "$tmp"
  if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
    return 0
  fi
  install -m 0640 -o root -g root "$tmp" "$path"
  rm -f "$tmp"
}

render_logrotate_conf() {
  cat <<EOF
# Managed by bond_manager.sh v${VERSION}
${LOG_FILE} {
    ${LOGROTATE_FREQUENCY}
    rotate ${LOGROTATE_ROTATE}
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF
}

ensure_config() {
  if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<'EOF'
# /etc/bond_manager.conf
# Managed by bond_manager.sh. Edit values below to change defaults.

DEFAULT_MIIMON="100"
DEFAULT_8023AD_LACP_RATE="fast"       # fast|slow
DEFAULT_8023AD_XHP="layer3+4"         # layer2|layer3+4|layer2+3

MAX_BACKUPS="10"
LOGROTATE_FREQUENCY="weekly"          # daily|weekly|monthly
LOGROTATE_ROTATE="12"

NIC_ALLOWLIST_PATTERNS="^(ens|enp|eth)[0-9].*"
NIC_BLOCKLIST_PATTERNS="^lo$ ^veth.* ^docker.* ^br-.* ^virbr.* ^vnet.* ^tun.* ^tap.* ^nm-.* ^wl.* ^bond.* ^team.* ^ovs.*"
EOF
    chmod 0640 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE" || true
    log_info "Installed default config at $CONFIG_FILE"
  fi

  # shellcheck disable=SC1090
  . "$CONFIG_FILE" || die "Failed to source $CONFIG_FILE"

  : "${DEFAULT_MIIMON:=${DEFAULT_MIIMON}}"
  : "${DEFAULT_8023AD_LACP_RATE:=${DEFAULT_8023AD_LACP_RATE}}"
  : "${DEFAULT_8023AD_XHP:=${DEFAULT_8023AD_XHP}}"
  : "${LOGROTATE_FREQUENCY:=${LOGROTATE_FREQUENCY}}"
  : "${LOGROTATE_ROTATE:=${LOGROTATE_ROTATE}}"
  : "${MAX_BACKUPS:=${MAX_BACKUPS}}"
  : "${NIC_ALLOWLIST_PATTERNS:=${NIC_ALLOWLIST_PATTERNS}}"
  : "${NIC_BLOCKLIST_PATTERNS:=${NIC_BLOCKLIST_PATTERNS}}"
}

ensure_first_run_artifacts() {
  mkdir -p "$BACKUP_DIR" "$SUPPORT_DIR"
  touch "$LOG_FILE"
  local lr
  lr="$(render_logrotate_conf)"
  write_text_if_changed "$LOGROTATE_CONF" "$lr"
}

restore_selinux_contexts() {
  if have_cmd restorecon; then
    log_info "Restoring SELinux contexts for $CONN_DIR"
    run_cmd restorecon -RFv "$CONN_DIR" || true
  else
    log_warn "restorecon not found; skipping SELinux context restore."
  fi
}

# -----------------------------
# Preflight checks
# -----------------------------
check_requirements() {
  have_cmd nmcli || die "nmcli not found; install NetworkManager."
  systemctl is-active --quiet NetworkManager || die "NetworkManager is not active. Run: systemctl enable --now NetworkManager"

  if ! modprobe -n bonding >/dev/null 2>&1 && ! lsmod | grep -q '^bonding'; then
    log_warn "Bonding module not detected; attempting to load."
  fi
  if ! lsmod | grep -q '^bonding'; then
    modprobe bonding >/dev/null 2>&1 || die "Unable to load bonding kernel module."
  fi

  local reqs=(ip tar ping awk sed ethtool journalctl)
  for b in "${reqs[@]}"; do
    have_cmd "$b" || die "Missing required command: $b"
  done
}

# -----------------------------
# Backups & Rollback
# -----------------------------
backup_networkmanager() {
  require_root
  mkdir -p "$BACKUP_DIR"
  local ts archive
  ts="$(date +'%Y%m%d%H%M%S')"
  archive="$BACKUP_DIR/conn-${ts}.tar.gz"
  log_info "Creating NetworkManager backup at $archive"
  tar -C "$CONN_DIR" -czf "$archive" .
  echo "$archive"

  mapfile -t backups < <(ls -1t "$BACKUP_DIR"/conn-*.tar.gz 2>/dev/null || true)
  local count="${#backups[@]}"
  if (( count > MAX_BACKUPS )); then
    for ((i=MAX_BACKUPS; i<count; i++)); do
      log_info "Removing old backup ${backups[$i]}"
      rm -f "${backups[$i]}"
    done
  fi
}

restore_last_backup() {
  require_root
  mapfile -t backups < <(ls -1t "$BACKUP_DIR"/conn-*.tar.gz 2>/dev/null || true)
  (( ${#backups[@]} > 0 )) || die "No backups found in $BACKUP_DIR"
  local latest="${backups[0]}"
  log_info "Restoring backup $latest"
  tar -C "$CONN_DIR" -xzf "$latest"
  restore_selinux_contexts
  systemctl reload NetworkManager || true
  echo "Restored from $latest"
}

# -----------------------------
# Discovery helpers
# -----------------------------
list_bonds() {
  if ls /proc/net/bonding/* >/dev/null 2>&1; then
    basename -a /proc/net/bonding/* 2>/dev/null || true
    return
  fi
  nmcli -t -f NAME,TYPE con show | awk -F: '$2=="bond"{print $1}'
}

bond_exists() {
  local bond="$1"
  [[ -n "$bond" ]] || return 1
  [[ -e "/proc/net/bonding/$bond" ]] && return 0
  nmcli -t -f NAME,TYPE con show | awk -F: -v b="$bond" '$2=="bond" && $1==b {found=1} END{exit !found}'
}

bond_slaves_from_proc() {
  local bond="$1"
  [[ -r "/proc/net/bonding/$bond" ]] || return 0
  awk -F': +' '/^Slave Interface:/{print $2}' "/proc/net/bonding/$bond" | tr -d '[:space:]'
}

bond_mode_from_proc() {
  local bond="$1"
  awk -F': +' '/^Bonding Mode:/{print $2}' "/proc/net/bonding/$bond" 2>/dev/null | head -n1
}

is_10g() {
  local ifname="$1" spd=""
  if [[ -r "/sys/class/net/$ifname/speed" ]]; then
    spd="$(cat "/sys/class/net/$ifname/speed" 2>/dev/null || echo "")"
  fi
  if [[ -z "$spd" || "$spd" == "unknown" ]]; then
    spd="$(ethtool "$ifname" 2>/dev/null | awk -F': ' '/Speed:/{gsub(/[^0-9]/,"",$2);print $2}')"
  fi
  [[ -n "$spd" && "$spd" -ge 10000 ]]
}

nic_exists() { [[ -e "/sys/class/net/$1" ]]; }

_match_any() {
  local text="$1"; shift || true
  local p
  for p in "$@"; do
    [[ -z "$p" ]] && continue
    if [[ "$text" =~ $p ]]; then return 0; fi
  done
  return 1
}

nic_allowed() {
  local ifname="$1"
  local -a allow=() block=()
  # shellcheck disable=SC2206
  allow=($NIC_ALLOWLIST_PATTERNS)
  # shellcheck disable=SC2206
  block=($NIC_BLOCKLIST_PATTERNS)

  _match_any "$ifname" "${block[@]}" && return 1
  (( ${#allow[@]} == 0 )) && return 0
  _match_any "$ifname" "${allow[@]}" && return 0
  return 1
}

validate_slaves() {
  local -a out=()
  local s
  for s in "$@"; do
    if ! nic_exists "$s"; then
      log_warn "Skipping $s: interface not found."
      continue
    fi
    if ! nic_allowed "$s"; then
      log_warn "Skipping $s: blocked by NIC policy (see $CONFIG_FILE)."
      continue
    fi
    if grep -Rqs "Slave Interface: $s" /proc/net/bonding/* 2>/dev/null; then
      log_warn "$s appears to already be in a bond."
    fi
    out+=("$s")
  done
  (( ${#out[@]} > 0 )) || die "No eligible member NICs after validation. Adjust NIC_* patterns in $CONFIG_FILE."
  printf '%s ' "${out[@]}"
}

# -----------------------------
# Summary (human + JSON)
# -----------------------------
json_escape() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r/\\r/g' -e 's/\n/\\n/g'; }

bond_summary_json() {
  mapfile -t bonds < <(list_bonds)
  echo "["
  local first_bond=true
  for b in "${bonds[@]}"; do
    $first_bond || echo ","
    first_bond=false

    local mode mii active primary
    mode="$(awk -F': +' '/^Bonding Mode:/{print $2}' "/proc/net/bonding/$b" 2>/dev/null | head -n1)"
    mii="$(awk -F': +' '/^MII Status:/{print $2}' "/proc/net/bonding/$b" 2>/dev/null | head -n1)"
    active="$(awk -F': +' '/^Currently Active Slave:/{print $2}' "/proc/net/bonding/$b" 2>/dev/null | head -n1)"
    primary="$(awk -F': +' '/^Primary Slave:/{print $2}' "/proc/net/bonding/$b" 2>/dev/null | head -n1)"
    [[ -z "$mode" ]] && mode="unknown"
    [[ -z "$mii" ]] && mii="unknown"
    [[ -z "$active" ]] && active="unknown"
    [[ -z "$primary" ]] && primary=""

    mapfile -t slaves < <(bond_slaves_from_proc "$b")
    echo "  {"
    echo "    \"bond\": \"$(echo "$b" | json_escape)\","
    echo "    \"mode\": \"$(echo "$mode" | json_escape)\","
    echo "    \"mii_status\": \"$(echo "$mii" | json_escape)\","
    echo "    \"active_slave\": \"$(echo "$active" | json_escape)\","
    echo "    \"primary_slave\": \"$(echo "$primary" | json_escape)\","
    echo "    \"slaves\": ["
    local first=true
    for s in "${slaves[@]}"; do
      $first || echo ","
      first=false
      local state speed
      state="$(cat "/sys/class/net/$s/operstate" 2>/dev/null || echo "unknown")"
      speed="$(cat "/sys/class/net/$s/speed" 2>/dev/null || echo "unknown")"
      echo "      {\"name\": \"$(echo "$s" | json_escape)\", \"state\": \"$(echo "$state" | json_escape)\", \"speed\": \"$(echo "$speed" | json_escape)\"}"
    done
    echo "    ]"
    local addrs; addrs="$(ip -json addr show dev "$b" 2>/dev/null || echo "[]")"
    echo "   ,\"addresses\": $addrs"
    mapfile -t vlans < <(nmcli -t -f NAME,TYPE,DEVICE con show | awk -F: -v b="$b" '$2=="vlan" && $3 ~ ("^" b "\\.") {print $1}')
    echo "   ,\"vlans\": ["
    first=true
    for v in "${vlans[@]}"; do
      $first || echo ","
      first=false
      echo "      \"$(echo "$v" | json_escape)\""
    done
    echo "    ]"
    echo "  }"
  done
  echo "]"
}

bond_summary_human() {
  mapfile -t bonds < <(list_bonds)
  if (( ${#bonds[@]} == 0 )); then
    echo "No bonds detected."
    return
  fi
  for b in "${bonds[@]}"; do
    echo "=== $b ==="
    if [[ -r "/proc/net/bonding/$b" ]]; then
      awk '
        /^Bonding Mode:/ || /^MII Status:/ || /^Currently Active Slave:/ || /^Primary Slave:/ ||
        /^Slave Interface:/ || /^Speed:/ || /^Duplex:/ { print }' "/proc/net/bonding/$b"
    else
      echo "(No /proc/net/bonding/$b; showing link info)"
      ip -br link show "$b" || true
    fi
    echo
  done
}

export_json() {
  local path="$1"
  [[ -n "$path" ]] || die "--export-json requires a path"
  mkdir -p "$(dirname "$path")"
  bond_summary_json > "$path"
  echo "JSON written to $path"
  log_info "Exported JSON to $path"
}

# -----------------------------
# NetworkManager profile operations
# -----------------------------
create_bond_profile() {
  local bond="$1" mode="$2" miimon="$3" lacp_rate="$4" xhp="$5" arp_targets="$6"
  require_root
  local opts="mode=$mode,miimon=$miimon"
  if [[ "$mode" == "802.3ad" ]]; then
    [[ -n "$lacp_rate" ]] && opts+=",lacp_rate=$lacp_rate"
    [[ -n "$xhp" ]] && opts+=",xmit_hash_policy=$xhp"
  fi
  if [[ -n "$arp_targets" ]]; then
    opts+=",arp_interval=250,arp_ip_target=$arp_targets"
  fi
  run_nmcli connection add type bond ifname "$bond" con-name "$bond" bond.options "$opts"
}

add_bond_slaves() {
  local bond="$1"; shift || true
  local slaves=("$@")
  local s
  for s in "${slaves[@]}"; do
    run_nmcli connection add type bond-slave ifname "$s" con-name "${bond}-slave-${s}" master "$bond"
  done
}

up_conn() { run_nmcli connection up "$1"; }

configure_ip() {
  local con="$1" method="$2" ipaddr="$3" gw="$4" dns="$5"
  if [[ "$method" == "dhcp" ]]; then
    run_nmcli connection modify "$con" ipv4.method auto ipv6.method ignore
  else
    run_nmcli connection modify "$con" ipv4.addresses "$ipaddr" ipv4.gateway "$gw" ipv4.method manual ipv6.method ignore
    [[ -n "$dns" ]] && run_nmcli connection modify "$con" ipv4.dns "$dns"
  fi
}

create_vlan_profile() {
  local bond="$1" vid="$2"
  local vlan_if="${bond}.${vid}"
  run_nmcli connection add type vlan ifname "$vlan_if" con-name "$vlan_if" dev "$bond" id "$vid"
  echo "$vlan_if"
}

delete_bond_profile() {
  local bond="$1"
  require_root

  mapfile -t vlan_cons < <(nmcli -t -f NAME,TYPE,DEVICE con show | awk -F: -v b="$bond" '$2=="vlan" && $3 ~ ("^" b "\\.") {print $1}')
  local v
  for v in "${vlan_cons[@]}"; do
    run_nmcli connection down "$v" || true
    run_nmcli connection delete "$v" || true
  done

  mapfile -t slave_cons < <(nmcli -t -f NAME,TYPE,MASTER con show | awk -F: -v b="$bond" '$2 ~ /bond-?slave/ && $3==b {print $1}')
  local s
  for s in "${slave_cons[@]}"; do
    run_nmcli connection down "$s" || true
    run_nmcli connection delete "$s" || true
  done

  run_nmcli connection down "$bond" || true
  run_nmcli connection delete "$bond" || true
  restore_selinux_contexts
}

# -----------------------------
# UI layer (whiptail preferred, fallback to plain prompts)
# -----------------------------
USE_WHIPTAIL=false
init_ui() {
  if have_cmd whiptail && [[ -t 0 ]]; then
    USE_WHIPTAIL=true
  fi
}

ui_title() {
  local mode="LIVE"
  [[ "$DRY_RUN" == "true" ]] && mode="DRY-RUN"
  echo "RHEL Bond Manager v$VERSION ($mode)"
}

ui_msg() {
  local msg="$1"
  if [[ "$USE_WHIPTAIL" == "true" ]]; then
    whiptail --title "$(ui_title)" --msgbox "$msg" 18 78
  else
    echo -e "\n$msg\n"
    read -r -p "Press Enter to continue..." _ || true
  fi
}

ui_yesno() {
  local msg="$1"
  if [[ "$USE_WHIPTAIL" == "true" ]]; then
    whiptail --title "$(ui_title)" --yesno "$msg" 18 78
    return $?
  fi
  read -r -p "$msg [y/N]: " ans || true
  [[ "${ans,,}" == "y" ]]
}

ui_input() {
  local prompt="$1" def="${2:-}"
  if [[ "$USE_WHIPTAIL" == "true" ]]; then
    local out
    out="$(whiptail --title "$(ui_title)" --inputbox "$prompt" 12 78 "$def" 3>&1 1>&2 2>&3)" || return 1
    echo "$out"
    return 0
  fi
  local v
  read -r -p "$prompt${def:+ [$def]}: " v || true
  [[ -z "$v" ]] && v="$def"
  echo "$v"
}

ui_menu() {
  local title="$1"; shift
  if [[ "$USE_WHIPTAIL" == "true" ]]; then
    local out
    out="$(whiptail --title "$(ui_title)" --menu "$title" 22 88 12 "$@" 3>&1 1>&2 2>&3)" || return 1
    echo "$out"
    return 0
  fi
  echo -e "\n$title\n"
  while (( $# )); do
    printf "  %s) %s\n" "$1" "$2"
    shift 2
  done
  local sel
  read -r -p "Select: " sel || true
  echo "$sel"
}

ui_checklist_nics() {
  local title="$1"
  local -a nics=()
  mapfile -t nics < <(ls -1 /sys/class/net 2>/dev/null | awk '{print $1}')
  local -a eligible=()
  local n
  for n in "${nics[@]}"; do
    nic_allowed "$n" || continue
    eligible+=("$n")
  done
  (( ${#eligible[@]} > 0 )) || die "No eligible NICs found (policy may be too strict)."

  if [[ "$USE_WHIPTAIL" == "true" ]]; then
    local -a items=()
    for n in "${eligible[@]}"; do
      local state spd
      state="$(cat "/sys/class/net/$n/operstate" 2>/dev/null || echo "?")"
      spd="$(cat "/sys/class/net/$n/speed" 2>/dev/null || echo "?")"
      items+=("$n" "state=$state speed=$spd" "OFF")
    done
    local out
    out="$(whiptail --title "$(ui_title)" --checklist "$title" 22 88 12 "${items[@]}" 3>&1 1>&2 2>&3)" || return 1
    echo "$out" | tr -d '"' | tr -s ' ' ' '
    return 0
  fi

  ui_msg "Eligible interfaces:\n\n$(printf '%s\n' "${eligible[@]}")\n\nEnter interface names separated by spaces."
  ui_input "Member interfaces (space-separated)" ""
}

select_bond() {
  mapfile -t bonds < <(list_bonds)
  (( ${#bonds[@]} > 0 )) || die "No bonds detected."
  if [[ "$USE_WHIPTAIL" == "true" ]]; then
    local -a items=()
    local b
    for b in "${bonds[@]}"; do
      local mode
      mode="$(bond_mode_from_proc "$b" 2>/dev/null || echo "unknown")"
      items+=("$b" "$mode")
    done
    ui_menu "Select a bond:" "${items[@]}"
  else
    ui_msg "Available bonds:\n\n$(printf '%s\n' "${bonds[@]}")"
    ui_input "Bond name" "${bonds[0]}"
  fi
}

confirm_exact() {
  local what="$1" expected="$2"
  local got
  got="$(ui_input "Type '$expected' to confirm ${what}" "")" || return 1
  [[ "$got" == "$expected" ]]
}

# -----------------------------
# Workflows (grouped)
# -----------------------------
post_change_prompt() {
  restore_selinux_contexts
  if [[ "$DRY_RUN" == "true" ]]; then
    ui_msg "Dry-run complete. No changes were applied."
    return
  fi
  if ui_yesno "Change complete. Restore the most recent backup now?"; then
    restore_last_backup
    ui_msg "Rollback complete."
  fi
}

workflow_overview() {
  ui_msg "Bond overview:\n\n$(bond_summary_human 2>&1 || true)"
}

workflow_diagnose() {
  local bond
  bond="$(select_bond)" || return 0
  [[ -n "$bond" ]] || return 0
  bond_exists "$bond" || die "Bond '$bond' not found."

  local target
  target="$(ui_input "Ping target (for per-interface test)" "8.8.8.8")" || return 0
  [[ -z "$target" ]] && target="8.8.8.8"

  local out=""
  out+="--- /proc/net/bonding/$bond ---\n"
  if [[ -r "/proc/net/bonding/$bond" ]]; then
    out+="$(cat "/proc/net/bonding/$bond")\n"
  else
    out+="(No /proc data)\n"
  fi

  out+="\n--- Link state ---\n"
  out+="$(ip -br link show "$bond" 2>&1 || true)\n"
  mapfile -t slaves < <(bond_slaves_from_proc "$bond")
  local s
  for s in "${slaves[@]}"; do
    out+="$(ip -br link show "$s" 2>&1 || true)\n"
  done

  out+="\n--- Pings (per slave via -I) to $target ---\n"
  for s in "${slaves[@]}"; do
    out+="\n>> $s\n"
    out+="$(ping -c 3 -W 1 -I "$s" "$target" 2>&1 || true)\n"
  done

  ui_msg "$out"
}

workflow_extended_diag() {
  local bond
  bond="$(select_bond)" || return 0
  [[ -n "$bond" ]] || return 0
  bond_exists "$bond" || die "Bond '$bond' not found."

  local target
  target="$(ui_input "Ping target (for per-interface test)" "8.8.8.8")" || return 0
  [[ -z "$target" ]] && target="8.8.8.8"

  local out=""
  out+="--- /proc/net/bonding/$bond ---\n"
  out+="$(cat "/proc/net/bonding/$bond" 2>/dev/null || echo "(No /proc data)")\n"

  out+="\n--- Link state ---\n"
  out+="$(ip -br link show "$bond" 2>&1 || true)\n"
  mapfile -t slaves < <(bond_slaves_from_proc "$bond")
  local s
  for s in "${slaves[@]}"; do
    out+="$(ip -br link show "$s" 2>&1 || true)\n"
  done

  out+="\n--- Pings (per slave via -I) to $target ---\n"
  for s in "${slaves[@]}"; do
    out+="\n>> $s\n"
    out+="$(ping -c 3 -W 1 -I "$s" "$target" 2>&1 || true)\n"
  done

  out+="\n--- ethtool (driver + stats) ---\n"
  for s in "${slaves[@]}"; do
    out+="\n>> $s: ethtool -i\n"
    out+="$(ethtool -i "$s" 2>&1 || true)\n"
    out+="\n>> $s: ethtool -S\n"
    out+="$(ethtool -S "$s" 2>&1 || true)\n"
  done

  out+="\n--- Recent NetworkManager logs ---\n"
  out+="$(journalctl -u NetworkManager -n 200 --no-pager 2>&1 || true)\n"

  ui_msg "$out"
}

workflow_create_bond() {
  local bond
  bond="$(ui_input "New bond name" "bond0")" || return 0
  [[ -n "$bond" ]] || return 0
  bond_exists "$bond" && die "Bond '$bond' already exists."

  local mode
  mode="$(ui_menu "Select bond mode:" \
    "active-backup" "Failover (one active, one standby)" \
    "802.3ad"       "LACP (requires switch configuration)")" || return 0

  local miimon
  miimon="$(ui_input "Link monitoring interval (miimon, ms)" "$DEFAULT_MIIMON")" || return 0
  [[ -z "$miimon" ]] && miimon="$DEFAULT_MIIMON"

  local lacp_rate="" xhp="" arp_targets=""
  if [[ "$mode" == "802.3ad" ]]; then
    lacp_rate="$(ui_menu "LACP rate:" \
      "fast" "Fast (1s)" \
      "slow" "Slow (30s)")" || return 0
    xhp="$(ui_menu "Transmit hash policy:" \
      "layer3+4" "Balances per flow (recommended)" \
      "layer2"   "Balances per MAC" \
      "layer2+3" "Balances per MAC+IP")" || return 0
  fi

  arp_targets="$(ui_input "Optional ARP monitor targets (comma-separated; blank to skip)" "")" || return 0

  local raw slaves
  raw="$(ui_checklist_nics "Select member interfaces for $bond")" || return 0
  raw="$(echo "$raw" | tr -s ' ' ' ' | sed 's/^ *//;s/ *$//')"
  [[ -n "$raw" ]] || die "At least one member interface is required."
  read -r -a slaves <<<"$raw"

  local validated
  validated="$(validate_slaves "${slaves[@]}")"
  # shellcheck disable=SC2206
  slaves=($validated)

  local ip_loc
  ip_loc="$(ui_menu "IP configuration location:" \
    "bond" "Assign IP directly to the bond device" \
    "vlan" "Assign IP to a VLAN on top of the bond")" || return 0

  local vlan_if=""
  if [[ "$ip_loc" == "vlan" ]]; then
    local vid
    vid="$(ui_input "VLAN ID" "")" || return 0
    [[ -n "$vid" ]] || die "VLAN ID is required."
    vlan_if="${bond}.${vid}"
  fi

  local ip_mode
  ip_mode="$(ui_menu "IPv4 configuration:" \
    "dhcp"   "DHCP" \
    "static" "Static IPv4")" || return 0

  local addr="" gw="" dns=""
  if [[ "$ip_mode" == "static" ]]; then
    addr="$(ui_input "IPv4 address/prefix (e.g., 10.0.0.10/24)" "")" || return 0
    gw="$(ui_input "IPv4 gateway" "")" || return 0
    dns="$(ui_input "DNS servers (comma or space separated)" "")" || return 0
    [[ -n "$addr" && -n "$gw" ]] || die "Static IP requires address/prefix and gateway."
  fi

  # Summary + confirm
  local summary="Planned changes:\n\n"
  summary+="Create bond: $bond\n"
  summary+="Mode: $mode\n"
  summary+="miimon: $miimon\n"
  [[ "$mode" == "802.3ad" ]] && summary+="lacp_rate: $lacp_rate\nxmit_hash_policy: $xhp\n"
  [[ -n "$arp_targets" ]] && summary+="arp_targets: $arp_targets\n"
  summary+="Members: ${slaves[*]}\n"
  if [[ "$ip_loc" == "vlan" ]]; then
    summary+="VLAN: $vlan_if\n"
    summary+="IPv4: $ip_mode\n"
  else
    summary+="IPv4 on bond: $ip_mode\n"
  fi
  ui_msg "$summary"
  ui_yesno "Proceed with these changes?" || return 0

  backup_networkmanager >/dev/null
  create_bond_profile "$bond" "$mode" "$miimon" "$lacp_rate" "$xhp" "$arp_targets"
  add_bond_slaves "$bond" "${slaves[@]}"

  if [[ "$ip_loc" == "vlan" ]]; then
    local vid2="${vlan_if#*.}"
    create_vlan_profile "$bond" "$vid2" >/dev/null
    if [[ "$ip_mode" == "static" ]]; then
      configure_ip "$vlan_if" "static" "$addr" "$gw" "$dns"
    else
      configure_ip "$vlan_if" "dhcp" "" "" ""
    fi
    up_conn "$bond" || true
    up_conn "$vlan_if" || true
  else
    if [[ "$ip_mode" == "static" ]]; then
      configure_ip "$bond" "static" "$addr" "$gw" "$dns"
    else
      configure_ip "$bond" "dhcp" "" "" ""
    fi
    up_conn "$bond" || true
  fi

  post_change_prompt
}

workflow_edit_bond() {
  local bond
  bond="$(select_bond)" || return 0
  [[ -n "$bond" ]] || return 0
  bond_exists "$bond" || die "Bond '$bond' not found."

  local action
  action="$(ui_menu "Edit '$bond' - select action:" \
    "add"    "Add member interfaces" \
    "remove" "Remove member interfaces" \
    "tune"   "Change bond mode/tuning" \
    "vlan"   "Add VLAN on bond" \
    "ip"     "Edit IPv4 configuration (bond or VLAN profile)" \
    "back"   "Back")" || return 0
  [[ "$action" == "back" ]] && return 0

  # display context
  ui_msg "Current bond context:\n\n$(bond_context_text "$bond")"

  backup_networkmanager >/dev/null

  case "$action" in
    add)
      local raw slaves
      raw="$(ui_checklist_nics "Select interfaces to add to $bond")" || return 0
      raw="$(echo "$raw" | tr -s ' ' ' ' | sed 's/^ *//;s/ *$//')"
      [[ -n "$raw" ]] || die "No interfaces selected."
      read -r -a slaves <<<"$raw"
      local validated; validated="$(validate_slaves "${slaves[@]}")"
      # shellcheck disable=SC2206
      slaves=($validated)
      add_bond_slaves "$bond" "${slaves[@]}"
      up_conn "$bond" || true
      ;;
    remove)
      local to_remove
      to_remove="$(ui_input "Interfaces to remove (space-separated)" "")" || return 0
      to_remove="$(echo "$to_remove" | tr -s ' ' ' ' | sed 's/^ *//;s/ *$//')"
      [[ -n "$to_remove" ]] || die "No interfaces specified."
      local -a slaves=()
      read -r -a slaves <<<"$to_remove"
      local s
      for s in "${slaves[@]}"; do
        run_nmcli connection delete "${bond}-slave-${s}" || true
      done
      up_conn "$bond" || true
      ;;
    tune)
      local mode miimon lacp_rate xhp arp_targets
      mode="$(ui_input "Mode (active-backup|802.3ad; blank to keep)" "")" || return 0
      miimon="$(ui_input "miimon (ms; blank to keep)" "")" || return 0

      local opts
      opts="$(nmcli -g bond.options con show "$bond" 2>/dev/null || echo "")"
      opts="${opts// /}"

      if [[ -n "$mode" ]]; then
        [[ "$mode" == "active-backup" || "$mode" == "802.3ad" ]] || die "Unsupported mode '$mode'."
        opts="$(echo "$opts" | awk -v v="mode=$mode" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^mode=/ && $i!="") print $i} print v}' | sed 's/,$//')"
      fi
      if [[ -n "$miimon" ]]; then
        opts="$(echo "$opts" | awk -v v="miimon=$miimon" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^miimon=/ && $i!="") print $i} print v}' | sed 's/,$//')"
      fi

      if [[ "$mode" == "802.3ad" || "$opts" =~ mode=802\.3ad ]]; then
        lacp_rate="$(ui_input "lacp_rate (fast|slow; blank to keep)" "")" || return 0
        xhp="$(ui_input "xmit_hash_policy (layer2|layer3+4|layer2+3; blank to keep)" "")" || return 0
        if [[ -n "$lacp_rate" ]]; then
          opts="$(echo "$opts" | awk -v v="lacp_rate=$lacp_rate" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^lacp_rate=/ && $i!="") print $i} print v}' | sed 's/,$//')"
        fi
        if [[ -n "$xhp" ]]; then
          opts="$(echo "$opts" | awk -v v="xmit_hash_policy=$xhp" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^xmit_hash_policy=/ && $i!="") print $i} print v}' | sed 's/,$//')"
        fi
      fi

      arp_targets="$(ui_input "ARP targets (comma list; blank to keep/remove)" "")" || return 0
      if [[ -n "$arp_targets" ]]; then
        opts="$(echo "$opts" | awk -v v="arp_interval=250,arp_ip_target=$arp_targets" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^arp_interval=/ && $i !~ /^arp_ip_target=/ && $i!="") print $i} print v}' | sed 's/,$//')"
      fi

      ui_msg "Applying bond.options:\n\n$opts"
      ui_yesno "Proceed?" || return 0
      run_nmcli connection modify "$bond" bond.options "$opts"
      up_conn "$bond" || true
      ;;
    vlan)
      local vid
      vid="$(ui_input "VLAN ID to add on $bond" "")" || return 0
      [[ -n "$vid" ]] || die "VLAN ID required."
      local vlan_if
      vlan_if="$(create_vlan_profile "$bond" "$vid")"
      up_conn "$vlan_if" || true
      ;;
    ip)
      local target
      target="$(ui_input "Profile to edit IPv4 (bond name or VLAN profile name)" "$bond")" || return 0
      [[ -n "$target" ]] || die "Target required."
      local ip_mode
      ip_mode="$(ui_menu "IPv4 configuration:" \
        "dhcp" "DHCP" \
        "static" "Static IPv4")" || return 0
      if [[ "$ip_mode" == "static" ]]; then
        local addr gw dns
        addr="$(ui_input "IPv4 address/prefix" "")" || return 0
        gw="$(ui_input "IPv4 gateway" "")" || return 0
        dns="$(ui_input "DNS servers (comma or space separated)" "")" || return 0
        [[ -n "$addr" && -n "$gw" ]] || die "Static IP requires address/prefix and gateway."
        configure_ip "$target" "static" "$addr" "$gw" "$dns"
      else
        configure_ip "$target" "dhcp" "" "" ""
      fi
      up_conn "$target" || true
      ;;
  esac

  post_change_prompt
}

workflow_remove_bond() {
  local bond
  bond="$(select_bond)" || return 0
  [[ -n "$bond" ]] || return 0
  bond_exists "$bond" || die "Bond '$bond' not found."

  ui_msg "You are about to remove bond '$bond' and its related profiles (members and VLANs)."
  ui_yesno "Proceed?" || return 0
  confirm_exact "removal" "$bond" || { ui_msg "Cancelled."; return 0; }

  backup_networkmanager >/dev/null
  delete_bond_profile "$bond"
  post_change_prompt
}

workflow_swap_members() {
  local bond
  bond="$(select_bond)" || return 0
  [[ -n "$bond" ]] || return 0
  bond_exists "$bond" || die "Bond '$bond' not found."

  ui_msg "Current bond context:\n\n$(bond_context_text "$bond")\n\nThis workflow adds new member interfaces first, then optionally removes old members."
  local raw_new
  raw_new="$(ui_checklist_nics "Select NEW member interfaces to add to $bond")" || return 0
  raw_new="$(echo "$raw_new" | tr -s ' ' ' ' | sed 's/^ *//;s/ *$//')"
  [[ -n "$raw_new" ]] || die "No interfaces selected."
  local -a new_slaves=()
  read -r -a new_slaves <<<"$raw_new"

  local validated
  validated="$(validate_slaves "${new_slaves[@]}")"
  # shellcheck disable=SC2206
  new_slaves=($validated)

  backup_networkmanager >/dev/null
  add_bond_slaves "$bond" "${new_slaves[@]}"
  up_conn "$bond" || true

  if ui_yesno "Remove old member interfaces now?"; then
    local raw_old
    raw_old="$(ui_input "Old member interfaces to remove (space-separated)" "")" || true
    raw_old="$(echo "$raw_old" | tr -s ' ' ' ' | sed 's/^ *//;s/ *$//')"
    if [[ -n "$raw_old" ]]; then
      local -a old=()
      read -r -a old <<<"$raw_old"
      local s
      for s in "${old[@]}"; do
        run_nmcli connection delete "${bond}-slave-${s}" || true
      done
    fi
  fi

  post_change_prompt
}

workflow_clone_bond() {
  local src_bond
  src_bond="$(select_bond)" || return 0
  [[ -n "$src_bond" ]] || return 0
  bond_exists "$src_bond" || die "Bond '$src_bond' not found."

  local dst_bond
  dst_bond="$(ui_input "New bond name (destination)" "bond10")" || return 0
  [[ -n "$dst_bond" ]] || return 0
  bond_exists "$dst_bond" && die "Bond '$dst_bond' already exists."

  ui_msg "Source bond context:\n\n$(bond_context_text "$src_bond")"

  local raw
  raw="$(ui_checklist_nics "Select member interfaces for new bond '$dst_bond'")" || return 0
  raw="$(echo "$raw" | tr -s ' ' ' ' | sed 's/^ *//;s/ *$//')"
  [[ -n "$raw" ]] || die "At least one interface is required."
  local -a new_slaves=()
  read -r -a new_slaves <<<"$raw"

  local validated
  validated="$(validate_slaves "${new_slaves[@]}")"
  # shellcheck disable=SC2206
  new_slaves=($validated)

  local warn10g=false
  local s
  for s in "${new_slaves[@]}"; do
    if ! is_10g "$s"; then
      warn10g=true
    fi
  done
  if [[ "$warn10g" == "true" ]]; then
    ui_msg "Note: One or more selected interfaces do not report 10Gb+ speed. This may be expected on some drivers/ports."
  fi

  local mode miimon lacp_rate xhp
  mode="$(awk -F': +' '/^Bonding Mode:/{print $2}' "/proc/net/bonding/$src_bond" 2>/dev/null | awk '{print $1}' | head -n1)"
  [[ -z "$mode" ]] && mode="active-backup"
  miimon="$(awk -F': +' '/^MII Polling Interval \(ms\):/{print $2}' "/proc/net/bonding/$src_bond" 2>/dev/null | head -n1)"
  [[ -z "$miimon" ]] && miimon="$DEFAULT_MIIMON"
  if [[ "$mode" == "802.3ad" ]]; then
    xhp="$(awk -F': +' '/^Transmit Hash Policy:/{print $2}' "/proc/net/bonding/$src_bond" 2>/dev/null | head -n1 | awk '{print $1}')"
    lacp_rate="$(awk -F': +' '/^LACP rate:/{print $2}' "/proc/net/bonding/$src_bond" 2>/dev/null | head -n1 | awk '{print $1}')"
    [[ -z "$lacp_rate" ]] && lacp_rate="$DEFAULT_8023AD_LACP_RATE"
    [[ -z "$xhp" ]] && xhp="$DEFAULT_8023AD_XHP"
  fi

  local copy_ip=true copy_vlans=true
  ui_yesno "Copy IPv4 configuration from source bond?" && copy_ip=true || copy_ip=false
  ui_yesno "Clone VLAN profiles on top of the source bond?" && copy_vlans=true || copy_vlans=false

  local summary="Planned changes:\n\n"
  summary+="Clone from: $src_bond\nCreate: $dst_bond\n"
  summary+="Mode: $mode\nmiimon: $miimon\n"
  [[ "$mode" == "802.3ad" ]] && summary+="lacp_rate: $lacp_rate\nxmit_hash_policy: $xhp\n"
  summary+="Members: ${new_slaves[*]}\n"
  summary+="Copy IPv4: $copy_ip\nClone VLANs: $copy_vlans\n"
  ui_msg "$summary"
  ui_yesno "Proceed with these changes?" || return 0

  backup_networkmanager >/dev/null

  create_bond_profile "$dst_bond" "$mode" "$miimon" "$lacp_rate" "$xhp" ""
  add_bond_slaves "$dst_bond" "${new_slaves[@]}"
  up_conn "$dst_bond" || true

  if [[ "$copy_ip" == "true" ]]; then
    local v4addr v4gw v4dns method
    v4addr="$(nmcli -g ipv4.addresses con show "$src_bond" 2>/dev/null || true)"
    v4gw="$(nmcli -g ipv4.gateway   con show "$src_bond" 2>/dev/null || true)"
    v4dns="$(nmcli -g ipv4.dns       con show "$src_bond" 2>/dev/null || true)"
    method="$(nmcli -g ipv4.method   con show "$src_bond" 2>/dev/null || echo "auto")"
    if [[ "$method" == "auto" || -z "$v4addr" ]]; then
      configure_ip "$dst_bond" "dhcp" "" "" ""
    else
      configure_ip "$dst_bond" "static" "$v4addr" "$v4gw" "$v4dns"
    fi
  fi

  if [[ "$copy_vlans" == "true" ]]; then
    mapfile -t src_vlans < <(nmcli -t -f NAME,TYPE,DEVICE con show | awk -F: -v b="$src_bond" '$2=="vlan" && $3 ~ ("^" b "\\.") {print $1}')
    local v
    for v in "${src_vlans[@]}"; do
      local vid
      vid="$(nmcli -g vlan.id con show "$v" 2>/dev/null || true)"
      [[ -n "$vid" ]] || continue
      local new_vlan_if
      new_vlan_if="$(create_vlan_profile "$dst_bond" "$vid")"

      local a g d m
      a="$(nmcli -g ipv4.addresses con show "$v" 2>/dev/null || true)"
      g="$(nmcli -g ipv4.gateway   con show "$v" 2>/dev/null || true)"
      d="$(nmcli -g ipv4.dns       con show "$v" 2>/dev/null || true)"
      m="$(nmcli -g ipv4.method    con show "$v" 2>/dev/null || echo "auto")"
      if [[ "$m" == "auto" || -z "$a" ]]; then
        configure_ip "$new_vlan_if" "dhcp" "" "" ""
      else
        configure_ip "$new_vlan_if" "static" "$a" "$g" "$d"
      fi
      up_conn "$new_vlan_if" || true
    done
  fi

  post_change_prompt
}

workflow_repair_slaves() {
  local bond
  bond="$(select_bond)" || return 0
  [[ -n "$bond" ]] || return 0
  bond_exists "$bond" || die "Bond '$bond' not found."

  mapfile -t slaves < <(bond_slaves_from_proc "$bond")
  (( ${#slaves[@]} > 0 )) || die "No member interfaces discovered for '$bond' via /proc."

  ui_msg "This will rebuild bond-slave profiles for '$bond' using current kernel state.\n\nCurrent bond context:\n\n$(bond_context_text "$bond")"
  ui_yesno "Proceed?" || return 0

  backup_networkmanager >/dev/null

  mapfile -t slave_cons < <(nmcli -t -f NAME,TYPE,MASTER con show | awk -F: -v b="$bond" '$2 ~ /bond-?slave/ && $3==b {print $1}')
  local c
  for c in "${slave_cons[@]}"; do
    run_nmcli connection down "$c" || true
    run_nmcli connection delete "$c" || true
  done

  local validated
  validated="$(validate_slaves "${slaves[@]}")"
  # shellcheck disable=SC2206
  slaves=($validated)

  add_bond_slaves "$bond" "${slaves[@]}"
  up_conn "$bond" || true

  post_change_prompt
}

workflow_enforce_10g_ab() {
  local bond
  bond="$(select_bond)" || return 0
  [[ -n "$bond" ]] || return 0
  bond_exists "$bond" || die "Bond '$bond' not found."

  ui_msg "This will set '$bond' to active-backup and remove member interfaces that do not report 10Gb+ speed.\n\nCurrent bond context:\n\n$(bond_context_text "$bond")"
  ui_yesno "Proceed?" || return 0

  backup_networkmanager >/dev/null

  run_nmcli connection modify "$bond" bond.options "mode=active-backup,miimon=${DEFAULT_MIIMON}"

  mapfile -t slaves < <(bond_slaves_from_proc "$bond")
  local s
  for s in "${slaves[@]}"; do
    if ! is_10g "$s"; then
      log_info "Removing non-10Gb member $s from $bond"
      run_nmcli connection delete "${bond}-slave-${s}" || true
    fi
  done

  mapfile -t remaining < <(bond_slaves_from_proc "$bond")
  if (( ${#remaining[@]} == 0 )); then
    local raw ns
    raw="$(ui_checklist_nics "No 10Gb members remain. Select 10Gb member interfaces to add to $bond")" || return 0
    raw="$(echo "$raw" | tr -s ' ' ' ' | sed 's/^ *//;s/ *$//')"
    [[ -n "$raw" ]] || die "No interfaces selected."
    read -r -a ns <<<"$raw"
    local validated; validated="$(validate_slaves "${ns[@]}")"
    # shellcheck disable=SC2206
    ns=($validated)
    add_bond_slaves "$bond" "${ns[@]}"
  fi

  up_conn "$bond" || true
  post_change_prompt
}

workflow_rollback() {
  ui_msg "This restores the most recent NetworkManager connection snapshot from:\n\n$BACKUP_DIR"
  ui_yesno "Proceed with rollback?" || return 0
  restore_last_backup
  ui_msg "Rollback complete."
}

workflow_support_bundle() {
  local ts outdir archive
  ts="$(date +'%Y%m%d%H%M%S')"
  outdir="$SUPPORT_DIR/sb_${ts}"
  archive="$SUPPORT_DIR/support_${ts}.tar.gz"
  mkdir -p "$outdir"

  (lsmod | grep bonding || true) > "$outdir/modules.txt"
  (nmcli -f NAME,UUID,TYPE,DEVICE con show || true) > "$outdir/nm_connections.txt"
  (nmcli dev status || true) > "$outdir/nm_dev_status.txt"
  (ip -d -s link show || true) > "$outdir/ip_link.txt"
  (ip addr show || true) > "$outdir/ip_addr.txt"
  (journalctl -u NetworkManager -n 1000 --no-pager || true) > "$outdir/nm_journal.txt"
  (echo "Bonds:"; list_bonds || true) > "$outdir/bonds.txt"
  for f in /proc/net/bonding/*; do
    [[ -r "$f" ]] || continue
    cp "$f" "$outdir/$(basename "$f").txt"
  done
  cp -a "$LOG_FILE" "$outdir/" 2>/dev/null || true
  cp -a "$CONFIG_FILE" "$outdir/" 2>/dev/null || true

  tar -C "$SUPPORT_DIR" -czf "$archive" "$(basename "$outdir")"
  rm -rf "$outdir"
  ui_msg "Support bundle created:\n\n$archive"
  log_info "Collected support bundle at $archive"
}

workflow_version() {
  ui_msg "RHEL Bond Manager v$VERSION\n\nConfig: $CONFIG_FILE\nBackups retained: $MAX_BACKUPS\nLogrotate: $LOGROTATE_FREQUENCY (keep $LOGROTATE_ROTATE)\nNIC allowlist: ${NIC_ALLOWLIST_PATTERNS:-<none>}\nNIC blocklist: ${NIC_BLOCKLIST_PATTERNS:-<none>}\n\nMode: $([[ "$DRY_RUN" == "true" ]] && echo DRY-RUN || echo LIVE)"
}

# -----------------------------
# Professional menu structure
# -----------------------------
menu_main() {
  ui_menu "Main menu" \
    "1" "Status: bond overview" \
    "2" "Status: diagnose bond" \
    "3" "Status: extended diagnostics" \
    "4" "Change: create a new bond" \
    "5" "Change: edit an existing bond" \
    "6" "Change: remove a bond" \
    "7" "Migration: swap member NICs (add new, then remove old)" \
    "8" "Migration: clone bond to new NICs (optionally copy IP/VLANs)" \
    "9" "Repair: rebuild bond-slave profiles from current state" \
    "10" "Repair: enforce 10Gb active-backup membership" \
    "11" "Safety: roll back to most recent snapshot" \
    "12" "Support: create support bundle" \
    "13" "About: version and configuration" \
    "0" "Exit"
}

menu_loop() {
  while true; do
    local choice
    choice="$(menu_main)" || true
    case "${choice:-}" in
      1)  workflow_overview ;;
      2)  workflow_diagnose ;;
      3)  workflow_extended_diag ;;
      4)  workflow_create_bond ;;
      5)  workflow_edit_bond ;;
      6)  workflow_remove_bond ;;
      7)  workflow_swap_members ;;
      8)  workflow_clone_bond ;;
      9)  workflow_repair_slaves ;;
      10) workflow_enforce_10g_ab ;;
      11) workflow_rollback ;;
      12) workflow_support_bundle ;;
      13) workflow_version ;;
      0)  ui_msg "Exiting."; break ;;
      *)  ui_msg "Invalid selection." ;;
    esac
  done
}

# -----------------------------
# CLI
# -----------------------------
show_help() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -n, --dry-run        Print nmcli commands without applying changes.
      --debug          Mirror log entries to STDERR.
      --status         Print bond summary and exit.
      --export-json PATH
                       Export bond inventory as JSON to PATH and exit.
  -h, --help           Show help.

Notes:
  --dry-run affects nmcli changes only. The tool may still write logs/config and create backups.

Examples:
  $0 --status
  $0 --export-json /var/log/bond_manager/bonds.json
  $0 -n --debug
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--dry-run) DRY_RUN=true; shift ;;
      --debug) DEBUG=true; shift ;;
      --status) FLAG_STATUS=true; shift ;;
      --export-json) EXPORT_JSON_PATH="${2:-}"; shift 2 ;;
      -h|--help) show_help; exit 0 ;;
      *) echo "Unknown option: $1" >&2; show_help; exit 2 ;;
    esac
  done
}

main() {
  parse_args "$@"
  require_root
  ensure_config
  ensure_first_run_artifacts
  check_requirements

  if [[ "$FLAG_STATUS" == "true" ]]; then
    bond_summary_human
    [[ -n "$EXPORT_JSON_PATH" ]] && export_json "$EXPORT_JSON_PATH"
    exit 0
  fi
  if [[ -n "$EXPORT_JSON_PATH" ]]; then
    export_json "$EXPORT_JSON_PATH"
    exit 0
  fi

  if [[ ! -t 0 ]]; then
    die "Interactive mode requires a TTY. Use --status or --export-json for non-interactive runs."
  fi

  init_ui
  menu_loop
}

main "$@"
