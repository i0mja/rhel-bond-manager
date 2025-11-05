#!/usr/bin/env bash
# RHEL Bond Manager
# An interactive NetworkManager helper for RHEL 8/9 (and compatible) systems.
# SPDX-License-Identifier: MIT
# shellcheck shell=bash

set -Eeuo pipefail

VERSION="1.0.0"

# -----------------------------
# Constants & Paths
# -----------------------------
LOG_FILE="/var/log/bond_manager.log"
BACKUP_DIR="/var/backups/bond_manager"
SUPPORT_DIR="/var/log/bond_manager/support"
LOGROTATE_CONF="/etc/logrotate.d/bond_manager"
CONN_DIR="/etc/NetworkManager/system-connections"
MAX_BACKUPS=10

# -----------------------------
# Runtime flags (default)
# -----------------------------
DRY_RUN=false
DEBUG=false
FLAG_STATUS=false
EXPORT_JSON_PATH=""

# -----------------------------
# Utilities
# -----------------------------
timestamp() { date +'%%Y-%%m-%%dT%%H:%%M:%%S%z'; }

_log_common() {
  local level="$1"; shift || true
  local msg="$*"
  local line="[$(timestamp)] [$level] $msg"
  # file
  mkdir -p "$(dirname "$LOG_FILE")"
  printf '%%s\n' "$line" >> "$LOG_FILE" || true
  # stderr mirror in --debug
  if [[ "$DEBUG" == "true" ]]; then
    printf '%%s\n' "$line" >&2
  fi
}

log_info()  { _log_common INFO  "$*"; }
log_warn()  { _log_common WARN  "$*"; }
log_error() { _log_common ERROR "$*"; }
log_debug() { _log_common DEBUG "$*"; }

die() {
  log_error "$*"
  echo "ERROR: $*" >&2
  exit 1
}

on_error() {
  local line="$1"
  local cmd="$2"
  log_error "Line $line failed: $cmd"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "This utility must be run as root."
  fi
}

ensure_first_run_artifacts() {
  mkdir -p "$BACKUP_DIR" "$SUPPORT_DIR"
  touch "$LOG_FILE"
  # Create logrotate policy if missing
  if [[ ! -f "$LOGROTATE_CONF" ]]; then
    cat <<'EOF' > "$LOGROTATE_CONF"
/var/log/bond_manager.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF
    log_info "Installed logrotate policy at $LOGROTATE_CONF"
  fi
}

# Run an nmcli command with logging and dry-run support
run_nmcli() {
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "DRY-RUN nmcli $*"
    echo "[DRY-RUN] nmcli $*"
  else
    log_info "nmcli $*"
    nmcli "$@"
  fi
}

# Run a command that is not nmcli; always executes (dry-run affects nmcli only per README)
run_cmd() {
  log_info "RUN $*"
  "$@"
}

# SELinux contexts restore (best-effort)
restore_selinux_contexts() {
  if command -v restorecon >/dev/null 2>&1; then
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
  # OS check: RHEL-like 8 or 9
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    local id_like="${ID_LIKE:-}"
    local id="${ID:-}"
    local ver="${VERSION_ID:-}"
    if [[ ! "$ver" =~ ^(8|9)(\.[0-9]+)?$ ]]; then
      log_warn "Detected $PRETTY_NAME; this tool targets RHEL-like 8/9. Continuing anyway."
    fi
    case "$id $id_like" in
      *rhel*|*centos*|*rocky*|*almalinux*|*fedora*)
        ;;
      *)
        log_warn "OS ID=$id ID_LIKE=$id_like not clearly RHEL-like; proceeding cautiously."
        ;;
    esac
  fi

  # NetworkManager active
  if ! command -v nmcli >/dev/null 2>&1; then
    die "nmcli not found; please install NetworkManager."
  fi
  if ! systemctl is-active --quiet NetworkManager; then
    die "NetworkManager is not active. Start it with: systemctl enable --now NetworkManager"
  fi

  # Kernel bonding support
  if ! modprobe -n bonding >/dev/null 2>&1 && ! lsmod | grep -q '^bonding'; then
    log_warn "Bonding module not detected; attempting to load."
  fi
  if ! lsmod | grep -q '^bonding'; then
    if ! modprobe bonding >/dev/null 2>&1; then
      die "Unable to load bonding kernel module."
    fi
  fi

  # Standard utilities
  local reqs=(ip tar ping awk sed ethtool)
  for b in "${reqs[@]}"; do
    command -v "$b" >/dev/null 2>&1 || die "Missing required command: $b"
  done
}

# -----------------------------
# Backups & Rollback
# -----------------------------
backup_networkmanager() {
  require_root
  mkdir -p "$BACKUP_DIR"
  local ts
  ts="$(date +'%Y%m%d%H%M%S')"
  local archive="$BACKUP_DIR/conn-${ts}.tar.gz"
  log_info "Creating NetworkManager backup at $archive"
  tar -C "$CONN_DIR" -czf "$archive" .
  echo "$archive"
  # Rotate older backups
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
  if (( ${#backups[@]} == 0 )); then
    die "No backups found in $BACKUP_DIR"
  fi
  local latest="${backups[0]}"
  log_info "Restoring backup $latest"
  tar -C "$CONN_DIR" -xzf "$latest"
  restore_selinux_contexts
  systemctl reload NetworkManager || true
  echo "Restored from $latest"
}

post_change_recovery_prompt() {
  echo
  read -r -p "Change complete. Roll back to the last backup now? [y/N]: " ans || true
  if [[ "${ans,,}" == "y" ]]; then
    restore_last_backup
  fi
}

# -----------------------------
# Discovery helpers
# -----------------------------
list_bonds() {
  # Prefer /proc view
  if ls /proc/net/bonding/* >/dev/null 2>&1; then
    basename -a /proc/net/bonding/* 2>/dev/null || true
    return
  fi
  # Fallback via nmcli
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

is_10g() {
  local ifname="$1"
  local spd=""
  if [[ -r "/sys/class/net/$ifname/speed" ]]; then
    spd="$(cat "/sys/class/net/$ifname/speed" 2>/dev/null || echo "")"
  fi
  if [[ -z "$spd" || "$spd" == "unknown" ]]; then
    spd="$(ethtool "$ifname" 2>/dev/null | awk -F': ' '/Speed:/{gsub(/[^0-9]/,"",$2);print $2}')"
  fi
  [[ -n "$spd" && "$spd" -ge 10000 ]]
}

# -----------------------------
# JSON & Summary
# -----------------------------
json_escape() {
  # minimal JSON string escape
  sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r/\\r/g' -e 's/\n/\\n/g'
}

bond_summary_json() {
  local bonds
  mapfile -t bonds < <(list_bonds)
  echo "["
  local first_bond=true
  for b in "${bonds[@]}"; do
    $first_bond || echo ","
    first_bond=false

    # glean some properties from /proc
    local mode mii active primary
    mode="$(awk -F': +' '/^Bonding Mode:/{print $2}' "/proc/net/bonding/$b" 2>/dev/null | head -n1)"
    mii="$(awk -F': +' '/^MII Status:/{print $2}' "/proc/net/bonding/$b" 2>/dev/null | head -n1)"
    active="$(awk -F': +' '/^Currently Active Slave:/{print $2}' "/proc/net/bonding/$b" 2>/dev/null | head -n1)"
    primary="$(awk -F': +' '/^Primary Slave:/{print $2}' "/proc/net/bonding/$b" 2>/dev/null | head -n1)"
    [[ -z "$mode" ]] && mode="unknown"
    [[ -z "$mii" ]] && mii="unknown"
    [[ -z "$active" ]] && active="unknown"
    [[ -z "$primary" ]] && primary=""
    # slaves
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
    # also capture IPs of the bond and any VLANs on top
    local addrs
    addrs="$(ip -json addr show dev "$b" 2>/dev/null || echo "[]")"
    echo "   ,\"addresses\": $addrs"
    # VLANs
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
  local bonds
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
        /^Slave Interface:/ || /^MII Status:/ || /^Speed:/ || /^Duplex:/ { print }' "/proc/net/bonding/$b"
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
  local dir
  dir="$(dirname "$path")"
  mkdir -p "$dir"
  bond_summary_json > "$path"
  echo "JSON written to $path"
  log_info "Exported JSON to $path"
}

# -----------------------------
# Core workflows
# -----------------------------

prompt_read() {
  local prompt="$1"
  local var
  read -r -p "$prompt" var
  echo "$var"
}

prompt_list() {
  local prompt="$1"
  local val
  read -r -p "$prompt (space-separated): " val
  # normalize spacing
  echo "$val" | tr -s ' ' ' '
}

# Add a bond connection
create_bond_profile() {
  local bond="$1" mode="$2" miimon="$3" lacp_rate="$4" xhp="$5" arp_targets="$6"
  require_root
  backup_networkmanager >/dev/null
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

# Add bond slaves
add_bond_slaves() {
  local bond="$1"; shift
  local slaves=("$@")
  for s in "${slaves[@]}"; do
    run_nmcli connection add type bond-slave ifname "$s" con-name "${bond}-slave-${s}" master "$bond"
  done
}

# Bring a connection up
up_conn() { run_nmcli connection up "$1"; }

# Configure IP on the bond or VLAN
configure_ip() {
  local con="$1" method="$2" ipaddr="$3" gw="$4" dns="$5"
  if [[ "$method" == "dhcp" ]]; then
    run_nmcli connection modify "$con" ipv4.method auto ipv6.method ignore
  else
    run_nmcli connection modify "$con" ipv4.addresses "$ipaddr" ipv4.gateway "$gw" ipv4.method manual ipv6.method ignore
    [[ -n "$dns" ]] && run_nmcli connection modify "$con" ipv4.dns "$dns"
  fi
}

# Create VLAN on top of bond
create_vlan_profile() {
  local bond="$1" vid="$2"
  local vlan_if="${bond}.${vid}"
  run_nmcli connection add type vlan ifname "$vlan_if" con-name "$vlan_if" dev "$bond" id "$vid"
  echo "$vlan_if"
}

# Delete bond safely (including VLANs)
delete_bond_profile() {
  local bond="$1"
  require_root
  backup_networkmanager >/dev/null
  # Delete VLANs first
  mapfile -t vlan_cons < <(nmcli -t -f NAME,TYPE,DEVICE con show | awk -F: -v b="$bond" '$2=="vlan" && $3 ~ ("^" b "\\.") {print $1}')
  for v in "${vlan_cons[@]}"; do
    run_nmcli connection down "$v" || true
    run_nmcli connection delete "$v" || true
  done
  # Delete slave profiles
  mapfile -t slave_cons < <(nmcli -t -f NAME,TYPE,MASTER con show | awk -F: -v b="$bond" '$2 ~ /bond-?slave/ && $3==b {print $1}')
  for s in "${slave_cons[@]}"; do
    run_nmcli connection down "$s" || true
    run_nmcli connection delete "$s" || true
  done
  # Delete bond itself
  run_nmcli connection down "$bond" || true
  run_nmcli connection delete "$bond" || true
  restore_selinux_contexts
}

# -----------------------------
# Workflows - Menu Options
# -----------------------------

opt_0_rollback() {
  restore_last_backup
}

opt_1_switch_migration() {
  local bond; bond="$(prompt_read "Bond name: ")"
  [[ -n "$bond" ]] || die "Bond name required."
  if ! bond_exists "$bond"; then die "Bond $bond not found."; fi
  local new_slaves raw
  raw="$(prompt_list "Enter NEW slave interfaces to add to $bond")"
  read -r -a new_slaves <<<"$raw"
  [[ ${#new_slaves[@]} -gt 0 ]] || die "No new slaves provided."

  backup_networkmanager >/dev/null
  add_bond_slaves "$bond" "${new_slaves[@]}"
  up_conn "$bond" || true

  local old raw_old
  raw_old="$(prompt_list "Enter OLD slave interfaces to remove after adding new ones (or leave blank to skip)")"
  read -r -a old <<<"$raw_old"
  for s in "${old[@]:-}"; do
    run_nmcli connection delete "${bond}-slave-${s}" || true
  done
  restore_selinux_contexts
  post_change_recovery_prompt
}

opt_2_10g_migration_wizard() {
  local src_bond; src_bond="$(prompt_read "Existing bond to clone: ")"
  [[ -n "$src_bond" ]] || die "Source bond required."
  if ! bond_exists "$src_bond"; then die "Bond $src_bond not found."; fi

  local dst_bond; dst_bond="$(prompt_read "New 10Gb bond name (e.g., bond10): ")"
  [[ -n "$dst_bond" ]] || die "Destination bond required."

  local raw new_slaves
  raw="$(prompt_list "Enter new 10Gb slave interfaces")"
  read -r -a new_slaves <<<"$raw"
  [[ ${#new_slaves[@]} -gt 0 ]] || die "No new slaves provided."
  for s in "${new_slaves[@]}"; do
    if ! is_10g "$s"; then
      log_warn "$s doesn't look like 10Gb (speed check may be unreliable on some NICs)."
    fi
  done

  backup_networkmanager >/dev/null

  # Extract a few props from source
  local mode miimon lacp_rate xhp
  mode="$(awk -F': +' '/^Bonding Mode:/{print $2}' "/proc/net/bonding/$src_bond" 2>/dev/null | awk '{print $1}' | head -n1)"
  [[ -z "$mode" ]] && mode="active-backup"
  miimon="$(awk -F': +' '/^MII Polling Interval \(ms\):/{print $2}' "/proc/net/bonding/$src_bond" 2>/dev/null | head -n1)"
  [[ -z "$miimon" ]] && miimon="100"
  if [[ "$mode" == "802.3ad" ]]; then
    xhp="$(awk -F': +' '/^Transmit Hash Policy:/{print $2}' "/proc/net/bonding/$src_bond" 2>/dev/null | head -n1 | awk '{print $1}')"
    lacp_rate="$(awk -F': +' '/^LACP rate:/{print $2}' "/proc/net/bonding/$src_bond" 2>/dev/null | head -n1 | awk '{print $1}')"
    [[ -z "$lacp_rate" ]] && lacp_rate="fast"
  fi

  create_bond_profile "$dst_bond" "$mode" "$miimon" "$lacp_rate" "$xhp" ""

  add_bond_slaves "$dst_bond" "${new_slaves[@]}"
  up_conn "$dst_bond" || true

  # Clone IP from source bond if any
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

  # Clone VLANs
  mapfile -t src_vlans < <(nmcli -t -f NAME,TYPE,DEVICE con show | awk -F: -v b="$src_bond" '$2=="vlan" && $3 ~ ("^" b "\\.") {print $1}')
  for v in "${src_vlans[@]}"; do
    local vid
    vid="$(nmcli -g vlan.id con show "$v" 2>/dev/null || true)"
    if [[ -n "$vid" ]]; then
      local new_vlan_if; new_vlan_if="$(create_vlan_profile "$dst_bond" "$vid")"
      # Clone IPv4 settings from the source VLAN profile
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
    fi
  done

  restore_selinux_contexts
  post_change_recovery_prompt
}

opt_3_repair_bond() {
  local bond; bond="$(prompt_read "Bond to repair: ")"
  [[ -n "$bond" ]] || die "Bond required."
  if ! bond_exists "$bond"; then die "Bond $bond not found."; fi

  backup_networkmanager >/dev/null

  # rebuild slave profiles from /proc
  mapfile -t slaves < <(bond_slaves_from_proc "$bond")
  if (( ${#slaves[@]} == 0 )); then
    die "No slaves discovered for $bond; cannot rebuild."
  fi

  # Delete existing slave connections pointing to this bond
  mapfile -t slave_cons < <(nmcli -t -f NAME,TYPE,MASTER con show | awk -F: -v b="$bond" '$2 ~ /bond-?slave/ && $3==b {print $1}')
  for s in "${slave_cons[@]}"; do
    run_nmcli connection down "$s" || true
    run_nmcli connection delete "$s" || true
  done

  add_bond_slaves "$bond" "${slaves[@]}"
  up_conn "$bond" || true
  restore_selinux_contexts
  post_change_recovery_prompt
}

opt_4_repair_10g_ab() {
  local bond; bond="$(prompt_read "Bond to enforce 10Gb Active/Backup: ")"
  [[ -n "$bond" ]] || die "Bond required."
  if ! bond_exists "$bond"; then die "Bond $bond not found."; fi

  backup_networkmanager >/dev/null
  # Set mode=active-backup
  run_nmcli connection modify "$bond" bond.options "mode=active-backup,miimon=100"
  # Remove non-10G and re-add 10G only
  mapfile -t slaves < <(bond_slaves_from_proc "$bond")
  for s in "${slaves[@]}"; do
    if ! is_10g "$s"; then
      log_info "Removing non-10Gb slave $s"
      run_nmcli connection delete "${bond}-slave-${s}" || true
    fi
  done
  # prompt to add 10G slaves (if none left)
  mapfile -t remaining < <(bond_slaves_from_proc "$bond")
  if (( ${#remaining[@]} == 0 )); then
    local raw ns
    raw="$(prompt_list "Enter 10Gb slave interfaces to add to $bond")"
    read -r -a ns <<<"$raw"
    add_bond_slaves "$bond" "${ns[@]}"
  fi
  up_conn "$bond" || true
  restore_selinux_contexts
  post_change_recovery_prompt
}

_ping_target_prompt() {
  local target; target="$(prompt_read "Ping target (default 8.8.8.8): ")"
  [[ -z "$target" ]] && target="8.8.8.8"
  echo "$target"
}

opt_5_diagnose() {
  local bond; bond="$(prompt_read "Bond to diagnose: ")"
  [[ -n "$bond" ]] || die "Bond required."
  if ! bond_exists "$bond"; then die "Bond $bond not found."; fi

  echo "------ /proc/net/bonding/$bond ------"
  if [[ -r "/proc/net/bonding/$bond" ]]; then
    cat "/proc/net/bonding/$bond"
  else
    echo "(No /proc data)"
  fi

  echo
  echo "------ Link state ------"
  ip -br link show "$bond" || true
  mapfile -t slaves < <(bond_slaves_from_proc "$bond")
  for s in "${slaves[@]}"; do
    ip -br link show "$s" || true
  done

  local target; target="$(_ping_target_prompt)"
  echo
  echo "------ Pings (per slave via -I) to $target ------"
  for s in "${slaves[@]}"; do
    echo ">> $s"
    ping -c 3 -W 1 -I "$s" "$target" || true
    echo
  done
}

opt_6_extended_diag() {
  local bond; bond="$(prompt_read "Bond to run extended diagnostics: ")"
  [[ -n "$bond" ]] || die "Bond required."
  if ! bond_exists "$bond"; then die "Bond $bond not found."; fi
  opt_5_diagnose <<<"$bond" || true

  echo
  echo "------ ethtool stats ------"
  mapfile -t slaves < <(bond_slaves_from_proc "$bond")
  for s in "${slaves[@]}"; do
    echo ">> $s ethtool -i/-S"
    ethtool -i "$s" 2>/dev/null || true
    ethtool -S "$s" 2>/dev/null || true
    echo
  done

  echo "------ Recent NetworkManager logs ------"
  journalctl -u NetworkManager -n 200 --no-pager || true
}

opt_7_create_bond() {
  local bond; bond="$(prompt_read "Bond name (e.g., bond0): ")"
  [[ -n "$bond" ]] || die "Bond name required."
  if bond_exists "$bond"; then die "Bond $bond already exists."; fi

  local mode; mode="$(prompt_read "Mode [active-backup|802.3ad] (default active-backup): ")"
  [[ -z "$mode" ]] && mode="active-backup"
  if [[ "$mode" != "active-backup" && "$mode" != "802.3ad" ]]; then
    die "Unsupported mode: $mode"
  fi

  local miimon; miimon="$(prompt_read "miimon interval ms (default 100): ")"
  [[ -z "$miimon" ]] && miimon="100"

  local lacp_rate=""; local xhp=""; local arp_targets=""
  if [[ "$mode" == "802.3ad" ]]; then
    lacp_rate="$(prompt_read "LACP rate [fast|slow] (default fast): ")"; [[ -z "$lacp_rate" ]] && lacp_rate="fast"
    xhp="$(prompt_read "xmit_hash_policy [layer2|layer3+4|layer2+3] (default layer3+4): ")"; [[ -z "$xhp" ]] && xhp="layer3+4"
  fi

  arp_targets="$(prompt_read "Optional ARP monitor targets (comma-separated), blank to skip: ")"

  local raw slaves
  raw="$(prompt_list "Slave interfaces")"
  read -r -a slaves <<<"$raw"
  (( ${#slaves[@]} > 0 )) || die "At least one slave required."

  backup_networkmanager >/dev/null
  create_bond_profile "$bond" "$mode" "$miimon" "$lacp_rate" "$xhp" "$arp_targets"
  add_bond_slaves "$bond" "${slaves[@]}"

  # Optional VLAN & IP
  local v_opt; v_opt="$(prompt_read "Add a VLAN on top? [y/N]: ")"
  if [[ "${v_opt,,}" == "y" ]]; then
    local vid; vid="$(prompt_read "VLAN ID: ")"
    [[ -n "$vid" ]] || die "VLAN ID required."
    local vlan_if; vlan_if="$(create_vlan_profile "$bond" "$vid")"
    local ip_mode; ip_mode="$(prompt_read "IP on $vlan_if: [dhcp|static] (default dhcp): ")"
    [[ -z "$ip_mode" ]] && ip_mode="dhcp"
    if [[ "$ip_mode" == "static" ]]; then
      local addr gw dns
      addr="$(prompt_read "IPv4 address/prefix (e.g., 10.0.0.10/24): ")"
      gw="$(prompt_read "IPv4 gateway: ")"
      dns="$(prompt_read "DNS servers (comma-separated or space): ")"
      configure_ip "$vlan_if" "static" "$addr" "$gw" "$dns"
      up_conn "$vlan_if" || true
    else
      configure_ip "$vlan_if" "dhcp" "" "" ""
      up_conn "$vlan_if" || true
    fi
  else
    # IP directly on bond?
    local ip_opt; ip_opt="$(prompt_read "Configure IP directly on $bond? [y/N]: ")"
    if [[ "${ip_opt,,}" == "y" ]]; then
      local ip_mode; ip_mode="$(prompt_read "IP on $bond: [dhcp|static] (default dhcp): ")"
      [[ -z "$ip_mode" ]] && ip_mode="dhcp"
      if [[ "$ip_mode" == "static" ]]; then
        local addr gw dns
        addr="$(prompt_read "IPv4 address/prefix (e.g., 10.0.0.10/24): ")"
        gw="$(prompt_read "IPv4 gateway: ")"
        dns="$(prompt_read "DNS servers (comma-separated or space): ")"
        configure_ip "$bond" "static" "$addr" "$gw" "$dns"
      else
        configure_ip "$bond" "dhcp" "" "" ""
      fi
    fi
    up_conn "$bond" || true
  fi

  restore_selinux_contexts
  post_change_recovery_prompt
}

opt_8_edit_bond() {
  local bond; bond="$(prompt_read "Bond to edit: ")"
  [[ -n "$bond" ]] || die "Bond required."
  if ! bond_exists "$bond"; then die "Bond $bond not found."; fi

  echo "Edit options:"
  echo "  1) Add slave(s)"
  echo "  2) Remove slave(s)"
  echo "  3) Change mode and tuning"
  echo "  4) Add VLAN"
  echo "  5) Edit IP (bond or VLAN)"
  echo "  6) Back"
  read -r -p "Select: " choice || true

  backup_networkmanager >/dev/null

  case "$choice" in
    1)
      local raw slaves
      raw="$(prompt_list "Slave interfaces to add")"
      read -r -a slaves <<<"$raw"
      add_bond_slaves "$bond" "${slaves[@]}"
      ;;
    2)
      local raw slaves
      raw="$(prompt_list "Slave interfaces to remove")"
      read -r -a slaves <<<"$raw"
      for s in "${slaves[@]}"; do
        run_nmcli connection delete "${bond}-slave-${s}" || true
      done
      ;;
    3)
      local mode miimon lacp_rate xhp arp_targets
      mode="$(prompt_read "Mode [active-backup|802.3ad] (blank to keep): ")"
      miimon="$(prompt_read "miimon interval ms (blank to keep): ")"
      if [[ "$mode" == "802.3ad" ]]; then
        lacp_rate="$(prompt_read "LACP rate [fast|slow] (blank to keep): ")"
        xhp="$(prompt_read "xmit_hash_policy [layer2|layer3+4|layer2+3] (blank to keep): ")"
      fi
      arp_targets="$(prompt_read "ARP targets (comma list, blank to keep/remove): ")"
      # Build new options from existing + overrides
      local opts
      opts="$(nmcli -g bond.options con show "$bond" 2>/dev/null || echo "")"
      # normalize
      opts="${opts// /}"
      # Apply overrides
      [[ -n "$mode" ]]     && opts="$(echo "$opts" | awk -v v="mode=$mode" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^mode=/) print $i} print v}' | sed 's/,$//')"
      [[ -n "$miimon" ]]   && opts="$(echo "$opts" | awk -v v="miimon=$miimon" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^miimon=/) print $i} print v}' | sed 's/,$//')"
      if [[ "$mode" == "802.3ad" || "$opts" =~ mode=802\.3ad ]]; then
        [[ -n "$lacp_rate" ]] && opts="$(echo "$opts" | awk -v v="lacp_rate=$lacp_rate" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^lacp_rate=/) print $i} print v}' | sed 's/,$//')"
        [[ -n "$xhp" ]]       && opts="$(echo "$opts" | awk -v v="xmit_hash_policy=$xhp" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^xmit_hash_policy=/) print $i} print v}' | sed 's/,$//')"
      fi
      if [[ -n "$arp_targets" ]]; then
        opts="$(echo "$opts" | awk -v v="arp_interval=250,arp_ip_target=$arp_targets" -F, 'BEGIN{ORS=","} {for(i=1;i<=NF;i++){if($i !~ /^arp_interval=/ && $i !~ /^arp_ip_target=/) print $i} print v}' | sed 's/,$//')"
      fi
      run_nmcli connection modify "$bond" bond.options "$opts"
      ;;
    4)
      local vid; vid="$(prompt_read "VLAN ID to add on $bond: ")"
      [[ -n "$vid" ]] || die "VLAN ID required."
      local vlan_if; vlan_if="$(create_vlan_profile "$bond" "$vid")"
      up_conn "$vlan_if" || true
      ;;
    5)
      local target; target="$(prompt_read "Profile to edit IP (bond name or VLAN con-name): ")"
      [[ -n "$target" ]] || die "Target required."
      local ip_mode; ip_mode="$(prompt_read "IP mode [dhcp|static]: ")"
      if [[ "$ip_mode" == "static" ]]; then
        local addr gw dns
        addr="$(prompt_read "IPv4 address/prefix: ")"
        gw="$(prompt_read "IPv4 gateway: ")"
        dns="$(prompt_read "DNS servers: ")"
        configure_ip "$target" "static" "$addr" "$gw" "$dns"
      else
        configure_ip "$target" "dhcp" "" "" ""
      fi
      ;;
    *)
      echo "No change."
      ;;
  esac
  restore_selinux_contexts
  post_change_recovery_prompt
}

opt_9_remove_bond() {
  local bond; bond="$(prompt_read "Bond to remove: ")"
  [[ -n "$bond" ]] || die "Bond required."
  if ! bond_exists "$bond"; then die "Bond $bond not found."; fi
  delete_bond_profile "$bond"
  post_change_recovery_prompt
}

opt_10_show_summary() {
  bond_summary_human
}

opt_11_export_json() {
  local path; path="$(prompt_read "Export JSON path (e.g., /var/log/bond_manager/bonds.json): ")"
  [[ -n "$path" ]] || die "Path required."
  export_json "$path"
}

opt_12_support_bundle() {
  local ts outdir archive
  ts="$(date +'%Y%m%d%H%M%S')"
  outdir="$SUPPORT_DIR/sb_${ts}"
  archive="$SUPPORT_DIR/support_${ts}.tar.gz"
  mkdir -p "$outdir"

  # Collect data
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

  tar -C "$SUPPORT_DIR" -czf "$archive" "$(basename "$outdir")"
  rm -rf "$outdir"
  echo "Support bundle: $archive"
  log_info "Collected support bundle at $archive"
}

opt_13_version() {
  echo "RHEL Bond Manager version $VERSION"
}

# -----------------------------
# Menu
# -----------------------------
print_menu() {
  cat <<'MENU'
RHEL Bond Manager - Main Menu
0) Roll back to the most recent NetworkManager backup
1) Switch migration helper – add new slaves before removing the old ones
2) 10Gb migration wizard – clone an existing bond onto fresh 10Gb interfaces
3) Repair bond – rebuild slave profiles and bring the bond online
4) Repair bond (10Gb Active/Backup) – enforce 10Gb-only slaves in A/B mode
5) Diagnose bond – print /proc/net/bonding data, NIC link state, and pings
6) Extended diagnostics – deeper collection of bond and NIC telemetry
7) Create bond – guided creation with validation and optional VLAN/IP config
8) Edit bond – modify slaves, mode, VLAN, IP data, and advanced options
9) Remove bond – detach slaves and delete the bond profile safely
10) Show bond summary – human-readable snapshot of every bond and member
11) Export bond summary (JSON) – interactive prompt for export path
12) Collect support bundle – gather logs and diagnostics into a tarball
13) Show version
14) Exit
MENU
}

menu_loop() {
  while true; do
    print_menu
    read -r -p "Select an option: " choice || true
    case "$choice" in
      0)  opt_0_rollback ;;
      1)  opt_1_switch_migration ;;
      2)  opt_2_10g_migration_wizard ;;
      3)  opt_3_repair_bond ;;
      4)  opt_4_repair_10g_ab ;;
      5)  opt_5_diagnose ;;
      6)  opt_6_extended_diag ;;
      7)  opt_7_create_bond ;;
      8)  opt_8_edit_bond ;;
      9)  opt_9_remove_bond ;;
      10) opt_10_show_summary ;;
      11) opt_11_export_json ;;
      12) opt_12_support_bundle ;;
      13) opt_13_version ;;
      14) echo "Bye." ; break ;;
      *) echo "Invalid selection." ;;
    esac
    echo
  done
}

# -----------------------------
# CLI
# -----------------------------
show_help() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -n, --dry-run        Echo the nmcli commands that would run without applying changes.
      --debug         Mirror log entries to STDERR for live troubleshooting.
      --status        Print the bond summary view and exit.
      --export-json PATH
                       Export the bond inventory as JSON to PATH and exit.
  -h, --help          Show this help.

Examples:
  $0 --status
  $0 --status --export-json /var/log/bond_manager/bonds.json
  $0 -n --debug
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--dry-run) DRY_RUN=true; shift;;
      --debug) DEBUG=true; shift;;
      --status) FLAG_STATUS=true; shift;;
      --export-json) EXPORT_JSON_PATH="${2:-}"; shift 2;;
      -h|--help) show_help; exit 0;;
      *) echo "Unknown option: $1" >&2; show_help; exit 2;;
    esac
  done
}

main() {
  parse_args "$@"
  require_root
  ensure_first_run_artifacts
  check_requirements

  # Non-interactive flags
  if [[ "$FLAG_STATUS" == "true" ]]; then
    bond_summary_human
    if [[ -n "$EXPORT_JSON_PATH" ]]; then
      export_json "$EXPORT_JSON_PATH"
    fi
    exit 0
  fi
  if [[ -n "$EXPORT_JSON_PATH" ]]; then
    export_json "$EXPORT_JSON_PATH"
    exit 0
  fi

  # Interactive menu (require TTY)
  if [[ ! -t 0 ]]; then
    die "Interactive mode requires a TTY. Use --status or --export-json for non-interactive runs."
  fi
  menu_loop
}

main "$@"
