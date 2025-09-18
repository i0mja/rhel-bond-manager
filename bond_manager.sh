#!/bin/bash

# Network Manager Bond Script v1.0.0
# Manages Ethernet bonds on RHEL/CentOS 7-9 using NetworkManager
# Requires root privileges

set -Eeuo pipefail
IFS=$'\n\t'
shopt -s nullglob

# Constants
VERSION="1.0.0"
LOG_FILE="/var/log/bond_manager.log"
BACKUP_DIR="/var/backups/bond_manager"
BACKUP_PREFIX="conn"  # timestamp appended in backup_configs
BACKUP_RETENTION=10
TIMEOUT=15
MAX_RETRIES=2
BOND_MODES=("balance-rr" "active-backup" "balance-xor" "broadcast" "802.3ad" "balance-tlb" "balance-alb")
TEMP_FILES=()
SUPPORT_DIR="/var/log/bond_manager/support"

# NetworkManager device metadata caches
declare -Ag DEVICE_CONNECTION_MAP=()
declare -Ag DEVICE_STATE_MAP=()
CURRENT_PRIMARY_DEVICE=""
CURRENT_PRIMARY_CONNECTION=""

# Global state flags
DEBUG=false
DRY_RUN=false
STATUS_MODE=false
EXPORT_JSON_PATH=""
ALLOW_NON_INTERACTIVE=false
for arg in "$@"; do
    if [[ $arg == "--status" || $arg == "--export-json" || $arg == "--help" ]]; then
        ALLOW_NON_INTERACTIVE=true
        break
    fi
done

# Set traps early
trap cleanup EXIT
trap rollback ERR

# Ensure script runs as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root" >&2
    exit 1
fi

# Check for interactive terminal unless running in explicit non-interactive mode
if [[ ! -t 0 && "$ALLOW_NON_INTERACTIVE" != "true" ]]; then
    echo "Error: This script requires an interactive terminal" >&2
    exit 1
fi

# Initialize terminal settings
export TERM=${TERM:-xterm}
if command -v stty >/dev/null; then
    stty sane 2>/dev/null
fi

# Log terminal settings for debugging
{
    echo "=== Terminal Settings ==="
    echo "TERM=$TERM"
    command -v stty >/dev/null && stty -a
    echo "================="
} >> "$LOG_FILE" 2>/dev/null

# Check required commands
REQUIRED_CMDS=("nmcli" "ip" "awk" "sed" "tar" "ping" "ethtool")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: Required command '$cmd' not found" >&2
        exit 1
    fi
done

# Create log and backup directories
mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR"
chmod 750 "$BACKUP_DIR"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

# Create logrotate config
cat << 'EOF' > /etc/logrotate.d/bond_manager
/var/log/bond_manager.log {
    weekly
    rotate 4
    compress
    copytruncate
    missingok
}
EOF
chmod 644 /etc/logrotate.d/bond_manager

# Logging function
log() {
    local level="INFO"
    if [[ $# -gt 1 && $1 =~ ^(INFO|WARN|ERROR|DEBUG)$ ]]; then
        level=$1
        shift
    fi
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $*" >> "$LOG_FILE"
    if [[ "$DEBUG" == "true" ]]; then
        echo "[$level] $*" >&2
    fi
}

preflight_checks() {
    log INFO "Starting preflight checks"
    local os_id="" os_version=""
    if [[ -r /etc/os-release ]]; then
        os_id=$(awk -F= '$1=="ID" {gsub("\"", "", $2); print tolower($2)}' /etc/os-release)
        os_version=$(awk -F= '$1=="VERSION_ID" {gsub("\"", "", $2); print $2}' /etc/os-release)
        if [[ ! "$os_id" =~ ^(rhel|centos|rocky|almalinux)$ || ! "$os_version" =~ ^(8|9) ]]; then
            log WARN "Detected unsupported OS combination: ${os_id:-unknown} ${os_version:-unknown}"
            echo "Warning: Script is optimized for RHEL-compatible 8/9 hosts. Detected ${os_id:-unknown} ${os_version:-unknown}." >&2
        else
            log DEBUG "Detected supported OS: $os_id $os_version"
        fi
    else
        log WARN "Unable to read /etc/os-release"
    fi

    if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl is-active --quiet NetworkManager; then
            log ERROR "NetworkManager service is not active"
            echo "Error: NetworkManager service is not active" >&2
            exit 1
        fi
    else
        log WARN "systemctl not available; skipping NetworkManager service check"
    fi

    if ! nmcli general status &>>"$LOG_FILE"; then
        log ERROR "Unable to query NetworkManager status"
        echo "Error: Unable to query NetworkManager status via nmcli" >&2
        exit 1
    else
        local nm_state
        nm_state=$(nmcli -t -f STATE general status 2>/dev/null | cut -d: -f2)
        if [[ -n "$nm_state" && "$nm_state" != "connected" && "$nm_state" != "connected (global)" ]]; then
            log WARN "NetworkManager general state: ${nm_state}" 
            echo "Warning: NetworkManager general state is '${nm_state}'." >&2
        fi
    fi

    if ! lsmod | grep -q '^bonding'; then
        if command -v modprobe >/dev/null 2>&1; then
            if modprobe bonding 2>>"$LOG_FILE"; then
                log INFO "Loaded bonding kernel module"
            else
                log ERROR "Failed to load bonding kernel module"
                echo "Error: Failed to load bonding kernel module" >&2
                exit 1
            fi
        else
            log WARN "modprobe not available; unable to ensure bonding module is loaded"
        fi
    else
        log DEBUG "Bonding module already loaded"
    fi
}

prune_old_backups() {
    local backups=()
    mapfile -t backups < <(ls -1t "$BACKUP_DIR"/${BACKUP_PREFIX}-*.tar.gz 2>/dev/null || true)
    if (( ${#backups[@]} > BACKUP_RETENTION )); then
        for ((i=BACKUP_RETENTION; i<${#backups[@]}; i++)); do
            if rm -f "${backups[$i]}" 2>/dev/null; then
                log INFO "Pruned old backup ${backups[$i]}"
            fi
        done
    fi
}

restore_selinux_context() {
    [[ "$DRY_RUN" == "true" ]] && return 0
    if command -v restorecon >/dev/null 2>&1; then
        if restorecon -Rv /etc/NetworkManager/system-connections &>>"$LOG_FILE"; then
            log INFO "Restored SELinux context for NetworkManager profiles"
        else
            log WARN "restorecon reported errors while fixing SELinux context"
        fi
    else
        log DEBUG "restorecon not available; skipping SELinux context restore"
    fi
}

validate_nic_ready() {
    local nic=$1
    if [[ -z "$nic" ]]; then
        return 1
    fi
    if ip -o addr show dev "$nic" 2>/dev/null | grep -qE ' inet| inet6'; then
        log WARN "NIC $nic has existing IP configuration"
        echo "Error: NIC $nic has existing IP configuration. Please clean up addresses before bonding." >&2
        return 1
    fi
    if [[ -f "/sys/class/net/$nic/carrier" ]]; then
        local carrier
        carrier=$(<"/sys/class/net/$nic/carrier")
        if [[ "$carrier" == "0" ]]; then
            log WARN "NIC $nic currently reports no carrier"
            echo "Warning: NIC $nic currently reports no carrier" >&2
        fi
    fi
    return 0
}

confirm_prompt() {
    local prompt=$1
    local default=${2:-N}
    local response=""
    local prompt_text="$prompt"
    if [[ "$default" =~ ^[Yy]$ ]]; then
        prompt_text+=" (Y/n): "
    else
        prompt_text+=" (y/N): "
    fi
    if read_input "$prompt_text" response; then
        :
    else
        response="${response:-}"
    fi
    if [[ -z "$response" ]]; then
        if [[ "$default" =~ ^[Yy]$ ]]; then
            return 0
        fi
        return 1
    fi
    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    fi
    return 1
}

get_bond_option_value() {
    local options=$1
    local key=$2
    local value=""
    IFS=',' read -ra opts <<< "$options"
    for opt in "${opts[@]}"; do
        if [[ $opt == $key=* ]]; then
            value=${opt#*=}
            break
        fi
    done
    echo "$value"
}

nmcli_get_field() {
    local field=$1
    local connection=$2
    local output
    if output=$(nmcli -t -f "$field" con show "$connection" 2>/dev/null); then
        output=${output#*:}
        output=${output//$'\n'/, }
        echo "$output"
    fi
}

list_bonds() {
    while IFS=: read -r name type; do
        [[ $type == "bond" ]] && echo "$name"
    done < <(nmcli -t -f NAME,TYPE con show 2>/dev/null)
}

json_escape() {
    local s=$1
    local backslash='\\'
    local esc_backslash='\\\\'
    local dq='"'
    local esc_dq='\"'
    local newline=$'\n'
    s=${s//${backslash}/${esc_backslash}}
    s=${s//${dq}/${esc_dq}}
    s=${s//${newline}/\n}
    echo "$s"
}

to_json_array() {
    local list=$1
    if [[ -z "$list" ]]; then
        echo "[]"
        return
    fi
    local normalized=${list//, /,}
    IFS=',' read -ra items <<< "$normalized"
    local parts=()
    for item in "${items[@]}"; do
        [[ -z "$item" ]] && continue
        parts+=("\"$(json_escape "$item")\"")
    done
    if (( ${#parts[@]} == 0 )); then
        echo "[]"
    else
        local IFS=','
        echo "[${parts[*]}]"
    fi
}

configure_bond_options() {
    local bond_name=$1
    local mode=$2
    if [[ -z "$bond_name" ]]; then
        return 0
    fi
    if ! confirm_prompt "Configure advanced bond options for $bond_name?" "N"; then
        return 0
    fi
    local current_opts=""
    local nm_output=""
    if nm_output=$(nmcli -t -f bond.options con show "$bond_name" 2>/dev/null); then
        current_opts=$(echo "$nm_output" | cut -d: -f2)
    fi
    declare -A options_map=()
    if [[ -n "$current_opts" ]]; then
        IFS=',' read -ra opts <<< "$current_opts"
        for opt in "${opts[@]}"; do
            [[ -z "$opt" ]] && continue
            if [[ "$opt" == *=* ]]; then
                local key=${opt%%=*}
                local value=${opt#*=}
                options_map[$key]=$value
            else
                options_map[$opt]=""
            fi
        done
    fi

    local miimon=${options_map[miimon]:-100}
    local updelay=${options_map[updelay]:-0}
    local downdelay=${options_map[downdelay]:-0}
    local lacp_rate=${options_map[lacp_rate]:-slow}
    local xmit_hash_policy=${options_map[xmit_hash_policy]:-layer2}
    local arp_interval=${options_map[arp_interval]:-${options_map[arp_interval]:-0}}
    local arp_ip_target=${options_map[arp_ip_target]:-}
    local response=""

    if read_input "Set miimon (current: $miimon, Enter to keep): " response true; then
        if [[ -n "$response" ]]; then
            if [[ "$response" =~ ^[0-9]+$ ]]; then
                miimon=$response
            else
                echo "Warning: miimon must be numeric" >&2
                log WARN "Invalid miimon value '$response' provided"
            fi
        fi
    fi
    if read_input "Set updelay (current: $updelay, Enter to keep): " response true; then
        if [[ -n "$response" ]]; then
            if [[ "$response" =~ ^[0-9]+$ ]]; then
                updelay=$response
            else
                echo "Warning: updelay must be numeric" >&2
                log WARN "Invalid updelay value '$response' provided"
            fi
        fi
    fi
    if read_input "Set downdelay (current: $downdelay, Enter to keep): " response true; then
        if [[ -n "$response" ]]; then
            if [[ "$response" =~ ^[0-9]+$ ]]; then
                downdelay=$response
            else
                echo "Warning: downdelay must be numeric" >&2
                log WARN "Invalid downdelay value '$response' provided"
            fi
        fi
    fi
    if [[ "$mode" == "802.3ad" ]]; then
        if read_input "Set lacp_rate (slow/fast, current: $lacp_rate): " response true; then
            if [[ -n "$response" ]]; then
                if [[ "$response" =~ ^(slow|fast)$ ]]; then
                    lacp_rate=$response
                else
                    echo "Warning: lacp_rate must be 'slow' or 'fast'" >&2
                    log WARN "Invalid lacp_rate value '$response' provided"
                fi
            fi
        fi
    fi
    if [[ "$mode" == "802.3ad" || "$mode" == "balance-xor" || "$mode" == "balance-tlb" || "$mode" == "balance-alb" ]]; then
        if read_input "Set xmit_hash_policy (layer2/layer2+3/layer3+4, current: $xmit_hash_policy): " response true; then
            if [[ -n "$response" ]]; then
                case "$response" in
                    layer2|layer2+3|layer3+4)
                        xmit_hash_policy=$response
                        ;;
                    *)
                        echo "Warning: Unsupported xmit_hash_policy" >&2
                        log WARN "Invalid xmit_hash_policy value '$response' provided"
                        ;;
                esac
            fi
        fi
    fi
    if read_input "Set arp_interval in ms (current: $arp_interval, 0 to disable): " response true; then
        if [[ -n "$response" ]]; then
            if [[ "$response" =~ ^[0-9]+$ ]]; then
                arp_interval=$response
            else
                echo "Warning: arp_interval must be numeric" >&2
                log WARN "Invalid arp_interval value '$response' provided"
            fi
        fi
    fi
    if [[ "$arp_interval" =~ ^[0-9]+$ && "$arp_interval" -gt 0 ]]; then
        if read_input "Set arp_ip_target list (comma separated, current: ${arp_ip_target:-none}): " response true; then
            if [[ -n "$response" ]]; then
                arp_ip_target=$response
            fi
        fi
    else
        arp_ip_target=""
    fi

    options_map[miimon]=$miimon
    options_map[updelay]=$updelay
    options_map[downdelay]=$downdelay
    if [[ "$mode" == "802.3ad" ]]; then
        options_map[lacp_rate]=$lacp_rate
    else
        unset options_map[lacp_rate]
    fi
    if [[ "$mode" == "802.3ad" || "$mode" == "balance-xor" || "$mode" == "balance-tlb" || "$mode" == "balance-alb" ]]; then
        options_map[xmit_hash_policy]=$xmit_hash_policy
    else
        unset options_map[xmit_hash_policy]
    fi
    if [[ "$arp_interval" =~ ^[0-9]+$ && "$arp_interval" -gt 0 ]]; then
        options_map[arp_interval]=$arp_interval
        if [[ -n "$arp_ip_target" ]]; then
            options_map[arp_ip_target]=$arp_ip_target
        else
            unset options_map[arp_ip_target]
        fi
    else
        options_map[arp_interval]=0
        unset options_map[arp_ip_target]
    fi

    local -a option_pairs=()
    local ordered_keys=(mode primary miimon updelay downdelay lacp_rate xmit_hash_policy arp_interval arp_ip_target)
    for key in "${ordered_keys[@]}"; do
        if [[ -n ${options_map[$key]+_} ]]; then
            if [[ -n ${options_map[$key]} ]]; then
                option_pairs+=("$key=${options_map[$key]}")
            else
                option_pairs+=("$key")
            fi
            unset options_map[$key]
        fi
    done
    for key in "${!options_map[@]}"; do
        if [[ -n ${options_map[$key]} ]]; then
            option_pairs+=("$key=${options_map[$key]}")
        else
            option_pairs+=("$key")
        fi
    done

    if (( ${#option_pairs[@]} == 0 )); then
        return 0
    fi

    local options_string
    (IFS=','; options_string="${option_pairs[*]}")
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "nmcli con mod $bond_name bond.options $options_string"
        return 0
    fi
    if nmcli con mod "$bond_name" bond.options "$options_string" &>>"$LOG_FILE"; then
        log INFO "Configured advanced bond options for $bond_name: $options_string"
        return 0
    fi
    log ERROR "Failed to configure advanced options for $bond_name"
    echo "Error: Failed to configure advanced bond options" >&2
    return 1
}

show_bond_summary() {
    local skip_clear=$1
    if [[ "$skip_clear" != "--no-clear" ]]; then
        clear_screen
    fi
    echo "Bond Summary"
    local bonds=()
    mapfile -t bonds < <(list_bonds)
    if (( ${#bonds[@]} == 0 )); then
        echo "No bonds configured."
        return 0
    fi
    for bond in "${bonds[@]}"; do
        local mode=$(get_bond_mode "$bond")
        local options=$(nmcli_get_field bond.options "$bond")
        local vlan=$(nmcli_get_field 802-3-ethernet.vlan "$bond")
        local ipv4=$(nmcli_get_field ipv4.addresses "$bond")
        local gateway=$(nmcli_get_field ipv4.gateway "$bond")
        local ipv6=$(nmcli_get_field ipv6.addresses "$bond")
        local primary=$(get_bond_option_value "$options" "primary")
        echo ""
        echo "Bond: $bond"
        echo "  Mode: ${mode:-unknown}"
        [[ -n "$primary" ]] && echo "  Primary: $primary"
        if [[ -n "$vlan" && "$vlan" != "0" ]]; then
            echo "  VLAN: $vlan"
        fi
        echo "  IPv4: ${ipv4:-none}"
        [[ -n "$gateway" ]] && echo "  Gateway: $gateway"
        echo "  IPv6: ${ipv6:-none}"
        echo "  Options: ${options:-none}"
        local slaves=()
        mapfile -t slaves < <(get_bond_slaves "$bond")
        if (( ${#slaves[@]} == 0 )); then
            echo "  Slaves: none"
            continue
        fi
        echo "  Slaves:"
        for slave in "${slaves[@]}"; do
            local iface=$(nmcli_get_field connection.interface-name "$slave")
            [[ -z "$iface" ]] && iface="$slave"
            local info=($(get_nic_info "$iface"))
            local speed="${info[0]:-Unknown}"
            local status="${info[1]:-DOWN}"
            echo "    - $iface (connection: $slave) speed: $speed link: $status"
        done
    done
}

export_bond_summary() {
    local target_path=$1
    local mode_flag=${2:-}
    if [[ -z "$target_path" ]]; then
        if [[ "$mode_flag" != "--no-clear" ]]; then
            clear_screen
        fi
        echo "Export Bond Summary"
        local default_path="/var/log/bond_manager/bond_summary.json"
        local response=""
        if read_input "Enter output path [$default_path]: " response true; then
            target_path=${response:-$default_path}
        else
            target_path=$default_path
        fi
    fi
    local bonds=()
    mapfile -t bonds < <(list_bonds)
    local tmp_file
    tmp_file=$(mktemp)
    TEMP_FILES+=("$tmp_file")
    {
        printf '{\n'
        printf '  "generated_at": "%s",\n' "$(date -Iseconds)"
        local host_name=$(hostname -f 2>/dev/null || hostname)
        printf '  "host": "%s",\n' "$(json_escape "$host_name")"
        printf '  "bonds": [\n'
        for i in "${!bonds[@]}"; do
            local bond="${bonds[$i]}"
            local mode=$(get_bond_mode "$bond")
            local options=$(nmcli_get_field bond.options "$bond")
            local vlan=$(nmcli_get_field 802-3-ethernet.vlan "$bond")
            local ipv4=$(nmcli_get_field ipv4.addresses "$bond")
            local ipv6=$(nmcli_get_field ipv6.addresses "$bond")
            local gateway=$(nmcli_get_field ipv4.gateway "$bond")
            local primary=$(get_bond_option_value "$options" "primary")
            printf '    {\n'
            printf '      "name": "%s",\n' "$(json_escape "$bond")"
            printf '      "mode": "%s",\n' "$(json_escape "${mode:-unknown}")"
            if [[ -n "$primary" ]]; then
                printf '      "primary": "%s",\n' "$(json_escape "$primary")"
            else
                printf '      "primary": null,\n'
            fi
            if [[ -n "$vlan" && "$vlan" != "0" ]]; then
                printf '      "vlan": %s,\n' "$vlan"
            else
                printf '      "vlan": null,\n'
            fi
            printf '      "ipv4": %s,\n' "$(to_json_array "$ipv4")"
            printf '      "ipv6": %s,\n' "$(to_json_array "$ipv6")"
            if [[ -n "$gateway" ]]; then
                printf '      "gateway": "%s",\n' "$(json_escape "$gateway")"
            else
                printf '      "gateway": null,\n'
            fi
            printf '      "options": %s,\n' "$(to_json_array "$options")"
            local slaves=()
            mapfile -t slaves < <(get_bond_slaves "$bond")
            printf '      "slaves": [\n'
            for j in "${!slaves[@]}"; do
                local slave="${slaves[$j]}"
                local iface=$(nmcli_get_field connection.interface-name "$slave")
                [[ -z "$iface" ]] && iface="$slave"
                local info=($(get_nic_info "$iface"))
                local speed="${info[0]:-Unknown}"
                local status="${info[1]:-DOWN}"
                printf '        {\n'
                printf '          "connection": "%s",\n' "$(json_escape "$slave")"
                printf '          "interface": "%s",\n' "$(json_escape "$iface")"
                printf '          "speed": "%s",\n' "$(json_escape "$speed")"
                printf '          "link": "%s"\n' "$(json_escape "$status")"
                if (( j == ${#slaves[@]} - 1 )); then
                    printf '        }\n'
                else
                    printf '        },\n'
                fi
            done
            printf '      ]\n'
            if (( i == ${#bonds[@]} - 1 )); then
                printf '    }\n'
            else
                printf '    },\n'
            fi
        done
        printf '  ]\n'
        printf '}\n'
    } > "$tmp_file"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Dry run: would export bond summary to $target_path"
        return 0
    fi
    local dir
    dir=$(dirname "$target_path")
    if ! mkdir -p "$dir" 2>/dev/null; then
        log ERROR "Failed to create directory $dir for bond summary"
        echo "Error: Failed to create directory $dir" >&2
        return 1
    fi
    if mv "$tmp_file" "$target_path" 2>/dev/null; then
        chmod 640 "$target_path" 2>/dev/null || true
        log INFO "Exported bond summary to $target_path"
        echo "Bond summary exported to $target_path"
        return 0
    fi
    log ERROR "Failed to move bond summary to $target_path"
    echo "Error: Failed to write bond summary" >&2
    return 1
}

collect_support_bundle() {
    clear_screen
    echo "Collect Support Bundle"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local workdir
    workdir=$(mktemp -d)
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Dry run: would collect support bundle at $SUPPORT_DIR/support_${timestamp}.tar.gz"
        rm -rf "$workdir"
        return 0
    fi
    mkdir -p "$SUPPORT_DIR"
    show_bond_summary --no-clear > "$workdir/bond_summary.txt" 2>&1 || true
    export_bond_summary "$workdir/bond_summary.json" "--no-clear" > /dev/null 2>&1 || true
    nmcli general status > "$workdir/nmcli_general_status.txt" 2>&1 || true
    nmcli device status > "$workdir/nmcli_device_status.txt" 2>&1 || true
    nmcli con show > "$workdir/nmcli_connections.txt" 2>&1 || true
    ip addr show > "$workdir/ip_addr.txt" 2>&1 || true
    ip route show > "$workdir/ip_route.txt" 2>&1 || true
    hostnamectl status > "$workdir/hostnamectl.txt" 2>&1 || true
    cp /etc/os-release "$workdir/os-release" 2>/dev/null || true
    if [[ -f "$LOG_FILE" ]]; then
        cp "$LOG_FILE" "$workdir/bond_manager.log" 2>/dev/null || true
    fi
    local bonds=()
    mapfile -t bonds < <(list_bonds)
    for bond in "${bonds[@]}"; do
        if [[ -f "/proc/net/bonding/$bond" ]]; then
            cp "/proc/net/bonding/$bond" "$workdir/bonding_$bond.txt" 2>/dev/null || true
        fi
    done
    local interfaces=()
    for bond in "${bonds[@]}"; do
        local slaves=()
        mapfile -t slaves < <(get_bond_slaves "$bond")
        for slave in "${slaves[@]}"; do
            local iface=$(nmcli_get_field connection.interface-name "$slave")
            [[ -z "$iface" ]] && iface="$slave"
            interfaces+=("$iface")
        done
    done
    local unique_interfaces=()
    local seen=""
    for iface in "${interfaces[@]}"; do
        [[ -z "$iface" ]] && continue
        if [[ ",$seen," != *",$iface,"* ]]; then
            unique_interfaces+=("$iface")
            seen+="${iface},"
        fi
    done
    for iface in "${unique_interfaces[@]}"; do
        ethtool "$iface" > "$workdir/ethtool_$iface.txt" 2>&1 || true
        ip -s link show "$iface" > "$workdir/ip_link_$iface.txt" 2>&1 || true
    done
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u NetworkManager -n 300 > "$workdir/journalctl_NetworkManager.txt" 2>&1 || true
    fi
    local bundle="$SUPPORT_DIR/support_${timestamp}.tar.gz"
    if tar -czf "$bundle" -C "$workdir" .; then
        chmod 640 "$bundle" 2>/dev/null || true
        log INFO "Collected support bundle at $bundle"
        echo "Support bundle created at $bundle"
    else
        log ERROR "Failed to create support bundle archive"
        echo "Error: Failed to create support bundle" >&2
        rm -rf "$workdir"
        return 1
    fi
    rm -rf "$workdir"
    return 0
}

# Portable screen clear
clear_screen() {
    if command -v clear >/dev/null; then
        clear
    else
        printf '\033[H\033[2J'
    fi
}

# Backup NetworkManager configs
backup_configs() {
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/${BACKUP_PREFIX}-${timestamp}.tar.gz"
    log "Backing up NetworkManager configs to $backup_file"
    tar -czf "$backup_file" /etc/NetworkManager/system-connections/ 2>/dev/null || {
        log "Warning: Backup failed"
        echo "Warning: Failed to create backup" >&2
    }
    prune_old_backups
}

# Rollback to last backup
rollback() {
    trap - ERR  # prevent recursive trap
    local backups=("$BACKUP_DIR"/conn-*.tar.gz)
    if (( ${#backups[@]} == 0 )); then
        log "Rollback failed: No backups found"
        echo "Error: No backups available for rollback" >&2
        trap rollback ERR
        return 1
    fi
    local last_backup
    last_backup=$(ls -t "${backups[@]}" 2>/dev/null | head -n1)
    log "Restoring from $last_backup"
    if tar -xzf "$last_backup" -C /etc/NetworkManager/system-connections/; then
        nmcli con reload
        restore_selinux_context
        log "Rollback successful"
        echo "Rollback successful" >&2
    else
        log "Rollback failed"
        echo "Error: Rollback failed" >&2
        trap rollback ERR
        return 1
    fi
    trap rollback ERR
}

# Remove temporary files and reset state
cleanup() {
    set +x
    for tmp in "${TEMP_FILES[@]}"; do
        [[ -f "$tmp" ]] && rm -f "$tmp"
    done
    stty sane 2>/dev/null
    tput init 2>/dev/null
}

# Prompt user for rollback after successful operations
prompt_rollback() {
    local prev_timeout=$TIMEOUT
    local response=""
    TIMEOUT=60
    if read_input "Rollback? (y/N): " response; then
        if [[ "$response" =~ ^[Yy]$ ]]; then
            rollback
        fi
    else
        echo "No response within $TIMEOUT seconds, rolling back..."
        rollback
    fi
    TIMEOUT=$prev_timeout
}

# Pause without triggering rollback on timeout
pause_continue() {
    local prev_timeout=$TIMEOUT
    TIMEOUT=15
    read_input "Press Enter to continue..." _ || true
    TIMEOUT=$prev_timeout
}

# Get available Ethernet NICs
get_available_nics() {
    local -a preferred=()
    local -a busy=()
    local -a fallback=()
    declare -A skip_map=()
    declare -A seen=()
    local bond line nic dev type state flags connection
    local broadcast_re='^[^<]*<([^>]*)>'
    local summary="none"

    DEVICE_CONNECTION_MAP=()
    DEVICE_STATE_MAP=()

    # Track interfaces that are already enslaved in an existing bond
    for bond in /proc/net/bonding/*; do
        [[ -f "$bond" ]] || continue
        while IFS= read -r line; do
            if [[ $line =~ ^Slave\ Interface:\ (.*)$ ]]; then
                skip_map["${BASH_REMATCH[1]}"]=1
            fi
        done < "$bond"
    done

    # Prefer idle Ethernet devices reported by NetworkManager
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        IFS=: read -r dev type state _ <<<"$line"
        [[ -z "$dev" ]] && continue
        [[ $type == "ethernet" || $type == "802-3-ethernet" ]] || continue
        [[ -n ${skip_map[$dev]+x} ]] && continue
        connection=${line#"$dev:$type:$state"}
        connection=${connection#:}
        [[ -z "$connection" ]] && connection="--"
        DEVICE_CONNECTION_MAP["$dev"]="$connection"
        DEVICE_STATE_MAP["$dev"]="$state"
        if [[ $state == connected* || $state == connecting* || $state == activating* ]]; then
            if [[ -z ${seen[$dev]+x} ]]; then
                busy+=("$dev")
                seen[$dev]=1
            fi
        else
            if [[ -z ${seen[$dev]+x} ]]; then
                preferred+=("$dev")
                seen[$dev]=1
            fi
        fi
    done < <(nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status 2>/dev/null || true)

    # Capture any additional active Ethernet devices so they can be offered as a fallback
    while IFS=: read -r dev type; do
        [[ -z "$dev" ]] && continue
        [[ $type == "ethernet" || $type == "802-3-ethernet" ]] || continue
        [[ -n ${skip_map[$dev]+x} ]] && continue
        if [[ -z ${seen[$dev]+x} ]]; then
            busy+=("$dev")
            seen[$dev]=1
        fi
    done < <(nmcli -t -f DEVICE,TYPE connection show --active 2>/dev/null || true)

    # Enumerate interfaces reported by ip(8) and include broadcast-capable devices
    while IFS= read -r line; do
        if [[ $line =~ ^[0-9]+:\ ([^:@]+)[:@] ]]; then
            nic="${BASH_REMATCH[1]}"
        else
            continue
        fi
        [[ $nic =~ ^(en|eth|em|p[0-9]).* ]] || continue
        [[ -n ${skip_map[$nic]+x} ]] && continue
        if [[ $line =~ $broadcast_re ]]; then
            flags=${BASH_REMATCH[1]}
            [[ $flags == *BROADCAST* ]] || continue
        fi
        if [[ -z ${seen[$nic]+x} ]]; then
            fallback+=("$nic")
            seen[$nic]=1
        fi
    done < <(ip -o link show 2>/dev/null || true)

    local -a available=()
    available+=("${preferred[@]}")
    available+=("${fallback[@]}")
    available+=("${busy[@]}")

    if (( ${#available[@]} > 0 )); then
        summary="${available[*]}"
    fi
    log DEBUG "Discovered NIC candidates: $summary"

    detect_primary_connection

    if [[ -n "$CURRENT_PRIMARY_DEVICE" ]]; then
        local active_conn="${CURRENT_PRIMARY_CONNECTION:-none}"
        log DEBUG "Primary network path detected via $CURRENT_PRIMARY_DEVICE (connection: $active_conn)"
    else
        log DEBUG "Unable to determine primary network path"
    fi

    if (( ${#available[@]} > 0 )); then
        printf '%s\n' "${available[@]}"
    fi
}

detect_primary_connection() {
    CURRENT_PRIMARY_DEVICE=""
    CURRENT_PRIMARY_CONNECTION=""

    local remote_info="${SSH_CONNECTION:-}"
    local candidate_dev=""
    if [[ -n "$remote_info" ]]; then
        local remote_host="${remote_info%% *}"
        if [[ -n "$remote_host" ]]; then
            candidate_dev=$(ip route get "$remote_host" 2>/dev/null | \
                awk '/ dev / {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
        fi
    fi

    if [[ -z "$candidate_dev" ]]; then
        candidate_dev=$(ip route show default 2>/dev/null | \
            awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
    fi
    if [[ -z "$candidate_dev" ]]; then
        candidate_dev=$(ip -6 route show default 2>/dev/null | \
            awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
    fi

    if [[ -n "$candidate_dev" ]]; then
        CURRENT_PRIMARY_DEVICE="$candidate_dev"
        local active_conn=""
        if [[ -n ${DEVICE_CONNECTION_MAP[$candidate_dev]+x} ]]; then
            active_conn="${DEVICE_CONNECTION_MAP[$candidate_dev]}"
        else
            active_conn=$(nmcli -t -f DEVICE,CONNECTION device status 2>/dev/null | \
                awk -F: -v dev="$candidate_dev" '$1==dev {sub($1 FS, ""); print; exit}')
        fi
        if [[ -n "$active_conn" && "$active_conn" != "--" ]]; then
            CURRENT_PRIMARY_CONNECTION="$active_conn"
        fi
    fi
}

# Get NIC speed and status
get_nic_info() {
    local nic=$1
    local speed="Unknown"
    local status="DOWN"
    local ethtool_out
    ethtool_out=$(ethtool "$nic" 2>/dev/null)
    if [[ "$ethtool_out" =~ Speed:[[:space:]]*([0-9]+)Mb/s ]]; then
        speed="${BASH_REMATCH[1]}Mb/s"
    fi
    if [[ "$ethtool_out" =~ Link\ detected:[[:space:]]*yes ]]; then
        status="UP"
    fi
    echo "$speed $status"
}

# Display NICs with indices
display_nics() {
    local bond_name=$1
    shift
    local nics=("$@")
    local slaves=()
    if [[ -n "$bond_name" && -f "/proc/net/bonding/$bond_name" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^Slave\ Interface:\ (.*)$ ]]; then
                slaves+=("${BASH_REMATCH[1]}")
            fi
        done < "/proc/net/bonding/$bond_name"
    fi
    echo "Available NICs (select at least two for new bonds):"
    for i in "${!nics[@]}"; do
        local slave_mark=""
        for slave in "${slaves[@]}"; do
            if [[ "${nics[$i]}" == "$slave" ]]; then
                slave_mark=" S"
                break
            fi
        done
        local IFS=' '
        read -r speed status < <(get_nic_info "${nics[$i]}")
        local nic="${nics[$i]}"
        local nm_summary=""
        if [[ -n ${DEVICE_STATE_MAP[$nic]+x} || -n ${DEVICE_CONNECTION_MAP[$nic]+x} ]]; then
            local state_display="${DEVICE_STATE_MAP[$nic]:-unknown}"
            local connection_display="none"
            local nm_connection="${DEVICE_CONNECTION_MAP[$nic]:-}"
            if [[ -n "$nm_connection" && "$nm_connection" != "--" ]]; then
                connection_display="$nm_connection"
            fi
            nm_summary=" [NM: $state_display, conn: $connection_display]"
        fi
        if [[ "$nic" == "$CURRENT_PRIMARY_DEVICE" ]]; then
            if [[ -n "$CURRENT_PRIMARY_CONNECTION" ]]; then
                nm_summary+=" {primary route: $CURRENT_PRIMARY_CONNECTION}"
            else
                nm_summary+=" {primary route}"
            fi
        fi
        printf "%d) %s (%s, %s)%s%s\n" $((i+1)) "$nic" "$speed" "$status" "$slave_mark" "$nm_summary"
    done
}

# Sanitize and read input
read_input() {
    local prompt=$1
    local var_name=$2
    local allow_empty=${3:-false}
    local retries=0
    local input=""
    # Clear input buffer
    while read -r -t 0.1 < /dev/tty; do :; done 2>/dev/null
    while [[ $retries -lt $MAX_RETRIES ]]; do
        /bin/echo -n "$prompt" >&2
        if read -t $TIMEOUT -r input < /dev/tty 2>/dev/null; then
            # Sanitize input
            input=$(echo "$input" | tr -d '\r\n' | sed 's/[^a-zA-Z0-9._,:\/ -]//g')
            if [[ -n "$input" || "$allow_empty" == "true" ]]; then
                eval "$var_name='$input'"
                return 0
            fi
            log WARN "Input timed out or empty, retry $((retries+1))/$MAX_RETRIES"
            ((retries++))
        else
            log WARN "Input read failed, retry $((retries+1))/$MAX_RETRIES"
            ((retries++))
        fi
    done
    log ERROR "Input timed out after $MAX_RETRIES retries"
    echo "Error: Input timed out" >&2
    return 1
}

# Validate bond name
validate_bond_name() {
    local name=$1
    if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "Error: Bond name must be alphanumeric with hyphens or underscores" >&2
        return 1
    fi
    return 0
}

# Validate VLAN ID
validate_vlan_id() {
    local vlan=$1
    if [[ -z "$vlan" ]]; then
        return 0
    fi
    if [[ ! "$vlan" =~ ^[0-9]+$ ]] || ((vlan < 1 || vlan > 4094)); then
        echo "Error: VLAN ID must be between 1 and 4094" >&2
        return 1
    fi
    return 0
}

# Validate IP address
validate_ip() {
    local ip=$1
    if [[ -z "$ip" ]]; then
        return 0
    fi
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        # Infer CIDR for IPv4
        if [[ ! "$ip" =~ /[0-9]{1,2}$ ]]; then
            if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]]; then
                ip="$ip/24"
            elif [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
                ip="$ip/12"
            else
                ip="$ip/32"
            fi
        fi
        echo "$ip"
        return 0
    elif [[ "$ip" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
        # Infer CIDR for IPv6
        if [[ ! "$ip" =~ /[0-9]{1,3}$ ]]; then
            ip="$ip/64"
        fi
        echo "$ip"
        return 0
    fi
    echo "Error: Invalid IP address format" >&2
    return 1
}

# Validate gateway
validate_gateway() {
    local gw=$1
    if [[ -z "$gw" ]]; then
        return 0
    fi
    if ping -c3 -W2 "$gw" &>/dev/null; then
        return 0
    fi
    echo "Error: Gateway $gw is not reachable" >&2
    return 1
}

# Retrieve current bonding mode. Works across NetworkManager versions.
get_bond_mode() {
    local bn=$1
    local mode
    mode=$(nmcli -t -f bond.mode con show "$bn" 2>/dev/null | cut -d: -f2)
    if [[ -z "$mode" ]]; then
        mode=$(nmcli -t -f bond.options con show "$bn" 2>/dev/null | \
            grep -o 'mode=[^,]*' | cut -d= -f2)
    fi
    echo "$mode"
}
# Set bonding mode with fallback to bond.options
set_bond_mode() {
    local bn="$1"
    local mode="$2"
    local primary="${3:-}"
    if nmcli con mod "$bn" bond.mode "$mode" &>>"$LOG_FILE"; then
        [[ -n "$primary" ]] && nmcli con mod "$bn" bond.options "primary=$primary" &>>"$LOG_FILE"
        return 0
    fi
    if nmcli con mod "$bn" bond.options "mode=$mode" &>>"$LOG_FILE"; then
        [[ -n "$primary" ]] && nmcli con mod "$bn" bond.options "primary=$primary" &>>"$LOG_FILE"
        return 0
    fi
    return 1
}


# Return slave connection names for the specified bond
get_bond_slaves() {
    local bn=$1
    local conn type master
    while IFS=: read -r conn type; do
        [[ $type == "ethernet" || $type == "802-3-ethernet" ]] || continue
        master=$(nmcli -t -f connection.master con show "$conn" 2>/dev/null | cut -d: -f2)
        [[ "$master" == "$bn" ]] && echo "$conn"
    done < <(nmcli -t -f NAME,TYPE con show)
}

# Create bond
create_bond() {
    local bond_name mode vlan ipv4 ipv6 gateway primary_nic
    local nics=()
    clear_screen
    echo "Create Bond"
    if ! read_input "Enter bond name (e.g., bond0): " bond_name; then
        return 1
    fi
    if ! validate_bond_name "$bond_name"; then
        return 1
    fi
    echo "Select bonding mode:"
    for i in "${!BOND_MODES[@]}"; do
        printf "%d) %s\n" $((i+1)) "${BOND_MODES[$i]}"
    done
    if ! read_input "Enter mode number (1-${#BOND_MODES[@]}): " mode_num; then
        return 1
    fi
    if [[ ! "$mode_num" =~ ^[0-9]+$ ]] || ((mode_num < 1 || mode_num > ${#BOND_MODES[@]})); then
        echo "Error: Invalid mode number" >&2
        return 1
    fi
    mode=${BOND_MODES[$((mode_num-1))]}
    local available_nics=($(get_available_nics))
    if [[ ${#available_nics[@]} -lt 2 ]]; then
        echo "Error: At least two available NICs required" >&2
        return 1
    fi
    display_nics "" "${available_nics[@]}"
    if ! read_input "Enter NIC numbers (e.g., '1 2' for ${available_nics[0]} and ${available_nics[1]}), 'q' to cancel, or press Enter to cancel: " nic_selection true; then
        return 1
    fi
    if [[ "$nic_selection" == "q" || -z "$nic_selection" ]]; then
        echo "Bond creation cancelled"
        return 0
    fi
    for num in $nic_selection; do
        if [[ ! "$num" =~ ^[0-9]+$ ]] || ((num < 1 || num > ${#available_nics[@]})); then
            echo "Error: Invalid NIC number: $num" >&2
            return 1
        fi
        local selected_nic="${available_nics[$((num-1))]}"
        if ! validate_nic_ready "$selected_nic"; then
            return 1
        fi
        nics+=("$selected_nic")
    done
    if [[ ${#nics[@]} -lt 2 ]]; then
        echo "Error: At least two NICs must be selected" >&2
        return 1
    fi
    echo "Selected NICs: ${nics[*]}"
    if ! read_input "Confirm selection? (y/n): " confirm; then
        return 1
    fi
    if [[ "$confirm" != "y" ]]; then
        echo "Bond creation cancelled"
        return 0
    fi
    if ! read_input "Enter VLAN ID (1-4094, optional, press Enter to skip): " vlan true; then
        return 1
    fi
    if ! validate_vlan_id "$vlan"; then
        return 1
    fi
    if ! read_input "Enter IPv4 address (optional, press Enter to skip): " ipv4 true; then
        return 1
    fi
    if [[ -n "$ipv4" ]]; then
        ipv4=$(validate_ip "$ipv4") || return 1
    fi
    if ! read_input "Enter IPv4 gateway (optional, press Enter to skip): " gateway true; then
        return 1
    fi
    if ! validate_gateway "$gateway"; then
        return 1
    fi
    if ! read_input "Enter IPv6 address (optional, press Enter to skip): " ipv6 true; then
        return 1
    fi
    if [[ -n "$ipv6" ]]; then
        ipv6=$(validate_ip "$ipv6") || return 1
    fi
    if [[ "$mode" == "active-backup" ]]; then
        if ! read_input "Enter primary NIC (optional, press Enter to skip): " primary_nic true; then
            return 1
        fi
        if [[ -n "$primary_nic" ]] && ! [[ " ${nics[*]} " =~ " $primary_nic " ]]; then
            echo "Error: Primary NIC must be one of the selected NICs" >&2
            return 1
        fi
    fi
    backup_configs
    local cmd=("nmcli" "con" "add" "type" "bond" "ifname" "$bond_name" "mode" "$mode")
    [[ -n "$primary_nic" ]] && cmd+=("bond.options" "primary=$primary_nic")
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "${cmd[*]}"
    else
        if "${cmd[@]}" &>>"$LOG_FILE"; then
            log "Created bond $bond_name with mode $mode"
        else
            log "Failed to create bond $bond_name"
            echo "Error: Failed to create bond" >&2
            rollback
            return 1
        fi
    fi
    if ! configure_bond_options "$bond_name" "$mode"; then
        rollback
        return 1
    fi
    for nic in "${nics[@]}"; do
        local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$nic" "master" "$bond_name")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${slave_cmd[*]}"
        else
            if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                log "Added slave $nic to bond $bond_name"
            else
                log "Failed to add slave $nic to bond $bond_name"
                echo "Error: Failed to add slave $nic" >&2
                rollback
                return 1
            fi
        fi
    done
    if [[ -n "$vlan" ]]; then
        local vlan_cmd=("nmcli" "con" "mod" "$bond_name" "802-3-ethernet.vlan" "$vlan")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${vlan_cmd[*]}"
        else
            if "${vlan_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set VLAN $vlan for bond $bond_name"
            else
                log "Failed to set VLAN $vlan for bond $bond_name"
                echo "Error: Failed to set VLAN" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv4" ]]; then
        local ip4_cmd=("nmcli" "con" "mod" "$bond_name" "ipv4.addresses" "$ipv4" "ipv4.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${ip4_cmd[*]}"
        else
            if "${ip4_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set IPv4 $ipv4 for bond $bond_name"
            else
                log "Failed to set IPv4 $ipv4 for bond $bond_name"
                echo "Error: Failed to set IPv4" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$gateway" ]]; then
        local gw_cmd=("nmcli" "con" "mod" "$bond_name" "ipv4.gateway" "$gateway")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${gw_cmd[*]}"
        else
            if "${gw_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set gateway $gateway for bond $bond_name"
            else
                log "Failed to set gateway $gateway for bond $bond_name"
                echo "Error: Failed to set gateway" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv6" ]]; then
        local ip6_cmd=("nmcli" "con" "mod" "$bond_name" "ipv6.addresses" "$ipv6" "ipv6.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${ip6_cmd[*]}"
        else
            if "${ip6_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set IPv6 $ipv6 for bond $bond_name"
            else
                log "Failed to set IPv6 $ipv6 for bond $bond_name"
                echo "Error: Failed to set IPv6" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Dry run complete"
        return 0
    fi
    if nmcli con up "$bond_name" &>>"$LOG_FILE"; then
        if [[ -n "$gateway" ]] && ! ping -c3 -W2 "$gateway" &>/dev/null; then
            log "Gateway $gateway not reachable after bond creation"
            echo "Error: Gateway not reachable after bond creation" >&2
            rollback
            return 1
        fi
        log "Bond $bond_name created and activated successfully"
        echo "Bond $bond_name created successfully"
        restore_selinux_context
    else
        log "Failed to activate bond $bond_name"
        echo "Error: Failed to activate bond" >&2
        rollback
        return 1
    fi
}

# Edit bond
edit_bond() {
    local bond_name mode vlan ipv4 ipv6 gateway primary_nic
    local nics=()
    clear_screen
    echo "Edit Bond"
    local bonds=()
    mapfile -t bonds < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="bond"{print $1}')
    if [[ ${#bonds[@]} -eq 0 ]]; then
        echo "No bonds found" >&2
        return 1
    fi
    echo "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        echo "Error: Invalid bond number" >&2
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    echo "Editing bond $bond_name"
    echo "Select bonding mode (current: $(get_bond_mode "$bond_name")):"
    for i in "${!BOND_MODES[@]}"; do
        printf "%d) %s\n" $((i+1)) "${BOND_MODES[$i]}"
    done
    if ! read_input "Enter mode number (1-${#BOND_MODES[@]}, press Enter to keep current): " mode_num true; then
        return 1
    fi
    if [[ -n "$mode_num" ]]; then
        if [[ ! "$mode_num" =~ ^[0-9]+$ ]] || ((mode_num < 1 || mode_num > ${#BOND_MODES[@]})); then
            echo "Error: Invalid mode number" >&2
            return 1
        fi
        mode=${BOND_MODES[$((mode_num-1))]}
    fi
    local available_nics=($(get_available_nics))
    display_nics "$bond_name" "${available_nics[@]}"
    if ! read_input "Enter NIC numbers to add/remove (e.g., '1 2', press Enter to keep current, 'q' to cancel): " nic_selection true; then
        return 1
    fi
    if [[ "$nic_selection" == "q" ]]; then
        echo "Bond edit cancelled"
        return 0
    fi
    if [[ -n "$nic_selection" ]]; then
        for num in $nic_selection; do
            if [[ ! "$num" =~ ^[0-9]+$ ]] || ((num < 1 || num > ${#available_nics[@]})); then
                echo "Error: Invalid NIC number: $num" >&2
                return 1
            fi
            local selected_nic="${available_nics[$((num-1))]}"
            if ! validate_nic_ready "$selected_nic"; then
                return 1
            fi
            nics+=("$selected_nic")
        done
        if [[ ${#nics[@]} -lt 2 ]]; then
            echo "Error: At least two NICs must be selected" >&2
            return 1
        fi
        echo "Selected NICs: ${nics[*]}"
        if ! read_input "Confirm selection? (y/n): " confirm; then
            return 1
        fi
        if [[ "$confirm" != "y" ]]; then
            echo "Bond edit cancelled"
            return 0
        fi
    fi
    if ! read_input "Enter VLAN ID (1-4094, optional, press Enter to keep current or skip): " vlan true; then
        return 1
    fi
    if ! validate_vlan_id "$vlan"; then
        return 1
    fi
    if ! read_input "Enter IPv4 address (optional, press Enter to keep current or skip): " ipv4 true; then
        return 1
    fi
    if [[ -n "$ipv4" ]]; then
        ipv4=$(validate_ip "$ipv4") || return 1
    fi
    if ! read_input "Enter IPv4 gateway (optional, press Enter to keep current or skip): " gateway true; then
        return 1
    fi
    if ! validate_gateway "$gateway"; then
        return 1
    fi
    if ! read_input "Enter IPv6 address (optional, press Enter to keep current or skip): " ipv6 true; then
        return 1
    fi
    if [[ -n "$ipv6" ]]; then
        ipv6=$(validate_ip "$ipv6") || return 1
    fi
    if [[ -n "$mode" && "$mode" == "active-backup" ]]; then
        if ! read_input "Enter primary NIC (optional, press Enter to keep current or skip): " primary_nic true; then
            return 1
        fi
        if [[ -n "$primary_nic" ]] && ! [[ " ${nics[*]} " =~ " $primary_nic " ]]; then
            echo "Error: Primary NIC must be one of the selected NICs" >&2
            return 1
        fi
    fi
    backup_configs
    if [[ -n "$mode" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "set_bond_mode $bond_name $mode ${primary_nic:-}"
        else
            if set_bond_mode "$bond_name" "$mode" "$primary_nic"; then
                log "Updated bond $bond_name mode to $mode"
            else
                log "Failed to update bond $bond_name mode"
                echo "Error: Failed to update bond mode" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ ${#nics[@]} -gt 0 ]]; then
        # Remove existing slaves
        local current_slaves=()
        mapfile -t current_slaves < <(get_bond_slaves "$bond_name")
        for slave in "${current_slaves[@]}"; do
            local slave_cmd=("nmcli" "con" "del" "$slave")
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "${slave_cmd[*]}"
            else
                if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                    log "Removed slave $slave from bond $bond_name"
                else
                    log "Failed to remove slave $slave from bond $bond_name"
                    echo "Error: Failed to remove slave $slave" >&2
                    rollback
                    return 1
                fi
            fi
        done
        # Add new slaves
        for nic in "${nics[@]}"; do
            local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$nic" "master" "$bond_name")
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "${slave_cmd[*]}"
            else
                if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                    log "Added slave $nic to bond $bond_name"
                else
                    log "Failed to add slave $nic to bond $bond_name"
                    echo "Error: Failed to add slave $nic" >&2
                    rollback
                    return 1
                fi
            fi
        done
    fi
    local effective_mode="$mode"
    if [[ -z "$effective_mode" ]]; then
        effective_mode=$(get_bond_mode "$bond_name")
    fi
    if ! configure_bond_options "$bond_name" "$effective_mode"; then
        rollback
        return 1
    fi
    if [[ -n "$vlan" ]]; then
        local vlan_cmd=("nmcli" "con" "mod" "$bond_name" "802-3-ethernet.vlan" "$vlan")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${vlan_cmd[*]}"
        else
            if "${vlan_cmd[@]}" &>>"$LOG_FILE"; then
                log "Updated VLAN $vlan for bond $bond_name"
            else
                log "Failed to update VLAN $vlan for bond $bond_name"
                echo "Error: Failed to update VLAN" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv4" ]]; then
        local ip4_cmd=("nmcli" "con" "mod" "$bond_name" "ipv4.addresses" "$ipv4" "ipv4.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${ip4_cmd[*]}"
        else
            if "${ip4_cmd[@]}" &>>"$LOG_FILE"; then
                log "Updated IPv4 $ipv4 for bond $bond_name"
            else
                log "Failed to update IPv4 $ipv4 for bond $bond_name"
                echo "Error: Failed to update IPv4" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$gateway" ]]; then
        local gw_cmd=("nmcli" "con" "mod" "$bond_name" "ipv4.gateway" "$gateway")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${gw_cmd[*]}"
        else
            if "${gw_cmd[@]}" &>>"$LOG_FILE"; then
                log "Updated gateway $gateway for bond $bond_name"
            else
                log "Failed to update gateway $gateway for bond $bond_name"
                echo "Error: Failed to update gateway" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv6" ]]; then
        local ip6_cmd=("nmcli" "con" "mod" "$bond_name" "ipv6.addresses" "$ipv6" "ipv6.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${ip6_cmd[*]}"
        else
            if "${ip6_cmd[@]}" &>>"$LOG_FILE"; then
                log "Updated IPv6 $ipv6 for bond $bond_name"
            else
                log "Failed to update IPv6 $ipv6 for bond $bond_name"
                echo "Error: Failed to update IPv6" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Dry run complete"
        return 0
    fi
    if nmcli con up "$bond_name" &>>"$LOG_FILE"; then
        if [[ -n "$gateway" ]] && ! ping -c3 -W2 "$gateway" &>/dev/null; then
            log "Gateway $gateway not reachable after bond edit"
            echo "Error: Gateway not reachable after bond edit" >&2
            rollback
            return 1
        fi
        log "Bond $bond_name edited and activated successfully"
        echo "Bond $bond_name edited successfully"
        restore_selinux_context
    else
        log "Failed to activate bond $bond_name"
        echo "Error: Failed to activate bond" >&2
        rollback
        return 1
    fi
}

# Remove bond
remove_bond() {
    local bond_name
    clear_screen
    echo "Remove Bond"
    local bonds=()
    mapfile -t bonds < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="bond"{print $1}')
    if [[ ${#bonds[@]} -eq 0 ]]; then
        echo "No bonds found" >&2
        return 1
    fi
    echo "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number to remove (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        echo "Error: Invalid bond number" >&2
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    if ! read_input "Confirm removal of bond $bond_name? (y/n): " confirm; then
        return 1
    fi
    if [[ "$confirm" != "y" ]]; then
        echo "Bond removal cancelled"
        return 0
    fi
    backup_configs
    local slaves=()
    mapfile -t slaves < <(get_bond_slaves "$bond_name")
    for slave in "${slaves[@]}"; do
        local slave_cmd=("nmcli" "con" "del" "$slave")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${slave_cmd[*]}"
        else
            if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                log "Removed slave $slave from bond $bond_name"
            else
                log "Failed to remove slave $slave from bond $bond_name"
                echo "Error: Failed to remove slave $slave" >&2
                rollback
                return 1
            fi
        fi
    done
    local bond_cmd=("nmcli" "con" "del" "$bond_name")
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "${bond_cmd[*]}"
    else
        if "${bond_cmd[@]}" &>>"$LOG_FILE"; then
            log "Removed bond $bond_name"
            echo "Bond $bond_name removed successfully"
            restore_selinux_context
        else
            log "Failed to remove bond $bond_name"
            echo "Error: Failed to remove bond" >&2
            rollback
            return 1
        fi
    fi
}

# Repair bond
repair_bond() {
    local bond_name
    clear_screen
    echo "Repair Bond"
    local bonds=()
    mapfile -t bonds < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="bond"{print $1}')
    if [[ ${#bonds[@]} -eq 0 ]]; then
        echo "No bonds found" >&2
        return 1
    fi
    echo "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number to repair (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        echo "Error: Invalid bond number" >&2
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    backup_configs
    local slaves=()
    if [[ -f "/proc/net/bonding/$bond_name" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^Slave\ Interface:\ (.*)$ ]]; then
                slaves+=("${BASH_REMATCH[1]}")
            fi
        done < "/proc/net/bonding/$bond_name"
    fi
    # Remove any existing slave connections for the bond to avoid duplicates
    local current_slaves=()
    mapfile -t current_slaves < <(get_bond_slaves "$bond_name")
    for conn in "${current_slaves[@]}"; do
        local del_cmd=("nmcli" "con" "del" "$conn")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${del_cmd[*]}"
        else
            if "${del_cmd[@]}" &>>"$LOG_FILE"; then
                log "Removed stale slave connection $conn from bond $bond_name"
                local iface=$(nmcli -t -f connection.interface-name con show "$conn" | cut -d: -f2)
                ip link set "$iface" down 2>/dev/null || true
                ip link set "$iface" nomaster 2>/dev/null || true
            else
                log "Failed to remove stale slave connection $conn from bond $bond_name"
                echo "Warning: Failed to remove stale slave $conn" >&2
            fi
        fi
    done
    for slave in "${slaves[@]}"; do
        if ! get_bond_slaves "$bond_name" | grep -q "^.*$slave$"; then
            local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$slave" "master" "$bond_name")
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "${slave_cmd[*]}"
            else
                if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                    log "Re-added slave $slave to bond $bond_name"
                else
                    log "Failed to re-add slave $slave to bond $bond_name"
                    echo "Error: Failed to re-add slave $slave" >&2
                    rollback
                    return 1
                fi
            fi
        fi
        if [[ "$DRY_RUN" != "true" ]]; then
            nmcli con up "$slave" &>>"$LOG_FILE" || {
                log "Failed to bring up slave $slave"
                echo "Warning: Failed to bring up slave $slave" >&2
            }
        fi
    done
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Dry run complete"
        return 0
    fi
    if nmcli con up "$bond_name" &>>"$LOG_FILE"; then
        echo "Bond $bond_name repaired and activated"
        log "Bond $bond_name repaired and activated"
        echo "Bond $bond_name repaired successfully"
        restore_selinux_context
    else
        log "Failed to activate bond $bond_name"
        echo "Error: Failed to activate bond" >&2
        rollback
        return 1
    fi
}

# Repair bond (10Gb Active-Backup)
repair_bond_10gb_ab() {
    local bond_name
    clear_screen
    echo "Repair Bond (10Gb Active-Backup)"
    local bonds=()
    mapfile -t bonds < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="bond"{print $1}')
    if [[ ${#bonds[@]} -eq 0 ]]; then
        echo "No bonds found" >&2
        return 1
    fi
    echo "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number to repair (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        echo "Error: Invalid bond number" >&2
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    backup_configs
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "set_bond_mode $bond_name active-backup"
    else
        if set_bond_mode "$bond_name" "active-backup"; then
            log "Set bond $bond_name to active-backup"
        else
            log "Failed to set bond $bond_name to active-backup"
            echo "Error: Failed to set bond mode" >&2
            rollback
            return 1
        fi
    fi
    local slaves=()
    if [[ -f "/proc/net/bonding/$bond_name" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^Slave\ Interface:\ (.*)$ ]]; then
                slaves+=("${BASH_REMATCH[1]}")
            fi
        done < "/proc/net/bonding/$bond_name"
    fi
    # Remove any existing slave connections for the bond to avoid duplicates
    local current_slaves=()
    mapfile -t current_slaves < <(get_bond_slaves "$bond_name")
    for conn in "${current_slaves[@]}"; do
        local del_cmd=("nmcli" "con" "del" "$conn")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${del_cmd[*]}"
        else
            if "${del_cmd[@]}" &>>"$LOG_FILE"; then
                log "Removed stale slave connection $conn from bond $bond_name"
                local iface=$(nmcli -t -f connection.interface-name con show "$conn" | cut -d: -f2)
                ip link set "$iface" down 2>/dev/null || true
                ip link set "$iface" nomaster 2>/dev/null || true
            else
                log "Failed to remove stale slave connection $conn from bond $bond_name"
                echo "Warning: Failed to remove stale slave $conn" >&2
            fi
        fi
    done
    for slave in "${slaves[@]}"; do
        if ! ethtool "$slave" 2>/dev/null | grep -q "Speed: 10000Mb/s"; then
            echo "Skipping $slave: not 10Gb" >&2
            continue
        fi
        if ! get_bond_slaves "$bond_name" | grep -q "^.*$slave$"; then
            local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$slave" "master" "$bond_name")
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "${slave_cmd[*]}"
            else
                if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                    log "Re-added slave $slave to bond $bond_name"
                else
                    log "Failed to re-add slave $slave to bond $bond_name"
                    echo "Error: Failed to re-add slave $slave" >&2
                    rollback
                    return 1
                fi
            fi
        fi
        if [[ "$DRY_RUN" != "true" ]]; then
            nmcli con up "$slave" &>>"$LOG_FILE" || {
                log "Failed to bring up slave $slave"
                echo "Warning: Failed to bring up slave $slave" >&2
            }
        fi
    done
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Dry run complete"
        return 0
    fi
    if nmcli con up "$bond_name" &>>"$LOG_FILE"; then
        echo "Bond $bond_name repaired and activated"
        log "Bond $bond_name repaired and activated"
        echo "Bond $bond_name repaired successfully"
        restore_selinux_context
    else
        log "Failed to activate bond $bond_name"
        echo "Error: Failed to activate bond" >&2
        rollback
        return 1
    fi
}

# Diagnose bond
diagnose_bond() {
    local bond_name
    clear_screen
    echo "Diagnose Bond"
    local bonds=()
    mapfile -t bonds < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="bond"{print $1}')
    if [[ ${#bonds[@]} -eq 0 ]]; then
        echo "No bonds found" >&2
        return 1
    fi
    echo "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number to diagnose (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        echo "Error: Invalid bond number" >&2
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    echo "Bond Status for $bond_name:"
    if [[ -f "/proc/net/bonding/$bond_name" ]]; then
        cat "/proc/net/bonding/$bond_name"
    else
        echo "Bond $bond_name not found in /proc/net/bonding/"
    fi
    echo -e "\nDetailed Slave Information:"
    local slaves=()
    mapfile -t slaves < <(get_bond_slaves "$bond_name")
    for slave in "${slaves[@]}"; do
        local nic=$(nmcli -t -f connection.interface-name con show "$slave" | cut -d: -f2)
        echo "Slave: $nic"
        ethtool "$nic" | grep -E "Speed|Duplex|Link detected"
        ip -s link show "$nic"
        echo
    done
}

# Extended diagnostics
extended_diagnostics() {
    local bond_name
    clear
    echo "Extended Diagnostics"
    local bonds=$(nmcli -t -f NAME con show | grep bond)
    if [[ -z "$bonds" ]]; then
        echo "No bonds found" >&2
        return 1
    fi
    bonds=( $bonds )
    echo "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number for diagnostics (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        echo "Error: Invalid bond number" >&2
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    echo "Bond Status for $bond_name:"
    [[ -f "/proc/net/bonding/$bond_name" ]] && cat "/proc/net/bonding/$bond_name"
    local slaves=()
    mapfile -t slaves < <(get_bond_slaves "$bond_name")
    local gw=$(ip route show default | awk '/default/ {print $3; exit}')
    for slave in "${slaves[@]}"; do
        local nic=$(nmcli -t -f connection.interface-name con show "$slave" | cut -d: -f2)
        echo ""
        echo "Interface $nic:"
        ethtool "$nic" 2>/dev/null | grep -E "Speed|Duplex|Port|Link detected"
        if [[ -f "/sys/class/net/$nic/carrier" ]]; then
            [[ $(cat "/sys/class/net/$nic/carrier") == "1" ]] && echo "Carrier: on" || echo "Carrier: off"
        fi
        local target="$gw"
        [[ -z "$target" ]] && target="8.8.8.8"
        echo "Latency test to $target via $nic:"
        ping -I "$nic" -c 3 -w 5 "$target" | tail -n 2
    done
}

# Switch migration
switch_migration() {
    local bond_name new_nics=()
    clear_screen
    echo "Switch Migration Helper"
    local bonds=()
    mapfile -t bonds < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="bond"{print $1}')
    if [[ ${#bonds[@]} -eq 0 ]]; then
        echo "No bonds found" >&2
        return 1
    fi
    echo "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number to migrate (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        echo "Error: Invalid bond number" >&2
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    local available_nics=($(get_available_nics))
    if [[ ${#available_nics[@]} -lt 2 ]]; then
        echo "Error: At least two available NICs required" >&2
        return 1
    fi
    display_nics "$bond_name" "${available_nics[@]}"
    if ! read_input "Enter new NIC numbers (e.g., '1 2'), 'q' to cancel: " nic_selection true; then
        return 1
    fi
    if [[ "$nic_selection" == "q" ]]; then
        echo "Switch migration cancelled"
        return 0
    fi
    for num in $nic_selection; do
        if [[ ! "$num" =~ ^[0-9]+$ ]] || ((num < 1 || num > ${#available_nics[@]})); then
            echo "Error: Invalid NIC number: $num" >&2
            return 1
        fi
        local selected_nic="${available_nics[$((num-1))]}"
        if ! validate_nic_ready "$selected_nic"; then
            return 1
        fi
        new_nics+=("$selected_nic")
    done
    if [[ ${#new_nics[@]} -lt 2 ]]; then
        echo "Error: At least two NICs must be selected" >&2
        return 1
    fi
    echo "Selected new NICs: ${new_nics[*]}"
    if ! read_input "Confirm migration to new NICs? (y/n): " confirm; then
        return 1
    fi
    if [[ "$confirm" != "y" ]]; then
        echo "Switch migration cancelled"
        return 0
    fi
    backup_configs
    for nic in "${new_nics[@]}"; do
        local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$nic" "master" "$bond_name")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${slave_cmd[*]}"
        else
            if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                log "Added new slave $nic to bond $bond_name"
            else
                log "Failed to add new slave $nic to bond $bond_name"
                echo "Error: Failed to add new slave $nic" >&2
                rollback
                return 1
            fi
        fi
    done
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Dry run complete"
        return 0
    fi
    if nmcli con up "$bond_name" &>>"$LOG_FILE"; then
        local gateway=$(nmcli -t -f ipv4.gateway con show "$bond_name" | cut -d: -f2)
        if [[ -n "$gateway" ]] && ! ping -c3 -W2 "$gateway" &>/dev/null; then
            log "Gateway $gateway not reachable after adding new slaves"
            echo "Error: Gateway not reachable after migration" >&2
            rollback
            return 1
        fi
        # Remove old slaves not in the new selection
        local current_slave_conns=()
        mapfile -t current_slave_conns < <(get_bond_slaves "$bond_name")
        local slaves_to_remove=()
        for slave in "${current_slave_conns[@]}"; do
            local iface=$(nmcli_get_field connection.interface-name "$slave")
            [[ -z "$iface" ]] && iface="$slave"
            local keep=0
            for nic in "${new_nics[@]}"; do
                if [[ "$iface" == "$nic" ]]; then
                    keep=1
                    break
                fi
            done
            [[ $keep -eq 0 ]] && slaves_to_remove+=("$slave")
        done
        for slave in "${slaves_to_remove[@]}"; do
            local slave_cmd=("nmcli" "con" "del" "$slave")
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "${slave_cmd[*]}"
            else
                if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                    log "Removed old slave $slave from bond $bond_name"
                else
                    log "Failed to remove old slave $slave from bond $bond_name"
                    echo "Error: Failed to remove old slave $slave" >&2
                    rollback
                    return 1
                fi
            fi
        done
        log "Switch migration for bond $bond_name completed"
        echo "Switch migration for bond $bond_name completed successfully"
        restore_selinux_context
    else
        log "Failed to activate bond $bond_name after migration"
        echo "Error: Failed to activate bond after migration" >&2
        rollback
        return 1
    fi
}

# 10Gb migration wizard
ten_gb_migration() {
    local old_bond new_bond new_nics=()
    clear_screen
    echo "10Gb Migration Wizard"
    local bonds=()
    mapfile -t bonds < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="bond"{print $1}')
    if [[ ${#bonds[@]} -eq 0 ]]; then
        echo "No bonds found" >&2
        return 1
    fi
    echo "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter source bond number (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        echo "Error: Invalid bond number" >&2
        return 1
    fi
    old_bond=${bonds[$((bond_num-1))]}
    if ! read_input "Enter new bond name (e.g., bond10g): " new_bond; then
        return 1
    fi
    if ! validate_bond_name "$new_bond"; then
        return 1
    fi
    local available_nics=()
    for nic in $(get_available_nics); do
        if ethtool "$nic" | grep -q "Speed: 10000Mb/s"; then
            available_nics+=("$nic")
        fi
    done
    if [[ ${#available_nics[@]} -lt 2 ]]; then
        echo "Error: At least two 10Gb NICs required" >&2
        return 1
    fi
    display_nics "" "${available_nics[@]}"
    if ! read_input "Enter NIC numbers for new 10Gb bond (e.g., '1 2'), 'q' to cancel: " nic_selection true; then
        return 1
    fi
    if [[ "$nic_selection" == "q" ]]; then
        echo "10Gb migration cancelled"
        return 0
    fi
    for num in $nic_selection; do
        if [[ ! "$num" =~ ^[0-9]+$ ]] || ((num < 1 || num > ${#available_nics[@]})); then
            echo "Error: Invalid NIC number: $num" >&2
            return 1
        fi
        local selected_nic="${available_nics[$((num-1))]}"
        if ! validate_nic_ready "$selected_nic"; then
            return 1
        fi
        new_nics+=("$selected_nic")
    done
    if [[ ${#new_nics[@]} -lt 2 ]]; then
        echo "Error: At least two NICs must be selected" >&2
        return 1
    fi
    echo "Selected 10Gb NICs: ${new_nics[*]}"
    if ! read_input "Confirm creation of new 10Gb bond? (y/n): " confirm; then
        return 1
    fi
    if [[ "$confirm" != "y" ]]; then
        echo "10Gb migration cancelled"
        return 0
    fi
    backup_configs
    local mode=$(get_bond_mode "$old_bond")
    local vlan=$(nmcli -t -f 802-3-ethernet.vlan con show "$old_bond" | cut -d: -f2)
    local ipv4=$(nmcli -t -f ipv4.addresses con show "$old_bond" | cut -d: -f2)
    local gateway=$(nmcli -t -f ipv4.gateway con show "$old_bond" | cut -d: -f2)
    local ipv6=$(nmcli -t -f ipv6.addresses con show "$old_bond" | cut -d: -f2)
    local primary_nic=$(nmcli -t -f bond.options con show "$old_bond" | grep -o "primary=[^,]*" | cut -d= -f2)
    local cmd=("nmcli" "con" "add" "type" "bond" "ifname" "$new_bond" "mode" "$mode")
    [[ -n "$primary_nic" ]] && cmd+=("bond.options" "primary=$primary_nic")
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "${cmd[*]}"
    else
        if "${cmd[@]}" &>>"$LOG_FILE"; then
            log "Created new 10Gb bond $new_bond with mode $mode"
        else
            log "Failed to create new 10Gb bond $new_bond"
            echo "Error: Failed to create new bond" >&2
            rollback
            return 1
        fi
    fi
    if ! configure_bond_options "$new_bond" "$mode"; then
        rollback
        return 1
    fi
    for nic in "${new_nics[@]}"; do
        local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$nic" "master" "$new_bond")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${slave_cmd[*]}"
        else
            if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                log "Added slave $nic to new bond $new_bond"
            else
                log "Failed to add slave $nic to new bond $new_bond"
                echo "Error: Failed to add slave $nic" >&2
                rollback
                return 1
            fi
        fi
    done
    if [[ -n "$vlan" && "$vlan" != "0" ]]; then
        local vlan_cmd=("nmcli" "con" "mod" "$new_bond" "802-3-ethernet.vlan" "$vlan")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${vlan_cmd[*]}"
        else
            if "${vlan_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set VLAN $vlan for new bond $new_bond"
            else
                log "Failed to set VLAN $vlan for new bond $new_bond"
                echo "Error: Failed to set VLAN" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv4" ]]; then
        local ip4_cmd=("nmcli" "con" "mod" "$new_bond" "ipv4.addresses" "$ipv4" "ipv4.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${ip4_cmd[*]}"
        else
            if "${ip4_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set IPv4 $ipv4 for new bond $new_bond"
            else
                log "Failed to set IPv4 $ipv4 for new bond $new_bond"
                echo "Error: Failed to set IPv4" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$gateway" ]]; then
        local gw_cmd=("nmcli" "con" "mod" "$new_bond" "ipv4.gateway" "$gateway")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${gw_cmd[*]}"
        else
            if "${gw_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set gateway $gateway for new bond $new_bond"
            else
                log "Failed to set gateway $gateway for new bond $new_bond"
                echo "Error: Failed to set gateway" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv6" ]]; then
        local ip6_cmd=("nmcli" "con" "mod" "$new_bond" "ipv6.addresses" "$ipv6" "ipv6.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "${ip6_cmd[*]}"
        else
            if "${ip6_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set IPv6 $ipv6 for new bond $new_bond"
            else
                log "Failed to set IPv6 $ipv6 for new bond $new_bond"
                echo "Error: Failed to set IPv6" >&2
                rollback
                return 1
            fi
        fi
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Dry run complete"
        return 0
    fi
    if nmcli con up "$new_bond" &>>"$LOG_FILE"; then
        if [[ -n "$gateway" ]] && ! ping -c3 -W2 "$gateway" &>/dev/null; then
            log "Gateway $gateway not reachable after 10Gb migration"
            echo "Error: Gateway not reachable after migration" >&2
            rollback
            return 1
        fi
        log "10Gb migration to bond $new_bond completed"
        echo "10Gb migration to bond $new_bond completed successfully"
        restore_selinux_context
    else
        log "Failed to activate new bond $new_bond"
        echo "Error: Failed to activate new bond" >&2
        rollback
        return 1
    fi
}

# Main menu
main_menu() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--dry-run)
                DRY_RUN=true
                shift
                ;;
            --debug)
                DEBUG=true
                shift
                ;;
            --status)
                STATUS_MODE=true
                shift
                ;;
            --export-json)
                if [[ $# -lt 2 ]]; then
                    echo "Error: --export-json requires a path argument" >&2
                    exit 1
                fi
                EXPORT_JSON_PATH=$2
                shift 2
                ;;
            --help)
                echo "Usage: $0 [-n|--dry-run] [--debug] [--help]"
                echo "  -n, --dry-run: Echo commands without executing"
                echo "  --debug: Enable verbose output"
                echo "  --status: Print bond summary and exit"
                echo "  --export-json <path>: Export bond summary to JSON and exit"
                echo "  --help: Show this help message"
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                exit 1
                ;;
        esac
    done
    [[ "$DEBUG" == "true" ]] && set -x
    if [[ "$STATUS_MODE" == "true" ]]; then
        show_bond_summary --no-clear
        if [[ -n "$EXPORT_JSON_PATH" ]]; then
            export_bond_summary "$EXPORT_JSON_PATH" "--no-clear"
        fi
        exit 0
    fi
    if [[ -n "$EXPORT_JSON_PATH" ]]; then
        export_bond_summary "$EXPORT_JSON_PATH" "--no-clear"
        exit 0
    fi
    while true; do
        clear_screen
        echo "Bond Manager v$VERSION"
        echo "0) Rollback last change"
        echo "1) Switch migration helper"
        echo "2) 10Gb migration wizard"
        echo "3) Repair bond"
        echo "4) Repair bond (10GB A/B)"
        echo "5) Diagnose bond"
        echo "6) Extended diagnostics"
        echo "7) Create bond"
        echo "8) Edit bond"
        echo "9) Remove bond"
        echo "10) Show bond summary"
        echo "11) Export bond summary (JSON)"
        echo "12) Collect support bundle"
        echo "13) Show version"
        echo "14) Exit"
        if ! read_input "Select an option: " option; then
            continue
        fi
        case $option in
            0)
                rollback
                ;;
            1)
                switch_migration
                ;;
            2)
                ten_gb_migration
                ;;
            3)
                repair_bond
                ;;
            4)
                repair_bond_10gb_ab
                ;;
            5)
                diagnose_bond
                ;;
            6)
                extended_diagnostics
                ;;
            7)
                create_bond
                ;;
            8)
                edit_bond
                ;;
            9)
                remove_bond
                ;;
            10)
                show_bond_summary
                ;;
            11)
                export_bond_summary ""
                ;;
            12)
                collect_support_bundle
                ;;
            13)
                clear_screen
                echo "Bond Manager v$VERSION"
                ;;
            14)
                clear_screen
                exit 0
                ;;
            *)
                echo "Invalid option: $option" >&2
                ;;
        esac
        case $option in
            1|2|3|4|5|6|7|8|9)
                prompt_rollback
                ;;
        esac
        pause_continue
    done
}

# Run main menu
preflight_checks
main_menu "$@"
