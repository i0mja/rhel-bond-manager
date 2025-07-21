
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
BACKUP_PREFIX="conn-$(date +%Y%m%d_%H%M%S)"
TIMEOUT=15
MAX_RETRIES=2
BOND_MODES=("balance-rr" "active-backup" "balance-xor" "broadcast" "802.3ad" "balance-tlb" "balance-alb")

# Color constants
GREEN="$(tput setaf 2)"
RED="$(tput setaf 1)"
YELLOW="$(tput setaf 3)"
CYAN="$(tput setaf 6)"
RESET="$(tput sgr0)"

# Output helpers
info() {
    echo -e "${GREEN}$*${RESET}"
}

warn() {
    echo -e "${YELLOW}$*${RESET}" >&2
}

error_msg() {
    echo -e "${RED}$*${RESET}" >&2
}

dry_run() {
    echo -e "${CYAN}$*${RESET}"
}

# Ensure script runs as root
if [[ $EUID -ne 0 ]]; then
    error_msg "Error: This script must be run as root"
    exit 1
fi

# Check for interactive terminal
if [[ ! -t 0 ]]; then
    error_msg "Error: This script requires an interactive terminal"
    exit 1
fi

# Initialize terminal settings
export TERM=xterm
stty sane 2>/dev/null
tput init 2>/dev/null

# Log terminal settings for debugging
{
    echo "=== Terminal Settings ==="
    echo "TERM=$TERM"
    stty -a
    echo "================="
} >> "$LOG_FILE" 2>/dev/null

# Check required commands
REQUIRED_CMDS=("nmcli" "ip" "awk" "sed" "tar" "ping" "ethtool" "stdbuf" "tput")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        error_msg "Error: Required command '$cmd' not found"
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
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $*" >> "$LOG_FILE"
}

# Backup NetworkManager configs
backup_configs() {
    local backup_file="$BACKUP_DIR/$BACKUP_PREFIX.tar.gz"
    log "Backing up NetworkManager configs to $backup_file"
    tar -czf "$backup_file" /etc/NetworkManager/system-connections/ 2>/dev/null || {
        log "Warning: Backup failed"
        warn "Warning: Failed to create backup"
    }
}

# Rollback to last backup
rollback() {
    local last_backup
    last_backup=$(ls -t "$BACKUP_DIR"/conn-*.tar.gz 2>/dev/null | head -n1)
    if [[ -z "$last_backup" ]]; then
        log "Rollback failed: No backups found"
        error_msg "Error: No backups available for rollback"
        return 1
    fi
    log "Restoring from $last_backup"
    if tar -xzf "$last_backup" -C /etc/NetworkManager/system-connections/; then
        nmcli con reload
        log "Rollback successful"
        info "Rollback successful"
    else
        log "Rollback failed"
        error_msg "Error: Rollback failed"
        return 1
    fi
}

# Get available Ethernet NICs
get_available_nics() {
    local nics=()
    local exclude_nics=()
    # Get enslaved NICs
    for bond in /proc/net/bonding/*; do
        if [[ -f "$bond" ]]; then
            while IFS= read -r line; do
                if [[ "$line" =~ ^Slave\ Interface:\ (.*)$ ]]; then
                    exclude_nics+=("${BASH_REMATCH[1]}")
                fi
            done < "$bond"
        fi
    done
    # Get NICs with standalone connections
    while IFS= read -r line; do
        if [[ "$line" =~ ^([^:]+):.*type\ ethernet ]]; then
            exclude_nics+=("${BASH_REMATCH[1]}")
        fi
    done < <(nmcli -t -f NAME,TYPE con show --active)
    # Get all Ethernet NICs
    while IFS= read -r line; do
        if [[ "$line" =~ ^([0-9]+):\ (en|eth|ens|eno)[^:]+ ]]; then
            local nic="${BASH_REMATCH[2]}${line#*: }"
            nic=${nic%%:*} # Remove trailing colon and beyond
            # Exclude enslaved or connected NICs
            local skip=0
            for exclude in "${exclude_nics[@]}"; do
                if [[ "$nic" == "$exclude" ]]; then
                    skip=1
                    break
                fi
            done
            [[ $skip -eq 0 ]] && nics+=("$nic")
        fi
    done < <(ip link show)
    echo "${nics[@]}"
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
    local nics=("$@")
    local bond_name=$1
    local slaves=()
    if [[ -n "$bond_name" && -f "/proc/net/bonding/$bond_name" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^Slave\ Interface:\ (.*)$ ]]; then
                slaves+=("${BASH_REMATCH[1]}")
            fi
        done < "/proc/net/bonding/$bond_name"
    fi
    info "Available NICs (select at least two for new bonds):"
    for i in "${!nics[@]}"; do
        local slave_mark=""
        for slave in "${slaves[@]}"; do
            if [[ "${nics[$i]}" == "$slave" ]]; then
                slave_mark=" S"
                break
            fi
        done
        read -r speed status < <(get_nic_info "${nics[$i]}")
        printf "%d) %s (%s, %s)%s\n" $((i+1)) "${nics[$i]}" "$speed" "$status" "$slave_mark"
    done
}

# Sanitize and read input
read_input() {
    local prompt=$1
    local var_name=$2
    local retries=0
    local input=""
    # Clear input buffer
    while read -r -t 0.1 < /dev/tty; do :; done 2>/dev/null
    while [[ $retries -lt $MAX_RETRIES ]]; do
        /bin/echo -n "$prompt" >&2
        if read -t $TIMEOUT -r input < /dev/tty 2>/dev/null; then
            # Sanitize input
            input=$(echo "$input" | tr -d '\r\n' | sed 's/[^a-zA-Z0-9._\- ]//g')
            if [[ -n "$input" ]]; then
                eval "$var_name='$input'"
                return 0
            fi
            log "Input timed out or empty, retry $((retries+1))/$MAX_RETRIES"
            ((retries++))
        else
            log "Input read failed, retry $((retries+1))/$MAX_RETRIES"
            ((retries++))
        fi
    done
    log "Input timed out after $MAX_RETRIES retries"
    error_msg "Error: Input timed out"
    return 1
}

# Validate bond name
validate_bond_name() {
    local name=$1
    if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        error_msg "Error: Bond name must be alphanumeric with hyphens or underscores"
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
        error_msg "Error: VLAN ID must be between 1 and 4094"
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
    error_msg "Error: Invalid IP address format"
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
    error_msg "Error: Gateway $gw is not reachable"
    return 1
}

# Create bond
create_bond() {
    local bond_name mode vlan ipv4 ipv6 gateway primary_nic
    local nics=()
    clear
    info "Create Bond"
    if ! read_input "Enter bond name (e.g., bond0): " bond_name; then
        return 1
    fi
    if ! validate_bond_name "$bond_name"; then
        return 1
    fi
    info "Select bonding mode:"
    for i in "${!BOND_MODES[@]}"; do
        printf "%d) %s\n" $((i+1)) "${BOND_MODES[$i]}"
    done
    if ! read_input "Enter mode number (1-${#BOND_MODES[@]}): " mode_num; then
        return 1
    fi
    if [[ ! "$mode_num" =~ ^[0-9]+$ ]] || ((mode_num < 1 || mode_num > ${#BOND_MODES[@]})); then
        error_msg "Error: Invalid mode number"
        return 1
    fi
    mode=${BOND_MODES[$((mode_num-1))]}
    local available_nics=($(get_available_nics))
    if [[ ${#available_nics[@]} -lt 2 ]]; then
        error_msg "Error: At least two available NICs required"
        return 1
    fi
    display_nics "" "${available_nics[@]}"
    if ! read_input "Enter NIC numbers (e.g., '1 2' for ${available_nics[0]} and ${available_nics[1]}), 'q' to cancel, or press Enter to cancel: " nic_selection; then
        return 1
    fi
    if [[ "$nic_selection" == "q" || -z "$nic_selection" ]]; then
        info "Bond creation cancelled"
        return 0
    fi
    for num in $nic_selection; do
        if [[ ! "$num" =~ ^[0-9]+$ ]] || ((num < 1 || num > ${#available_nics[@]})); then
            error_msg "Error: Invalid NIC number: $num"
            return 1
        fi
        nics+=("${available_nics[$((num-1))]}")
    done
    if [[ ${#nics[@]} -lt 2 ]]; then
        error_msg "Error: At least two NICs must be selected"
        return 1
    fi
    info "Selected NICs: ${nics[*]}"
    if ! read_input "Confirm selection? (y/n): " confirm; then
        return 1
    fi
    if [[ "$confirm" != "y" ]]; then
        info "Bond creation cancelled"
        return 0
    fi
    if ! read_input "Enter VLAN ID (1-4094, optional, press Enter to skip): " vlan; then
        return 1
    fi
    if ! validate_vlan_id "$vlan"; then
        return 1
    fi
    if ! read_input "Enter IPv4 address (optional, press Enter to skip): " ipv4; then
        return 1
    fi
    if [[ -n "$ipv4" ]]; then
        ipv4=$(validate_ip "$ipv4") || return 1
    fi
    if ! read_input "Enter IPv4 gateway (optional, press Enter to skip): " gateway; then
        return 1
    fi
    if ! validate_gateway "$gateway"; then
        return 1
    fi
    if ! read_input "Enter IPv6 address (optional, press Enter to skip): " ipv6; then
        return 1
    fi
    if [[ -n "$ipv6" ]]; then
        ipv6=$(validate_ip "$ipv6") || return 1
    fi
    if [[ "$mode" == "active-backup" ]]; then
        if ! read_input "Enter primary NIC (optional, press Enter to skip): " primary_nic; then
            return 1
        fi
        if [[ -n "$primary_nic" ]] && ! [[ " ${nics[*]} " =~ " $primary_nic " ]]; then
            error_msg "Error: Primary NIC must be one of the selected NICs"
            return 1
        fi
    fi
    backup_configs
    local cmd=("nmcli" "con" "add" "type" "bond" "ifname" "$bond_name" "mode" "$mode")
    [[ -n "$primary_nic" ]] && cmd+=("bond.options" "primary=$primary_nic")
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${cmd[*]}"
    else
        if "${cmd[@]}" &>>"$LOG_FILE"; then
            log "Created bond $bond_name with mode $mode"
        else
            log "Failed to create bond $bond_name"
            error_msg "Error: Failed to create bond"
            rollback
            return 1
        fi
    fi
    for nic in "${nics[@]}"; do
        local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$nic" "master" "$bond_name")
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run "${slave_cmd[*]}"
        else
            if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                log "Added slave $nic to bond $bond_name"
            else
                log "Failed to add slave $nic to bond $bond_name"
                error_msg "Error: Failed to add slave $nic"
                rollback
                return 1
            fi
        fi
    done
    if [[ -n "$vlan" ]]; then
        local vlan_cmd=("nmcli" "con" "mod" "$bond_name" "802-3-ethernet.vlan" "$vlan")
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run "${vlan_cmd[*]}"
        else
            if "${vlan_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set VLAN $vlan for bond $bond_name"
            else
                log "Failed to set VLAN $vlan for bond $bond_name"
                error_msg "Error: Failed to set VLAN"
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv4" ]]; then
        local ip4_cmd=("nmcli" "con" "mod" "$bond_name" "ipv4.addresses" "$ipv4" "ipv4.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run "${ip4_cmd[*]}"
        else
            if "${ip4_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set IPv4 $ipv4 for bond $bond_name"
            else
                log "Failed to set IPv4 $ipv4 for bond $bond_name"
                error_msg "Error: Failed to set IPv4"
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$gateway" ]]; then
        local gw_cmd=("nmcli" "con" "mod" "$bond_name" "ipv4.gateway" "$gateway")
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run "${gw_cmd[*]}"
        else
            if "${gw_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set gateway $gateway for bond $bond_name"
            else
                log "Failed to set gateway $gateway for bond $bond_name"
                error_msg "Error: Failed to set gateway"
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv6" ]]; then
        local ip6_cmd=("nmcli" "con" "mod" "$bond_name" "ipv6.addresses" "$ipv6" "ipv6.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run "${ip6_cmd[*]}"
        else
            if "${ip6_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set IPv6 $ipv6 for bond $bond_name"
            else
                log "Failed to set IPv6 $ipv6 for bond $bond_name"
                error_msg "Error: Failed to set IPv6"
                rollback
                return 1
            fi
        fi
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Dry run complete"
        return 0
    fi
    if nmcli con up "$bond_name" &>>"$LOG_FILE"; then
        if [[ -n "$gateway" ]] && ! ping -c3 -W2 "$gateway" &>/dev/null; then
            log "Gateway $gateway not reachable after bond creation"
            error_msg "Error: Gateway not reachable after bond creation"
            rollback
            return 1
        fi
        log "Bond $bond_name created and activated successfully"
        info "Bond $bond_name created successfully"
    else
        log "Failed to activate bond $bond_name"
        error_msg "Error: Failed to activate bond"
        rollback
        return 1
    fi
}

# Edit bond
edit_bond() {
    local bond_name mode vlan ipv4 ipv6 gateway primary_nic
    local nics=()
    clear
    info "Edit Bond"
    local bonds=($(nmcli -t -f NAME con show | grep bond))
    if [[ ${#bonds[@]} -eq 0 ]]; then
        error_msg "No bonds found"
        return 1
    fi
    info "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        error_msg "Error: Invalid bond number"
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    info "Editing bond $bond_name"
    info "Select bonding mode (current: $(nmcli -t -f bond.mode con show "$bond_name" | cut -d: -f2)):"
    for i in "${!BOND_MODES[@]}"; do
        printf "%d) %s\n" $((i+1)) "${BOND_MODES[$i]}"
    done
    if ! read_input "Enter mode number (1-${#BOND_MODES[@]}, press Enter to keep current): " mode_num; then
        return 1
    fi
    if [[ -n "$mode_num" ]]; then
        if [[ ! "$mode_num" =~ ^[0-9]+$ ]] || ((mode_num < 1 || mode_num > ${#BOND_MODES[@]})); then
            error_msg "Error: Invalid mode number"
            return 1
        fi
        mode=${BOND_MODES[$((mode_num-1))]}
    fi
    local available_nics=($(get_available_nics))
    display_nics "$bond_name" "${available_nics[@]}"
    if ! read_input "Enter NIC numbers to add/remove (e.g., '1 2', press Enter to keep current, 'q' to cancel): " nic_selection; then
        return 1
    fi
    if [[ "$nic_selection" == "q" ]]; then
        info "Bond edit cancelled"
        return 0
    fi
    if [[ -n "$nic_selection" ]]; then
        for num in $nic_selection; do
            if [[ ! "$num" =~ ^[0-9]+$ ]] || ((num < 1 || num > ${#available_nics[@]})); then
                error_msg "Error: Invalid NIC number: $num"
                return 1
            fi
            nics+=("${available_nics[$((num-1))]}")
        done
        if [[ ${#nics[@]} -lt 2 ]]; then
            error_msg "Error: At least two NICs must be selected"
            return 1
        fi
        info "Selected NICs: ${nics[*]}"
        if ! read_input "Confirm selection? (y/n): " confirm; then
            return 1
        fi
        if [[ "$confirm" != "y" ]]; then
            info "Bond edit cancelled"
            return 0
        fi
    fi
    if ! read_input "Enter VLAN ID (1-4094, optional, press Enter to keep current or skip): " vlan; then
        return 1
    fi
    if ! validate_vlan_id "$vlan"; then
        return 1
    fi
    if ! read_input "Enter IPv4 address (optional, press Enter to keep current or skip): " ipv4; then
        return 1
    fi
    if [[ -n "$ipv4" ]]; then
        ipv4=$(validate_ip "$ipv4") || return 1
    fi
    if ! read_input "Enter IPv4 gateway (optional, press Enter to keep current or skip): " gateway; then
        return 1
    fi
    if ! validate_gateway "$gateway"; then
        return 1
    fi
    if ! read_input "Enter IPv6 address (optional, press Enter to keep current or skip): " ipv6; then
        return 1
    fi
    if [[ -n "$ipv6" ]]; then
        ipv6=$(validate_ip "$ipv6") || return 1
    fi
    if [[ -n "$mode" && "$mode" == "active-backup" ]]; then
        if ! read_input "Enter primary NIC (optional, press Enter to keep current or skip): " primary_nic; then
            return 1
        fi
        if [[ -n "$primary_nic" ]] && ! [[ " ${nics[*]} " =~ " $primary_nic " ]]; then
            error_msg "Error: Primary NIC must be one of the selected NICs"
            return 1
        fi
    fi
    backup_configs
    if [[ -n "$mode" ]]; then
        local cmd=("nmcli" "con" "mod" "$bond_name" "bond.mode" "$mode")
        [[ -n "$primary_nic" ]] && cmd+=("bond.options" "primary=$primary_nic")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${cmd[*]}"
        else
            if "${cmd[@]}" &>>"$LOG_FILE"; then
                log "Updated bond $bond_name mode to $mode"
            else
                log "Failed to update bond $bond_name mode"
                error_msg "Error: Failed to update bond mode"
                rollback
                return 1
            fi
        fi
    fi
    if [[ ${#nics[@]} -gt 0 ]]; then
        # Remove existing slaves
        local current_slaves=($(nmcli -t -f NAME con show | grep "ethernet.*$bond_name"))
        for slave in "${current_slaves[@]}"; do
            local slave_cmd=("nmcli" "con" "del" "$slave")
            if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${slave_cmd[*]}"
            else
                if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                    log "Removed slave $slave from bond $bond_name"
                else
                    log "Failed to remove slave $slave from bond $bond_name"
                    error_msg "Error: Failed to remove slave $slave"
                    rollback
                    return 1
                fi
            fi
        done
        # Add new slaves
        for nic in "${nics[@]}"; do
            local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$nic" "master" "$bond_name")
            if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${slave_cmd[*]}"
            else
                if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                    log "Added slave $nic to bond $bond_name"
                else
                    log "Failed to add slave $nic to bond $bond_name"
                    error_msg "Error: Failed to add slave $nic"
                    rollback
                    return 1
                fi
            fi
        done
    fi
    if [[ -n "$vlan" ]]; then
        local vlan_cmd=("nmcli" "con" "mod" "$bond_name" "802-3-ethernet.vlan" "$vlan")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${vlan_cmd[*]}"
        else
            if "${vlan_cmd[@]}" &>>"$LOG_FILE"; then
                log "Updated VLAN $vlan for bond $bond_name"
            else
                log "Failed to update VLAN $vlan for bond $bond_name"
                error_msg "Error: Failed to update VLAN"
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv4" ]]; then
        local ip4_cmd=("nmcli" "con" "mod" "$bond_name" "ipv4.addresses" "$ipv4" "ipv4.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${ip4_cmd[*]}"
        else
            if "${ip4_cmd[@]}" &>>"$LOG_FILE"; then
                log "Updated IPv4 $ipv4 for bond $bond_name"
            else
                log "Failed to update IPv4 $ipv4 for bond $bond_name"
                error_msg "Error: Failed to update IPv4"
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$gateway" ]]; then
        local gw_cmd=("nmcli" "con" "mod" "$bond_name" "ipv4.gateway" "$gateway")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${gw_cmd[*]}"
        else
            if "${gw_cmd[@]}" &>>"$LOG_FILE"; then
                log "Updated gateway $gateway for bond $bond_name"
            else
                log "Failed to update gateway $gateway for bond $bond_name"
                error_msg "Error: Failed to update gateway"
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv6" ]]; then
        local ip6_cmd=("nmcli" "con" "mod" "$bond_name" "ipv6.addresses" "$ipv6" "ipv6.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${ip6_cmd[*]}"
        else
            if "${ip6_cmd[@]}" &>>"$LOG_FILE"; then
                log "Updated IPv6 $ipv6 for bond $bond_name"
            else
                log "Failed to update IPv6 $ipv6 for bond $bond_name"
                error_msg "Error: Failed to update IPv6"
                rollback
                return 1
            fi
        fi
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Dry run complete"
        return 0
    fi
    if nmcli con up "$bond_name" &>>"$LOG_FILE"; then
        if [[ -n "$gateway" ]] && ! ping -c3 -W2 "$gateway" &>/dev/null; then
            log "Gateway $gateway not reachable after bond edit"
            error_msg "Error: Gateway not reachable after bond edit"
            rollback
            return 1
        fi
        log "Bond $bond_name edited and activated successfully"
        info "Bond $bond_name edited successfully"
    else
        log "Failed to activate bond $bond_name"
        error_msg "Error: Failed to activate bond"
        rollback
        return 1
    fi
}

# Remove bond
remove_bond() {
    local bond_name
    clear
    info "Remove Bond"
    local bonds=($(nmcli -t -f NAME con show | grep bond))
    if [[ ${#bonds[@]} -eq 0 ]]; then
        error_msg "No bonds found"
        return 1
    fi
    info "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number to remove (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        error_msg "Error: Invalid bond number"
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    if ! read_input "Confirm removal of bond $bond_name? (y/n): " confirm; then
        return 1
    fi
    if [[ "$confirm" != "y" ]]; then
        info "Bond removal cancelled"
        return 0
    fi
    backup_configs
    local slaves=($(nmcli -t -f NAME con show | grep "ethernet.*$bond_name"))
    for slave in "${slaves[@]}"; do
        local slave_cmd=("nmcli" "con" "del" "$slave")
        if [[ "$DRY_RUN" == "true" ]]; then
            dry_run "${slave_cmd[*]}"
        else
            if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                log "Removed slave $slave from bond $bond_name"
            else
                log "Failed to remove slave $slave from bond $bond_name"
                error_msg "Error: Failed to remove slave $slave"
                rollback
                return 1
            fi
        fi
    done
    local bond_cmd=("nmcli" "con" "del" "$bond_name")
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${bond_cmd[*]}"
    else
        if "${bond_cmd[@]}" &>>"$LOG_FILE"; then
            log "Removed bond $bond_name"
            info "Bond $bond_name removed successfully"
        else
            log "Failed to remove bond $bond_name"
            error_msg "Error: Failed to remove bond"
            rollback
            return 1
        fi
    fi
}

# Repair bond
repair_bond() {
    local bond_name
    clear
    info "Repair Bond"
    local bonds=($(nmcli -t -f NAME con show | grep bond))
    if [[ ${#bonds[@]} -eq 0 ]]; then
        error_msg "No bonds found"
        return 1
    fi
    info "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number to repair (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        error_msg "Error: Invalid bond number"
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
    for slave in "${slaves[@]}"; do
        if ! nmcli con show | grep -q "ethernet.*$bond_name.*$slave"; then
            local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$slave" "master" "$bond_name")
            if [[ "$DRY_RUN" == "true" ]]; then
                dry_run "${slave_cmd[*]}"
            else
                if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                    log "Re-added slave $slave to bond $bond_name"
                else
                    log "Failed to re-add slave $slave to bond $bond_name"
                    error_msg "Error: Failed to re-add slave $slave"
                    rollback
                    return 1
                fi
            fi
        fi
        if [[ "$DRY_RUN" != "true" ]]; then
            nmcli con up "$slave" &>>"$LOG_FILE" || {
                log "Failed to bring up slave $slave"
                warn "Warning: Failed to bring up slave $slave"
            }
        fi
    done
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Dry run complete"
        return 0
    fi
    if nmcli con up "$bond_name" &>>"$LOG_FILE"; then
        info "Bond $bond_name repaired and activated"
        info "Bond $bond_name repaired successfully"
    else
        log "Failed to activate bond $bond_name"
        error_msg "Error: Failed to activate bond"
        rollback
        return 1
    fi
}

# Diagnose bond
diagnose_bond() {
    local bond_name
    clear
    info "Diagnose Bond"
    local bonds=($(nmcli -t -f NAME con show | grep bond))
    if [[ ${#bonds[@]} -eq 0 ]]; then
        error_msg "No bonds found"
        return 1
    fi
    info "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number to diagnose (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        error_msg "Error: Invalid bond number"
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    info "Bond Status for $bond_name:"
    if [[ -f "/proc/net/bonding/$bond_name" ]]; then
        cat "/proc/net/bonding/$bond_name"
    else
        info "Bond $bond_name not found in /proc/net/bonding/"
    fi
    info "\nDetailed Slave Information:"
    local slaves=($(nmcli -t -f NAME con show | grep "ethernet.*$bond_name"))
    for slave in "${slaves[@]}"; do
        local nic=$(nmcli -t -f connection.interface-name con show "$slave" | cut -d: -f2)
        info "Slave: $nic"
        ethtool "$nic" | grep -E "Speed|Duplex|Link detected"
        ip -s link show "$nic"
        echo
    done
}

# Switch migration
switch_migration() {
    local bond_name new_nics=()
    clear
    info "Switch Migration Helper"
    local bonds=($(nmcli -t -f NAME con show | grep bond))
    if [[ ${#bonds[@]} -eq 0 ]]; then
        error_msg "No bonds found"
        return 1
    fi
    info "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter bond number to migrate (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        error_msg "Error: Invalid bond number"
        return 1
    fi
    bond_name=${bonds[$((bond_num-1))]}
    local available_nics=($(get_available_nics))
    if [[ ${#available_nics[@]} -lt 2 ]]; then
        error_msg "Error: At least two available NICs required"
        return 1
    fi
    display_nics "$bond_name" "${available_nics[@]}"
    if ! read_input "Enter new NIC numbers (e.g., '1 2'), 'q' to cancel: " nic_selection; then
        return 1
    fi
    if [[ "$nic_selection" == "q" ]]; then
        info "Switch migration cancelled"
        return 0
    fi
    for num in $nic_selection; do
        if [[ ! "$num" =~ ^[0-9]+$ ]] || ((num < 1 || num > ${#available_nics[@]})); then
            error_msg "Error: Invalid NIC number: $num"
            return 1
        fi
        new_nics+=("${available_nics[$((num-1))]}")
    done
    if [[ ${#new_nics[@]} -lt 2 ]]; then
        error_msg "Error: At least two NICs must be selected"
        return 1
    fi
    info "Selected new NICs: ${new_nics[*]}"
    if ! read_input "Confirm migration to new NICs? (y/n): " confirm; then
        return 1
    fi
    if [[ "$confirm" != "y" ]]; then
        info "Switch migration cancelled"
        return 0
    fi
    backup_configs
    for nic in "${new_nics[@]}"; do
        local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$nic" "master" "$bond_name")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${slave_cmd[*]}"
        else
            if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                log "Added new slave $nic to bond $bond_name"
            else
                log "Failed to add new slave $nic to bond $bond_name"
                error_msg "Error: Failed to add new slave $nic"
                rollback
                return 1
            fi
        fi
    done
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Dry run complete"
        return 0
    fi
    if nmcli con up "$bond_name" &>>"$LOG_FILE"; then
        local gateway=$(nmcli -t -f ipv4.gateway con show "$bond_name" | cut -d: -f2)
        if [[ -n "$gateway" ]] && ! ping -c3 -W2 "$gateway" &>/dev/null; then
            log "Gateway $gateway not reachable after adding new slaves"
            error_msg "Error: Gateway not reachable after migration"
            rollback
            return 1
        fi
        # Remove old slaves
        local old_slaves=($(nmcli -t -f NAME con show | grep "ethernet.*$bond_name" | grep -v "$(echo "${new_nics[*]}" | tr ' ' '|')"))
        for slave in "${old_slaves[@]}"; do
            local slave_cmd=("nmcli" "con" "del" "$slave")
            if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${slave_cmd[*]}"
            else
                if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                    log "Removed old slave $slave from bond $bond_name"
                else
                    log "Failed to remove old slave $slave from bond $bond_name"
                    error_msg "Error: Failed to remove old slave $slave"
                    rollback
                    return 1
                fi
            fi
        done
        log "Switch migration for bond $bond_name completed"
         info "Switch migration for bond $bond_name completed successfully"
    else
        log "Failed to activate bond $bond_name after migration"
        error_msg "Error: Failed to activate bond after migration"
        rollback
        return 1
    fi
}

# 10Gb migration wizard
ten_gb_migration() {
    local old_bond new_bond new_nics=()
    clear
    info "10Gb Migration Wizard"
    local bonds=($(nmcli -t -f NAME con show | grep bond))
    if [[ ${#bonds[@]} -eq 0 ]]; then
        error_msg "No bonds found"
        return 1
    fi
    info "Available bonds:"
    for i in "${!bonds[@]}"; do
        printf "%d) %s\n" $((i+1)) "${bonds[$i]}"
    done
    if ! read_input "Enter source bond number (1-${#bonds[@]}): " bond_num; then
        return 1
    fi
    if [[ ! "$bond_num" =~ ^[0-9]+$ ]] || ((bond_num < 1 || bond_num > ${#bonds[@]})); then
        error_msg "Error: Invalid bond number"
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
        error_msg "Error: At least two 10Gb NICs required"
        return 1
    fi
    display_nics "" "${available_nics[@]}"
    if ! read_input "Enter NIC numbers for new 10Gb bond (e.g., '1 2'), 'q' to cancel: " nic_selection; then
        return 1
    fi
    if [[ "$nic_selection" == "q" ]]; then
        info "10Gb migration cancelled"
        return 0
    fi
    for num in $nic_selection; do
        if [[ ! "$num" =~ ^[0-9]+$ ]] || ((num < 1 || num > ${#available_nics[@]})); then
            error_msg "Error: Invalid NIC number: $num"
            return 1
        fi
        new_nics+=("${available_nics[$((num-1))]}")
    done
    if [[ ${#new_nics[@]} -lt 2 ]]; then
        error_msg "Error: At least two NICs must be selected"
        return 1
    fi
    echo "Selected 10Gb NICs: ${new_nics[*]}"
    if ! read_input "Confirm creation of new 10Gb bond? (y/n): " confirm; then
        return 1
    fi
    if [[ "$confirm" != "y" ]]; then
        info "10Gb migration cancelled"
        return 0
    fi
    backup_configs
    local mode=$(nmcli -t -f bond.mode con show "$old_bond" | cut -d: -f2)
    local vlan=$(nmcli -t -f 802-3-ethernet.vlan con show "$old_bond" | cut -d: -f2)
    local ipv4=$(nmcli -t -f ipv4.addresses con show "$old_bond" | cut -d: -f2)
    local gateway=$(nmcli -t -f ipv4.gateway con show "$old_bond" | cut -d: -f2)
    local ipv6=$(nmcli -t -f ipv6.addresses con show "$old_bond" | cut -d: -f2)
    local primary_nic=$(nmcli -t -f bond.options con show "$old_bond" | grep -o "primary=[^,]*" | cut -d= -f2)
    local cmd=("nmcli" "con" "add" "type" "bond" "ifname" "$new_bond" "mode" "$mode")
    [[ -n "$primary_nic" ]] && cmd+=("bond.options" "primary=$primary_nic")
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${cmd[*]}"
    else
        if "${cmd[@]}" &>>"$LOG_FILE"; then
            log "Created new 10Gb bond $new_bond with mode $mode"
        else
            log "Failed to create new 10Gb bond $new_bond"
            error_msg "Error: Failed to create new bond"
            rollback
            return 1
        fi
    fi
    for nic in "${new_nics[@]}"; do
        local slave_cmd=("nmcli" "con" "add" "type" "ethernet" "ifname" "$nic" "master" "$new_bond")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${slave_cmd[*]}"
        else
            if "${slave_cmd[@]}" &>>"$LOG_FILE"; then
                log "Added slave $nic to new bond $new_bond"
            else
                log "Failed to add slave $nic to new bond $new_bond"
                error_msg "Error: Failed to add slave $nic"
                rollback
                return 1
            fi
        fi
    done
    if [[ -n "$vlan" && "$vlan" != "0" ]]; then
        local vlan_cmd=("nmcli" "con" "mod" "$new_bond" "802-3-ethernet.vlan" "$vlan")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${vlan_cmd[*]}"
        else
            if "${vlan_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set VLAN $vlan for new bond $new_bond"
            else
                log "Failed to set VLAN $vlan for new bond $new_bond"
                error_msg "Error: Failed to set VLAN"
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv4" ]]; then
        local ip4_cmd=("nmcli" "con" "mod" "$new_bond" "ipv4.addresses" "$ipv4" "ipv4.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${ip4_cmd[*]}"
        else
            if "${ip4_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set IPv4 $ipv4 for new bond $new_bond"
            else
                log "Failed to set IPv4 $ipv4 for new bond $new_bond"
                error_msg "Error: Failed to set IPv4"
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$gateway" ]]; then
        local gw_cmd=("nmcli" "con" "mod" "$new_bond" "ipv4.gateway" "$gateway")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${gw_cmd[*]}"
        else
            if "${gw_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set gateway $gateway for new bond $new_bond"
            else
                log "Failed to set gateway $gateway for new bond $new_bond"
                error_msg "Error: Failed to set gateway"
                rollback
                return 1
            fi
        fi
    fi
    if [[ -n "$ipv6" ]]; then
        local ip6_cmd=("nmcli" "con" "mod" "$new_bond" "ipv6.addresses" "$ipv6" "ipv6.method" "manual")
        if [[ "$DRY_RUN" == "true" ]]; then
        dry_run "${ip6_cmd[*]}"
        else
            if "${ip6_cmd[@]}" &>>"$LOG_FILE"; then
                log "Set IPv6 $ipv6 for new bond $new_bond"
            else
                log "Failed to set IPv6 $ipv6 for new bond $new_bond"
                error_msg "Error: Failed to set IPv6"
                rollback
                return 1
            fi
        fi
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        info "Dry run complete"
        return 0
    fi
    if nmcli con up "$new_bond" &>>"$LOG_FILE"; then
        if [[ -n "$gateway" ]] && ! ping -c3 -W2 "$gateway" &>/dev/null; then
            log "Gateway $gateway not reachable after 10Gb migration"
            error_msg "Error: Gateway not reachable after migration"
            rollback
            return 1
        fi
        log "10Gb migration to bond $new_bond completed"
         info "10Gb migration to bond $new_bond completed successfully"
    else
        log "Failed to activate new bond $new_bond"
        error_msg "Error: Failed to activate new bond"
        rollback
        return 1
    fi
}

# Main menu
main_menu() {
    DRY_RUN=false
    DEBUG=false
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --debug)
                DEBUG=true
                shift
                ;;
            --help)
                info "Usage: $0 [--dry-run] [--debug] [--help]"
                info "  --dry-run: Echo commands without executing"
                info "  --debug: Enable verbose output"
                info "  --help: Show this help message"
                exit 0
                ;;
            *)
                error_msg "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    [[ "$DEBUG" == "true" ]] && set -x
    while true; do
        clear
        stdbuf -oL info "Bond Manager v$VERSION"
        stdbuf -oL info "0) Rollback last change"
        stdbuf -oL info "1) Switch migration helper"
        stdbuf -oL info "2) 10Gb migration wizard"
        stdbuf -oL info "3) Repair bond"
        stdbuf -oL info "4) Diagnose bond"
        stdbuf -oL info "5) Extended diagnostics"
        stdbuf -oL info "6) Create bond"
        stdbuf -oL info "7) Edit bond"
        stdbuf -oL info "8) Remove bond"
        stdbuf -oL info "9) Show version"
        stdbuf -oL info "10) Exit"
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
                diagnose_bond
                ;;
            5)
                diagnose_bond
                ;;
            6)
                create_bond
                ;;
            7)
                edit_bond
                ;;
            8)
                remove_bond
                ;;
            9)
                clear
                info "Bond Manager v$VERSION"
                ;;
            10)
                clear
                exit 0
                ;;
            *)
                error_msg "Invalid option: $option"
                ;;
        esac
        read_input "Press Enter to continue..." _
    done
}

# Run main menu
main_menu "$@"
