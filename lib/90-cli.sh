# lib/90-cli.sh — argument parsing, dispatch, output commands and the TUI.
# shellcheck shell=bash
[[ -n "${BM_LIB_CLI:-}" ]] && return 0
BM_LIB_CLI=1

bm::cli::usage() {
  cat <<EOF
$BM_PROG v$BM_VERSION — safe NetworkManager bond management for RHEL-like systems

New here? Run  sudo $BM_PROG  for guided menus (with a practice mode).
Explain one command: $BM_PROG help COMMAND   Plain-words intro: $BM_PROG help basics

Common tasks:
$(bm::help::common_tasks)

Usage: $BM_PROG [GLOBAL FLAGS] <command> [ARGS]
       $BM_PROG                      (interactive TUI when run on a terminal)

Global flags:
  -n, --dry-run             Render the plan; execute nothing, write nothing
  -y, --yes                 No prompts; auto-commit when verification passes
      --json                Machine-readable output (list/show/status)
      --debug               Mirror log records to stderr
      --quiet               Suppress progress messages
      --no-color            Disable colored output (NO_COLOR is also honored)
      --plain               Plain numbered menus (serial consoles, basic terminals)
      --rollback-window S   Auto-rollback window in seconds (default: config)
      --no-checkpoint       Skip NM checkpoints (fall back to deadman/snapshot)
      --force-unsafe        Allow touching your SSH egress device w/o checkpoint
  -V, --version             Print version
  -h, --help                This help (after a command: help for that command)

Read-only commands (no root, write nothing):
  list                      One line per bond: name, mode, health
  show BOND                 Full bond detail (--json supported)
  status [BOND]             Health summary; exit 0 healthy / 10 degraded / 11 down
  diagnose BOND [--extended] [--target IP]
  verify BOND               Re-run the verification checks against kernel state
  nics [--all]              Network ports: link, speed, bond, "free - good to use"
  doctor                    Environment preflight + protection-tier report
  config show|path          Effective configuration / config file path
  completion bash           Emit bash completion script
  help [COMMAND|TOPIC]      Plain-English help with examples

Change commands (root; guarded by plan → snapshot → checkpoint → verify):
  create BOND --mode MODE --members IF1,IF2 [options]   Create a bond
  modify BOND [--mode MODE] [--opt k=v]... [--del-opt k]... [ip/mtu flags]
  add-member BOND IF[,IF...]
  remove-member BOND IF[,IF...]
  swap-member BOND --old IF --new IF     Add new first, then remove old
  remove BOND [--keep-vlans]             Delete bond + member/VLAN profiles
  vlan add BOND VID[:ip4=..;gw4=..] | vlan modify BOND VID [ip flags]
  vlan remove BOND VID | vlan list BOND
  clone SRC DST --members IF[,IF...] [--copy-ip] [--copy-vlans]
  repair BOND                            Rebuild port profiles from kernel state

Create/modify IP + tuning flags:
  --ip4 dhcp|none|CIDR[,CIDR]  --gw4 A  --dns4 A,B
  --ip6 auto|dhcp|none|CIDR[,CIDR]  --gw6 A  --dns6 A,B
  --mtu N   --opt key=value (repeatable)   --vlan VID[:ip4=..;gw4=..] (repeatable)
  --miimon MS  --primary IF  --lacp-rate fast|slow  --xmit-hash POLICY
  --arp-interval MS --arp-targets IP[,IP]  --min-links N  --no-activate

Safety commands:
  commit                    Confirm a pending change (disarms auto-rollback)
  rollback [--snapshot ID]  Revert pending change, or restore a snapshot
  snapshot create|list|diff ID|restore [ID]|prune
  bundle [--output PATH] [--redact]      Support bundle
  init                      Install default config + logrotate policy

Bond modes: ${BM_MODES[*]}

Exit codes: 0 ok/no-op | 1 error | 2 usage | 3 precondition | 4 locked
            5 verify-failed-and-rolled-back | 6 applied-but-unconfirmed
            10 degraded | 11 down

Legacy flags: --status ≡ status, --export-json PATH ≡ status --json > PATH

Help topics ($BM_PROG help TOPIC): ${BM_HELP_TOPICS[*]}
EOF
}

# A flag that needs a value got none (or got the next flag instead).
bm::cli::_need_arg() { # _need_arg <flag> <value>
  local flag="$1" val="${2:-}" ex=""
  if [[ -n "$val" && "$val" != --* ]]; then
    return 0
  fi
  case "$flag" in
    --mode) ex="--mode active-backup" ;;
    --members) ex="--members ens1f0,ens1f1" ;;
    --opt) ex="--opt miimon=100" ;;
    --del-opt) ex="--del-opt primary" ;;
    --mtu) ex="--mtu 9000" ;;
    --ip4) ex="--ip4 10.0.0.10/24 (or dhcp / none)" ;;
    --gw4) ex="--gw4 10.0.0.1" ;;
    --dns4) ex="--dns4 10.0.0.53,10.0.0.54" ;;
    --ip6) ex="--ip6 2001:db8::10/64 (or auto / dhcp / none)" ;;
    --gw6) ex="--gw6 2001:db8::1" ;;
    --dns6) ex="--dns6 2001:db8::53" ;;
    --vlan) ex="--vlan 120" ;;
    --miimon) ex="--miimon 100" ;;
    --primary) ex="--primary ens1f0" ;;
    --lacp-rate) ex="--lacp-rate fast" ;;
    --xmit-hash) ex="--xmit-hash layer3+4" ;;
    --arp-interval) ex="--arp-interval 1000" ;;
    --arp-targets) ex="--arp-targets 10.0.0.1" ;;
    --min-links) ex="--min-links 1" ;;
    --old) ex="--old ens1f0" ;;
    --new) ex="--new ens2f0" ;;
    --target) ex="--target 10.0.0.1" ;;
    --snapshot) ex="--snapshot $(date +%Y%m%d)-120000 (see: $BM_PROG snapshot list)" ;;
    --output) ex="--output /root/bond-support.tar.gz" ;;
    --rollback-window) ex="--rollback-window 300" ;;
    --export-json) ex="--export-json /var/lib/metrics/bonds.json" ;;
  esac
  bm::core::die "flag '$flag' needs a value" "$BM_EX_USAGE" "${ex:+for example: $ex}"
}

BM_CLI_CHANGE_FLAGS=(--mode --members --opt --del-opt --mtu --ip4 --gw4 --dns4 --ip6 --gw6
  --dns6 --vlan --miimon --primary --lacp-rate --xmit-hash --arp-interval --arp-targets
  --min-links --no-activate --copy-ip --copy-vlans --keep-vlans --old --new)

# What the operator probably meant by an unknown flag or a stray word.
bm::cli::_flag_hint() { # _flag_hint <token>
  local t="$1" m near n all=1
  if [[ "$t" != -* ]]; then
    m="$(bm::help::mode_alias "$t")"
    if [[ -n "$m" ]]; then
      printf "did you mean '--mode %s'?" "$m"
      return 0
    fi
    if bm::val::ipv4_cidr "$t"; then
      printf "did you mean '--ip4 %s'?" "$t"
      return 0
    fi
    bm::core::split_list "$t"
    for n in "${BM_LIST[@]}"; do
      bm::facts::nic_exists "$n" || all=0
    done
    if (( all && ${#BM_LIST[@]} > 0 )); then
      printf "did you mean '--members %s'?" "$t"
      return 0
    fi
    printf 'values go after the flag they belong to, e.g. --mode active-backup - see: %s help %s' \
      "$BM_PROG" "${BM_CUR_CMD:-}"
    return 0
  fi
  near="$(bm::core::closest "$t" "${BM_CLI_CHANGE_FLAGS[@]}")"
  if [[ -n "$near" ]]; then
    printf "did you mean '%s'? (all flags: %s help %s)" "$near" "$BM_PROG" "${BM_CUR_CMD:-}"
  else
    printf 'see the flags this command takes: %s help %s' "$BM_PROG" "${BM_CUR_CMD:-}"
  fi
}

# ---- read-only output commands --------------------------------------------

bm::cli::preflight_read() {
  bm::core::have_cmd nmcli || bm::core::die "nmcli not found; install NetworkManager" "$BM_EX_PRECONDITION" \
    "install it with: dnf install NetworkManager && systemctl enable --now NetworkManager"
}

# Can changes run at all right now? Never dies (the menus ask before every
# wizard). 0 = yes; 3 = no, with BM_CLI_BLOCKER=no-nmcli|not-root|nm-inactive
# and a plain explanation in BM_CLI_BLOCKER_MSG.
BM_CLI_BLOCKER=""
BM_CLI_BLOCKER_MSG=""
bm::cli::mutate_blocker() {
  BM_CLI_BLOCKER=""
  BM_CLI_BLOCKER_MSG=""
  if ! bm::core::have_cmd nmcli; then
    BM_CLI_BLOCKER=no-nmcli
    BM_CLI_BLOCKER_MSG="NetworkManager (nmcli) is not installed, so nothing can be changed."
    return "$BM_EX_PRECONDITION"
  fi
  if ! bm::core::is_root; then
    BM_CLI_BLOCKER=not-root
    BM_CLI_BLOCKER_MSG="You are not root, so changes are not possible. Start bond-manager with sudo to make real changes."
    return "$BM_EX_PRECONDITION"
  fi
  if bm::core::have_cmd systemctl && ! systemctl is-active --quiet NetworkManager; then
    BM_CLI_BLOCKER=nm-inactive
    BM_CLI_BLOCKER_MSG="NetworkManager is not running. Start it first: systemctl enable --now NetworkManager"
    return "$BM_EX_PRECONDITION"
  fi
  return 0
}

bm::cli::preflight_mutate() {
  bm::cli::preflight_read
  # a dry-run only renders the plan: no root, no NM, no module loading needed
  (( BM_DRY_RUN )) && return 0
  bm::core::require_root
  if bm::core::have_cmd systemctl && ! systemctl is-active --quiet NetworkManager; then
    bm::core::die "NetworkManager is not active (systemctl enable --now NetworkManager)" "$BM_EX_PRECONDITION" \
      "start it with: systemctl enable --now NetworkManager"
  fi
  if [[ ! -e "$BM_PROC_ROOT/net/bonding" ]] && bm::core::have_cmd modprobe; then
    modprobe bonding 2>/dev/null || bm::log::warn "could not load bonding module (NM may load it on demand)"
  fi
}

bm::cli::all_bonds() { # kernel bonds ∪ NM bond profiles
  {
    bm::facts::kernel_bonds
    bm::nm::bond_cons | awk -F'\x1f' '{ print ($3 != "" ? $3 : $2) }'
  } | LC_ALL=C sort -u | sed '/^$/d'
}

bm::cli::_bond_json() { # one bond as a JSON object
  local b="$1"
  local mode health verdict
  mode="$(bm::facts::bond_mode "$b")"
  health="$(bm::facts::bond_health "$b")"
  verdict="$(head -n1 <<<"$health")"
  local reasons_json
  reasons_json="$(tail -n +2 <<<"$health" | sed '/^$/d' | bm::json::arr_of_lines)"

  local members_json="" m mii spd dup lf
  while IFS= read -r m; do
    [[ -n "$m" ]] || continue
    mii="$(bm::facts::bond_member_mii "$b" "$m")"
    read -r spd dup <<<"$(bm::facts::bond_member_speed_duplex "$b" "$m")"
    lf="$(bm::facts::nic_link_failures "$b" "$m")"
    [[ -n "$members_json" ]] && members_json+=","
    members_json+="{\"name\":$(bm::json::str "$m"),\"mii\":$(bm::json::str "$mii"),\"speed\":$(bm::json::num_or_str "$spd"),\"duplex\":$(bm::json::str "$dup"),\"link_failures\":$(bm::json::num_or_str "$lf")}"
  done < <(bm::facts::bond_members "$b")

  local addrs_json vlans_json
  addrs_json="$(bm::facts::dev_addrs "$b" | bm::json::arr_of_lines)"
  vlans_json="$(bm::nm::vlan_cons "$b" | awk -F'\x1f' '{ print $3 }' | bm::json::arr_of_lines)"

  local active primary miimon
  active="$(bm::facts::bond_proc_value "$b" "Currently Active Slave")"
  primary="$(bm::facts::bond_proc_value "$b" "Primary Slave")"
  miimon="$(bm::facts::bond_proc_value "$b" "MII Polling Interval (ms)")"

  printf '{"name":%s,"mode":%s,"health":%s,"reasons":%s,"miimon":%s,"active_member":%s,"primary":%s,"members":[%s],"addresses":%s,"vlans":%s}' \
    "$(bm::json::str "$b")" "$(bm::json::str "$mode")" "$(bm::json::str "$verdict")" \
    "$reasons_json" "$(bm::json::num_or_str "${miimon:-unknown}")" \
    "$(bm::json::str "${active:-}")" "$(bm::json::str "${primary:-}")" \
    "$members_json" "$addrs_json" "$vlans_json"
}

bm::cli::_bonds_json_doc() { # full inventory document
  local bonds_json="" b
  while IFS= read -r b; do
    [[ -n "$b" ]] || continue
    [[ -n "$bonds_json" ]] && bonds_json+=","
    bonds_json+="$(bm::cli::_bond_json "$b")"
  done < <(bm::cli::all_bonds)
  printf '{"schema_version":%s,"generated":%s,"host":%s,"tool_version":%s,"bonds":[%s]}\n' \
    "$BM_JSON_SCHEMA_VERSION" "$(bm::json::str "$(bm::core::timestamp)")" \
    "$(bm::json::str "$(hostname 2>/dev/null || echo unknown)")" \
    "$(bm::json::str "$BM_VERSION")" "$bonds_json"
}

bm::cli::cmd_list() {
  bm::cli::preflight_read
  if (( BM_JSON )); then
    bm::cli::_bonds_json_doc
    return "$BM_EX_OK"
  fi
  local b any=0 mode verdict
  while IFS= read -r b; do
    [[ -n "$b" ]] || continue
    any=1
    mode="$(bm::facts::bond_mode "$b")"
    verdict="$(bm::facts::bond_health "$b" | head -n1)"
    printf '%-16s %-16s %s\n' "$b" "$mode" "$verdict"
  done < <(bm::cli::all_bonds)
  (( any )) || echo "No bonds found."
  return "$BM_EX_OK"
}

bm::cli::_show_human() {
  local b="$1"
  local health verdict
  health="$(bm::facts::bond_health "$b")"
  verdict="$(head -n1 <<<"$health")"
  echo "=== $b ==="
  printf 'mode:            %s\n' "$(bm::facts::bond_mode "$b")"
  case "$verdict" in
    healthy) printf 'health:          %s\n' "$(bm::core::c_ok healthy)" ;;
    degraded) printf 'health:          %s\n' "$(bm::core::c_warn degraded)" ;;
    *) printf 'health:          %s\n' "$(bm::core::c_err "$verdict")" ;;
  esac
  tail -n +2 <<<"$health" | sed '/^$/d; s/^/                   - /'
  local miimon active primary
  miimon="$(bm::facts::bond_proc_value "$b" "MII Polling Interval (ms)")"
  active="$(bm::facts::bond_proc_value "$b" "Currently Active Slave")"
  primary="$(bm::facts::bond_proc_value "$b" "Primary Slave")"
  [[ -n "$miimon" ]] && printf 'miimon:          %s ms\n' "$miimon"
  [[ -n "$active" ]] && printf 'active member:   %s\n' "$active"
  [[ -n "$primary" && "$primary" != None ]] && printf 'primary:         %s\n' "$primary"
  echo "members:"
  local m mii spd dup lf
  while IFS= read -r m; do
    [[ -n "$m" ]] || continue
    mii="$(bm::facts::bond_member_mii "$b" "$m")"
    read -r spd dup <<<"$(bm::facts::bond_member_speed_duplex "$b" "$m")"
    lf="$(bm::facts::nic_link_failures "$b" "$m")"
    printf '  %-14s mii=%-8s speed=%-10s duplex=%-6s link_failures=%s\n' \
      "$m" "$mii" "$spd" "$dup" "$lf"
  done < <(bm::facts::bond_members "$b")
  local addrs
  addrs="$(bm::facts::dev_addrs "$b")"
  if [[ -n "$addrs" ]]; then
    echo "addresses:"
    sed 's/^/  /' <<<"$addrs"
  fi
  local rec uuid name dev vid
  local vl=""
  while IFS= read -r rec; do
    IFS=$'\x1f' read -r uuid name dev vid <<<"$rec"
    vl+="  $dev (vlan $vid, profile '$name')"$'\n'
  done < <(bm::nm::vlan_cons "$b")
  if [[ -n "$vl" ]]; then
    echo "vlans:"
    printf '%s' "$vl"
  fi
}

bm::cli::cmd_show() {
  local bond="${1:-}"
  [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG show BOND" "$BM_EX_USAGE"
  bm::cli::preflight_read
  if (( BM_JSON )); then
    printf '{"schema_version":%s,"bond":%s}\n' "$BM_JSON_SCHEMA_VERSION" "$(bm::cli::_bond_json "$bond")"
    return "$BM_EX_OK"
  fi
  bm::cli::_show_human "$bond"
}

bm::cli::cmd_status() {
  local bond="${1:-}"
  bm::cli::preflight_read
  local -a bonds=()
  if [[ -n "$bond" ]]; then
    bonds=("$bond")
  else
    mapfile -t bonds < <(bm::cli::all_bonds)
  fi

  if (( BM_JSON )); then
    if [[ -n "$bond" ]]; then
      printf '{"schema_version":%s,"bonds":[%s]}\n' \
        "$BM_JSON_SCHEMA_VERSION" "$(bm::cli::_bond_json "$bond")"
    else
      bm::cli::_bonds_json_doc
    fi
  fi

  local worst=healthy b verdict
  for b in "${bonds[@]}"; do
    [[ -n "$b" ]] || continue
    verdict="$(bm::facts::bond_health "$b" | head -n1)"
    if ! (( BM_JSON )); then
      bm::cli::_show_human "$b"
      echo
    fi
    case "$verdict" in
      down) worst=down ;;
      degraded) [[ "$worst" == healthy ]] && worst=degraded ;;
    esac
  done
  if (( ${#bonds[@]} == 0 )) && ! (( BM_JSON )); then
    echo "No bonds found."
  fi
  case "$worst" in
    down) return "$BM_EX_DOWN" ;;
    degraded) return "$BM_EX_DEGRADED" ;;
    *) return "$BM_EX_OK" ;;
  esac
}

bm::cli::_doc_check() {
  local level="$1" msg="$2"
  case "$level" in
    ok) printf '[%s] %s\n' "$(bm::core::c_ok ' ok ')" "$msg" ;;
    warn) printf '[%s] %s\n' "$(bm::core::c_warn 'warn')" "$msg" ;;
    fail) printf '[%s] %s\n' "$(bm::core::c_err 'FAIL')" "$msg" ;;
  esac
}

bm::cli::cmd_doctor() {
  bm::log::set_op doctor
  local hard_fail=0
  echo "bond-manager doctor — environment preflight"
  echo

  if bm::core::have_cmd nmcli; then
    bm::cli::_doc_check ok "nmcli present ($(nmcli --version 2>/dev/null | head -n1))"
  else
    bm::cli::_doc_check fail "nmcli not found — install NetworkManager"
    hard_fail=1
  fi
  if bm::core::have_cmd systemctl; then
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
      bm::cli::_doc_check ok "NetworkManager service active"
    else
      bm::cli::_doc_check fail "NetworkManager service not active"
      hard_fail=1
    fi
  else
    bm::cli::_doc_check warn "systemctl not found — cannot verify NetworkManager state"
  fi
  if [[ -e "$BM_PROC_ROOT/net/bonding" ]]; then
    bm::cli::_doc_check ok "bonding kernel module loaded"
  elif bm::core::have_cmd modprobe && modprobe -n bonding >/dev/null 2>&1; then
    bm::cli::_doc_check ok "bonding kernel module available (will load on demand)"
  else
    bm::cli::_doc_check warn "bonding kernel module not detected"
  fi

  local tier
  tier="$(bm::ckpt::probe_tier)"
  case "$tier" in
    checkpoint)
      bm::cli::_doc_check ok "protection tier: checkpoint (NM D-Bus checkpoints with server-side auto-rollback)" ;;
    deadman)
      bm::cli::_doc_check warn "protection tier: deadman (no NM D-Bus checkpoint; transient systemd rollback timer)" ;;
    snapshot)
      bm::cli::_doc_check warn "protection tier: snapshot-only (no busctl, no systemd-run — rollback is manual)" ;;
  esac

  local t
  for t in ip tar ping awk sed; do
    if bm::core::have_cmd "$t"; then
      bm::cli::_doc_check ok "$t present"
    else
      bm::cli::_doc_check fail "required tool '$t' missing"
      hard_fail=1
    fi
  done
  for t in ethtool journalctl flock logger restorecon; do
    if bm::core::have_cmd "$t"; then
      bm::cli::_doc_check ok "$t present"
    else
      bm::cli::_doc_check warn "optional tool '$t' missing"
    fi
  done

  if bm::core::have_cmd getenforce; then
    bm::cli::_doc_check ok "SELinux: $(getenforce 2>/dev/null || echo unknown)"
  fi
  if [[ -f "$BM_CONF" ]]; then
    bm::cli::_doc_check ok "config present: $BM_CONF"
  else
    bm::cli::_doc_check warn "no config file (defaults in effect; run '$BM_PROG init' to install one)"
  fi
  if bm::ckpt::load_pending; then
    local secs_left=$(( ${BM_PENDING_DEADLINE:-0} - $(bm::core::epoch) ))
    bm::cli::_doc_check warn "PENDING CHANGE: ${BM_PENDING_SUMMARY:-?} (auto-rollback in ${secs_left}s) — run '$BM_PROG commit' or '$BM_PROG rollback'"
  fi

  echo
  if (( hard_fail )); then
    echo "verdict: $(bm::core::c_err 'not ready')"
    echo "  Next step: fix the FAIL lines above, then run '$BM_PROG doctor' again."
    return "$BM_EX_PRECONDITION"
  fi
  echo "verdict: $(bm::core::c_ok ready) (protection tier: $tier)"
  echo "  $(bm::help::tier_sentence "$tier")"
  echo "  Next step: '$BM_PROG list' to see your bonds, or 'sudo $BM_PROG' for guided menus."
  return "$BM_EX_OK"
}

bm::cli::cmd_config() {
  case "${1:-show}" in
    path) printf '%s\n' "$BM_CONF" ;;
    show)
      echo "# effective configuration (source: ${BM_CONF}$([[ -f "$BM_CONF" ]] || echo ' — missing, defaults in effect'))"
      local k
      while IFS= read -r k; do
        printf '%s="%s"\n' "$k" "${BM_CFG[$k]}"
      done < <(printf '%s\n' "${!BM_CFG[@]}" | LC_ALL=C sort)
      ;;
    *) bm::core::die "usage: $BM_PROG config show|path" "$BM_EX_USAGE" ;;
  esac
}

# ---- nics ---------------------------------------------------------------------

# Does <nic> carry this session's SSH traffic? True for the egress device
# itself, the port under a VLAN that is, and the members of a bond (or of a
# bond under a VLAN) that is.
bm::cli::_carries_ssh() { # _carries_ssh <nic> <master> <ssh-dev> <ssh-parent>
  local n="$1" master="$2" dev="$3" parent="$4"
  [[ -n "$dev" ]] || return 1
  [[ "$n" == "$dev" ]] && return 0
  [[ -n "$parent" && "$n" == "$parent" ]] && return 0 # eth2 under SSH on eth2.100
  [[ -n "$master" && ( "$master" == "$dev" || "$master" == "$parent" ) ]] && return 0
  return 1
}

# Print the collected nics rows (c_* arrays of the caller): columns as wide
# as their content, and on a terminal the NOTE column wraps under itself
# instead of spilling into the next line's NIC column.
bm::cli::_nics_table() {
  local -a heads=(NIC LINK SPEED IN-BOND ADDRESSES)
  local -a w=(${#heads[0]} ${#heads[1]} ${#heads[2]} ${#heads[3]} ${#heads[4]})
  local i
  for i in "${!c_nic[@]}"; do
    (( ${#c_nic[i]} > w[0] )) && w[0]=${#c_nic[i]}
    (( ${#c_link[i]} > w[1] )) && w[1]=${#c_link[i]}
    (( ${#c_speed[i]} > w[2] )) && w[2]=${#c_speed[i]}
    (( ${#c_bond[i]} > w[3] )) && w[3]=${#c_bond[i]}
    (( ${#c_addr[i]} > w[4] )) && w[4]=${#c_addr[i]}
  done
  local fmt="%-${w[0]}s  %-${w[1]}s  %-${w[2]}s  %-${w[3]}s  %-${w[4]}s  "
  local notecol=$(( w[0] + w[1] + w[2] + w[3] + w[4] + 10 )) room=0 cols
  if [[ -t 1 ]]; then
    cols="${COLUMNS:-}"
    if ! [[ "$cols" =~ ^[0-9]+$ ]]; then cols="$(tput cols 2>/dev/null || true)"; fi
    if [[ "$cols" =~ ^[0-9]+$ ]]; then room=$(( cols - 1 - notecol )); fi
    (( room >= 20 )) || room=0 # too narrow to be worth wrapping: let it spill
  fi
  # shellcheck disable=SC2059 # fmt is built from numbers only
  printf "$fmt%s\n" "${heads[@]}" NOTE
  local line pad
  printf -v pad '%*s' "$notecol" ''
  for i in "${!c_nic[@]}"; do
    # shellcheck disable=SC2059
    printf "$fmt" "${c_nic[i]}" "${c_link[i]}" "${c_speed[i]}" "${c_bond[i]}" "${c_addr[i]}"
    if (( room > 0 && ${#c_note[i]} > room )); then
      bm::ui::wrap "$room" "${c_note[i]}"
    else
      BM_UI_WRAPPED=("${c_note[i]}")
    fi
    local first=1
    for line in "${BM_UI_WRAPPED[@]}"; do
      (( first )) || printf '%s' "$pad"
      first=0
      case "${c_tone[i]}" in
        warn) bm::core::c_warn "$line" ;;
        ok) bm::core::c_ok "$line" ;;
        dim) bm::core::c_dim "$line" ;;
        *) printf '%s' "$line" ;;
      esac
      printf '\n'
    done
  done
}

bm::cli::cmd_nics() {
  local all=0
  while (( $# )); do
    case "$1" in
      --all) all=1; shift ;;
      *) bm::core::die "unknown flag '$1'" "$BM_EX_USAGE" "the only flag is --all" ;;
    esac
  done
  if (( BM_JSON )); then
    bm::core::die "nics has no JSON output yet" "$BM_EX_USAGE" "for bonds use: $BM_PROG --json list"
  fi
  local ssh_dev ssh_parent=""
  ssh_dev="$(bm::facts::ssh_egress_dev || true)"
  if [[ -n "$ssh_dev" ]]; then
    ssh_parent="$(bm::facts::vlan_parent "$ssh_dev")"
  fi

  local d n hidden=0 allowed
  local -a names=()
  for d in "$BM_SYS_ROOT"/class/net/*; do
    [[ -e "$d" ]] || continue
    n="${d##*/}"
    [[ "$n" == lo ]] && continue
    bm::facts::bond_exists_kernel "$n" && continue # a bond is not a port
    if ! bm::facts::nic_allowed "$n" && (( ! all )); then
      hidden=$(( hidden + 1 ))
      continue
    fi
    names+=("$n")
  done

  if (( ${#names[@]} == 0 )); then
    echo "No network ports found that bond-manager may use."
    if (( hidden > 0 )); then
      echo "($hidden hidden by the NIC policy - see them with: $BM_PROG nics --all)"
    fi
    return "$BM_EX_OK"
  fi

  local link speed inbond addrs first extra note tone active vpar
  local -a free_up=() addr_list=()
  local -a c_nic=() c_link=() c_speed=() c_bond=() c_addr=() c_note=() c_tone=()
  for n in "${names[@]}"; do
    bm::facts::nic_info "$n" || true
    case "$BM_NIC_LINK" in
      up) link=up ;;
      no-link) link="no link" ;;
      off) link=off ;;
      *) link="?" ;;
    esac
    speed="$(bm::help::speed_label "$BM_NIC_SPEED")"
    inbond="${BM_NIC_MASTER:--}"
    mapfile -t addr_list < <(bm::facts::dev_addrs "$n" | grep -v '^fe80:' || true)
    first="${addr_list[0]:-}"
    extra=""
    if (( ${#addr_list[@]} > 1 )); then extra=" +$(( ${#addr_list[@]} - 1 ))"; fi
    addrs="${first:--}$extra"
    allowed=1
    bm::facts::nic_allowed "$n" || allowed=0
    vpar="$(bm::facts::vlan_parent "$n")"
    tone=plain
    if (( ! allowed )); then
      note="hidden by the NIC policy"; tone=dim
    elif [[ -n "$vpar" ]]; then
      note="VLAN interface on $vpar"
      if [[ "$n" == "$ssh_dev" ]]; then note+=" - carries your SSH connection"; tone=warn; fi
    elif bm::cli::_carries_ssh "$n" "$BM_NIC_MASTER" "$ssh_dev" "$ssh_parent"; then
      tone=warn
      note="carries your SSH connection"
      if [[ -n "$BM_NIC_MASTER" ]]; then
        note="in $BM_NIC_MASTER - carries your SSH connection"
      elif [[ "$n" != "$ssh_dev" ]]; then
        note="carries your SSH connection (through $ssh_dev)"
      fi
    elif [[ -n "$BM_NIC_MASTER" ]]; then
      active="$(bm::facts::bond_proc_value "$BM_NIC_MASTER" "Currently Active Slave")"
      note="in $BM_NIC_MASTER"
      [[ "$active" == "$n" ]] && note+=" (active)"
    elif [[ -n "$first" ]]; then
      note="has an IP - probably in use"; tone=warn
    elif [[ "$BM_NIC_LINK" == up ]]; then
      note="free - good to use"; tone=ok
      free_up+=("$n")
    elif [[ "$BM_NIC_LINK" == no-link ]]; then
      note="free, but no link - cable or switch port?"; tone=warn
    elif [[ "$BM_NIC_LINK" == off ]]; then
      note="free, but switched off (ip link set $n up)"; tone=warn
    else
      note="free"
    fi
    c_nic+=("$n") c_link+=("$link") c_speed+=("$speed") c_bond+=("$inbond")
    c_addr+=("$addrs") c_note+=("$note") c_tone+=("$tone")
  done
  bm::cli::_nics_table
  echo
  if (( ${#free_up[@]} >= 2 )); then
    local b=0
    while bm::facts::bond_exists_kernel "bond$b" || bm::facts::nic_exists "bond$b"; do
      b=$(( b + 1 ))
    done
    echo "Tip: build a bond from two free ports (preview first, -n changes nothing):"
    echo "  $BM_PROG -n create bond$b --mode active-backup --members ${free_up[0]},${free_up[1]}"
  elif (( ${#free_up[@]} == 1 )); then
    echo "Tip: '${free_up[0]}' is free - add it to a bond, or move a bond onto it:"
    echo "  $BM_PROG help swap-member"
  fi
  if (( hidden > 0 )); then
    echo "($hidden more hidden by the NIC policy - see them with: $BM_PROG nics --all)"
  fi
  return "$BM_EX_OK"
}

# ---- help ---------------------------------------------------------------------

bm::cli::cmd_help() {
  local x="${1:-}"
  if [[ -z "$x" ]]; then
    bm::cli::usage
    return "$BM_EX_OK"
  fi
  if bm::help::is_command "$x"; then
    bm::help::command "$x"
    return "$BM_EX_OK"
  fi
  if bm::help::is_topic "$x"; then
    bm::help::topic "$x"
    return "$BM_EX_OK"
  fi
  local sug
  sug="$(bm::help::synonym "$x")"
  if [[ -z "$sug" ]]; then
    sug="$(bm::core::closest "$x" "${BM_HELP_COMMANDS[@]}" "${BM_HELP_TOPICS[@]}")"
  fi
  printf '%s: no help for "%s"\n' "$BM_PROG" "$x" >&2
  if [[ -n "$sug" ]]; then
    printf '  Did you mean: %s help %s\n' "$BM_PROG" "$sug" >&2
  fi
  printf '  Commands: %s\n' "${BM_HELP_COMMANDS[*]}" >&2
  printf '  Topics:   %s\n' "${BM_HELP_TOPICS[*]}" >&2
  return "$BM_EX_USAGE"
}

# ---- mutation command parsers ---------------------------------------------

# Parse shared create/modify flags into BM_SPEC. Consumes "$@" after the
# positional args have been shifted away.
bm::cli::_parse_change_flags() {
  local -a opt_pairs=()
  local -a vlan_tokens=()
  while (( $# )); do
    case "$1" in
      --mode) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[mode]="$2"; shift 2 ;;
      --members) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[members]="$2"; shift 2 ;;
      --opt) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("$2"); shift 2 ;;
      --del-opt) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[del_opts]="${BM_SPEC[del_opts]:-} $2"; shift 2 ;;
      --mtu) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[mtu]="$2"; shift 2 ;;
      --ip4) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[ip4]="$2"; shift 2 ;;
      --gw4) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[gw4]="$2"; shift 2 ;;
      --dns4) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[dns4]="$2"; shift 2 ;;
      --ip6) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[ip6]="$2"; shift 2 ;;
      --gw6) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[gw6]="$2"; shift 2 ;;
      --dns6) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[dns6]="$2"; shift 2 ;;
      --vlan) bm::cli::_need_arg "$1" "${2-}"; vlan_tokens+=("$2"); shift 2 ;;
      --miimon) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("miimon=$2"); shift 2 ;;
      --primary) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("primary=$2"); shift 2 ;;
      --lacp-rate) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("lacp_rate=$2"); shift 2 ;;
      --xmit-hash) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("xmit_hash_policy=$2"); shift 2 ;;
      --arp-interval) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("arp_interval=$2"); shift 2 ;;
      --arp-targets) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("arp_ip_target=$2"); shift 2 ;;
      --min-links) bm::cli::_need_arg "$1" "${2-}"; opt_pairs+=("min_links=$2"); shift 2 ;;
      --no-activate) BM_SPEC[activate]=0; shift ;;
      --copy-ip) BM_SPEC[copy_ip]=1; shift ;;
      --copy-vlans) BM_SPEC[copy_vlans]=1; shift ;;
      --keep-vlans) BM_SPEC[keep_vlans]=1; shift ;;
      --old) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[old]="$2"; shift 2 ;;
      --new) bm::cli::_need_arg "$1" "${2-}"; BM_SPEC[new]="$2"; shift 2 ;;
      *) bm::core::die "unknown flag '$1'" "$BM_EX_USAGE" "$(bm::cli::_flag_hint "$1")" ;;
    esac
  done
  if (( ${#opt_pairs[@]} > 0 )); then
    BM_SPEC[opts]="$(bm::core::join , "${opt_pairs[@]}")"
  fi
  if (( ${#vlan_tokens[@]} > 0 )); then
    BM_SPEC[vlans]="${vlan_tokens[*]}"
  fi
}

bm::cli::cmd_create() {
  local bond="${1:-}"
  [[ -n "$bond" && "$bond" != --* ]] || bm::core::die "usage: $BM_PROG create BOND --mode MODE --members IF1,IF2 [...]" "$BM_EX_USAGE"
  shift
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::cli::_parse_change_flags "$@"
  bm::wf::create
}

bm::cli::cmd_modify() {
  local bond="${1:-}"
  [[ -n "$bond" && "$bond" != --* ]] || bm::core::die "usage: $BM_PROG modify BOND [flags]" "$BM_EX_USAGE"
  shift
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::cli::_parse_change_flags "$@"
  bm::wf::modify
}

bm::cli::cmd_add_member() {
  local bond="${1:-}" members_csv="${2:-}"
  [[ -n "$bond" && -n "$members_csv" ]] || bm::core::die "usage: $BM_PROG add-member BOND IF[,IF...]" "$BM_EX_USAGE"
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[members]="$members_csv"
  bm::wf::add_members
}

bm::cli::cmd_remove_member() {
  local bond="${1:-}" members_csv="${2:-}"
  [[ -n "$bond" && -n "$members_csv" ]] || bm::core::die "usage: $BM_PROG remove-member BOND IF[,IF...]" "$BM_EX_USAGE"
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  BM_SPEC[members]="$members_csv"
  bm::wf::remove_members
}

bm::cli::cmd_swap_member() {
  local bond="${1:-}"
  [[ -n "$bond" && "$bond" != --* ]] || bm::core::die "usage: $BM_PROG swap-member BOND --old IF --new IF" "$BM_EX_USAGE"
  shift
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::cli::_parse_change_flags "$@"
  [[ -n "${BM_SPEC[old]:-}" && -n "${BM_SPEC[new]:-}" ]] || bm::core::die "swap-member requires --old and --new" "$BM_EX_USAGE"
  bm::wf::swap_member
}

bm::cli::cmd_remove() {
  local bond="${1:-}"
  [[ -n "$bond" && "$bond" != --* ]] || bm::core::die "usage: $BM_PROG remove BOND [--keep-vlans]" "$BM_EX_USAGE"
  shift
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::cli::_parse_change_flags "$@"
  bm::wf::remove
}

bm::cli::cmd_vlan() {
  local action="${1:-}" bond="${2:-}"
  case "$action" in
    list)
      [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG vlan list BOND" "$BM_EX_USAGE"
      bm::cli::preflight_read
      local rec uuid name dev vid
      while IFS= read -r rec; do
        IFS=$'\x1f' read -r uuid name dev vid <<<"$rec"
        printf '%-18s vlan=%-5s profile=%s\n' "$dev" "$vid" "$name"
      done < <(bm::nm::vlan_cons "$bond")
      ;;
    add)
      local tok="${3:-}"
      [[ -n "$bond" && -n "$tok" ]] || bm::core::die "usage: $BM_PROG vlan add BOND VID[:ip4=..;gw4=..]" "$BM_EX_USAGE"
      bm::cli::preflight_mutate
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlans]="$tok"
      bm::wf::vlan_add
      ;;
    modify)
      local vid="${3:-}"
      [[ -n "$bond" && -n "$vid" ]] || bm::core::die "usage: $BM_PROG vlan modify BOND VID [ip flags]" "$BM_EX_USAGE"
      shift 3
      bm::cli::preflight_mutate
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      bm::cli::_parse_change_flags "$@"
      bm::wf::vlan_modify "$vid"
      ;;
    remove)
      local vid2="${3:-}"
      [[ -n "$bond" && -n "$vid2" ]] || bm::core::die "usage: $BM_PROG vlan remove BOND VID" "$BM_EX_USAGE"
      bm::cli::preflight_mutate
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlan_id]="$vid2"
      bm::wf::vlan_remove
      ;;
    *) bm::core::die "usage: $BM_PROG vlan add|modify|remove|list BOND ..." "$BM_EX_USAGE" ;;
  esac
}

bm::cli::cmd_clone() {
  local src="${1:-}" dst="${2:-}"
  [[ -n "$src" && -n "$dst" && "$dst" != --* ]] || bm::core::die "usage: $BM_PROG clone SRC DST --members IF[,IF...] [--copy-ip] [--copy-vlans]" "$BM_EX_USAGE"
  shift 2
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[src]="$src"
  BM_SPEC[bond]="$dst"
  bm::cli::_parse_change_flags "$@"
  [[ -n "${BM_SPEC[members]:-}" ]] || bm::core::die "clone requires --members" "$BM_EX_USAGE"
  bm::wf::clone
}

bm::cli::cmd_repair() {
  local bond="${1:-}"
  [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG repair BOND" "$BM_EX_USAGE"
  bm::cli::preflight_mutate
  bm::wf::spec_reset
  BM_SPEC[bond]="$bond"
  bm::wf::repair
}

bm::cli::cmd_verify() {
  local bond="${1:-}"
  [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG verify BOND" "$BM_EX_USAGE"
  bm::cli::preflight_read
  bm::verify::reset
  local members_csv
  members_csv="$(bm::facts::bond_members "$bond" | paste -sd, -)"
  bm::verify::bond "$bond" "$(bm::facts::bond_mode "$bond")" "$members_csv" "$bond" ""
  bm::verify::render
  bm::verify::failed && return "$BM_EX_ERR"
  return "$BM_EX_OK"
}

bm::cli::cmd_diagnose() {
  local bond="" level=basic target=""
  while (( $# )); do
    case "$1" in
      --extended) level=extended; shift ;;
      --target) bm::cli::_need_arg "$1" "${2-}"; target="$2"; shift 2 ;;
      -*) bm::core::die "unknown flag '$1'" "$BM_EX_USAGE" ;;
      *) bond="$1"; shift ;;
    esac
  done
  [[ -n "$bond" ]] || bm::core::die "usage: $BM_PROG diagnose BOND [--extended] [--target IP]" "$BM_EX_USAGE"
  bm::cli::preflight_read
  bm::diag::run "$bond" "$level" "$target"
}

# ---- safety commands ------------------------------------------------------

bm::cli::cmd_commit() {
  if (( BM_DRY_RUN )); then
    if bm::ckpt::load_pending; then
      bm::log::say "[dry-run] would commit the pending change: ${BM_PENDING_SUMMARY:-?} (tier ${BM_PENDING_TIER:-?})"
    else
      bm::log::say "[dry-run] no pending change to commit"
    fi
    return "$BM_EX_OK"
  fi
  bm::core::require_root
  bm::log::enable_file
  bm::log::set_op commit
  bm::lock::acquire
  local rc=0
  bm::ckpt::commit || rc=$?
  case "$rc" in
    0)
      bm::log::say "$(bm::core::c_ok "pending change committed")"
      return "$BM_EX_OK"
      ;;
    "$BM_EX_CKPT_LOST")
      printf '%s: %s the checkpoint was already gone, so NetworkManager has most likely rolled this change back already.\nCheck the current state with: %s status\n' \
        "$BM_PROG" "$(bm::core::c_err ERROR:)" "$BM_PROG" >&2
      return "$BM_EX_VERIFY"
      ;;
    *) return "$BM_EX_PRECONDITION" ;;
  esac
}

bm::cli::cmd_rollback() {
  local snapshot="" deadman=0
  while (( $# )); do
    case "$1" in
      --snapshot) bm::cli::_need_arg "$1" "${2-}"; snapshot="$2"; shift 2 ;;
      --deadman) deadman=1; shift ;;
      *) bm::core::die "usage: $BM_PROG rollback [--snapshot ID]" "$BM_EX_USAGE" ;;
    esac
  done

  if (( BM_DRY_RUN )); then
    if [[ -z "$snapshot" ]] && bm::ckpt::load_pending; then
      bm::log::say "[dry-run] would roll back the pending change: ${BM_PENDING_SUMMARY:-?} (tier ${BM_PENDING_TIER:-?}, snapshot ${BM_PENDING_SNAPSHOT:-?})"
      return "$BM_EX_OK"
    fi
    [[ -n "$snapshot" ]] || snapshot="$(bm::snap::latest)"
    [[ -n "$snapshot" ]] || bm::core::die "no pending change and no snapshots found in $BM_BACKUP_DIR" "$BM_EX_PRECONDITION"
    bm::snap::exists "$snapshot" || bm::core::die "snapshot '$snapshot' not found" "$BM_EX_PRECONDITION"
    bm::log::say "[dry-run] would restore snapshot $snapshot:"
    bm::snap::diff "$snapshot" || true
    return "$BM_EX_OK"
  fi

  bm::core::require_root
  bm::log::enable_file
  bm::log::set_op rollback
  # The deadman timer runs this from systemd while the operator's session may
  # still hold the lock in the commit gate; that race is resolved by whoever
  # gets the lock first, so the deadman waits rather than acting concurrently.
  bm::lock::acquire
  (( deadman )) && bm::log::warn "DEADMAN rollback fired — the operator never confirmed the change"

  local had_pending=0
  bm::ckpt::load_pending && had_pending=1

  # A deadman firing after the operator already committed or rolled back must
  # do nothing: the pending state it was armed for is gone.
  if (( deadman )) && (( ! had_pending )); then
    bm::log::info "deadman: no pending change remains; nothing to roll back"
    return "$BM_EX_OK"
  fi

  if [[ -z "$snapshot" ]] && (( had_pending )); then
    if bm::ckpt::rollback_pending; then
      bm::log::say "$(bm::core::c_ok "pending change rolled back")"
      return "$BM_EX_OK"
    fi
    bm::core::die "rollback of pending change failed — inspect manually" "$BM_EX_ERR"
  fi

  [[ -n "$snapshot" ]] || snapshot="$(bm::snap::latest)"
  [[ -n "$snapshot" ]] || bm::core::die "no pending change and no snapshots found in $BM_BACKUP_DIR" "$BM_EX_PRECONDITION"
  bm::snap::exists "$snapshot" || bm::core::die "snapshot '$snapshot' not found" "$BM_EX_PRECONDITION"

  echo "Restoring snapshot: $snapshot"
  bm::snap::diff "$snapshot" || true
  echo
  if ! (( BM_ASSUME_YES )); then
    bm::ui::yesno "Restore snapshot $snapshot (see change summary above)?" || {
      bm::log::say "cancelled"
      return "$BM_EX_OK"
    }
  fi

  # Restoring an explicit snapshot while a change is pending would leave the
  # checkpoint or deadman timer armed against state it no longer describes:
  # disarm it first so nothing fires later on top of the restored profiles.
  if (( had_pending )); then
    bm::log::warn "disarming pending change protection before an explicit snapshot restore"
    bm::ckpt::commit >/dev/null 2>&1 || true
  fi

  bm::snap::restore "$snapshot"
  return "$BM_EX_OK"
}

bm::cli::cmd_snapshot() {
  local action="${1:-list}"
  shift || true
  case "$action" in
    create)
      if (( BM_DRY_RUN )); then
        bm::log::say "[dry-run] would create a snapshot of $BM_CONN_DIR"
        return "$BM_EX_OK"
      fi
      bm::core::require_root
      bm::log::enable_file
      bm::lock::acquire
      local id
      id="$(bm::snap::create manual)" || bm::core::die "snapshot creation failed" "$BM_EX_ERR"
      echo "snapshot created: $id"
      ;;
    list)
      local rows
      rows="$(bm::snap::list)"
      if [[ -z "$rows" ]]; then
        echo "No snapshots in $BM_BACKUP_DIR"
      else
        printf '%-22s %-28s %s\n' ID CREATED REASON
        printf '%s\n' "$rows" | awk -F'\t' '{ printf "%-22s %-28s %s\n", $1, $2, $3 }'
      fi
      ;;
    diff)
      local id="${1:-}"
      [[ -n "$id" ]] || bm::core::die "usage: $BM_PROG snapshot diff ID" "$BM_EX_USAGE"
      bm::snap::diff "$id"
      ;;
    restore)
      local want="${1:-}"
      if [[ -z "$want" ]]; then
        want="$(bm::snap::latest)"
        [[ -n "$want" ]] || bm::core::die "no snapshots found in $BM_BACKUP_DIR" "$BM_EX_PRECONDITION"
      fi
      bm::cli::cmd_rollback --snapshot "$want"
      ;;
    prune)
      if (( BM_DRY_RUN )); then
        bm::log::say "[dry-run] would prune snapshots beyond the newest $(bm::config::get MAX_BACKUPS)"
        return "$BM_EX_OK"
      fi
      bm::core::require_root
      bm::log::enable_file
      bm::lock::acquire
      bm::snap::prune
      echo "pruned to $(bm::config::get MAX_BACKUPS) newest snapshots"
      ;;
    *) bm::core::die "usage: $BM_PROG snapshot create|list|diff ID|restore [ID]|prune" "$BM_EX_USAGE" ;;
  esac
}

bm::cli::cmd_bundle() {
  local out="" redact=0
  while (( $# )); do
    case "$1" in
      --output) bm::cli::_need_arg "$1" "${2-}"; out="$2"; shift 2 ;;
      --redact) redact=1; shift ;;
      *) bm::core::die "usage: $BM_PROG bundle [--output PATH] [--redact]" "$BM_EX_USAGE" ;;
    esac
  done
  bm::core::require_root
  bm::log::enable_file
  bm::diag::bundle "$out" "$redact" || bm::core::die "support bundle creation failed" "$BM_EX_ERR"
  echo "support bundle: $BM_BUNDLE_PATH"
}

bm::cli::cmd_init() {
  bm::core::require_root
  bm::log::enable_file
  bm::config::install
  echo "initialized (config: $BM_CONF)"
}

# ---- completion -----------------------------------------------------------

bm::cli::cmd_completion() {
  [[ "${1:-bash}" == bash ]] || bm::core::die "only 'bash' completion is available" "$BM_EX_USAGE"
  cat <<'EOF'
# bash completion for bond-manager
_bond_manager() {
  local cur prev commands
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  commands="list show status diagnose doctor nics create modify add-member remove-member swap-member remove vlan clone repair verify snapshot commit rollback bundle init config completion help tui version"
  case "$prev" in
    show|status|diagnose|modify|add-member|remove-member|swap-member|remove|repair|verify|clone)
      COMPREPLY=( $(compgen -W "$(bond-manager list 2>/dev/null | awk '{print $1}')" -- "$cur") )
      return ;;
    --old|--new|--members|--primary)
      COMPREPLY=( $(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur") )
      return ;;
    help)
      COMPREPLY=( $(compgen -W "$commands basics modes lacp safety practice moving glossary keys exit-codes" -- "$cur") )
      return ;;
    --mode)
      COMPREPLY=( $(compgen -W "balance-rr active-backup balance-xor broadcast 802.3ad balance-tlb balance-alb" -- "$cur") )
      return ;;
    vlan)
      COMPREPLY=( $(compgen -W "add modify remove list" -- "$cur") )
      return ;;
    snapshot)
      COMPREPLY=( $(compgen -W "create list diff restore prune" -- "$cur") )
      return ;;
    config)
      COMPREPLY=( $(compgen -W "show path" -- "$cur") )
      return ;;
  esac
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "--dry-run --yes --json --debug --quiet --no-color --plain --rollback-window --no-checkpoint --force-unsafe --help --version" -- "$cur") )
    return
  fi
  COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
}
complete -F _bond_manager bond-manager
EOF
}
