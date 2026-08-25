# lib/90-cli.sh — argument parsing, dispatch, output commands and the TUI.
# shellcheck shell=bash
[[ -n "${BM_LIB_CLI:-}" ]] && return 0
BM_LIB_CLI=1

bm::cli::usage() {
  cat <<EOF
$BM_PROG v$BM_VERSION — safe NetworkManager bond management for RHEL-like systems

Usage: $BM_PROG [GLOBAL FLAGS] <command> [ARGS]
       $BM_PROG                      (interactive TUI when run on a terminal)

Global flags:
  -n, --dry-run             Render the plan; execute nothing, write nothing
  -y, --yes                 No prompts; auto-commit when verification passes
      --json                Machine-readable output (list/show/status)
      --debug               Mirror log records to stderr
      --quiet               Suppress progress messages
      --no-color            Disable colored output (NO_COLOR is also honored)
      --plain               Force plain prompts (skip whiptail)
      --rollback-window S   Auto-rollback window in seconds (default: config)
      --no-checkpoint       Skip NM checkpoints (fall back to deadman/snapshot)
      --force-unsafe        Allow touching your SSH egress device w/o checkpoint
  -V, --version             Print version
  -h, --help                This help

Read-only commands (no root, write nothing):
  list                      One line per bond: name, mode, health
  show BOND                 Full bond detail (--json supported)
  status [BOND]             Health summary; exit 0 healthy / 10 degraded / 11 down
  diagnose BOND [--extended] [--target IP]
  verify BOND               Re-run the verification checks against kernel state
  doctor                    Environment preflight + protection-tier report
  config show|path          Effective configuration / config file path
  completion bash           Emit bash completion script

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
EOF
}

# ---- read-only output commands --------------------------------------------

bm::cli::preflight_read() {
  bm::core::have_cmd nmcli || bm::core::die "nmcli not found; install NetworkManager" "$BM_EX_PRECONDITION"
}

bm::cli::preflight_mutate() {
  bm::cli::preflight_read
  # a dry-run only renders the plan: no root, no NM, no module loading needed
  (( BM_DRY_RUN )) && return 0
  bm::core::require_root
  if bm::core::have_cmd systemctl && ! systemctl is-active --quiet NetworkManager; then
    bm::core::die "NetworkManager is not active (systemctl enable --now NetworkManager)" "$BM_EX_PRECONDITION"
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
  for t in ethtool journalctl whiptail flock logger restorecon; do
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
    return "$BM_EX_PRECONDITION"
  fi
  echo "verdict: $(bm::core::c_ok ready) (protection tier: $tier)"
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

# ---- mutation command parsers ---------------------------------------------

# Parse shared create/modify flags into BM_SPEC. Consumes "$@" after the
# positional args have been shifted away.
bm::cli::_parse_change_flags() {
  local -a opt_pairs=()
  local -a vlan_tokens=()
  while (( $# )); do
    case "$1" in
      --mode) BM_SPEC[mode]="${2:?}"; shift 2 ;;
      --members) BM_SPEC[members]="${2:?}"; shift 2 ;;
      --opt) opt_pairs+=("${2:?}"); shift 2 ;;
      --del-opt) BM_SPEC[del_opts]="${BM_SPEC[del_opts]:-} ${2:?}"; shift 2 ;;
      --mtu) BM_SPEC[mtu]="${2:?}"; shift 2 ;;
      --ip4) BM_SPEC[ip4]="${2:?}"; shift 2 ;;
      --gw4) BM_SPEC[gw4]="${2:?}"; shift 2 ;;
      --dns4) BM_SPEC[dns4]="${2:?}"; shift 2 ;;
      --ip6) BM_SPEC[ip6]="${2:?}"; shift 2 ;;
      --gw6) BM_SPEC[gw6]="${2:?}"; shift 2 ;;
      --dns6) BM_SPEC[dns6]="${2:?}"; shift 2 ;;
      --vlan) vlan_tokens+=("${2:?}"); shift 2 ;;
      --miimon) opt_pairs+=("miimon=${2:?}"); shift 2 ;;
      --primary) opt_pairs+=("primary=${2:?}"); shift 2 ;;
      --lacp-rate) opt_pairs+=("lacp_rate=${2:?}"); shift 2 ;;
      --xmit-hash) opt_pairs+=("xmit_hash_policy=${2:?}"); shift 2 ;;
      --arp-interval) opt_pairs+=("arp_interval=${2:?}"); shift 2 ;;
      --arp-targets) opt_pairs+=("arp_ip_target=${2:?}"); shift 2 ;;
      --min-links) opt_pairs+=("min_links=${2:?}"); shift 2 ;;
      --no-activate) BM_SPEC[activate]=0; shift ;;
      --copy-ip) BM_SPEC[copy_ip]=1; shift ;;
      --copy-vlans) BM_SPEC[copy_vlans]=1; shift ;;
      --keep-vlans) BM_SPEC[keep_vlans]=1; shift ;;
      --old) BM_SPEC[old]="${2:?}"; shift 2 ;;
      --new) BM_SPEC[new]="${2:?}"; shift 2 ;;
      *) bm::core::die "unknown flag '$1'" "$BM_EX_USAGE" ;;
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
      --target) target="${2:?}"; shift 2 ;;
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
      --snapshot) snapshot="${2:?}"; shift 2 ;;
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
      --output) out="${2:?}"; shift 2 ;;
      --redact) redact=1; shift ;;
      *) bm::core::die "usage: $BM_PROG bundle [--output PATH] [--redact]" "$BM_EX_USAGE" ;;
    esac
  done
  bm::core::require_root
  bm::log::enable_file
  local path
  path="$(bm::diag::bundle "$out" "$redact")" || bm::core::die "support bundle creation failed" "$BM_EX_ERR"
  echo "support bundle: $path"
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
  commands="list show status diagnose doctor create modify add-member remove-member swap-member remove vlan clone repair verify snapshot commit rollback bundle init config completion help"
  case "$prev" in
    show|status|diagnose|modify|add-member|remove-member|swap-member|remove|repair|verify)
      COMPREPLY=( $(compgen -W "$(bond-manager list 2>/dev/null | awk '{print $1}')" -- "$cur") )
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

# ---- TUI ------------------------------------------------------------------

bm::cli::tui_create() {
  bm::wf::spec_reset
  local bond
  if ! bond="$(bm::ui::input "New bond name" "bond0")"; then return 0; fi
  BM_SPEC[bond]="$bond"

  local -a mode_items=()
  local m
  for m in "${BM_MODES[@]}"; do
    mode_items+=("$m" "${BM_MODE_HELP[$m]}")
  done
  local mode
  if ! mode="$(bm::ui::menu "Bond mode:" "${mode_items[@]}")"; then return 0; fi
  BM_SPEC[mode]="$mode"

  local members
  if ! members="$(bm::ui::pick_nics "Select member interfaces for $bond")"; then return 0; fi
  BM_SPEC[members]="${members// /,}"

  local ipmode
  if ! ipmode="$(bm::ui::menu "IPv4 configuration:" \
    dhcp "DHCP" static "Static address" none "No IPv4 on the bond")"; then return 0; fi
  case "$ipmode" in
    dhcp) BM_SPEC[ip4]=dhcp ;;
    none) BM_SPEC[ip4]=none ;;
    static)
      local addr gw dns
      if ! addr="$(bm::ui::input "IPv4 address/prefix (e.g. 10.0.0.10/24)")"; then return 0; fi
      if ! gw="$(bm::ui::input "IPv4 gateway (blank for none)")"; then return 0; fi
      if ! dns="$(bm::ui::input "DNS servers, comma-separated (blank for none)")"; then return 0; fi
      BM_SPEC[ip4]="$addr"
      [[ -n "$gw" ]] && BM_SPEC[gw4]="$gw"
      [[ -n "$dns" ]] && BM_SPEC[dns4]="$dns"
      ;;
  esac

  if bm::ui::yesno "Add a VLAN on top of $bond?"; then
    local vid
    if ! vid="$(bm::ui::input "VLAN ID (1-4094)")"; then return 0; fi
    local vtok="$vid"
    if bm::ui::yesno "Put the IP on the VLAN interface instead of the bond?"; then
      local vaddr vgw
      if ! vaddr="$(bm::ui::input "VLAN IPv4 address/prefix (or 'dhcp')")"; then return 0; fi
      if [[ "$vaddr" == dhcp ]]; then
        vtok+=":ip4=dhcp"
      else
        if ! vgw="$(bm::ui::input "VLAN IPv4 gateway (blank for none)")"; then return 0; fi
        vtok+=":ip4=$vaddr${vgw:+;gw4=$vgw}"
      fi
      BM_SPEC[ip4]=none
      unset "BM_SPEC[gw4]" "BM_SPEC[dns4]"
    fi
    BM_SPEC[vlans]="$vtok"
  fi

  bm::wf::print_cli_equivalent create
  local rc=0
  ( bm::wf::create ) || rc=$?
  bm::cli::_tui_show_rc "$rc"
}

# TUI workflows run in a subshell (see the '( bm::wf::... )' call sites) so a
# validation failure — which calls bm::core::die, i.e. exit — returns the
# operator to the menu instead of dropping them out of the program.
bm::cli::_tui_show_rc() {
  local rc="$1"
  case "$rc" in
    0) : ;;
    "$BM_EX_VERIFY") bm::ui::msg "The change FAILED verification and was rolled back." ;;
    *) bm::ui::msg "Operation ended with exit code $rc (see $BM_LOG_FILE)." ;;
  esac
}

bm::cli::tui_edit() {
  local bond
  if ! bond="$(bm::ui::pick_bond)"; then return 0; fi
  local action
  if ! action="$(bm::ui::menu "Edit '$bond':" \
    add "Add member interfaces" \
    remove "Remove member interfaces" \
    tune "Change mode / bond options" \
    vlan "Add a VLAN" \
    ip "Change IPv4/IPv6 on the bond" \
    back "Back")"; then return 0; fi
  local rc=0
  case "$action" in
    back) return 0 ;;
    add)
      local members
      if ! members="$(bm::ui::pick_nics "Interfaces to add to $bond")"; then return 0; fi
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[members]="${members// /,}"
      bm::wf::print_cli_equivalent add-member
      ( bm::wf::add_members ) || rc=$?
      ;;
    remove)
      local cur
      cur="$(bm::facts::bond_members "$bond" | paste -sd' ' -)"
      local rem
      if ! rem="$(bm::ui::input "Members to remove (current: ${cur:-none})")"; then return 0; fi
      [[ -n "$rem" ]] || return 0
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[members]="${rem// /,}"
      bm::wf::print_cli_equivalent remove-member
      ( bm::wf::remove_members ) || rc=$?
      ;;
    tune)
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      local newmode
      if ! newmode="$(bm::ui::input "New mode (blank to keep; one of: ${BM_MODES[*]})")"; then return 0; fi
      [[ -n "$newmode" ]] && BM_SPEC[mode]="$newmode"
      local opts
      if ! opts="$(bm::ui::input "Options to set, comma-separated key=value (blank for none)")"; then return 0; fi
      [[ -n "$opts" ]] && BM_SPEC[opts]="$opts"
      bm::wf::print_cli_equivalent modify
      ( bm::wf::modify ) || rc=$?
      ;;
    vlan)
      local vid
      if ! vid="$(bm::ui::input "VLAN ID to add on $bond")"; then return 0; fi
      [[ -n "$vid" ]] || return 0
      local vtok="$vid" vaddr vgw
      if bm::ui::yesno "Configure IPv4 on the new VLAN interface?"; then
        if ! vaddr="$(bm::ui::input "IPv4 address/prefix (or 'dhcp')")"; then return 0; fi
        if [[ "$vaddr" == dhcp ]]; then
          vtok+=":ip4=dhcp"
        elif [[ -n "$vaddr" ]]; then
          if ! vgw="$(bm::ui::input "IPv4 gateway (blank for none)")"; then return 0; fi
          vtok+=":ip4=$vaddr${vgw:+;gw4=$vgw}"
        fi
      fi
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      BM_SPEC[vlans]="$vtok"
      bm::log::say "CLI equivalent: $BM_PROG vlan add $bond '$vtok'"
      ( bm::wf::vlan_add ) || rc=$?
      ;;
    ip)
      bm::wf::spec_reset
      BM_SPEC[bond]="$bond"
      local ipmode
      if ! ipmode="$(bm::ui::menu "IPv4 configuration:" \
        dhcp "DHCP" static "Static address" none "Disable IPv4" keep "Leave IPv4 unchanged")"; then return 0; fi
      case "$ipmode" in
        dhcp) BM_SPEC[ip4]=dhcp ;;
        none) BM_SPEC[ip4]=none ;;
        static)
          local addr gw dns
          if ! addr="$(bm::ui::input "IPv4 address/prefix")"; then return 0; fi
          if ! gw="$(bm::ui::input "IPv4 gateway (blank for none)")"; then return 0; fi
          if ! dns="$(bm::ui::input "DNS servers (blank for none)")"; then return 0; fi
          BM_SPEC[ip4]="$addr"
          [[ -n "$gw" ]] && BM_SPEC[gw4]="$gw"
          [[ -n "$dns" ]] && BM_SPEC[dns4]="$dns"
          ;;
      esac
      bm::wf::print_cli_equivalent modify
      ( bm::wf::modify ) || rc=$?
      ;;
  esac
  bm::cli::_tui_show_rc "$rc"
}

bm::cli::tui_loop() {
  bm::ui::init
  while :; do
    local choice
    if ! choice="$(bm::ui::menu "Main menu — $(bm::ui::title)" \
      status "Status: all bonds (health, members, addresses)" \
      diagnose "Status: diagnose a bond" \
      extended "Status: extended diagnostics" \
      create "Change: create a new bond" \
      edit "Change: edit an existing bond" \
      delete "Change: remove a bond" \
      swap "Migration: swap a member NIC (add new, then remove old)" \
      clone "Migration: clone a bond to new NICs" \
      repair "Repair: rebuild member profiles from kernel state" \
      snapshots "Safety: snapshots (list / restore)" \
      pending "Safety: commit or roll back a pending change" \
      bundle "Support: create a support bundle" \
      doctor "About: environment doctor" \
      quit "Exit")"; then
      break
    fi
    local rc=0
    case "$choice" in
      status)
        local out
        out="$(bm::cli::cmd_status 2>&1 || true)"
        bm::ui::msg "${out:-No bonds found.}"
        ;;
      diagnose | extended)
        local bond target
        if bond="$(bm::ui::pick_bond)"; then
          if ! target="$(bm::ui::input "Ping target (blank = default gateway)")"; then target=""; fi
          local lvl=basic
          [[ "$choice" == extended ]] && lvl=extended
          bm::ui::msg "$(bm::diag::run "$bond" "$lvl" "$target" 2>&1 || true)"
        fi
        ;;
      create) bm::cli::tui_create ;;
      edit) bm::cli::tui_edit ;;
      delete)
        local bond
        if bond="$(bm::ui::pick_bond)"; then
          bm::wf::spec_reset
          BM_SPEC[bond]="$bond"
          bm::log::say "CLI equivalent: $BM_PROG remove $bond"
          ( bm::wf::remove ) || rc=$?
          bm::cli::_tui_show_rc "$rc"
        fi
        ;;
      swap)
        local bond old new
        if bond="$(bm::ui::pick_bond)"; then
          local cur
          cur="$(bm::facts::bond_members "$bond" | paste -sd' ' -)"
          if old="$(bm::ui::input "Member to replace (current: ${cur:-none})")" && [[ -n "$old" ]]; then
            if new="$(bm::ui::pick_nics "Replacement NIC for $old" "$old")" && [[ -n "$new" ]]; then
              new="${new%% *}"
              bm::wf::spec_reset
              BM_SPEC[bond]="$bond"
              BM_SPEC[old]="$old"
              BM_SPEC[new]="$new"
              bm::log::say "CLI equivalent: $BM_PROG swap-member $bond --old $old --new $new"
              ( bm::wf::swap_member ) || rc=$?
              bm::cli::_tui_show_rc "$rc"
            fi
          fi
        fi
        ;;
      clone)
        local src dst members
        if src="$(bm::ui::pick_bond)"; then
          if dst="$(bm::ui::input "New bond name" "bond1")" && [[ -n "$dst" ]]; then
            if members="$(bm::ui::pick_nics "Member interfaces for $dst")"; then
              bm::wf::spec_reset
              BM_SPEC[src]="$src"
              BM_SPEC[bond]="$dst"
              BM_SPEC[members]="${members// /,}"
              bm::ui::yesno "Copy IP configuration from $src?" && BM_SPEC[copy_ip]=1
              bm::ui::yesno "Clone VLANs from $src?" && BM_SPEC[copy_vlans]=1
              bm::log::say "CLI equivalent: $BM_PROG clone $src $dst --members ${BM_SPEC[members]}${BM_SPEC[copy_ip]:+ --copy-ip}${BM_SPEC[copy_vlans]:+ --copy-vlans}"
              ( bm::wf::clone ) || rc=$?
              bm::cli::_tui_show_rc "$rc"
            fi
          fi
        fi
        ;;
      repair)
        local bond
        if bond="$(bm::ui::pick_bond)"; then
          bm::wf::spec_reset
          BM_SPEC[bond]="$bond"
          bm::log::say "CLI equivalent: $BM_PROG repair $bond"
          ( bm::wf::repair ) || rc=$?
          bm::cli::_tui_show_rc "$rc"
        fi
        ;;
      snapshots)
        local out
        out="$(bm::cli::cmd_snapshot list 2>&1 || true)"
        bm::ui::msg "$out"
        if bm::ui::yesno "Restore a snapshot now?"; then
          local id
          if id="$(bm::ui::input "Snapshot ID (blank = most recent)")"; then
            if [[ -n "$id" ]]; then
              bm::cli::cmd_rollback --snapshot "$id" || rc=$?
            else
              bm::cli::cmd_rollback || rc=$?
            fi
            bm::cli::_tui_show_rc "$rc"
          fi
        fi
        ;;
      pending)
        if bm::ckpt::load_pending; then
          if bm::ui::yesno "Pending change: ${BM_PENDING_SUMMARY:-?}. Commit it? (No = roll back)"; then
            bm::cli::cmd_commit || rc=$?
          else
            bm::cli::cmd_rollback || rc=$?
          fi
          bm::cli::_tui_show_rc "$rc"
        else
          bm::ui::msg "No pending change."
        fi
        ;;
      bundle)
        local out
        if bm::ui::yesno "Redact IPs/MACs from the bundle (for off-site tickets)?"; then
          out="$(bm::cli::cmd_bundle --redact 2>&1 || true)"
        else
          out="$(bm::cli::cmd_bundle 2>&1 || true)"
        fi
        bm::ui::msg "$out"
        ;;
      doctor)
        bm::ui::msg "$(bm::cli::cmd_doctor 2>&1 || true)"
        ;;
      quit) break ;;
    esac
  done
}

# ---- main -----------------------------------------------------------------

bm::main() {
  bm::core::init_traps

  local -a args=()
  local legacy_export=""
  local legacy_status=0
  while (( $# )); do
    case "$1" in
      -n | --dry-run) BM_DRY_RUN=1; shift ;;
      -y | --yes) BM_ASSUME_YES=1; shift ;;
      --json) BM_JSON=1; shift ;;
      --debug) BM_DEBUG=1; shift ;;
      --quiet) BM_QUIET=1; shift ;;
      --no-color) BM_NO_COLOR=1; shift ;;
      --plain) BM_PLAIN=1; shift ;;
      --rollback-window) BM_ROLLBACK_WINDOW="${2:?}"; shift 2 ;;
      --no-checkpoint) BM_NO_CHECKPOINT=1; shift ;;
      --force-unsafe) BM_FORCE_UNSAFE=1; shift ;;
      -V | --version) printf '%s %s\n' "$BM_PROG" "$BM_VERSION"; return 0 ;;
      -h | --help) bm::cli::usage; return 0 ;;
      --status) legacy_status=1; shift ;;                       # v2.x compat
      --export-json) legacy_export="${2:?}"; shift 2 ;;          # v2.x compat
      --) shift; while (( $# )); do args+=("$1"); shift; done ;;
      *) args+=("$1"); shift ;;
    esac
  done

  bm::core::init_color
  bm::config::load
  # The deadman timer re-executes this program from systemd, so BM_SELF must
  # be the entrypoint that was actually invoked ($0) — not the module file
  # that happens to define bm::main, which is what BASH_SOURCE[0] resolves to
  # under the dev entrypoint (and is not executable).
  BM_SELF="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  if [[ ! -x "$BM_SELF" ]]; then
    BM_SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
  fi

  if [[ -n "$BM_ROLLBACK_WINDOW" ]] && ! bm::val::uint "$BM_ROLLBACK_WINDOW" 10 86400; then
    bm::core::die "--rollback-window must be 10..86400 seconds" "$BM_EX_USAGE"
  fi

  # legacy one-flag invocations
  if [[ -n "$legacy_export" ]]; then
    bm::cli::preflight_read
    mkdir -p "$(dirname "$legacy_export")"
    BM_JSON=1
    bm::cli::_bonds_json_doc >"$legacy_export"
    echo "JSON written to $legacy_export"
    if (( legacy_status )); then
      BM_JSON=0
      local lrc=0
      bm::cli::cmd_status || lrc=$?
      return "$lrc"
    fi
    return 0
  fi
  if (( legacy_status )); then
    args=(status)
  fi

  local cmd="${args[0]:-}"
  local -a rest=("${args[@]:1}")

  if [[ -z "$cmd" ]]; then
    if bm::core::is_tty; then
      bm::cli::preflight_read
      bm::cli::tui_loop
      return 0
    fi
    bm::cli::usage >&2
    return "$BM_EX_USAGE"
  fi

  local rc=0
  case "$cmd" in
    list) bm::cli::cmd_list "${rest[@]}" || rc=$? ;;
    show) bm::cli::cmd_show "${rest[@]}" || rc=$? ;;
    status) bm::cli::cmd_status "${rest[@]}" || rc=$? ;;
    diagnose) bm::cli::cmd_diagnose "${rest[@]}" || rc=$? ;;
    doctor) bm::cli::cmd_doctor "${rest[@]}" || rc=$? ;;
    create) bm::cli::cmd_create "${rest[@]}" || rc=$? ;;
    modify) bm::cli::cmd_modify "${rest[@]}" || rc=$? ;;
    add-member) bm::cli::cmd_add_member "${rest[@]}" || rc=$? ;;
    remove-member) bm::cli::cmd_remove_member "${rest[@]}" || rc=$? ;;
    swap-member) bm::cli::cmd_swap_member "${rest[@]}" || rc=$? ;;
    remove | delete) bm::cli::cmd_remove "${rest[@]}" || rc=$? ;;
    vlan) bm::cli::cmd_vlan "${rest[@]}" || rc=$? ;;
    clone) bm::cli::cmd_clone "${rest[@]}" || rc=$? ;;
    repair) bm::cli::cmd_repair "${rest[@]}" || rc=$? ;;
    verify) bm::cli::cmd_verify "${rest[@]}" || rc=$? ;;
    snapshot) bm::cli::cmd_snapshot "${rest[@]}" || rc=$? ;;
    commit) bm::cli::cmd_commit "${rest[@]}" || rc=$? ;;
    rollback) bm::cli::cmd_rollback "${rest[@]}" || rc=$? ;;
    bundle | support-bundle) bm::cli::cmd_bundle "${rest[@]}" || rc=$? ;;
    init) bm::cli::cmd_init "${rest[@]}" || rc=$? ;;
    config) bm::cli::cmd_config "${rest[@]}" || rc=$? ;;
    completion) bm::cli::cmd_completion "${rest[@]}" || rc=$? ;;
    tui) bm::cli::preflight_read; bm::cli::tui_loop || rc=$? ;;
    help) bm::cli::usage ;;
    version) printf '%s %s\n' "$BM_PROG" "$BM_VERSION" ;;
    *)
      printf '%s: unknown command "%s"\n\n' "$BM_PROG" "$cmd" >&2
      bm::cli::usage >&2
      rc="$BM_EX_USAGE"
      ;;
  esac
  return "$rc"
}
