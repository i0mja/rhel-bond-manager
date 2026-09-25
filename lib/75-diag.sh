# lib/75-diag.sh — diagnostics and support bundles.
# One parameterized diagnose (basic/extended) instead of two copy-pasted
# workflows; bundles get a file manifest and an optional --redact pass that
# masks IPs and MACs for tickets leaving the site.
# shellcheck shell=bash
[[ -n "${BM_LIB_DIAG:-}" ]] && return 0
BM_LIB_DIAG=1

bm::diag::run() { # run <bond> <basic|extended> [ping-target]
  local bond="$1" level="${2:-basic}" target="${3:-}"

  echo "=== $bond: kernel bonding state ==="
  if [[ -r "$BM_PROC_ROOT/net/bonding/$bond" ]]; then
    cat "$BM_PROC_ROOT/net/bonding/$bond"
  else
    echo "(no $BM_PROC_ROOT/net/bonding/$bond — bond not present in kernel)"
  fi
  echo

  echo "=== Health assessment ==="
  local health verdict
  health="$(bm::facts::bond_health "$bond")"
  verdict="$(head -n1 <<<"$health")"
  case "$verdict" in
    healthy) echo "verdict: $(bm::core::c_ok healthy)" ;;
    degraded) echo "verdict: $(bm::core::c_warn degraded)" ;;
    *) echo "verdict: $(bm::core::c_err "$verdict")" ;;
  esac
  tail -n +2 <<<"$health" | sed '/^$/d; s/^/  - /'
  echo

  echo "=== Link state ==="
  ip -br link show 2>/dev/null | awk -v b="$bond" '$1 == b || index($1, b ".") == 1 { print }'
  local -a members=()
  mapfile -t members < <(bm::facts::bond_members "$bond")
  local m
  for m in "${members[@]}"; do
    ip -br link show dev "$m" 2>/dev/null || true
  done
  echo

  echo "=== Member detail ==="
  local mii spd dup lf agg
  for m in "${members[@]}"; do
    mii="$(bm::facts::bond_member_mii "$bond" "$m")"
    read -r spd dup <<<"$(bm::facts::bond_member_speed_duplex "$bond" "$m")"
    lf="$(bm::facts::nic_link_failures "$bond" "$m")"
    printf '  %-14s mii=%-8s speed=%-8s duplex=%-6s link_failures=%s' \
      "$m" "$mii" "$spd" "$dup" "$lf"
    if [[ "$(bm::facts::bond_mode "$bond")" == "802.3ad" ]]; then
      agg="$(bm::facts::bond_member_agg_id "$bond" "$m")"
      printf ' agg_id=%s' "$agg"
    fi
    printf '\n'
  done
  echo

  if [[ "$(bm::facts::bond_mode "$bond")" == "802.3ad" ]]; then
    echo "=== LACP (802.3ad) ==="
    bm::facts::bond_lacp_info "$bond" | sed 's/^/  /'
    local partner
    partner="$(bm::facts::bond_lacp_info "$bond" | awk '$1=="partner_mac"{print $2}')"
    if [[ -z "$partner" || "$partner" == "00:00:00:00:00:00" ]]; then
      echo "  $(bm::core::c_warn 'WARNING: no LACP partner — is the switch side configured as an LACP bundle?')"
    fi
    echo
  fi

  echo "=== Addresses ==="
  ip -br addr show 2>/dev/null | awk -v b="$bond" '$1 == b || index($1, b ".") == 1 { print }'
  echo

  # Reachability through the bond (or its VLANs) — enslaved members carry no
  # IP, so per-member ping is not a meaningful test.
  if [[ -z "$target" ]]; then
    read -r target _ <<<"$(bm::facts::default_gw4)"
  fi
  if [[ -n "$target" ]]; then
    echo "=== Reachability ($target) ==="
    local dev
    for dev in "$bond" $(bm::nm::vlan_cons "$bond" | awk -F'\x1f' '{ print $3 }'); do
      [[ -n "$dev" ]] || continue
      if [[ -n "$(bm::facts::dev_addrs "$dev")" ]]; then
        if ping -c 2 -W 2 -I "$dev" "$target" >/dev/null 2>&1; then
          echo "  via $dev: $(bm::core::c_ok reachable)"
        else
          echo "  via $dev: $(bm::core::c_err 'no reply')"
        fi
      fi
    done
    echo
  fi

  if [[ "$level" == extended ]]; then
    echo "=== NetworkManager profiles ==="
    local rec uuid name dev
    while IFS= read -r rec; do
      IFS=$'\x1f' read -r uuid name dev <<<"$rec"
      printf '  bond profile: %s (uuid %s, ifname %s)\n' "$name" "$uuid" "$dev"
    done < <(bm::nm::bond_cons | awk -F'\x1f' -v b="$bond" '$3 == b || $2 == b { print }')
    while IFS= read -r rec; do
      IFS=$'\x1f' read -r uuid name dev <<<"$rec"
      printf '  port profile: %s (uuid %s, ifname %s)\n' "$name" "$uuid" "$dev"
    done < <(bm::nm::port_cons "$bond")
    while IFS= read -r rec; do
      IFS=$'\x1f' read -r uuid name dev vid <<<"$rec" || true
      printf '  vlan profile: %s (uuid %s, ifname %s, vlan %s)\n' "$name" "$uuid" "$dev" "${vid:-?}"
    done < <(bm::nm::vlan_cons "$bond")
    echo

    if bm::core::have_cmd ethtool; then
      echo "=== ethtool driver info ==="
      for m in "${members[@]}"; do
        echo "--- $m ---"
        ethtool -i "$m" 2>&1 || true
      done
      echo
    fi

    if bm::core::have_cmd journalctl; then
      echo "=== Recent NetworkManager log ==="
      journalctl -u NetworkManager -n 100 --no-pager 2>&1 || true
      echo
    fi
  fi
}

# ---- support bundle -------------------------------------------------------

bm::diag::_redact() { # mask IPv4 addresses and MACs on stdin
  sed -E \
    -e 's/([0-9]{1,3}\.){3}[0-9]{1,3}/IP-REDACTED/g' \
    -e 's/([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/MAC-REDACTED/g'
}

# Collect a support bundle. The archive path is returned in BM_BUNDLE_PATH
# (not on stdout): running this inside $(...) would leak the scratch
# directory, see bm::core::ensure_tmpdir.
BM_BUNDLE_PATH=""
bm::diag::bundle() { # bundle [output-path] [redact:0|1] -> BM_BUNDLE_PATH
  local out="${1:-}" redact="${2:-0}"
  BM_BUNDLE_PATH=""
  bm::core::require_root
  mkdir -p "$BM_SUPPORT_DIR"
  local ts dir archive
  ts="$(date +'%Y%m%d-%H%M%S')"
  if ! bm::core::ensure_tmpdir; then
    bm::log::error "could not create a temporary directory in ${TMPDIR:-/tmp}"
    return 1
  fi
  dir="${BM_TMPDIR:?}/bundle-$ts"
  mkdir -p "$dir"
  [[ -n "$out" ]] || out="$BM_SUPPORT_DIR/support_$ts.tar.gz"

  local filter=cat
  [[ "$redact" == 1 ]] && filter=bm::diag::_redact

  { nmcli -f NAME,UUID,TYPE,DEVICE connection show 2>&1 || true; } | "$filter" >"$dir/nm_connections.txt"
  { nmcli device status 2>&1 || true; } | "$filter" >"$dir/nm_dev_status.txt"
  { ip -d -s link show 2>&1 || true; } | "$filter" >"$dir/ip_link.txt"
  { ip addr show 2>&1 || true; } | "$filter" >"$dir/ip_addr.txt"
  { ip route show 2>&1 || true; } | "$filter" >"$dir/ip_route.txt"
  if bm::core::have_cmd journalctl; then
    { journalctl -u NetworkManager -n 1000 --no-pager 2>&1 || true; } | "$filter" >"$dir/nm_journal.txt"
  fi
  { lsmod 2>/dev/null | grep -i bond || true; } >"$dir/modules.txt"

  local b
  for b in "$BM_PROC_ROOT"/net/bonding/*; do
    [[ -r "$b" ]] || continue
    "$filter" <"$b" >"$dir/proc_$(basename "$b").txt"
    bm::diag::run "$(basename "$b")" basic 2>&1 | "$filter" >"$dir/diagnose_$(basename "$b").txt" || true
  done

  [[ -f "$BM_LOG_FILE" ]] && { "$filter" <"$BM_LOG_FILE" >"$dir/bond_manager.log"; }
  [[ -f "$BM_CONF" ]] && cp "$BM_CONF" "$dir/bond_manager.conf"

  {
    printf 'bundle created: %s\n' "$(bm::core::timestamp)"
    printf 'tool version: %s\n' "$BM_VERSION"
    printf 'redacted: %s\n' "$redact"
    printf 'host: %s\n' "$( { [[ "$redact" == 1 ]] && echo REDACTED; } || hostname 2>/dev/null || echo unknown)"
    printf '\nfiles:\n'
    (cd "$dir" && find . -type f -printf '  %P (%s bytes)\n' | LC_ALL=C sort)
  } >"$dir/MANIFEST.txt"

  if ! tar -C "$(dirname "$dir")" -czf "$out" "$(basename "$dir")"; then
    rm -rf "$dir"
    bm::log::error "support bundle archive creation failed ($out)"
    return 1
  fi
  chmod 0640 "$out" 2>/dev/null || true
  rm -rf "$dir"
  bm::log::info "support bundle created at $out (redacted=$redact)"
  BM_BUNDLE_PATH="$out"
}
