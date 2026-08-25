# tests/helpers.bash — shared setup for the bond-manager test suite.
#
# Every test runs inside a throwaway sandbox under $BATS_TEST_TMPDIR:
#   - fixture /proc and /sys trees (BM_PROC_ROOT / BM_SYS_ROOT)
#   - private conn/backup/run/log/support roots (BM_CONN_DIR, BM_BACKUP_DIR, ...)
#   - tests/stubs prepended to PATH so nmcli/ip/systemctl/... are PATH-shims
#   - $BM_TEST_CALLS collects one line per stub invocation ("<cmd> <argv...>")
#
# Unit tests source the dist artifact (source-able: defines bm:: functions,
# never runs main) via load_artifact; integration tests execute it via run_cli.

bats_require_minimum_version 1.5.0

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BM_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
FIXTURES="$TESTS_DIR/fixtures"
BM_ARTIFACT="$BM_ROOT/bond_manager.sh"

# ---- sandbox ---------------------------------------------------------------

setup_sandbox() {
  BM_TEST_SANDBOX="$BATS_TEST_TMPDIR/sandbox"
  export BM_TEST_SANDBOX
  export BM_PROC_ROOT="$BM_TEST_SANDBOX/proc"
  export BM_SYS_ROOT="$BM_TEST_SANDBOX/sys"
  export BM_CONN_DIR="$BM_TEST_SANDBOX/conn"
  # Must be sandboxed: the default points at the real ifcfg store, which the
  # snapshot code reads and (on restore) writes.
  export BM_IFCFG_DIR="$BM_TEST_SANDBOX/ifcfg"
  export BM_CONF="$BM_TEST_SANDBOX/bond_manager.conf"       # absent by default
  export BM_LOG_FILE="$BM_TEST_SANDBOX/log/bond_manager.log"
  export BM_BACKUP_DIR="$BM_TEST_SANDBOX/backups"
  export BM_SUPPORT_DIR="$BM_TEST_SANDBOX/support"
  export BM_RUN_DIR="$BM_TEST_SANDBOX/run"
  export BM_LOGROTATE_CONF="$BM_TEST_SANDBOX/logrotate.conf"
  export BM_TEST_CALLS="$BM_TEST_SANDBOX/calls.log"
  export BM_STUB_NM_DIR="$BM_TEST_SANDBOX/nm"    # nmcli stub connection db
  export BM_STUB_IP_DIR="$BM_TEST_SANDBOX/ip"    # ip stub canned outputs

  # test-only generator used by nmcli hooks to model kernel reactions
  export BM_TEST_MKPROC="$TESTS_DIR/tools/mk-proc-bond"

  mkdir -p "$BM_PROC_ROOT/net/bonding" "$BM_SYS_ROOT/class/net" \
    "$BM_CONN_DIR" "$BM_IFCFG_DIR" "$BM_BACKUP_DIR" "$BM_RUN_DIR" "$BM_SUPPORT_DIR" \
    "$BM_STUB_NM_DIR" "$BM_STUB_IP_DIR"
  : >"$BM_TEST_CALLS"

  export PATH="$TESTS_DIR/stubs:$PATH"
  export NO_COLOR=1
  unset SSH_CONNECTION SSH_CLIENT || true
}

# ---- loading the artifact for unit tests -----------------------------------

# The dist artifact begins with `set -Eeuo pipefail`; save and restore the
# bats shell options around the source so bats' own error handling is intact.
load_artifact() {
  local _opts
  _opts="$(set +o)"
  # shellcheck disable=SC1090
  source "$BM_ARTIFACT"
  eval "$_opts" 2>/dev/null || true
}

# ---- running the CLI for integration tests ---------------------------------

run_cli() { # run_cli [args...] — sets $status/$output (stdout+stderr merged)
  run "$BM_ARTIFACT" "$@"
}

run_cli_stdout() { # like run_cli, but $output is stdout only (for JSON checks)
  run --separate-stderr "$BM_ARTIFACT" "$@"
}

# ---- fixture installers ----------------------------------------------------

install_proc_bond() { # install_proc_bond <fixture-name> <bond>
  cp "$FIXTURES/$1" "$BM_PROC_ROOT/net/bonding/$2"
}

install_sysfs_skeleton() { # canonical bond0 + eth0/eth1 skeleton
  cp -r "$FIXTURES/sysfs/." "$BM_SYS_ROOT/"
}

mk_sys_nic() { # mk_sys_nic <name> [operstate] [speed] [mac]
  local n="$1" state="${2:-up}" speed="${3:-1000}" mac="${4:-52:54:00:00:00:aa}"
  local d="$BM_SYS_ROOT/class/net/$n"
  mkdir -p "$d/device"
  printf '%s\n' "$state" >"$d/operstate"
  printf '%s\n' "$speed" >"$d/speed"
  printf '%s\n' "$mac" >"$d/address"
  printf '1500\n' >"$d/mtu"
}

mk_sys_bond() { # mk_sys_bond <name> [operstate] — virtual dev, no device/ dir
  local n="$1" state="${2:-up}"
  local d="$BM_SYS_ROOT/class/net/$n"
  mkdir -p "$d"
  printf '%s\n' "$state" >"$d/operstate"
  printf '1500\n' >"$d/mtu"
  printf '52:54:00:00:00:b0\n' >"$d/address"
}

enslave_sys_nic() { # enslave_sys_nic <nic> <bond> — create the master symlink
  ln -sfn "../$2" "$BM_SYS_ROOT/class/net/$1/master"
}

# Standard scenarios used by several files.
scenario_bond0_healthy() { # active-backup bond0 (eth0,eth1), all up
  install_sysfs_skeleton
  install_proc_bond proc_bonding_active_backup_healthy bond0
}

scenario_bond0_degraded() { # active-backup bond0, eth1 MII down
  install_sysfs_skeleton
  install_proc_bond proc_bonding_active_backup_degraded bond0
}

scenario_bond0_down() { # healthy members but bond operstate down
  install_sysfs_skeleton
  install_proc_bond proc_bonding_active_backup_healthy bond0
  printf 'down\n' >"$BM_SYS_ROOT/class/net/bond0/operstate"
}

scenario_bond1_8023ad() { # 802.3ad bond1 (ens1f0,ens1f1), LACP partner present
  mk_sys_bond bond1 up
  mk_sys_nic ens1f0 up 10000 52:54:00:12:35:10
  mk_sys_nic ens1f1 up 10000 52:54:00:12:35:11
  enslave_sys_nic ens1f0 bond1
  enslave_sys_nic ens1f1 bond1
  install_proc_bond proc_bonding_8023ad_healthy bond1
}

scenario_bond1_8023ad_no_partner() { # 802.3ad bond1, zero partner MAC
  mk_sys_bond bond1 up
  mk_sys_nic ens1f0 up 10000 52:54:00:12:35:10
  mk_sys_nic ens1f1 up 10000 52:54:00:12:35:11
  enslave_sys_nic ens1f0 bond1
  enslave_sys_nic ens1f1 bond1
  install_proc_bond proc_bonding_8023ad_no_partner bond1
}

# ---- stub data helpers -----------------------------------------------------

stub_nm_conn() { # stub_nm_conn <uuid> <key=value>...
  local uuid="$1"
  shift
  local f="$BM_STUB_NM_DIR/$uuid.conn"
  {
    printf 'connection.uuid=%s\n' "$uuid"
    local kv
    for kv in "$@"; do printf '%s\n' "$kv"; done
  } >"$f"
}

stub_nm_bond0_profile() { # canonical bond0 NM profile + port profiles
  stub_nm_conn 11111111-1111-1111-1111-111111111111 \
    connection.id=bond0 connection.type=bond connection.interface-name=bond0 \
    "bond.options=mode=active-backup,miimon=100"
  stub_nm_conn 22222222-2222-2222-2222-222222222222 \
    connection.id=bond-port-eth0 connection.type=802-3-ethernet \
    connection.interface-name=eth0 \
    connection.master=11111111-1111-1111-1111-111111111111 \
    connection.slave-type=bond
  stub_nm_conn 33333333-3333-3333-3333-333333333333 \
    connection.id=bond-port-eth1 connection.type=802-3-ethernet \
    connection.interface-name=eth1 \
    connection.master=11111111-1111-1111-1111-111111111111 \
    connection.slave-type=bond
}

stub_ip_file() { # stub_ip_file <name> <line>... — canned `ip` output
  local name="$1"
  shift
  printf '%s\n' "$@" >"$BM_STUB_IP_DIR/$name"
}

# Pretend this session arrived over SSH from <peer>, routed out of <dev>.
stub_ssh_session() { # stub_ssh_session <peer-ip> <egress-dev>
  export SSH_CONNECTION="$1 54321 10.0.0.5 22"
  stub_ip_file route_get "$1 via 10.0.0.1 dev $2 src 10.0.0.5 uid 0" "    cache"
}

# Install an executable that the nmcli stub runs after every mutating verb,
# standing in for what NetworkManager/the kernel do in response. The script
# body is read from stdin and receives the nmcli argv.
install_nmcli_hook() { # install_nmcli_hook <<'EOF' ... EOF
  local hook="$BM_TEST_SANDBOX/nmcli-hook"
  {
    printf '#!/usr/bin/env bash\nset -u\n'
    cat
  } >"$hook"
  chmod +x "$hook"
  export BM_STUB_NMCLI_HOOK="$hook"
}

# Write a generated active-backup /proc/net/bonding file (any member list).
write_proc_bond() { # write_proc_bond <bond> <active-slave> <member>...
  local bond="$1"
  shift
  "$BM_TEST_MKPROC" "$BM_PROC_ROOT/net/bonding/$bond" "$@"
}

# Write one config key into the (otherwise absent) sandbox config file.
set_conf() { # set_conf <KEY> <VALUE>
  printf '%s="%s"\n' "$1" "$2" >>"$BM_CONF"
}

# Seed a pending-change state file as a previous, disconnected session would
# have left it — what `commit` / `rollback` / the deadman timer act on.
seed_pending() { # seed_pending [tier] [snapshot-id] [summary]
  local tier="${1:-checkpoint}" snap="${2:-}" summary="${3:-seeded test change}"
  local path="" unit=""
  case "$tier" in
    checkpoint) path="/org/freedesktop/NetworkManager/Checkpoint/1" ;;
    deadman) unit="bond-manager-deadman-4242-1700000000" ;;
  esac
  mkdir -p "$BM_RUN_DIR"
  {
    printf 'tier=%s\n' "$tier"
    printf 'checkpoint_path=%s\n' "$path"
    printf 'deadman_unit=%s\n' "$unit"
    printf 'snapshot=%s\n' "$snap"
    printf 'deadline=%s\n' "$(( $(date +%s) + 120 ))"
    printf 'created=%s\n' "$(date +'%Y-%m-%dT%H:%M:%S%z')"
    printf 'pid=4242\n'
    printf 'summary=%s\n' "$summary"
  } >"$BM_RUN_DIR/pending.state"
}

# Sorted "path size" inventory of the given trees — compare before/after to
# prove a dry run wrote nothing at all.
tree_state() { # tree_state <dir>...
  local d
  for d in "$@"; do
    [[ -e "$d" ]] || continue
    find "$d" -printf '%y %s %p\n' 2>/dev/null
  done | LC_ALL=C sort
}

# ---- assertions ------------------------------------------------------------

assert_contains() { # assert_contains <haystack> <needle>
  if [[ "$1" != *"$2"* ]]; then
    printf 'expected to find: %s\n--- in ---\n%s\n' "$2" "$1" >&2
    return 1
  fi
}

assert_not_contains() {
  if [[ "$1" == *"$2"* ]]; then
    printf 'expected NOT to find: %s\n--- in ---\n%s\n' "$2" "$1" >&2
    return 1
  fi
}

assert_valid_json() { # assert_valid_json <string>
  printf '%s\n' "$1" | python3 -m json.tool >/dev/null
}

# ---- external-call assertions ($BM_TEST_CALLS) -----------------------------

_dump_calls() { printf -- '--- calls ---\n%s\n' "$(cat "$BM_TEST_CALLS")" >&2; }

call_index() { # call_index <ere> -> 1-based line number of the FIRST match
  grep -n -m1 -E -- "$1" "$BM_TEST_CALLS" 2>/dev/null | cut -d: -f1
}

assert_called() { # assert_called <ere>
  if ! grep -qE -- "$1" "$BM_TEST_CALLS"; then
    printf 'expected an external call matching: %s\n' "$1" >&2
    _dump_calls
    return 1
  fi
}

assert_not_called() { # assert_not_called <ere>
  if grep -qE -- "$1" "$BM_TEST_CALLS"; then
    printf 'expected NO external call matching: %s\n' "$1" >&2
    _dump_calls
    return 1
  fi
}

# Every pattern must have been called, in strictly increasing order.
assert_call_order() { # assert_call_order <ere> <ere> [<ere>...]
  local prev=0 pat idx
  for pat in "$@"; do
    idx="$(call_index "$pat")"
    if [[ -z "$idx" ]]; then
      printf 'expected an external call matching: %s\n' "$pat" >&2
      _dump_calls
      return 1
    fi
    if (( idx <= prev )); then
      printf 'call out of order: %s appeared at line %s, expected after line %s\n' \
        "$pat" "$idx" "$prev" >&2
      _dump_calls
      return 1
    fi
    prev="$idx"
  done
}

# No mutating nmcli verb was issued (read-only listings are fine).
assert_no_nmcli_mutations() {
  assert_not_called '^nmcli .*connection (add|modify|up|down|delete|reload)'
}

require_root() { # skip a test that genuinely needs euid 0
  [[ "$EUID" -eq 0 ]] || skip "requires root"
}
