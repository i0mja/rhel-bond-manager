#!/usr/bin/env bats
# The guided menus in plain mode (what --plain, a serial console or a pipe
# gets), driven end to end with scripted answers. Menu answers may be the
# number or the item's tag; the tags keep these scripts readable.
#
# Every run is wrapped in `timeout`: a menu that fails to notice the end of
# its input must fail the test, not hang CI.

load ../helpers

setup() {
  setup_sandbox
  scenario_bond0_healthy                       # bond0 = eth0 (active) + eth1
  mk_sys_nic eth2 up 1000 52:54:00:12:34:03
  mk_sys_nic eth3 up 1000 52:54:00:12:34:04
  stub_nm_bond0_profile
  set_conf LINK_SETTLE_TIMEOUT 0
}

tui() { # tui <answers (printf %b)> [global flags...]
  local answers="$1"
  shift
  run timeout 30 bash -c 'printf "%b" "$1" | "$2" "${@:3}" tui' _ "$answers" "$BM_ARTIFACT" "$@"
}

@test "home: the dashboard, the menu, and q to quit" {
  tui 'q\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond-manager 3.1.0"
  assert_contains "$output" "PRACTICE"
  assert_contains "$output" "* bond0  active-backup (failover)  healthy"
  assert_contains "$output" "|- eth0  up"
  assert_contains "$output" "(active)"
  assert_contains "$output" "What do you want to do?"
  assert_contains "$output" "Move a bond to a new switch"
  assert_contains "$output" "Bye."
}

@test "home: end of input exits cleanly (no hang, rc 0)" {
  run timeout 30 "$BM_ARTIFACT" --dry-run tui </dev/null
  [ "$status" -eq 0 ]
}

@test "home: -y is ignored in the menus, and says so" {
  tui 'q\n' --dry-run -y
  [ "$status" -eq 0 ]
  assert_contains "$output" "-y/--yes is ignored in the menus"
}

@test "home: the SSH connection is marked on the dashboard" {
  stub_ssh_session 10.9.9.9 bond0
  tui 'q\n' --dry-run
  assert_contains "$output" "<- your SSH connection"
}

@test "check: health in plain words" {
  tui 'check\nquick\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond0 is healthy."
  assert_contains "$output" "All good."
}

@test "check: a degraded bond is explained with what to do" {
  install_proc_bond proc_bonding_active_backup_degraded bond0
  tui 'check\nquick\n\nq\nq\n' --dry-run
  assert_contains "$output" "bond0 needs attention:"
  assert_contains "$output" "Port eth1 has no link"
  assert_contains "$output" "What to do: Check the cable and the switch port."
}

@test "build: the wizard reaches the exact plan and changes nothing" {
  tui 'build\nbond9\neth2 eth3\nactive-backup\nnone\nfinish\ngo\n\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "Step 1 of 5"
  assert_contains "$output" "Step 5 of 5"
  assert_contains "$output" "Build bond bond9 from: eth2, eth3"
  assert_contains "$output" "bond-manager -n create bond9 --mode active-backup --members eth2,eth3 --ip4 none"
  assert_contains "$output" "Plan:"
  assert_contains "$output" "Create bond profile 'bond9' (mode=active-backup,miimon=100)"
  assert_contains "$output" "(dry-run: no commands executed, no files written, no snapshot taken)"
  assert_contains "$output" "Practice run finished - nothing was changed."
  assert_no_nmcli_mutations
  [ -z "$(ls -A "$BM_BACKUP_DIR")" ]
  [ -z "$(ls -A "$BM_RUN_DIR")" ]
}

@test "build: a bad answer is explained and asked again" {
  tui 'build\nbad name!\nbond0\nbond9\neth2\nactive-backup\nstatic\n10.0.0.5\n10.0.0.5/24\n\n\nfinish\ngo\n\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "Use up to 15 letters"
  assert_contains "$output" "'bond0' already exists"
  assert_contains "$output" "Add the prefix length after a slash, e.g. 10.0.0.5/24."
  assert_contains "$output" "One port works, but there is no spare yet."
  assert_contains "$output" "create bond9 --mode active-backup --members eth2 --ip4 10.0.0.5/24"
}

@test "build: ports already in a bond are not offered" {
  tui 'build\nbond9\nq\nq\nq\n' --dry-run
  assert_contains "$output" "Not shown - already in a bond: eth0 (bond0) eth1 (bond0)"
}

@test "build: a VLAN carries the address, the bond gets none" {
  tui 'build\nbond9\neth2 eth3\nactive-backup\nvlan\n120\ndhcp\nfinish\ngo\n\nq\n' --dry-run
  assert_contains "$output" "--ip4 none --vlan 120:ip4=dhcp"
  assert_contains "$output" "Create VLAN 120 on bond9 (bond9.120)"
}

@test "move: the swap wizard renders the add-then-remove plan" {
  tui 'move\neth0\neth2\ngo\n\nn\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "Using bond0 (the only bond)."
  assert_contains "$output" "bond-manager -n swap-member bond0 --old eth0 --new eth2"
  assert_contains "$output" "Add replacement member 'eth2'"
  assert_contains "$output" "Wait for 'eth2' to enslave"
  assert_contains "$output" "Remove old member profile for 'eth0'"
  assert_no_nmcli_mutations
}

@test "move: an LACP bond is warned about crossing switches" {
  install_proc_bond proc_bonding_8023ad_healthy bond0
  tui 'move\nback\nq\n' --dry-run
  assert_contains "$output" "LACP and the move (bond0 runs 802.3ad)"
  assert_contains "$output" "switch bond0 to active-backup first"
}

@test "change > remove port: cannot take out every port" {
  tui 'change\nremove\neth0 eth1\neth1\ngo\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "Please pick exactly 1."
  assert_contains "$output" "bond-manager -n remove-member bond0 eth1"
  assert_contains "$output" "Remove member profile for 'eth1'"
}

@test "change > remove port: a port with no link is removed without a link warning" {
  scenario_bond0_degraded
  printf 'down\n' >"$BM_SYS_ROOT/class/net/eth1/operstate"
  tui 'change\nremove\neth1\ngo\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_not_contains "$output" "has no link right now"
  assert_not_contains "$output" "anyway?"
  assert_contains "$output" "Remove member profile for 'eth1'"
}

@test "change > add port: a port whose VLAN carries the SSH session is flagged first" {
  mkdir -p "$BM_PROC_ROOT/net/vlan"
  printf 'VLAN Dev name | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\neth2.100 | 100 | eth2\n' \
    >"$BM_PROC_ROOT/net/vlan/config"
  mk_sys_nic eth2.100 up 1000 52:54:00:12:34:03
  stub_ssh_session 10.9.9.9 eth2.100
  tui 'change\nadd\neth2\n\nq\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "YOUR SSH CONNECTION"
  assert_contains "$output" "eth2 carries your SSH connection"
  assert_not_contains "$output" "Add member 'eth2'"   # Enter (no) went back to the list
}

@test "change > mode: switching to 802.3ad asks about the switch and adds LACP defaults" {
  tui 'change\nmode\n802.3ad\ny\ngo\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "LACP is a deal between this server AND the switch"
  assert_contains "$output" "modify bond0 --mode 802.3ad --opt lacp_rate=fast,xmit_hash_policy=layer3+4"
}

@test "change > add port: the add-member plan" {
  tui 'change\nadd\neth2\ngo\n\nq\nq\n' --dry-run
  assert_contains "$output" "bond-manager -n add-member bond0 eth2"
  assert_contains "$output" "Add member 'eth2'"
}

@test "fix: nothing to fix when the saved settings match" {
  tui 'fix\n\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "The saved settings already match what bond0 really uses"
}

@test "a waiting change is announced, offered first, and quitting warns" {
  seed_pending checkpoint "" "modify bond bond0"
  tui 'q\ny\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "A change is waiting for you: modify bond bond0"
  assert_contains "$output" "1) Keep or undo the last change"
  assert_contains "$output" "A change is still waiting to be kept"
  assert_contains "$output" "sudo bond-manager commit"
}

@test "help: topics are readable from the menu" {
  tui 'help\nbasics\n\nq\nq\n' --dry-run
  assert_contains "$output" "WHAT IS A BOND?"
}

@test "tools: the network port list" {
  tui 'tools\nnics\n\nq\nq\n' --dry-run
  assert_contains "$output" "free - good to use"
}

@test "not root: practice mode is forced and explained" {
  [[ "$EUID" -ne 0 ]] || skip "needs a non-root user"
  tui 'q\n'
  [ "$status" -eq 0 ]
  assert_contains "$output" "Practice mode is on"
  assert_contains "$output" "You are not root"
  assert_contains "$output" "sudo bond-manager"
  assert_contains "$output" "PRACTICE (look only)"
}

@test "not root: practice cannot be switched off" {
  [[ "$EUID" -ne 0 ]] || skip "needs a non-root user"
  tui '\np\n\nq\n'
  assert_contains "$output" "Practice mode has to stay on"
}

@test "change > IP address > IPv6: a fixed address, with a missing prefix explained" {
  tui 'change\nip\nv6\nstatic\n2001:db8::10\n2001:db8::10/64\n2001:db8::1\n\ngo\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "Add the prefix length after a slash, e.g. 2001:db8::10/64."
  assert_contains "$output" "Set the IPv6 address of bond0: 2001:db8::10/64, gateway 2001:db8::1."
  assert_contains "$output" "bond-manager -n modify bond0 --ip6 2001:db8::10/64 --gw6 2001:db8::1"
  assert_contains "$output" "Configure IPv6 (2001:db8::10/64) on bond0"
  assert_contains "$output" "ipv6.method manual"
  assert_no_nmcli_mutations
}

@test "change > IP address > IPv6: SLAAC and DHCPv6 map to auto and dhcp" {
  tui 'change\nip\nv6\nauto\ngo\n\nq\nq\n' --dry-run
  assert_contains "$output" "bond-manager -n modify bond0 --ip6 auto"
  assert_contains "$output" "Configure IPv6 (SLAAC/auto) on bond0"
  tui 'change\nip\nv6\ndhcp\ngo\n\nq\nq\n' --dry-run
  assert_contains "$output" "bond-manager -n modify bond0 --ip6 dhcp"
  assert_contains "$output" "Configure IPv6 (DHCPv6) on bond0"
}

@test "change > IP address > IPv4 still works after the family question" {
  tui 'change\nip\nv4\ndhcp\ngo\n\nq\nq\n' --dry-run
  assert_contains "$output" "bond-manager -n modify bond0 --ip4 dhcp"
}

@test "change > VLANs > add: IPv4 and IPv6 together in one VLAN token" {
  tui 'change\nvlan\nadd\n120\nstatic\n10.20.30.40/24\n\n\ny\nauto\ngo\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "bond-manager -n vlan add bond0 '120:ip4=10.20.30.40/24;ip6=auto'"
  assert_contains "$output" "Create VLAN 120 on bond0 (bond0.120)"
  assert_contains "$output" "Configure IPv6 (SLAAC/auto) on bond0.120"
}

@test "build: the review says where IPv6 is set" {
  tui 'build\nbond9\neth2 eth3\nactive-backup\nnone\nfinish\ncancel\nq\n' --dry-run
  assert_contains "$output" "IPv6: not set here - add it afterwards with Change a bond > IP"
}

@test "change > VLANs > change IP: IPv6 on an existing VLAN" {
  stub_nm_conn 44444444-4444-4444-4444-444444444444 \
    connection.id=bond0.120 connection.type=vlan connection.interface-name=bond0.120 \
    vlan.parent=bond0 vlan.id=120
  tui 'change\nvlan\nmodify\n120\nv6\ndhcp\ngo\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "VLANs now: 120"
  assert_contains "$output" "Set the IPv6 address of VLAN 120 on bond0: DHCPv6."
  assert_contains "$output" "bond-manager -n vlan modify bond0 120 --ip6 dhcp"
  assert_contains "$output" "Configure IPv6 (DHCPv6) on bond0.120"
}

# ---- keep or undo, racing the safety net ------------------------------------

# Opens "Keep or undo?" while a deadman-tier change waits, lets the timer undo
# the change underneath the open screen, then answers <choice>.
race_the_timer() { # race_the_timer keep|undo
  export BM_STUB_NM_DIR="$BM_CONN_DIR"   # profiles live where snapshots look
  mkdir -p "$BM_STUB_NM_DIR"
  stub_nm_bond0_profile
  export BM_STUB_BUSCTL_PING_RC=1        # deadman tier
  install_nmcli_hook <<'HOOK'
if [[ "$*" == *"connection modify 11111111-1111-1111-1111-111111111111"* ]]; then
  sed -i 's/miimon=100/miimon=250/' "$BM_STUB_NM_DIR/11111111-1111-1111-1111-111111111111.conn"
fi
HOOK
  run bash -c "printf 'y\n' | '$BM_ARTIFACT' modify bond0 --opt miimon=250"
  [ "$status" -eq 6 ]
  local snap
  snap="$(sed -n 's/^snapshot=//p' "$BM_RUN_DIR/pending.state")"

  mkfifo "$BATS_TEST_TMPDIR/keys"
  timeout 60 "$BM_ARTIFACT" --plain tui <"$BATS_TEST_TMPDIR/keys" >"$BATS_TEST_TMPDIR/screen" 2>&1 &
  local tui=$!
  exec 7>"$BATS_TEST_TMPDIR/keys"
  printf 'pending\n' >&7
  local i
  for i in $(seq 100); do
    grep -q "Decide later" "$BATS_TEST_TMPDIR/screen" && break
    sleep 0.1
  done
  # the timer fires while the screen is open
  "$BM_ARTIFACT" rollback --snapshot "$snap" --deadman --yes >/dev/null 2>&1
  [ ! -f "$BM_RUN_DIR/pending.state" ]
  printf '%s\ny\n\n' "$1" >&7
  exec 7>&-
  wait "$tui" || true
  output="$(cat "$BATS_TEST_TMPDIR/screen")"
}

@test "keep or undo: Undo after the safety net already undid the change does not bring it back" {
  require_root
  race_the_timer undo
  assert_contains "$output" "Nothing was waiting any more"
  assert_not_contains "$output" "Restoring snapshot"
  grep -q 'miimon=100' "$BM_CONN_DIR/11111111-1111-1111-1111-111111111111.conn"
}

@test "keep or undo: Keep after the safety net already undid the change says so" {
  require_root
  race_the_timer keep
  assert_contains "$output" "Nothing was waiting any more"
  assert_not_contains "$output" "Could not start"
}

@test "result: a change left waiting on the snapshot tier is not promised an automatic undo" {
  require_root
  export BM_STUB_BUSCTL_PING_RC=1 BM_STUB_SYSTEMD_RUN_RC=1   # snapshot-only protection
  tui 'change\nopt\nset\nmiimon\n250\ngo\ny\n\nq\nq\ny\n'
  assert_contains "$output" "Snapshot-only protection"
  assert_contains "$output" "The change is live but NOT kept yet."
  assert_not_contains "$output" "It will undo itself automatically"
  assert_contains "$output" "Nothing on this server undoes it automatically"
}

# ---- IP answers ----------------------------------------------------------------

stub_bond0_with_gateway() {
  stub_nm_conn 11111111-1111-1111-1111-111111111111 \
    connection.id=bond0 connection.type=bond connection.interface-name=bond0 \
    'bond.options=mode=active-backup,miimon=100' ipv4.method=manual \
    ipv4.addresses=10.0.0.5/24 ipv4.gateway=10.0.0.1 ipv4.dns=10.0.0.53
}

@test "change > IP address: Enter keeps the current gateway and DNS, and says so" {
  stub_bond0_with_gateway
  tui 'change\nip\nv4\nstatic\n10.0.0.6/24\n\n\ngo\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "Enter keeps 10.0.0.1"
  assert_contains "$output" "bond-manager -n modify bond0 --ip4 10.0.0.6/24"
  assert_not_contains "$output" "--gw4"
}

@test "change > IP address: none removes the old gateway and DNS" {
  stub_bond0_with_gateway
  tui 'change\nip\nv4\nstatic\n192.168.5.10/24\nnone\nnone\ngo\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "--gw4 none --dns4 none"
  assert_contains "$output" "ipv4.gateway '' ipv4.dns ''"
}

@test "build: a VLAN DNS list typed with spaces becomes one comma list" {
  tui 'build\nbond9\neth2 eth3\nactive-backup\nvlan\n120\nstatic\n10.0.0.5/24\n10.0.0.1\n10.0.0.53, 10.0.0.54\nfinish\ngo\n\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "--vlan '120:ip4=10.0.0.5/24;gw4=10.0.0.1;dns4=10.0.0.53,10.0.0.54'"
  assert_not_contains "$output" "invalid VLAN id"
  assert_not_contains "$output" "was not accepted"
}

@test "result: a support bundle made in practice mode is not called 'nothing was changed'" {
  tui 'tools\nbundle\nn\n\nq\nq\n' --dry-run
  [ "$status" -eq 0 ]
  assert_contains "$output" "support bundle:"
  assert_not_contains "$output" "nothing was changed"
}

@test "result: saying no to a snapshot restore is shown as cancelled, not finished" {
  require_root
  tui 'safety\nsave\n\nsnapshots\n1\nrestore\nn\n\nq\nq\n'
  assert_contains "$output" "Cancelled - nothing was changed."
}
