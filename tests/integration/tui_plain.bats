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
