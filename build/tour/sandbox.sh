# shellcheck shell=bash
# Sourced by capture.py: a believable server ("web01") for the tour's screen
# captures. Nothing here touches a real network: nmcli, ip, busctl and
# friends are the test stubs from tests/stubs, and /proc, /sys and the
# NetworkManager profiles are files under $TOUR_SB, rebuilt on every source.
#
#   bond0  active-backup on ens1f0 + ens1f1, carries the SSH session
#   bond1  802.3ad on ens3f0 + ens3f1, switch side never bundled (a problem)
#   ens2f0, ens2f1  free, cabled to the new switch
#   ens4f0  free, no link;  eno1  management port with an address

: "${TOUR_SB:?TOUR_SB must name a scratch directory}"
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SB="$TOUR_SB"
rm -rf "$SB"
mkdir -p "$SB/bin"
export BM_TEST_SANDBOX="$SB" BM_PROC_ROOT="$SB/proc" BM_SYS_ROOT="$SB/sys"
export BM_CONN_DIR="$SB/conn" BM_IFCFG_DIR="$SB/ifcfg" BM_CONF="$SB/bond_manager.conf"
export BM_LOG_FILE="$SB/log/bm.log" BM_BACKUP_DIR="$SB/backups" BM_SUPPORT_DIR="$SB/support"
export BM_RUN_DIR="$SB/run" BM_LOGROTATE_CONF="$SB/logrotate.conf" BM_TEST_CALLS="$SB/calls.log"
export BM_STUB_NM_DIR="$SB/nm" BM_STUB_IP_DIR="$SB/ip" BM_TEST_MKPROC="$R/tests/tools/mk-proc-bond"
mkdir -p "$BM_PROC_ROOT/net/bonding" "$BM_SYS_ROOT/class/net" "$BM_CONN_DIR" "$BM_IFCFG_DIR" \
  "$BM_BACKUP_DIR" "$BM_RUN_DIR" "$BM_SUPPORT_DIR" "$BM_STUB_NM_DIR" "$BM_STUB_IP_DIR" "$SB/log"
: > "$BM_TEST_CALLS"
printf '#!/bin/sh\necho web01\n' > "$SB/bin/hostname"
chmod +x "$SB/bin/hostname"
ln -sf "$R/bond_manager.sh" "$SB/bin/bond-manager"
export PATH="$SB/bin:$R/tests/stubs:$PATH"
unset NO_COLOR
printf 'LINK_SETTLE_TIMEOUT="0"\n' > "$BM_CONF"

nic() { # nic <name> [operstate] [speed] [mac]
  local d="$BM_SYS_ROOT/class/net/$1"
  mkdir -p "$d/device"
  echo "${2:-up}" > "$d/operstate"; echo "${3:-10000}" > "$d/speed"
  echo "${4:-52:54:00:ab:cd:01}" > "$d/address"; echo 1500 > "$d/mtu"
}
bond() { # bond <name>
  local d="$BM_SYS_ROOT/class/net/$1"
  mkdir -p "$d"
  echo up > "$d/operstate"; echo 1500 > "$d/mtu"; echo 52:54:00:ab:cd:ff > "$d/address"
}
enslave() { ln -sfn "../$2" "$BM_SYS_ROOT/class/net/$1/master"; }
nmc() { # nmc <uuid> key=value...
  local u="$1"; shift
  { echo "connection.uuid=$u"; printf '%s\n' "$@"; } > "$BM_STUB_NM_DIR/$u.conn"
}

bond bond0
nic ens1f0 up 10000 52:54:00:ab:10:00
nic ens1f1 up 10000 52:54:00:ab:10:01
enslave ens1f0 bond0
enslave ens1f1 bond0
"$BM_TEST_MKPROC" "$BM_PROC_ROOT/net/bonding/bond0" ens1f0 ens1f0 ens1f1

bond bond1
nic ens3f0 up 10000 52:54:00:ab:30:00
nic ens3f1 up 10000 52:54:00:ab:30:01
enslave ens3f0 bond1
enslave ens3f1 bond1
sed 's/ens1f0/ens3f0/g; s/ens1f1/ens3f1/g' "$R/tests/fixtures/proc_bonding_8023ad_no_partner" \
  > "$BM_PROC_ROOT/net/bonding/bond1"

nic ens2f0 up 10000 52:54:00:ab:20:00
nic ens2f1 up 10000 52:54:00:ab:20:01
nic ens4f0 down 10000 52:54:00:ab:40:00
nic eno1 up 1000 52:54:00:ab:e0:01

printf 'bond0 UP 10.20.30.41/24 fe80::5054:ff:feab:ff/64\n' > "$BM_STUB_IP_DIR/addr_bond0"
printf 'bond1 UP 10.20.60.41/24\n' > "$BM_STUB_IP_DIR/addr_bond1"
printf 'eno1 UP 192.168.10.21/24\n' > "$BM_STUB_IP_DIR/addr_eno1"
printf 'default via 10.20.30.1 dev bond0 proto static\n' > "$BM_STUB_IP_DIR/route4_default"

# the SSH session arrives over bond0
export SSH_CONNECTION="10.9.8.7 51514 10.20.30.41 22"
printf '10.9.8.7 via 10.20.30.1 dev bond0 src 10.20.30.41 uid 0\n    cache\n' > "$BM_STUB_IP_DIR/route_get"

nmc 11111111-1111-1111-1111-111111111111 connection.id=bond0 connection.type=bond \
  connection.interface-name=bond0 "bond.options=mode=active-backup,miimon=100"
nmc 22222222-2222-2222-2222-222222222222 connection.id=bond-port-ens1f0 connection.type=802-3-ethernet \
  connection.interface-name=ens1f0 connection.master=11111111-1111-1111-1111-111111111111 connection.slave-type=bond
nmc 33333333-3333-3333-3333-333333333333 connection.id=bond-port-ens1f1 connection.type=802-3-ethernet \
  connection.interface-name=ens1f1 connection.master=11111111-1111-1111-1111-111111111111 connection.slave-type=bond
nmc 44444444-4444-4444-4444-444444444444 connection.id=bond1 connection.type=bond \
  connection.interface-name=bond1 "bond.options=mode=802.3ad,lacp_rate=fast,miimon=100,xmit_hash_policy=layer3+4"
nmc 55555555-5555-5555-5555-555555555555 connection.id=bond-port-ens3f0 connection.type=802-3-ethernet \
  connection.interface-name=ens3f0 connection.master=44444444-4444-4444-4444-444444444444 connection.slave-type=bond
nmc 66666666-6666-6666-6666-666666666666 connection.id=bond-port-ens3f1 connection.type=802-3-ethernet \
  connection.interface-name=ens3f1 connection.master=44444444-4444-4444-4444-444444444444 connection.slave-type=bond

# NetworkManager and the kernel reacting to the ens1f0 -> ens2f0 swap on bond0
cat > "$SB/nmcli-hook" <<'HOOK'
#!/usr/bin/env bash
case "$*" in
  *"connection up bond-port-ens2f0"*)
    "$BM_TEST_MKPROC" "$BM_PROC_ROOT/net/bonding/bond0" ens1f0 ens1f0 ens1f1 ens2f0
    ln -sfn ../bond0 "$BM_SYS_ROOT/class/net/ens2f0/master" ;;
  *"connection delete 22222222-2222-2222-2222-222222222222"*)
    "$BM_TEST_MKPROC" "$BM_PROC_ROOT/net/bonding/bond0" ens1f1 ens1f1 ens2f0
    rm -f "$BM_SYS_ROOT/class/net/ens1f0/master" "$BM_STUB_NM_DIR/22222222-2222-2222-2222-222222222222.conn" ;;
esac
exit 0
HOOK
chmod +x "$SB/nmcli-hook"
export BM_STUB_NMCLI_HOOK="$SB/nmcli-hook"
