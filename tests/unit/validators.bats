#!/usr/bin/env bats
# bm::val::* input validators.

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

@test "ifname: accepts sane names up to 15 chars" {
  bm::val::ifname eth0
  bm::val::ifname bond0
  bm::val::ifname ens1f0.100
  bm::val::ifname a23456789012345          # exactly 15
  bm::val::ifname bond_backup-1
}

@test "ifname: rejects too-long, empty and dangerous names" {
  run bm::val::ifname a234567890123456;  [ "$status" -ne 0 ]   # 16 chars
  run bm::val::ifname "";                [ "$status" -ne 0 ]
  run bm::val::ifname "eth 0";           [ "$status" -ne 0 ]
  run bm::val::ifname "eth/0";           [ "$status" -ne 0 ]
  run bm::val::ifname ".";               [ "$status" -ne 0 ]
  run bm::val::ifname "..";              [ "$status" -ne 0 ]
  run bm::val::ifname 'eth$(reboot)';    [ "$status" -ne 0 ]
}

@test "vlan_id: 1..4094" {
  bm::val::vlan_id 1
  bm::val::vlan_id 100
  bm::val::vlan_id 4094
  run bm::val::vlan_id 0;     [ "$status" -ne 0 ]
  run bm::val::vlan_id 4095;  [ "$status" -ne 0 ]
  run bm::val::vlan_id abc;   [ "$status" -ne 0 ]
  run bm::val::vlan_id -1;    [ "$status" -ne 0 ]
  run bm::val::vlan_id "";    [ "$status" -ne 0 ]
}

@test "uint: bounds honored" {
  bm::val::uint 0
  bm::val::uint 4294967295
  bm::val::uint 50 10 100
  run bm::val::uint 9 10 100;    [ "$status" -ne 0 ]
  run bm::val::uint 101 10 100;  [ "$status" -ne 0 ]
  run bm::val::uint -1;          [ "$status" -ne 0 ]
  run bm::val::uint 1.5;         [ "$status" -ne 0 ]
}

@test "mtu: 68..65535" {
  bm::val::mtu 68
  bm::val::mtu 1500
  bm::val::mtu 9000
  bm::val::mtu 65535
  run bm::val::mtu 67;     [ "$status" -ne 0 ]
  run bm::val::mtu 65536;  [ "$status" -ne 0 ]
}

@test "ipv4_addr: octet range enforced" {
  bm::val::ipv4_addr 10.0.0.1
  bm::val::ipv4_addr 255.255.255.255
  bm::val::ipv4_addr 0.0.0.0
  run bm::val::ipv4_addr 256.0.0.1;    [ "$status" -ne 0 ]
  run bm::val::ipv4_addr 10.0.0;       [ "$status" -ne 0 ]
  run bm::val::ipv4_addr 10.0.0.1.2;   [ "$status" -ne 0 ]
  run bm::val::ipv4_addr "a.b.c.d";    [ "$status" -ne 0 ]
}

@test "ipv4_cidr: requires /prefix 0..32" {
  bm::val::ipv4_cidr 192.168.1.10/24
  bm::val::ipv4_cidr 10.0.0.1/32
  bm::val::ipv4_cidr 10.0.0.0/0
  run bm::val::ipv4_cidr 192.168.1.10;      [ "$status" -ne 0 ]  # no prefix
  run bm::val::ipv4_cidr 192.168.1.10/33;   [ "$status" -ne 0 ]
  run bm::val::ipv4_cidr 300.1.1.1/24;      [ "$status" -ne 0 ]
}

@test "ipv6_addr: accepts common forms" {
  bm::val::ipv6_addr 2001:db8::1
  bm::val::ipv6_addr fe80::1
  bm::val::ipv6_addr ::1
  bm::val::ipv6_addr ::
  bm::val::ipv6_addr 1:2:3:4:5:6:7:8
}

@test "ipv6_addr: rejects malformed forms" {
  run bm::val::ipv6_addr ":::";            [ "$status" -ne 0 ]
  run bm::val::ipv6_addr "1::2::3";        [ "$status" -ne 0 ]  # two '::'
  run bm::val::ipv6_addr "1:2:3:4:5:6:7";  [ "$status" -ne 0 ]  # 7 groups, no ::
  run bm::val::ipv6_addr "2001:zz8::1";    [ "$status" -ne 0 ]
  run bm::val::ipv6_addr "10.0.0.1";       [ "$status" -ne 0 ]
  run bm::val::ipv6_addr "";               [ "$status" -ne 0 ]
}

@test "ipv6_cidr: requires /prefix 0..128" {
  bm::val::ipv6_cidr 2001:db8::1/64
  bm::val::ipv6_cidr fe80::1/128
  run bm::val::ipv6_cidr 2001:db8::1;      [ "$status" -ne 0 ]
  run bm::val::ipv6_cidr 2001:db8::1/129;  [ "$status" -ne 0 ]
}

@test "ip_list: validates every element of a comma list" {
  bm::val::ip_list v4 "10.0.0.1"
  bm::val::ip_list v4 "10.0.0.1,192.168.1.1"
  bm::val::ip_list v6 "2001:db8::1,fe80::2"
  run bm::val::ip_list v4 "10.0.0.1,999.0.0.1";  [ "$status" -ne 0 ]
  run bm::val::ip_list v4 "";                    [ "$status" -ne 0 ]
  run bm::val::ip_list v6 "2001:db8::1,bogus";   [ "$status" -ne 0 ]
}
