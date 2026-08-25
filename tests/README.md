# bond-manager test suite

## Running

```sh
bats -r tests                          # everything
bats tests/unit tests/integration      # same thing, explicit
bats tests/unit/facts.bats             # one file
bats tests/unit/facts.bats -f "health" # one group by name filter
```

Requires: bats >= 1.5 (uses `run --separate-stderr`), python3, jq.
The snapshot/checkpoint tests that genuinely need euid 0 skip themselves when
not run as root; everything else is uid-independent.

## Layout

- `helpers.bash` — per-test sandbox under `$BATS_TEST_TMPDIR`: fixture
  `/proc` + `/sys` trees, private conn/backup/run/log roots, all exported as
  `BM_*` env overrides. `load_artifact` sources the committed dist artifact
  `bond_manager.sh` (sourcing defines every `bm::` function without running
  main) for unit tests; `run_cli` executes it end-to-end for integration
  tests (`run_cli_stdout` keeps stderr out of `$output` for JSON checks).
- `stubs/` — PATH-shim executables (`nmcli`, `ip`, `systemctl`, `busctl`,
  `systemd-run`, `ping`, `modprobe`, `ethtool`, `journalctl`, `logger`,
  `restorecon`, `who`, `ps`). The sandbox prepends this dir to `PATH`, so the
  tool's PATH-resolved external commands hit the shims.
- `tools/mk-proc-bond` — test-only generator (not a shim, not on `PATH`) that
  writes a realistic active-backup `/proc/net/bonding/<bond>` for an arbitrary
  member list. `write_proc_bond` calls it, and so do the nmcli hooks that model
  the kernel enslaving/releasing a NIC in response to a plan step.
- `fixtures/` — realistic `/proc/net/bonding` files (active-backup
  healthy/degraded, 802.3ad with partner / with zero partner MAC — including
  the kernel's tab-indented `Active Aggregator Info:` block and capitalized
  `Speed: Unknown` for down slaves) plus a sysfs skeleton
  (`sysfs/class/net/{bond0,eth0,eth1}` with operstate/speed/address/mtu,
  `device/` backing dirs and `master` symlinks).

## How the stubs work

Every stub appends `"<cmd> <argv...>"` to the file named by `$BM_TEST_CALLS`,
so tests can assert exactly which external commands ran (e.g. that a dry run
issued no mutating `nmcli` verb). Behavior is driven by fixture files and env
vars:

- **nmcli** — connection database in `$BM_STUB_NM_DIR/*.conn`, one file per
  profile with `property=value` lines (`connection.uuid`, `connection.id`,
  `connection.type`, `connection.interface-name`, `bond.options`,
  `vlan.parent`, ...). Supports `--version`, terse listings
  (`-t -f F1,F2 connection show`, escaping `:` as `\:` and `\` as `\\`), and
  single-property reads (`-g PROP connection show <uuid-or-id>`; unknown
  profile exits 10). Mutating verbs (`add/modify/up/down/delete/reload`) log,
  then in order: fail with `${BM_STUB_NMCLI_FAIL_RC:-1}` when the argv matches
  `$BM_STUB_NMCLI_FAIL_RE` (fail one chosen plan step), run
  `$BM_STUB_NMCLI_HOOK` with the argv (model NetworkManager/kernel reacting —
  helper `install_nmcli_hook`), and exit `${BM_STUB_NMCLI_MUTATE_RC:-0}`.
  Helpers: `stub_nm_conn`, `stub_nm_bond0_profile`.
- **ip** — canned outputs from `$BM_STUB_IP_DIR`: `addr`, `addr_<dev>`,
  `link`, `link_<dev>`, `route4_default`, `route_get` (helper:
  `stub_ip_file`). Missing file = empty output, rc 0.
- **systemctl** — `is-active [--quiet] NetworkManager` exits
  `${BM_STUB_NM_ACTIVE_RC:-0}` (0 = active).
- **busctl** — answers the `org.freedesktop.DBus.Peer Ping` probe
  (`${BM_STUB_BUSCTL_PING_RC:-0}`) and `CheckpointCreate` with
  `o "/org/freedesktop/NetworkManager/Checkpoint/1"`
  (`${BM_STUB_CKPT_CREATE_RC:-0}`). `CheckpointDestroy`,
  `CheckpointRollback` and `CheckpointAdjustRollbackTimeout` exit
  `${BM_STUB_CKPT_DESTROY_RC:-0}`, `${BM_STUB_CKPT_ROLLBACK_RC:-0}` and
  `${BM_STUB_CKPT_ADJUST_RC:-0}` — a non-zero Destroy is a checkpoint that is
  already gone, i.e. a change NetworkManager has auto-rolled-back.
- **who / ps** — the SSH-egress fallback that reads the peer address from the
  login record of our controlling terminal. `who` prints
  `$BM_STUB_WHO_LINES` (empty by default); `ps` answers `-o tty= -p PID` with
  `$BM_STUB_PS_TTY` when it is set and otherwise delegates to the real `ps`,
  so the shim cannot perturb anything else.
- **ping** — exits `${BM_STUB_PING_RC:-0}` (reachable by default).
- **systemd-run** — pretends the transient deadman timer was created; exits
  `${BM_STUB_SYSTEMD_RUN_RC:-0}` (non-zero = "this host cannot arm a timer").
- **modprobe / ethtool / journalctl / logger / restorecon** — log-and-succeed
  (ethtool/journalctl print small fixed outputs).

## Fixture scenarios (helpers)

`scenario_bond0_healthy`, `scenario_bond0_degraded`, `scenario_bond0_down`,
`scenario_bond1_8023ad`, `scenario_bond1_8023ad_no_partner` install a proc
file plus matching sysfs entries; `mk_sys_nic` / `mk_sys_bond` /
`enslave_sys_nic` build extra interfaces; `write_proc_bond <bond> <active>
<member>...` generates a proc file for any member list (used to model the
kernel mid-run). `fixtures/proc_bonding_8023ad_churned` is an aggregation with
a real partner whose ports report `Actor/Partner Churn State: churned`.

## Safety-engine helpers

- `seed_pending [tier] [snapshot-id] [summary]` — write the pending-change
  state file a disconnected session would have left, so `commit` / `rollback`
  / the deadman timer have something to act on.
- `stub_ssh_session <peer-ip> <egress-dev>` — set `SSH_CONNECTION` and the
  `ip route get` answer that puts the session on `<egress-dev>`.
- `install_nmcli_hook <<'EOF' ... EOF` — script run after every mutating nmcli
  verb, standing in for NetworkManager and the kernel.
- `tree_state <dir>...` — sorted type/size/path inventory; compare before and
  after to prove a dry run wrote nothing.
- Call-log assertions over `$BM_TEST_CALLS`: `assert_called <ere>`,
  `assert_not_called <ere>`, `assert_no_nmcli_mutations`, and
  `assert_call_order <ere> <ere>...` which pins the ORDER of external commands
  (e.g. swap-member adding and activating the new port before deleting the
  old one).
