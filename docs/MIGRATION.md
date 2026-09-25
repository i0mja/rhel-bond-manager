# Migrating from v2.1 to 3.0

v3 is a rebuild, not a refactor, but it was built to drop into a v2
installation: your config, your existing bonds and their profiles, and
your old backups all keep working. What breaks is confined to consumers of
the old JSON output and scripts that depended on v2's (buggy) side
behaviors. This page lists both, with worked examples.

## Compatible — no action needed

### Configuration file

`/etc/bond_manager.conf` keys are honored **verbatim**: `DEFAULT_MIIMON`,
`DEFAULT_8023AD_LACP_RATE`, `DEFAULT_8023AD_XHP`, `MAX_BACKUPS`,
`LOGROTATE_FREQUENCY`, `LOGROTATE_ROTATE`, `NIC_ALLOWLIST_PATTERNS`,
`NIC_BLOCKLIST_PATTERNS`. New optional keys: `ROLLBACK_WINDOW`,
`ACTIVATE_TIMEOUT`, `LINK_SETTLE_TIMEOUT`, `MIN_SPEED_MBPS`.

One deliberate change in *how* the file is read: v2 **sourced** it as root
shell code; v3 parses `KEY="value"` lines against an allowlist and never
executes it. A stock v2 config parses cleanly. If you had added actual
shell to yours (command substitutions, conditionals), those lines are now
ignored with a warning — `bond-manager config show` prints what took
effect.

### Legacy flags

```bash
bond-manager --status                      # ≡ bond-manager status
bond-manager --export-json /path/out.json  # writes the (new) JSON inventory to PATH
bond-manager --status --export-json /path/out.json   # both, as in v2
bond-manager -n                            # -n is still --dry-run
```

Two upgrades hide behind `--status`: it no longer requires root (v2
refused without it) and no longer writes anything (v2 installed the
config and logrotate policy on first run — even from `--status`). Note the
exit code change below.

### Existing bonds, profiles, and v2 snapshot archives

- Bonds created by v2 (or by hand) are fully manageable. v2 found port
  profiles by the `${bond}-slave-${nic}` naming convention; v3 discovers
  them via `connection.master` and addresses them by UUID, so it operates
  on your existing `bond0-slave-ens1f0`-style profiles — and on any
  hand-made profile v2 would have missed — without renaming anything.
- v2's `type bond-slave` profiles are ordinary ethernet profiles with
  `slave-type bond` in NetworkManager; v3 handles them as such.
- v2 backup archives (`/var/backups/bond_manager/conn-<ts>.tar.gz`) appear
  in `bond-manager snapshot list` marked `legacy` and are restorable:

  ```
  $ bond-manager snapshot list
  ID                     CREATED                      REASON
  20260825-141530        2026-08-25T14:15:30+0000     create
  20260207143012         (no manifest)                legacy
  $ bond-manager snapshot restore 20260207143012
  ```

  Legacy archives have no manifest, so their restore is an overlay (it
  cannot delete profiles created after the backup was taken). Snapshots
  taken by v3 carry manifests and restore reconciling — see
  [SAFETY.md](SAFETY.md).

### RHEL 8 hosts: the ifcfg profile store is now covered

v2 archived `/etc/NetworkManager/system-connections` and nothing else. On a
RHEL 8 host, where NetworkManager's `ifcfg-rh` plugin keeps profiles in
`/etc/sysconfig/network-scripts`, that archive captured nothing that
configured the machine — the backup existed, and restoring it changed
nothing.

v3 snapshots both stores. Each snapshot writes `conn-<ID>.tar.gz` (keyfile),
`conn-<ID>.ifcfg.tar.gz` (ifcfg, when that store holds NetworkManager
files) and a manifest listing both. In the ifcfg directory only
NetworkManager's own files are read or written — `ifcfg-*`, `keys-*`,
`route-*`, `route6-*`, `rule-*`, `rule6-*` at the top level — so the legacy
`ifup*`/`ifdown*` scripts and helpers that share that directory are left
strictly alone. Nothing to do on your side; take a fresh snapshot
(step 4 below) so your new baseline includes it.

### The TUI

Running with no arguments on a terminal still opens the menu (whiptail or
plain prompts), with the same operator grouping (Status / Change /
Migration / Repair / Safety / Support). It now drives exactly the same
workflow code as the CLI and prints the CLI equivalent of every action
before applying it.

From 3.1 the menus are built in (plain bash, arrow keys, numbered prompts
on serial consoles and with `--plain`): whiptail is no longer used, so
the `newt` package is not needed. The grouping is now by job: *Check my
bonds*, *Move a bond to a new switch*, *Build*, *Change*, *Fix*,
*Undo & safety*, *Tools*, *Help*.

## Changed — action may be needed

### JSON output: breaking for consumers

The v2 JSON was structurally unsafe (its escaper could not escape
newlines, multi-line values were embedded raw, and `ip -json` output was
injected verbatim), so v3 replaces the format rather than preserving it.
The new documents are RFC 8259-correct and carry `schema_version` (currently
`1`) so future changes are detectable.

Shape change — v2 was a top-level array:

```json
[ { "bond": "bond0", "mode": "IEEE 802.3ad Dynamic link aggregation",
    "mii_status": "up", "active_slave": "...", "primary_slave": "",
    "slaves": [ { "name": "ens1f0", "state": "up", "speed": "10000" } ],
    "addresses": [ ...raw ip -json output... ], "vlans": [] } ]
```

v3 is a versioned object, with normalized mode names, numeric numbers, and
a computed health verdict:

```json
{ "schema_version": 1, "generated": "2026-08-25T14:15:30+0000",
  "host": "db01", "tool_version": "3.0.0",
  "bonds": [ { "name": "bond0", "mode": "802.3ad", "health": "healthy",
               "reasons": [], "miimon": 100, "active_member": "", "primary": "",
               "members": [ { "name": "ens1f0", "mii": "up", "speed": 10000,
                              "duplex": "full", "link_failures": 0 } ],
               "addresses": ["10.20.30.40/24"], "vlans": [] } ] }
```

Typical jq migrations:

| v2 | v3 |
|---|---|
| `.[].bond` | `.bonds[].name` |
| `.[] \| select(.mii_status != "up")` | `.bonds[] \| select(.health != "healthy")` |
| `.[].slaves[].name` | `.bonds[].members[].name` |
| `.[].slaves[] \| select(.state != "up")` | `.bonds[].members[] \| select(.mii != "up")` |

Guard your consumers: `jq -e '.schema_version == 1'`.

### Health checks: exit codes now carry meaning

v2's `--status` always exited 0. v3's `status` (and legacy `--status`)
exits 0 healthy, **10** degraded, **11** down — so a check that treated
"non-zero" as "tool failed" will now fire on a degraded bond. That is the
point, but update your monitoring accordingly:

```bash
# v2 cron job (parse the text, root required):
# bond_manager --status | grep -q 'MII Status: up' || alert
# v3 (no root, no parsing):
bond-manager status || alert       # any non-healthy state or error
bond-manager status; case $? in 10) warn ;; 11) page ;; esac
```

The v2 spelling carries the same exit codes, including when it is combined
with an export: `bond-manager --status --export-json /path/out.json` writes
the file, prints the status, and exits 0/10/11 — a check that used that
combination sees the verdict rather than a flat 0.

`--json` applies to `list`, `show` and `status` (not `doctor`), and
`status BOND --json` scopes the document to that bond:

```bash
bond-manager status bond0 --json   # {"schema_version":1,"bonds":[{"name":"bond0",...}]}
```

### Port profile naming for new ports

New members get profiles named `bond-port-<nic>` (v2: `<bond>-slave-<nic>`).
Nothing operational depends on either name anymore, but if external
tooling greps profile names, update it — or better, match on
`connection.master`, as v3 does.

### Menu-driven → subcommand + TUI hybrid

v2 was interactive-only for changes; automation had exactly `--status` and
`--export-json`. In v3 every workflow is a subcommand, so changes can be
scripted, reviewed via `--dry-run`, and run unattended with `--yes`:

```bash
# rehearse
bond-manager -n create bond0 --mode 802.3ad --members ens1f0,ens1f1 \
    --ip4 none --vlan '120:ip4=10.20.30.40/24;gw4=10.20.30.1'
# apply with auto-commit after verification
bond-manager -y create bond0 --mode 802.3ad --members ens1f0,ens1f1 \
    --ip4 none --vlan '120:ip4=10.20.30.40/24;gw4=10.20.30.1'
```

**Automation note:** without `--yes`, a change that passes verification on
a non-TTY exits **6** and stays pending until `bond-manager commit` — by
design. On the checkpoint and deadman tiers the auto-rollback then fires at
the deadline; on the snapshot-only tier nothing does, and the tool says so.
Unattended runs should pass `--yes`, and treat exit **5** as "the change is
not live": either verification failed and it was rolled back, or the commit
found the checkpoint already gone because the window had expired (the
message names which). Follow up with `bond-manager status`.

### Dry-run is now actually dry

v2's `-n` skipped only the nmcli calls; it still wrote the config,
logrotate policy, log file, and created backups. v3's `--dry-run` renders
the plan and does nothing else — no root, no writes, no snapshot. If
anything relied on dry runs creating backups as a side effect, call
`bond-manager snapshot create` explicitly.

This holds for the safety commands too: `commit`, `rollback` and
`snapshot create|restore|prune` report what they would do and write
nothing under `--dry-run`, which makes `bond-manager -n snapshot restore
ID` a safe way to review a restore (it prints the same diff) before running
it for real.

### IPv6 methods are explicit

`--ip6 auto` is SLAAC (`ipv6.method auto`) and `--ip6 dhcp` is DHCPv6
without SLAAC (`ipv6.method dhcp`) — they are different NetworkManager
methods, and the tool no longer collapses one into the other. `--ip6 none`
writes `ipv6.method ignore` rather than `disabled`, because `disabled`
exists only from NetworkManager 1.20 while `ignore` works on every release
v3 supports, RHEL 8 included.

### First-run writes moved to `init`

v2 installed `/etc/bond_manager.conf` and the logrotate policy on first
run, whatever the command. v3 only does this when you ask:

```bash
sudo bond-manager init
```

Existing v2 installations already have both files; `init` leaves an
existing config untouched (it may update the managed logrotate policy).

### Removed: "enforce 10Gb active-backup membership"

The v2 repair workflow that force-removed members reporting < 10Gb is
gone. Equivalent explicit operations:

```bash
bond-manager show bond0                      # see member speeds
bond-manager remove-member bond0 ens3f0      # remove the slow one
bond-manager swap-member bond0 --old ens3f0 --new ens1f2   # or replace it
```

Set `MIN_SPEED_MBPS` in the config to be warned when selecting a member
below your standard.

## Suggested migration steps

```bash
# 1. Install v3 alongside your existing state (config/backups are reused)
install -m 0755 bond_manager.sh /usr/local/sbin/bond-manager

# 2. Preflight: tool availability, NM state, protection tier, config pickup
bond-manager doctor
bond-manager config show          # confirm your v2 keys took effect

# 3. Verify v3 sees your existing bonds correctly (read-only)
bond-manager list
bond-manager show bond0
bond-manager verify bond0

# 4. Take a v3 snapshot (with manifest) as the new baseline
sudo bond-manager snapshot create

# 5. Update JSON consumers and monitoring exit-code handling (see above)

# 6. Optionally remove the old script
rm -f /usr/local/sbin/bond_manager
```
