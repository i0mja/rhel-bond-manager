# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2026-09-25

Anyone should be able to pick this tool up at 2am and not get hurt. This
release rebuilds the menus in pure bash and makes every screen, prompt and
error explain itself in plain words. The safety engine is unchanged except
for the fixes below; exit codes (except one, see *Changed*) and the JSON
schema are unchanged.

### Added

- **Built-in guided menus** (`bond-manager` on a terminal, or
  `bond-manager tui`), written in plain bash: no whiptail, nothing to
  install.
  - A home dashboard shows every bond's health, its ports (link, speed,
    active port), the port carrying *your SSH connection*, the safety net
    this server gives you, and a live banner when a change is waiting to be
    kept.
  - Jobs are named in plain language, each with a step-by-step wizard:
    *Check my bonds*, *Move a bond to a new switch* (including the LACP
    cross-switch situation), *Build a new bond*, *Change a bond* (add/remove
    port, mode, preferred port, IP, MTU, VLANs, advanced options, clone,
    delete), *Fix a bond that looks wrong*, *Undo & safety*, *Tools* and
    *Help*.
  - Choices come from lists with a plain note on every item. Typed values
    are validated on the spot with a message that says how to fix them.
  - A review screen summarises every change in plain words, warns early
    when it touches the SSH connection, and shows the equivalent command
    line.
  - **Practice mode** (key `p`) runs every job as a dry run. It is forced
    on, with an explanation, when changes are impossible (not root,
    NetworkManager down).
  - A result panel says what happened and what to do next.
  - Arrow keys, `j`/`k`, `1`-`9`, Esc/`q` for back, and Space for check
    boxes. Numbered prompts are used on serial consoles, dumb terminals,
    pipes and with `--plain`. Output falls back to ASCII without UTF-8 (or
    with `BM_ASCII=1`), and `NO_COLOR` is honored.
- **IPv6 in the menus**: *Change a bond → IP address* and a VLAN's
  address offer IPv4 or IPv6. For IPv6 the options are SLAAC, DHCPv6, a
  fixed address with gateway and DNS (validated as you type), or off. A new
  VLAN can get both.
- **`bond-manager nics [--all]`**: every network port with its link state,
  speed, bond, addresses and a plain verdict ("free - good to use", "no
  link - cable or switch port?", "has an IP - probably in use", "carries
  your SSH connection"), plus a ready-made `create` example. It is
  read-only, needs no root, and never calls nmcli.
- **`bond-manager help [COMMAND|TOPIC]`** and **`COMMAND --help`**: plain
  English with copy-paste examples, always starting from a `-n` preview.
  The topics are `basics`, `modes`, `lacp`, `safety`, `practice`, `moving`,
  `glossary`, `keys` and `exit-codes`.
- **"Next step" hints** on errors, on their own line under the unchanged
  `ERROR:` line:
  - a missing port gives the closest name plus `bond-manager nics`;
  - a port already in another bond says how to free it;
  - a mistyped mode gives its alias (`lacp` -> `802.3ad`);
  - a missing bond gives the closest bond;
  - a bond NetworkManager doesn't manage is explained;
  - a non-root run gives the same command with `sudo`;
  - a malformed address shows the expected format.
- **"Did you mean"** suggestions for unknown commands (by spelling, and by
  meaning: `move` suggests `swap-member`, `undo` suggests `rollback`) and
  for unknown flags. A stray mode, port list or address typed without its
  flag gets a hint too (`did you mean '--mode active-backup'?`).
- `--help` output now leads with "New here?" and a *Common tasks* cheat
  sheet. `doctor` ends with the safety net in plain words and a next step.
- [docs/GUIDE.md](docs/GUIDE.md): the beginner's guide.
- **A tour in the README**: an animated terminal at the top, and 30 real
  screens in eight chapters that open with a click. `make tour` records
  them from the real menus against a fake server (`build/tour/`), so they
  are never out of date; the same screens are published as a click-through
  page on GitHub Pages.

### Changed

- **The commit gate is a clear box** with a live countdown that changes
  colour as time runs out. `K` keeps the change, `U` undoes it, `E` adds 5
  minutes; `c`/`r`/`e` still work. Other keys explain what to press.
- **`yes/no` questions stay typed answers** (y + Enter). Type-ahead is
  discarded before the gate, so a stray key never answers it.
- **A flag given without its value** (`--mode` at the end of the line, or
  followed by another flag) is now a usage error, exit 2 with an example.
  It used to exit 1 with a raw shell message.
- **An unknown command** prints a suggestion and a pointer to `help`
  instead of dumping the whole usage text. It still exits 2.
- **The deadman timer is armed with `AccuracySec=1s`**, so it fires at the
  deadline instead of up to a minute late.
- **whiptail is no longer used**, and `doctor` no longer lists it.
- **`bm::main` moved to `lib/99-main.sh`** so that dispatching to the menus
  (`lib/95-tui.sh`) is a downward call. The plain-English text lives in
  `lib/45-help.sh`.

### Fixed

- **Deadman tier: an unanswered change was never undone.** When the
  countdown ran out at the interactive prompt, the gate announced "the
  change has been reverted" and cleared the pending state. The deadman
  timer then either could not take the lock (the gate still held it) or
  found nothing pending, so nothing was reverted. The gate now restores the
  snapshot itself on that tier. If the restore reports problems, it says
  so.
- **The commit gate spun at 100% CPU** when its terminal reached end of
  input (e.g. the SSH connection went away mid-countdown). End of input now
  keeps protection armed, prints how to commit or roll back from another
  session, and exits 6.
- **Menus:**
  - Committing or rolling back a waiting change from the menus kept the
    lock open for the rest of the session, so every later change failed
    with "another instance is running".
  - An error in a menu action (including "must be run as root") exited the
    whole program; now every action runs isolated and the menus explain
    the result.
  - A validation error ended a wizard with "exit code 2 (see log)"; the
    error and its next step are now shown, and wizards validate while you
    type.
  - Non-root users filled in a whole wizard before being told they needed
    root. Changes are now checked up front, with practice mode offered.
  - The plan could be hidden behind the whiptail "Apply this plan?"
    dialog; it now stays on screen above the question.
- **Every `init` and `bundle` leaked a `/tmp/bond-manager.XXXXXX`
  directory.** The scratch directory was created inside `$(...)`, so the
  exit cleanup never knew about it. It is now created in the running shell
  (and in a menu action's own subshell, which cleans up after itself).
- **Plain numbered prompts:** `010` picked item 8 (bash read it as octal)
  and `08`/`09` printed a raw bash error; numbers are now always decimal.
  The home menu listed Quit twice, and its `?) help` hint disappeared when
  the current directory held one-character file names.
- **`nics`:** on an 80-column terminal the NOTE column spilled into the
  next row. Columns are now as wide as their content and a long note wraps
  under its own column.
- **SSH over a VLAN on a plain port was not protected.** With the session
  on `eth2.100`, `eth2` was offered as "free" by `nics` and the menus, and
  the SSH guard let a change put it into a bond, cutting the session. The
  guard now treats the port under the session's VLAN as carrying it
  (refused below the checkpoint tier, warned about on it), and `nics` and
  the menus say so.
- **The commit gate's `E` (+5 minutes)** extended NetworkManager's timer
  but not the saved deadline, so the menus, `doctor` and other sessions
  counted down to an undo 5 minutes too early.
- **The plain commit gate** (`--plain`, serial consoles) took a key typed
  while the change was running as its answer, before the verification
  result was shown. Type-ahead is now discarded there too.
- **Removing or replacing a port with no link** in the menus warned that
  it "will not carry traffic" and asked to confirm; that warning is now
  only given when adding a port.
- **`--dns6` was never validated** (`--dns4` was). A bad IPv6 DNS server
  now fails up front with the expected format, instead of reaching nmcli.
- **The CLI equivalent shown for `add-member` / `remove-member`** used
  `--members`, which those commands reject. One function now builds the
  equivalent for every subcommand, quoting values that need it.

## [3.0.0] - 2026-08-25

Ground-up rebuild. The tool is now compiled from modules in `lib/` into the
single-file artifact `bond_manager.sh` by a gated, deterministic build
(`make dist`). See [docs/MIGRATION.md](docs/MIGRATION.md) for the v2.1 → 3.0
migration guide.

### Added

- **Transaction engine**: every change runs as plan → snapshot → arm
  protection → execute → verify → commit-or-rollback. The plan is rendered
  as literal `nmcli` commands before anything executes.
- **Three protection tiers** with automatic probing and fallback:
  NetworkManager D-Bus checkpoints (server-side auto-rollback that survives
  losing the SSH session; created with `DELETE_NEW_CONNECTIONS |
  DISCONNECT_NEW_DEVICES` so a rollback undoes creates), a transient
  systemd deadman timer, and tar snapshots. Auto-rollback window is
  configurable (`ROLLBACK_WINDOW`, `--rollback-window`).
- **Pending-change state** in `/run/bond-manager/pending.state`:
  `commit` and `rollback` work from a second SSH session after a disconnect.
- **SSH egress guard**: changes touching the device carrying the current SSH
  session warn under checkpoint protection and are refused under weaker
  tiers unless `--force-unsafe` is given.
- **Verification gate** (`verify`, and automatic after every change) reading
  kernel ground truth. Failing checks — bond present and up (unless the
  change legitimately leaves it down), mode as requested, members enslaved,
  removed members gone — roll the change back (exit 5). Advisory checks —
  member MII state, LACP partner presence, addresses assigned, gateway
  reachable through the changed interface — are reported as warnings, since
  a link or DHCP lease can lag a correct change.
- New subcommand CLI: `list`, `show`, `status`, `diagnose`, `doctor`,
  `create`, `modify`, `add-member`, `remove-member`, `swap-member`,
  `remove`, `vlan add|modify|remove|list`, `clone`, `repair`, `verify`,
  `snapshot create|list|diff|restore|prune`, `commit`, `rollback`, `bundle`,
  `init`, `config`, `completion bash`.
- Typed exit codes: 0 ok, 1 error, 2 usage, 3 precondition, 4 locked,
  5 verify-failed-rolled-back, 6 applied-but-unconfirmed, 10 degraded,
  11 down — `status` doubles as a monitoring probe.
- Per-mode bond option matrix: options and cross-option constraints
  (`miimon` vs `arp_interval`, `primary` only for
  active-backup/tlb/alb, ARP monitoring rejected for 802.3ad/tlb/alb) are
  validated before anything runs.
- Full IPv6 support (`--ip6`, `--gw6`, `--dns6`), MTU (`--mtu`),
  multiple static addresses, per-VLAN IP settings
  (`--vlan 'VID:ip4=..;gw4=..;dns4=..;ip6=..'`).
- Snapshots of **both** NetworkManager profile stores — the keyfile store
  (`/etc/NetworkManager/system-connections`) and RHEL 8's ifcfg store
  (`/etc/sysconfig/network-scripts`, `ifcfg-*`/`keys-*`/`route-*`/
  `route6-*`/`rule-*`/`rule6-*` only) — with manifests (sha256 per file),
  `snapshot diff`, and a reconciling restore that deletes files created
  after the snapshot in both stores.
- `doctor` environment preflight including the protection tier the host
  will get and any pending change.
- Support bundles gained a file manifest and `--redact` (masks IPs/MACs for
  off-site tickets).
- Health verdicts (healthy/degraded/down) with reasons: member MII, speed
  and duplex mismatches, LACP partner presence and churn state.
- `--json` for `list`/`show`/`status`: versioned (`schema_version: 1`),
  RFC 8259-correct documents.
- Bash completion (`completion bash`), a man page (`docs/bond-manager.8`),
  `Makefile` (dist/check-dist/lint/test/check/man/install), and CI that
  verifies the committed artifact matches the `lib/` sources.
- Every filesystem root is overridable via environment
  (`BM_PROC_ROOT`, `BM_SYS_ROOT`, `BM_CONN_DIR`, `BM_IFCFG_DIR`, `BM_CONF`,
  `BM_LOG_FILE`, `BM_BACKUP_DIR`, `BM_SUPPORT_DIR`, `BM_RUN_DIR`,
  `BM_LOGROTATE_CONF`),
  and sourcing `bond_manager.sh` defines all functions without running
  main — the test suite drives internals against fixtures and PATH shims.

### Changed

- **Breaking:** the JSON output format. The v2 format was structurally
  broken (see Fixed); consumers must adopt the new versioned schema. The
  legacy `--export-json PATH` flag still exists but now writes the new
  schema-versioned inventory document.
- The interactive menu was replaced by a subcommand CLI + TUI hybrid:
  running with no arguments on a terminal starts the TUI, which drives the
  same workflow code as the CLI and prints the CLI equivalent of every
  action before applying it.
- New port profiles are named `bond-port-<nic>` (v2: `<bond>-slave-<nic>`),
  and — unlike v2 — no operation depends on profile names: ports and VLANs
  are discovered via `connection.master`/`vlan.parent` and addressed by
  UUID.
- The config file is now parsed line-by-line against a key allowlist
  instead of being sourced (see Fixed). v2.x key names are honored
  verbatim; new keys: `ROLLBACK_WINDOW`, `ACTIVATE_TIMEOUT`,
  `LINK_SETTLE_TIMEOUT`, `MIN_SPEED_MBPS`.
- Read-only commands (`list`, `show`, `status`, `diagnose`, `doctor`,
  `config`, `verify`, `completion`) no longer require root and write
  nothing; file logging is enabled only for mutating commands.
- `remove` requires typing the bond name to confirm; removing the last
  member of a bond requires explicit confirmation.
- `swap-member` adds the replacement and waits for it to enslave before
  removing the old member, so redundancy never drops below the starting
  level.
- Snapshots are pruned to `MAX_BACKUPS` with their manifests; v2 archives
  without manifests are still listed (as `legacy`) and restorable.
- The default NIC blocklist additionally excludes `cali.*`, `flannel.*`,
  and `cni.*`; the allowlist covers `eno`, `em`, and `p<N>p<M>` naming.

### Changed

- `modify --mode` now drops bond options that are only valid in the previous
  mode, naming them, instead of failing validation. Switching an 802.3ad bond
  to `active-backup` (needed when migrating between two switches that are not
  in one LAG domain) no longer requires hand-listing `--del-opt lacp_rate
  --del-opt xmit_hash_policy`. Options supplied in the same invocation are
  still validated strictly, so a contradictory request is still an error.

### Fixed

All of the following are verified against the v2.1.0 script
(`git show a3d4d89:bond_manager.sh`):

- `bond_context_text` was called in five workflows (edit, swap, clone,
  rebuild-slaves, enforce-10Gb) but never defined anywhere: every one of
  those menu entries failed with `command not found` and displayed an empty
  bond context. The v3 build gates reject any `bm::` function that is
  called but not defined, so this class of bug cannot ship again.
- The config file was sourced as shell (`. "$CONFIG_FILE"`), executing
  whatever a writable `/etc/bond_manager.conf` contained as root. It is now
  parsed against a key allowlist with per-key value validation.
- Rollback restored a backup by untarring **over** the current profiles
  without removing files created after the backup — restoring after a bond
  *create* left the new bond in place, i.e. rollback could not undo a
  create. v3 restores are manifest-reconciling (strays are deleted, with
  the diff shown first), and tier-1 checkpoints delete new connections
  server-side.
- `--dry-run` still wrote the config file, the logrotate policy, the log
  file, and created backups (the v2 help even said so: "The tool may still
  write logs/config and create backups"). A v3 dry run executes nothing and
  writes nothing, and needs neither root nor a running NetworkManager.
- `nmcli -t` output was split with `awk -F:`, which corrupts fields
  containing nmcli-escaped colons (`\:` — legal in connection names) and
  breaks on `\\`. v3 parses terse output with an escape-aware state
  machine.
- Member removal deleted profiles by the `${bond}-slave-${nic}` naming
  convention, silently missing any port profile not created by the tool
  itself. v3 discovers ports via `connection.master` and deletes by UUID.
- Bond ports were created with the deprecated `nmcli connection add type
  bond-slave` syntax; v3 uses `type ethernet ... master <bond> slave-type
  bond`.
- `--status` required root and, before printing anything, wrote to `/etc`
  (installing the default config and logrotate policy on first run). v3
  `status` is read-only and unprivileged.
- No locking: two concurrent instances could interleave nmcli changes and
  backups. v3 serializes concurrent changes through a `flock` and exits 4
  (naming the holder) when the lock is taken.
- Diagnostics pinged through each member with `ping -I <member>`, which is
  meaningless for enslaved NICs that carry no IP (and, in active-backup,
  cannot even transmit unless active). v3 tests reachability through the
  bond or its VLAN interfaces, where the IP actually lives.
- JSON export was structurally unsafe: the sed-based escaper's newline
  substitution could never match (sed strips the newline before matching),
  multi-line values were embedded raw, control characters were passed
  through, and `ip -json` output was injected verbatim. v3 emits
  RFC 8259-escaped, schema-versioned documents built by a dedicated
  emitter.
- After every successful change the tool asked "Change complete. Restore
  the most recent backup now?" — one accidental "yes" immediately reverted
  the change just applied. Replaced by the commit gate: the operator
  confirms (or the change auto-rolls-back), and rollback is its own
  explicit command.

### Fixed — post-review hardening

Found by an adversarial review of the v3 tree before release, and fixed in
`lib/` before 3.0.0 shipped:

**Snapshots and restore**

- Snapshots covered only the keyfile store
  (`/etc/NetworkManager/system-connections`). On RHEL 8, where
  NetworkManager's `ifcfg-rh` plugin keeps profiles in
  `/etc/sysconfig/network-scripts`, that archive captured nothing relevant
  and a "successful" restore protected nothing. Snapshots now cover both
  stores: a second archive `conn-<ID>.ifcfg.tar.gz`, `ifcfg_file=` lines in
  the manifest, and stray detection plus restore for both. Only
  NetworkManager's own patterns are touched there (`ifcfg-*`, `keys-*`,
  `route-*`, `route6-*`, `rule-*`, `rule6-*`, top level) — the legacy
  `ifup*`/`ifdown*` helpers sharing that directory are never read or
  written.
- Restore ignored `tar`'s exit status: an extraction that failed *after*
  the stray profiles had already been deleted was still reported as a
  successful restore, leaving the host with fewer profiles than either
  state. The extraction is now checked, and a failure dies loudly naming
  the pre-restore snapshot to recover from.
- `--dry-run` on a restore took the pre-restore snapshot before deciding it
  was a dry run — a real write during a "writes nothing" run. It now
  returns after printing the diff and before any write.
- Pruning could delete the snapshot a pending change (or an in-progress
  restore) depended on, destroying the only way back. `bm::snap::prune` now
  never deletes the snapshot named in the pending-state file, the one a
  restore is reading, or the one just created — and protected snapshots do
  not consume the `MAX_BACKUPS` budget, so pinning one cannot silently
  shorten retention.

**Commit, rollback and the protection tiers**

- `commit` reported success when `CheckpointDestroy` failed. A checkpoint
  that is already gone means NetworkManager most likely rolled the change
  back when the window expired — the operator was told their change was
  live when it was not. That case now reports "most likely rolled back" and
  exits 5, from `commit`, from the interactive gate's `c` key, and from the
  `--yes` auto-commit.
- Applying a plan consumes real time (each activation up to
  `ACTIVATE_TIMEOUT`), so the operator was left with whatever remained of
  the rollback window — sometimes nothing at all on a slow bond. Once
  verification passes the deadline is now re-budgeted to a full window
  (`CheckpointAdjustRollbackTimeout` on tier 1; cancel and re-arm on
  tier 2).
- The deadman timer could be armed against a path systemd cannot execute,
  silently arming protection that would never fire. `BM_SELF` is now
  resolved from `$0` (the entrypoint actually invoked), and arming is
  refused unless that path is executable — falling back a tier instead.
- A deadman timer firing after the operator had already committed or rolled
  back is now a no-op instead of acting on state that no longer exists.
- The non-TTY message promised an auto-rollback at the deadline even on the
  snapshot-only tier, where nothing fires. It now says plainly that nothing
  will roll the change back automatically.
- The SSH egress guard aborted by dying, which skipped disarming the
  protection armed a moment earlier when the guard was re-evaluated after a
  tier fallback. It now returns a refusal and the caller disarms first.

**The SSH egress guard and verification**

- The guard resolved the session's device from `$SSH_CONNECTION` only —
  which `sudo`'s default `env_reset` strips, so under `sudo` (the normal
  way to run this tool) it silently concluded "not over SSH" and skipped
  the check. It now falls back to `SSH_CLIENT` and then to the `who(1)`
  login record for the session's terminal.
- The guard now considers the bond's **current members and VLAN
  interfaces**, not just the devices named on the command line: a session
  riding `bond0.120` is warned about a change to `bond0`
  (`modify`, `add-member`, `remove-member`, `swap-member`, `remove`).
- Operations that legitimately leave a bond down — `--no-activate`, and
  removing the last member — failed their own verification gate and were
  rolled back. They are now verified with a relaxed state expectation,
  while `remove-member` additionally asserts the removed members are no
  longer enslaved and `swap-member` verifies both halves of the swap
  (new member present, old member gone). `bm::verify::bond` gained the
  trailing `expect-state` and `absent-members` parameters this needs.
- `bond_lacp_info` read Actor/Partner Churn State with an `awk` range that
  ended at the first `Slave Interface:` line and therefore could never
  reach the per-port sections where the kernel prints them; churn state now
  actually reaches the health verdict.

**CLI behavior**

- `commit`, `rollback` and `snapshot create|restore|prune` ignored
  `--dry-run` and took no lock, so a "writes nothing" invocation could
  restore profiles and two sessions could act at once. All of them now
  honor `--dry-run` and take the single-instance lock — the man page's
  claim that every mutating invocation locks is now true.
- `rollback --snapshot ID` left a pending change's checkpoint or deadman
  timer armed against state it no longer described; it now disarms that
  protection before restoring.
- `snapshot restore` with no snapshots present now gives a clean
  precondition error (exit 3).
- `status BOND --json` ignored `BOND` and emitted the whole inventory while
  the exit code reflected only the named bond; it now emits a `bonds` array
  holding just that bond.
- The legacy `--status --export-json PATH` combination always exited 0,
  hiding a degraded or down bond from monitoring callers that used the v2
  spelling. It now propagates the health exit code (10/11).
- `modify` on a profile with no explicit `mode=` assumed `active-backup`,
  validating the new option set against the wrong matrix; a mode-less
  profile runs the kernel default, so it is now treated as `balance-rr`
  (with a note).
- `--opt` values were merged by splitting on commas, so
  `--opt arp_ip_target=10.0.0.1,10.0.0.2` turned the second address into a
  bogus option key. Merging now goes through the escape-aware options
  parser.
- `--ip6 dhcp` was mapped to `ipv6.method auto`, silently giving SLAAC
  where DHCPv6 was asked for; it now writes `ipv6.method dhcp`.
- Disabling IPv6 wrote `ipv6.method disabled`, which only exists from
  NetworkManager 1.20; it now writes `ipv6.method ignore`, which every
  supported release understands (and the rendered plan shows that).

### Removed

- The "enforce 10Gb active-backup membership" workflow (auto-removed
  members below 10Gb). Replaced by the advisory `MIN_SPEED_MBPS` warning
  plus explicit `remove-member`/`swap-member` operations.
- The post-change restore prompt (see Fixed).
- Automatic first-run writes to `/etc`: config and logrotate policy are now
  installed only by the explicit `init` command.

## [2.1.0] - 2026-02-07

- TUI reworked with clearer messages and harmonized workflows.
- Last release of the monolithic v1/v2 line; superseded by the 3.0.0
  rebuild.

## [1.1.0] - 2025-11-05

- Version bump with additional configuration options.

## [1.0.0] - 2025-07-21

- Initial release: interactive whiptail menu for bond create/edit/repair,
  profile backups, support bundles, `--status` and `--export-json`.

[3.0.0]: https://github.com/i0mja/rhel-bond-manager/releases/tag/v3.0.0
