# The safety model

bond-manager assumes the worst realistic case: you are root over SSH on a
production machine, the change you are about to make touches the network
that carries your session, and something — the switch config, a typo, the
driver — is about to go wrong. This document describes exactly what
protects you, when, and what to do afterwards.

## The transaction

Every mutating command (`create`, `modify`, `add-member`, `remove-member`,
`swap-member`, `remove`, `vlan add/modify/remove`, `clone`, `repair`) runs
through one engine (`bm::plan::apply`):

```
build plan ──► acquire lock ──► refuse if a change is already pending
      │
      ▼
probe protection tier ──► SSH egress guard ──► render plan ──► confirm
      │
      ▼
snapshot ──► arm protection ──► execute steps ──► verify
                                     │              │
                              step failed      verify failed
                                     │              │
                                     ▼              ▼
                                  rollback (exit 5)
                                                    │ verify passed
                                                    ▼
                                          re-budget the window
                                                    │
                                                    ▼
                              commit gate: commit / rollback / extend
                              (auto-rollback at the deadline if neither)
```

Notes on ordering that matter:

- The **plan is rendered before anything executes** — as the literal
  `nmcli` commands each step performs. With `--dry-run` the rendering is
  the entire run: no root, no lock, no snapshot, no writes of any kind.
- The **snapshot precedes the first mutating step**; if snapshot creation
  fails, the change is aborted before anything happened.
- **Protection is armed after the snapshot and before the first step**, so
  there is no window in which a change exists without a way back.
- If arming falls back to a weaker tier (e.g. the NM checkpoint call
  fails), the SSH egress guard is **re-evaluated under the real tier**
  before any step runs. If the guard refuses at that point, the protection
  armed a moment ago is disarmed (a commit of zero changes) so nothing can
  fire later against a host that was never changed.
- Applying a plan consumes real time — each activation may take up to
  `ACTIVATE_TIMEOUT`, and verification waits up to `LINK_SETTLE_TIMEOUT`.
  Once verification passes, the **rollback deadline is re-budgeted to a
  full window**, so the operator always gets the whole documented interval
  to decide instead of whatever was left of it. On tier 1 this is a
  `CheckpointAdjustRollbackTimeout` call; on tier 2 the timer is cancelled
  and re-armed.
- Every mutating invocation takes the same `flock` — the change commands
  and `commit`, `rollback`, `snapshot create`, `snapshot restore`,
  `snapshot prune` alike. All of them also honor `--dry-run`, which reports
  what would happen and writes nothing.

## The three protection tiers

`bm::ckpt::probe_tier` picks the strongest tier the host supports;
`doctor` reports which one you will get.

### Tier 1 — `checkpoint` (NetworkManager D-Bus checkpoints)

Used when `busctl` is present and NetworkManager answers a D-Bus ping
(and `--no-checkpoint` was not given). Before the first step, the engine
calls `CheckpointCreate` on `org.freedesktop.NetworkManager` with the
rollback timeout set to the window and flags
`DELETE_NEW_CONNECTIONS | DISCONNECT_NEW_DEVICES`.

This is the only tier whose rollback is **server-side**: NetworkManager
itself restores device *and* profile state if the checkpoint is never
destroyed — no bond-manager process needs to survive. If the change cuts
your SSH session, kills the terminal, or the box becomes unreachable, NM
reverts everything at the deadline on its own. The flags are why a rollback
undoes a *create*: connections added after the checkpoint are deleted and
newly-connected devices are disconnected, not merely "restored".

`commit` calls `CheckpointDestroy` (keep the changes); `rollback` calls
`CheckpointRollback`; the interactive gate's `e` key calls
`CheckpointAdjustRollbackTimeout` to add 300 seconds.

**If `CheckpointDestroy` fails, the commit is not reported as success.**
A checkpoint that no longer exists means NetworkManager already used it —
the rollback timeout expired and the change was reverted server-side.
`commit` (and the `c` key in the gate, and the `--yes` auto-commit) then
prints that the checkpoint was already gone and that the change has most
likely been rolled back, clears the pending state, and exits **5**. Check
what actually happened with `bond-manager status`.

### Tier 2 — `deadman` (transient systemd timer)

Used when checkpoints are unavailable but `systemd-run` exists, and always
when you pass `--no-checkpoint`. Before the first step:

```
systemd-run --collect --unit bond-manager-deadman-<pid>-<epoch> \
    --on-active=<window>s  <bond-manager> rollback --snapshot <ID> --deadman --yes
```

If you never commit, the timer fires and restores the pre-change snapshot,
then reloads NetworkManager. `commit` stops the timer unit. This tier
survives losing your session (systemd runs the rollback), but it is weaker
than tier 1: the rollback is profile-level (snapshot restore + reload), and
it depends on the timer actually firing on a functioning system.

The timer runs bond-manager from systemd, with no shell and no working
directory, so the tool refuses to arm a deadman timer unless the path it
was invoked as is an executable file — arming protection that could never
run is worse than honestly falling back to tier 3. (That path is resolved
from `$0`, the entrypoint actually invoked.) A timer that fires after the
operator already committed or rolled back finds no pending state and does
nothing.

### Tier 3 — `snapshot` (manual)

Used when neither busctl nor systemd-run is available. The tar snapshot is
taken (it always is, in every tier), but nothing automatic will revert the
change — the interactive gate offers only commit/rollback with no
countdown, and if you lose your session you must run
`bond-manager rollback` yourself (from a console if need be).

### The window

The auto-rollback window is `ROLLBACK_WINDOW` (default 120 s), overridable
per-invocation with `--rollback-window S` (10–86400). The window is armed
before the first step and **re-budgeted to its full length once
verification passes**, so the time the apply itself consumed does not come
out of your decision time. With `--yes` the change is committed immediately
after verification passes — use `--yes` only when you have out-of-band
access or high confidence.

## The SSH egress guard

Before applying, the engine resolves which device carries the current SSH
session and compares it against every device the plan touches: the bond,
its **current members**, and its **VLAN interfaces**. That list is built
from live state for changes to an existing bond (`modify`, `add-member`,
`remove-member`, `swap-member`, `remove`), because an operator whose
session rides `bond0.120` must be warned about a change to `bond0` just as
much as one riding `bond0` itself.

Resolving the session's device works under `sudo`. The peer address is
taken from the first of these that is available, then handed to
`ip route get`:

1. `$SSH_CONNECTION` — set by sshd, but stripped by `sudo`'s default
   `env_reset`, which is exactly how this tool is normally run;
2. `$SSH_CLIENT` — the same information, and often preserved where
   `SSH_CONNECTION` is not;
3. the `who(1)` login record for this session's controlling terminal, from
   which only a literal IP address is accepted (a hostname is useless to
   `ip route get`).

If none of the three yields a peer, the session is treated as not being
over SSH and the guard stays quiet.

- **Tier 1 (checkpoint):** you get a warning and the change proceeds —
  NM's server-side rollback protects you even if the session dies.
- **Tier 2/3:** the change is **refused** (exit 3) with an explanation,
  because the protection is not guaranteed to fire on a machine you can no
  longer reach. Use a console, or pass `--force-unsafe` to accept the risk
  explicitly.

## The pending-change state file

Everything a second session needs lives in
`/run/bond-manager/pending.state` (`$BM_RUN_DIR`), written when protection
is armed:

```
tier=checkpoint
checkpoint_path=/org/freedesktop/NetworkManager/Checkpoint/1
deadman_unit=
snapshot=20260825-141530
deadline=1787921730
created=2026-08-25T14:15:30+0000
pid=41337
summary=create bond bond0 (802.3ad, members ens1f0,ens1f1)
```

Because the state is on disk, **commit and rollback work from a brand-new
session** after a disconnect:

```bash
bond-manager doctor      # shows: PENDING CHANGE: <summary> (auto-rollback in Ns)
bond-manager commit      # keep it: destroys checkpoint / cancels timer, clears state
bond-manager rollback    # revert it: checkpoint rollback, else timer cancel + snapshot restore
```

While a change is pending, any new mutating command is refused (exit 3)
until you commit or roll back — two half-applied changes cannot stack.

`rollback` degrades gracefully: if the checkpoint has already expired (NM
rolled back on its own), `CheckpointRollback` fails and the command falls
back to restoring the recorded snapshot — which is the same pre-change
state — then clears the pending state. Running `rollback` after the
deadline is therefore safe and is the standard way to clean up.

`rollback --snapshot ID` (and `snapshot restore [ID]`, which is the same
code path) restores a *named* snapshot rather than the pending change. If a
change is pending when you do that, its protection is **disarmed first** —
otherwise a checkpoint or deadman timer would still be armed against state
it no longer describes and could fire later on top of the restored
profiles. With no snapshots at all, the command stops with a precondition
error (exit 3) instead of a confusing failure.

A deadman timer that fires when nothing is pending — because the operator
already committed or rolled back — logs that fact and does nothing.

One honest caveat: `/run` is tmpfs. A reboot clears the pending state (and
any checkpoint/timer with it). After a reboot, work from
`bond-manager snapshot list` / `diff` / `restore` instead.

## Verification, and what failure does

After the last step, the verification gate checks **kernel ground truth**,
not nmcli's opinion. Each check is recorded as pass, warn, or FAIL, and
only a FAIL rolls back:

**Checks that FAIL (and roll the change back, exit 5)**

- the bond is absent from `/proc/net/bonding`;
- the bond's operstate does not reach `up` within `LINK_SETTLE_TIMEOUT`;
- the mode is not the mode that was asked for;
- an expected member is not enslaved within `LINK_SETTLE_TIMEOUT`;
- a member that the operation was supposed to remove is still enslaved.

**Checks that only WARN (printed for your commit decision)**

- a member is enslaved but its MII status is not `up` — a link can lag a
  correct change;
- 802.3ad: no LACP partner detected (switch side not aggregating yet);
- active-backup: no currently-active member reported;
- the IP-bearing interface has no address yet (DHCP still negotiating);
- the gateway does not answer ping through the changed interface — the
  probe runs *through the changed interface* (never per-member `ping -I`,
  which is meaningless on enslaved NICs that carry no IP).

**Relaxed expectations.** Some operations legitimately leave the bond
down, and demanding `up` there would fail a correct change and roll it
back. For `--no-activate` (create, clone) and for removing the *last*
member of a bond, verification runs with the expectation "any state": a
bond that is missing or not up is reported as a warning instead of a
failure. Removing members additionally asserts the named members are no
longer enslaved, and `swap-member` verifies both halves of the swap — the
new member present, the old one gone — so a relaxed state expectation
never means "check nothing".

Any FAIL — or any failed plan step — triggers an immediate rollback
through the armed tier and exits 5. `bond-manager verify BOND` re-runs the
same checks on demand; it is read-only (no root, no lock, no writes) and
exits 1 if a check fails.

If verification passes, the window is re-budgeted to its full length and
the commit gate takes over:

- **Interactive:** a live countdown with `c` (commit), `r` (rollback), and
  `e` (extend by 300 s, tier 1 only). Reaching the deadline means the
  change has been reverted (exit 5). On tier 3 there is no countdown —
  nothing will revert the change on its own — so the gate offers only
  commit and rollback.
- **`--yes`:** committed immediately.
- **No TTY and no `--yes`:** the command exits **6** with protection still
  armed and prints the commit/rollback instructions — an automation
  wrapper must then decide. On tiers 1 and 2 the auto-rollback fires at the
  deadline if it does not; on tier 3 the message says plainly that
  *nothing* will roll the change back automatically, and the change simply
  stays pending until someone runs `commit` or `rollback`.

In every one of those paths, a commit that finds the checkpoint already
destroyed exits 5 rather than claiming success (see tier 1 above).

## What a snapshot covers

NetworkManager's default profile storage differs across the supported
releases, so a snapshot covers **both** stores:

| Store | Directory (override) | Used by |
|---|---|---|
| keyfile | `/etc/NetworkManager/system-connections` (`$BM_CONN_DIR`) | RHEL 9+ |
| ifcfg | `/etc/sysconfig/network-scripts` (`$BM_IFCFG_DIR`) | RHEL 8's `ifcfg-rh` plugin |

A snapshot without the ifcfg store would silently fail to protect a RHEL 8
host: the archive would be taken, the restore would report success, and
none of the profiles that actually configure the machine would be in it.

Each snapshot ID therefore writes up to three files into
`/var/backups/bond_manager/`:

```
conn-<ID>.tar.gz          the keyfile store
conn-<ID>.ifcfg.tar.gz    the ifcfg store (only when it holds NM files)
conn-<ID>.manifest        sha256 of every file in both stores
```

The manifest names both directories in its header (`keyfile_dir=`,
`ifcfg_dir=`) and lists keyfile profiles as `file=<sha256>\t<path>` and
ifcfg files as `ifcfg_file=<sha256>\t<path>`.

In the ifcfg directory, **only NetworkManager's own file patterns** are
read, archived, restored, or considered stray:

```
ifcfg-*   keys-*   route-*   route6-*   rule-*   rule6-*      (top level only)
```

Everything else that lives there on RHEL 8 — `ifup*`/`ifdown*`, the
`network-functions` helpers, anything an admin dropped in — is never
touched by a snapshot or a restore.

## Reconciling snapshot restore

Restore is not a blind untar (that was the v2 bug that made rollback
unable to undo a create):

1. `snapshot diff ID` (also shown before any interactive restore) reports
   exactly what a restore would do: profiles created since the snapshot
   (**deleted** on restore, keyfile and ifcfg listed separately), removed
   since (**recreated**), and modified since (**reverted**).
2. With `--dry-run`, restore returns after printing that diff and before
   any write at all — including the pre-restore snapshot, which is itself
   a real write.
3. Restore first snapshots the *current* state (`pre-restore-of-ID`), so a
   restore is itself undoable; if that snapshot cannot be taken, the
   restore refuses to run. The snapshot being read is protected from
   pruning while this happens.
4. Stray files — present now, absent from the manifest — are deleted in
   both stores, then each archive is untarred, SELinux contexts are
   restored (`restorecon`), and NetworkManager reloads its profiles.
5. **The extraction is checked.** If `tar` fails, the restore does not
   report success: it dies with an error naming the pre-restore snapshot,
   because at that point the strays are already deleted and the host may
   hold fewer profiles than either state. Recover with
   `bond-manager snapshot restore <pre-restore-ID>`.

v2-era archives have no manifest; they are listed as `legacy` and restore
as a plain overlay (no stray reconciliation possible).

## Pruning, and snapshots that must not be pruned

Snapshots are pruned to the `MAX_BACKUPS` (default 10) newest — after
every new snapshot, and on demand with `bond-manager snapshot prune`.

Pruning the snapshot a rollback depends on would destroy the only way
back, so these are never deleted:

- the snapshot recorded in the pending-change state file
  (`/run/bond-manager/pending.state`);
- the snapshot a restore is currently reading;
- the snapshot just created (a fresh snapshot cannot prune itself).

Protected snapshots also **do not consume the retention budget**: with
`MAX_BACKUPS=10` and one pinned by a pending change, you still keep ten
prunable snapshots plus the pinned one, rather than nine.

## Failure matrix

| Failure | What protects you | Outcome |
|---|---|---|
| Plan step fails mid-apply | Engine rolls back through the armed tier | Pre-change state, exit 5 |
| Verification fails | Same | Pre-change state, exit 5 |
| Change severs your SSH session — tier 1 | NM checkpoint expires server-side | NM restores device + profile state at the deadline; run `rollback` afterwards to clear the pending state |
| Change severs your SSH session — tier 2 | Deadman timer | systemd runs `bond-manager rollback --snapshot ID`; profiles restored, NM reloaded |
| Change severs your SSH session — tier 3 | Guard refused this upfront (unless `--force-unsafe`) | You need console access; run `bond-manager rollback` there |
| bond-manager process killed (SIGKILL, OOM) mid-window | Protection is armed *outside* the process | Checkpoint/timer fires at deadline; or commit/rollback from a new session via the state file |
| Operator walks away without confirming | Auto-rollback deadline | Change reverted (tier 1/2); tier 3 waits for a manual decision |
| Second admin starts a change concurrently | `flock` in `/run/bond-manager` | Second invocation exits 4, naming the holder |
| Verification passes but the app is broken anyway | Commit gate window | Press `r`, or `bond-manager rollback` before/after commit (post-commit: snapshot restore) |
| Bad change committed days ago | Snapshots | `snapshot list` → `snapshot diff ID` → `snapshot restore ID` |
| Host reboots mid-window | Snapshot on disk (state in `/run` is lost) | Verify with `status`; restore the snapshot manually if needed |
| `commit` runs after the window expired (tier 1) | `CheckpointDestroy` fails — the checkpoint is gone | Reported as exit 5 with "most likely rolled back", never as success; confirm with `status` |
| Apply itself eats the window (slow activations) | Window re-budgeted after verification | The full window is available for the commit decision |
| Retention would delete the snapshot a pending change needs | Prune protection | Pending/in-use snapshots are never pruned and do not use up `MAX_BACKUPS` |
| `tar` fails while extracting a restore | Pre-restore snapshot | The restore fails loudly and names the pre-restore snapshot to recover from — it does not report success |
| Host stores profiles as ifcfg (RHEL 8) | Snapshots cover both stores | `/etc/sysconfig/network-scripts` NM files are archived and restored alongside the keyfile store |

## Recovery runbook

Scenario: a change was applied, something broke, and the session that drove
it is gone.

1. **Get back on the machine** — reconnect SSH; if the change killed your
   path, use the console (iLO/iDRAC/virsh). If you cannot get on at all and
   the host was tier 1 or 2, wait out the window (default 120 s): the
   rollback fires without you, and connectivity via the previous
   configuration should return.
2. **Assess:**

   ```bash
   bond-manager doctor        # pending change? which tier? time remaining?
   bond-manager status        # health verdicts with reasons; exit 0/10/11
   bond-manager diagnose bond0 --extended
   ```

3. **If the change is pending and the system is actually fine** — the
   breakage was elsewhere — commit before the deadline:

   ```bash
   bond-manager commit
   ```

4. **If the change is pending and bad**, revert it:

   ```bash
   bond-manager rollback
   ```

   This uses whichever tier is armed and falls back to the recorded
   snapshot. It is safe to run even if the auto-rollback already fired —
   it converges on the same pre-change state and clears the pending file.
5. **If there is no pending state** (already committed, or the host
   rebooted), work from snapshots:

   ```bash
   bond-manager snapshot list
   bond-manager snapshot diff 20260825-141530       # review the blast radius first
   bond-manager -n snapshot restore 20260825-141530 # rehearse: prints the diff, writes nothing
   bond-manager snapshot restore 20260825-141530    # takes a pre-restore snapshot itself
   ```

   If the restore fails while extracting, it says so and names the
   pre-restore snapshot it took a moment earlier — restore *that* to get
   back to where you started.

6. **Confirm recovery:**

   ```bash
   bond-manager verify bond0
   bond-manager status
   ```

7. **Collect evidence for the postmortem** while it is fresh:

   ```bash
   bond-manager bundle --redact   # /var/log/bond_manager/support/support_<ts>.tar.gz
   ```

   The bundle includes nmcli state, ip link/addr/route, the NM journal,
   `/proc/net/bonding/*`, per-bond diagnostics, the tool log, and a file
   manifest; `--redact` masks IPs and MACs for tickets leaving the site.

Every mutating run is logged to `/var/log/bond_manager.log` (and the
journal via `logger`) with an `op=` tag per operation — the timeline of
what the tool did, step by step, is there.
