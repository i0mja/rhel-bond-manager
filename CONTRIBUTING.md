# Contributing

bond-manager is a bash project with an unusual constraint: the deliverable
is a single reviewable file (`bond_manager.sh`) that must run on a bare
RHEL-like box with nothing but NetworkManager and the base system, while
the *source of truth* is the modular tree in `lib/`. Everything below
follows from that.

## Development setup

Requirements: bash ≥ 4.4 (the code targets 4.4, what RHEL 8 ships; do not
use 5.x-only features — CI runs the whole suite on bash 4.4.18 as well, in
the `test-bash44` job), [shellcheck](https://www.shellcheck.net/) ≥ 0.9, and
[bats](https://github.com/bats-core/bats-core) ≥ 1.10 for the test suite.

```bash
git clone https://github.com/i0mja/rhel-bond-manager.git
cd rhel-bond-manager

./bin/bond-manager --help    # dev entrypoint: sources lib/*.sh directly
make dist                    # compile lib/ -> bond_manager.sh
make check                   # check-dist + lint + test
```

`bin/bond-manager` sources the modules in numeric order and dispatches —
use it during development so you are always running your edited sources.
`bond_manager.sh` at the repo root is **generated**; never edit it by hand.
It is committed so that production hosts can consume a single file and so
CI can prove the artifact matches the sources (`make check-dist`).

## Module layering

Modules live in `lib/` with numeric prefixes that define both the source
order and the dependency direction:

```
00-core    constants, exit codes, error handling, helpers
10-log     logging
15-config  config parsing (allowlisted keys — the file is never sourced)
18-val     validators + per-mode bond option matrix
20-facts   read-only inventory from /proc, /sys, routing table
25-nm      the only module allowed to invoke nmcli
30-snap    snapshots of both profile stores (keyfile + ifcfg) + reconciling restore
33-ckpt    protection tiers (NM checkpoint / deadman timer / snapshot)
35-verify  post-apply verification gate
40-json    JSON emission
45-help    every plain-English text: command help, topics, explanations
50-ui      pure-bash terminal toolkit (menus, checklists, input, boxes)
60-plan    transaction engine (lock, plan, ssh guard, apply, commit gate)
70-workflows  operation workflows (build plans, hand them to the engine)
75-diag    diagnostics + support bundles
90-cli     argument parsing and every command
95-tui     the guided menus (dashboard, wizards, results)
99-main    entrypoint: global flags, --help routing, dispatch
```

The rules:

- **Call downward only.** A module may call functions from lower-numbered
  modules, never from higher-numbered ones. (`60-plan` calling `bm::ui::*`
  from `50-ui` is fine; `30-snap` calling a workflow is not.)
- All functions are namespaced `bm::<module>::<name>`. Functions prefixed
  with `_` are module-private.
- Modules define functions and defaults only — **no I/O at source time**.
  Sourcing the artifact must be side-effect free (the test suite depends on
  it).
- Only `25-nm` invokes `nmcli`, and only through `bm::nm::run` (logged,
  dry-run-guarded argv). Address profiles by UUID, never by naming
  convention. Parse `nmcli -t` output only via `bm::nm::terse_split`
  (nmcli escapes `:` as `\:` and `\` as `\\`; a plain `awk -F:` is the v2
  bug we do not reintroduce).
- Every filesystem path goes through the `BM_*` root variables
  (`BM_PROC_ROOT`, `BM_SYS_ROOT`, `BM_CONN_DIR`, `BM_IFCFG_DIR`, …) and
  every external command is PATH-resolved — no absolute command paths. This
  is what makes the code testable without root. `BM_IFCFG_DIR`
  (`/etc/sysconfig/network-scripts`) is the RHEL 8 ifcfg profile store that
  snapshots cover alongside the keyfile store; a test that touches
  snapshots **must** point it at the sandbox, or it will read and restore
  the developer's real network scripts.
- Anything that mutates state must honor `--dry-run` (report, write
  nothing — including no snapshot) and must take the lock via
  `bm::lock::acquire`. That applies to the safety commands (`commit`,
  `rollback`, `snapshot create|restore|prune`) exactly as it does to the
  change workflows; read-only commands take no lock and write nothing.
- Workflows (`70`) never call `nmcli` directly: they build a plan
  (`bm::plan::add` steps) and hand it to `bm::plan::apply`. That is what
  makes `--dry-run` exact — rendering the plan *is* the dry run.
- Read-only commands must stay read-only: no root requirement, no file
  writes (file logging is off until `bm::log::enable_file`).

## The build and its gates

`make dist` runs `build/build.sh`, which concatenates `lib/*.sh` (stripping
shebangs and source guards), appends the entrypoint, and refuses to emit
the artifact unless all gates pass:

1. `bash -n` — the generated file must parse.
2. **Duplicate function definitions** — two modules defining the same
   function is a merge accident; the build fails.
3. **Called-but-undefined `bm::` functions** — every `bm::*` reference must
   have a definition. This gate exists because v2.1.0 shipped with
   `bond_context_text` called in five workflows and defined nowhere.
4. `shellcheck -S warning` on the generated file (best-effort locally,
   mandatory in CI).

The build is deterministic — no timestamps — so the committed artifact is
reproducible and `make check-dist` can fail CI when `bond_manager.sh` is
out of sync with `lib/`.

Shellcheck runs against the *built artifact*, not per-module: the modules
are one compilation unit and per-module linting drowns in cross-file
SC2034 false positives (see the note in the Makefile).

## Writing tests

Tests are bats (`make test` runs `bats -r tests/`). The pattern:

1. **Source the artifact.** Sourcing (not executing) `bond_manager.sh`
   defines every `bm::` function without running `main`:

   ```bash
   setup() {
     source "$BATS_TEST_DIRNAME/../bond_manager.sh"
   }

   @test "terse_split honors escaped colons" {
     bm::nm::terse_split 'uuid-1:my\:name:bond:bond0'
     [ "${BM_FIELDS[1]}" = "my:name" ]
   }
   ```

2. **Point the roots at fixtures.** Build a fixture tree and export the
   `BM_*` variables before calling functions that read state:

   ```bash
   export BM_PROC_ROOT="$FIXTURES/proc" BM_SYS_ROOT="$FIXTURES/sys"
   run bm::facts::bond_health bond0
   ```

   A fixture needs only the files the code reads, e.g.
   `proc/net/bonding/bond0` (real `/proc/net/bonding` format) and
   `sys/class/net/<if>/{operstate,speed,mtu,address}`.

3. **Stub external commands with PATH shims.** All external commands
   (`nmcli`, `ip`, `busctl`, `systemctl`, `systemd-run`, `ping`, `ethtool`,
   `journalctl`, `modprobe`, `logger`, `restorecon`) are
   PATH-resolved. Put executable stubs in a directory and prepend it to
   `PATH`; have stubs record their argv to a file when you need to assert
   on what would have been executed.

4. **End-to-end runs** go through the executed artifact with roots and
   PATH set, asserting on output and the typed exit codes (0/1/2/3/4/5/6/
   10/11 — treat these as a stable contract; changing them is a breaking
   change).

Keep tests root-free where possible: nothing in the suite may touch real
system paths, and a test that genuinely needs euid 0 must guard itself with
the `require_root` helper. If you need a writable config/log/backup dir,
point `BM_CONF`, `BM_LOG_FILE`, `BM_BACKUP_DIR`, `BM_RUN_DIR`,
`BM_CONN_DIR`, `BM_IFCFG_DIR`, etc. at a temp directory — `setup_sandbox`
in `tests/helpers.bash` does all of this for you.

## Words and UI code

Anything a person reads should say **what happened and what to do next**,
in plain words:

- Put explanations in `45-help` so the CLI and the menus say the same
  thing. Help text stays 7-bit ASCII and within 79 columns (a test checks
  both): it has to read on a serial console.
- `bm::core::die MESSAGE CODE HINT`: the `ERROR:` line is a stable contract
  that scripts and tests match on, so never reword an existing message. Put
  the advice in the third argument; it prints as a `Next step:` line.
- In the menus, prefer a list to typing. When typing is unavoidable, pass a
  validator whose `BM_UI_VERR` says how to fix the value.

The widgets in `50-ui` answer through globals (`BM_UI_REPLY`, ...), return
0 for an answer and 1 for "back", and set `BM_UI_EOF=1` at end of input.
Bash pitfalls that bite interactive code under `set -Eeuo pipefail`:

- Every `read` sits in an `if` or `||`: a timeout (status > 128) or end of
  input (1) would otherwise trip errexit. Every loop must stop on
  `BM_UI_EOF`.
- Never end a function with `[[ ... ]] && x` or `(( ... )) && x`: when the
  test is false the function returns 1 and the caller's errexit fires. Use
  `if`, or end with `return 0`.
- Never call something that can `die` inside `$(...)`: the exit only ends
  the substitution. In the menus, run actions through `bm::tui::run`, which
  isolates them in a subshell and reports the outcome.
- Never call a widget inside `while read ... done < <(...)`: it would read
  the loop's input. Collect with `mapfile` first.
- Avoid `grep -q` at the end of a pipeline: under `pipefail` the writer's
  SIGPIPE can turn a match into a failure.
- Top-level associative arrays must be declared `declare -A NAME=(...)` at
  column 0 (the unit-test loader rewrites them to `declare -gA`).
- Bash 4.4: no `EPOCHSECONDS`, `EPOCHREALTIME`, `${x@U}` or `wait -p`. Get
  the time with `printf -v now '%(%s)T' -1`.

## Pull request checklist

- [ ] Edits are in `lib/` (and/or `bin/`, `build/`, `tests/`, docs) —
      never directly in `bond_manager.sh`.
- [ ] `make dist` was run and the regenerated `bond_manager.sh` is
      committed (CI runs `make check-dist` and fails otherwise).
- [ ] `make check` is green locally (check-dist + shellcheck lint + bats).
- [ ] New behavior has tests following the stubs/fixtures pattern above.
- [ ] Bash 4.4 compatible — no 5.x-only features.
- [ ] Module layering respected: calls go downward, nmcli stays in
      `25-nm`, paths go through `BM_*` roots.
- [ ] New mutating paths honor `--dry-run`, take the lock, and cannot
      report success for an operation that did not happen (check the exit
      status of anything that can fail — `tar`, D-Bus calls, `nmcli`).
- [ ] User-visible changes are reflected in `README.md`,
      `docs/bond-manager.8`, and `CHANGELOG.md`; safety-model changes also
      in `docs/SAFETY.md`.
- [ ] Exit codes and the JSON schema unchanged — or the change is called
      out as breaking and `BM_JSON_SCHEMA_VERSION` is bumped.
