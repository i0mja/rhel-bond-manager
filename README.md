# RHEL Bond Manager

`bond_manager.sh` is an interactive NetworkManager helper for Red Hat Enterprise Linux
8/9 (and compatible) servers.  It streamlines creation, maintenance, and diagnosis of
Ethernet bonding profiles that back Hadoop, Cloudera, Elasticsearch, and other data
platform fleets.

## Key Capabilities

- **Fast preflight validation** – verifies OS compatibility, NetworkManager
  availability, and bonding kernel support before presenting the menu.
- **Interactive bond lifecycle workflows** – create, edit, repair, migrate, and remove
  bonds with guard rails such as automatic backups, SELinux context restoration, and
  NIC readiness checks.
- **Advanced tuning prompts** – optionally adjust miimon timers, LACP rate, transmit
  hashing policies, and ARP monitoring targets during create/edit flows.
- **Deep diagnostics** – run standard or extended health checks, including latency
  tests per slave, interface speed detection, and `/proc/net/bonding` inspection.
- **Safe recovery paths** – snapshot NetworkManager profiles before any change,
  retain the last 10 backups, and expose a one-touch rollback option from the main
  menu.
- **JSON and human-readable summaries** – print real-time bond status in the terminal
  or export structured JSON inventories for automation.
- **Support bundle collector** – capture bonding stats, NetworkManager data, recent
  logs, and NIC details into a timestamped tarball for triage.
- **Robust logging** – append structured log entries to
  `/var/log/bond_manager.log`, automatically rotated via `/etc/logrotate.d/bond_manager`.
- **Dry-run and debug modes** – preview the nmcli actions that would be executed and
  mirror log output to STDERR during troubleshooting.

## Requirements

- RHEL, CentOS Stream, Rocky, or AlmaLinux release 8 or 9.
- Root privileges (the script writes to `/etc`, `/var/log`, and NetworkManager).
- NetworkManager with `nmcli` available and active.
- Standard networking utilities: `ip`, `tar`, `ping`, `awk`, `sed`, and `ethtool`
  (the script checks for these commands at start-up).

## Installation

1. Copy `bond_manager.sh` to a secure location, e.g. `/usr/local/sbin/bond_manager.sh`.
2. Ensure it is executable:
   ```bash
   sudo chmod 750 /usr/local/sbin/bond_manager.sh
   ```
3. (Optional) add the location to your `$PATH` or create a convenience symlink.

The first run will create the log file, backup directory, and a logrotate policy if
they do not already exist.

## Usage

Launch the interactive menu with root privileges:

```bash
sudo ./bond_manager.sh
```

### Menu actions

The menu exposes the following workflows:

| Option | Description |
| ------ | ----------- |
| 0 | Roll back to the most recent NetworkManager backup. |
| 1 | Switch migration helper – add new slaves before removing the old ones. |
| 2 | 10Gb migration wizard – clone an existing bond onto fresh 10Gb interfaces. |
| 3 | Repair bond – rebuild slave profiles and bring the bond online. |
| 4 | Repair bond (10Gb Active/Backup) – enforce 10Gb-only slaves in A/B mode. |
| 5 | Diagnose bond – print `/proc/net/bonding` data, NIC link state, and pings. |
| 6 | Extended diagnostics – deeper collection of bond and NIC telemetry. |
| 7 | Create bond – guided creation with validation and optional VLAN/IP config. |
| 8 | Edit bond – modify slaves, mode, VLAN, IP data, and advanced options. |
| 9 | Remove bond – detach slaves and delete the bond profile safely. |
| 10 | Show bond summary – human-readable snapshot of every bond and member. |
| 11 | Export bond summary (JSON) – interactive prompt for export path. |
| 12 | Collect support bundle – gather logs and diagnostics into a tarball. |
| 13 | Show version – print the current script version. |
| 14 | Exit the utility. |

After any workflow that alters NetworkManager profiles the script offers an
immediate rollback prompt and, upon success, restores SELinux contexts for the
connection files.

### Command-line flags

Run non-interactive reports or change runtime behaviour with flags:

```bash
sudo ./bond_manager.sh [OPTIONS]
```

- `-n`, `--dry-run` – echo the `nmcli` commands that would run without applying
  changes.
- `--debug` – mirror log entries (with severity tags) to STDERR for live
  troubleshooting.
- `--status` – print the bond summary view and exit.
- `--export-json <path>` – export the bond inventory to the supplied path and exit.
- `--help` – show supported flags.

`--status` and `--export-json` can be combined, enabling cronable bond audits:

```bash
sudo ./bond_manager.sh --status --export-json /var/log/bond_manager/bonds.json
```

## Data and Artifacts Produced

- **Backups** – `/var/backups/bond_manager/conn-<timestamp>.tar.gz` (up to 10 recent
  archives are retained).
- **Logs** – `/var/log/bond_manager.log` with automatic weekly rotation.
- **Support bundles** – `/var/log/bond_manager/support/support_<timestamp>.tar.gz`.
- **JSON exports** – Custom path provided when invoking `--export-json` or menu
  option 11.

## Development Notes

- The script is `bash`-strict (`set -Eeuo pipefail`) and expects a functional TTY
  for interactive prompts.
- Before submitting changes, validate syntax with:
  ```bash
  bash -n bond_manager.sh
  ```

## License

This project is distributed under the terms of the [MIT License](LICENSE).
