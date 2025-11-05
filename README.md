# RHEL Bond Manager

**bond_manager.sh** is an interactive NetworkManager helper for Red Hat Enterprise Linux **8/9** (and compatible) servers.  
It streamlines creation, maintenance, and diagnosis of Ethernet bonding profiles for data‑platform and fleet workloads (Hadoop, Cloudera, Elasticsearch, etc.).

> **Version:** 1.1.0 · **License:** MIT

---

## Table of Contents
- [Key Capabilities](#key-capabilities)
- [What’s New in v1.1.0](#whats-new-in-v110)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration (`/etc/bond_manager.conf`)](#configuration-etcbond_managerconf)
- [Usage](#usage)
  - [Interactive Menu](#interactive-menu)
  - [Command‑Line Flags](#command-line-flags)
  - [Examples](#examples)
- [Workflows (Menu Actions)](#workflows-menu-actions)
- [Summaries and JSON Exports](#summaries-and-json-exports)
- [Diagnostics and Support Bundle](#diagnostics-and-support-bundle)
- [Backups, Rollback & SELinux](#backups-rollback--selinux)
- [Safety Notes](#safety-notes)
- [Troubleshooting](#troubleshooting)
- [Development Notes](#development-notes)
- [Uninstall](#uninstall)
- [License](#license)

---

## Key Capabilities
- **Fast preflight validation** – verifies OS compatibility, NetworkManager availability, and bonding kernel support before presenting the menu.
- **Interactive bond lifecycle** – create, edit, repair, migrate, and remove bonds with guard rails (automatic backups, SELinux context restoration, NIC policy checks).
- **Advanced tuning prompts** – optionally adjust `miimon`, LACP rate, transmit hash policy, and ARP monitoring targets.
- **Deep diagnostics** – standard or extended health checks: per‑slave pings, interface speeds, `ethtool` info, and `/proc/net/bonding` inspection.
- **Safe recovery paths** – NetworkManager profile snapshots before any change; retain the last *N* backups (default **10**); one‑touch rollback from the menu.
- **JSON + human summaries** – print real‑time status in the terminal or export a structured JSON inventory for automation.
- **Support bundle** – capture bonding stats, NM data, recent logs, and NIC details into a timestamped tarball for triage.
- **Robust logging** – append structured log entries to `/var/log/bond_manager.log`, rotated per `/etc/logrotate.d/bond_manager`.
- **Dry‑run & debug modes** – preview the `nmcli` actions and mirror logs to STDERR for live troubleshooting.

---

## What’s New in v1.1.0
- **Managed config file:** `/etc/bond_manager.conf` with safe defaults and overridable knobs (miimon, LACP, xmit_hash_policy, backup retention, logrotate policy).
- **NIC allowlist/blocklist policy:** only enslave eligible NICs by default (e.g., `ens*`, `enp*`, `eth*`); virtual/wireless/bridge interfaces are blocked unless you change policy.
- **Config‑driven logrotate:** policy is rendered from your config; changes are applied next run.
- **Defaults respected across flows:** creation, edit, and 10Gb migration use your configured defaults whenever values aren’t discoverable.

---

## Requirements
- **OS:** RHEL, CentOS Stream, Rocky, or AlmaLinux release **8** or **9**.
- **Root** privileges (writes to `/etc`, `/var/log`, and NetworkManager).
- **NetworkManager** with `nmcli` installed **and active**.
- Utilities: `ip`, `tar`, `ping`, `awk`, `sed`, `ethtool` (script checks these at start‑up).

---

## Installation

1. Copy the script into a secure location:
   ```bash
   sudo install -m 750 bond_manager.sh /usr/local/sbin/bond_manager.sh
   ```

(Optional) Pre‑seed the config (the script creates a default if missing):

```bash
sudo install -m 640 -o root -g root bond_manager.conf /etc/bond_manager.conf
```

First run will create:

- Log: `/var/log/bond_manager.log` (+ logrotate policy at `/etc/logrotate.d/bond_manager`)
- Backups dir: `/var/backups/bond_manager/`
- Support dir: `/var/log/bond_manager/support/`

---

## Configuration (/etc/bond_manager.conf)
The script creates and then sources this file on every run. Edit it to customize defaults and safety policy:

```bash
# --------- Bond tuning defaults ---------
DEFAULT_MIIMON="100"
DEFAULT_8023AD_LACP_RATE="fast"   # fast|slow
DEFAULT_8023AD_XHP="layer3+4"     # layer2|layer3+4|layer2+3

# --------- Backups & log rotation ---------
MAX_BACKUPS="10"                  # snapshots to retain
LOGROTATE_FREQUENCY="weekly"      # daily|weekly|monthly
LOGROTATE_ROTATE="12"             # rotated files to keep

# --------- NIC selection policy (ERE patterns, space-separated) ---------
NIC_ALLOWLIST_PATTERNS="^(ens|enp|eth)[0-9].*"
NIC_BLOCKLIST_PATTERNS="^lo$ ^veth.* ^docker.* ^br-.* ^virbr.* ^vnet.* ^tun.* ^tap.* ^nm-.* ^wl.* ^bond.* ^team.* ^ovs.*"
```

> Note: If `NIC_ALLOWLIST_PATTERNS` is empty, any NIC is eligible except those matching the blocklist.

---

## Usage

### Interactive Menu
```bash
sudo /usr/local/sbin/bond_manager.sh
```

### Command‑Line Flags
```text
-n, --dry-run         Echo the nmcli commands that would run without applying changes.
    --debug          Mirror log entries to STDERR for live troubleshooting.
    --status         Print the bond summary view and exit.
    --export-json PATH
                      Export the bond inventory as JSON to PATH and exit.
-h, --help           Show help.
```

### Examples
```bash
# Status-only (human readable)
sudo bond_manager.sh --status

# Status + export JSON (cron-friendly)
sudo bond_manager.sh --status --export-json /var/log/bond_manager/bonds.json

# Trace actions without changing the system
sudo bond_manager.sh --dry-run --debug
```

---

## Workflows (Menu Actions)

| Option | Description |
|--------:|-------------|
| 0 | Roll back to the most recent NetworkManager backup. |
| 1 | Switch migration helper – add new slaves before removing old ones (safe add‑then‑remove sequence). |
| 2 | 10Gb migration wizard – clone an existing bond onto fresh 10Gb interfaces. Copies IP and VLAN profiles. |
| 3 | Repair bond – rebuild slave profiles and bring the bond online using `/proc/net/bonding` as truth. |
| 4 | Repair 10Gb A/B – enforce active‑backup and restrict to 10Gb‑only slaves. |
| 5 | Diagnose – print `/proc/net/bonding`, link state for bond & slaves, and run per‑slave pings. |
| 6 | Extended diagnostics – option 5 plus `ethtool -i/-S` and recent NetworkManager logs. |
| 7 | Create bond – guided creation of active-backup or 802.3ad with optional VLAN/IP and ARP monitoring. |
| 8 | Edit bond – add/remove slaves, change mode/tunables, add VLANs, or edit IP on bond/VLAN. |
| 9 | Remove bond – safely detach slaves, remove VLANs, then delete the bond. |
| 10 | Show bond summary (human). |
| 11 | Export bond summary (JSON). |
| 12 | Collect support bundle. |
| 13 | Show version & current effective configuration. |
| 14 | Exit. |

> All mutating workflows create a backup first and offer an immediate rollback prompt on completion.
> SELinux contexts for connection files are restored via `restorecon` after changes.

---

## Summaries and JSON Exports
Human summary (`--status` or menu **10**) prints per‑bond data from `/proc/net/bonding`.

JSON export (`--export-json PATH` or menu **11**) returns an array of objects with the shape:

```jsonc
[
  {
    "bond": "bond0",
    "mode": "802.3ad",
    "mii_status": "up",
    "active_slave": "ens3f0",
    "primary_slave": "",
    "slaves": [
      {"name": "ens3f0", "state": "up", "speed": "10000"},
      {"name": "ens3f1", "state": "up", "speed": "10000"}
    ],
    "addresses": [ /* raw objects from: ip -json addr show dev <bond> */ ],
    "vlans": ["bond0.123", "bond0.200"]
  }
]
```

> Addresses are the unmodified JSON objects provided by `ip -json addr show` for the bond interface.

---

## Diagnostics and Support Bundle
**Diagnose (5):**
- `/proc/net/bonding/<bond>`
- `ip -br link` for bond + slaves
- Quick per‑slave pings (default target: `8.8.8.8`)

**Extended diagnostics (6):**
- Everything in (5) plus `ethtool -i/-S` per slave
- Recent NetworkManager logs (`journalctl -u NetworkManager -n 200`)

**Support bundle (12):**
Creates a timestamped archive at `/var/log/bond_manager/support/support_<timestamp>.tar.gz` with:
- `lsmod | grep bonding`
- `nmcli con show` and `nmcli dev status`
- `ip -d -s link show`, `ip addr show`
- `journalctl -u NetworkManager -n 1000`
- `/proc/net/bonding/*`
- `bond_manager.log`

---

## Backups, Rollback & SELinux
Before any change, a tarball snapshot of `/etc/NetworkManager/system-connections` is stored at:

`/var/backups/bond_manager/conn-<timestamp>.tar.gz`

The last **MAX_BACKUPS** (default 10) are retained.

Rollback (option **0**) restores the most recent snapshot and reloads NetworkManager.

After mutating workflows, the tool runs `restorecon -RFv` on the connection directory (best effort).

---

## Safety Notes
- **NIC policy:** slaves must pass the allowlist/blocklist rules. Adjust patterns in `/etc/bond_manager.conf` if your environment uses different names.
- **Dry‑run scope:** `--dry-run` echoes `nmcli` actions only; non‑`nmcli` commands (e.g., `ip`, `tar`) will still run.
- **TTY requirement:** interactive mode requires a functional TTY. Use `--status`/`--export-json` for non‑interactive runs.
- **Supported modes:** active-backup and 802.3ad (LACP). Other bonding modes are not exposed.

---

## Troubleshooting
| Issue | Solution |
|-------|-----------|
| NetworkManager inactive | `sudo systemctl enable --now NetworkManager` |
| `nmcli` not found | Install the NetworkManager CLI package. |
| Unable to load bonding module | Ensure the kernel supports bonding; run `modprobe bonding`. |
| No eligible slave interfaces | Adjust allow/block patterns in `/etc/bond_manager.conf`. |
| 802.3ad bond stays down | Verify switch LAG config, correct ports, and matching hashing policy. |

---

## Development Notes
- Bash‑strict: `set -Eeuo pipefail` with error trap.
- Validate syntax before submitting changes:
  ```bash
  bash -n bond_manager.sh
  ```
- Style: POSIX‑ish Bash, pure `nmcli`, no external JSON parser required.

---

## Uninstall
```bash
sudo rm -f /usr/local/sbin/bond_manager.sh
sudo rm -f /etc/logrotate.d/bond_manager
sudo rm -f /etc/bond_manager.conf    # optional (keep if you plan to reinstall)
sudo rm -rf /var/log/bond_manager*   # optional logs & support bundles
sudo rm -rf /var/backups/bond_manager # optional snapshots
```

---

## License
This project is distributed under the terms of the **MIT License**.

