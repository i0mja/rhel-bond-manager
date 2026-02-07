# RHEL Bond Manager

A professional, interactive helper for managing Linux bonding via **NetworkManager** (`nmcli`) on RHEL-like 8/9 systems (RHEL, Rocky, AlmaLinux, CentOS Stream, etc.).

It provides a safer operator workflow for common bond tasks (create/edit/migrate/repair) while keeping everything backed by standard NetworkManager connection profiles.

---

## What this tool is

- A **TUI/CLI wrapper** around `nmcli` for bond creation and maintenance.
- A **workflow-driven** operator tool: status → plan → backup → apply → verify → rollback.
- A **support/diagnostic collector** for ticket-driven troubleshooting.

## What this tool is not

- A replacement for NetworkManager.
- A switch configuration tool (e.g., LACP must be configured on the switch side when using 802.3ad).
- A high-availability “orchestrator” across hosts (this is per-host).

---

## Key Features

### Status (read-only)
- Bond overview (mode, members, basic state)
- Diagnostics (bond `/proc` view, link state, per-member ping tests)
- Extended diagnostics (adds `ethtool` telemetry + recent NetworkManager logs)

### Change management
- Guided **bond creation** with:
  - `active-backup` (failover)
  - `802.3ad` (LACP)
  - Optional VLAN-on-bond
  - IPv4 via DHCP or static configuration
- Bond editing:
  - Add/remove member NICs
  - Adjust mode and tuning (`bond.options`)
  - Add VLAN
  - Edit IPv4 on bond or VLAN profile
- Safe removal:
  - Deletes bond members (bond-slave profiles) and VLAN profiles first, then the bond

### Migration workflows
- Swap member NICs (add new first, optionally remove old after)
- Clone an existing bond to new NICs (optionally copy IPv4 and VLAN profiles)

### Repair workflows
- Rebuild bond-slave profiles from current kernel `/proc` state
- Enforce 10Gb active-backup membership (removes non-10Gb members based on speed reporting)

### Safety & Support
- Automatic **NetworkManager profile backups** before any change
- One-click **rollback** to the most recent snapshot
- Support bundle generator (logs + nmcli outputs + `/proc/net/bonding` + NM journal)

---

## Requirements

- **Root** privileges (writes under `/etc/NetworkManager/system-connections`, `/etc/logrotate.d`, and backup/log paths)
- NetworkManager running:
  - `systemctl enable --now NetworkManager`
- Tools used:
  - `nmcli`, `ip`, `tar`, `ping`, `awk`, `sed`, `ethtool`, `journalctl`
- Kernel bonding module:
  - Automatically `modprobe bonding` if needed

Optional:
- `whiptail` for a richer interactive UI (fallback to plain prompts if not present)

---

## Installation

1) Copy the script to a standard location, for example:

```bash
install -m 0750 -o root -g root bond_manager.sh /usr/local/sbin/bond_manager
```

2) (Optional) Install `whiptail` for a better UI:

- RHEL/Rocky/Alma:
```bash
dnf install -y newt
```

3) Run:

```bash
/usr/local/sbin/bond_manager
```

---

## Usage

### Interactive (recommended)
```bash
bond_manager
```

### Dry-run
Print `nmcli` commands without applying changes:

```bash
bond_manager --dry-run
```

> Note: `--dry-run` affects `nmcli` only. The tool may still write logs/config and create backups.

### Status-only
```bash
bond_manager --status
```

### Export JSON inventory
```bash
bond_manager --export-json /var/log/bond_manager/bonds.json
```

You can combine:
```bash
bond_manager --status --export-json /var/log/bond_manager/bonds.json
```

---

## Menu Layout

The UI is organized into operator-friendly groups:

- **Status**: overview, diagnostics, extended diagnostics  
- **Change**: create/edit/remove  
- **Migration**: swap NICs, clone bond  
- **Repair**: rebuild slaves, enforce 10Gb A/B  
- **Safety**: rollback  
- **Support**: support bundle  
- **About**: version/config  

---

## Configuration

On first run, the tool creates:

- Config: `/etc/bond_manager.conf`
- Log: `/var/log/bond_manager.log`
- Backups: `/var/backups/bond_manager/conn-<timestamp>.tar.gz`
- Support bundles: `/var/log/bond_manager/support/support_<timestamp>.tar.gz`
- Logrotate: `/etc/logrotate.d/bond_manager`

### `/etc/bond_manager.conf` (highlights)

- Bond tuning defaults:
  - `DEFAULT_MIIMON="100"`
  - `DEFAULT_8023AD_LACP_RATE="fast"`
  - `DEFAULT_8023AD_XHP="layer3+4"`
- Backups / rotation:
  - `MAX_BACKUPS="10"`
  - `LOGROTATE_FREQUENCY="weekly"`
  - `LOGROTATE_ROTATE="12"`
- NIC policy:
  - `NIC_ALLOWLIST_PATTERNS="^(ens|enp|eth)[0-9].*"`
  - `NIC_BLOCKLIST_PATTERNS="^lo$ ^veth.* ^docker.* ^br-.* ..."`

The NIC policy reduces operator error by excluding non-physical interfaces (veth, bridges, tunnels, etc.) and optionally restricting selection to certain naming patterns.

---

## Operational Notes

### 802.3ad (LACP) requires switch configuration
If you choose `802.3ad`, ensure the switch ports are configured for LACP as a bundle (vendor-specific: LAG, port-channel, etc.). If not, connectivity may be disrupted.

### VLAN placement
You can place the IPv4 configuration:
- **Directly on the bond** (no VLAN)
- **On a VLAN interface** (e.g., `bond0.120`) on top of the bond

Ensure your environment’s network design matches the choice.

### Remote session safety
If you are connected through the interface you are modifying, use one (or more) of:
- `--dry-run` first to review changes
- Console/iDRAC/iLO access
- A planned rollback window

---

## Logs and Troubleshooting

### Logs
- Primary log: `/var/log/bond_manager.log`
- NetworkManager logs:
  - `journalctl -u NetworkManager`

### Support bundle
From the menu: **Support: create support bundle**

Produces:
- `/var/log/bond_manager/support/support_<timestamp>.tar.gz`

Contents include:
- `nmcli` connection and device status
- `ip link` and `ip addr` output
- `journalctl -u NetworkManager` recent entries
- `/proc/net/bonding/*`
- Tool log and config

---

## Rollback

Before any change workflow, a snapshot of NetworkManager connection profiles is created from:

- `/etc/NetworkManager/system-connections`

Rollback restores the most recent snapshot from:

- `/var/backups/bond_manager/conn-<timestamp>.tar.gz`

Then:
- SELinux contexts are restored (best-effort)
- NetworkManager is reloaded

---

## Security Considerations

- Support bundles may contain sensitive information (IPs, interface names, network topology hints).
- Restrict access to:
  - `/var/log/bond_manager.log`
  - `/var/log/bond_manager/support/`
  - `/var/backups/bond_manager/`

---

## License

MIT (see script header).

---

## Quick Start Example

1) Run interactively:
```bash
bond_manager
```

2) Choose:
- **Change: create a new bond**
- Select mode (`active-backup` for simple failover)
- Select member NICs
- Configure IPv4 (DHCP or Static)
- Apply, then verify with:
  - **Status: diagnose bond**

3) If something goes wrong:
- **Safety: roll back to most recent snapshot**
