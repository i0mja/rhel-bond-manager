# bond-manager: the beginner's guide

This guide assumes you have never set up a network bond before. It explains
what a bond is, then walks through every common job step by step. If you
already know bonding and just want the command reference, see the
[README](../README.md) or run `bond-manager help`.

---

## 1. What is a bond?

A server usually has several network ports (sockets for network cables).
A **bond** joins two or more of them into **one** connection. The server
sees a single network interface, e.g. `bond0`, with one IP address, while
the traffic actually runs over several cables:

```
   cable 1 ──┐
              ├── bond0 (one IP address) ── the server
   cable 2 ──┘
```

If a cable is pulled, a network card dies or a switch reboots, traffic
keeps flowing over the cables that are left. Depending on the **mode**, the
ports can also share the load.

A few words you will keep seeing:

| Word | Meaning |
|---|---|
| **port**, **member** | One network port inside a bond, e.g. `ens1f0`. (The kernel says a port is "enslaved" to the bond.) |
| **link** | A working cable connection. *No link* means the cable is unplugged or broken, or the switch port is off. |
| **mode** | How the bond uses its ports. See [section 7](#7-which-mode-should-i-pick). |
| **LACP / 802.3ad** | A mode where the server **and the switch** agree to use all ports. The switch must be set up for it. |
| **VLAN** | A tagged network on top of the bond, e.g. `bond0.120` is VLAN 120. |
| **profile** | A saved NetworkManager setting (what `nmcli connection` lists). |

## 2. Why use bond-manager instead of typing nmcli?

Changing a bond on a live server is risky: one step in the wrong order and
you cut off the SSH session you are typing in. bond-manager makes every
change safe in the same five steps:

1. **It shows the plan first.** You see the exact commands before anything
   happens, and **practice mode** stops right there.
2. **It saves a backup copy** of all network settings.
3. **It arms a safety net.** If you do not confirm the change in time, it
   is **undone automatically**, even if the change cut your connection and
   you cannot type any more.
4. **It makes the change, then checks the real result** by reading what the
   Linux kernel is actually doing, not what the tools claim. If a check
   fails, the change is undone right away.
5. **It asks you to keep the change.** Press **K** to keep it. Do nothing
   and it is undone.

## 3. Before you start

- **Log in as root, or use `sudo`.** Without root you can still look at
  everything and practise; you just cannot change anything.
- **Know which ports you want to use.** `bond-manager nics` lists every
  port and says which ones are *free - good to use*.
- **Using LACP (802.3ad)?** Ask the network team to configure the switch
  ports as an LACP bundle (also called a port-channel or LAG) **first**.
  Not sure? Use `active-backup`, which works with any switch.
- **Have a plan B.** The safety net handles almost everything, but console
  access (iDRAC, iLO, a KVM, or a virtual machine console) is always nice
  to have.
- **Check the server once:** `bond-manager doctor` tells you whether
  everything is ready and which safety net you will get.

## 4. Start the menus

```bash
sudo bond-manager
```

You get a home screen like this:

```
┌─ bond-manager 3.1.0 · web01 ─────────────────────────────  LIVE  ─┐
│ ● bond0  active-backup (failover)  healthy   10.0.0.5/24          │  ← each bond, with its health
│    ├─ ens1f0  up       10G  (active)                              │  ← its ports: link, speed
│    └─ ens1f1  up       10G           ← your SSH connection        │  ← the port your session uses
│                                                                   │
│ ✔ Safety net: automatic undo (NetworkManager)                     │  ← how well you are protected
└───────────────────────────────────────────────────────────────────┘
What do you want to do?
 ❯ 1   Check my bonds               health, problems explained
   2   Move a bond to a new switch  one cable at a time, no outage
   3   Build a new bond
   4   Change a bond                ports, mode, IP, VLANs...
   5   Fix a bond that looks wrong
   6   Undo & safety                waiting change, backup copies
   7   Tools                        network ports, server check, support bundle
   8   Help: what is all this?
   9   Practice mode is OFF         pick to try things without changing anything
       Quit
 ▲▼ move · Enter choose · 1-9 jump · p practice · r refresh · ? help · q quit
```

**Keys:** arrows (or `j`/`k`) move, **Enter** chooses, a number jumps
straight to an item, **Esc** or `q` goes back one step. In lists with
check boxes, **Space** ticks a line. On the home screen, `p` switches
practice mode, `r` refreshes, `?` opens help.

The badge in the top-right corner always tells you where you are:
**LIVE** means changes are real, **PRACTICE** means nothing will be
changed.

## 5. Practise first

Press **p** on the home screen. The badge switches to **PRACTICE**. Now go
through any job you like: the questions are the same, and at the end you
see the exact plan that *would* run. Nothing on the server changes.

Happy with the plan? Press **p** again to go back to **LIVE**, then repeat
the job for real.

On the command line, practice mode is `-n` (or `--dry-run`):

```bash
bond-manager -n swap-member bond0 --old ens1f0 --new ens2f0
```

## 6. The safety net, and what to do if your session drops

After a change passes its checks, you see:

```
┌─ Keep this change? ──────────────────────────────────────────────┐
│ ✔ All checks passed - your change is live.                        │
│                                                                   │
│ If you do nothing, it is UNDONE automatically when the time runs  │
│ out. That is the safety net: if this change cut your connection,  │
│ just wait.                                                        │
│                                                                   │
│   K  keep it       U  undo it now       E  5 more minutes         │
└───────────────────────────────────────────────────────────────────┘
Keep this change?  [K]eep  [U]ndo  [E]+5 min   Auto-undo in 1:52
```

- **Can you still reach what you need?** Press **K**. Done.
- **Something looks wrong?** Press **U**. Everything goes back to how it
  was.
- **Need more time to check?** Press **E** (only offered when
  NetworkManager itself holds the undo).

**If your SSH session freezes or drops:** don't panic, and don't start
changing things by hand. Wait for the countdown (2 minutes by default) and
reconnect: the change has been undone. If you manage to reconnect *before*
the countdown ends, you can decide from the new session:

```bash
sudo bond-manager commit      # keep the change
sudo bond-manager rollback    # undo it now
```

The home screen also shows a **"A change is waiting for you"** banner with
the time left, and offers "Keep or undo the last change" as its first item.

Which safety net you get depends on the server (`bond-manager doctor` tells
you):

| Safety net | What happens if you never confirm |
|---|---|
| **automatic undo (NetworkManager)** | NetworkManager itself undoes the change. Works even if the change cut your session. The best one; the default on RHEL 8/9. |
| **automatic undo (backup timer)** | A system timer restores the backup copy. |
| **backup copy only** | Nothing automatic. You must undo by hand. Have console access ready, because bond-manager refuses to touch your SSH connection's device on this tier. |

## 7. Which mode should I pick?

**Not sure? Pick `active-backup`.** It works with any switch and never
needs the network team.

| Mode | What it does | Switch setup needed? |
|---|---|---|
| `active-backup` | One port works, the others wait to take over. | **No** |
| `802.3ad` (LACP) | All ports carry traffic at once. | **Yes**, an LACP bundle |
| `balance-alb` | Shares traffic in and out. | No |
| `balance-tlb` | Shares outgoing traffic. | No |
| `balance-xor` | Shares traffic by address. | Yes, a static port-channel |
| `balance-rr` | Packets take turns on each port. | Yes, a static port-channel |
| `broadcast` | Sends everything on every port. | Special cases only |

If the switch is not set up for the mode you pick, the bond may come up but
pass no traffic. bond-manager's checks notice, and the change is undone.

## 8. Recipes

Each recipe shows the menu path first, then the command that does the same
thing. Every menu job also prints its own command at the end, so you can
copy it into a runbook.

### Is everything OK?

**Menu:** *Check my bonds → Quick health check*

```bash
bond-manager list          # one line per bond
bond-manager status        # details; exit code 0 = healthy, 10 = attention, 11 = down
```

Problems are explained in plain words with what to do, e.g.
*"Port ens1f1 has no link: the cable is unplugged or broken, or the switch
port is off."*

### Move a server to a new switch without an outage

This is what bond-manager was built for. A bond survives losing one cable,
so you move **one cable at a time**:

1. Plug a **free** port into the new switch (`bond-manager nics` shows
   which ports are free and have a link).
2. **Menu:** *Move a bond to a new switch.* Pick the bond, the old port
   (still on the old switch) and the new port (on the new switch).
3. bond-manager adds the new port, **waits until it really works**, and
   only then removes the old one. The bond is never short a cable.
4. Press **K** to keep it, then do the same for the other cable. The
   wizard offers this straight away.

```bash
sudo bond-manager swap-member bond0 --old ens1f0 --new ens2f0
sudo bond-manager swap-member bond0 --old ens1f1 --new ens2f1
```

**LACP bonds (802.3ad):** during the move one cable is on the old switch
and one on the new. LACP only works if both switches act as **one** (MLAG,
vPC, a stack). If they don't, or you are not sure, the wizard offers to
switch the bond to `active-backup` for the move. Switch it back afterwards:

```bash
sudo bond-manager modify bond0 --mode active-backup
# ...move both cables...
sudo bond-manager modify bond0 --mode 802.3ad
```

### Build a new bond

**Menu:** *Build a new bond*: five short questions (name, ports, mode,
address, extras), then a summary to check before anything happens.

```bash
bond-manager -n create bond1 --mode active-backup --members ens2f0,ens2f1 --ip4 dhcp
sudo bond-manager create bond1 --mode active-backup --members ens2f0,ens2f1 \
    --ip4 10.0.0.10/24 --gw4 10.0.0.1 --dns4 10.0.0.53
```

### Add or remove a port

**Menu:** *Change a bond → Add a port* / *Remove a port*. The menu won't
let you remove every port; use *Delete this bond* for that.

```bash
sudo bond-manager add-member bond0 ens1f2
sudo bond-manager remove-member bond0 ens1f2
```

To **replace** a port, use *Move a bond to a new switch* instead: it adds
the new one before removing the old one.

### Change the IP address

**Menu:** *Change a bond → IP address*

```bash
sudo bond-manager modify bond0 --ip4 10.0.0.20/24 --gw4 10.0.0.1
```

**If you are logged in through that address**, the change ends your
session. That is expected. Open a **new** SSH session to the **new**
address and run `sudo bond-manager commit` before the countdown runs out.
If you can't reach the new address, just wait: the change is undone and
the old address comes back.

### VLANs

**Menu:** *Change a bond → VLANs*

```bash
sudo bond-manager vlan add bond0 '120:ip4=10.20.30.40/24;gw4=10.20.30.1'
sudo bond-manager vlan remove bond0 120
bond-manager vlan list bond0
```

The switch ports must carry the VLAN (tagged / trunk). Quote the
`VID:settings` part: the `;` would otherwise end the command.

### Fix a bond that "drifted"

Sometimes the saved settings no longer match what the bond really does:
someone added a port by hand and never saved it, or a saved port no longer
exists. The next reboot then brings the bond back wrong.

**Menu:** *Fix a bond that looks wrong*. It shows exactly what the fix
would do before asking.

```bash
bond-manager -n repair bond0     # see which way it drifted, change nothing
sudo bond-manager repair bond0
```

### Undo something

**Menu:** *Undo & safety*

```bash
sudo bond-manager rollback                  # undo the change that is waiting
bond-manager snapshot list                  # backup copies (taken before every change)
bond-manager snapshot diff 20260101-120000  # what restoring one would change
sudo bond-manager rollback --snapshot 20260101-120000
```

## 9. When something goes wrong

Every error says **what** went wrong on the `ERROR:` line and **what to do**
on the `Next step:` line underneath:

```
bond-manager: ERROR: interface 'ens1f9' does not exist
  Next step: did you mean 'ens1f0'? See every port: bond-manager nics
```

Common ones:

| Message | What it means |
|---|---|
| `this operation must be run as root` | Run it again with `sudo`. |
| `NetworkManager is not active` | `systemctl enable --now NetworkManager` |
| `interface 'X' is already enslaved to bond 'Y'` | That port is already in another bond. Pick a free one (`bond-manager nics`). |
| `a previous change is still pending` | Keep or undo the last change first (`commit` / `rollback`). |
| `another bond-manager instance is running` | Someone else is changing this server right now. Wait. |
| `this change touches 'X', which carries your SSH connection` | Only on servers without automatic undo: use the console instead. |
| `verification FAILED — rolling back` | The change did not work, so it was undone. The `FAIL` lines above say what did not check out. |

Exit codes, for scripts: `0` ok · `1` error · `2` something typed wrong ·
`3` could not start · `4` another run in progress · `5` checks failed and
the change was undone · `6` applied but not confirmed yet · `10`/`11`
(`status`) a bond needs attention / is down. Details: `bond-manager help
exit-codes`.

**The terminal looks odd after a crash?** Type `reset` (or `stty sane`)
and press Enter.

## 10. From menus to scripts

Every change in the menus ends with *"Same thing as a command"*. Click
through the first server, paste that line into your runbook, and script the
other thirty-nine. To learn any command:

```bash
bond-manager help                  # the overview and common tasks
bond-manager help swap-member      # one command, with examples
bond-manager swap-member --help    # the same
bond-manager help modes            # topics: basics modes lacp safety practice moving glossary keys exit-codes
```

## 11. Terminals

The menus need nothing extra installed. They adapt to the terminal:

- **Arrow-key menus with colours and boxes** on a normal terminal.
- **Plain numbered menus** on serial consoles, dumb terminals, when piped,
  or with `--plain`. Type the number and press Enter; `q` goes back.
- **ASCII instead of box-drawing characters** when the terminal has no
  UTF-8, or with `BM_ASCII=1`.
- **No colours** with `NO_COLOR=1` or `--no-color`.
