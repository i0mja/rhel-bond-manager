# lib/45-help.sh — every piece of plain-English guidance in one place, so the
# CLI (`help`, error hints) and the TUI (menus, help screens, result panels)
# say exactly the same thing. Pure text: nothing here reads or changes state
# except config defaults quoted in examples.
#
# Help text is deliberately 7-bit ASCII: it must read cleanly on a serial
# console with no UTF-8 locale, which is where people need it most.
# shellcheck shell=bash
[[ -n "${BM_LIB_HELP:-}" ]] && return 0
BM_LIB_HELP=1

BM_HELP_COMMANDS=(list show status diagnose verify doctor nics config completion help
  create modify add-member remove-member swap-member remove vlan clone repair
  commit rollback snapshot bundle init tui version)
BM_HELP_TOPICS=(basics modes lacp safety practice moving glossary keys exit-codes)

# Words people type when they mean a command. Suggested, never executed.
declare -A BM_HELP_SYNONYMS=(
  [move]=swap-member [migrate]=swap-member [swap]=swap-member [replace]=swap-member
  [undo]=rollback [revert]=rollback [keep]=commit [confirm]=commit [accept]=commit
  [fix]=repair [new]=create [make]=create [build]=create [add]=add-member
  [ls]=list [info]=show [check]=status [health]=status [ports]=nics
  [interfaces]=nics [nic]=nics [cards]=nics [delete]=remove [destroy]=remove
  [del]=remove [rm]=remove [edit]=modify [change]=modify [set]=modify
  [backup]=snapshot [menu]=tui [menus]=tui [preflight]=doctor [support]=bundle
)

bm::help::canonical() { # canonical <word> -> command name (aliases resolved), rc 1 if none
  local w="$1"
  case "$w" in
    delete) w=remove ;;
    support-bundle) w=bundle ;;
  esac
  bm::core::in_list "$w" "${BM_HELP_COMMANDS[@]}" || return 1
  printf '%s\n' "$w"
}

bm::help::is_command() { bm::help::canonical "$1" >/dev/null; }
bm::help::is_topic() { bm::core::in_list "$1" "${BM_HELP_TOPICS[@]}"; }

bm::help::synonym() { # synonym <word> -> suggested command, or nothing
  local w="${1,,}"
  if [[ -n "${BM_HELP_SYNONYMS[$w]:-}" ]]; then
    printf '%s\n' "${BM_HELP_SYNONYMS[$w]}"
  fi
  return 0
}

# Best "did you mean" for a word that is not a command: synonym first, then
# the closest spelling.
bm::help::suggest_command() { # suggest_command <word>
  local s
  s="$(bm::help::synonym "$1")"
  if [[ -z "$s" ]]; then
    s="$(bm::core::closest "$1" "${BM_HELP_COMMANDS[@]}" delete)"
  fi
  printf '%s' "$s"
}

# ---- short lists shared by usage and the TUI ------------------------------

bm::help::common_tasks() {
  cat <<EOF
  Are my bonds OK?            $BM_PROG list
  Which ports can I use?      $BM_PROG nics
  Preview, change nothing     $BM_PROG -n <command> ...
  Move to a new switch        $BM_PROG swap-member BOND --old IF --new IF
  Build a bond                $BM_PROG create BOND --mode M --members A,B
  Fix settings that drifted   $BM_PROG repair BOND
  Keep / undo last change     $BM_PROG commit  |  $BM_PROG rollback
EOF
}

# ---- modes ------------------------------------------------------------------

bm::help::mode_short() { # a two-word nickname shown next to the kernel name
  case "$1" in
    active-backup) echo "failover" ;;
    802.3ad) echo "LACP" ;;
    balance-alb) echo "adaptive balancing" ;;
    balance-tlb) echo "transmit balancing" ;;
    balance-xor) echo "hash balancing" ;;
    balance-rr) echo "round-robin" ;;
    broadcast) echo "broadcast" ;;
    *) echo "$1" ;;
  esac
}

bm::help::mode_label() { # one plain sentence per mode (BM_MODE_HELP, 18-val)
  printf '%s\n' "${BM_MODE_HELP[$1]:-$1}"
}

bm::help::mode_switch_needs() { # none | lacp | static
  case "$1" in
    802.3ad) echo lacp ;;
    balance-rr | balance-xor | broadcast) echo static ;;
    *) echo none ;;
  esac
}

bm::help::mode_alias() { # mode_alias <word> -> kernel mode name, or nothing
  local w="${1,,}"
  case "$w" in
    lacp | 8023ad | 802.3 | 802-3ad | ieee802.3ad | 4) echo 802.3ad ;;
    failover | ab | active-passive | activebackup | active_backup | 1) echo active-backup ;;
    round-robin | roundrobin | rr | 0) echo balance-rr ;;
    xor | 2) echo balance-xor ;;
    tlb | 5) echo balance-tlb ;;
    alb | 6) echo balance-alb ;;
    3) echo broadcast ;;
    *)
      if bm::val::mode "$w"; then echo "$w"; fi
      ;;
  esac
  return 0
}

# ---- health reasons, results, safety -------------------------------------

# Turn one bond_health reason into plain words plus what to do about it.
# Prints two lines: the explanation, then "What to do: ...".
bm::help::explain_reason() { # explain_reason <reason>
  local r="$1" what="" todo=""
  case "$r" in
    "bond device not present in kernel")
      what="The bond is not running right now - only its saved settings exist."
      todo="Bring it up (nmcli connection up NAME) or check that its ports exist." ;;
    "bond operstate is "*)
      what="The bond itself is not up (the kernel says ${r#bond operstate is })."
      todo="Usually every cable is unplugged or the switch ports are disabled." ;;
    "bond has no members")
      what="The bond has no network ports in it, so it cannot carry traffic."
      todo="Add a port: menu 'Change a bond' > 'Add a port' (or: $BM_PROG add-member)." ;;
    "member "*" MII status is "*)
      local m="${r#member }"
      m="${m%% *}"
      what="Port $m has no link: the cable is unplugged or broken, or the switch port is off."
      todo="Check the cable and the switch port. The other ports keep the bond working." ;;
    "member speed mismatch"*)
      what="The ports run at different speeds ${r#member speed mismatch }. Traffic gets uneven."
      todo="Use ports of the same speed, or check speed/auto-negotiation on the switch." ;;
    "member "*" duplex is "*)
      local d="${r#member }"
      d="${d%% *}"
      what="Port $d runs at half duplex, which is slow and error-prone."
      todo="Check the cable and the switch port settings (it should say full duplex)." ;;
    "no member has link")
      what="None of the bond's ports has a link, so this bond carries no traffic."
      todo="Check the cables and switch ports of every port in the bond." ;;
    "no LACP partner"*)
      what="The switch is not answering LACP: its ports are probably not set up as an LACP bundle."
      todo="Ask the network team for an LACP port-channel on these switch ports, or use active-backup." ;;
    "LACP partner churn"*)
      what="LACP talks to the switch but cannot agree - often ports split across two separate switches."
      todo="Check the switch port-channel. During a switch migration, use active-backup." ;;
    *)
      what="$r"
      todo="Run a closer look: $BM_PROG diagnose BOND" ;;
  esac
  printf '%s\nWhat to do: %s\n' "$what" "$todo"
}

bm::help::health_word() { # healthy | needs attention | DOWN
  case "$1" in
    healthy) echo "healthy" ;;
    degraded) echo "needs attention" ;;
    down) echo "DOWN" ;;
    *) echo "$1" ;;
  esac
}

bm::help::tier_sentence() { # tier_sentence <checkpoint|deadman|snapshot>
  case "$1" in
    checkpoint) echo "Safety net: if you do not confirm, NetworkManager undoes the change by itself - even if the change cuts your connection." ;;
    deadman) echo "Safety net: if you do not confirm, a system timer undoes the change by itself." ;;
    snapshot) echo "Safety net: a backup copy only - nothing undoes the change automatically. Have console access ready." ;;
    *) echo "Safety net: $1" ;;
  esac
}

bm::help::tier_short() { # for the dashboard
  case "$1" in
    checkpoint) echo "automatic undo (NetworkManager)" ;;
    deadman) echo "automatic undo (backup timer)" ;;
    snapshot) echo "backup copy only - nothing undoes changes automatically" ;;
    *) echo "$1" ;;
  esac
}

# Plain-words summary of how an action ended. Fills BM_HELP_TITLE,
# BM_HELP_STYLE (ok|warn|err|info) and BM_HELP_LINES.
BM_HELP_TITLE=""
BM_HELP_STYLE=info
BM_HELP_LINES=()
bm::help::explain_rc() { # explain_rc <rc> [outcome] [practice 0|1] [tier]
  # practice mode shows in the outcome (dry-run); $3 no longer changes the words
  local rc="$1" outcome="${2:-}" tier="${4:-}"
  BM_HELP_LINES=()
  case "$rc:$outcome" in
    0:committed)
      BM_HELP_TITLE="Done - the change is live and kept."
      BM_HELP_STYLE=ok
      BM_HELP_LINES=("All checks passed and you confirmed it.") ;;
    0:dry-run)
      BM_HELP_TITLE="Practice run finished - nothing was changed."
      BM_HELP_STYLE=info
      BM_HELP_LINES=("The plan above is exactly what would run for real."
        "To do it for real: switch practice mode off (key p) and repeat.") ;;
    0:cancelled)
      BM_HELP_TITLE="Cancelled - nothing was changed."
      BM_HELP_STYLE=info ;;
    0:noop)
      BM_HELP_TITLE="Nothing to do - it is already set up that way."
      BM_HELP_STYLE=ok ;;
    0:undone)
      BM_HELP_TITLE="Undone - the settings from before the change are back."
      BM_HELP_STYLE=ok
      BM_HELP_LINES=("The messages above list what was brought back up.") ;;
    0:gone)
      BM_HELP_TITLE="Nothing was waiting any more."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("The safety net had already undone the change (its time ran out), or it was kept or undone from another session."
        "The dashboard shows what runs now; 'Check my bonds' says whether all is well.") ;;
    0:*)
      # not "nothing was changed" in practice mode: a support bundle, for
      # one, is written either way
      BM_HELP_TITLE="Finished."
      BM_HELP_STYLE=ok
      BM_HELP_LINES=("See the messages above for details.") ;;
    "$BM_EX_USAGE":*)
      BM_HELP_TITLE="Something you entered was not accepted - nothing was changed."
      BM_HELP_STYLE=err
      BM_HELP_LINES=("The red ERROR line above says what, and 'Next step' how to fix it.") ;;
    "$BM_EX_PRECONDITION":*)
      BM_HELP_TITLE="Could not start - nothing was changed."
      BM_HELP_STYLE=err
      BM_HELP_LINES=("The ERROR line above says why (and what to do next).") ;;
    "$BM_EX_LOCKED":*)
      BM_HELP_TITLE="Another bond-manager is busy on this server - nothing was changed."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("Wait for it to finish, then try again.") ;;
    "$BM_EX_VERIFY":expired)
      BM_HELP_TITLE="Time ran out, so the change was undone."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("Your network is back the way it was before.") ;;
    "$BM_EX_VERIFY":lost)
      BM_HELP_TITLE="Too late to keep it - the safety net had already undone the change."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("Check the result with 'Check my bonds'.") ;;
    "$BM_EX_VERIFY":*)
      BM_HELP_TITLE="The change was undone - everything is back as it was."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("Either a check failed (see the FAIL lines above) or you chose Undo."
        "Nothing is left half-done.") ;;
    "$BM_EX_PARTIAL":*)
      BM_HELP_TITLE="The change is live but NOT kept yet."
      BM_HELP_STYLE=warn
      if [[ "$tier" == snapshot ]]; then
        BM_HELP_LINES=("Nothing on this server undoes it automatically (snapshot-only protection)."
          "Keep it or undo it: menu 'Undo & safety' (or: $BM_PROG commit / $BM_PROG rollback).")
      else
        BM_HELP_LINES=("It will undo itself automatically unless you keep it."
          "Keep it: menu 'Undo & safety' (or: $BM_PROG commit).")
      fi ;;
    130:*)
      BM_HELP_TITLE="You stopped it."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("If a change had already started, its safety net is still armed.") ;;
    "$BM_EX_DEGRADED":* | "$BM_EX_DOWN":*)
      BM_HELP_TITLE="Some bonds need attention."
      BM_HELP_STYLE=warn
      BM_HELP_LINES=("The reasons and what to do are listed above.") ;;
    *)
      BM_HELP_TITLE="Something went wrong (code $rc)."
      BM_HELP_STYLE=err
      BM_HELP_LINES=("Read the messages above; the full record is in $BM_LOG_FILE.") ;;
  esac
}

bm::help::speed_label() { # speed_label <Mb/s|unknown> -> 10G, 1G, 100M, -
  local s="$1"
  if [[ ! "$s" =~ ^[0-9]+$ ]]; then
    echo "-"
  elif (( s >= 1000 && s % 1000 == 0 )); then
    echo "$(( s / 1000 ))G"
  elif (( s >= 1000 )); then
    echo "$(( s / 100 ))" | sed 's/\(.\)$/.\1G/'
  else
    echo "${s}M"
  fi
}

bm::help::option_help() { # one line per bond option key
  case "$1" in
    miimon) echo "How often (ms) to check each port's link. 100 is a good default." ;;
    updelay) echo "Wait this long (ms) after a link comes back before using it again." ;;
    downdelay) echo "Wait this long (ms) after a link drops before giving up on it." ;;
    use_carrier) echo "1 = trust the driver's link signal (normal); 0 = older method." ;;
    primary) echo "The port to prefer whenever it has a link (failover-style modes)." ;;
    primary_reselect) echo "When the preferred port returns: always | better | failure." ;;
    fail_over_mac) echo "How the MAC address moves on failover: none | active | follow." ;;
    lacp_rate) echo "How often LACP talks to the switch: fast (1s) or slow (30s)." ;;
    xmit_hash_policy) echo "How traffic is split across ports: layer2 | layer2+3 | layer3+4 ..." ;;
    ad_select) echo "Which LACP group wins: stable | bandwidth | count." ;;
    min_links) echo "Minimum working ports before the bond reports itself up." ;;
    arp_interval) echo "Check links by ARP-pinging a target every N ms (instead of miimon)." ;;
    arp_ip_target) echo "The IPv4 address(es) to ARP-ping when arp_interval is used." ;;
    arp_validate) echo "Which ARP replies count as proof of life: none | active | backup | all." ;;
    arp_all_targets) echo "A port is up if any / all ARP targets answer." ;;
    num_grat_arp | num_unsol_na) echo "How many announcements to send after a failover." ;;
    resend_igmp) echo "How many IGMP reports to resend after a failover." ;;
    all_slaves_active) echo "1 = accept traffic on standby ports too (rarely needed)." ;;
    lp_interval) echo "Seconds between learning packets (tlb/alb modes)." ;;
    packets_per_slave) echo "Packets per port before moving to the next (round-robin)." ;;
    tlb_dynamic_lb) echo "1 = rebalance by load; 0 = by hash only (tlb mode)." ;;
    ad_actor_sys_prio | ad_actor_system | ad_user_port_key) echo "Advanced LACP identity setting. Leave alone unless the network team asks." ;;
    *) echo "Advanced bonding option (see the kernel bonding documentation)." ;;
  esac
}

# ---- topics -----------------------------------------------------------------

bm::help::topic_title() {
  case "$1" in
    basics) echo "What is a bond? (start here)" ;;
    modes) echo "Which bond mode should I pick?" ;;
    lacp) echo "LACP and the switch" ;;
    safety) echo "The safety net: how changes undo themselves" ;;
    practice) echo "Practice mode" ;;
    moving) echo "Moving a server to a new switch" ;;
    glossary) echo "Words you will see" ;;
    keys) echo "Keys in the menus" ;;
    exit-codes) echo "Exit codes (for scripts)" ;;
    *) echo "$1" ;;
  esac
}

bm::help::topic() { # topic <name> — rc 1 if unknown
  local t="$1"
  case "$t" in
    basics) cat <<EOF
WHAT IS A BOND?

A bond joins two (or more) network ports into one. The server sees a single
connection - say bond0 with one IP address - that runs over several cables.
If a cable, a network card or a switch dies, traffic keeps flowing over the
others. Depending on the mode, the ports can also share the load.

    cable 1 --\\
               >== bond0 (one IP) ==> the server
    cable 2 --/

The ports inside a bond are called its "members" (or "ports"). Each one is
a network card such as ens1f0 or eth1. A VLAN is a tagged network riding on
top of the bond, e.g. bond0.120.

WHAT THIS TOOL DOES FOR YOU

Changing a bond on a live server is risky: one wrong step and you cut off the
SSH session you are typing in. bond-manager makes every change safe:

  1. It shows you the exact plan first (and can stop there: practice mode).
  2. It saves a backup copy of the network settings.
  3. It arms a safety net that undoes the change if you do not confirm it.
  4. It makes the change, then checks the real kernel state.
  5. If a check fails it undoes everything by itself. If all is well, it asks
     you to keep the change - and undoes it if you never answer.

Start with:  sudo $BM_PROG        (menus; press p for practice mode)
       or:   $BM_PROG list        (are my bonds OK?)
EOF
      ;;
    modes) cat <<EOF
WHICH BOND MODE SHOULD I PICK?

Not sure? Pick active-backup. It works with any switch and never needs the
network team.

  Mode           What it does                     Switch setup needed?
  -------------  -------------------------------  -------------------------
  active-backup  One port works, the others wait. No
  802.3ad        LACP: all ports carry traffic.   YES - an LACP bundle
  balance-alb    Shares traffic in and out.       No
  balance-tlb    Shares outgoing traffic.         No
  balance-xor    Shares traffic by address.       Yes - static port-channel
  balance-rr     Packets take turns per port.     Yes - static port-channel
  broadcast      Everything on every port.        Yes - special cases only

If the switch is not set up for the mode you pick, the bond may come up but
pass no traffic - bond-manager's checks will notice and undo the change.
EOF
      ;;
    lacp) cat <<EOF
LACP AND THE SWITCH

802.3ad (LACP) lets all ports carry traffic at once, but it is a deal between
the server AND the switch: the switch ports must be configured as one LACP
bundle (Cisco: "port-channel ... mode active"; others: "LAG", "trunk group").

- If the switch side is not set up, the bond has "no LACP partner" and may
  carry no traffic. '$BM_PROG diagnose BOND' shows this.
- All ports of an LACP bond must end on ONE switch, or on a pair of switches
  that act as one (MLAG, vPC, a stack).
- Moving to a new switch one cable at a time means one leg on each switch for
  a while. Unless the two switches share an LACP group, switch the bond to
  active-backup first, move both cables, then switch back to 802.3ad.
EOF
      ;;
    safety) cat <<EOF
THE SAFETY NET: HOW CHANGES UNDO THEMSELVES

Every change follows the same steps:

  plan -> backup copy -> arm the safety net -> change -> check -> keep?

- Plan: the exact nmcli commands are shown before anything happens.
- Backup copy: the saved network settings are archived (a "snapshot").
- Safety net: the strongest one this server supports.
    automatic undo (NetworkManager)  NetworkManager itself undoes the change
                                     if it is not confirmed in time - even if
                                     the change cut your SSH session.
    automatic undo (backup timer)    a system timer restores the backup copy.
    backup copy only                 nothing automatic; undo by hand.
  '$BM_PROG doctor' tells you which one you get.
- Check: the real kernel state is read back. A failed check undoes the
  change immediately.
- Keep?: you get a countdown (default $(bm::config::get ROLLBACK_WINDOW) seconds). Press K to keep the
  change, U to undo it. Do nothing and it is undone.

IF YOUR SSH SESSION DROPS

Do not panic. Wait for the countdown to run out and reconnect - the change
will have been undone. If you can reconnect before that, run
  sudo $BM_PROG commit      to keep the change, or
  sudo $BM_PROG rollback    to undo it now.
EOF
      ;;
    practice) cat <<EOF
PRACTICE MODE

In practice mode bond-manager does everything except change the server: you
go through the same questions and see the exact plan, and it stops there.
Nothing is written, no backup is taken, no network is touched.

- In the menus: press p (or pick "Practice mode") to switch it on or off.
  If you are not root it is always on.
- On the command line: add -n (or --dry-run), e.g.
    $BM_PROG -n swap-member bond0 --old ens1f0 --new ens2f0
EOF
      ;;
    moving) cat <<EOF
MOVING A SERVER TO A NEW SWITCH (NO OUTAGE)

A bond survives losing one cable, so you move one cable at a time:

  1. Plug a free port into the new switch.
  2. Swap it into the bond in place of one old port:
       $BM_PROG swap-member bond0 --old ens1f0 --new ens2f0
     bond-manager adds the new port, WAITS until it really works, and only
     then removes the old one. The bond is never short a leg.
  3. Keep the change, then repeat for the other cable.

LACP bonds (802.3ad): unless the old and new switches are one LACP group,
switch to active-backup for the move, then back:
       $BM_PROG modify bond0 --mode active-backup
       ...swap both cables...
       $BM_PROG modify bond0 --mode 802.3ad

In the menus: "Move a bond to a new switch" walks you through all of this.
EOF
      ;;
    glossary) cat <<EOF
WORDS YOU WILL SEE

bond           Several network ports acting as one connection (e.g. bond0).
port / member  One network card inside a bond (e.g. ens1f0). "Enslaved" is
               the kernel's word for "is a member".
NIC            Network interface card - a network port.
link           A working cable connection. "No link" = unplugged cable,
               broken cable, or a switch port that is off.
mode           How the bond uses its ports (see: $BM_PROG help modes).
LACP / 802.3ad A mode where server and switch agree to use all ports.
VLAN           A tagged network on top of the bond, e.g. bond0.120 = VLAN 120.
MTU            The largest packet size. 1500 is normal; 9000 = "jumbo frames"
               (only if every switch in the path allows it).
profile        A saved NetworkManager setting (what 'nmcli connection' lists).
snapshot       A backup copy of all saved network settings.
checkpoint     NetworkManager's own undo point; the strongest safety net.
commit / keep  Confirm a change so it is not undone.
rollback/undo  Put the network back the way it was.
drift          When the saved settings no longer match what the kernel runs.
EOF
      ;;
    keys) cat <<EOF
KEYS IN THE MENUS

  Up / Down (or k / j)   move
  Enter (or Right)       choose
  1-9                    choose item by number
  Esc, q (or Left)       go back
  Space                  tick / untick (lists with checkboxes)
  a / n                  tick all / none
  p                      practice mode on/off (main menu)
  r                      refresh (main menu)
  ?                      help (main menu)

While a change waits for you:  K = keep it,  U = undo it,  E = 5 more minutes

Plain mode (--plain, serial consoles): type the number and press Enter;
q goes back.
EOF
      ;;
    exit-codes) cat <<EOF
EXIT CODES (FOR SCRIPTS AND MONITORING)

  0   success, or nothing to do
  1   error
  2   usage error (something typed wrong)
  3   could not start (not root, NetworkManager down, bond missing, ...)
  4   another bond-manager is running
  5   the change failed its checks and was undone
      (also: 'commit' found the change already undone)
  6   applied but not confirmed yet (no terminal to ask on)
  10  status: at least one bond needs attention
  11  status: at least one bond is down
EOF
      ;;
    *) return 1 ;;
  esac
}

# ---- per-command help --------------------------------------------------------

bm::help::command() { # command <name> — rc 1 if unknown
  local c
  c="$(bm::help::canonical "$1")" || return 1
  local p="$BM_PROG"
  case "$c" in
    list) cat <<EOF
$p list - one line per bond: name, mode, health

Shows every bond on this server and whether it is healthy. Needs no root and
changes nothing.

Usage:
  $p list
  $p --json list          (machine-readable)

Examples:
  $p list

See also: $p status, $p show BOND
EOF
      ;;
    show) cat <<EOF
$p show - everything about one bond

Mode, health (with reasons), link monitoring, the active port, every member
with its link state and speed, addresses and VLANs. Read-only.

Usage:
  $p show BOND
  $p --json show BOND

Examples:
  $p show bond0

See also: $p diagnose BOND (deeper), $p list
EOF
      ;;
    status) cat <<EOF
$p status - health check, made for monitoring

Like 'show' for every bond (or one), and the exit code says how it went:
0 = all healthy, 10 = something needs attention, 11 = something is down.
Read-only; safe to run from cron or a monitoring agent.

Usage:
  $p status [BOND]
  $p --json status [BOND]

Examples:
  $p status
  $p status bond0 || echo "bond0 needs attention"

See also: $p help exit-codes
EOF
      ;;
    diagnose) cat <<EOF
$p diagnose - a closer look at one bond, for troubleshooting

Shows the kernel's own view of the bond, a plain health verdict, the link of
every port, LACP partner details (802.3ad), addresses, and a ping test
through the bond. --extended adds the saved profiles, driver details and the
recent NetworkManager log. Read-only.

Usage:
  $p diagnose BOND [--extended] [--target IP]

Examples:
  $p diagnose bond0
  $p diagnose bond0 --extended --target 10.0.0.1

See also: $p verify BOND, $p help lacp
EOF
      ;;
    verify) cat <<EOF
$p verify - re-run the safety checks against the bond as it is now

The same checks that run after every change: bond exists, is up, has the
right mode, members really are members, the gateway answers. Read-only.
Exit code 1 if a check fails.

Usage:
  $p verify BOND

Examples:
  $p verify bond0
EOF
      ;;
    doctor) cat <<EOF
$p doctor - is this server ready, and how well am I protected?

Checks that the tools bond-manager needs are present, that NetworkManager is
running, and which safety net changes will get (see: $p help safety).
Run it once on every new server. Read-only.

Usage:
  $p doctor
EOF
      ;;
    nics) cat <<EOF
$p nics - which network ports are there, and can I use them?

Lists every network port with its link state, speed, which bond it is in,
its addresses, and a plain note: "free - good to use", "no link - cable or
switch port?", "has an IP - probably in use", "carries your SSH connection".
Read-only; needs no root.

Usage:
  $p nics [--all]

  --all   also list ports the NIC policy hides (virtual devices etc.)

Examples:
  $p nics

See also: $p create, $p swap-member
EOF
      ;;
    config) cat <<EOF
$p config - show the settings in effect

Usage:
  $p config show     every setting and its current value
  $p config path     where the config file lives

The file ($BM_CONF) is read, never executed.
Create a commented default with 'sudo $p init'.
EOF
      ;;
    completion) cat <<EOF
$p completion - tab completion for bash

Usage:
  $p completion bash > /etc/bash_completion.d/bond-manager
EOF
      ;;
    help) cat <<EOF
$p help - explanations and examples

Usage:
  $p help            the overview
  $p help COMMAND    one command, with examples (= COMMAND --help)
  $p help TOPIC      a topic explained in plain words

Topics: ${BM_HELP_TOPICS[*]}

Examples:
  $p help swap-member
  $p help modes
EOF
      ;;
    create) cat <<EOF
$p create - build a new bond from free network ports

Joins two or more free ports into one bond, optionally with an IP address
and VLANs, then checks it really works.

Usage:
  $p create BOND --mode MODE --members IF1,IF2 [options]

  --mode MODE        active-backup (safe choice), 802.3ad (LACP), ...
                     see: $p help modes
  --members A,B      the ports to use (see: $p nics)
  --ip4 dhcp|none|ADDRESS/PREFIX   --gw4 GATEWAY   --dns4 A,B
  --ip6 auto|dhcp|none|ADDRESS/PREFIX  --gw6 GATEWAY  --dns6 A,B
  --vlan VID[:ip4=..;gw4=..]   add a VLAN (repeatable)
  --mtu N   --no-activate   --opt key=value (advanced)

Examples:
  $p -n create bond0 --mode active-backup \\
      --members ens1f0,ens1f1 --ip4 dhcp
  sudo $p create bond0 --mode 802.3ad --members ens1f0,ens1f1 \\
      --ip4 10.0.0.10/24 --gw4 10.0.0.1 --dns4 10.0.0.53

Good to know:
  - Pick free ports: '$p nics' marks them "free - good to use".
  - 802.3ad needs the switch ports set up as an LACP bundle first.
  - The whole change is undone automatically if you do not confirm it.
EOF
      ;;
    modify) cat <<EOF
$p modify - change an existing bond's mode, options, IP or MTU

Only what you name is changed; everything else stays as it is.

Usage:
  $p modify BOND [--mode MODE] [--opt K=V]... [--del-opt KEY]...
      [--ip4 ...] [--gw4 ...] [--dns4 ...] [--ip6 ...] [--mtu N]
  shortcuts: --miimon MS  --primary IF  --lacp-rate fast|slow
      --xmit-hash POLICY  --min-links N  --arp-interval MS --arp-targets IP

Examples:
  $p -n modify bond0 --mode active-backup
  sudo $p modify bond0 --primary ens1f0
  sudo $p modify bond0 --ip4 10.0.0.10/24 --gw4 10.0.0.1

Good to know:
  - Changing the mode drops options that only made sense in the old mode,
    and tells you which.
  - A new address keeps the old gateway and DNS unless you say otherwise:
    --gw4 none / --dns4 none remove them. --ip4 dhcp drops the old address.
  - Changing the IP of the address you are logged in on will cut your
    session: open a new session to the new address and run
    'sudo $p commit' before the countdown ends.
EOF
      ;;
    add-member) cat <<EOF
$p add-member - add one or more ports to a bond

Usage:
  $p add-member BOND IF[,IF...]

Examples:
  $p -n add-member bond0 ens1f2
  sudo $p add-member bond0 ens1f2,ens1f3

Good to know:
  - The new port should be plugged in and have a link ('$p nics').
  - For 802.3ad, the switch port must join the same LACP bundle.
EOF
      ;;
    remove-member) cat <<EOF
$p remove-member - take one or more ports out of a bond

Usage:
  $p remove-member BOND IF[,IF...]

Examples:
  $p -n remove-member bond0 ens1f1
  sudo $p remove-member bond0 ens1f1

Good to know:
  - A bond with one port left still works, but has no spare.
  - Removing the LAST port takes the bond down; you are asked first.
  - To replace a port, use swap-member instead - it never leaves a gap.
EOF
      ;;
    swap-member) cat <<EOF
$p swap-member - replace a bond port with another, with no outage

The tool for moving a live server to a new switch, one cable at a time. It
adds the new port, WAITS until the kernel really uses it, and only then
removes the old one - so the bond is never short a leg.

Usage:
  $p swap-member BOND --old IF --new IF

Examples:
  $p -n swap-member bond0 --old ens1f0 --new ens2f0      (preview)
  sudo $p swap-member bond0 --old ens1f0 --new ens2f0
  sudo $p swap-member bond0 --old ens1f1 --new ens2f1

Good to know:
  - The new port must have a link before you start ('$p nics').
  - 802.3ad (LACP) across two separate switches will not aggregate; switch
    to active-backup for the move (see: $p help moving).
EOF
      ;;
    remove) cat <<EOF
$p remove - delete a bond and its saved settings

Deletes the bond's profile, its member profiles and (unless --keep-vlans)
its VLAN profiles. You are asked to type the bond name to confirm.

Usage:
  $p remove BOND [--keep-vlans]

Examples:
  $p -n remove bond1
  sudo $p remove bond1

Good to know:
  - Removing the bond your SSH session uses will disconnect you (the safety
    net then undoes it, if the server supports automatic undo).
EOF
      ;;
    vlan) cat <<EOF
$p vlan - add, change, remove or list VLANs on a bond

Usage:
  $p vlan add BOND VID[:ip4=ADDR/PREFIX;gw4=GW;dns4=DNS]
  $p vlan modify BOND VID [--ip4 ...] [--gw4 ...] [--ip6 ...]
  $p vlan remove BOND VID
  $p vlan list BOND

Examples:
  $p -n vlan add bond0 120
  sudo $p vlan add bond0 '120:ip4=10.20.30.40/24;gw4=10.20.30.1'
  sudo $p vlan remove bond0 120

Good to know:
  - The switch ports must carry the VLAN (tagged/trunk) for it to work.
  - Quote the VID:settings part - the ';' would otherwise end the command.
EOF
      ;;
    clone) cat <<EOF
$p clone - copy a bond's settings onto a new bond with other ports

Usage:
  $p clone SRC DST --members IF[,IF...] [--copy-ip] [--copy-vlans]

Examples:
  $p -n clone bond0 bond1 --members ens2f0,ens2f1
  sudo $p clone bond0 bond1 --members ens2f0,ens2f1 --copy-vlans

Good to know:
  - --copy-ip copies the IP too: two bonds with the same IP conflict, so
    only use it when the old bond is going away.
EOF
      ;;
    repair) cat <<EOF
$p repair - make the saved settings match what the bond really runs

Bonds drift: a port gets added by hand and never saved, or a saved port no
longer exists. The next reboot then brings the bond back wrong. repair
saves a profile for every real member that lacks one and deletes profiles
for ports that are no longer members.

Usage:
  $p repair BOND

Examples:
  $p -n repair bond0      (which way did it drift? changes nothing)
  sudo $p repair bond0
EOF
      ;;
    commit) cat <<EOF
$p commit - keep the last change (stop the automatic undo)

Normally you press K when asked. Use this from a NEW session when the
change cut your old one - for example after changing the IP you were
logged in on.

Usage:
  sudo $p commit

Exit code 5 means you were too late: the change had already been undone.
EOF
      ;;
    rollback) cat <<EOF
$p rollback - undo the last change now, or restore a backup copy

Usage:
  sudo $p rollback                    undo the change that is waiting
  sudo $p rollback --snapshot ID      restore a specific backup copy

Examples:
  sudo $p snapshot list
  sudo $p -n rollback --snapshot 20260101-120000  (what would change)
EOF
      ;;
    snapshot) cat <<EOF
$p snapshot - backup copies of all saved network settings

A snapshot is taken automatically before every change.

Usage:
  sudo $p snapshot list         the copies there are
  sudo $p snapshot diff ID      what restoring ID would change
  sudo $p snapshot create       take one now
  sudo $p snapshot restore [ID] restore one (default: the newest)
  sudo $p snapshot prune        keep only the newest $(bm::config::get MAX_BACKUPS)
EOF
      ;;
    bundle) cat <<EOF
$p bundle - collect everything support needs in one file

Usage:
  sudo $p bundle [--output PATH] [--redact]

  --redact   hide IP and MAC addresses (for tickets that leave the site)
EOF
      ;;
    init) cat <<EOF
$p init - install a commented default config and log rotation

Usage:
  sudo $p init

Writes $BM_CONF (if missing) and a logrotate policy.
Optional: without a config file the defaults are used.
EOF
      ;;
    tui) cat <<EOF
$p tui - the guided menus

The same as running $p with no arguments on a terminal. Every menu
explains itself, practice mode (key p) lets you try things safely, and each
change shows the command line that does the same thing.

Usage:
  sudo $p            (or: $p tui)
  $p --plain         numbered menus for serial consoles

See also: $p help keys
EOF
      ;;
    version) cat <<EOF
$p version - print the version (same as --version)
EOF
      ;;
  esac
  return 0
}
