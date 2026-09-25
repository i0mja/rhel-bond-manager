#!/usr/bin/env python3
"""capture.py: record real bond-manager screens for the tour.

Runs bond_manager.sh in a pseudo-terminal against the fake server that
sandbox.sh builds, presses keys like a person would, and saves what the
terminal shows after each step to docs/tour/tour.json. render.py turns that
into the README tour, the SVG screens and the interactive page.

Needs python3 and the pyte terminal emulator (pip install pyte). Run it with
`make tour`, which renders the result as well.
"""
import atexit, json, os, pty, select, shutil, signal, struct, fcntl, termios, tempfile, time, subprocess, sys

try:
    import pyte
except ImportError:
    sys.exit('capture.py needs the pyte module: pip install pyte')

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
OUT = os.path.join(ROOT, 'docs', 'tour', 'tour.json')
COLS, ROWS = 100, 34
SANDBOX_SH = os.path.join(HERE, 'sandbox.sh')
SCRATCH = tempfile.mkdtemp(prefix='bm-tour.')
atexit.register(shutil.rmtree, SCRATCH, True)

FG = {'default': None, 'black': 'k', 'red': 'r', 'green': 'g', 'brown': 'y', 'yellow': 'y',
      'blue': 'b', 'magenta': 'm', 'cyan': 'c', 'white': 'w', 'brightblack': 'd',
      'brightred': 'r', 'brightgreen': 'g', 'brightbrown': 'y', 'brightyellow': 'y',
      'brightblue': 'b', 'brightmagenta': 'm', 'brightcyan': 'c', 'brightwhite': 'W'}


def reset_world():
    # fresh fixtures for every flow, exported into this process
    out = subprocess.run(['bash', '-c', 'source "$1" >/dev/null && env -0', '_', SANDBOX_SH],
                         env=dict(os.environ, TOUR_SB=os.path.join(SCRATCH, 'sb')),
                         capture_output=True, check=True).stdout
    env = dict(kv.split('=', 1) for kv in out.decode().split('\0') if '=' in kv)
    env.update(TERM='xterm-256color', LANG='C.UTF-8', LC_ALL='C.UTF-8',
               COLUMNS=str(COLS), LINES=str(ROWS))
    return env


class Session:
    def __init__(self, argv, env):
        self.screen = pyte.Screen(COLS, ROWS)
        self.stream = pyte.ByteStream(self.screen)
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', ROWS, COLS, 0, 0))
            os.execvpe(argv[0], argv, env)
        self.pump(1.0)

    def pump(self, t):
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    return
                if not data:
                    return
                # pyte ignores SGR 2 (dim); show it as bright black instead
                self.stream.feed(data.replace(b'\x1b[2m', b'\x1b[90m'))

    def text(self):
        return '\n'.join(self.screen.display)

    def wait(self, needle, timeout=15):
        end = time.time() + timeout
        while time.time() < end:
            if needle in self.text():
                self.pump(0.35)
                return
            self.pump(0.1)
        raise SystemExit(f'timeout waiting for {needle!r}\n----\n{self.text()}')

    def keys(self, k, settle=0.5):
        os.write(self.fd, k.encode('latin-1') if isinstance(k, str) else k)
        self.pump(settle)

    def frame(self):
        rows = []
        for y in range(ROWS):
            line = self.screen.buffer[y]
            segs, cur, txt = [], None, ''
            for x in range(COLS):
                ch = line[x]
                cls = []
                f = FG.get(ch.fg, None) if isinstance(ch.fg, str) else None
                if f:
                    cls.append('f' + f)
                b = FG.get(ch.bg, None) if isinstance(ch.bg, str) else None
                if b:
                    cls.append('b' + b)
                if ch.bold:
                    cls.append('B')
                if ch.reverse:
                    cls.append('R')
                key = ' '.join(cls)
                if key != cur:
                    if txt:
                        segs.append([cur or '', txt])
                    cur, txt = key, ''
                txt += ch.data
            if txt:
                segs.append([cur or '', txt])
            # drop trailing unstyled blanks
            while segs and segs[-1][0] == '' and not segs[-1][1].strip():
                segs.pop()
            if segs and segs[-1][0] == '':
                segs[-1][1] = segs[-1][1].rstrip()
            rows.append(segs)
        return rows

    def close(self):
        try:
            os.kill(self.pid, signal.SIGTERM)
            os.waitpid(self.pid, 0)
        except Exception:
            pass


FLOWS = []


def flow(fid, title, blurb):
    f = {'id': fid, 'title': title, 'blurb': blurb, 'steps': []}
    FLOWS.append(f)
    return f


def snap(f, s, keys, text):
    f['steps'].append({'keys': keys, 'text': text, 'frame': s.frame()})


BM = 'bond-manager'

# ---- 1. home ---------------------------------------------------------------
env = reset_world()
f = flow('home', 'The home screen', 'What you see the moment you run sudo bond-manager.')
s = Session([BM], env)
s.wait('What do you want to do?')
snap(f, s, ['sudo bond-manager'],
     'The dashboard shows every bond, its ports and their links, which port carries your SSH connection, and how this server can undo a change. bond1 has a problem, and the first reason is explained in plain words.')
s.keys('\x1b[B'); s.keys('\x1b[B')
snap(f, s, ['↓', '↓'],
     'Arrow keys move the highlight. A number jumps straight to an item, Enter chooses, q quits. The badge in the corner says LIVE: changes will be real.')
s.keys('p')
s.wait('PRACTICE')
snap(f, s, ['p'],
     'p switches to practice mode. Everything works the same, but at the end you only see the exact plan; nothing on the server changes.')
s.close()

# ---- 2. check --------------------------------------------------------------
env = reset_world()
f = flow('check', 'Check my bonds', 'Health, with every problem explained and what to do about it.')
s = Session([BM], env)
s.wait('What do you want to do?')
s.keys('1')
s.wait('What would you like to see?')
snap(f, s, ['1'], 'Checking is read-only and needs no root.')
s.keys('\r')
s.wait('Press Enter to go back')
snap(f, s, ['Enter'],
     'Each problem comes with what it means and what to do. Here the switch ports behind bond1 were never set up as an LACP bundle.')
s.keys('\r'); s.wait('What would you like to see?')
s.keys('5'); s.wait('Press Enter to go back')
snap(f, s, ['5'],
     'The list of network ports says, for each one, whether you can use it.')
s.close()

# ---- 3. move ---------------------------------------------------------------
env = reset_world()
f = flow('move', 'Move to a new switch', 'Swap bond0 onto the new switch one cable at a time, live, with no outage.')
s = Session([BM], env)
s.wait('What do you want to do?')
s.keys('2')
s.wait('Which bond are you moving?')
snap(f, s, ['2'],
     'The wizard explains the idea first: the new port is added and must really work before the old one is removed.')
s.keys('\r')
s.wait('Port to replace')
snap(f, s, ['Enter'], 'Step 1: pick the port whose cable is still on the old switch.')
s.keys('\r')
s.wait('New port for bond0')
snap(f, s, ['Enter'],
     'Step 2: pick the free port cabled to the new switch. Ports already in a bond are not offered, and risky ones say why (eno1 has an IP, ens4f0 has no link).')
s.keys('2')
s.wait('Ready?')
snap(f, s, ['2'],
     'Nothing has happened yet. You pressed 2 for ens2f0. The summary says what will happen in plain words, warns that bond0 carries your SSH session, and shows the same thing as a command you can paste into a runbook.')
s.keys('\r')
s.wait('Apply this plan?')
snap(f, s, ['Enter'],
     'The exact nmcli commands, in order. Note step 3: it waits until the kernel really uses ens2f0 before step 4 removes ens1f0.')
s.keys('y\r')
s.wait('Auto-undo in')
s.pump(1.2)
snap(f, s, ['y', 'Enter'],
     'A backup copy is taken, the safety net is armed, the change runs and is checked against the kernel. Then it waits for you. If the change had cut your connection, doing nothing would undo it.')
s.keys('k')
s.wait('Press Enter to go back')
snap(f, s, ['K'], 'K keeps the change.')
s.keys('\r')
s.pump(1.0)
snap(f, s, ['Enter'], 'Move the other cable too? The wizard offers it straight away.')
s.keys('n\r')
s.wait('What do you want to do?')
snap(f, s, ['n', 'Enter'], 'Back home, the dashboard shows bond0 now running on ens1f1 and ens2f0.')
s.close()

# ---- 4. build --------------------------------------------------------------
env = reset_world()
f = flow('build', 'Build a new bond', 'Five short questions, in practice mode: see the plan, change nothing.')
s = Session([BM, '--dry-run'], env)
s.wait('What do you want to do?')
s.keys('3')
s.wait('Bond name')
snap(f, s, ['3'], 'Step 1 suggests the next free name. Esc always goes back one step.')
s.keys('\r')
s.wait('Ports for bond2')
s.keys('\x1b[B'); s.keys(' '); s.keys('\x1b[B'); s.keys(' ')
snap(f, s, ['Enter', '↓', 'Space', '↓', 'Space'],
     'Step 2 is a checklist of free ports: link, speed and anything to watch out for (no link, already has an IP).')
s.keys('\r')
s.wait('How should the ports work together?')
snap(f, s, ['Enter'],
     'Step 3: the safe choice comes first. Picking 802.3ad asks whether the switch is ready for LACP.')
s.keys('\r')
s.wait('IPv4 address for bond2')
s.keys('2')
s.wait('Address with prefix')
for c in '10.20.40.10':
    s.keys(c, 0.03)
s.keys('\r')
s.pump(0.5)
snap(f, s, ['2', '10.20.40.10', 'Enter'],
     'Step 4: typing mistakes are caught on the spot, with how to fix them.')
for c in '/24':
    s.keys(c, 0.03)
s.keys('\r'); s.wait('Gateway')
for c in '10.20.40.1':
    s.keys(c, 0.03)
s.keys('\r'); s.wait('DNS servers')
s.keys('\r'); s.wait('Extras (optional)')
s.keys('\r')
s.wait('Ready?')
snap(f, s, ['/24', 'Enter', '10.20.40.1', 'Enter', 'Enter', 'Enter'],
     'The review in plain words, and the command that does the same thing.')
s.keys('\r')
s.wait('Press Enter to go back')
snap(f, s, ['Enter'], 'In practice mode this is where it stops: the exact plan, and nothing changed.')
s.close()

# ---- 5. waiting change -------------------------------------------------------
env = reset_world()
deadline = int(time.time()) + 95
with open(os.path.join(env['BM_RUN_DIR'], 'pending.state'), 'w') as fh:
    fh.write(f"tier=checkpoint\ncheckpoint_path=/org/freedesktop/NetworkManager/Checkpoint/1\ndeadman_unit=\n"
             f"snapshot=20260925-141500\ndeadline={deadline}\ncreated=2026-09-25T14:15:00+0000\npid=4242\n"
             f"summary=modify bond bond0\n")
f = flow('pending', 'A change is waiting', 'When a session dropped, or you walked away before pressing K.')
s = Session([BM], env)
s.wait('What do you want to do?')
snap(f, s, ['sudo bond-manager'],
     'A banner counts down to the automatic undo, and "Keep or undo" is the first item.')
s.keys('\r')
s.wait('Decide later')
snap(f, s, ['Enter'], 'Keep it if everything works, or undo it now.')
s.close()

# ---- 6. help ---------------------------------------------------------------
env = reset_world()
f = flow('help', 'Help, in plain words', 'Nine short topics, written for someone who has never set up a bond.')
s = Session([BM, '--dry-run'], env)
s.wait('What do you want to do?')
s.keys('8')
s.wait('What would you like to know?')
snap(f, s, ['8'], 'The same text is available on the command line: bond-manager help TOPIC.')
s.keys('2')
s.wait('Press Enter to go back')
snap(f, s, ['2'], 'Which mode should I pick? The answer, and what each one asks of the switch.')
s.close()

# ---- 7. command line -----------------------------------------------------------
PROMPT = '\x1b[32m[root@web01 ~]#\x1b[0m '


def cli(f, cmd, text, keys=None, lines=None):
    env = reset_world()
    shown = cmd
    script = f"printf '%b' '{PROMPT}'; printf '%s\\n' {json.dumps(shown)}; {cmd}"
    if lines:
        script = f"printf '%b' '{PROMPT}'; printf '%s\\n' {json.dumps(shown)}; {cmd} 2>&1 | head -n {lines}"
    s = Session(['bash', '--norc', '--noprofile', '-c', script + '; sleep 30'], env)
    s.pump(1.5)
    snap(f, s, keys or [cmd], text)
    s.close()


f = flow('cli', 'On the command line', 'Every error says what to do next, and every command has help with examples.')
cli(f, 'bond-manager nics', 'Which ports can I use? A plain verdict for every port, and a ready-made command.')
cli(f, 'bond-manager create bond2 active-backup',
    'A mode typed without its flag: the ERROR line stays the same for scripts, and the Next step line says what was meant.')
cli(f, 'bond-manager move', 'Unknown commands get a suggestion by meaning, not only by spelling.')
cli(f, 'bond-manager help swap-member', 'Per-command help: plain words, usage, examples that always start with a -n preview.', lines=31)

# ---- 8. plain mode ---------------------------------------------------------------
env = reset_world()
env['TERM'] = 'vt100'
f = flow('plain', 'Serial consoles', 'No arrow keys or colors needed: numbered menus, 7-bit ASCII.')
s = Session([BM, '--plain'], env)
s.wait('Choose 1-10')
snap(f, s, ['sudo bond-manager --plain'],
     'The same menus on a serial console, a dumb terminal or with --plain: type the number and press Enter.')
s.close()

with open(OUT, 'w') as fh:
    json.dump({'cols': COLS, 'rows': ROWS, 'flows': FLOWS}, fh, ensure_ascii=False, separators=(',', ':'))
    fh.write('\n')
print('capture: wrote', os.path.relpath(OUT, ROOT), '-', sum(len(f['steps']) for f in FLOWS), 'screens')
