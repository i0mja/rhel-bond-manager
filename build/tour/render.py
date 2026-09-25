#!/usr/bin/env python3
"""render.py: turn docs/tour/tour.json into the tour people see on GitHub.

  docs/tour/hero.svg       an animated terminal for the top of the README
  docs/tour/<id>-<n>.svg   one still picture per screen
  docs/tour/index.html     the click-through page that GitHub Pages serves
  README.md                the hero and the chapters, between tour markers

Standard library only. `make tour` captures fresh screens first (that part
needs pyte); `make tour-render` only renders the screens already captured.
"""
import html
import json
import os
import re
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
TOUR = os.path.join(ROOT, 'docs', 'tour')
README = os.path.join(ROOT, 'README.md')
PAGES_URL = 'https://i0mja.github.io/rhel-bond-manager/'
REPO_URL = 'https://github.com/i0mja/rhel-bond-manager'
HERO_FLOW = 'move'

# The terminal palette; build/tour/page.html uses the same colours.
T_BG, T_BAR, T_EDGE, T_FG, T_CHROME = '#0A0F14', '#121920', '#222C36', '#D3DBE3', '#83919F'
FG = {'r': '#F07A78', 'g': '#74D38A', 'y': '#EFC263', 'b': '#72A9EA', 'm': '#C49AF0',
      'c': '#6CCFDC', 'w': T_FG, 'W': '#FFFFFF', 'k': T_BG, 'd': '#6A7887'}
BG = {'r': '#C2413E', 'g': '#2F8A48', 'y': '#EFC263', 'b': '#2F63A8', 'm': '#7D55B8',
      'c': '#2A8C98', 'w': T_FG, 'k': T_BG}

FS, CW, LH = 14, 8.4, 18          # font size, cell width, line height (px)
PAD, BAR = 16, 30                 # inner padding, title bar height
MONO = 'ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"DejaVu Sans Mono","Liberation Mono",monospace'
SANS = '-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif'

# Box-drawing characters are drawn as lines, so they join up whatever font
# the viewer has. Arms: left, right, up, down.
BOX = {'─': 'lr', '━': 'LR', '│': 'ud', '┌': 'rd', '┐': 'ld', '└': 'ru', '┘': 'lu',
       '├': 'udr', '┤': 'udl', '┬': 'lrd', '┴': 'lru', '┼': 'lrud'}
TEXT_STYLE = '︎'  # asks for the text (not emoji) form of ✔ and ✖


def esc(s):
    return html.escape(s, quote=False)


def num(v):
    return ('%.1f' % v).rstrip('0').rstrip('.')


def style_of(cls):
    """(text colour, background colour or None, bold) for a tour.json class string."""
    fg = bg = None
    bold = rev = False
    for tok in cls.split():
        if tok == 'B':
            bold = True
        elif tok == 'R':
            rev = True
        elif tok[0] == 'f':
            fg = FG.get(tok[1:])
        elif tok[0] == 'b':
            bg = BG.get(tok[1:])
    if rev:
        fg, bg = (bg or T_BG), (fg or T_FG)
    return fg or T_FG, bg, bold


def cells(row, cols):
    out = []
    for cls, text in row:
        out.extend((ch, cls) for ch in text)
    out = out[:cols]
    out.extend((' ', '') for _ in range(cols - len(out)))
    return out


def used_rows(frame):
    n = 0
    for i, row in enumerate(frame):
        if any(t.strip() for _, t in row):
            n = i + 1
    return n


def merge(segs):
    """Union of 1-D intervals keyed by their fixed coordinate."""
    out = []
    for key in sorted(segs):
        spans = sorted(segs[key])
        a, b = spans[0]
        for c, d in spans[1:]:
            if c <= b + 0.01:
                b = max(b, d)
            else:
                out.append((key, a, b))
                a, b = c, d
        out.append((key, a, b))
    return out


def screen_svg(frame, cols, nrows, x0, y0):
    """SVG elements that draw the first nrows rows of a frame at (x0, y0)."""
    rects, texts = [], []
    lines = {}  # (colour, width) -> {'h': {y: [(x1, x2)]}, 'v': {x: [(y1, y2)]}}
    for r in range(nrows):
        row = cells(frame[r], cols) if r < len(frame) else [(' ', '')] * cols
        top = y0 + r * LH
        base = top + 13.5
        c = 0
        while c < cols:
            cls = row[c][1]
            end = c
            while end < cols and row[end][1] == cls:
                end += 1
            fill, bg, bold = style_of(cls)
            if bg:
                rects.append('<rect x="%s" y="%s" width="%s" height="%d" fill="%s"/>'
                             % (num(x0 + c * CW), num(top), num((end - c) * CW), LH, bg))
            attrs = ''
            if fill != T_FG:
                attrs += ' fill="%s"' % fill
            if bold:
                attrs += ' font-weight="700"'
            run_start, run = None, ''

            def flush(start, text):
                stripped = text.rstrip()
                lead = len(stripped) - len(stripped.lstrip())
                stripped = stripped.lstrip()
                if not stripped:
                    return
                x = x0 + (start + lead) * CW
                texts.append('<text x="%s" y="%s" textLength="%s"%s>%s</text>'
                             % (num(x), num(base), num(len(stripped) * CW), attrs, esc(stripped)))

            for i in range(c, end):
                ch = row[i][0]
                if ch in BOX:
                    flush(run_start, run)
                    run_start, run = None, ''
                    arms = BOX[ch]
                    width = 2 if arms.isupper() else 1
                    key = (fill, width)
                    lines.setdefault(key, {'h': {}, 'v': {}})
                    cx = round(x0 + i * CW + CW / 2 - 0.5) + 0.5
                    cy = round(top + LH / 2 - 0.5) + 0.5
                    left, right = x0 + i * CW, x0 + (i + 1) * CW
                    a = arms.lower()
                    if 'l' in a or 'r' in a:
                        lines[key]['h'].setdefault(cy, []).append(
                            (left if 'l' in a else cx, right if 'r' in a else cx))
                    if 'u' in a or 'd' in a:
                        lines[key]['v'].setdefault(cx, []).append(
                            (top if 'u' in a else cy, top + LH if 'd' in a else cy))
                elif ord(ch) > 126:
                    flush(run_start, run)
                    run_start, run = None, ''
                    glyph = ch + (TEXT_STYLE if ch in '✔✖' else '')
                    texts.append('<text x="%s" y="%s" text-anchor="middle"%s>%s</text>'
                                 % (num(x0 + i * CW + CW / 2), num(base), attrs, esc(glyph)))
                else:
                    if run_start is None:
                        run_start = i
                    run += ch
            flush(run_start, run)
            c = end
    paths = []
    for (colour, width), segs in lines.items():
        d = ''.join('M%s %sH%s' % (num(a), num(y), num(b)) for y, a, b in merge(segs['h']))
        d += ''.join('M%s %sV%s' % (num(x), num(a), num(b)) for x, a, b in merge(segs['v']))
        paths.append('<path d="%s" stroke="%s" stroke-width="%d" fill="none"/>' % (d, colour, width))
    return rects + paths + texts


def window(w, h, title):
    return [
        '<rect x=".5" y=".5" width="%s" height="%s" rx="10" fill="%s" stroke="%s"/>' % (num(w - 1), num(h - 1), T_BG, T_EDGE),
        '<path d="M1 %d V11 A10 10 0 0 1 11 1 H%s A10 10 0 0 1 %s 11 V%d Z" fill="%s"/>' % (BAR, num(w - 11), num(w - 1), BAR, T_BAR),
        '<path d="M1 %s H%s" stroke="%s"/>' % (num(BAR + .5), num(w - 1), T_EDGE),
        '<circle cx="%d" cy="%s" r="4" fill="%s"/>' % (PAD + 4, num(BAR / 2), FG['g']),
        '<text x="%d" y="%s" class="bar">%s</text>' % (PAD + 16, num(BAR / 2 + 4), esc(title)),
    ]


def svg_doc(w, h, label, body, extra_css=''):
    # Text colour is inherited from the <g>, never set by CSS: a CSS fill
    # would beat each run's own fill attribute.
    css = ('text{font-family:%s;font-size:%dpx;white-space:pre}'
           '.bar{font-size:12px;fill:%s}' % (MONO, FS, T_CHROME)) + extra_css
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %s %s" width="%s" height="%s" '
            'role="img" xml:space="preserve"><title>%s</title><style>%s</style><g fill="%s">%s</g></svg>\n'
            % (num(w), num(h), num(w), num(h), esc(label), css, T_FG, ''.join(body)))


def still(frame, cols, title, label):
    nrows = max(used_rows(frame), 4)
    w = PAD * 2 + cols * CW
    h = BAR + PAD + nrows * LH + PAD
    body = window(w, h, title) + screen_svg(frame, cols, nrows, PAD, BAR + PAD)
    return svg_doc(w, h, label, body)


# ---- the animated hero ------------------------------------------------------

NAMED_KEYS = {'Enter', 'Space', 'Esc', 'Tab', '↓', '↑', '←', '→', 'Ctrl-C'}


def is_command(k):
    return k.startswith('sudo ') or k.startswith('bond-manager')


def key_chips(keys, x, y):
    """Keycaps for a step, drawn left to right from (x, y); returns (elements, end x)."""
    out = []
    for k in keys:
        chips = [('$ ' + k, True), ('Enter', False)] if is_command(k) else [(k, not (k in NAMED_KEYS or len(k) == 1))]
        for text, typed in chips:
            wdt = len(text) * 7.2 + 16
            out.append('<rect x="%s" y="%s" width="%s" height="22" rx="4" fill="%s" stroke="%s"/>'
                       % (num(x), num(y), num(wdt), T_BAR if typed else '#1E2832', T_EDGE if typed else '#3A4754'))
            out.append('<text x="%s" y="%s" class="kc" textLength="%s">%s</text>'
                       % (num(x + 8), num(y + 15.5), num(len(text) * 7.2), esc(text)))
            x += wdt + 6
    return out, x


def hero(flow, cols):
    steps = flow['steps']
    nrows = max(used_rows(s['frame']) for s in steps)
    w = PAD * 2 + cols * CW
    wrap_at = 104
    cap_lines = max(len(textwrap.wrap(s['text'], wrap_at)) for s in steps)
    cap_h = 16 + 22 + 10 + cap_lines * 20 + 10
    top = BAR + PAD + nrows * LH + PAD
    h = top + cap_h

    durations = [min(14.0, 2.5 + len(s['text']) / 17.0) for s in steps]
    total = sum(durations)
    body = window(w, h, 'root@web01: ~') + [
        '<path d="M1 %s H%s" stroke="%s"/>' % (num(top + .5), num(w - 1), T_EDGE)]
    css = ['.f{opacity:0;animation:%ss step-end infinite}' % num(total),
           '.kc{font-size:12px;font-weight:700}',
           '.cap{font-family:%s;font-size:15px}' % SANS,
           '.st{font-family:%s;font-size:13px;fill:%s}' % (SANS, T_CHROME)]
    t = 0.0
    for i, s in enumerate(steps):
        a, b = 100 * t / total, 100 * (t + durations[i]) / total
        t += durations[i]
        if i == 0:
            css.append('@keyframes k0{0%%{opacity:1}%s%%{opacity:0}}' % num(b))
        else:
            css.append('@keyframes k%d{0%%{opacity:0}%s%%{opacity:1}%s%%{opacity:0}}' % (i, num(a), num(b)))
        css.append('#f%d{animation-name:k%d}' % (i, i))
        g = ['<g class="f" id="f%d">' % i]
        g += screen_svg(s['frame'], cols, nrows, PAD, BAR + PAD)
        label = 'Step %d of %d' % (i + 1, len(steps))
        g.append('<text x="%d" y="%s" class="st">%s</text>' % (PAD, num(top + 16 + 15.5), label))
        chips, _ = key_chips(s['keys'], PAD + 86, top + 16)
        g += chips
        for j in range(len(steps)):
            g.append('<circle cx="%s" cy="%s" r="3.5" fill="%s"/>'
                     % (num(w - PAD - 4 - (len(steps) - 1 - j) * 14), num(top + 27), FG['b'] if j == i else '#2A3540'))
        for j, line in enumerate(textwrap.wrap(s['text'], wrap_at)):
            g.append('<text x="%d" y="%s" class="cap">%s</text>' % (PAD, num(top + 16 + 22 + 10 + 15 + j * 20), esc(line)))
        g.append('</g>')
        body += g
    # Without motion, hold the screen that says the most: the review.
    still_i = min(3, len(steps) - 1)
    css.append('@media (prefers-reduced-motion:reduce){.f{animation:none}#f%d{opacity:1}}' % still_i)
    label = 'bond-manager moving bond0 to a new switch, screen by screen'
    return svg_doc(w, h, label, body, ''.join(css))


# ---- the README section -----------------------------------------------------

def keys_md(keys):
    """'You press <kbd>2</kbd>, then type `10.20.40.10`, then press <kbd>Enter</kbd>'."""
    groups = []
    for k in keys:
        if is_command(k):
            groups += [['type', ['`%s`' % k]], ['press', ['<kbd>Enter</kbd>']]]
        elif k in NAMED_KEYS or len(k) == 1:
            if groups and groups[-1][0] == 'press':
                groups[-1][1].append('<kbd>%s</kbd>' % esc(k))
            else:
                groups.append(['press', ['<kbd>%s</kbd>' % esc(k)]])
        else:
            groups.append(['type', ['`%s`' % k]])
    return 'You ' + ', then '.join('%s %s' % (verb, ' '.join(parts)) for verb, parts in groups)


def readme_hero():
    return '\n'.join([
        '<p align="center">',
        '  <img src="docs/tour/hero.svg" width="100%" '
        'alt="bond-manager moving bond0 to a new switch: pick the bond, the old port and the new one, '
        'read the plan, and keep the change once the checks pass">',
        '</p>',
        '<p align="center"><sub>Real screens from bond-manager 3.1 on a test server. '
        '<a href="#take-the-tour">Take the tour</a> or '
        '<a href="%s">click through it</a>.</sub></p>' % PAGES_URL,
    ])


def readme_chapters(data):
    out = ['Every picture below is a real screen, captured from the tool by `make tour`.',
           'Open a chapter to step through it, or use the',
           '[interactive version](%s), where the arrow keys turn the pages.' % PAGES_URL,
           '']
    for fl in data['flows']:
        n = len(fl['steps'])
        out.append('<details>')
        out.append('<summary><b>%s</b> &middot; %s <i>(%d %s)</i></summary>'
                   % (esc(fl['title']), esc(fl['blurb']), n, 'screen' if n == 1 else 'screens'))
        out.append('')
        for i, s in enumerate(fl['steps'], 1):
            out.append('**%d.** %s. %s' % (i, keys_md(s['keys']), s['text']))
            out.append('')
            out.append('<img src="docs/tour/%s-%d.svg" width="100%%" alt="%s, screen %d of %d">'
                       % (fl['id'], i, html.escape(fl['title']), i, n))
            out.append('')
        out.append('</details>')
        out.append('')
    return '\n'.join(out).rstrip() + '\n'


def splice(text, name, body):
    start, end = '<!-- tour-%s:start -->' % name, '<!-- tour-%s:end -->' % name
    pat = re.compile(re.escape(start) + r'.*?' + re.escape(end), re.S)
    if not pat.search(text):
        sys.exit('render.py: README.md has no %s ... %s markers' % (start, end))
    note = '<!-- generated by make tour: edit the steps and captions in build/tour/capture.py, not here -->'
    return pat.sub(lambda _: '%s\n%s\n%s\n%s' % (start, note, body.rstrip('\n'), end), text)


# ---- the interactive page -----------------------------------------------------

def page(data):
    blob = json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')
    with open(os.path.join(HERE, 'page.html')) as fh:
        body = fh.read()
    body = body.replace('__TOUR_JSON__', blob).replace('__REPO_URL__', REPO_URL)
    title_end = body.index('</title>') + len('</title>')
    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n'
            '<meta name="description" content="Real screens from bond-manager 3.1, the menu-driven tool '
            'for network bonds on RHEL, one step at a time.">\n'
            + body[:title_end] + '\n'
            '<style>body{margin:0}[hidden]{display:none!important}</style>\n'
            + body[title_end:].replace('<div class="page">', '</head>\n<body>\n<div class="page">', 1)
            + '</body>\n</html>\n')


def main():
    with open(os.path.join(TOUR, 'tour.json')) as fh:
        data = json.load(fh)
    cols = data['cols']
    for name in os.listdir(TOUR):
        if name.endswith('.svg'):
            os.remove(os.path.join(TOUR, name))
    count = 0
    for fl in data['flows']:
        for i, s in enumerate(fl['steps'], 1):
            label = '%s, screen %d: %s' % (fl['title'], i, s['text'])
            with open(os.path.join(TOUR, '%s-%d.svg' % (fl['id'], i)), 'w') as fh:
                fh.write(still(s['frame'], cols, 'root@web01: ~', label))
            count += 1
    hero_flow = next(f for f in data['flows'] if f['id'] == HERO_FLOW)
    with open(os.path.join(TOUR, 'hero.svg'), 'w') as fh:
        fh.write(hero(hero_flow, cols))
    with open(os.path.join(TOUR, 'index.html'), 'w') as fh:
        fh.write(page(data))
    with open(README) as fh:
        text = fh.read()
    text = splice(text, 'hero', readme_hero())
    text = splice(text, 'chapters', readme_chapters(data))
    with open(README, 'w') as fh:
        fh.write(text)
    print('render: %d screens, hero.svg, index.html and the README tour' % count)


if __name__ == '__main__':
    main()
