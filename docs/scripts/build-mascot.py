#!/usr/bin/env python3
"""Build the landing-page mascot sprite sheets from public/logo.svg.

The logo is pixel art drawn on a 20-unit grid. This rasterises it onto a 10-unit
grid, then draws two 3x3 SVG sheets for components/mascot.astro:

  public/mascots/logo-directions.svg  up-left, up, up-right / left, center, right / down-...
  public/mascots/logo-reactions.svg   blink, heart, sparkle / surprised, wink, bashful /
                                      sleepy, dizzy, delighted

Directions move the pupil inside the eye and nudge the head one pixel toward the
pointer; reactions swap the eye shape and add pixel effects above the head.

Run from docs/: python3 scripts/build-mascot.py   (stdlib only)
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PX = 10  # grid unit, half a logo pixel so the pupil can move inside the eye
FILL = "#b96c45"

# Cell frame in logo coordinates: the logo's own frame plus headroom for effects.
X0, Y0, W, H = -30, -110, 820, 620

EYE = (60, 8)  # top-left grid cell of the 4x4 eye
HEAD_X, HEAD_Y = 54, 20  # head = cells right of x=540 and above y=200


def rasterise(svg: str) -> set[tuple[int, int]]:
    """Even-odd fill of the logo's single H/V path, sampled at grid-cell centres."""
    d = re.search(r' d="([^"]+)"', svg).group(1)
    edges, x, y, start = [], 0, 0, (0, 0)
    for cmd, args in re.findall(r"([MHVZ])([^MHVZ]*)", d):
        nums = [int(n) for n in args.split()]
        if cmd == "M":
            x, y = nums
            start = (x, y)
        elif cmd == "H":
            x = nums[0]
        elif cmd == "V":
            edges.append((x, min(y, nums[0]), max(y, nums[0])))
            y = nums[0]
        else:
            if x == start[0] and y != start[1]:
                edges.append((x, min(y, start[1]), max(y, start[1])))
            x, y = start
    cells = set()
    for gy in range(-3, 51):
        for gx in range(-3, 77):
            cx, cy = gx * PX + PX / 2, gy * PX + PX / 2
            crossings = sum(1 for ex, y1, y2 in edges if ex > cx and y1 < cy < y2)
            if crossings % 2:
                cells.add((gx, gy))
    return cells


def stamp(cells, pattern, ax, ay, on=True):
    """Set (or clear) the cells marked X in a pattern whose top-left is (ax, ay)."""
    for dy, row in enumerate(pattern):
        for dx, ch in enumerate(row):
            if ch == "X":
                (cells.add if on else cells.discard)((ax + dx, ay + dy))


def eye(cells, holes, dx=0, dy=0):
    """Redraw the 4x4 eye: fill it, then cut the X cells of `holes` back out."""
    ex, ey = EYE[0] + dx, EYE[1] + dy
    stamp(cells, ["XXXX"] * 4, ex, ey)
    stamp(cells, holes, ex, ey, on=False)


def pupil(px, py):
    """An open eye with a 2x2 pupil at (px, py), each 0..2."""
    return ["".join("." if px <= x < px + 2 and py <= y < py + 2 else "X" for x in range(4)) for y in range(4)]


SLIT = ["....", "....", "XXXX", "...."]
CARET = ["....", ".XX.", "X..X", "...."]
CROSS = ["X..X", ".XX.", ".XX.", "X..X"]
WIDE = ["XXXX"] * 4

HEART = [".XX.XX.", "XXXXXXX", "XXXXXXX", ".XXXXX.", "..XXX..", "...X..."]
PLUS = ["..X..", "..X..", "XXXXX", "..X..", "..X.."]
DOT = [".X.", "XXX", ".X."]
BIG_Z = ["XXXXX", "...X.", "..X..", ".X...", "XXXXX"]
SMALL_Z = ["XXX", ".X.", "XXX"]
BANG = ["XX", "XX", "XX", "XX", "..", "XX"]
SLASHES = ["..X..X..X", ".X..X..X.", "X..X..X.."]
MOUTH = ["XXXXXX", "....XX"]


def with_head(logo, dx, dy):
    """The logo with its head shifted by (dx, dy) cells, still joined to the neck."""
    head = {(x, y) for x, y in logo if x >= HEAD_X and y < HEAD_Y}
    body = logo - head
    seam = {
        (x, y)
        for x, y in head
        if any(n in body for n in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)))
    }
    return body | seam | {(x + dx, y + dy) for x, y in head}


def directions(logo):
    frames = []
    for row in range(3):
        for col in range(3):
            cells = with_head(logo, col - 1, row - 1)
            eye(cells, pupil(col, row), col - 1, row - 1)
            frames.append(cells)
    return frames


def reactions(logo):
    def frame(holes, *effects, head=(0, 0), mouth=False):
        cells = with_head(logo, *head)
        eye(cells, holes, *head)
        if mouth:
            stamp(cells, MOUTH, 66, 16, on=False)
        for pattern, ax, ay, *cut in effects:
            stamp(cells, pattern, ax, ay, on=not cut)
        return cells

    return [
        frame(SLIT),  # blink
        frame(CARET, (HEART, 69, -7)),  # heart
        frame(pupil(1, 0), (PLUS, 70, -8), (DOT, 75, -2), (DOT, 63, -4)),  # sparkle
        frame(WIDE, (BANG, 72, -8), mouth=True),  # surprised
        frame(CARET, (DOT, 72, -3)),  # wink
        frame(pupil(1, 2), (SLASHES, 62, 14, "cut"), head=(0, 1)),  # bashful
        frame(SLIT, (SMALL_Z, 65, -3), (BIG_Z, 70, -9)),  # sleepy
        frame(CROSS, (DOT, 57, -3), (DOT, 65, -6), (DOT, 73, -3)),  # dizzy
        frame(CARET, (PLUS, 71, -8), (HEART, 61, -7), mouth=True),  # delighted
    ]


def rects(cells):
    """Horizontal runs of filled cells as <rect>s."""
    out = []
    for y in sorted({y for _, y in cells}):
        xs = sorted(x for x, cy in cells if cy == y)
        start = prev = xs[0]
        for x in xs[1:] + [None]:
            if x != prev + 1:
                out.append(f'<rect x="{start * PX}" y="{y * PX}" width="{(prev - start + 1) * PX}" height="{PX}"/>')
                start = x
            prev = x
    return "".join(out)


def sheet(frames):
    groups = "".join(
        f'<g transform="translate({(i % 3) * W - X0} {(i // 3) * H - Y0})">{rects(f)}</g>'
        for i, f in enumerate(frames)
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {3 * W} {3 * H}" '
        f'preserveAspectRatio="none" shape-rendering="crispEdges" fill="{FILL}">{groups}</svg>\n'
    )


logo = rasterise((ROOT / "public/logo.svg").read_text())
out = ROOT / "public/mascots"
out.mkdir(exist_ok=True)
(out / "logo-directions.svg").write_text(sheet(directions(logo)))
(out / "logo-reactions.svg").write_text(sheet(reactions(logo)))
print(f"wrote {out}/logo-{{directions,reactions}}.svg ({W}x{H} cells)")
