#!/usr/bin/env python3
"""Emit the 1200x630 social share card (A c44, B c21 pattern ported).

B's railsite ships an og:image built by the generator; my Pages carried
`twitter:card=summary` and NO og:image for 13+ cycles — the last social-meta
gap on my lane (my own c30/c37 candidate, demand = quiet cycle, no churn
elsewhere). Deterministic by construction: fixed fonts (DejaVu), fixed
palette, no timestamps, no dataset values — regenerating must produce
BYTE-IDENTICAL bytes (CI pins that).

Layout lesson taken from B c21 the hard way (their vision-QA caught two
eyeballed collisions): clearance is MEASURED with font.getlength and
ASSERTED at build time, never eyeballed. This build asserts all three
sharing rules: headline vs tile (same y-band), body vs tile (same y-band),
and the bottom-right URL footer vs the tile above it.

Palette mirrors index.html CSS vars (bg #0e1116, card #171b21, acc #7ee787,
dim #9aa0a6, fg #e6e6e6) so the share card IS the site.

Run from the repo root: python3 scripts/build-og-image.py  -> og-image.png
Requires Pillow (hard dependency: a missing card is a FAIL, never a skip).
"""
import sys
from pathlib import Path

OG_IMAGE_NAME = "og-image.png"
SITE_URL = "https://tianzhicdev.github.io/secretgate/"

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    # Fail loud, never skip: the page WILL carry og:image, so a card that
    # silently fails to build is a 404 the moment someone shares the link.
    print("FAIL: Pillow is required to build og-image.png (no-skip policy)")
    sys.exit(2)


def font(path, size):
    return ImageFont.truetype(
        "/usr/share/fonts/truetype/dejavu/" + path, size)


def main():
    root = Path(__file__).resolve().parent.parent
    W, H = 1200, 630
    BG, CARD, BORDER, FG, DIM, ACC = (
        "#0e1116", "#171b21", "#30363d", "#e6e6e6", "#9aa0a6", "#7ee787")
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    f_big = font("DejaVuSans-Bold.ttf", 60)
    f_mid = font("DejaVuSans.ttf", 30)
    f_sml = font("DejaVuSans.ttf", 26)

    # right column: padlock glyph (favicon motif, enlarged), vertically
    # centered against the text block (vision-QA c44: a top-right tile left
    # the bottom-right quadrant dead).
    gx, gy, TS = 880, 150, 240

    # left column: headline — measured clearance vs the tile (B c21 lesson)
    headline = ("Single file.", "Zero deps. Scans", "your git history.")
    hx, hy = 72, 96
    for line in headline:
        assert hx + f_big.getlength(line) <= gx - 12, \
            f"og-image headline '{line}' collides with the glyph tile"
    d.multiline_text((hx, hy), "\n".join(headline), font=f_big, fill=FG,
                     spacing=14)

    body = ("One Python file scans your working tree,",
            "staged diff, or entire git history for",
            "leaked keys and tokens. curl it, run it —",
            "no install, no network calls.")
    by0, leading = 392, 42
    assert by0 + leading * (len(body) - 1) + 34 <= H - 40, \
        "body block overruns the bottom margin"
    for i, line in enumerate(body):
        y = by0 + leading * i
        # tile spans gx..gx+TS vertically at gy..gy+TS; any body line that
        # shares that y-band must clear the tile's left edge
        if y < gy + TS:
            assert hx + f_mid.getlength(line) <= gx - 12, \
                f"og-image body line '{line}' collides with the glyph tile"
        else:
            assert hx + f_mid.getlength(line) <= W - 72, \
                f"og-image body line '{line}' overruns the right margin"
        d.text((hx, y), line, font=f_mid, fill=DIM)

    # footer: site URL, bottom-right (fills the quadrant the tile vacates)
    uw = f_sml.getlength(SITE_URL)
    ux = W - 72 - uw
    uy = H - 52
    body_bottom = by0 + leading * (len(body) - 1) + 34
    assert uy >= body_bottom, "footer URL collides with the body block"
    assert uy >= gy + TS + 12 or ux >= gx + TS, \
        "footer URL collides with the glyph tile"
    d.text((ux, uy), SITE_URL, font=f_sml, fill=ACC)

    # glyph: rounded tile + padlock (same shape family as the data-URI
    # favicon; closed shackle = arched top + straight legs into the body)
    d.rounded_rectangle((gx, gy, gx + TS, gy + TS), radius=24,
                        fill=CARD, outline=BORDER, width=2)
    body_l, body_r = gx + 66, gx + 174
    body_t = gy + 124
    d.rounded_rectangle((body_l, body_t, body_r, gy + 196), radius=10,
                        fill=ACC)                       # lock body
    sh_l, sh_r = body_l + 18, body_r - 18
    d.arc((sh_l, gy + 66, sh_r, gy + 138), 180, 360, fill=ACC, width=10)
    d.line((sh_l + 5, gy + 102, sh_l + 5, body_t + 2), fill=ACC, width=10)
    d.line((sh_r - 5, gy + 102, sh_r - 5, body_t + 2), fill=ACC, width=10)
    d.ellipse((gx + 111, gy + 145, gx + 129, gy + 163), fill=BG)  # keyhole
    d.rounded_rectangle((gx + 115, gy + 158, gx + 125, gy + 176), radius=3,
                        fill=BG)

    out = root / OG_IMAGE_NAME
    img.save(out, "PNG", optimize=True)
    print(f"OK: wrote {out.name} ({out.stat().st_size} bytes, "
          f"{W}x{H}, deterministic)")


if __name__ == "__main__":
    main()
