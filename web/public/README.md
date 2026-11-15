# Favicon mark

Square ink tile with the masthead's own letterform: solid `#111111` square (zero radius,
no shadow, no gradient), white lowercase **e** outlined from **Archivo ExtraBold /
wght 800** — the typeface of the black masthead band — ink-bbox centred on the tile with
the ink height at 63% of the tile (20.16 of 32 units) so the counters stay open at 16 px.
No red: signal red `#e4002b` is reserved for critical state.

## Reproduce `favicon.svg` from the app's woff2

The only tooling used is fontTools + brotli (to read the variable `.woff2` and outline the
glyph); no pip install, no new repo dependency.

```sh
cd /home/mei/Documents/eBPF-runtime
nix shell --impure --expr 'let p = import <nixpkgs> {}; in p.python3.withPackages (ps: [ ps.fonttools ps.brotli ])' -c python3 - <<'PY'
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

font = instantiateVariableFont(TTFont("web/src/assets/fonts/archivo-variable.woff2"),
                               {"wght": 800}, inplace=False)
gs = font.getGlyphSet()
glyph = gs[font.getBestCmap()[ord("e")]]
bp = BoundsPen(gs)
glyph.draw(bp)
xMin, yMin, xMax, yMax = bp.bounds
GRID, INK_HEIGHT = 32.0, 20.16  # 32-unit tile, glyph ink = 63% of the tile
s = INK_HEIGHT / (yMax - yMin)
tx = GRID / 2 - (xMin + xMax) / 2 * s
ty = GRID / 2 + (yMin + yMax) / 2 * s
pen = SVGPathPen(gs, ntos=lambda v: f"{v:.3f}".rstrip("0").rstrip("."))
glyph.draw(TransformPen(pen, (s, 0, 0, -s, tx, ty)))
d = pen.getCommands()
svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">\n'
       '  <rect width="32" height="32" fill="#111111" shape-rendering="crispEdges"/>\n'
       f'  <path d="{d}" fill="#ffffff"/>\n'
       '</svg>\n')
open("web/public/favicon.svg", "w").write(svg)
PY
```

Output is byte-identical to the committed `favicon.svg`: one `<rect>` + one `<path>`, no
`<text>`, no `@font-face`, no external reference.

## PNG / ICO

`favicon-32.png`, `favicon-192.png` and `apple-touch-icon.png` (180) are Chromium raster
renders of `favicon.svg` at exactly those pixel sizes (Playwright's Chromium, already in
`web/node_modules`); each is pixel-identical to the SVG. `favicon.ico` is a multi-size
16/32/48 ICO assembled from the same master renders:

```sh
magick 16.png 32.png 48.png favicon.ico   # ImageMagick 7
```

`magick identify favicon.ico` → three icons at 16x16, 32x32, 48x48.

`web/index.html` links the SVG first (modern browsers), then the 32/192 PNG fallbacks,
the apple-touch icon and the ICO, plus `<meta name="theme-color" content="#111111">`.
