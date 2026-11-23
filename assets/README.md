# IC-SYNC assets

`ic-sync.svg` is the **canonical source** for the application icon. It is a
hand-authored, 256×256 vector icon: a rounded-square indigo-to-cyan gradient
tile, a white cloud silhouette, and two indigo circular sync arrows. It contains
no text, uses a transparent background outside the rounded tile, and contains no
account, session or credential data.

All PNG and ICO files in this directory are generated from the SVG.

| File | Size | Use |
| --- | --- | --- |
| `ic-sync.svg` | vector | Canonical source; README and docs |
| `ic-sync.png` | 1024×1024 | High-resolution app/marketing image |
| `ic-sync-256.png` | 256×256 | Large tray/window icon |
| `ic-sync-128.png` | 128×128 | Tray/window icon |
| `ic-sync-64.png` | 64×64 | Tray/window icon |
| `ic-sync-32.png` | 32×32 | Small tray/taskbar icon |
| `ic-sync.ico` | 16/32/48/64/128/256 | Windows executable and window icon |

## Regenerate the raster assets

ImageMagick with librsvg support is required (`magick -list format` should list
`SVG` with an `RSVG` delegate). From this directory:

```sh
# 1024px master, rendered from the vector at high density
magick -background none -density 384 ic-sync.svg -resize 1024x1024 PNG32:ic-sync.png

# Downsample the master so every size stays visually identical
for size in 256 128 64 32; do
  magick ic-sync.png -resize "${size}x${size}" "PNG32:ic-sync-${size}.png"
done

# Extra Windows ICO sizes
magick ic-sync.png -resize 16x16 PNG32:/tmp/ic-sync-16.png
magick ic-sync.png -resize 48x48 PNG32:/tmp/ic-sync-48.png

# Multi-resolution Windows icon
magick /tmp/ic-sync-16.png ic-sync-32.png /tmp/ic-sync-48.png \
  ic-sync-64.png ic-sync-128.png ic-sync-256.png ic-sync.ico
```

All outputs keep the alpha channel (`PNG32:`), so the corners remain
transparent. After changing the SVG, regenerate and commit every raster file
together so the tray, window and release archives stay consistent.

Never place credentials, session/cookie JSON, or real account data in this
directory. Assets are bundled into release archives and published publicly.
