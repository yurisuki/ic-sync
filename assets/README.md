# IC-SYNC assets

`ic-sync.png` is the **canonical source** for the application icon: a plain
white iCloud-style cloud on a transparent background, with no text, no
account, session or credential data.

All other PNG and ICO files in this directory are generated from it:

| File | Size | Use |
| --- | --- | --- |
| `ic-sync.png` | 1024×1024 | Canonical source; README and docs |
| `ic-sync-256.png` | 256×256 | Large tray/window icon |
| `ic-sync-128.png` | 128×128 | Tray/window icon |
| `ic-sync-64.png` | 64×64 | Tray/window icon |
| `ic-sync-32.png` | 32×32 | Small tray/taskbar icon |
| `ic-sync.ico` | 16/32/48/64/128/256 | Windows executable and window icon |

The system-tray and window icons are this same plain cloud, tinted by the
sync state: **green** when idle/synced, **orange** while working,
**red** on error (gray when offline).

Regenerate the PNG variants with:

```bash
magick ic-sync.png -resize 1024x1024 ic-sync.png
for size in 256 128 64 32; do
  magick ic-sync.png -resize "${size}x${size}" "ic-sync-${size}.png"
done
magick ic-sync.png -define icon:auto-resize=16,32,48,64 ic-sync.ico
```
