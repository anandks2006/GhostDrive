"""
generate_icons.py -- Dev utility that renders the GhostDrive PWA PNG icons.

Run `py ghostdrive/web/static/icons/generate_icons.py` to regenerate the
icons after a brand change. Drawing logic mirrors
``ghostdrive.platform.tray.build_icon_image``: a dark rounded square with a
cyan "G" built from an arc plus a bar (no font dependency). Maskable and
apple-touch variants paint edge-to-edge and shrink the glyph into the
platform safe zone.
"""

from pathlib import Path

OUT_DIR = Path(__file__).parent

# Brand colors (dark square + cyan glyph, same as tray.build_icon_image).
BG = (18, 22, 30, 255)
GLYPH = (0, 229, 255, 255)


def draw_icon(size: int, *, full_bleed: bool = False, glyph_scale: float = 0.52):
    """
    Draw the GhostDrive glyph at ``size`` px and return a PIL image.

    ``full_bleed`` paints the background edge-to-edge (opaque, no outline)
    for maskable and iOS icons, which apply their own corner masking.
    """
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    if full_bleed:
        draw.rectangle([0, 0, size - 1, size - 1], fill=BG)
    else:
        pad = max(1, size // 16)
        draw.rounded_rectangle(
            [pad, pad, size - pad - 1, size - pad - 1],
            radius=size // 5,
            fill=BG,
            outline=GLYPH,
            width=max(1, size // 32),
        )
    # Letter "G" as an arc + bar, scaled into the safe zone when full_bleed.
    center = size / 2
    half = (size * glyph_scale) / 2
    bbox = [center - half, center - half, center + half, center + half]
    arc_w = max(2, int(size * glyph_scale // 5))
    draw.arc(bbox, start=-60, end=300, fill=GLYPH, width=arc_w)
    draw.line([center, center, center + half, center], fill=GLYPH, width=arc_w)
    return img


def main():
    targets = [
        ("icon-64.png", 64, False, 0.52),
        ("icon-192.png", 192, False, 0.52),
        ("icon-512.png", 512, False, 0.52),
        # Maskable: background edge-to-edge, glyph inside the 80% safe zone.
        ("icon-192-maskable.png", 192, True, 0.5),
        ("icon-512-maskable.png", 512, True, 0.5),
        # iOS applies its own rounded corners, so keep the background opaque.
        ("apple-touch-icon-180.png", 180, True, 0.5),
    ]
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, size, full_bleed, glyph_scale in targets:
        path = OUT_DIR / name
        draw_icon(size, full_bleed=full_bleed, glyph_scale=glyph_scale).save(path, "PNG")
        print(f"wrote {path.name} ({size}x{size})")


if __name__ == "__main__":
    main()
