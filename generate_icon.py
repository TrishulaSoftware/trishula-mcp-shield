import math
from PIL import Image, ImageDraw, ImageFont, ImageFilter

def create_cyberpunk_shield_logo(output_path="mcp_shield_logo_512.png"):
    size = (512, 512)
    img = Image.new("RGBA", size, (10, 14, 23, 255)) # Deep void dark background
    draw = ImageDraw.Draw(img)

    # 1. Subtle Radial / Circular Grid background
    cx, cy = 256, 240
    for r in range(40, 240, 30):
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(20, 35, 55, 120), width=1)
    
    # Diagonal subtle grid lines
    for angle in range(0, 360, 45):
        rad = math.radians(angle)
        x2 = cx + int(240 * math.cos(rad))
        y2 = cy + int(240 * math.sin(rad))
        draw.line([cx, cy, x2, y2], fill=(24, 42, 65, 80), width=1)

    # 2. Outer Shield Polygon (Cyberpunk Hex-Shield silhouette)
    shield_outer = [
        (256, 45),   # Top center peak
        (395, 100),  # Top right shoulder
        (420, 230),  # Right flank
        (370, 360),  # Right lower taper
        (256, 435),  # Bottom tip
        (142, 360),  # Left lower taper
        (92, 230),   # Left flank
        (117, 100),  # Top left shoulder
    ]

    # Glowing outer border
    glow_color = (0, 229, 255, 180)   # Neon Cyan
    accent_color = (138, 43, 226, 200) # Electric Violet
    fill_color = (14, 22, 36, 255)     # Dark slate armor plate

    # Draw outer plate
    draw.polygon(shield_outer, fill=fill_color, outline=(0, 229, 255, 255), width=4)

    # Inner Shield (Accent line)
    shield_inner = [
        (256, 75),
        (370, 120),
        (390, 225),
        (350, 335),
        (256, 400),
        (162, 335),
        (122, 225),
        (142, 120),
    ]
    draw.polygon(shield_inner, fill=(18, 28, 48, 255), outline=(138, 43, 226, 220), width=3)

    # Core High-Tech Trident / Diamond Symbol (Trishula Aegis)
    # Center diamond / core
    draw.polygon([(256, 120), (290, 185), (256, 250), (222, 185)], fill=(0, 229, 255, 230), outline=(255, 255, 255, 255), width=2)
    # Left prong
    draw.polygon([(220, 170), (180, 160), (200, 235), (230, 210)], fill=(138, 43, 226, 220), outline=(0, 229, 255, 200), width=2)
    # Right prong
    draw.polygon([(292, 170), (332, 160), (312, 235), (282, 210)], fill=(138, 43, 226, 220), outline=(0, 229, 255, 200), width=2)

    # Vertical energy lance downward
    draw.line([(256, 250), (256, 360)], fill=(0, 229, 255, 255), width=4)
    draw.line([(254, 250), (254, 360)], fill=(255, 255, 255, 200), width=2)
    
    # Energy nodes / circuitry
    nodes = [(256, 360), (200, 310), (312, 310), (256, 120)]
    for nx, ny in nodes:
        draw.ellipse([nx-6, ny-6, nx+6, ny+6], fill=(0, 229, 255, 255), outline=(255, 255, 255, 255), width=2)
    
    # Connecting circuit lines
    draw.line([(256, 360), (200, 310)], fill=(0, 229, 255, 180), width=2)
    draw.line([(256, 360), (312, 310)], fill=(0, 229, 255, 180), width=2)

    # Typography at bottom: "MCP SHIELD"
    # Draw simple high-tech label
    draw.rectangle([130, 445, 382, 485], fill=(12, 18, 30, 240), outline=(0, 229, 255, 220), width=2)
    
    # Text rendering with standard font
    try:
        font = ImageFont.truetype("arial.ttf", 22)
        font_sub = ImageFont.truetype("arial.ttf", 11)
    except Exception:
        font = ImageFont.load_default()
        font_sub = ImageFont.load_default()

    # MCP SHIELD banner text
    draw.text((176, 453), "MCP SHIELD", fill=(0, 229, 255, 255), font=font)
    draw.text((188, 489), "TRISHULA SOVEREIGN", fill=(160, 180, 210, 220), font=font_sub)

    # Top corner accent tech markings
    draw.line([(30, 30), (70, 30)], fill=(0, 229, 255, 200), width=2)
    draw.line([(30, 30), (30, 70)], fill=(0, 229, 255, 200), width=2)

    draw.line([(482, 30), (442, 30)], fill=(0, 229, 255, 200), width=2)
    draw.line([(482, 30), (482, 70)], fill=(0, 229, 255, 200), width=2)

    draw.line([(30, 482), (70, 482)], fill=(0, 229, 255, 200), width=2)
    draw.line([(30, 482), (30, 442)], fill=(0, 229, 255, 200), width=2)

    draw.line([(482, 482), (442, 482)], fill=(0, 229, 255, 200), width=2)
    draw.line([(482, 482), (482, 442)], fill=(0, 229, 255, 200), width=2)

    img.save(output_path, "PNG")
    print(f"Cyberpunk MCP Shield icon rendered to: {output_path}")

if __name__ == "__main__":
    create_cyberpunk_shield_logo()
