from PIL import Image, ImageDraw, ImageOps
import math

frames = 60
size = 115
center = size // 2
radius = 40  # Extended to perfectly hit the original outer ring

# 1. Load your original image
try:
    base_img = Image.open(r"C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\image_3.png").convert("RGBA")
    base_img = base_img.resize((size, size))
except Exception as e:
    print(f"[-] Error loading image_3.png: {e}")
    base_img = Image.new('RGBA', (size, size), (0, 0, 0, 255))

# 2. THE PYTHON CLONE STAMP (Absolute Perfection)
# Crop the perfectly clean left half of the image
left_half = base_img.crop((0, 0, center, size))
# Flip it horizontally
clean_right_half = ImageOps.mirror(left_half)

# Paste the clean flipped half over the right side, completely deleting the frozen line!
clean_base = base_img.copy()
clean_base.paste(clean_right_half, (center, 0))

# 3. GENERATE THE SPINNING TRAIL FRAMES
for i in range(frames):
    frame = clean_base.copy()
    
    # Create a transparent layer for the trailing sweep
    overlay = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw_overlay = ImageDraw.Draw(overlay)
    
    # Current rotating angle
    current_angle = (2 * math.pi / frames) * i - (math.pi / 4)
    
    # Draw the fading trail behind the sweep
    trail_steps = 6
    for step in range(trail_steps, 0, -1):
        angle = current_angle - (step * 0.15)
        x_end = center + int(radius * math.cos(angle))
        y_end = center + int(radius * math.sin(angle))
        
        # Fade out opacity
        alpha = int(200 * (1 - (step / trail_steps)))
        draw_overlay.line([center, center, x_end, y_end], fill=(0, 255, 255, alpha), width=3)
        
    # Draw the solid white leading edge
    hx = center + int(radius * math.cos(current_angle))
    hy = center + int(radius * math.sin(current_angle))
    draw_overlay.line([center, center, hx, hy], fill=(255, 255, 255, 255), width=3)
    
    # Combine the cloned base with the animated sweep
    final_frame = Image.alpha_composite(frame, overlay)
    final_frame.save(f"ghost_f{i}.png")

print("[*] SUCCESS: Clone Stamp applied. Flawless radar frames generated!")
