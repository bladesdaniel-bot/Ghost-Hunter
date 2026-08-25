import os
import math
from PIL import Image, ImageDraw, ImageFilter

print("[*] Generating 60 EXTREME swinging door frames...")

# Ensure we are saving directly into the correct folder!
folder_name = "port checker animation"
os.makedirs(folder_name, exist_ok=True)

for i in range(60):
    canvas = Image.new("RGBA", (100, 100), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    
    # Swing factor goes smoothly from 0.0 (shut tight) to 1.0 (wide open)
    swing_factor = (math.sin(i / 60 * 2 * math.pi) + 1) / 2
    
    # Right edge swings from 75 (fully closed) down to 35 (wide open)
    door_right = int(75 - (swing_factor * 40))
    
    # 1. Background: The glowing red room
    # We draw this behind the door. When the door hits 75, it covers this completely!
    draw.rectangle([25, 15, 75, 85], fill=(255, 20, 20, 255))
    
    # 2. Foreground: The Solid Brown Door
    draw.rectangle([25, 15, door_right, 85], fill=(101, 67, 33, 255), outline=(50, 30, 15, 255), width=2)
    
    # 3. The Door Knob (Moves dynamically with the edge of the door)
    knob_left = door_right - 10
    knob_right = door_right - 4
    draw.ellipse([knob_left, 48, knob_right, 54], fill=(255, 200, 50, 255), outline=(255, 255, 255, 255))
    
    # 4. Glow Logic
    glow_alpha = int(swing_factor * 200)
    
    # Only draw the glow if the door is actually open
    if glow_alpha > 5:
        glow_layer = Image.new("RGBA", (100, 100), (0, 0, 0, 0))
        glow_draw = ImageDraw.Draw(glow_layer)
        
        # Glow spills out from the exact point the door is open
        glow_draw.rectangle([door_right, 10, 85, 90], fill=(255, 50, 50, glow_alpha))
        glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(5))
        
        final_frame = Image.alpha_composite(canvas, glow_layer)
    else:
        # Door is shut tight, no light escapes
        final_frame = canvas
        
    # 5. Save explicitly into the correct folder!
    final_frame.save(f"{folder_name}/port_checker_f{i}.png")

print("[+] Done! Extreme swing animation frames created.")
