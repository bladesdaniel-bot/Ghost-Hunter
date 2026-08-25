import os
import math
from PIL import Image, ImageDraw, ImageFilter

print("[*] Generating 60 holographic scrolling blocklist frames...")

# 1. Create the folder to hold the new animation
folder_name = "show blocklist animation"
os.makedirs(folder_name, exist_ok=True)

# 2. Loop 60 times for a perfectly seamless animation
for i in range(60):
    canvas = Image.new("RGBA", (100, 100), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    
    glow_layer = Image.new("RGBA", (100, 100), (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow_layer)

    # --- THE COLORS ---
    neon_green = (10, 255, 80, 255)
    glow_green = (10, 255, 80, 150)
    
    # 1. Draw the Clipboard / Document Frame
    draw.rectangle([25, 20, 75, 85], outline=neon_green, width=2)
    glow_draw.rectangle([25, 20, 75, 85], outline=glow_green, width=5)
    
    # Draw the metal clip at the top
    draw.rectangle([40, 15, 60, 25], fill=(200, 200, 200, 255))
    
    # 2. The Scrolling Data Lines
    # Math magic: shifts the lines up seamlessly so it creates an infinite loop
    line_spacing = 15
    offset = int((i / 60) * line_spacing)
    
    for j in range(6): 
        y_pos = 80 - (j * line_spacing) - offset
        
        # Only draw the text lines if they are inside the document boundaries!
        if 25 < y_pos < 80: 
            # Make the lines look like staggered data/IP addresses
            line_width = 30 if j % 2 == 0 else 18 
            
            draw.line([(32, y_pos), (32 + line_width, y_pos)], fill=neon_green, width=3)
            glow_draw.line([(32, y_pos), (32 + line_width, y_pos)], fill=glow_green, width=6)

    # 3. The Red Laser Scanner
    # Sine wave makes it smoothly bounce from top to bottom and back up
    laser_y = int(25 + (math.sin(i / 60 * math.pi) * 55))
    
    draw.line([(20, laser_y), (80, laser_y)], fill=(255, 20, 20, 255), width=2)
    glow_draw.line([(20, laser_y), (80, laser_y)], fill=(255, 20, 20, 150), width=6)

    # Blur the glow layer so it bleeds like real neon tubes
    glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(3))
    
    # Mash together and save
    final_frame = Image.alpha_composite(canvas, glow_layer)
    final_frame.save(f"{folder_name}/blocklist_f{i}.png")

print("[+] Success! All 60 frames of the neon scroll generated.")
