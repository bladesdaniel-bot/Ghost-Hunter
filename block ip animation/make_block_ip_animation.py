from PIL import Image, ImageEnhance
import math

frames = 60
size = 45  # <--- The new, larger size

try:
    # Loading the clean image you just made
    base_img = Image.open(r"C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\shield_clean.png").convert("RGBA")
    base_img = base_img.resize((size, size))
except Exception as e:
    print(f"[-] Error loading shield_clean.png: {e}")
    exit()

for i in range(frames):
    pulse = (math.sin(i * (2 * math.pi / frames)) + 1) / 2
    enhancer = ImageEnhance.Brightness(base_img)
    brightness_factor = 0.4 + (0.8 * pulse) 
    
    frame = enhancer.enhance(brightness_factor)
    frame.save(f"block_f{i}.png")
    
print(f"[*] SUCCESS: 60 smooth pulsing Block frames generated at {size}x{size}!")
