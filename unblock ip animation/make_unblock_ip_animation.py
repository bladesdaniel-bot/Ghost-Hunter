from PIL import Image

print("[*] Performing surgical background removal...")

# 1. Load the original image
image_path = "unblock ip animation/unblocking ip.png"
img = Image.open(image_path).convert("RGBA")
pixels = img.load()

# 2. Loop through every single pixel in the image
for y in range(img.height):
    for x in range(img.width):
        r, g, b, a = pixels[x, y]
        
        # The dark background has almost zero Green. 
        # The bright neon shield has very high Green.
        if g > 30:
            # It's the shield! Force it to be pure neon cyan (0, 255, 255)
            # We multiply the alpha so the glowing edges stay smooth but the core is solid.
            new_alpha = min(255, int(g * 3))
            pixels[x, y] = (0, 255, 255, new_alpha)
        else:
            # It's the background! Erase it completely.
            pixels[x, y] = (0, 0, 0, 0)

# 3. Save the masterpiece
new_path = "unblock ip animation/unblocking_transparent.png"
img.save(new_path)

print(f"[+] Success! Surgical cut complete. Saved as: {new_path}")
