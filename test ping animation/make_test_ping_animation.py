from PIL import Image, ImageDraw

frames = 20
width, height = 100, 100
tail_length = 50 

def get_y(x):
    if x <= 25: return 50
    elif x <= 40: return 50 + (20 - 50) * ((x - 25) / 15)  # Spike up
    elif x <= 55: return 20 + (85 - 20) * ((x - 40) / 15)  # Drop down
    elif x <= 70: return 85 + (50 - 85) * ((x - 55) / 15)  # Recover
    else: return 50

for i in range(frames):
    img = Image.new('RGBA', (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    head_x = int((width / frames) * (i + 1))
    
    # 1. Draw the gradient tail (shifting from yellow/orange near the head, to bright red, to dark crimson)
    for x in range(max(0, head_x - tail_length), head_x):
        x1, y1 = x, get_y(x)
        x2, y2 = x + 1, get_y(x + 1)
        
        # Distance from the head (0 is right at the head, 1 is the tail end)
        distance_ratio = (head_x - x) / tail_length
        
        # Color transition math: Yellow/Orange -> Bright Red -> Deep Crimson -> Fade out
        if distance_ratio < 0.2:
            # Near the head: Hot Yellow-Orange fading to Red
            r, g, b = 255, int(165 * (1 - distance_ratio/0.2)), 0
        elif distance_ratio < 0.7:
            # Middle: Pure Neon Red
            r, g, b = 255, 0, 0
        else:
            # Tail end: Dark Crimson
            r, g, b = 150, 0, 0
            
        # Opacity fade out
        fade = int(255 * (1 - distance_ratio))
        
        draw.line([(x1, y1), (x2, y2)], fill=(r, g, b, fade), width=5, joint="curve")
        
    # 2. Draw the blazing white-hot leading dot
    if head_x < width:
        head_y = get_y(head_x)
        draw.ellipse([(head_x - 3, head_y - 3), (head_x + 3, head_y + 3)], fill="#FFFFFF")
    
    img.save(f"image_6_f{i}.png")

print("[*] SUCCESS: 20 Gradient EKG frames generated with a color-shifting trail!")
