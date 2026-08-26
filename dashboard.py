# dashboard.py
"""
Front-End UI for CyberSecurity Multi-Agent Infrastructure
"""

import customtkinter as ctk
import threading
from vulnerability_checker import VulnerabilityChecker
import subprocess
import re
from PIL import Image, ImageDraw
import math
import webbrowser

class TCPSniffer:
    def __init__(self, callback_func, interface="any"):
        self.callback = callback_func
        self.process = None
        self.is_sniffing = False

    def start(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            # Launch the Rust compiled engine in the background
            self.process = subprocess.Popen(
                ["cargo", "run"], 
                stdin=subprocess.PIPE,   # <--- ADDED: Allows Python to send commands to Rust
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=r'C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool'
            )
            
            # Start background reader so the dashboard doesn't freeze
            threading.Thread(target=self._read_output, daemon=True).start()

    def _read_output(self):
        # Read the terminal output from Rust and send it to your visual console
        for line in iter(self.process.stdout.readline, ''):
            if not self.is_sniffing:
                break
            if line:
                self.callback(line.strip())

    # --- ADDED: Method to send "clear" to Rust ---
    def clear_backend_threats(self):
        if self.is_sniffing and self.process and self.process.stdin:
            try:
                self.process.stdin.write("clear\n")
                self.process.stdin.flush()
            except Exception as e:
                pass # Fail silently if the process isn't ready

    def stop(self):
        self.is_sniffing = False
        if self.process:
            self.process.terminate()
            self.process.wait()

# 1. Initialize the visual window
app = ctk.CTk()

# --- WINDOW STABILIZATION & CENTERING ---
window_width = 800
window_height = 720
screen_width = app.winfo_screenwidth()
screen_height = app.winfo_screenheight()

# Calculate the exact center coordinates of your monitor
x = int((screen_width / 2) - (window_width / 2))
y = int((screen_height / 2) - (window_height / 2))

# Lock the window size and spawn location
app.geometry(f"{window_width}x{window_height}+{x}+{y}")
# ----------------------------------------

app.title("CyberSecurity Multi-Agent Dashboard")
ctk.set_appearance_mode("dark")  # Forces a sleek hacker-style dark theme
ctk.set_default_color_theme("blue")

# --- HOLOGRAPHIC BACKGROUND SETTINGS (BREATHING ANIMATION) ---
try:
    # Force the absolute background of the app to be pure pitch black
    app.configure(fg_color="#000000") 
    
    # 1. Load the base image and resize it ONCE
    base_bg = Image.open("Animation file/Insane Hacker Background/Insane Hacker pic.png").convert("RGBA")
    base_bg = base_bg.resize((800, 720), Image.Resampling.LANCZOS)
    
    # 2. Pre-render the breathing frames (Opacity pulsing)
    breathing_frames = []
    for i in range(40): # 40 frames for a smooth, deep breath
        # Sine wave for smooth in-and-out pulsing
        alpha = int(200 + 55 * math.sin(i / 40 * 2 * math.pi))
        
        # Copy the base image and apply the pulsing alpha
        frame_img = base_bg.copy()
        frame_img.putalpha(alpha)
        
        # Save it to our background flipbook
        breathing_frames.append(ctk.CTkImage(light_image=frame_img, dark_image=frame_img, size=(800, 720)))
        
    # 3. Pin the first frame to the background (Set label to pitch black too!)
    bg_label = ctk.CTkLabel(app, text="", image=breathing_frames[0], fg_color="#000000")
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)
    
    # 4. The Breathing Animation Engine
    current_bg_frame = 0
    
    def animate_background():
        global current_bg_frame
        current_bg_frame = (current_bg_frame + 1) % len(breathing_frames)
        bg_label.configure(image=breathing_frames[current_bg_frame])
        
        # 60ms creates a slow, eerie, living pulse
        app.after(60, animate_background) 
        
    animate_background()
    
except Exception as e:
    print(f"[*] Background image skipped: {e}")
# ---------------------------------------

# 2. Initialize the middle-end worker agent
checker = VulnerabilityChecker()

# --- NEW ALERT FLASHING LOGIC ---
ansi_cleaner = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
is_flashing = False

def flash_alerts():
    global is_flashing
    is_flashing = not is_flashing
    bg_color = "#000000" # Deep pitch black to match the new consoles
    
    # Flash configurations for the main console
    if 'result_console' in globals():
        result_console.tag_config("alert_yellow", foreground="#FFFF00" if is_flashing else bg_color)
        result_console.tag_config("alert_cyan", foreground="#00FFFF" if is_flashing else bg_color)
        result_console.tag_config("alert_red", foreground="#FF0000" if is_flashing else bg_color)
        result_console.tag_config("alert_magenta", foreground="#FF00FF" if is_flashing else bg_color)
        result_console.tag_config("alert_fatal", foreground="#FFFFFF" if is_flashing else bg_color, background="#FF0000" if is_flashing else bg_color)
        
    # Flash configurations for the dedicated threat box
    if 'threat_box' in globals():
        threat_box.tag_config("alert_yellow", foreground="#FFFF00" if is_flashing else bg_color)
        threat_box.tag_config("alert_cyan", foreground="#00FFFF" if is_flashing else bg_color)
        threat_box.tag_config("alert_red", foreground="#FF0000" if is_flashing else bg_color)
        threat_box.tag_config("alert_magenta", foreground="#FF00FF" if is_flashing else bg_color)
        threat_box.tag_config("alert_fatal", foreground="#FFFFFF" if is_flashing else bg_color, background="#FF0000" if is_flashing else bg_color)
        
    app.after(500, flash_alerts)

# Start the background flasher
app.after(500, flash_alerts)

def load_ip_to_target(ip_address):
    target_entry.delete(0, "end")
    target_entry.insert(0, ip_address)

# --- STATE TRACKER FOR ALERT DEDUPLICATION ---
active_threats = {}

def sniffer_callback(log_text):
    # 1. Scrub the raw brackets out of the Rust string
    clean_text = ansi_cleaner.sub('', log_text)
    
    # 2. Tag the line based on the threat signature
    tag = None
    if "SYN FLOOD" in clean_text: tag = "alert_yellow"
    elif "PORT SCAN" in clean_text: tag = "alert_cyan"
    elif "UNSAFE PROTOCOL" in clean_text: tag = "alert_red"
    elif "BRUTE FORCE" in clean_text: tag = "alert_magenta"
    elif "REVERSE SHELL" in clean_text: tag = "alert_fatal"

    # 3. Process the main console: Make ALL printed IPs clickable on the fly
    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', clean_text)
    
    def insert_main_console():
        if ip_match:
            detected_ip = ip_match.group(0)
            main_click_tag = f"main_click_{detected_ip}_{len(clean_text)}_{id(clean_text)}"
            
            # Insert text into the main console with its color tag (if it's a threat) plus the click tag
            tags_to_apply = (tag, main_click_tag) if tag else (main_click_tag,)
            result_console.insert("end", clean_text + "\n", tags_to_apply)
            
            # Configure the click behavior for the main console
            result_console.tag_config(main_click_tag, underline=True)
            result_console.tag_bind(main_click_tag, "<Button-1>", lambda e, ip=detected_ip: load_ip_to_target(ip))
            result_console.tag_bind(main_click_tag, "<Enter>", lambda e: result_console.configure(cursor="hand2"))
            result_console.tag_bind(main_click_tag, "<Leave>", lambda e: result_console.configure(cursor="arrow"))
        else:
            # Normal text without an IP address
            if tag:
                result_console.insert("end", clean_text + "\n", tag)
            else:
                result_console.insert("end", clean_text + "\n")
                
        result_console.see("end")

    app.after(0, insert_main_console)

    # 4. IF it's a threat, also clone it into the top static threat box
    if tag:
        if ip_match:
            detected_ip = ip_match.group(0)
            
            def insert_clickable_threat():
                # 1. Update the state tracker
                if clean_text in active_threats:
                    active_threats[clean_text]['count'] += 1
                else:
                    unique_tag = f"click_tag_{id(clean_text)}"
                    active_threats[clean_text] = {'count': 1, 'tag': tag, 'ip': detected_ip, 'id': unique_tag}
                    
                # 2. Wipe the box clean
                threat_box.delete("0.0", "end")
                
                # 3. Redraw the aggregated list
                for threat, data in active_threats.items():
                    count_str = f"  (x{data['count']})" if data['count'] > 1 else ""
                    display_text = threat + count_str + "\n"
                    
                    threat_box.insert("end", display_text, (data['tag'], data['id']))
                    
                    # Reapply styling and click events to the redrawn line
                    threat_box.tag_config(data['id'], relief="solid", borderwidth=1, underline=True)
                    threat_box.tag_bind(data['id'], "<Button-1>", lambda e, ip=data['ip']: load_ip_to_target(ip))
                    threat_box.tag_bind(data['id'], "<Enter>", lambda e: threat_box.configure(cursor="hand2"))
                    threat_box.tag_bind(data['id'], "<Leave>", lambda e: threat_box.configure(cursor="arrow"))
                    
                threat_box.see("end")

            app.after(0, insert_clickable_threat)
# --------------------------------

sniffer = TCPSniffer(sniffer_callback)

def toggle_sniffer():
    if not sniffer.is_sniffing:
        result_console.insert("end", "\n[*] Initiating Wireshark-style TCP Capture...\n")
        sniffer.start()
        # Turn the button red to indicate active monitoring
        sniff_button.configure(text="Stop Sniffer", fg_color="#C9302C", hover_color="#AC2925") 
    else:
        sniffer.stop()
        result_console.insert("end", "\n[*] TCP Capture Stopped.\n")
        # Revert button back to default blue
        sniff_button.configure(text="Start Sniffer", fg_color=["#3B8ED0", "#1F6AA5"])

# --- ADDED: The new function to clear threats across Python, UI, and Rust ---
def clear_threats_ui():
    # 1. Send command to Rust
    sniffer.clear_backend_threats()
    
    # 2. Clear Python's tracking memory
    global active_threats
    active_threats.clear()
    
    # 3. Reset the visual red box
    threat_box.delete("0.0", "end")
    threat_box.insert("0.0", "--- WAITING FOR THREAT SIGNATURES ---\n")
    
    # 4. Log it in the main console
    result_console.insert("end", "\n[*] Threat trackers and GUI reset.\n")
    result_console.see("end")

# 3. Define what happens when the button is clicked
def execute_scan():
    target = target_entry.get()
    
    # Catch empty inputs
    if not target:
        result_console.insert("end", "[!] Error: Please enter a target IP or domain.\n")
        return
        
    # Clear previous results and show status
    result_console.delete("0.0", "end")
    result_console.insert("end", f"[*] TARGET ACQUIRED: {target}\n")
    result_console.insert("end", "[*] Executing comprehensive vulnerability scan...\n\n")
    
    # This is the "Walkie-Talkie" function. 
    # The backend will call this every time it finishes a single step.
    def ui_callback(text):
        app.after(0, lambda: result_console.insert("end", text + "\n"))
        app.after(0, result_console.see, "end")
    
    # Run the scan in a background thread
    def background_worker():
        try:
            # We pass the callback function into the backend
            checker.run_scan(target, callback=ui_callback)
        except Exception as e:
            ui_callback(f"\n[!] Critical Scan Error: {str(e)}")
            
    threading.Thread(target=background_worker, daemon=True).start()

def run_port_checker():
    target = target_entry.get()
    if not target:
        result_console.insert("end", "[!] Error: Please enter a target IP or domain.\n")
        return
        
    result_console.delete("0.0", "end")
    result_console.insert("end", f"[*] INITIATING HIGH-SPEED GO SCANNER ON: {target}\n")
    result_console.insert("end", "============================================================\n\n")
    
    def execute_go_backend():
        try:
            exe_path = r'C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\SecurityScanner.exe'
            result = subprocess.run([exe_path, target], capture_output=True, text=True, encoding='utf-8')
            app.after(0, lambda: result_console.insert("end", result.stdout + "\n"))
            app.after(0, result_console.see, "end")
        except Exception as e:
            error_message = str(e)
            app.after(0, lambda: result_console.insert("end", f"[!] Error: {error_message}\n"))
    threading.Thread(target=execute_go_backend, daemon=True).start()

def block_target():
    target = target_entry.get()
    if not target:
        result_console.insert("end", "[!] Error: Please enter a target IP to block.\n")
        return
        
    result_console.insert("end", f"[*] Attempting to block IP: {target}...\n")
    def run_block():
        try:
            exe_path = r'C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\SecurityScanner.exe'
            result = subprocess.run([exe_path, '--block', target], capture_output=True, text=True, encoding='utf-8')
            app.after(0, lambda: result_console.insert("end", result.stdout + "\n"))
            app.after(0, result_console.see, "end")
        except Exception as e:
            error_message = str(e)
            app.after(0, lambda: result_console.insert("end", f"[!] Error: {error_message}\n"))
    threading.Thread(target=run_block, daemon=True).start()

def unblock_target():
    target = target_entry.get()
    if not target:
        result_console.insert("end", "[!] Error: Please enter a target IP to unblock.\n")
        return
        
    result_console.insert("end", f"[*] Attempting to unblock IP: {target}...\n")
    def run_unblock():
        try:
            exe_path = r'C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\SecurityScanner.exe'
            result = subprocess.run([exe_path, '--unblock', target], capture_output=True, text=True, encoding='utf-8')
            app.after(0, lambda: result_console.insert("end", result.stdout + "\n"))
            app.after(0, result_console.see, "end")
        except Exception as e:
            error_message = str(e)
            app.after(0, lambda: result_console.insert("end", f"[!] Error: {error_message}\n"))
    threading.Thread(target=run_unblock, daemon=True).start()

def list_blocked_targets():
    result_console.insert("end", "[*] Querying Host Firewall for active blocks...\n")
    def run_list():
        try:
            exe_path = r'C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\SecurityScanner.exe'
            result = subprocess.run([exe_path, '--list'], capture_output=True, text=True, encoding='utf-8')
            app.after(0, lambda: result_console.insert("end", result.stdout + "\n"))
            app.after(0, result_console.see, "end")
        except Exception as e:
            error_message = str(e)
            app.after(0, lambda: result_console.insert("end", f"[!] Error: {error_message}\n"))
    threading.Thread(target=run_list, daemon=True).start()

def locate_target():
    target = target_entry.get()
    if not target:
        result_console.insert("end", "[!] Error: Please enter a target IP to locate.\n")
        return
        
    result_console.insert("end", f"[*] Triangulating geographical location for IP: {target}...\n")
    result_console.see("end")

    def display_popup(content, map_url, coords):
        # Create a floating window
        popup = ctk.CTkToplevel(app)
        popup.title(f"Geolocation: {target}")
        
        # --- Top Right Positioning Math ---
        pop_width = 500
        pop_height = 420
        screen_width = popup.winfo_screenwidth()
        
        # Calculate X position (Screen Width - Popup Width - 20 pixels padding from the edge)
        # Calculate Y position (20 pixels padding from the top)
        x_pos = screen_width - pop_width - 20
        y_pos = 20
        
        # Apply the size and exact coordinates
        popup.geometry(f"{pop_width}x{pop_height}+{x_pos}+{y_pos}")
        
        # Make it 90% opaque (transparent) and lock it on top of the main UI
        popup.attributes("-alpha", 0.90)
        popup.attributes("-topmost", True)
        
        # Popup Title
        lbl = ctk.CTkLabel(popup, text=f"📍 Location Data: {target}", font=("Arial", 16, "bold"), text_color="#00FFFF")
        lbl.pack(pady=10)
        
        # Dedicated Textbox for the API results
        txt = ctk.CTkTextbox(
            popup, 
            width=450, 
            height=200, 
            font=("Consolas", 14), 
            fg_color="#050806", 
            text_color="#00FF00", 
            border_color="#17A2B8", 
            border_width=1
        )
        txt.pack(padx=10, pady=5)
        txt.insert("0.0", content)
        txt.configure(state="disabled")  # Locks the text so it can't be edited
        
        # Dynamic Clickable Map Button
        if map_url and coords:
            map_btn = ctk.CTkButton(
                popup, 
                text=f"🗺️ Open Google Maps [{coords}]", 
                font=("Arial", 14, "bold"), 
                fg_color="#0D9488", 
                hover_color="#0F766E", 
                command=lambda: webbrowser.open(map_url) # Launches default web browser
            )
            map_btn.pack(pady=(10, 5))
        
        # Close button
        btn = ctk.CTkButton(
            popup, 
            text="Close", 
            font=("Arial", 14, "bold"), 
            fg_color="#C9302C", 
            hover_color="#AC2925", 
            command=popup.destroy
        )
        btn.pack(pady=(5, 10))

    def run_locate():
        import subprocess
        try:
            exe_path = r'C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\SecurityScanner.exe'
            result = subprocess.run([exe_path, '--locate', target], capture_output=True, text=True, encoding='utf-8')
            
            # --- Parse the Go output to extract the Map URL and Coordinates ---
            map_url = None
            coords = None
            
            for line in result.stdout.split('\n'):
                if "Map:" in line and "http" in line:
                    map_url = line.split("Map:")[1].strip()
                    if "query=" in map_url:
                        coords = map_url.split("query=")[1].strip()
            
            # Send the parsed data to the UI thread
            app.after(0, lambda: display_popup(result.stdout, map_url, coords))
            
        except Exception as e:
            error_message = str(e)
            app.after(0, lambda: result_console.insert("end", f"[!] Error: {error_message}\n"))
            
    threading.Thread(target=run_locate, daemon=True).start()

def single_ping_target():
    target = target_entry.get()
    if not target:
        result_console.insert("end", "[!] Error: Please enter a target IP to ping.\n")
        return
        
    result_console.insert("end", f"[*] Executing single test ping against: {target}...\n")
    def run_ping():
        try:
            exe_path = r'C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\SecurityScanner.exe'
            result = subprocess.run([exe_path, '--ping', target], capture_output=True, text=True, encoding='utf-8')
            app.after(0, lambda: result_console.insert("end", result.stdout + "\n"))
            app.after(0, result_console.see, "end")
        except Exception as e:
            error_message = str(e)
            app.after(0, lambda: result_console.insert("end", f"[!] Error: {error_message}\n"))
    threading.Thread(target=run_ping, daemon=True).start()

# ---------------------------------------------------------
# 4. Build the Visual Elements (Widgets)
# ---------------------------------------------------------

# Title
title_label = ctk.CTkLabel(app, text="System Diagnostic & Security Scanner", font=("Arial", 24, "bold"), fg_color="transparent")
title_label.pack(pady=20)

# =========================================================
# ROW 1: Target Input & Primary Scans
# =========================================================
target_entry = ctk.CTkEntry(app, placeholder_text="Enter Target IP (e.g., 192.168.1.1)", width=350, font=("Arial", 14))
target_entry.place(relx=0.5, y=80, x=-160, anchor="center")

# --- ANIMATED MASTER CONTROLS GENERATOR ---
scan_frames, sniffer_frames, clear_frames = [], [], []

for f in range(24):
    img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([4, 4, 27, 27], outline="#0284c7", width=2)
    draw.ellipse([14, 14, 17, 17], fill="#38bdf8")
    angle = (f / 24) * (2 * math.pi)
    draw.line([15.5, 15.5, 15.5 + 11 * math.cos(angle), 15.5 + 11 * math.sin(angle)], fill="#e0f2fe", width=2)
    for pts in [[15,1,15,4], [15,27,15,30], [1,15,4,15], [27,15,30,15]]: draw.line(pts, fill="#38bdf8", width=1)
    scan_frames.append(ctk.CTkImage(light_image=img, dark_image=img, size=(20, 20)))

for f in range(20):
    img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    for idx, bx in enumerate([6, 12, 18, 24]):
        phase = (f / 20) * (2 * math.pi) + (idx * 1.5)
        bar_height = int(12 + 9 * math.sin(phase))
        draw.rounded_rectangle([bx, 16 - (bar_height // 2), bx + 3, 16 + (bar_height // 2)], radius=1, fill="#22d3ee")
    sniffer_frames.append(ctk.CTkImage(light_image=img, dark_image=img, size=(20, 20)))

for f in range(20):
    img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.polygon([(16, 4), (26, 8), (24, 22), (16, 28), (8, 22), (6, 8)], outline="#f97316", width=2)
    sweep_y = int(5 + (f / 20) * 22)
    draw.line([7, sweep_y, 25, sweep_y], fill="#ffffff", width=2)
    draw.line([9, min(sweep_y + 1, 27), 23, min(sweep_y + 1, 27)], fill="#ef4444", width=1)
    clear_frames.append(ctk.CTkImage(light_image=img, dark_image=img, size=(20, 20)))
# ------------------------------------------

scan_button = ctk.CTkButton(
    app, 
    text=" Execute Scan", 
    image=scan_frames[0], 
    compound="left", 
    font=("Arial", 14, "bold"),
    fg_color="#722F37",  
    hover_color="#4B1F24",
    command=execute_scan
)
scan_button.place(relx=0.5, y=80, x=100, anchor="center")

sniff_button = ctk.CTkButton(
    app, 
    text=" Start Sniffer", 
    image=sniffer_frames[0], 
    compound="left", 
    font=("Arial", 14, "bold"), 
    command=toggle_sniffer
)
sniff_button.place(relx=0.5, y=80, x=255, anchor="center")

current_scan_f, current_sniff_f = 0, 0
def animate_top_controls():
    global current_scan_f, current_sniff_f
    current_scan_f = (current_scan_f + 1) % len(scan_frames)
    scan_button.configure(image=scan_frames[current_scan_f])
    current_sniff_f = (current_sniff_f + 1) % len(sniffer_frames)
    sniff_button.configure(image=sniffer_frames[current_sniff_f])
    app.after(50, animate_top_controls)

animate_top_controls()

# =========================================================
# ROW 2: Recon & Diagnostics 
# =========================================================

ghost_frames = []
for i in range(60):
    img_data = Image.open(f"Animation file/locate ip animation/ghost_f{i}.png").convert("RGBA")
    y_offset = int(math.sin(i / 60 * 2 * math.pi) * 2) 
    bobbing_img = Image.new("RGBA", img_data.size, (0, 0, 0, 0))
    bobbing_img.paste(img_data, (0, y_offset))
    ghost_frames.append(ctk.CTkImage(light_image=bobbing_img, dark_image=bobbing_img, size=(30, 30)))

locate_button = ctk.CTkButton(
    app, 
    text=" Locate IP", 
    image=ghost_frames[0], 
    font=("Arial", 14, "bold"), 
    fg_color="#17A2B8", 
    hover_color="#138496", 
    text_color="black", 
    command=locate_target
)
# Moved down to the bottom left (Clear Threat's old spot)
locate_button.place(x=50, rely=1.0, y=-325)

current_ghost_frame = 0
def animate_ghost_button():
    global current_ghost_frame
    current_ghost_frame = (current_ghost_frame + 1) % len(ghost_frames)
    locate_button.configure(image=ghost_frames[current_ghost_frame])
    app.after(50, animate_ghost_button) 

animate_ghost_button()

port_checker_frames = []
for i in range(60):
    img_data = Image.open(f"Animation file/port checker animation/port_checker_f{i}.png").convert("RGBA")
    port_checker_frames.append(ctk.CTkImage(light_image=img_data, dark_image=img_data, size=(30, 30)))

port_checker_button = ctk.CTkButton(
    app, 
    text=" Port Checker", 
    image=port_checker_frames[0],  
    compound="left",               
    font=("Arial", 14, "bold"), 
    fg_color="#28A745",         
    hover_color="#218838",      
    text_color="white", 
    command=run_port_checker
)
# Placed directly over the lower-left shield, right where you pointed!
port_checker_button.place(x=50, rely=1.0, y=-450)

current_port_frame = 0
def animate_port_checker():
    global current_port_frame
    current_port_frame = (current_port_frame + 1) % len(port_checker_frames)
    port_checker_button.configure(image=port_checker_frames[current_port_frame])
    app.after(50, animate_port_checker)

animate_port_checker()

ping_frames = []
for i in range(20):
    img_data = Image.open(f"Animation file/test ping animation/image_6_f{i}.png")
    ping_frames.append(ctk.CTkImage(light_image=img_data, dark_image=img_data, size=(30, 30)))

ping_button = ctk.CTkButton(
    app, 
    text=" Test Ping", 
    image=ping_frames[0], 
    font=("Arial", 14, "bold"), 
    fg_color="#8A2BE2", 
    hover_color="#5D3FD3", 
    command=single_ping_target
)
ping_button.place(relx=0.5, y=140, x=160, anchor="center")

current_ping_frame = 0
def animate_ping_button():
    global current_ping_frame
    current_ping_frame = (current_ping_frame + 1) % len(ping_frames)
    ping_button.configure(image=ping_frames[current_ping_frame])
    app.after(60, animate_ping_button)

animate_ping_button()

# =========================================================
# ROW 3: Firewall Controls (Perfectly framing the cyber ghost!)
# =========================================================

block_frames = []
for i in range(60):
    img_data = Image.open(f"Animation file/block ip animation/block_f{i}.png").convert("RGBA")
    angle = math.sin(i / 60 * 2 * math.pi) * 15 
    rotated_img = img_data.rotate(angle, resample=Image.BICUBIC, fillcolor=(0,0,0,0))
    block_frames.append(ctk.CTkImage(light_image=rotated_img, dark_image=rotated_img, size=(45, 45)))

block_button = ctk.CTkButton(
    app, 
    text=" Block IP", 
    image=block_frames[0],
    height=28,
    font=("Arial", 14, "bold"), 
    fg_color="#000000",         
    border_width=2,             
    border_color="#C9302C",     
    hover_color="#2b0a0a",      
    command=block_target
)
# Nudged inward by 25 pixels to sit perfectly centered inside the background shield!
block_button.place(relx=0.5, y=200, x=-165, anchor="center")

current_block_frame = 0
def animate_block_button():
    global current_block_frame
    current_block_frame = (current_block_frame + 1) % len(block_frames)
    block_button.configure(image=block_frames[current_block_frame])
    app.after(30, animate_block_button)

animate_block_button()

unblock_frames = []
base_unblock_img = Image.open("Animation file/unblock ip animation/unblocking_transparent.png").convert("RGBA")
for i in range(60):
    angle = math.sin(i / 60 * 2 * math.pi) * 15 
    rotated_img = base_unblock_img.rotate(angle, resample=Image.BICUBIC, fillcolor=(0,0,0,0))
    unblock_frames.append(ctk.CTkImage(light_image=rotated_img, dark_image=rotated_img, size=(30, 30)))

unblock_button = ctk.CTkButton(
    app, 
    text=" Unblock IP",
    image=unblock_frames[0],    
    height=28,                  
    font=("Arial", 14, "bold"), 
    fg_color="#F0AD4E", 
    hover_color="#D58512", 
    text_color="black", 
    command=unblock_target
)
# Dropped down to perfectly mirror the Port Checker and sit over the keyhole shield!
unblock_button.place(x=750, rely=1.0, y=-450, anchor="ne")

current_unblock_frame = 0
def animate_unblock_button():
    global current_unblock_frame
    current_unblock_frame = (current_unblock_frame + 1) % len(unblock_frames)
    unblock_button.configure(image=unblock_frames[current_unblock_frame])
    app.after(30, animate_unblock_button) 

animate_unblock_button()
# ----------------------------------

# The Show Blocklist button stays the same
# --- ANIMATED SHOW BLOCKLIST BUTTON FRAMES ---
blocklist_frames = []
for i in range(60):
    img_data = Image.open(f"Animation file/show blocklist animation/blocklist_f{i}.png").convert("RGBA")
    blocklist_frames.append(ctk.CTkImage(light_image=img_data, dark_image=img_data, size=(30, 30)))

# ---------------------------------------------------------
# --- BOTTOM SECTION: CONSOLES & THREAT CONTROLS ---
# We pack from the BOTTOM UP so they stick to the floor without blocking the background!
# ---------------------------------------------------------

# 1. Main Output Console (Bottom-most)
result_console = ctk.CTkTextbox(
    app, 
    width=700, 
    height=160, 
    font=("Consolas", 14), 
    fg_color=("#050806", "#050806"), 
    border_color="#10b981", 
    border_width=1, 
    text_color="#00ff00"
)
result_console.pack(side="bottom", pady=(5, 20))
result_console.insert("0.0", "System Ready. Waiting for target input...\n")

# 2. Dedicated Active Threats Box (Sits right above the green box)
threat_box = ctk.CTkTextbox(
    app, 
    width=700, 
    height=90, 
    font=("Consolas", 13), 
    fg_color=("#050806", "#050806"), 
    border_color="#EF4444", 
    border_width=1, 
    text_color="#FFFFFF"
)
threat_box.pack(side="bottom", pady=(2, 10))
threat_box.insert("0.0", "--- WAITING FOR THREAT SIGNATURES ---\n")

# 3. Threat Controls Row (Using .place to completely remove the black background!)

# The Teal Clear Threat Button (Anchored precisely to the left edge of the red box)
clear_threats_button = ctk.CTkButton(
    app, 
    text=" Clear Threats", 
    image=clear_frames[0], 
    compound="left", 
    font=("Arial", 14, "bold"), 
    fg_color="#0D9488",  
    hover_color="#0F766E", 
    text_color="white", 
    command=clear_threats_ui
)
# Moved over to the bottom right (Show Blocklist's old spot)
clear_threats_button.place(x=750, rely=1.0, y=-325, anchor="ne")

# Active Threat Label (Centered perfectly BETWEEN the two buttons!)
threat_label = ctk.CTkLabel(
    app, 
    text="Active Threat Detections (Click IP to Target)", 
    font=("Arial", 12, "bold"), 
    text_color="#EF4444",
    fg_color="transparent" # Forces the text background to be completely see-through
)
threat_label.place(relx=0.5, rely=1.0, y=-322, anchor="n")

# The Show Blocklist Button (Anchored precisely to the right edge of the red box)
list_button = ctk.CTkButton(
    app, 
    text=" Show Blocklist", 
    image=blocklist_frames[0], 
    compound="left",
    height=28,
    font=("Arial", 14, "bold"), 
    fg_color="#000000",
    border_width=2,
    border_color="#5CB85C", 
    hover_color="#1a1a1a", 
    text_color="white", 
    command=list_blocked_targets
)
# Moved up to the top left (completing the 3-way swap into Locate IP's old spot!)
list_button.place(relx=0.5, y=140, x=-160, anchor="center")

# The Animation Engine for the Clear Threats Button
current_clear_f = 0
def animate_clear_button():
    global current_clear_f
    current_clear_f = (current_clear_f + 1) % len(clear_frames)
    clear_threats_button.configure(image=clear_frames[current_clear_f])
    app.after(50, animate_clear_button)

animate_clear_button()

# The Animation Engine for the List Button
current_list_frame = 0
def animate_list_button():
    global current_list_frame
    current_list_frame = (current_list_frame + 1) % len(blocklist_frames)
    list_button.configure(image=blocklist_frames[current_list_frame])
    app.after(40, animate_list_button) 

animate_list_button()

# 5. Keep the window running
if __name__ == "__main__":
    app.mainloop()
