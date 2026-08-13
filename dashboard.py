# dashboard.py
"""
Front-End UI for CyberSecurity Multi-Agent Infrastructure
"""

import customtkinter as ctk
import threading
from vulnerability_checker import VulnerabilityChecker
from tcp_sniffer import TCPSniffer

# 1. Initialize the visual window
app = ctk.CTk()
app.geometry("800x600")
app.title("CyberSecurity Multi-Agent Dashboard")
ctk.set_appearance_mode("dark")  # Forces a sleek hacker-style dark theme
ctk.set_default_color_theme("blue")

# 2. Initialize the middle-end worker agent
checker = VulnerabilityChecker()

def sniffer_callback(log_text):
    # Safely pass live packet data into the visual terminal and auto-scroll
    app.after(0, lambda: result_console.insert("end", log_text + "\n"))
    app.after(0, result_console.see, "end") 

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
    result_console.insert("end", "[*] Waking up worker agents for comprehensive analysis...\n")
    result_console.insert("end", "============================================================\n\n")
    
    # Run the scan in a background thread so the visual UI doesn't freeze
    def background_worker():
        # PHASE 1: Port Scanning
        try:
            app.after(0, lambda: result_console.insert("end", "[>>>] PHASE 1: Executing TCP Port Scan...\n"))
            ports = checker.check_open_ports(target)
            app.after(0, lambda: result_console.insert("end", f"      [+] Open Ports Discovered: {ports}\n\n"))
            app.after(0, result_console.see, "end") # Auto-scrolls the terminal down
        except Exception as e:
            app.after(0, lambda: result_console.insert("end", f"      [-] Port Scan Failed: {str(e)}\n\n"))

        # PHASE 2: DNS Records
        try:
            app.after(0, lambda: result_console.insert("end", "[>>>] PHASE 2: Querying DNS Records...\n"))
            # If your method is named differently, just change 'check_dns' below
            if hasattr(checker, 'check_dns'):
                dns_data = checker.check_dns(target) 
                app.after(0, lambda: result_console.insert("end", f"      [+] DNS Data: {dns_data}\n\n"))
            else:
                app.after(0, lambda: result_console.insert("end", "      [-] DNS method 'check_dns' not found in checker.\n\n"))
            app.after(0, result_console.see, "end")
        except Exception as e:
            app.after(0, lambda: result_console.insert("end", f"      [-] DNS Query Skipped: {str(e)}\n\n"))

        # PHASE 3: HTTP Security Headers
        try:
            app.after(0, lambda: result_console.insert("end", "[>>>] PHASE 3: Analyzing HTTP Security Headers...\n"))
            if hasattr(checker, 'check_headers'):
                headers = checker.check_headers(target)
                app.after(0, lambda: result_console.insert("end", f"      [+] Headers: {headers}\n\n"))
            else:
                app.after(0, lambda: result_console.insert("end", "      [-] Header method 'check_headers' not found in checker.\n\n"))
            app.after(0, result_console.see, "end")
        except Exception as e:
            app.after(0, lambda: result_console.insert("end", f"      [-] Header Check Skipped: {str(e)}\n\n"))
            
        # PHASE 4: SSL/TLS Certificate
        try:
            app.after(0, lambda: result_console.insert("end", "[>>>] PHASE 4: Validating SSL/TLS Certificate...\n"))
            if hasattr(checker, 'check_ssl'):
                ssl_info = checker.check_ssl(target)
                app.after(0, lambda: result_console.insert("end", f"      [+] Certificate Info: {ssl_info}\n\n"))
            else:
                app.after(0, lambda: result_console.insert("end", "      [-] SSL method 'check_ssl' not found in checker.\n\n"))
            app.after(0, result_console.see, "end")
        except Exception as e:
            app.after(0, lambda: result_console.insert("end", f"      [-] SSL Check Skipped: {str(e)}\n\n"))

        # Final Sign-off
        app.after(0, lambda: result_console.insert("end", "============================================================\n"))
        app.after(0, lambda: result_console.insert("end", "[✓] COMPREHENSIVE SCAN COMPLETE.\n"))
        app.after(0, result_console.see, "end")
            
    threading.Thread(target=background_worker, daemon=True).start()

def block_target():
    target = target_entry.get()
    if not target:
        result_console.insert("end", "[!] Error: Please enter a target IP to block.\n")
        return
        
    result_console.insert("end", f"[*] Attempting to block IP: {target}...\n")
    def run_block():
        import subprocess
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
        import subprocess
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
        import subprocess
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
    def run_locate():
        import subprocess
        try:
            exe_path = r'C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\SecurityScanner.exe'
            # Fires the --locate command to the Go engine
            result = subprocess.run([exe_path, '--locate', target], capture_output=True, text=True, encoding='utf-8')
            app.after(0, lambda: result_console.insert("end", result.stdout + "\n"))
            app.after(0, result_console.see, "end")
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
        import subprocess
        try:
            exe_path = r'C:\Users\blade\OneDrive\Desktop\My Projects\CyberSecurity Tool\SecurityScanner.exe'
            result = subprocess.run([exe_path, '--ping', target], capture_output=True, text=True, encoding='utf-8')
            app.after(0, lambda: result_console.insert("end", result.stdout + "\n"))
            app.after(0, result_console.see, "end")
        except Exception as e:
            error_message = str(e)
            app.after(0, lambda: result_console.insert("end", f"[!] Error: {error_message}\n"))
    threading.Thread(target=run_ping, daemon=True).start()

# Create a third horizontal row for Recon & Diagnostic controls
recon_frame = ctk.CTkFrame(app, fg_color="transparent")
recon_frame.pack(pady=5)

locate_button = ctk.CTkButton(recon_frame, text="Locate IP", font=("Arial", 14, "bold"), fg_color="#8A2BE2", hover_color="#5D3FD3", command=locate_target)
locate_button.pack(side="left", padx=15)

# 4. Build the Visual Elements (Widgets)
title_label = ctk.CTkLabel(app, text="System Diagnostic & Security Scanner", font=("Arial", 24, "bold"))
title_label.pack(pady=30)

# Create a horizontal row for the input bar and button
input_frame = ctk.CTkFrame(app, fg_color="transparent")
input_frame.pack(pady=10)

target_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter Target IP (e.g., 192.168.1.1)", width=350, font=("Arial", 14))
target_entry.pack(side="left", padx=15)

scan_button = ctk.CTkButton(input_frame, text="Execute Scan", font=("Arial", 14, "bold"), command=execute_scan)
scan_button.pack(side="left", padx=(0, 15))

sniff_button = ctk.CTkButton(input_frame, text="Start Sniffer", font=("Arial", 14, "bold"), command=toggle_sniffer)
sniff_button.pack(side="left")

ping_button = ctk.CTkButton(recon_frame, text="Test Ping", font=("Arial", 14, "bold"), fg_color="#8A2BE2", hover_color="#5D3FD3", command=single_ping_target)
ping_button.pack(side="left", padx=(15, 0))

# Create a second horizontal row for firewall controls
firewall_frame = ctk.CTkFrame(app, fg_color="transparent")
firewall_frame.pack(pady=5)

block_button = ctk.CTkButton(firewall_frame, text="Block IP", font=("Arial", 14, "bold"), fg_color="#C9302C", hover_color="#AC2925", command=block_target)
block_button.pack(side="left", padx=(0, 15))

unblock_button = ctk.CTkButton(firewall_frame, text="Unblock IP", font=("Arial", 14, "bold"), fg_color="#F0AD4E", hover_color="#D58512", text_color="black", command=unblock_target)
unblock_button.pack(side="left", padx=(0, 15))

list_button = ctk.CTkButton(firewall_frame, text="Show Blocklist", font=("Arial", 14, "bold"), fg_color="#5CB85C", hover_color="#4CAE4C", text_color="black", command=list_blocked_targets)
list_button.pack(side="left")

# Create the black terminal-style output box
result_console = ctk.CTkTextbox(app, width=700, height=350, font=("Consolas", 14), fg_color="#1e1e1e", text_color="#00ff00")
result_console.pack(pady=30)
result_console.insert("0.0", "System Ready. Waiting for target input...\n")

# 5. Keep the window running
if __name__ == "__main__":
    app.mainloop()
