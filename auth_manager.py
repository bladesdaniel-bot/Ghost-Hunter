# auth_manager.py
import os
import sys
import json
import hashlib
import secrets
import random
import customtkinter as ctk

# Resolves the path to point inside the _internal folder
if getattr(sys, 'frozen', False):
    # When compiled as an .exe, route to the _internal directory
    INTERNAL_DIR = os.path.join(os.path.dirname(sys.executable), "_internal")
    VAULT_DIR = os.path.join(INTERNAL_DIR, "Auth_Vault")
else:
    # When running in dev mode (VS Code)
    VAULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Auth_Vault")

# Automatically create the Auth_Vault folder if it doesn't exist
os.makedirs(VAULT_DIR, exist_ok=True)

AUTH_FILE = os.path.join(VAULT_DIR, "auth_vault.json")

# Generates a highly secure, human-readable recovery key (CYBR-XXXX-XXXX-XXXX)
def generate_recovery_key() -> str:
    # Excluded O, 0, I, 1 to prevent user reading errors
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    
    def gen_block():
        return "".join(random.choice(chars) for _ in range(4))
        
    return f"CYBR-{gen_block()}-{gen_block()}-{gen_block()}"

# Hashes a secret using PBKDF2 HMAC SHA-256 (100,000 rounds)
def hash_secret(secret: str, salt_bytes: bytes = None):
    salt = salt_bytes or secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), salt, 100000)
    return salt.hex(), key.hex()

# Verifies a secret against the stored hash securely
def verify_secret(secret: str, salt_hex: str, key_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        stored_key = bytes.fromhex(key_hex)
        new_key = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), salt, 100000)
        # Constant-time check prevents timing attacks
        return secrets.compare_digest(new_key.hex(), stored_key.hex())
    except Exception:
        return False

# The UI State Application
class AuthApp:
    def __init__(self):
        ctk.set_appearance_mode("Dark")
        self.win = ctk.CTk()
        self.win.title("Terminal Access Control")
        self.win.geometry("380x390")
        self.win.resizable(False, False)
        self.win.attributes("-topmost", True)

        # Center window
        self.win.update_idletasks()
        x = (self.win.winfo_screenwidth() // 2) - (380 // 2)
        y = (self.win.winfo_screenheight() // 2) - (390 // 2)
        self.win.geometry(f"+{x}+{y}")

        self.auth_status = False
        self.attempts = 3
        self.status_msg = ""
        self.raw_recovery_key = ""
        
        # Determine initial state based on vault existence
        if os.path.exists(AUTH_FILE):
            self.state = "Login"
        else:
            self.state = "Setup"

        self.main_frame = ctk.CTkFrame(self.win, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.render_state()

    def clear_frame(self):
        # Clears all widgets to simulate immediate-mode GUI rendering (like egui)
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def render_state(self):
        self.clear_frame()
        self.win.unbind("<Return>")

        # Dynamic Headers based on State
        if self.state == "Setup":
            title, color, sub_lbl = "INITIAL SETUP", "#00FFAA", "Create your Master Passphrase"
        elif self.state == "ShowRecovery":
            title, color, sub_lbl = "VAULT SECURED", "#FFA500", "Crucial: Save Your Recovery Key"
        elif self.state == "Login":
            title, color, sub_lbl = "SECURITY GATEWAY", "#00BFFF", "Identity Verification Required"
        elif self.state == "Recovery":
            title, color, sub_lbl = "EMERGENCY RECOVERY", "#FF4444", "Enter your 16-character Recovery Key"

        # Render Headers
        ctk.CTkLabel(self.main_frame, text=title, font=("Consolas", 18, "bold"), text_color=color).pack(pady=(0, 5))
        ctk.CTkLabel(self.main_frame, text=sub_lbl, font=("Consolas", 11), text_color="gray").pack(pady=(0, 15))

        # State Machine UI Rendering
        if self.state == "Setup":
            pwd_input = ctk.CTkEntry(self.main_frame, placeholder_text="Master Password", show="*", width=260, font=("Consolas", 12))
            pwd_input.pack(pady=6)
            
            # --- FIX: Delayed focus so it grabs the cursor AFTER the window draws ---
            self.win.after(100, pwd_input.focus)

            confirm_input = ctk.CTkEntry(self.main_frame, placeholder_text="Confirm Password", show="*", width=260, font=("Consolas", 12))
            confirm_input.pack(pady=6)

            # --- DYNAMIC ENTER KEY ROUTING ---
            def jump_to_confirm(event):
                confirm_input.focus()
                return "break"  # The magic command: stops the main form from submitting early!
                
            pwd_input.bind("<Return>", jump_to_confirm)
            # ---------------------------------

            status_lbl = ctk.CTkLabel(self.main_frame, text=self.status_msg, font=("Consolas", 11), text_color="#FF4444")
            status_lbl.pack(pady=6)

            def on_setup_submit(event=None):
                pwd = pwd_input.get().strip()
                conf = confirm_input.get().strip()
                
                if len(pwd) < 6:
                    self.status_msg = "[!] Minimum 6 characters required"
                    self.render_state()
                elif pwd != conf:
                    self.status_msg = "[!] Passwords do not match"
                    self.render_state()
                else:
                    # Generate Recovery Key & Hash both
                    self.raw_recovery_key = generate_recovery_key()
                    pwd_salt, pwd_hash = hash_secret(pwd)
                    rec_salt, rec_hash = hash_secret(self.raw_recovery_key)

                    vault_data = {
                        "pwd_salt": pwd_salt,
                        "pwd_hash": pwd_hash,
                        "rec_salt": rec_salt,
                        "rec_hash": rec_hash
                    }

                    with open(AUTH_FILE, "w") as f:
                        json.dump(vault_data, f)
                    
                    self.status_msg = ""
                    self.state = "ShowRecovery"
                    self.render_state()

            self.win.bind("<Return>", on_setup_submit)
            ctk.CTkButton(self.main_frame, text="Initialize Vault", command=on_setup_submit, width=260, fg_color="#1F538D", font=("Consolas", 12, "bold")).pack(pady=(10, 0))

        elif self.state == "ShowRecovery":
            ctk.CTkLabel(self.main_frame, text="If you forget your password, this is the\nONLY way to recover your tool.", font=("Consolas", 11), text_color="#FF4444").pack(pady=10)
            
            # Display the raw key boldly
            ctk.CTkLabel(self.main_frame, text=self.raw_recovery_key, font=("Consolas", 24, "bold"), text_color="#00FFAA").pack(pady=20)

            def on_safely_written():
                self.auth_status = True
                self.win.destroy()

            ctk.CTkButton(self.main_frame, text="I Have Safely Written This Down", command=on_safely_written, width=260, fg_color="#AD6B00", font=("Consolas", 12, "bold")).pack(pady=10)

        elif self.state == "Login":
            pwd_input = ctk.CTkEntry(self.main_frame, placeholder_text="Master Password", show="*", width=260, font=("Consolas", 12))
            pwd_input.pack(pady=6)
            
            # --- FIX: Delayed focus so it grabs the cursor AFTER the window draws ---
            self.win.after(100, pwd_input.focus)

            status_lbl = ctk.CTkLabel(self.main_frame, text=self.status_msg, font=("Consolas", 11), text_color="#FF4444")
            status_lbl.pack(pady=6)

            def on_login_submit(event=None):
                pwd = pwd_input.get().strip()
                try:
                    with open(AUTH_FILE, "r") as f:
                        vault = json.load(f)
                    
                    if verify_secret(pwd, vault.get("pwd_salt", ""), vault.get("pwd_hash", "")):
                        self.auth_status = True
                        self.win.destroy()
                    else:
                        self.attempts -= 1
                        if self.attempts <= 0:
                            self.win.destroy()
                            sys.exit(0)
                        self.status_msg = f"[!] Access Denied ({self.attempts} attempts left)"
                        self.render_state()
                except Exception:
                    self.status_msg = "[!] Cryptographic vault error"
                    self.render_state()

            self.win.bind("<Return>", on_login_submit)
            ctk.CTkButton(self.main_frame, text="Authenticate", command=on_login_submit, width=260, fg_color="#1F538D", font=("Consolas", 12, "bold")).pack(pady=(5, 10))

            def go_to_recovery():
                self.status_msg = ""
                self.state = "Recovery"
                self.render_state()

            ctk.CTkButton(self.main_frame, text="Forgot Password?", command=go_to_recovery, fg_color="transparent", text_color="gray", hover_color="#2A2D2E", font=("Consolas", 11, "underline")).pack(pady=5)

        elif self.state == "Recovery":
            rec_input = ctk.CTkEntry(self.main_frame, placeholder_text="CYBR-XXXX-XXXX-XXXX", width=260, font=("Consolas", 12))
            rec_input.pack(pady=6)
            
            # --- FIX: Delayed focus so it grabs the cursor AFTER the window draws ---
            self.win.after(100, rec_input.focus)

            status_lbl = ctk.CTkLabel(self.main_frame, text=self.status_msg, font=("Consolas", 11), text_color="#FF4444")
            status_lbl.pack(pady=6)

            def on_recovery_submit(event=None):
                input_upper = rec_input.get().strip().upper()
                try:
                    with open(AUTH_FILE, "r") as f:
                        vault = json.load(f)
                    
                    if verify_secret(input_upper, vault.get("rec_salt", ""), vault.get("rec_hash", "")):
                        # Key matched! Wipe old data and send them to setup
                        os.remove(AUTH_FILE)
                        self.status_msg = ""
                        self.state = "Setup"
                        self.render_state()
                    else:
                        self.status_msg = "[!] Invalid Recovery Key"
                        self.render_state()
                except Exception:
                    self.status_msg = "[!] Vault read error"
                    self.render_state()

            self.win.bind("<Return>", on_recovery_submit)
            ctk.CTkButton(self.main_frame, text="Verify Recovery Key", command=on_recovery_submit, width=260, fg_color="#8D1F1F", font=("Consolas", 12, "bold")).pack(pady=(5, 10))

            def go_to_login():
                self.status_msg = ""
                self.state = "Login"
                self.render_state()

            ctk.CTkButton(self.main_frame, text="Back to Login", command=go_to_login, fg_color="transparent", text_color="gray", hover_color="#2A2D2E", font=("Consolas", 11, "underline")).pack(pady=5)

# The main gateway function to call from dashboard.py
def verify_master_access() -> bool:
    app = AuthApp()
    app.win.mainloop()
    return app.auth_status
