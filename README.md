# 🚀 Ghost-Hunter: Polyglot CyberSecurity Suite

https://github.com/bladesdaniel-bot/Ghost-Hunter/raw/main/Full%20Demo%20Video.mp4

An advanced, multi-language cybersecurity diagnostic and network analysis toolkit. This project utilizes a multi-agent architectural approach, delegating specific security tasks to specialized backend engines written in Go and Rust, all orchestrated by a sleek, animated Python holographic dashboard.

https://github.com/bladesdaniel-bot/Ghost-Hunter/raw/main/Final%20Video.mp4

## 🏗️ System Architecture

This tool breaks down complex security operations into three distinct language environments to maximize speed, safety, and interface fluidity:

*   **Python (The Coordinator & UI):** Manages the graphical interface, handles background task threading, generates dynamic UI animations, and orchestrates the worker agents via `subprocess.Popen`.
*   **Go (The Executioner):** Handles high-speed concurrent network operations, TCP handshake pings, and instant system-level firewall manipulation (blocking/unblocking/auditing IPs).
*   **Rust (The Sniffer):** Provides low-level, memory-safe, and lightning-fast packet capture across multiple protocols (TCP, UDP, ICMP), threat signature detection, and packet logging using native OS interfaces (Npcap).

---

## ✨ Core Features

### 🔐 Zero-Knowledge Security Gateway (IAM)
* **Offline Identity Access Management:** The application is locked behind a cryptographically secure gateway utilizing PBKDF2 HMAC-SHA256 hashing (100,000 iterations). 
* **Disaster Recovery Protocol:** Features an auto-generated, human-readable 16-character `CYBR-` recovery key system. The key is never stored in plaintext, utilizing a dual-hash JSON storage vault to prevent local memory extraction.
* **Frictionless Authentication UX:** Engineered dynamic window-rendering delays to resolve CustomTkinter GUI race conditions, guaranteeing immediate input auto-focus the exact millisecond the gateway launches.
* **Intelligent Keystroke Routing:** Implemented event-driven `<Return>` key bindings that intercept premature form submissions and seamlessly route cursor focus between multiple input fields during the initial vault setup.

### 🖥️ Holographic GUI Command Dashboard
* **Interactive UI:** Built with CustomTkinter, featuring real-time interactive threat consoles, regex-powered clickable IP targeting for instant countermeasures, and custom multi-frame animations (breathing backgrounds, EKG pings, rotating shields).
* **Interactive Threat Deduplication:** A dedicated state-tracking console isolates and aggregates duplicate attacks, displaying active threat counts instead of spamming terminal logs.

### 📍 Floating Geolocation HUD
Reroutes IP location telemetry into a dedicated, 90%-transparent floating popup window pinned to the top-right of the display. It automatically extracts GPS coordinates from the Go backend and features a dynamic, one-click button to open the target's physical location directly in Google Maps.

https://github.com/bladesdaniel-bot/Ghost-Hunter/raw/main/Geo-Location.mp4

### 🦀 Live Packet Sniffing & Threat Telemetry
Rust-powered packet capture that streams raw network telemetry to the Python UI. Includes a thread-safe interactive CLI to dynamically wipe threat memory on the fly. Instantly flags threat signatures including:
*   SYN Floods (DoS attacks)
*   Aggressive Port Scans
*   Cleartext Protocol Violations (FTP/Telnet)
*   Brute Force Attempts (SSH, RDP, MySQL)
*   Reverse Shell Payloads (`cmd.exe`, `/bin/bash`, `powershell`)

https://github.com/bladesdaniel-bot/Ghost-Hunter/raw/main/Different%20Kinds%20Of%20Attacks%20Alert.mp4

### 🗄️ SQLite Packet Vault
The Rust engine silently logs all intercepted packet metadata to a high-speed SQLite database (`packet_vault.db`) utilizing Write-Ahead Logging (WAL) for maximum I/O performance.

*Before Rust Memory Optimizations:*
https://github.com/bladesdaniel-bot/Ghost-Hunter/raw/main/Before%20Adjustments%20Were%20Made%20To%20Compile%20Tcp%20Packets.mp4

*After Rust Memory Optimizations:*
https://github.com/bladesdaniel-bot/Ghost-Hunter/raw/main/After%20Adjustments%20Were%20Made%20To%20Compile%20Tcp%20Packets.mp4

### 🐹 Threat Neutralization & Active Firewall Control
* **Instant OS-Level Blocking:** Instantly block or unblock active threats across the host operating system (Windows `netsh` or Linux `iptables`) using the Go binary. Actively wipes duplicate rules and aggressively blocks both INBOUND and OUTBOUND traffic.
* **Forensic Threat Logging:** Dynamically stamps and logs manual administrator blocks with 12-hour timestamps and specific threat reasons (e.g., "SYN FLOOD Attack") into a local JSON forensic vault, seamlessly integrated into the UI's active firewall auditing pop-ups.

https://github.com/bladesdaniel-bot/Ghost-Hunter/raw/main/Blocked%20Ip%20And%20It%20Coudnt%20Come%20Back%20Through%20Successfully.mp4

### 🔎 Comprehensive Vulnerability Probing
*   High-Speed Port Scanning
*   SSL Certificate validation & HTTP security header audits
*   DNS record extraction
*   Deep vulnerability analysis via Nmap Scripting Engine (NSE) integration

---

## ⚙️ Installation & Usage

**⚠️ Important:** Because this tool utilizes low-level network interface hooks (promiscuous mode) and executes dynamic firewall modifications, it requires elevated privileges to function.

1. Navigate to the **[Releases](../../releases)** page and download the latest `.zip` package.
2. Extract the downloaded folder.
3. Right-click **`CyberSecurity_Tool.exe`** and select **"Run as Administrator"**.
4. Upon first launch, the IAM Gateway will prompt you to initialize your secure vault and generate your master recovery key.

---

## 📂 Codebase Structure

*   `dashboard.py`: The main frontend entry point and UI orchestrator.
*   `auth_manager.py`: The Identity Access Management (IAM) security gateway.
*   `vulnerability_checker.py`: Python engine for deep vulnerability probing and Nmap integration.
*   `config.py`: Centralized configuration for ports, timeouts, and headers.
*   `main.go`: The Go source code handling port scanning, TCP pings, firewall rules, and geolocation.
*   `Cargo.toml`, `build.rs`, & `src/tcp_sniffer.rs`: The Rust backend utilizing `pcap`, `etherparse`, and `rusqlite` for live packet analysis.
*   **Animation Utilities:** Custom Python/Pillow scripts used to surgically remove backgrounds and generate multi-frame animations for the UI elements.

## 📂 Codebase Structure

Ghost-Hunter/
├── Animation file/                 # UI assets and multi-frame animation sequences
│   ├── block ip animation/         # Visual feedback for firewall block events
│   ├── Insane Hacker Background/   # Animated holographic background frames
│   ├── locate ip animation/        # Geolocation lookup HUD radar sweep
│   ├── port checker animation/     # Port scanning telemetry activity
│   ├── show blocklist animation/   # Active blacklist loading sequence
│   ├── test ping animation/        # Network latency and ping pulse
│   └── unblock ip animation/       # Rule de-provisioning sequence
├── npcap-sdk/                      # Native Npcap packet capture SDK
│   ├── Include/                    # C/C++ Header files for Rust FFI bindings
│   ├── Lib/                        # Compiled libraries for linking the sniffer
│   └── wpcap/                      # Offline HTML API documentation (Omitted for brevity)
├── src/                            # Rust low-level core
│   └── tcp_sniffer.rs              # High-throughput packet capture & threat engine
├── Auth_Vault/                     # Secure directory for IAM configuration
│   └── auth_vault.json             # PBKDF2 HMAC-SHA256 locked master configuration
├── auth_manager.py                 # Identity Access Management (IAM) security gateway
├── build.rs                        # Rust build script targeting npcap-sdk/Lib
├── Cargo.toml                      # Rust dependencies & package manifest
├── Cargo.lock                      # Deterministic dependency lockfile
├── config.py                       # Global network parameters, timeouts, & port lists
├── dashboard.py                    # Primary GUI orchestrator & Tkinter HUD
├── Forensic_Block_Logs.json        # Dynamic 12-hour timestamped active threat and firewall block log
├── go.mod                          # Go module definitions
├── main.go                         # Go engine (concurrent scanning & firewall manipulation)
├── Npcap_Guide.html                # Local setup instructions for driver configuration
├── packet_vault.db                 # Local SQLite WAL database for intercepted telemetry
├── SDK_CHANGELOG.md                # Npcap library revision tracking
├── SecurityScanner.exe             # Compiled standalone executable artifact
└── vulnerability_checker.py        # Middleware scanner & NSE integration
