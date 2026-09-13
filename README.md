# 🚀 Ghost-Hunter: Polyglot CyberSecurity Suite

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
Instantly block or unblock active threats across the host operating system (Windows `netsh` or Linux `iptables`) using the Go binary. Actively wipes duplicate rules and aggressively blocks both INBOUND and OUTBOUND traffic.

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
